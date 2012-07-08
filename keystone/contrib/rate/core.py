# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ast
import copy
import logging
import math
import re
import time

import webob.exc

from keystone.common import manager
from keystone.common import utils
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import identity
import keystone.middleware.core as core_mid
from keystone import policy
from keystone import token


DEFAULT_LIMITS = """(POST, *, .*, 10, MINUTE);
    (POST, /tokens, .*, 3, MINUTE);
    (PUT, *, .*, 10, MINUTE);
    (DELETE, *, .*, 10, MINUTE)"""

config.register_str('driver', group='rate_limiting',
                   default='keystone.contrib.rate.backends.kvs.Limiter')
config.register_str('limits', group='rate_limiting', default=DEFAULT_LIMITS)
config.register_str('userlimits', group='rate_limiting', default='{}')

CONF = config.CONF

LOG = logging.getLogger(__name__)
_ = lambda x: x


# Convenience constants for the limits dictionary passed to Limiter().
PER_SECOND = 1
PER_MINUTE = 60
PER_HOUR = 60 * 60
PER_DAY = 60 * 60 * 24


class Limit(object):
    """
    Stores information about a limit for HTTP requests.
    """

    UNITS = {
        1: "SECOND",
        60: "MINUTE",
        60 * 60: "HOUR",
        60 * 60 * 24: "DAY",
    }

    UNIT_MAP = dict([(v, k) for k, v in UNITS.items()])

    def __init__(self, verb, uri, regex, value, unit):
        """
        Initialize a new `Limit`.

        @param verb: HTTP verb (POST, PUT, etc.)
        @param uri: Human-readable URI
        @param regex: Regular expression format for this limit
        @param value: Integer number of requests which can be made
        @param unit: Unit of measure for the value parameter
        """
        self.verb = verb
        self.uri = uri
        self.regex = regex
        self.value = int(value)
        self.unit = unit
        self.unit_string = self.display_unit().lower()
        self.remaining = int(value)

        if value <= 0:
            raise ValueError("Limit value must be > 0")

        self.last_request = None
        self.next_request = None

        self.water_level = 0
        self.capacity = self.unit
        self.request_value = float(self.capacity) / float(self.value)
        msg = _("Only %(value)s %(verb)s request(s) can be "
                "made to %(uri)s every %(unit_string)s.")
        self.error_message = msg % self.__dict__

    def __call__(self, verb, url):
        """
        Represents a call to this limit from a relevant request.

        @param verb: string http verb (POST, GET, etc.)
        @param url: string URL
        """
        if self.verb != verb or not re.match(self.regex, url):
            return

        now = self._get_time()

        if self.last_request is None:
            self.last_request = now

        leak_value = now - self.last_request

        self.water_level -= leak_value
        self.water_level = max(self.water_level, 0)
        self.water_level += self.request_value

        difference = self.water_level - self.capacity

        self.last_request = now

        if difference > 0:
            self.water_level -= self.request_value
            self.next_request = now + difference
            return difference

        cap = self.capacity
        water = self.water_level
        val = self.value

        self.remaining = math.floor(((cap - water) / cap) * val)
        self.next_request = now

    def _get_time(self):
        """Retrieve the current time. Broken out for testability."""
        return time.time()

    def display_unit(self):
        """Display the string name of the unit."""
        return self.UNITS.get(self.unit, "UNKNOWN")

    def display(self):
        """Return a useful representation of this class."""
        return {
            "verb": self.verb,
            "URI": self.uri,
            "regex": self.regex,
            "value": self.value,
            "remaining": int(self.remaining),
            "unit": self.display_unit(),
            "resetTime": int(self.next_request or self._get_time()),
        }

    @staticmethod
    def parse_limits(limits):
        """
        Convert a string into a list of Limit instances.  This
        implementation expects a semicolon-separated sequence of
        parenthesized groups, where each group contains a
        comma-separated sequence consisting of HTTP method,
        user-readable URI, a URI reg-exp, an integer number of
        requests which can be made, and a unit of measure.  Valid
        values for the latter are "SECOND", "MINUTE", "HOUR", and
        "DAY".

        @return: List of Limit instances.
        """

        # Handle empty limit strings
        limits = limits.strip()
        if not limits:
            return []

        # Split up the limits by semicolon
        result = []
        for group in limits.split(';'):
            group = group.strip()
            if group[:1] != '(' or group[-1:] != ')':
                raise ValueError("Limit rules must be surrounded by "
                                 "parentheses")
            group = group[1:-1]

            # Extract the Limit arguments
            args = [a.strip() for a in group.split(',')]
            if len(args) != 5:
                raise ValueError("Limit rules must contain the following "
                                 "arguments: verb, uri, regex, value, unit")

            # Pull out the arguments
            verb, uri, regex, value, unit = args

            # Upper-case the verb
            verb = verb.upper()

            # Convert value--raises ValueError if it's not integer
            value = int(value)

            # Convert unit
            unit = unit.upper()
            if unit not in Limit.UNIT_MAP:
                raise ValueError("Invalid units specified")
            unit = Limit.UNIT_MAP[unit]

            # Build a limit
            result.append(Limit(verb, uri, regex, value, unit))

        return result


class RateLimitingExtension(wsgi.ExtensionRouter):
    """Provides rate limiting support and information about current limits
    usage by a given user.

    """

    def add_routes(self, mapper):
        limits_controller = LimitsController()
        mapper.connect(
                '/limits',
                controller=limits_controller,
                action='get_limits',
                conditions=dict(method=['GET']))


class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.rate_limiting.driver)


class Driver(object):
    """Interface description for an rate limiting driver."""

    def __init__(self, **kwargs):
        # Kwargs take precedence over confiugration, useful for testing.
        if 'limits' in kwargs:
            self.limits = copy.deepcopy(kwargs['limits'])
        else:
            self.limits = Limit.parse_limits(CONF.rate_limiting.limits)
        if 'userlimits' in kwargs:
            self.userlimits = kwargs['userlimits']
        elif CONF.rate_limiting.userlimits:
            self.userlimits = ast.literal_eval(CONF.rate_limiting.userlimits)

    def get_limits(self, user_id):
        """Get current limits for a given user."""
        raise exception.NotImplemented()

    def check_for_delay(self, verb, url, user_id=None):
        """
        Check the given verb/url/user_id triplet for limit.
        """
        raise exception.NotImplemented()


class LimitsController(wsgi.Application):

    def __init__(self):
        super(LimitsController, self).__init__()
        self.limiter = Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        self.identity_api = identity.Manager()

    def get_limits(self, context):
        return self.limiter.get_limits(context)


class RateLimitingMiddleware(wsgi.Middleware):
    def __init__(self, app):
        super(RateLimitingMiddleware, self).__init__(app)
        self.limiter = Manager()
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()
        self.os_p = core_mid.PARAMS_ENV
        self.os_c = core_mid.CONTEXT_ENV

    def process_response(self, request, response):
        return response

    def process_request(self, request):
        if request.environ[self.os_c]['is_admin']:
            return

        user_id = self._get_user_id(request)
        self.delay, self.msg = self.limiter.check_for_delay(
                {},
                verb=request.method,
                url=request.path,
                user_id=user_id)
        if self.delay:
            # Breaking the pipeline and returng a overLimitFault
            return self._reject_request

    def _get_user_id(self, request):
        env = request.environ
        token_id = env[self.os_c]['token_id']
        if token_id:
            user_id = self._get_user_id_from_token_id(token_id)
        else:
            try:
                username =\
                    env[self.os_p]['auth']['passwordCredentials']['username']
            except KeyError:
                # No user provided
                # TODO (rafaduran): is OK just raise a 401?
                raise exception.Unauthorized()

            # TODO (rafaduran): Need check NotFound, anything else???
            user_id = self.identity_api.get_user_by_name({}, username)['id']
        return user_id

    @utils.memoized
    def _get_user_id_from_token_id(self, token_id):
        """Returns the 'user_id' for a given 'token_id'."""
        # TODO (rafaduran): Need check NotFound, anything else???
        # Token user doesn't change, thus we can use memoize so we only need
        # ask for a given token once.
        return self.token_api.get_token({}, token_id)['user']['id']

    def _reject_request(self, env, start_response):
        """Rejet the request and set a 'Retry-after' header.

        :param env: wsgi request environment
        :param start_response: wsgi response callback
        :returns  http response

        """
        msg = '{"overLimitFault": {"details": "%s"}}' % self.msg
        headers = [("Retry-After", self.delay)]
        resp = HTTPTooManyRequests(headers=headers)
        # TODO (rafaduran): do we need xml too here?
        resp.content_type = 'txt/json'
        resp.body = msg
        return resp(env, start_response)


# Taking this from https://github.com/Pylons/webob/pull/48
# needed until we upgrade to WebOb 1.2
class HTTPTooManyRequests(webob.exc.HTTPClientError):
    """
    subclass of :class:`~HTTPClientError`

    This indicates that the client has sent too many requests in a
    given amount of time. Useful for rate limiting.

    From RFC 6585, "Additional HTTP Status Codes".

    code: 429, title: Too Many Requests
    """
    code = 429
    title = 'Too Many Requests'
    explanation = (
            'The client has sent too many requests in a given amount of time.')
