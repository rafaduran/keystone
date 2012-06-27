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

import logging
import math
import re
import time

from keystone.common import manager
from keystone.common import wsgi
from keystone import config
from keystone import exception

config.register_str('driver', group='rate_limiting',
                    default='keystone.contrib.rate.backends.kvs.Limiter')
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

    def get_limits(self, user_id):
        """Get current limits for a given user."""
        raise exception.NotImplemented()


class LimitsController(wsgi.Application):

    def __init__(self):
        self.rate_api = Manager()
        super(LimitsController, self).__init__()

    def get_limits(self, context):
        return self.rate_api.get_limits(context)


class RateLimitingMiddleware(wsgi.Middleware):
    def process_response(self, request, response):
        return response

    def process_request(self, request):
        pass
