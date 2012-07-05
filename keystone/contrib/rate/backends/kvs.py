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

from keystone.common import kvs
from keystone import config
from keystone.contrib.rate import core


CONF = config.CONF


class Limiter(core.Driver, kvs.Base):
    def __init__(self, **kwargs):
        super(Limiter, self).__init__(**kwargs)
        kvs.Base.__init__(self)

        # Kwargs take precedence over confiugration, useful for testing.
        if 'userlimits' in kwargs:
            ul_dict = kwargs['userlimits']
        elif CONF.rate_limiting.userlimits:
            ul_dict = ast.literal_eval(CONF.rate_limiting.userlimits)

        for user, limits in ul_dict.items():
            if isinstance(limits, basestring):
                limits = core.Limit.parse_limits(limits)
            self.set_limits(user, limits)

    def _get_limits(self, user_id=None):
        limits =  self.db.get('limits-%s' % user_id)
        if limits is None:
            # Setting default limits is the user has no specific limits when
            # first trying get limits.
            limits = copy.deepcopy(self.limits)
            self.set_limits(user_id, limits)
        return limits

    def get_limits(self, user_id=None):
        limits = self._get_limits(user_id)
        return {'limits': [limit.display() for limit in limits]}

    def set_limits(self, user_id, limits):
        self.db.set('limits-%s' % user_id, limits)

    def check_for_delay(self, verb, url, user_id=None):
        """
        Check the given verb/url/user_id triplet for limit.

        @return: Tuple of delay (in seconds) and error message (or None, None)
        """
        delays = []

        for limit in self._get_limits(user_id):
            delay = limit(verb, url)
            if delay:
                delays.append((delay, limit.error_message))

        if delays:
            delays.sort()
            return delays[0]

        return None, None
