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

import functools

from keystone import config
from keystone import exception
from keystone.common import utils


CONF = config.CONF

config.register_str('driver', group='security')
config.register_str('actions', group='security')


class Manager(object):
    """Default pivot point for the SecurityMiddleware backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self, driver_name):
        self.driver = utils.import_object(driver_name)

    def __getattr__(self, name):
        """Forward calls to the underlying driver."""
        f = getattr(self.driver, name)

        @functools.wraps(f)
        def _wrapper(*args, **kw):
            return f(*args, **kw)
        setattr(self, name, _wrapper)
        return _wrapper


class Driver(object):
    """Interface description for a Security Driver."""

    def get(self, codes, since, until, extra_filter):
        """Get security info for the given status codes and time.

        Args
            ``codes`` Iterable of exception status codes.

            ``since`` Start time.

            ``until`` End time.

            ``extra_filter`` Callable for extra filtering.

        Returns
            List of SecurityInfo objects matching search criterias.

        """
        raise exception.NotImplemented()

    def create(self, request, response, extra):
        """Create a new security info object.

        Args
            ``request`` The request triggering the exception.

            ``response`` The response for the given exception.

            ``extra`` Extra info to be stored.
        Returns
            The security info just stored.

        """
        raise exception.NotImplemented()

    def clean(self, sec_info):
        """Handles security info once they are not needed anymore, usually
        just delete them.

        """
        raise exception.NotImplemented()
