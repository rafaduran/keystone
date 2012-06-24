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

from keystone.common import wsgi

LOG = logging.getLogger(__name__)

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


class RateLimitingMiddleware(wsgi.Middleware):
    def process_response(self, request, response):
        return response

    def process_request(self, request):
        pass


class LimitsController(wsgi.Application):
    def get_limits(self, context):
        return {'limits': []}
