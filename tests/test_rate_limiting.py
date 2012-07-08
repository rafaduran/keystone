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

import datetime
import uuid

import nose.exc

import webob

from keystone import config
from keystone.contrib.rate.backends import kvs
import keystone.contrib.rate.core as rate_core
from keystone import exception
from keystone.openstack.common import importutils
from keystone.openstack.common import jsonutils
from keystone import test


CONF = config.CONF


TEST_LIMITS = [
    rate_core.Limit("GET", "/delayed", "^/delayed", 1, rate_core.PER_MINUTE),
    rate_core.Limit("POST", "*", ".*", 7, rate_core.PER_MINUTE),
    rate_core.Limit("POST", "/tokens", "^/tokens", 3, rate_core.PER_MINUTE),
    rate_core.Limit("PUT", "*", "", 10, rate_core.PER_MINUTE),
    rate_core.Limit("PUT", "/users", "^/users", 5, rate_core.PER_MINUTE),
]


class BaseRateLimitingTest(test.TestCase):
    """Base test suite which provides relevant stubs and time abstratcion."""

    def setUp(self):
        super(BaseRateLimitingTest, self).setUp()
        self.time = 0.0
        self.stubs.Set(rate_core.Limit, "_get_time", self._get_time)
        self.absolute_limits = {}

    def _get_time(self):
        """Return the "time" according to this test suite."""
        return self.time


class LimitTest(BaseRateLimitingTest):
    """Tests for the `keystone.contrib.rate_core.Limit` class."""

    def test_GET_no_delay(self):
        """Test a limit handles 1 GET per second."""
        limit = rate_core.Limit("GET", "*", ".*", 1, 1)
        delay = limit("GET", "/anything")
        self.assertEqual(None, delay)
        self.assertEqual(0, limit.next_request)
        self.assertEqual(0, limit.last_request)

    def test_GET_delay(self):
        """Test two calls to 1 GET per second limit."""
        limit = rate_core.Limit("GET", "*", ".*", 1, 1)
        delay = limit("GET", "/anything")
        self.assertEqual(None, delay)

        delay = limit("GET", "/anything")
        self.assertEqual(1, delay)
        self.assertEqual(1, limit.next_request)
        self.assertEqual(0, limit.last_request)

        self.time += 4

        delay = limit("GET", "/anything")
        self.assertEqual(None, delay)
        self.assertEqual(4, limit.next_request)
        self.assertEqual(4, limit.last_request)

    def test_invalid(self):
        """Test that parse_limits() handles invalid input correctly."""
        self.assertRaises(ValueError, rate_core.Limit.parse_limits,
                          ';;;;;')

    def test_bad_rule(self):
        """Test that parse_limits() handles bad rules correctly."""
        self.assertRaises(ValueError, rate_core.Limit.parse_limits,
                          'GET, *, .*, 20, minute')

    def test_missing_arg(self):
        """Test that parse_limits() handles missing args correctly."""
        self.assertRaises(ValueError, rate_core.Limit.parse_limits,
                          '(GET, *, .*, 20)')

    def test_bad_value(self):
        """Test that parse_limits() handles bad values correctly."""
        self.assertRaises(ValueError, rate_core.Limit.parse_limits,
                          '(GET, *, .*, foo, minute)')

    def test_bad_unit(self):
        """Test that parse_limits() handles bad units correctly."""
        self.assertRaises(ValueError, rate_core.Limit.parse_limits,
                          '(GET, *, .*, 20, lightyears)')

    def test_multiple_rules(self):
        """Test that parse_limits() handles multiple rules correctly."""
        try:
            l = rate_core.Limit.parse_limits('(get, *, .*, 20, minute);'
                                             '(PUT, /foo*, /foo.*, 10, hour);'
                                             '(POST, /bar*, /bar.*, 5, second)'
                                             ';(Say, /derp*, /derp.*, 1, day)')
        except ValueError, e:
            assert False, str(e)

        # Make sure the number of returned limits are correct
        self.assertEqual(len(l), 4)

        # Check all the verbs...
        expected = ['GET', 'PUT', 'POST', 'SAY']
        self.assertEqual([t.verb for t in l], expected)

        # ...the URIs...
        expected = ['*', '/foo*', '/bar*', '/derp*']
        self.assertEqual([t.uri for t in l], expected)

        # ...the regexes...
        expected = ['.*', '/foo.*', '/bar.*', '/derp.*']
        self.assertEqual([t.regex for t in l], expected)

        # ...the values...
        expected = [20, 10, 5, 1]
        self.assertEqual([t.value for t in l], expected)

        # ...and the units...
        expected = [rate_core.PER_MINUTE, rate_core.PER_HOUR,
                    rate_core.PER_SECOND, rate_core.PER_DAY]
        self.assertEqual([t.unit for t in l], expected)

    def test_empty(self):
        """Tests a blank string returns an empty list."""
        self.assertListEqual([], rate_core.Limit.parse_limits('  '))
        self.assertListEqual([], rate_core.Limit.parse_limits(''))

    def test_negative_value(self):
        """Tests a negative value raises `ValueError`."""
        self.assertRaises(ValueError,
                          rate_core.Limit.parse_limits,
                          '(get, *, .*, -1, minute);')


class LimitsControllerTest(object):
    def test_token_user_mapping(self):
        """Tests that a given token is mapped to its owner."""
        raise nose.exc.SkipTest('TODO')

    def test_default_limits(self):
        """Tests the default rate_core."""
        raise nose.exc.SkipTest('TODO')

    def test_non_default_limits(self):
        """Test limits from configuration."""
        raise nose.exc.SkipTest('TODO')

    def custom_limits(self):
        """Test custom limits for a given user."""
        raise nose.exc.SkipTest('TODO')


class LimiterTestSuite(object):
    """
    Test suite base for Limiter classes.
    """

    def _check(self, num, verb, url, user_id=None):
        """Check and yield results from checks."""
        for x in xrange(num):
            yield self.limiter.check_for_delay(verb, url, user_id)[0]

    def _check_sum(self, num, verb, url, user_id=None):
        """Check and sum results from checks."""
        results = self._check(num, verb, url, user_id)
        return sum(item for item in results if item)

    def test_no_delay_GET(self):
        """
        Simple test to ensure no delay on a single call for a limit verb we
        didn't set.
        """
        delay = self.limiter.check_for_delay("GET", "/anything")
        self.assertEqual(delay, (None, None))

    def test_no_delay_PUT(self):
        """
        Simple test to ensure no delay on a single call for a known limit.
        """
        delay = self.limiter.check_for_delay("PUT", "/anything")
        self.assertEqual(delay, (None, None))

    def test_delay_PUT(self):
        """
        Ensure the 11th PUT will result in a delay of 6.0 seconds until
        the next request will be granced.
        """
        expected = [None] * 10 + [6.0]
        results = list(self._check(11, "PUT", "/anything"))

        self.assertEqual(expected, results)

    def test_delay_POST(self):
        """
        Ensure the 8th POST will result in a delay of 6.0 seconds until
        the next request will be granced.
        """
        expected = [None] * 7
        results = list(self._check(7, "POST", "/anything"))
        self.assertEqual(expected, results)

        expected = 60.0 / 7.0
        results = self._check_sum(1, "POST", "/anything")
        self.failUnlessAlmostEqual(expected, results, 8)

    def test_delay_GET(self):
        """
        Ensure the 11th GET will result in NO delay.
        """
        expected = [None] * 11
        results = list(self._check(11, "GET", "/anything"))

        self.assertEqual(expected, results)

    def test_delay_PUT_users(self):
        """
        Ensure PUT on /users limits at 5 requests, and PUT elsewhere is still
        OK after 5 requests...but then after 11 total requests, PUT limiting
        kicks in.
        """
        # First 6 requests on PUT /users
        expected = [None] * 5 + [12.0]
        results = list(self._check(6, "PUT", "/users"))
        self.assertEqual(expected, results)

        # Next 5 request on PUT /anything
        expected = [None] * 4 + [6.0]
        results = list(self._check(5, "PUT", "/anything"))
        self.assertEqual(expected, results)

    def test_delay_PUT_wait(self):
        """
        Ensure after hitting the limit and then waiting for the correct
        amount of time, the limit will be lifted.
        """
        expected = [None] * 10 + [6.0]
        results = list(self._check(11, "PUT", "/anything"))
        self.assertEqual(expected, results)

        # Advance time
        self.time += 6.0

        expected = [None, 6.0]
        results = list(self._check(2, "PUT", "/anything"))
        self.assertEqual(expected, results)

    def test_multiple_delays(self):
        """
        Ensure multiple requests still get a delay.
        """
        expected = [None] * 10 + [6.0] * 10
        results = list(self._check(20, "PUT", "/anything"))
        self.assertEqual(expected, results)

        self.time += 1.0

        expected = [5.0] * 10
        results = list(self._check(10, "PUT", "/anything"))
        self.assertEqual(expected, results)

    def test_user_limit(self):
        """
        Test user-specific rate.
        """
        # Custom limit.
        self.assertDictEqual(self.limiter.get_limits('user3'),
                             {'limits': []})
        # Default limit.
        self.assertDictEqual(self.limiter.get_limits('user1'),
                             {'limits':
                                 [limit.display() for limit in TEST_LIMITS]})

    def test_multiple_users(self):
        """
        Tests involving multiple users.
        """
        # User1
        expected = [None] * 10 + [6.0] * 10
        results = list(self._check(20, "PUT", "/anything", "user1"))
        self.assertEqual(expected, results)

        # User2
        expected = [None] * 10 + [6.0] * 5
        results = list(self._check(15, "PUT", "/anything", "user2"))
        self.assertEqual(expected, results)

        # User3
        expected = [None] * 20
        results = list(self._check(20, "PUT", "/anything", "user3"))
        self.assertEqual(expected, results)

        self.time += 1.0

        # User1 again
        expected = [5.0] * 10
        results = list(self._check(10, "PUT", "/anything", "user1"))
        self.assertEqual(expected, results)

        self.time += 1.0

        # User1 again
        expected = [4.0] * 5
        results = list(self._check(5, "PUT", "/anything", "user2"))
        self.assertEqual(expected, results)


class KvsLimiterTests(BaseRateLimitingTest, LimiterTestSuite):
    def setUp(self):
        super(KvsLimiterTests, self).setUp()
        userlimits = {'user3': []}
        self.limiter = kvs.Limiter(limits=TEST_LIMITS, userlimits=userlimits)


class FakeHTTPResponse(object):
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.reason = ""

    def read(self):
        return self.body


class FakeHTTPConnection(object):
    status = 200

    def __init__(self, *args):
        pass

    def request(self, method, path, **kwargs):
        body = jsonutils.dumps({})
        status = self.status
        self.resp = FakeHTTPResponse(status, body)

    def getresponse(self):
        return self.resp

    def close(self):
        pass


class FakeApp(object):
    """This represents a WSGI app protected by the auth_token middleware."""
    def __call__(self, env, start_response):
        resp = webob.Response()
        resp.environ = env
        return resp(env, start_response)


class RateMiddlewareTests(BaseRateLimitingTest):
    """
    Tests for the `keystone.contrib.rate.RateLimitingMiddleware` class.
    """

    def setUp(self):
        """Prepare middleware for use through fake WSGI app."""
        super(RateMiddlewareTests, self).setUp()
        self.middleware = rate_core.RateLimitingMiddleware(FakeApp())
        self.middleware.http_client_class = FakeHTTPConnection
        self.username = 'user'
        self.user_id = uuid.uuid4().hex
        self.params = {"auth": {"passwordCredentials": {
                       "username": self.username, "password": "secrete"}}}
        self.delay = 60
        self.msg = "Only 1 GET request(s) can be made to * every minute."

    def _start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)

    def _request_and_stub(self, token_id=None, url='/', is_admin=False,
                          method='GET', params_ctx=False, delay=None,
                          msg=None):
        req = webob.Request.blank(url)
        req.method = method
        req.environ['openstack.context'] = {'token_id': token_id,
                                            'is_admin': is_admin}
        if params_ctx:
            req.environ['openstack.params'] = self.params

        if token_id:
            self.mox.StubOutWithMock(self.middleware.token_api, 'get_token')
            self.middleware.token_api.get_token({}, token_id).\
                AndReturn({'user': {'id': self.user_id}})
        else:
            self.mox.StubOutWithMock(self.middleware.identity_api,
                                     'get_user_by_name')
            self.middleware.identity_api.get_user_by_name({}, self.username).\
                AndReturn({'id': self.user_id})

        self.mox.StubOutWithMock(self.middleware.limiter, 'check_for_delay')
        self.middleware.limiter.check_for_delay({},
                                                verb=method,
                                                url=url,
                                                user_id=self.user_id).\
            AndReturn((delay, msg))

        self.mox.ReplayAll()

        return req

    def test_limiter_class(self):
        """Test that middleware selected correct limiter class."""
        self.assertTrue(isinstance(self.middleware.limiter.driver,
                                   importutils.import_class(
                                       CONF.rate_limiting.driver)))

    def test_GET_token_request(self):
        """Test GET request through middleware, 'user_id' is taken from
        token."""
        token_id = uuid.uuid4().hex
        req = self._request_and_stub(token_id=token_id)

        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(200, self.response_status)

    def test_POST_params_request(self):
        """Test POST request through middleware, 'user_id' is taken from
        params 'username'."""
        req = self._request_and_stub(method='POST',
                                     url='/tokens',
                                     params_ctx=True)

        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(200, self.response_status)

    def test_POST_token_request(self):
        """Tests token takes precedence over params."""
        token_id = uuid.uuid4().hex
        req = self._request_and_stub(token_id=token_id,
                                     method='POST',
                                     url='/tokens',
                                     params_ctx=True)

        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(200, self.response_status)

    def test_limited_token_request(self):
        """Test a rate-limited (429) GET request through middleware, 'ref_id'
        is 'token_id'."""
        token_id = uuid.uuid4().hex
        req = self._request_and_stub(token_id=token_id,
                                     delay=self.delay,
                                     msg=self.msg)

        response = self.middleware(req.environ, self._start_fake_response)[0]
        self.assertEqual(self.response_status, 429)

        self.assertTrue('Retry-After' in self.response_headers)
        retry_after = int(self.response_headers['Retry-After'])
        self.assertEqual(retry_after, 60)

        body = jsonutils.loads(response)
        value = body["overLimitFault"]["details"].strip()
        self.assertEqual(value, self.msg)

    def test_limited_user_request(self):
        """Test a rate-limited (429) POST request through middleware, 'user_id'
        is taken from params 'username'."""
        req = self._request_and_stub(method='POST',
                                     url='/tokens',
                                     params_ctx=True,
                                     delay=self.delay,
                                     msg=self.msg)

        response = self.middleware(req.environ, self._start_fake_response)[0]
        self.assertEqual(self.response_status, 429)

        self.assertTrue('Retry-After' in self.response_headers)
        retry_after = int(self.response_headers['Retry-After'])
        self.assertEqual(retry_after, 60)

        body = jsonutils.loads(response)
        value = body["overLimitFault"]["details"].strip()
        self.assertEqual(value, self.msg)

    def test_admin_token(self):
        token_id = CONF.admin_token
        req = webob.Request.blank("/")
        # This should be set by other middlewares, so adding here manaually.
        req.environ['openstack.context'] = {'token_id': token_id,
                                            'is_admin': True}

        self.middleware(req.environ, self._start_fake_response)

    def test_no_user_request(self):
        """Test request with no user."""
        raise nose.exc.SkipTest('Behavior to be determined.')

    def test_token_not_found(self):
        """Test request with missing token."""
        raise nose.exc.SkipTest('Behavior to be determined.')

    def test_user_not_found(self):
        """Test request with missing user."""
        raise nose.exc.SkipTest('Behavior to be determined.')


class LimitsrollerTest(BaseRateLimitingTest):
    def setUp(self):
        """Prepare middleware for use through fake WSGI app."""
        super(LimitsrollerTest, self).setUp()
        self.controller = rate_core.LimitsController()
        self.username = 'user'
        self.user_id = uuid.uuid4().hex
        self.token_id = uuid.uuid4().hex
        self.limits = {
            "limits": [
                {
                    "regex": ".*",
                    "resetTime": 1341692872,
                    "URI": "*",
                    "value": 10,
                    "verb": "GET",
                    "remaining": 10,
                    "unit": "MINUTE"
                },
                {
                    "regex": ".*",
                    "resetTime": 1341692880,
                    "URI": "*", "value": 5,
                    "verb": "POST",
                    "remaining": 3,
                    "unit": "HOUR"
                },
            ]
        }

        self.context = {'query_string': {},
                        'token_id': self.token_id,
                        'is_admin': False}

        self.user = {
            u'id': self.user_id,
            u'enabled': True,
            u'email': u'admin@example.com',
            u'name': u'admin',
            u'tenantId': None
        }

        self.token = {'id': self.token_id,
                      'expires': datetime.datetime(2012, 7, 8, 17, 47, 15),
                      u'user': self.user,
                      u'tenant': {u'enabled': True,
                                  u'description': None,
                                  u'name': u'admin',
                                  u'id': u'ce3d2b75b8fe4f508dfc85cbb8786a79'},
                      u'metadata': {
                      u'roles': [
                          u'b8ce535eba3c446d8ad78caebbb3c0aa',
                          u'ab93ed946b514bcda97f535bc539517f',
                          u'3cfd86b9614b42388ed688615cfadd07']}}

    def _stub(self, user_id=None, limits=None, context=None, token=None,
              token_id=None, token_not_found=False):
        if not user_id:
            user_id = self.user_id
        if not limits:
            limits = self.limits
        if not context:
            context = self.context
        if not token:
            token = self.token
        if not token_id:
            token_id = self.token_id

        self.mox.StubOutWithMock(self.controller.limiter, 'get_limits')
        self.controller.limiter.get_limits(context=self.context,
                                           user_id=user_id).AndReturn(limits)

        self.mox.StubOutWithMock(self.controller.token_api, 'get_token')
        if not token_not_found:
            self.controller.token_api.get_token(context,
                                                token_id).AndReturn(token)
        else:
            self.controller.token_api.get_token(context,
                                                token_id).\
                AndRaise(exception.NotFound(target=token_id))

        self.mox.ReplayAll()

    def _stub_admin(self, admin=True, user_id=None, user_found=True):
        if not user_id:
            user_id = self.user_id

        self.mox.StubOutWithMock(self.controller.identity_api, 'get_user')
        if user_found:
            self.controller.identity_api.get_user(self.context,
                                                  self.user_id).\
                AndReturn(self.user)
        else:
            self.controller.identity_api.get_user(self.context,
                                                  self.user_id).\
                AndRaise(exception.NotFound(target=user_id))

        self.mox.StubOutWithMock(self.controller, 'assert_admin')
        if admin:
            self.controller.assert_admin(self.context).AndReturn(None)
        else:
            self.controller.assert_admin(self.context).\
                AndRaise(exception.ForbiddenAction(action='admin_required'))

    def test_limiter_class(self):
        """Test the right limitir class is selected."""
        self.assertTrue(isinstance(self.controller.limiter.driver,
                                   importutils.import_class(
                                       CONF.rate_limiting.driver)))

    def test_get_limits(self):
        """Tests 'get_limits'."""
        self._stub()

        self.assertListEqual(self.controller.get_limits(self.context),
                             self.limits)

    def test_get_limits_unauthenticated(self):
        """Tests 'get_limits' unaunthenticated user."""
        self._stub(token_not_found=True)
        self.assertRaises(exception.Unauthorized,
                          self.controller.get_limits,
                          self.context)

    def test_admin_get_user_limits(self):
        """Test admin can get limits for any given user."""
        self._stub()
        self._stub_admin()

        self.assertListEqual(self.controller.get_user_limits(
            self.context, self.user_id), self.limits)

    def test_admin_get_user_not_found_limits(self):
        """Tests admin get limits for a user not found."""
        self._stub()
        self._stub_admin(user_found=False)
        self.assertRaises(exception.NotFound,
                          self.controller.get_user_limits,
                          self.context,
                          self.user_id)

    def test_non_admin_get_user_limits(self):
        """Tests a non admin user trying to get limits for any given user."""
        self._stub()
        self._stub_admin(False)

        self.assertRaises(exception.ForbiddenAction,
                          self.controller.get_user_limits,
                          self.context,
                          self.user_id)


#class RestfulRateLimit(object):
#    def test_good_request(self):
#        """Tests successful request."""
#        raise nose.exc.SkipTest('TODO')
#
#    def test_limited_request(self):
#        """Tests a rate-limited (413) GET request through middleware."""
#        raise nose.exc.SkipTest('TODO')
#
#    def test_request_limits_json(self):
#        """Tests successful limits request, JSON response."""
#        raise nose.exc.SkipTest('TODO')
#
#    def test_request_limits_xml(self):
#        """Tests succesful limits request, XML response."""
#        raise nose.exc.SkipTest('TODO')
#
#    def test_request_limits_bad(self):
#        """Tests bad limits requets."""
#        raise nose.exc.SkipTest('TODO')
