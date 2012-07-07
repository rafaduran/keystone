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

import uuid

import nose.exc

import webob

from keystone import config
from keystone.contrib.rate.backends import kvs
import keystone.contrib.rate.core as rate_core
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
                                             '(POST, /bar*, /bar.*, 5, second);'
                                             '(Say, /derp*, /derp.*, 1, day)')
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
        self.assertDictEqual(
                self.limiter.get_limits('user1'),
                {'limits': [limit.display() for limit in TEST_LIMITS]})

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
        self.params = {"auth": {"passwordCredentials":{
                    "username": self.username, "password": "secrete"}}}

    def _start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)

    def test_limit_class(self):
        """Test that middleware selected correct limiter class."""
        assert isinstance(self.middleware.limiter.driver,
                          importutils.import_class(CONF.rate_limiting.driver))

    def test_GET_token_request(self):
        """Test GET request through middleware, 'user_id' is taken from
        token."""
        token_id = uuid.uuid4().hex
        req = webob.Request.blank("/")
        # This should be set by other middlewares, so adding here manaually.
        req.environ['openstack.context'] = {
                'token_id': token_id,
                }

        self.mox.StubOutWithMock(self.middleware.limiter.driver,
                                 'check_for_delay')
        self.middleware.limiter.driver.check_for_delay(
                verb='GET', url='/', user_id=self.user_id).AndReturn(
                        (None, None))

        self.mox.StubOutWithMock(self.middleware.token_api.driver, 'get_token')
        self.middleware.token_api.driver.get_token(token_id=token_id).AndReturn(
                        ({'user_ref': self.user_id}))

        self.mox.ReplayAll()

        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(200, self.response_status)

    def test_POST_params_request(self):
        """Test POST request through middleware, 'user_id' is taken from
        params 'username'."""
        req = webob.Request.blank("/tokens")
        # This should be set by other middlewares, so adding here manaually.
        req.environ['openstack.context'] = {
                'token_id': None,
                }
        req.environ['openstack.params'] = self.params
        req.method = 'POST'

        self.mox.StubOutWithMock(self.middleware.identity_api.driver,
                'get_user_by_name')
        self.middleware.identity_api.driver.get_user_by_name(
                user_name=self.username).AndReturn(
                        ({'id': self.user_id}))

        self.mox.StubOutWithMock(self.middleware.limiter.driver,
                                 'check_for_delay')
        self.middleware.limiter.driver.check_for_delay(
                user_id=self.user_id, url='/tokens', verb='POST').AndReturn(
                    (None, None))

        self.mox.ReplayAll()

        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(200, self.response_status)

    def test_POST_token_request(self):
        """Tests token takes precedence over params."""
        token_id = uuid.uuid4().hex
        req = webob.Request.blank("/tokens")
        # This should be set by other middlewares, so adding here manaually.
        req.environ['openstack.context'] = {
                'token_id': token_id,
                }
        req.environ['openstack.params'] = self.params
        req.method = 'POST'

        self.mox.StubOutWithMock(self.middleware.limiter.driver,
                                 'check_for_delay')
        self.middleware.limiter.driver.check_for_delay(
                verb='GET', url='/', user_id=self.user_id).AndReturn(
                        (None, None))

        self.mox.StubOutWithMock(self.middleware.token_api.driver, 'get_token')
        self.middleware.token_api.driver.get_token(token_id=token_id).AndReturn(
                        ({'user_ref': self.user_id}))

        self.mox.ReplayAll()

        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(200, self.response_status)

    def test_no_user_request(self):
        """Test request with no user."""
        raise nose.exc.SkipTest('TODO')

    def test_limited_token_request(self):
        """Test a rate-limited (429) GET request through middleware, 'ref_id'
        is 'token_id'."""
        token_id = uuid.uuid4().hex
        delay = 60
        msg = "Only 1 GET request(s) can be made to * every minute."
        req = webob.Request.blank("/")
        # This should be set by other middlewares, so adding here manaually.
        req.environ['openstack.context'] = {
                'token_id': token_id,
                }

        self.mox.StubOutWithMock(self.middleware.limiter.driver,
                                 'check_for_delay')
        self.middleware.limiter.driver.check_for_delay(
                verb='GET', url='/', user_id=self.user_id).AndReturn(
                        (delay, msg))

        self.mox.StubOutWithMock(self.middleware.token_api.driver,'get_token')
        self.middleware.token_api.driver.get_token(token_id=token_id).AndReturn(
                        ({'user_ref': self.user_id}))

        self.mox.ReplayAll()

        response = self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(self.response_status, 429)

        self.assertTrue('Retry-After' in self.response_headers)
        retry_after = int(self.response_headers['Retry-After'])
        self.assertEqual(retry_after, 60)

        body = jsonutils.loads(response)
        value = body["overLimitFault"]["details"].strip()
        self.assertEqual(value, msg)

    def test_limited_user_request(self):
        """Test a rate-limited (429) POST request through middleware, 'user_id'
        is taken from params 'username'."""
        delay = 60
        msg = "Only 1 GET request(s) can be made to * every minute."
        req = webob.Request.blank("/tokens")
        # This should be set by other middlewares, so adding here manaually.
        req.environ['openstack.context'] = {
                'token_id': None,
                }
        req.environ['openstack.params'] = self.params
        req.method = 'POST'

        self.mox.StubOutWithMock(self.middleware.identity_api.driver,
                'get_user_by_name')
        self.middleware.identity_api.driver.get_user_by_name(
                user_name=self.username).AndReturn(
                        ({'id': self.user_id}))

        self.mox.StubOutWithMock(self.middleware.limiter.driver,
                                 'check_for_delay')
        self.middleware.limiter.driver.check_for_delay(
                verb='GET', url='/', user_id=self.user_id).AndReturn(
                        (delay, msg))

        self.mox.ReplayAll()

        response = self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(self.response_status, 429)

        self.assertTrue('Retry-After' in self.response_headers)
        retry_after = int(self.response_headers['Retry-After'])
        self.assertEqual(retry_after, 60)

        body = jsonutils.loads(response)
        value = body["overLimitFault"]["details"].strip()
        self.assertEqual(value, msg)


#class LimitsrollerTest(object):
#    def test_token_user_mapping(self):
#        """Tests that a given token is mapped to its owner."""
#        raise nose.exc.SkipTest('TODO')
#
#    def test_default_limits(self):
#        """Tests the default rate_core."""
#        raise nose.exc.SkipTest('TODO')
#
#    def test_non_default_limits(self):
#        """Test limits from configuration."""
#        raise nose.exc.SkipTest('TODO')
#
#    def custom_limits(self):
#        """Test custom limits for a given user."""
#        raise nose.exc.SkipTest('TODO')
#
#
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
