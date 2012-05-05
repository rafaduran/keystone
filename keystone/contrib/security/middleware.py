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
import datetime
import logging
import smtplib

import mailer as _mailer
import eventlet

from keystone import config
from keystone import exception
from keystone.common import utils
from keystone.common import wsgi
from keystone.contrib import security


CONF = config.CONF
config.register_int('expiration', group='mail_401')
config.register_int('tolerance', group='mail_401')
config.register_str('mail_manager', group='mail_401')
config.register_str('host', group='mail_401', default='localhost')
config.register_str('user', group='mail_401', default=None)
config.register_str('password', group='mail_401', default=None)
config.register_bool('use_tls', group='mail_401', default=True)
config.register_int('port', group='mail_401', default=25)
config.register_str('from_email', group='mail_401')
config.register_str('admin_emails', group='mail_401')


LOG = logging.getLogger(__name__)


class MailManager(object):
    def __init__(self, mailer=None, callback=None, **kwargs):
        self.mailer = mailer
        self.callback = callback
        self._messages = []

        if self.mailer is None:
            self.mailer = _mailer.Mailer(
                host=kwargs.get('host', 'localhost'),
                port=kwargs.get('port', 25),
                use_tls=kwargs.get('use_tls', False),
                usr=kwargs.get('usr', None),
                pwd=kwargs.get('pwd', None),
            )

    @staticmethod
    def make_msg(subject, to, from_, body, html=None, charset="utf-8"):
        return _mailer.Message(Subject=subject, From=from_, To=to,
                              charset=charset, Body=body, Html=html)

    def add_msg(self, msg):
        self._messages.insert(0, msg)

    def send(self):
        raise exception.NotImplemented()


class EventletMailer(MailManager):
    """Send emails in background using greenthreads."""

    def __init__(self, mailer=None, callback=None, **kwargs):
        self.pool = eventlet.GreenPool()
        super(EventletMailer, self).__init__(mailer, callback, **kwargs)

    def send(self):
        def _send(mailer, msg, callback=None):
            exc = None
            try:
                mailer.send(msg)
            except smtplib.SMTPException as exc:
                LOG.exception(exc)

            LOG.debug("Mail sent for message %s" % msg)

            if callback:
                callback(msg, exc)

        while(len(self._messages)):
            msg = self._messages.pop()
            LOG.debug("Spawning a new mailer for message %s" % msg)
            self.pool.spawn_n(_send, self.mailer, msg, self.callback)


class MailConsecutive401(wsgi.Middleware):
    """Sends an email whenever it detects a number of 401 errors greater than
    usual."""

    def __init__(self, app):
        LOG.debug("Starting the Security middleware")
        self.conf = CONF.mail_401
        self.sec_api = security.Manager(CONF.security.driver)
        self.mail_manager = None
        self.admins = ast.literal_eval(self.conf.admin_emails)
        super(MailConsecutive401, self).__init__(app)

    @property
    def mailer(self):
        if not self.mail_manager:
            manager = utils.import_class(self.conf.mail_manager)
            self.mail_manager = manager(host=self.conf.host,
                                        port=self.conf.port,
                                        use_tls=self.conf.use_tls,
                                        usr=self.conf.user,
                                        pwd=self.conf.password,)
        return self.mail_manager

    def make_msg(self, refs):
        return self.mailer.make_msg(subject='Keystone alert: 401 errors.',
                                    to=self.admins,
                                    from_=self.conf.from_email,
                                    body='\n'.join([str(ref) for ref in refs]),
                                    html=None)

    def process_response(self, request, response):
        if response.status_int == 401:
            _ = self.sec_api.create(request, response)

            until = datetime.datetime.utcnow()
            since = until - datetime.timedelta(seconds=self.conf.expiration)
            refs = self.sec_api.get((401,), since, until)

            if len(refs) >= self.conf.tolerance:
                LOG.critical("%d 401 errors in %d seconds" %
                             (len(refs), self.conf.expiration))
                self.mailer.add_msg(self.make_msg(refs))
                self.mailer.send()
                for ref in refs:
                    self.sec_api.clean(ref)
        return response
