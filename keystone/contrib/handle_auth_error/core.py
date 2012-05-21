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


CONF = config.CONF
config.register_bool('disable_user', group='auth_error_handler', default=False)
config.register_int('expiration', group='auth_error_handler')
config.register_int('tolerance', group='auth_error_handler', default=3)
config.register_str('mail_manager', group='auth_error_handler',
                    default='keystone.contrib.auth_error_handle.EventlerMailer')
config.register_str('host', group='auth_error_handler', default='localhost')
config.register_str('user', group='auth_error_handler', default=None)
config.register_str('password', group='auth_error_handler', default=None)
config.register_bool('use_tls', group='auth_error_handler', default=True)
config.register_int('port', group='auth_error_handler', default=25)
config.register_str('from_email', group='auth_error_handler')
config.register_str('to_emails', group='auth_error_handler')


LOG = logging.getLogger(__name__)

BODY = "The user %s tried %d logging attempts without success."
DISABLED_BODY = "The user %s was disabled after trying %d loging attempts."



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


class AuthErrorHandler(object):
    """Sends an email whenever it detects a number of 401 errors greater than
    usual for a user and optionally disable."""

    def __init__(self):
        self.conf = CONF.auth_error_handler
        self.mail_manager = None
        self.to_emails = ast.literal_eval(self.conf.to_emails)

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

    def handle(self, user_id, password, tenant_id, backend, user_ref=None):
        # The user exists
        # TODO: global handling
        if user_ref:
            # Updating logging attempts
            now = datetime.datetime.utcnow()
            try:
                user_ref['login_attempts'].append(str(now))
            except KeyError:
                user_ref['login_attempts'] = [str(now),]
            finally:
                limit = now - datetime.timedelta(
                                seconds=self.conf.expiration)

                time_filter = lambda x: datetime.datetime.strptime(x,
                                        '%Y-%m-%d %H:%M:%S.%f') >= limit
                user_ref['login_attempts'] = filter(time_filter,
                                                    user_ref['login_attempts'])
                backend.update_user(user_ref['id'], user_ref)

            if len(user_ref['login_attempts']) > self.conf.tolerance:
                if self.conf.disable_user:
                    user_ref.enabled = False
                    backend.update_user(user_ref['id'], user_ref)

                    self.mailer.add_msg(self.mailer.make_msg(
                            subject="[Keystone] Disabled user.",
                            to=self.to_emaails,
                            from_=self.conf.from_email,
                            body=DISABLED_BODY % (user_id,
                                                  self.conf.tolerance))
                        )
                    # TODO: mail disabled user if email avaliable.
                else:
                    self.mailer.add_msg(self.mailer.make_msg(
                            subject="[Keystone] Authentication errors.",
                            to=self.to_emails,
                            from_=self.conf.from_email,
                            body = BODY % (user_id, self.conf.tolerance))
                        )

                self.mailer.send()
