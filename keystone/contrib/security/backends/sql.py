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

import sqlalchemy

from keystone import config
from keystone.common import sql
from keystone.contrib import security


CONF = config.CONF


class SecurityInfo(sql.ModelBase, sql.DictBase):
    __tablename__ = 'secinfo'
    id = sql.Column(sql.String(64), primary_key=True)
    res_code = sql.Column(sqlalchemy.Integer)
    req_method = sql.Column(sql.String(64))
    path = sql.Column(sql.String(64))
    datetime = sql.Column(sql.DateTime(), default=datetime.datetime.utcnow())
    res_body = sql.Column(sqlalchemy.Text)
    extra = sql.Column(sql.JsonBlob())

    @classmethod
    def from_objs(cls, request, response, extra):
        extra.update({
                'req_headers': dict(request.headers),
                'res_headers': dict(response.headers),
                'os_context': request.environ['openstack.context'],
                'os_params': request.environ.get('openstack.params'),
                })

        return cls(**dict(id=uuid.uuid4().hex,
                          res_code=response.status_int,
                          req_method=request.environ['REQUEST_METHOD'],
                          path=request.environ['PATH_INFO'],
                          res_body=response.body,
                          extra=extra))

    def to_dict(self):
        extra_copy = self.extra.copy()
        for attr in ('id', 'res_code', 'req_method', 'path', 'datetime',
                     'res_body'):
            extra_copy[attr] = getattr(self, attr, None)
        return extra_copy

    def __str__(self):
        return "<SecurityInfo object: %s>" % str(self.to_dict())


class Security(sql.Base, security.Driver):

    def get(self, codes, since=None, until=None, extra_filter=None):
        session = self.get_session()
        query = session.query(SecurityInfo).filter(
                SecurityInfo.res_code.in_(codes))

        if since:
            query.filter(SecurityInfo.datetime >= since)
        if until:
            query.filter(SecurityInfo.datetime <= until)

        if extra_filter:
            query = filter(extra_filter, query)

        return [sec_info for sec_info in query]

    def create(self, request, response, extra={}):
        session = self.get_session()
        with session.begin():
            si_ref = SecurityInfo.from_objs(request=request,
                                            response=response,
                                            extra=extra)
            session.add(si_ref)
            session.flush()
        return si_ref

    def clean(self, sec_info):
       session = self.get_session()
       with session.begin():
           session.delete(sec_info)
           session.flush()
