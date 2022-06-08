# Copyright 2022 Vincent Unsel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import sqlalchemy

from sqlalchemy import delete
from sqlalchemy import select
from sqlalchemy.sql import functions as fn


from oslo_db import api as oslo_db_api
from oslo_log import log

from keystone.common import provider_api
from keystone.common import sql
from keystone import exception
from keystone.i18n import _
from keystone.identity.backends import sql_model as user_model

from keystone_rba_plugin import conf
from keystone_rba_plugin.rba.backends import base
from keystone_rba_plugin.rba.backends import sql_model as model

CONF = conf.CONF

LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class AuthenticationHistory(base.RBAHistoryDriverBase):
    """Default SQL back end driver for the Risk-Based Authentication
    method plug-in.
    """

    def __init__(self, conf=None):
        self.conf = conf
        super(AuthenticationHistory, self).__init__()

    @property
    def is_sql(self):
        return True

    def get_entries(self):
        with sql.session_for_read() as session:
            return self._get_entries(session)

    def _get_entries(self, session):
        query = select(model.History)
        ref_list = session.execute(query)
        return [(x[0].user_id, x[0].features) for x in ref_list]

    def get_features_list_by_user(self, user_id):
        with sql.session_for_read() as session:
            return self._get_features_list_by_user(session, user_id)

    def _get_features_list_by_user(self, session, user_id):
        query = (
            select(model.History.features).
            where(model.History.user_id == user_id))
        ref_list = session.execute(query).all()
        return [x.features for x in ref_list]

    def create_entry(self, user_id, features, confidence_score):
        """ Inserts a new entry to the database.

        :param str user_id: unique user identitier.
        :param dict features: environmental values collected during
        an authentication attempt.
        :param float confidence_score: risk score calculated for the features
        """
        with sql.session_for_write() as session:
            session.add(model.History(user_id, features, confidence_score))

    def count_entries_by_user(self, user_id):
        with sql.session_for_read() as session:
            query = (
                select(fn.count()).
                select_from(model.History).
                where(model.History.user_id == user_id))
            return session.execute(query).scalar()

    def delete_oldest_n_entries_by_user(self, user_id, n):
        with sql.session_for_write() as session:
            return self._delete_oldest_n_entries_by_user(session, user_id, n)

    def _delete_oldest_n_entries_by_user(self, session, user_id, n):
        subquery = (
            select(model.History).
            where(model.History.user_id == user_id).
            order_by(model.History.successful_auth_at.asc()).
            limit(n)
        )
        ref_list = session.execute(subquery)
        successful_auth_at = []
        returning = []
        for row in ref_list:
            successful_auth_at.append(row[0].successful_auth_at)
            returning.append((row[0].user_id, row[0].features))
        query = (
            delete(model.History).
            where(model.History.user_id == user_id).
            where(model.History.successful_auth_at.in_(successful_auth_at)).
            execution_options(synchronize_session='fetch')
        )
        session.execute(query)
        return returning

    def clear_entries(self):
        with sql.session_for_write() as session:
            session.execute(delete(model.History))
