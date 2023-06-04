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

from keystone.common import manager
from keystone.common import sql
from keystone.tests.unit import test_backend_sql as base

from keystone_rba_plugin.rba.backends import sql_model as model
from keystone_rba_plugin.tests.common import auth as common_auth

from sqlalchemy import select


class TestAuthenticationHistory(base.SqlTests, common_auth.RBATestMixin):

    def setUp(self):
        super(TestAuthenticationHistory, self).setUp()
        self.config_fixture.config(group='rba',
                                   features=['ip', 'rtt', 'osv'])
        self.config_fixture.config(group='rba', max_user_history_size=10)
        self.driver = manager.load_driver('keystone.rba', 'sql')

    def test_create_entry(self):
        user_id = self.user_foo['id']
        features = self._build_features(
            ip='10.0.0.1',
            rtt='500',
            ua='')['features']
        self.driver.create_entry(user_id, features, 0.0)
        expected = 1
        observed = self.driver.count_entries_by_user(user_id)
        self.assertEqual(expected, observed)
        self.driver.create_entry(user_id, features, 0.0)
        expected = 2
        observed = self.driver.count_entries_by_user(user_id)
        self.assertEqual(expected, observed)

    def test_get_features_list_by_user(self):
        user_id = self.user_foo['id']
        expected = 3
        observed = self.driver.get_features_list_by_user(user_id)
        self.assertFalse(observed)
        for i in range(expected):
            features = self._build_features(
                ip='10.0.0.1',
                rtt=str(i))['features']
            self.driver.create_entry(user_id, features, 0.0)
        observed = len(self.driver.get_features_list_by_user(user_id))
        self.assertEqual(expected, observed)

    def test_delete_oldest_n_entries_by_user(self):
        user_id = self.user_foo['id']
        n_entries_to_delete = 2
        m_entries_to_create = 5
        for i in range(m_entries_to_create):
            features = self._build_features(
                ip='10.0.0.1',
                rtt=str(i))['features']
            self.driver.create_entry(user_id, features, 0.0)
        with sql.session_for_write() as session:
            query = (
                select(model.History).
                where(model.History.user_id == user_id))
            ref_list = session.execute(query).all()
            before_delete = [x.History.to_dict()['successful_auth_at']
                             for x in ref_list]
            before_delete.sort()
            not_expected = before_delete[:n_entries_to_delete]
            deleted = self.driver._delete_oldest_n_entries_by_user(
                session,
                user_id,
                n_entries_to_delete)
            ref_list = session.execute(query).all()
            observed = [x.History.to_dict()['successful_auth_at']
                        for x in ref_list]
            self.assertNotEqual(not_expected, observed)
            self.assertNotIn(not_expected, observed)
            expected = not_expected + observed
            self.assertEqual(expected, before_delete)
            self.assertEqual(len(not_expected), len(deleted))


class TestRBAHistoryModel(base.SqlModels):

    def test_rba_history_model(self):
        cols = (('user_id', sql.String, 64),
                ('successful_auth_at', sql.DateTimeInt, None),
                ('features', sql.JsonBlob, None),
                ('confidence_score', sql.sql.Float, None))
        self.assertExpectedSchema('rba_history', cols)
