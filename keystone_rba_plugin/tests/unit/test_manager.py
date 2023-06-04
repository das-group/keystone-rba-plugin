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

from keystone_rba_plugin.rba import core
from keystone.tests.unit import test_backend_sql as base
from keystone.tests.unit.utils import wip
from keystone_rba_plugin import conf
from keystone_rba_plugin.tests.common import auth

CONF = conf.CONF
MALICIOUS_ADDRESSES = auth.MALICIOUS_ADDRESSES


class TestRBAManager(base.SqlTests, auth.RBATestMixin):

    def setUp(self):
        super(TestRBAManager, self).setUp()
        self.config_fixture.config(group='rba',
                                   features=['ip', 'rtt', 'ua'])
        self.config_fixture.config(group='rba', driver='sql')
        self.config_fixture.config(group='rba', messenger=None)
        self.config_fixture.config(group='rba',
                                   malicious_ip_list_path=MALICIOUS_ADDRESSES)
        self.config_fixture.config(group='rba', max_user_history_size=10)
        self.manager = core.RBAManager()
        self._init_features()

    def setUp_entries(self):
        self.entries, self.users = self._build_test_entries()
        for user_id, entry in self.entries.items():
            for features in entry['ls']:
                self.manager.add_features(user_id, features, 0.0)

    def test_filter_features(self):
        self.config_fixture.config(group='rba',
                                   features=['ip', 'rtt'])
        expected = self._build_features(
            ip='10.0.0.1',
            rtt='500')['features']
        test_features = self._build_features(
            ip='10.0.0.1',
            rtt='500',
            ua='')['features']
        observed = self.manager._filter_features(test_features)
        self.assertEqual(expected, observed)

    def test_hash_features(self):
        features = self._build_features(
            ip='10.0.0.1',
            rtt='500')['features']
        observed = self.manager._hash_features(features)
        self.assertNotEqual(features, observed)

    def test_load_histories(self):
        user_id = self.user_foo['id']
        features = self._build_features(
            ip='12.45.2.64',
            rtt='534',
            ua='Mozilla/5.0'
        )['features']
        self.manager.driver.create_entry(user_id, features, 0.0)
        self.manager.driver.create_entry(user_id, features, 0.0)
        self.manager.load_histories()
        self.assertIsNotNone(self.manager.total_history.get('ip'))
        self.assertIsNotNone(self.manager.users_history.get(user_id))

    def test_features_value_history(self):
        self.setUp_entries()
        for key, value in self.entries.items():
            entries = self.manager.driver.get_features_list_by_user(key)
            for ts in value['ts']:
                for feature_value in ts.items():
                    observed = self.manager.feature_value_history(
                        entries, feature_value)
                    self.assertIsNotNone(observed)
                    break
                break
            break

    def test_add_features(self):
        self.config_fixture.config(group='rba', max_user_history_size=0)
        user_id = self.user_foo['id']
        features = self._build_features(
            ip='12.45.2.64',
            rtt='534',
            ua='Mozilla/5.0'
        )['features']
        self.manager.add_features(user_id, features, 0.0)
        expected = 0
        observed = self.manager.driver.count_entries_by_user(user_id)
        self.assertEqual(expected, observed)
        self.assertIsNone(self.manager.total_history.get('ip'))
        self.assertIsNone(self.manager.users_history.get(user_id))

        self.config_fixture.config(group='rba', max_user_history_size=1)
        self.manager.add_features(user_id, features, 0.0)
        expected = 1
        observed = self.manager.driver.count_entries_by_user(user_id)
        self.assertEqual(expected, observed)
        observed = sum(self.manager.total_history.get('ip').values())
        self.assertEqual(expected, observed)
        observed = sum(self.manager.users_history[user_id]['ip'].values())
        self.assertEqual(expected, observed)
        added_first = self.manager.driver.get_features_list_by_user(user_id)
        features['rtt'] = '1337'
        self.manager.add_features(user_id, features, 0.0)
        observed = self.manager.driver.count_entries_by_user(user_id)
        self.assertEqual(expected, observed)
        observed = sum(self.manager.total_history.get('ip').values())
        self.assertEqual(expected, observed)
        observed = sum(self.manager.users_history[user_id]['ip'].values())
        self.assertEqual(expected, observed)
        added_after = self.manager.driver.get_features_list_by_user(user_id)
        self.assertNotEqual(added_first, added_after)
        self.config_fixture.config(group='rba', max_user_history_size=0)
        self.manager.add_features(user_id, features, 0.0)
        expected = 0
        observed = self.manager.driver.count_entries_by_user(user_id)
        self.assertEqual(expected, observed)
        self.assertIsNone(self.manager.total_history.get('ip'))
        self.assertIsNone(self.manager.users_history.get(user_id))

    def test_subtract_features(self):
        user_id = self.user_foo['id']
        features = self._build_features(
            ip='12.45.2.64',
            rtt='534',
            ua='Mozilla/5.0'
        )['features']
        self.assertRaises(AssertionError,
                          self.manager._subtract_features,
                          user_id, features)
        self.assertIsNone(self.manager.total_history.get('ip'))
        self.assertIsNone(self.manager.users_history.get(user_id))
        self.manager._add_features(user_id, features)
        self.manager._subtract_features(user_id, features)
        self.assertIsNone(self.manager.total_history.get('ip'))
        self.assertIsNone(self.manager.users_history.get(user_id))
        self.manager._add_features(user_id, features)
        features['rtt'] = '210'
        self.manager._add_features(user_id, features)
        self.manager._subtract_features(user_id, features)
        self.assertRaises(AssertionError,
                          self.manager._subtract_features,
                          user_id, features)
        self.assertRaises(AssertionError,
                          self.manager._subtract_features,
                          user_id, features)
        self.manager.init_histories()
        self.manager._add_features(user_id, features)
        self.manager._add_features(user_id, features)
        feature2 = {'ip': '', 'rtt': ''}
        self.manager._add_features(user_id, feature2)
        self.manager._subtract_features(user_id, features)
        self.manager._subtract_features(user_id, feature2)
        self.manager._subtract_features(user_id, features)
        self.assertIsNone(self.manager.total_history.get('ip'))
        self.assertIsNone(self.manager.users_history.get(user_id))

    def test_confidence_score(self):
        user_id = self.user_foo['id']
        self._init_features()
        features = self.features
        self.entries, self.users = self._build_test_entries()
        for key, value in self.entries.items():
            for ls in value['ls'][:]:
                score = self.manager.confidence_score(key, ls)
                self.manager.add_features(key, ls, score)
        for key, value in self.entries.items():
            for ts in value['ts'][:]:
                score = self.manager.confidence_score(key, ts)
                self.manager.add_features(key, ts, score)
        for key, value in self.entries.items():
            for tns in value['tns']:
                score = self.manager.confidence_score(key, tns)
                break

    def test_init_coefficients(self):
        self.config_fixture.config(group='rba',
                                   features=['ip', 'rtt'])
        self.manager.init_coefficients()
        self.assertEquals(2, len(self.manager.coefficients))
        self.assertEquals(1, len(self.manager.coefficients['ip']))
        self.config_fixture.config(group='rba',
                                   features=['ip', 'rtt', 'ua'])
        self.manager.init_coefficients()
        self.assertEquals(3, len(self.manager.coefficients))
        self.assertEquals(4, len(self.manager.coefficients['ua']))
        self.config_fixture.config(group='rba', maxmind_asn_db_path='')
        self.config_fixture.config(group='rba', maxmind_country_db_path='')
        self.manager.init_coefficients()
        self.assertEquals(3, len(self.manager.coefficients['ip']))

    def test_load_malicious_networks(self):
        self.setUp_entries()
        self.manager.load_malicious_networks()
        self.assertIsNotNone(self.manager.malicious_networks)

    def test_get_credentials(self):
        user_id = self.user_foo['id']
        observed = self.manager.get_credentials(user_id)
        self.assertEqual(observed, [])

    def test_credential_create_verify(self):
        user_id = self.user_foo['id']
        passcode = self.manager.create_credential(user_id,
                                                  self.features, 0.0)
        credentials = self.manager.get_credentials(user_id)
        for credential in credentials:
            self.manager.verify_passcode(passcode, credential)
            self.assertRaises(AssertionError,
                              self.manager.verify_passcode,
                              '123', credential)

    @wip("Requires actual testing data in in tests/common/rba_dataset.csv file.")
    def test_M_hk(self):
        self.config_fixture.config(group='rba', maxmind_asn_db_path='')
        self.config_fixture.config(group='rba', maxmind_country_db_path='')
        self.manager.init_coefficients()
        self.setUp_entries()
        if len(self.entries) == 0:
            raise Exception
        observed = self.manager.M_hk('ip')
        self.assertEquals(3, observed)
        observed = self.manager.M_hk('ua')
        self.assertEquals(1, observed)
        observed = self.manager.M_hk('rtt')
        self.assertEquals(1, observed)


    def test_authenticate(self):
        self.config_fixture.config(group='rba', reject_threshold=10.0)
        self.config_fixture.config(group='rba', request_threshold=0.0015)
        user_id = self.user_foo['id']
        features = self.features['features']
        observed = self.manager.authenticate(user_id, features)
        observed = self.manager.authenticate(user_id, features)
        observed = self.manager.authenticate(user_id, features,
                                             observed['passcode'])
        observed = self.manager.authenticate(user_id, features)
        self.manager.authenticate(user_id, features)
        self.assertRaises(AssertionError, self.manager.authenticate,
                          user_id, features, observed['passcode'])
        observed = self.manager.authenticate(user_id, features)
        self.assertRaises(AssertionError, self.manager.authenticate,
                          user_id, features, '123')
        self.assertRaises(AssertionError, self.manager.authenticate,
                          user_id, None, '123')
        self.assertRaises(AssertionError, self.manager.authenticate,
                          user_id, None, None)
        self.config_fixture.config(group='rba', reject_threshold=0.008)
        self.assertRaises(AssertionError, self.manager.authenticate,
                          user_id, features)
