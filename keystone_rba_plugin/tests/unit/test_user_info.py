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

from keystone import exception
from keystone.common import provider_api
from keystone.identity.backends import resource_options as ro
from keystone.tests.unit import test_backend_sql as base
from keystone.tests.unit.utils import wip

from keystone_rba_plugin.auth.plugins import core
from keystone_rba_plugin.tests.common import auth as common_auth

from pathlib import Path

ASN_DB = Path().resolve() / 'etc/GeoLite2-ASN.mmdb'
CC_DB = Path().resolve() / 'etc/GeoLite2-Country.mmdb'
PROVIDERS = provider_api.ProviderAPIs


class TestRBAUserInfo(base.SqlTests, common_auth.RBATestMixin):

    def setUp(self):
        super(TestRBAUserInfo, self).setUp()
        self.config_fixture.config(group='rba',
                                   features=['ip', 'rtt', 'ua'])
        self.user_info = core.RBAUserInfo()
        self._init_features()

    # From test_v3_auth.py but for user as argument
    def _update_user_with_MFA_rules(self, user, rule_list, rules_enabled=True):
        user = user.copy()
        # Do not update password
        user.pop('password')
        user['options'][ro.MFA_RULES_OPT.option_name] = rule_list
        user['options'][ro.MFA_ENABLED_OPT.option_name] = rules_enabled
        PROVIDERS.identity_api.update_user(user['id'], user)

    def test_validate_and_normalize(self):
        rule_list = [['password', 'rba'], ['rba']]
        func = self.user_info._validate_and_normalize_auth_data
        expected = exception.ValidationError
        self.config_fixture.config(group='rba', maxmind_asn_db_path=ASN_DB)
        self.config_fixture.config(group='rba', maxmind_country_db_path=CC_DB)
        auth_payload = self.build_authentication_request(
            user_id=self.user_foo['id'],
            username=self.user_foo['name'],
            features=self.features)['auth']['identity']['rba']

        self.config_fixture.config(group='rba', restrict_to_mfa=False)
        self._update_user_with_MFA_rules(self.user_foo, rule_list=rule_list,
                                         rules_enabled=False)
        func(auth_payload)
        observed = self.user_info.features
        self.assertIsNotNone(observed)
        self.config_fixture.config(group='rba', restrict_to_mfa=True)
        self.assertRaises(expected, func, auth_payload)
        self.config_fixture.config(group='rba', restrict_to_mfa=False)
        self._update_user_with_MFA_rules(self.user_foo, rule_list=rule_list,
                                         rules_enabled=True)
        func(auth_payload)
        self.config_fixture.config(group='rba', restrict_to_mfa=True)
        func(auth_payload)

    @wip("Requires set up ASN_DB and CC_DB path.")
    def test_validate_and_normalize_ip(self):
        func = self.user_info._validate_and_normalize_ip
        expected = {'ip': '10.0.0.0'}
        observed = func('10.0.0.0')
        self.assertEqual(expected, observed)
        self.config_fixture.config(group='rba',
                                   maxmind_asn_db_path=ASN_DB)
        observed = func('10.0.0.0')
        expected['asn'] = ''
        self.assertRaises(exception.ValidationError, func, '1234')
        self.assertEqual(expected, observed)
        self.config_fixture.config(group='rba',
                                   maxmind_country_db_path=CC_DB)
        observed = func('10.0.0.0')
        expected['cc'] = ''
        self.assertEqual(expected, observed)
        address = '13.14.19.140'
        expected['ip'] = address
        observed = func(address)
        self.assertIn(address, observed['ip'])
        self.assertRaises(exception.ValidationError, func, '1234')
        address = '2221:0db8:85a3:08d3:1319:8a2e:0370:7347'
        expected['ip'] = address
        observed = func(address)
        self.assertIn(address, observed['ip'])

    def test_validate_and_normalize_rtt(self):
        func = self.user_info._validate_and_normalize_rtt
        expected = '100'
        observed = func('51')['rtt']
        self.assertEqual(expected, observed)
        expected = '0'
        observed = func(50)['rtt']
        self.assertEqual(expected, observed)
        expected = '500'
        observed = func('501')['rtt']
        self.assertEqual(expected, observed)
        expected = '1400'
        observed = func('1361')['rtt']
        self.assertEqual(expected, observed)
        expected = '1300'
        observed = func('1341')['rtt']
        self.assertEqual(expected, observed)
        expected = '100'
        observed = func('105.879')['rtt']
        self.assertEqual(expected, observed)
        expected = ''
        observed = func('')['rtt']
        self.assertEqual(expected, observed)
        self.assertRaises(exception.ValidationError, func, {'': []})
        self.assertRaises(exception.ValidationError, func, -307)
        self.assertRaises(exception.ValidationError, func, 'abc')
        self.assertRaises(exception.ValidationError, func, None)

    def test_validate_and_normalize_ua(self):
        func = self.user_info._validate_and_normalize_ua
        ua_string = 'Mozilla/5.0  (iPhone; CPU iPhone OS 13_5_5 like Mac OS X) AppleWebKit/523.10 (KHTML, like Gecko Version/4.0 Mobile Safari/523.10'
        expected = 4
        observed = len(func(ua_string))
        self.assertEqual(expected, observed)
        ua_string = '523.10 (KHTML, like Gecko Version/ Safari/523.10'
        observed = func(ua_string)
        self.assertEqual(expected, len(observed))
        ua_string = ''
        observed = func(ua_string)
        self.assertEqual(expected, len(observed))
