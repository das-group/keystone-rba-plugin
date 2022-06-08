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
import fixtures
import freezegun
import http.client
import os

from keystone import exception
from keystone.common import provider_api
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import test_v3_auth
from keystone.tests.unit import test_auth_plugin
from keystone.tests.unit import utils #@wip()

from keystone_rba_plugin.auth.plugins import rba
from keystone_rba_plugin.tests.common import auth

from oslo_serialization import jsonutils
from oslo_utils import timeutils
from pathlib import Path

ASN_DB = Path().resolve() / 'etc/GeoLite2-ASN.mmdb'
CC_DB = Path().resolve() / 'etc/GeoLite2-Country.mmdb'
MALICIOUS_ADDRESSES = os.path.join(auth.DIR, 'malicious_addresses.netset')


class TestRiskBasedAuthentication(test_v3_auth.TestMFARules, auth.RBATestMixin):

    def setUp(self):
        super(TestRiskBasedAuthentication, self).setUp()
        self.config_fixture.config(group='rba', driver='sql')
        self.config_fixture.config(group='rba', features=['ip', 'rtt', 'ua'])
        self.config_fixture.config(group='rba', reject_threshold=0.9)
        self.config_fixture.config(group='rba', request_threshold=0.4)
        self.config_fixture.config(group='rba', max_user_history_size=10)
        self.config_fixture.config(group='rba', restrict_to_mfa=False)
        self.config_fixture.config(group='rba',
                                   maxmind_asn_db_path=ASN_DB)
        self.config_fixture.config(group='rba',
                                   maxmind_country_db_path=CC_DB)
        self.config_fixture.config(group='rba',
                                   malicious_ip_list_path=MALICIOUS_ADDRESSES)
        self._init_features()

    def auth_plugin_config_override(self, methods=None, **method_classes):
        if not methods:
            methods = ['rba', 'token', 'password', 'totp']
        super(test_v3_auth.TestMFARules,
              self).auth_plugin_config_override(methods)

    def config_overrides(self):
        super(TestRiskBasedAuthentication, self).config_overrides()

    def test_authenticate_with_restriction_to_MFA(self):
        self.config_fixture.config(group='rba', restrict_to_mfa=True)
        rule_list = [['password', 'rba'], ['rba']]
        self._update_user_with_MFA_rules(rule_list=rule_list,
                                         rules_enabled=False)
        self.v3_create_token(
            self.build_authentication_request(
                user_id=self.user_id,
                user_domain_id=self.domain_id,
                features=self.features),
            expected_status=http.client.BAD_REQUEST)
        self._update_user_with_MFA_rules(rule_list=rule_list,
                                         rules_enabled=True)
        self.v3_create_token(
            self.build_authentication_request(
                user_id=self.user_id,
                user_domain_id=self.domain_id,
                features=self.features),
            expected_status=http.client.CREATED)

    def test_authenticate_once_with_features(self):
        rule_list = [['password', 'rba'], ['rba']]
        self._update_user_with_MFA_rules(rule_list=rule_list)
        response = self.v3_create_token(
            self.build_authentication_request(
                user_id=self.user_id,
                user_domain_id=self.domain_id,
                features=self.features,
                rba_passcode=None
            ),
            expected_status=http.client.CREATED)

    def test_authenticate_with_features_and_passcode(self):
        self.config_fixture.config(group='rba', request_threshold=0.1)
        response = self.v3_create_token(
            self.build_authentication_request(
                user_id=self.user_id,
                user_domain_id=self.domain_id,
                features=self.features,
                rba_passcode=None
            ),
            expected_status=http.client.CREATED)
        response = self.v3_create_token(
            self.build_authentication_request(
                user_id=self.user_id,
                user_domain_id=self.domain_id,
                features=self.features,
                rba_passcode=None
            ),
            expected_status=http.client.UNAUTHORIZED)
        passcode = jsonutils.loads(response.text)[
            'error']['identity']['rba']['passcode']
        response = self.v3_create_token(
            self.build_authentication_request(
                user_id=self.user_id,
                user_domain_id=self.domain_id,
                rba_passcode=passcode
            ),
            expected_status=http.client.CREATED)

