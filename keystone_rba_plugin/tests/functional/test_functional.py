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

import copy
import os
import math
import http.client
import numpy as np
from keystone.tests.unit import test_backend_sql as base
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.utils import wip
from keystone_rba_plugin import conf
from keystone_rba_plugin.auth.plugins import core as user_info
from keystone_rba_plugin.rba import core
from keystone_rba_plugin.tests.common import auth
from pathlib import Path


MALICIOUS_ADDRESSES = os.path.join(auth.DIR, 'malicious_addresses.netset')
CONF = conf.CONF
ASN_DB = Path().resolve() / 'etc/GeoLite2-ASN.mmdb'
CC_DB = Path().resolve() / 'etc/GeoLite2-Country.mmdb'

class TestFunctional(base.SqlTests, auth.RBATestMixin):
    def setUp(self):
        super(TestFunctional, self).setUp()
        self.config_fixture.config(group='rba', driver='sql')
        self.config_fixture.config(group='rba', features=['ip', 'rtt', 'ua'])
        self.config_fixture.config(group='rba', reject_threshold=0.9)
        self.config_fixture.config(group='rba', request_threshold=0.4)
        self.config_fixture.config(group='rba', messenger=None)
        self.config_fixture.config(group='rba', max_user_history_size=10000)
        self.config_fixture.config(group='rba', maxmind_asn_db_path=ASN_DB)
        self.config_fixture.config(group='rba', maxmind_country_db_path=CC_DB)
        self.config_fixture.config(group='rba', restrict_to_mfa=False)
        self.config_fixture.config(group='rba',
                                   maxmind_asn_db_path=ASN_DB)
        self.config_fixture.config(group='rba',
                                   maxmind_country_db_path=CC_DB)
        self.config_fixture.config(group='rba',
                                   malicious_ip_list_path=MALICIOUS_ADDRESSES)
        self.entries, self.users = self._build_test_entries()
        self.domain_id = default_fixtures.DEFAULT_DOMAIN_ID
        self.manager = core.RBAManager()
        self.authenticate = self.manager.authenticate
        self.user_info = user_info.RBAUserInfo()

    def features_(self, features):
        features_ = {}
        for feature in CONF.rba.features:
            features_.update(
                self.user_info._validate_and_normalize_feature[
                    feature](features[feature]))
        return features_

    @wip("Requires actual testing data in in tests/common/rba_dataset.csv file.")
    def test_authenticate(self):
        self.config_fixture.config(group='rba', reject_threshold=0.9)
        self.config_fixture.config(group='rba', request_threshold=0.8)
        self.entries, self.users = self._build_test_entries()

        if len(self.entries) == 0:
            raise Exception

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
