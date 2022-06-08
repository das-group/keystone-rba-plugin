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

import pandas as pd
import os
from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.common import auth
from sklearn.model_selection import train_test_split

PROVIDERS = provider_api.ProviderAPIs
DIR = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(DIR, 'rba_dataset.csv')

class RBATestMixin(auth.AuthTestMixin):

    def _init_features(self):
        self.features = self._build_features(
            ip='13.14.19.140',
            rtt='1234',
            ua='Mozilla/5.0  (iPhone; CPU iPhone OS 13_5_5 like Mac OS X) AppleWebKit/523.10 (KHTML, like Gecko Version/4.0 Mobile Safari/523.10'
        )

    def build_authentication_request(self,
                                     token=None,
                                     user_id=None,
                                     username=None,
                                     user_domain_id=None,
                                     user_domain_name=None,
                                     password=None,
                                     kerberos=False,
                                     passcode=None,
                                     app_cred_id=None,
                                     app_cred_name=None,
                                     secret=None,
                                     rba_passcode=None,
                                     features=None,
                                     **kwargs):
        auth_data = super(RBATestMixin, self).build_authentication_request(
            token=token,
            user_id=user_id,
            username=username,
            user_domain_id=user_domain_id,
            user_domain_name=user_domain_name,
            password=password,
            kerberos=kerberos,
            passcode=passcode,
            app_cred_id=app_cred_id,
            app_cred_name=app_cred_name,
            secret=secret,
            **kwargs)['auth']
        if rba_passcode and (user_id or username):
            auth_data['identity']['methods'].append('rba')
            auth_data['identity']['rba'] = self._build_auth(
                user_id, username, user_domain_id, user_domain_name,
                passcode=rba_passcode)
        if features and (user_id or username):
            if not rba_passcode:
                auth_data['identity']['methods'].append('rba')
                auth_data['identity']['rba'] = {}
                auth_data['identity']['rba']['user'] = self._build_user(
                    user_id, username,
                    user_domain_id, user_domain_name)
            auth_data['identity']['rba']['user'].update(features)
        return {'auth': auth_data}

    def _build_features(self, ip=None, rtt=None, ua=None, bn=None,
                              bv=None, osn=None, osv=None):
        features = {}
        if ip or ip == '':
            features.update({'ip': ip})
        if rtt or rtt == '':
            features.update({'rtt': rtt})
        if ua or ua == '':
            features.update({'ua': ua})
        if bn or bn == '':
            features.update({'bn': bn})
        if bv or bv == '':
            features.update({'bv': bv})
        if osn or osn == '':
            features.update({'osn': osn})
        if osv or osv == '':
            features.update({'osv': osv})
        return {'features': features}

    def _build_users(self, amount):
        user_list = []
        for i in range(amount):
            user_list.append(
                unit.create_user(
                    PROVIDERS.identity_api,
                    default_fixtures.DEFAULT_DOMAIN_ID
                ))
        return user_list

    def _build_test_entries(self):
        sets = self._load_rba_dataset()
        users = self._build_users(len(sets))
        entries = {}
        for user, entry in zip(users, sets):
            entries[user['id']] = entry
        return entries, users

    def _load_rba_dataset(self):
        df = pd.read_csv(DATASET,
                         header=0,
                         usecols=[3, 4, 5, 6, 9, 10, 11, 12, 14],
                         names=['user_id', 'rtt', 'ip', 'cc', 'asn',
                                'ua', 'bf', 'osf', 'ls'],
                         nrows=200,
                         dtype=str,
                         skiprows=None,
                         na_values=['-'],
                         na_filter=False,
                         verbose=False,
                         )
        dfs = [x for _, x in df.groupby(by='user_id')]
        sets = []
        for frame in dfs:
            del frame['user_id']
            cases = [x for _, x in frame.groupby(by='ls')]
            if len(cases) < 2:
                continue
            del cases[0]['ls']
            del cases[1]['ls']
            total_successes = cases[1].to_dict(orient='records')
            try:
                train, test = train_test_split(total_successes,
                                               test_size=0.2,
                                               shuffle=False)
            except ValueError:
                continue
            user_set = {
                'ls': train,
                'ts': test,
                'tns': cases[0].to_dict(orient='records')}
            sets.append(user_set)
        return sets

    def history(self, entries):
        history = {}
        for entry in entries:
            for feature, value in entry.items():
                item = history.setdefault(feature, {})
                item.setdefault(value, 0)
                history[feature][value] += 1
        return history
