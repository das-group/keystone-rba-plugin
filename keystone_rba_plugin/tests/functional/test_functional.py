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
import datetime
import fixtures
import humanize
import numpy as np
import os
import pandas as pd
import unittest
import testtools
import time

from keystone.common import sql
from keystone.common import resource_options
from keystone.identity.backends import base as identity_base
from keystone.identity.backends import sql_model as identity_model
from keystone.tests.unit import test_backend_sql as base
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.utils import wip
from oslo_db import api as oslo_db_api
from pathlib import Path
from sqlalchemy import delete
from sqlalchemy import distinct
from sqlalchemy import select
from sqlalchemy.sql import functions as fn
from testtools import content
from tqdm import tqdm
from typing import Any
from typing import Callable
from typing import Mapping
from typing import Sequence
from typing import Union
from keystone_rba_plugin import conf
from keystone_rba_plugin.auth.plugins import core as user_info
from keystone_rba_plugin.rba import core
from keystone_rba_plugin.rba.backends import sql_model as model
from keystone_rba_plugin.tests.common import auth
try:
    from keystone_rba_plugin.tests.functional import rba_algorithm as ri
except ImportError:
    ri = None

timing = auth.timing
CONF = conf.CONF
ASN_DB = auth.ASN_DB
CC_DB = auth.CC_DB
BACKEND_SQL_CONF = Path(__file__).parent / 'config_files/backend_sql.conf'
SKIP = True

class TestFunctional(base.SqlTests, auth.RBATestMixin):

    @classmethod
    def setUpClass(cls):
        super(TestFunctional, cls).setUpClass()
        if (auth.DATASET is None or ASN_DB is None or CC_DB is None or SKIP):
            raise unittest.SkipTest("Missing dataset")
        cls.user_info = user_info.RBAUserInfo()
        # pd.set_option("display.width", 200)
        pd.set_option("display.max_colwidth", 300)
        # maximum entries 31,269,265
        cls.n_entries = [2000000,  # Written to mariadb keystone/rba_dataset
                         1000000,  # Default of reference implementation
                         500000, 100000, 60000, 40000, 30001, 20000, 500, 1][4]
        cls.use_mapping = [True, False][1]
        reference_test = [True, False][1]
        if reference_test and ri is not None:
            ri.init_global_logs(cls.n_entries)
            cls.df = ri.global_logs_.rename(
                columns={'userid': 'user_id',
                         'requestXRealIP': 'ip',
                         'ipASN': 'asn',
                         'ipCountry': 'cc',
                         'browser_name_version': 'bv',
                         'os_name_version': 'osv',
                         'device_type': 'df',
                         'trackingdatauserAgent': 'ua'},
                inplace=False)
        else:
            # cls.df = cls._load_dataset_as_dataframe(cls.n_entries)
            # cls._write_dataframe_to_sql(cls.df)
            cls.df = cls._read_dataframe_from_sql(limit=cls.n_entries,
                                                  where={'ls': 1})
        cls.user_refs = cls._build_user_refs_from_dataframe(cls.df)
        cls.available_users = cls.df['user_id'].nunique()
        cls.available_entries = len(cls.df)
        # For 100000 ls entries are these rtt values unseen
        cls.unseen_rtts = ['34300', '26300', '15300', '11800', '15100',
                           '31300', '10300', '53600', '21000', '36200',
                           '12500', '7100', '9400', '10100', '10300']

    def setUp(self):
        super(TestFunctional, self).setUp()
        self.config(self.config_files())
        self.config_fixture.config(group='rba', driver='sql')
        self.config_fixture.config(group='rba', features=['ip', 'rtt', 'ua'])
        self.config_fixture.config(group='rba', reject_threshold=10.0)
        self.config_fixture.config(group='rba', request_threshold=10.0)
        self.config_fixture.config(group='rba', messenger=None)
        self.config_fixture.config(group='rba', max_user_history_size=None)
        self.config_fixture.config(group='rba', maxmind_asn_db_path=ASN_DB)
        self.config_fixture.config(group='rba', maxmind_country_db_path=CC_DB)
        self.config_fixture.config(group='rba', restrict_to_mfa=False)
        self.rba_api = core.RBAManager()
        self.prepare_users()

    def prepare_users(self):
        if type(self).use_mapping:
            self.mapping = self._create_users_and_get_mapping(
                type(self).user_refs[:type(self).available_users])
        else:
            # Faster user creation with bundled insertions in a sql session.
            self.create_users(type(self).user_refs, chunk_size=10000)
            # Monkey patch RBAManager.authenticate method to circumvent threshold evaluation
            self.rba_api.authenticate = self.authenticate
            self.mapping = {}

    @classmethod
    def tearDownClass(cls):
        super(TestFunctional, cls).tearDownClass()

    def config_overrides(self):
        super(TestFunctional, self).config_overrides()

    def config_files(self):
        config_files = super(TestFunctional, self).config_files()
        config_files.append(BACKEND_SQL_CONF)
        return config_files

    def build_features(self, entry: Mapping[str, Any]):
        features = {}
        for feature in CONF.rba.features:
            features.update(
                type(self).user_info
                ._validate_and_normalize_feature[feature](entry[feature]))
        return features

    def count_history_users(self) -> int:
        with sql.session_for_read() as session:
            query = select(fn.count(distinct(model.History.user_id)))
            return session.execute(query).scalar()

    def count_history_entries(self) -> int:
        with sql.session_for_read() as session:
            query = select(fn.count(model.History.confidence_score))
            return session.execute(query).scalar()

    def count_history_user_entries(self, user_id) -> int:
        return self.rba_api.driver.count_entries_by_user(
            self.map_user(user_id))

    @sql.handle_conflicts(conflict_type='user')
    def create_users(self, user_refs, chunk_size: Union[int, None] = None):
        filtered_refs = []
        if chunk_size is None:
            chunk_size = len(user_refs)
        progress = tqdm(total=len(user_refs))
        for i in range(0, len(user_refs), chunk_size):
            chunk = user_refs[i:i + chunk_size]
            with sql.session_for_write() as session:
                for user in chunk:
                    user_ref = identity_model.User.from_dict(user)
                    session.add(user_ref)
                    # Set resource options passed on creation
                    resource_options.resource_options_ref_to_mapper(
                        user_ref, identity_model.UserOption)
                    filtered_refs.append(identity_base.filter_user(
                        user_ref.to_dict()))
                    progress.update(n=1)
        progress.close()
        return filtered_refs

    def delete_latest_user_entries(self, user_id: str,
                                   n_entries: int = 1) -> None:
        with sql.session_for_write() as session:
            query = (select(model.History)
                     .where(model.History.user_id == self.map_user(user_id))
                     .order_by(model.History.successful_auth_at.desc())
                     .limit(n_entries))
            rows = session.execute(query).all()
            for row in rows:
                session.delete(row[0])
        self.rba_api.load_histories()

    def get_score_mean(self,
                       filter_value: Union[float, None] = None,
                       limit: Union[int, None] = None) -> float:
        with sql.session_for_read() as session:
            query = select(model.History.confidence_score)
            res = session.execute(query).all()[:limit]
            if isinstance(filter_value, float):
                res = list(filter((lambda x: not x[0] == filter_value), res))
            return float(np.mean(res))

    def get_recent_user_score(self, user_id: str) -> float:
        with sql.session_for_read() as session:
            query = (select(model.History.confidence_score).
                     where(model.History.user_id == self.map_user(user_id)).
                     order_by(model.History.successful_auth_at.desc()).
                     limit(1))
            return session.execute(query).scalar()

    def get_history_user_entries(self, user_id: str, n_entries: int = 1):
        with sql.session_for_read() as session:
            query = (select(model.History).
                     where(model.History.user_id == self.map_user(user_id)).
                     limit(n_entries))
            rows = session.execute(query).all()
            return [{attribute: row[0][attribute]
                    for attribute in model.History.attributes}
                    for row in rows]

    def get_distance_to_threshold(self, value: float,
                                  threshold: str = 'request_threshold'):
        threshold_value = CONF.rba[threshold]
        distance = np.linalg.norm(threshold_value - value)
        return distance

    def set_threshold(self, value: float, threshold: str) -> None:
        self.config_fixture.config(group='rba', **{threshold: value})

    def set_threshold_as_discounted_mean(
            self,
            discount: Union[float, None] = None,
            discount_factor: float = 0.1,
            filter_value: Union[float, None] = 0.0,
            threshold: str = 'request_threshold') -> None:
        mean = self.get_score_mean(filter_value)
        if discount is None:
            distance = self.get_distance_to_threshold(mean, threshold)
            discount = distance * discount_factor
        self.set_threshold(mean + discount, threshold)

    def map_users(self, user_id_list: Sequence[str]) -> list:
        return [self.map_user(user_id) for user_id in user_id_list]

    def map_user(self, user_id: str) -> str:
        return self.mapping.get(user_id, user_id)

    def compare_with_score_mean(self, score: float):
        mean = self.get_score_mean(limit=-1)

    def authenticate(self, user_id, features=None, passcode=None) -> float:
        api = self.rba_api
        score = api.confidence_score(user_id, features)
        api.add_features(user_id, features, score)
        return score

    def authenticate_entry(self, entry: Mapping[str, Any],
                           normalize: bool = True) -> None:
        if entry:
            user_id = self.map_user(entry.get('user_id'))
            if normalize:
                features = self.build_features(entry)
            else:
                features = {}
                for feature in self.rba_api.coefficients.values():
                    for subfeature in feature.keys():
                        features[subfeature] = entry.get(subfeature, '')
            response = self.rba_api.authenticate(user_id=user_id,
                                                 features=features)
            if self.use_mapping:
                score = self.get_recent_user_score(user_id)
                if response:
                    pass
            else:
                score = response
            return score

    @timing
    def authenticate_entries(self, entries: Sequence[Mapping[str, Any]],
                                n: Union[int, None] = None) -> Union[list, None]:
        if n is None:
            n = len(entries)
        rest = entries[n:]
        for entry in tqdm(entries[:n]):
            self.authenticate_entry(entry)
        return rest if rest else None

    @timing
    def calculate_risk_scores(self,
                              entries: Sequence[Mapping[str, Any]],
                              filter_value: Union[float, None] = 0.0,
                              normalize: bool = True,
                              start_index=1,
                              ) -> list:
        index = []
        risk_scores = {'ks_risk_score': []}
        for i, entry in tqdm(enumerate(entries)):
            risk_score = self.authenticate_entry(entry, normalize=normalize)
            index.append(i + start_index)
            risk_scores['ks_risk_score'].append(risk_score)
        results = pd.DataFrame(risk_scores, index=index)
        results.index.name = 'Login Attempt'
        return (results if filter_value is None
                else results.loc[results['ks_risk_score'] != filter_value])

    def config_features(self, features: Sequence[str]) -> None:
        self.config_fixture.config(group='rba', features=features)
        self.rba_api.init_coefficients()

    @testtools.skip("Skip test to reduce resource utilization.")
    def test_reference(self):
        if ri is None:
            raise unittest.SkipTest("Missing reference implementation.")
        # Configure supported plug-in features to conform reference
        self.config_features(features=['ip', 'ua'])
        # Convert dataset to a list of row record dictionaries.
        log_entries = type(self).df.to_dict(orient='records')
        # Calculate risk scores
        start, amount = 0, 50000
        # start, amount = 0, 67
        ri_risk_scores = ri.login_test_single(
            slice_start=start, slice_size=amount)
        ri_risk_scores.to_csv(path_or_buf='rba-algorithm-output0-50000.csv')
        # ri_risk_scores = ri.login_test_single(
        #     slice_start=start, slice_size=amount)['risk_score']
        # ks_risk_scores = self.calculate_risk_scores(
        #     log_entries[start:start + amount],
        #     filter_value=0.0,
        #     normalize=[True, False][1])
        # lai_df = pd.concat([ri.lai_df, self.lai_df], ignore_index=True)
        # self.assertEqual(len(ri_risk_scores), len(ks_risk_scores))
        # ks_risk_scores['ri_index'] = ri_risk_scores.index
        # ks_risk_scores['ri_risk_score'] = ri_risk_scores.values
        # risk_scores = ks_risk_scores[['ri_risk_score', 'ks_risk_score']]
        # pd.set_option('display.float_format', '{:.10f}'.format)
        # risk_scores.to_csv(path_or_buf='risk_scores.csv',
        #                    sep='&',
        #                    line_terminator=' \\\\' + os.linesep,
        #                    # qoutechar='"',
        #                    doublequote=False,
        #                    # escapechar='?',
        #                    header=['Reference Risk Scores',
        #                            'Plug-in Risk Scores'],
        #                    index_label='Login Attempt')
        # slices = [i for i in range(10,12)] + [i for i in range(25,28)]
        # risk_scores[risk_scores.index.isin(slices)]
        # risk_scores.loc[risk_scores.index.isin(
        #     np.r_[60:80, 300:400])].to_latex(
        # risk_scores.to_latex(
        #     buf='risk_scores.tex',
        #     header=['Reference Risk Scores',
        #             'Plug-in Risk Scores'],
        #     float_format="{:0.10f}".format,
        #     label="tab:risk_scores",
        #     caption="Comparison of selected risk scores sequentially calculated by the reference and Keystone plug-in implementation for successful login attempts of the RBA dataset",
        # )

    @testtools.skip("Skip test to run another.")
    def test_find_unseen_rtt(self):
        ls_df = type(self)._read_dataframe_from_sql(
            where={'ls': 1}, nrows=1000000)
        not_ls_df = type(self)._read_dataframe_from_sql(
            where={'ls': 0}, nrows=1000000)
        norm_rtt = type(self).user_info._validate_and_normalize_rtt
        seen_unique_rtts = np.array([norm_rtt(x)['rtt']
                                     for x in ls_df['rtt'].unique()])
        unseen_unique_rtts = np.array([norm_rtt(x)['rtt']
                                       for x in not_ls_df['rtt'].unique()])
        criteria_rtt = timing(np.isin)(unseen_unique_rtts,
                                       seen_unique_rtts, invert=True)

    @testtools.skip("Skip test to run another.")
    def test_unseen_user_with_user_count_0_history_size_0(self):
        user_count = 1
        df = type(self).dataframe.head(user_count)
        test_entry = df.to_dict(orient='records').pop()
        timing(self.authenticate_entry)(test_entry)

    @testtools.skip("Skip test to run another.")
    def test_unseen_user_with_user_count_10_history_size_100(self):
        user_amount = 11
        df = type(self).dataframe.head(15000)
        # Select n user_ids of the largest occurencies
        user_id_counts = df['user_id'].value_counts().nlargest(user_amount, keep='all')
        # Get all entry rows for a test user as dataframe
        test_user_id = user_id_counts.index[0]
        test_user_df = df.loc[np.in1d(
            df['user_id'].to_numpy(), test_user_id)]
        # Get entry rows for building the history without test user's rows
        others_df = df[df['user_id'].isin(
            user_id_counts.index[1:user_amount].to_numpy())]
        # Convert dataframes to lists of row value dictionaries with labels as keys
        test_entries = test_user_df.to_dict(orient='records')
        # history_entries = history_df.to_dict(orient='records')
        history_df = self._limit_n_user_entries(others_df, 10)
        history_entries = self._get_user_entries_listed(history_df)
        history_entries = self._pop_n_next_in_order_entries(history_entries, 100)
        # Invoke authentication with listed entries to build history
        self.authenticate_entries(history_entries)
        # Test authentication for unseen user
        self.authenticate_entries(test_entries, 1)

    @testtools.skip("Skip test to run another.")
    def test_seen_user_seen_features_with_user_count_10_history_size_100(self):
        user_amount = 11
        df = type(self).dataframe.head(15000)
        df = df.loc[np.isin(df['ls'].to_numpy(), True)]
        # Select n user_ids of the largest occurencies
        user_id_counts = df['user_id'].value_counts().nlargest(
            user_amount, keep='all')
        # Get all entry rows for a test user as dataframe
        test_user_id = user_id_counts.index[0]
        test_user_df = df.loc[np.in1d(
            df['user_id'].to_numpy(), test_user_id)]
        # Get entry rows for building the history without test user's rows
        others_df = df[df['user_id'].isin(
            user_id_counts.index[1:user_amount].to_numpy())]
        # Convert dataframes to lists of row value dictionaries with labels as keys
        test_entries = test_user_df.to_dict(orient='records')
        history_df = self._limit_n_user_entries(others_df, n_foreach=10)
        history_entries_listed = self._get_user_entries_listed(history_df)
        history_entries = self._pop_next_n_entries(history_entries_listed,
                                                   n_entries=100)
        # Authentication of test user entry to be seen
        test_entry = test_entries[0]
        timing(self.authenticate_entry)(test_entry)
        recent_score = self.get_recent_user_score(test_user_id)
        score_mean = self.get_score_mean()
        # Invoke authentication with listed entries to build history
        self.authenticate_entries(history_entries)
        score_mean = self.get_score_mean()
        filtered_score_mean = self.get_score_mean(0.0)
        # Test authentication for seen test user with seen features
        timing(self.authenticate_entry)(test_entry)
        recent_score = self.get_recent_user_score(test_user_id)
        score_mean = self.get_score_mean()
        filtered_score_mean = self.get_score_mean(0.0)

    @testtools.skip("Skip test to run another.")
    def test_seen_user_unseen_features(self):
        # user_amount = 11
        user_amount = None
        df = type(self).df
        # df = df.loc[np.isin(df['ls'].to_numpy(), True)]
        # Select n user_ids of the largest occurencies
        # user_id_counts = df['user_id'].value_counts().nlargest(user_amount,
                                                               # keep='all')
        user_id_counts = df['user_id'].value_counts().sort_values(ascending=False)
        # Get all entry rows for a test user as dataframe
        test_user_id = user_id_counts.index[0]
        test_user_df = df.loc[np.in1d(
            df['user_id'].to_numpy(), test_user_id)]
        # Get entry rows for building the history without test user's rows
        others_df = df[df['user_id'].isin(
            user_id_counts.index[1:user_amount].to_numpy())]
        # Convert dataframes to lists of row value dictionaries with labels as keys
        test_entries = test_user_df.to_dict(orient='records')
        history_df = self._limit_n_user_entries(others_df, 10)
        history_entries = self._get_listed_entries(history_df.iloc[:100])
        # history_entries = self._get_listed_entries(history_df.iloc[100:200])

        # Authentication of test user entry to be seen
        test_entry = test_entries[0]
        timing(self.authenticate_entry)(test_entry)

        # Invoke authentication with listed entries to build history
        self.authenticate_entries(history_entries)

        seen_df = history_df + test_user_df.iloc[0]
        test_user_nls_df = type(self)._read_dataframe_from_sql(
            where={'ls': 0, 'user_id': test_user_id})
        criteria_ip = timing(np.isin)(test_user_nls_df['ip'].to_numpy(),
                                      seen_df['ip'].to_numpy(), invert=True)
        criteria_ua = timing(np.isin)(test_user_nls_df['ua'].to_numpy(),
                                      seen_df['ua'].to_numpy(), invert=True)

        unseen_ips = test_user_nls_df.loc[criteria_ip]['ip']
        unseen_rtts = type(self).unseen_rtts
        unseen_uas = test_user_nls_df.loc[criteria_ua]['ua']
        seen_test_entry = test_entry.copy()
        # Test user entry partially unseen and unseen
        history_entries = self.authenticate_entries(history_entries, 100)
        # Partially unseen ip
        test_entry['ip'] = unseen_ips[0]
        mean = self.get_score_mean()
        score = timing(self.authenticate_entry)(test_entry)
        self.delete_latest_user_entries(test_user_id, n_entries=1)

        # Partially unseen ip and rtt
        test_entry['rtt'] = unseen_rtts[0]
        mean = self.get_score_mean()
        score = timing(self.authenticate_entry)(test_entry)
        self.delete_latest_user_entries(test_user_id, n_entries=1)

        # Fully unseen ip, rtt, ua
        test_entry['ua'] = unseen_uas[0]
        mean = self.get_score_mean()
        score = timing(self.authenticate_entry)(test_entry)
        self.delete_latest_user_entries(test_user_id, n_entries=1)

        test_entry = seen_test_entry
        # Partially unseen rtt
        test_entry['rtt'] = unseen_rtts[0]
        mean = self.get_score_mean()
        score = timing(self.authenticate_entry)(test_entry)
        self.delete_latest_user_entries(test_user_id, n_entries=1)

        # Partially unseen rtt and ua
        test_entry['ua'] = unseen_uas[0]
        mean = self.get_score_mean()
        score = timing(self.authenticate_entry)(test_entry)
        self.delete_latest_user_entries(test_user_id, n_entries=1)

        test_entry = seen_test_entry
        # Partially unseen ua
        test_entry['ua'] = unseen_uas[0]
        mean = self.get_score_mean()
        score = timing(self.authenticate_entry)(test_entry)
        self.delete_latest_user_entries(test_user_id, n_entries=1)
