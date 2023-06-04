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

import functools
import itertools
import humanize
import numpy as np
import pandas as pd
import os
import socket
import time
import urllib
import uuid

from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.common import auth
from sklearn.model_selection import train_test_split
from sqlalchemy import create_engine
from sqlalchemy import text
from tqdm import tqdm
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Mapping
from typing import Sequence
from typing import Tuple
from typing import Union

PROVIDERS = provider_api.ProviderAPIs
# Some test cases rely on the configuration of resources from
# external providers to set up the Risk-Based Authentication (RBA)
# to include the ip address subfeature derivation, the lookup of maliciously
# noticed ip addresses and, especially for the functional testing,
# a login attempt feature value data set to perform authentication
# attemps to build up a sufficiently sized history.
# You will have to provide some of the resources by yourself to enable
# these tests, otherwise will they get skipped, if the required
# resources are not provided by changing their path below or by
# placing them in this files source folder 'tests/common'.
DIR = os.path.dirname(os.path.abspath(__file__))

# Included resources as example file:
MALICIOUS_ADDRESSES = os.path.join(DIR, 'malicious_addresses.netset')

# Not included resources, please provide yourself:
# The MaxMind, Inc GeoLite2 database files require an account
# and your consent to the terms of their end user license agreement
# to download for your setup.
# https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
ASN_DB = os.path.join(DIR, 'GeoLite2-ASN.mmdb')
CC_DB = os.path.join(DIR, 'GeoLite2-Country.mmdb')

# A data set of plausibly synthesized RBA login feature values has been
# provided to foster the research on RBA.
# The whole set is not included, as it takes unzipped about 9.05 GB of
# disk space. It can be downloaded at the following URL:
# https://github.com/das-group/rba-dataset/releases
DATASET = os.path.join(DIR, 'rba_dataset.csv')

# The following configuration can be set to use a connect to a running
# database management system. It was used during the functional testing
# to persist history entries and bypass the rebuild of temporary databases.
DBUSER = 'keystone'
DBPASS = urllib.parse.quote_plus(os.environ.get('KEYSTONE_DBPASS'))
HOST = socket.gethostbyaddr('10.0.0.11')[0]
# Hint: dialect+driver://username:password@host:port/database
DATABASE_URL = f'mysql+pymysql://{DBUSER}:{DBPASS}@{HOST}/keystone'


def time_measurement(start: float, end: float, in_ms: bool = False) -> float:
    """ Takes two measures of fractional seconds and returns their
    difference in seconds or milliseconds.
    """
    delta = end - start
    return delta * 1000 if in_ms else delta


def timing(function: Callable) -> Any:
    """ Timing decorator prints runtime in milliseconds of provided function.
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = function(*args, **kwargs)
        end_time = time.perf_counter()
        print("{:.5f}".format(time_measurement(start_time, end_time)),
              "s for", function.__name__)
        return result
    return wrapper


class RBATestMixin(auth.AuthTestMixin):
    engine = None

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

    def _build_features(self, ip=None, rtt=None, ua=None):
        features = {}
        if ip or ip == '':
            features.update({'ip': ip})
        if rtt or rtt == '':
            features.update({'rtt': rtt})
        if ua or ua == '':
            features.update({'ua': ua})
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
                         # usecols=[3, 4, 5, 6, 9, 10, 11, 12, 14],
                         usecols=[2, 3, 4, 5, 8, 9, 10, 11, 13],
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

    @classmethod
    def _create_db_engine(cls) -> None:
        if cls.engine is None:
            cls.engine = create_engine(DATABASE_URL,
                                       # connection_args=None,
                                       # creator=None,
                                       echo=False,
                                       echo_pool=False,
                                       # enable_from_linting=True,
                                       # execution_options={},
                                       future=False,
                                       # hide_parameters=False,
                                       # implicit_returning=True,
                                       # isolation_level=["SERIALIZABLE", "REPEATABLE READ",
                                       #                  "READ COMMITTED", "READ UNCOMMITTED",
                                       #                  "AUTOCOMMIT"][0],
                                       # json_deserializer=json.loads,
                                       # json_serializer=json.dumps,
                                       # label_length=None,
                                       # listeners=[PoolListener], # List if PoolListener objects,
                                       # that receive connection pool events
                                       # logging_name='name',
                                       # max_identifier_length=int, # None|0 no effect, sql names
                                       # max_overflow=10,
                                       # module=None,
                                       # paramstyle=None,
                                       # pool=None,
                                       # poolclass=None,
                                       # pool_logging_name='name',
                                       # pool_pre_ping=True,
                                       # pool_size=5,
                                       # pool_recycle=-1,
                                       # pool_reset_on_return=["rollback", "commit", None][0],
                                       # pool_timeout=30,
                                       # pool_use_lifo=False,
                                       # plugins=['pluginName'...],
                                       # query_cache_size=500, # 0 -> disable cache, 500 -> default
                                       )

    @classmethod
    @timing
    def _write_dataframe_to_sql(cls,
                                dataframe: pd.DataFrame,
                                filter_function: Union[Callable, None] = None,
                                insert_into: str = 'rba_dataset',
                                ) -> None:
        if filter_function:
            dataframe = filter_function(dataframe)
        cls._create_db_engine()
        dataframe.to_sql(
            name=insert_into,
            con=cls.engine,
            if_exists=('fail', 'replace', 'append')[1],
            index=False,
            index_label='index'
        )

    @classmethod
    @timing
    def _filter_login_successful(
            cls, dataframe: pd.DataFrame) -> pd.DataFrame:
        return dataframe.loc[np.isin(dataframe['ls'].to_numpy(), True)]

    @classmethod
    @timing
    def _read_dataframe_from_sql(
            cls,
            limit: Union[int, None] = None,
            select: str = '*',
            from_table: str = 'rba_dataset',
            where: Union[Mapping[str, Any], None] = None
    ) -> pd.DataFrame:
        sql = f"SELECT {select} FROM {from_table}"
        if where is not None:
            items = list(where.items())
            for k, v in items[:1]:
                sql += f" WHERE {from_table}.{k} = '{v}'"
            for k, v in items[1:]:
                sql += f" AND {from_table}.{k} = '{v}'"
        if limit is not None:
            sql += f" LIMIT {limit}"
        sql += ";"
        cls._create_db_engine()
        return pd.read_sql(
            sql=sql,
            con=cls.engine,
            index_col='index',
            coerce_float=True,
            parse_dates=None,
            columns=None,
            chunksize=None
        )

    @classmethod
    @timing
    def _load_dataset_as_dataframe(cls, n: int) -> pd.DataFrame:
        return pd.read_csv(DATASET,
                           header=0,
                           # usecols=[1, 3, 4, 5, 10, 14],
                           usecols=[0, 2, 3, 4, 9, 13],
                           # index,Timestamp,User_ID,RTT,IP,CC,Region,City,ASN,UA,BNV,OSNV,DT,
                           # Login Successful,Is Attack IP,Is Account Takeover
                           names=['index', 'user_id', 'rtt', 'ip', 'ua', 'ls'],
                           nrows=n,
                           dtype={'index': int, 'user_id': str, 'rtt': str,
                                  'ip': str, 'ua': str, 'ls': int},
                           skiprows=None,
                           # index_col='index',
                           na_values=['-'],
                           na_filter=False,
                           verbose=False,
                           true_values=['True'],
                           false_values=['False'],
                           low_memory=True,
                           )

    @classmethod
    def _sort_dataframe(cls, dataframe: pd.DataFrame,
                        colname: str = 'index',
                        inplace: bool = False) -> Union[pd.DataFrame, None]:
        return dataframe.sort_values(by=[colname], axis=0, inplace=inplace)

    @classmethod
    @timing
    def _build_user_refs_from_dataframe(cls, dataframe: pd.DataFrame
                                        ) -> List[Dict[str, str]]:
        """ Builds for each unique value of the 'user_id' labeled column of a
        pandas.DataFrame a dictionary with these as value for the 'id' key and
        sets up the necessary information randomly generated for a Keystone user
        in the DEFAULT_DOMAIN. Such a user information dictionary can be used to
        create a user in Keystone's back end with the use of its identity_api.
        Note, that the identity_api internally assigns another generated 'id' for a
        newly created user and returns a copied user information dictionary with
        the new 'id'. Therefore is this classmethod intended to set up a list of
        test user information dictionaries with assigned 'user_id's from the
        DataFrame to keep track and build a mapping during the actual creation
        with the _create_users_and_get_mapping method.

        :param pandas.DataFrame dataframe: A DataFrame of the pandas library
        with 'user_id' as a column label.
        :returns list user_refs: A list containing user information dictionaries
        with set up values for their 'id' key for each unique value in the
        dataframe column 'user_id'.
        """
        unique_users = dataframe['user_id'].unique()
        user_refs = [
            unit.new_user_ref(
                domain_id=default_fixtures.DEFAULT_DOMAIN_ID,
                project_id=None,
                id=user_id
            ) for user_id in tqdm(unique_users.tolist())]
        return user_refs

    # @timing
    # def _create_users(self, user_refs: Sequence[Mapping[str, str]]) -> None:
    #     for user_ref in tqdm(user_refs[:]):
    #         # print(user_ref)
    #         ref = PROVIDERS.identity_api.driver.create_user(
    #             user_ref.get('id'),
    #             user_ref)

    @timing
    def _create_users_and_get_mapping(self,
                                      user_refs: Sequence[Mapping[str, str]],
                                      bi_directional: bool = False
                                      ) -> Mapping[str, str]:
        """ Lets Keystone create users from listed user information
        dictionaries and returns a mapping dictionary for user_ids,
        as Keystone's identity_api ignores already contained user_ids and
        internally generates new user_ids as uuid4 hexadecimal string.
        The mapping key will be the old user_id and its value the user_id,
        that was written to the backend.
        Note that if no 'id' key is contained in a user_ref dictionary from
        the user_refs list, then will a random uuid4 hexadecimal string
        be set as value for the key to enable referencing.
        Optionally is bi-directional mapping with keys for both the new
        and old user_ids to their corresponding values.
        It should only be used if all user_ids are unique, otherwise they
        will get overwritten.

        :param list user_refs: A list containing user information as dictionary,
        obtained by keystone.tests.unit.new_user_ref or
        keystone.tests.unit.create_user functions, als well as by
        RBATestMixin._build_user_refs_from_dataframe classmethod.
        :param bool bi_directional: Default=False. If True, mapping of newly
        generated to previous user_ids gets also included in the returned
        dictionary.
        :returns dict mapping: A dictionary to map values of the 'id' key in
        user_ref dictionaries to Keystone's internally generated user_ids.
        """
        mapping = {}
        for user_ref in tqdm(user_refs):
            ref = PROVIDERS.identity_api.create_user(user_ref)
            mapping[user_ref.setdefault('id',
                                        uuid.uuid4().hex)] = ref.get('id')
            if bi_directional:
                mapping[ref.get('id')] = user_ref.get('id')
        return mapping

    def _get_user_entries_listed(self, dataframe: pd.DataFrame) -> list:
        return [self._get_listed_entries(df)
                for _, df in dataframe.groupby(by='user_id')]

    def _get_listed_entries(self, dataframe: pd.DataFrame) -> list:
        return dataframe.to_dict(orient='records')

    def _get_dataframes_listed(
            self, *args: Tuple[pd.DataFrame, ...]) -> Tuple[list, ...]:
        return tuple(map(self._get_listed_entries, args))

    def _limit_n_user_entries(self,
                              dataframe: pd.DataFrame,
                              n_foreach: int) -> pd.DataFrame:
        return dataframe.groupby(by='user_id').head(n_foreach)

    def _split_dataframe_by_column_value(
            self,
            dataframe: pd.DataFrame,
            column_name: str = 'user_id',
            value: Union[str, bool, int, float, None] = None) -> tuple:
        if value is None:
            value = dataframe.at[dataframe.index[0], column_name]
        df1 = dataframe.loc[np.in1d(dataframe[column_name].to_numpy(), value)]
        df2 = dataframe.drop(labels=df1.index.to_numpy(), axis=0)
        return df1, df2

    def _len_of_nested_list(self, nested_list: Sequence[Sequence]) -> int:
        return sum(map(len, nested_list))

    def _pop_n_list_entries(self,
                            entries_list: list,
                            n_entries: Union[int, None] = None) -> list:
        if n_entries is None:
            n_entries = len(entries_list)
        result = entries_list[:n_entries]
        entries_list = entries_list[n_entries:]
        return result

    def _pop_next_entry(self, entries_lists: list) -> dict:
        next_entry = {x[0].get('index'): i
                      for i, x in enumerate(entries_lists)
                      if x}
        if next_entry:
            index = next_entry.get(min(next_entry.keys()))
            next_entry = entries_lists[index].pop(0)
            self._remove_empty_lists(entries_lists, index)
        return next_entry

    def _pop_next_n_entries(self, entries_lists: list,
                            n_entries: Union[int, None] = None) -> list:
        n_entries = (self._len_of_nested_list(entries_lists)
                     if n_entries is None
                     else min(n_entries,
                              self._len_of_nested_list(entries_lists)))
        return [self._pop_next_entry(entries_lists)
                for i in range(n_entries)]

    def _remove_empty_lists(
            self, nested_list: list, index: Union[int, None] = None) -> int:
        count = 0
        if index is not None and not nested_list[index]:
            nested_list.pop(index)
            count = 1
        else:
            count = len([nested_list.pop(i)
                         for i, element in enumerate(nested_list)
                         if not element])
        return count

    def _sort_entries_in_order(self, *entries: Tuple[dict, ...]) -> tuple:
        entry_indices = {x.get('index'): i
                         for i, x in enumerate(entries)
                         if x}
        return tuple(entries[entry_indices.get(i)]
                     for i in sorted(entry_indices.keys()))

    def history(self, entries):
        history = {}
        for entry in entries:
            for feature, value in entry.items():
                item = history.setdefault(feature, {})
                item.setdefault(value, 0)
                history[feature][value] += 1
        return history

