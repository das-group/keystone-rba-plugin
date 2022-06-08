# Copyright 2022 Vincent Unsel
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

import sqlalchemy as sql
from migrate import *
from keystone.common import sql as ks_sql

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    table = sql.Table(
        'rba_history', meta,
        sql.Column('user_id', sql.String(length=64), primary_key=True),
        sql.Column('successful_auth_at', ks_sql.DateTimeInt.impl,
                   nullable=False, primary_key=True),
        sql.Column('features', ks_sql.JsonBlob.impl, nullable=False),
        sql.Column('confidence_score', sql.Float, nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    table.create(migrate_engine, checkfirst=True)

def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    table = sql.Table('rba_history', meta, autoload=True)
    table.drop(migrate_engine, checkfirst=True)

