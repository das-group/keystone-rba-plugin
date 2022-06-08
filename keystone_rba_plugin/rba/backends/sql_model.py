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

from keystone.common import sql


class History(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'rba_history'
    attributes = ['user_id', 'successful_auth_at', 'features', 'confidence_score']
    readonly_attributes = ['user_id', 'successful_auth_at', 'confidence_score']
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey(
                             'user.id',
                             ondelete='CASCADE'),
                         primary_key=True
                         )
    successful_auth_at = sql.Column(sql.DateTimeInt(),
                                    nullable=False,
                                    default=datetime.datetime.utcnow,
                                    primary_key=True
                                    )
    features = sql.Column(sql.JsonBlob(), nullable=False)
    confidence_score = sql.Column(sql.sql.Float(), nullable=False)
    __table_args__ = (
        sql.UniqueConstraint(
            'user_id',
            'successful_auth_at'),
        {})

    def __init__(self, user_id, features, confidence_score):
        self.user_id = user_id
        self.features = features
        self.confidence_score = confidence_score
