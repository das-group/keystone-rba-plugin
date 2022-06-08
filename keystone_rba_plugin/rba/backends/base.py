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

import abc

from keystone import exception


class RBAHistoryDriverBase(object, metaclass=abc.ABCMeta):
    """Abstract base for a Risk-Based Authentication History back end driver.
    """

    @abc.abstractmethod
    def clear_entries(self):
        """Delete history of all entries.
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def count_entries_by_user(self, user_id):
        """ Count the amount of entries for a specified user_id
        :param str user_id: unique user identitier.
        :returns the amount of entries as int
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_entry(self, user_id, features, confidence_score):
        """ Inserts a new entry to persist in the history.

        :param str user_id: unique user identitier.
        :param dict features: environmental values collected during
        an authentication attempt.
        :param float confidence_score: risk score calculated for the features
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_oldest_n_entries_by_user(self, user_id, n):
        """ Delete n of the oldest enties by user_id.

        :param str user_id: unique user identitier.
        :param int n: amount entries to delete.
        :returns a list of deleted tupels of the form (user_id, features)
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_features_list_by_user(self, user_id):
        """List features entries for a user.

        :param str user_id: unique user identitier.
        :returns a list of features entries or an empty list.
        """
        raise exception.NotImplemented()

class RBAMessengerDriverBase(object, metaclass=abc.ABCMeta):
    """Abstract base for a Risk-Based Authentication passcode messenger
    back end driver.
    """
    @abc.abstractmethod
    def send_passcode(self, recipient, contact, passcode, **kwargs):
        """ Send the passcode to the recipient using contact information.

        :param str recipient: greeted name.
        :param str contact: identifier to contact user with.
        :param str passcode: passcode to be sent.

        :raises keystone.exception.AuthPluginException: If the message
        could not be sent.
        """
        raise exception.NotImplemented()
