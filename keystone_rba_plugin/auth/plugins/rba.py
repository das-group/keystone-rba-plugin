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

from oslo_log import log

from keystone import exception
from keystone.auth.plugins import base
from keystone.common import provider_api
from keystone.i18n import _

from keystone_rba_plugin import conf
from keystone_rba_plugin.auth.plugins import core
from keystone_rba_plugin.rba import core as manager

CONF = conf.CONF

LOG = log.getLogger(__name__)
METHOD_NAME = 'rba'
PROVIDERS = provider_api.ProviderAPIs


class RiskBasedAuthentication(base.AuthMethodHandler):

    def __init__(self, *args, **kwargs):
        super(RiskBasedAuthentication, self).__init__(*args, **kwargs)
        self.manager = manager.RBAManager()

    def authenticate(self, auth_payload):
        """Try to authenticate against the login history."""
        response_data = {}
        user_info = core.RBAUserInfo.create(auth_payload, METHOD_NAME)
        try:
            result = self.manager.authenticate(
                user_id=user_info.user_id,
                features=user_info.features,
                passcode=user_info.passcode)
            response_data['user_id'] = user_info.user_id
            if result is not None:
                status = False
                response_body = result
            else:
                status = True
                response_body = None
            return base.AuthHandlerResponse(
                status=status,
                response_body=response_body,
                response_data=response_data)
        except AssertionError:
            # authentication failed because of invalid user or passcode
            msg = _('Invalid credentials.')
            raise exception.Unauthorized(msg)
