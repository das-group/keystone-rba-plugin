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
from keystone.auth import plugins
from keystone.identity.backends import resource_options as ro
from keystone_rba_plugin import conf
from geoip2 import database
from geoip2 import errors
from ipaddress import ip_address
from oslo_log import log
from user_agents import parse

CONF = conf.CONF
LOG = log.getLogger(__name__)


class RBAUserInfo(plugins.BaseUserInfo):

    def __init__(self):
        super(RBAUserInfo, self).__init__()
        self.passcode = None
        self.features = None
        self._validate_and_normalize_feature = {
            'ip': self._validate_and_normalize_ip,
            'rtt': self._validate_and_normalize_rtt,
            'ua': self._validate_and_normalize_ua
        }

    def _validate_and_normalize_auth_data(self, auth_payload):
        super(RBAUserInfo, self)._validate_and_normalize_auth_data(
            auth_payload)
        if CONF.rba.restrict_to_mfa and not self.user_ref['options'].get(
                ro.MFA_ENABLED_OPT.option_name, True):
            raise exception.ValidationError(attribute=CONF.rba.restrict_to_mfa,
                                            target=self.METHOD_NAME)
        user_info = auth_payload['user']
        passcode = user_info.get('passcode')
        if isinstance(passcode, str):
            self.passcode = passcode
        payload_features = user_info.get('features')
        if not isinstance(payload_features, dict):
            return
        self.features = {}
        LOG.debug(str(payload_features))
        try:
            for feature in CONF.rba.features:
                payload_feature = payload_features.get(feature, '')
                self.features.update(self._validate_and_normalize_feature[
                    feature](payload_feature))
        except KeyError:
            raise exception.ValidationError(attribute=feature,
                                            target=self.METHOD_NAME)

    def _validate_and_normalize_ip(self, address):
        if not address == '':
            try:
                ip_address(address)
            except ValueError:
                raise exception.ValidationError(attribute='ip',
                                                target=self.METHOD_NAME)
        feature = {'ip': address}
        if CONF.rba.maxmind_asn_db_path is not None:
            try:
                with database.Reader(
                        CONF.rba.maxmind_asn_db_path) as reader:
                    response = reader.asn(address)
                    feature['asn'] = str(response.autonomous_system_number)
            except errors.AddressNotFoundError:
                feature['asn'] = ''
            except Exception as e:
                LOG.debug(e)
        if CONF.rba.maxmind_country_db_path is not None:
            try:
                with database.Reader(
                        CONF.rba.maxmind_country_db_path) as reader:
                    response = reader.country(address)
                    feature['cc'] = response.country.iso_code
            except errors.AddressNotFoundError:
                feature['cc'] = ''
            except Exception as e:
                LOG.debug(e)
        return feature

    def _validate_and_normalize_rtt(self, rtt):
        try:
            if rtt == '':
                pass
            else:
                rtt = round(int(float(rtt)), -2)
                if rtt < 0:
                    raise Exception
            return {'rtt': str(rtt)}
        except Exception as e:
            LOG.debug(e)
            raise exception.ValidationError(attribute='rtt',
                                            target=self.METHOD_NAME)

    def _validate_and_normalize_ua(self, user_agent_string):
        feature = {}
        ua = parse(user_agent_string)
        feature['ua'] = ua.ua_string
        feature['bv'] = ua.browser.family + ' ' + ua.browser.version_string
        feature['osv'] = ua.os.family + ' ' + ua.os.version_string
        feature['df'] = ua.device.family
        return feature
