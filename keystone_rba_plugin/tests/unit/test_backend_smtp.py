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

import smtpd
from keystone.tests.unit import test_backend_sql as base
from keystone.tests.unit.utils import wip
from keystone_rba_plugin.rba import core
from keystone_rba_plugin.tests.common import auth as common_auth

class TestPasscodeMessenger(base.SqlTests, common_auth.RBATestMixin):

    def setUp(self):
        super(TestPasscodeMessenger, self).setUp()
        host = '127.0.0.1'
        port = 1025
        self.config_fixture.config(group='rba', messenger='smtp')
        self.config_fixture.config(group='rba', email_host_user='noreply')
        self.config_fixture.config(group='rba', email_host_password=None)
        self.config_fixture.config(group='rba', smtp_host=host)
        self.config_fixture.config(group='rba', smtp_port=port)
        self.config_fixture.config(group='rba', smtp_use_tls=False)
        self.manager = core.RBAManager()
        self.messenger = self.manager.messenger

    @wip("SMTP server required.")
    def test_send_passcode(self):
        recipient = self.user_foo['name']
        contact = self.user_foo['email']
        passcode = '012345'
        self.messenger.send_passcode(recipient, contact, passcode)
        self.config_fixture.config(group='rba', recipient_designator='nic')
        self.config_fixture.config(group='rba', include_contact=True)
        self.manager.send_message(self.user_foo, passcode)
