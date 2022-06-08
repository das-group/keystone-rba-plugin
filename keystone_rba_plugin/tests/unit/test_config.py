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

import os
import stevedore

from keystone import conf
from keystone.tests import unit

from testtools import matchers

CONF = conf.CONF
TESTSDIR = os.path.dirname(os.path.abspath(__file__))


class TestRBAConf(unit.TestCase):

    def setUp(self):
        super(TestRBAConf, self).setUp()

    def auth_plugin_config_override(self, methods=None, **method_classes):
        if not methods:
            methods = ['password', 'rba', 'token']
        super(TestRBAConf, self).auth_plugin_config_override(methods)

    def config_files(self):
        config_files = super(TestRBAConf, self).config_files()
        testconf = os.path.join(TESTSDIR, 'config_files', 'test_rba.conf')
        config_files.append(testconf)
        return config_files

    def test_config_default(self):
        self.assertIsInstance(CONF.rba.driver, str)
        self.assertIsInstance(CONF.rba.features, list)
        self.assertIsInstance(CONF.rba.max_user_history_size, int)

    def test_entry_points(self):
        expected = ['default', 'sql', 'smtp']
        em = stevedore.ExtensionManager('keystone.auth.rba')
        observed = [extension.name for extension in em]
        em = stevedore.ExtensionManager('keystone.rba')
        observed.extend([extension.name for extension in em])
        self.assertThat(observed, matchers.ContainsAll(expected))
