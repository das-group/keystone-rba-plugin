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

import smtplib

from email.message import EmailMessage
from keystone import exception
from keystone_rba_plugin import conf
from keystone_rba_plugin.rba.backends import base
from oslo_log import log

CONF = conf.CONF
LOG = log.getLogger(__name__)

class PasscodeMessenger(base.RBAMessengerDriverBase):

    def __init__(self):
        pass

    def send_passcode(self, recipient, contact, passcode, **kwargs):
        if not all((recipient, contact, passcode,
               CONF.rba.smtp_host, CONF.rba.email_host_user)):
            raise exception.AuthPluginException('Sending passcode failed.')
        msg = EmailMessage()
        msg['Subject'] = 'Your personal security code'
        msg['From'] = CONF.rba.email_host_user
        msg['To'] = contact
        msg.set_content("""Dear """ + recipient + """,
someone just tried to sign in to your account.
If you were prompted for a security code, please enter the following to complete your sign-in: """ + passcode + """
If you were not prompted, please change your password immediately in the profile settings.
""")
        try:
            if CONF.rba.smtp_port == 465 and CONF.rba.smtp_use_tls:
                with smtplib.SMTP_SSL(CONF.rba.smtp_host,
                                  port=CONF.rba.smtp_port) as client:
                    if CONF.rba.email_host_password is not None:
                        client.login(CONF.rba.email_host_user,
                                     CONF.rba.email_host_password)
                    client.send_message(msg)
            else:
                with smtplib.SMTP(CONF.rba.smtp_host,
                                  port=CONF.rba.smtp_port) as client:
                    client.ehlo()
                    if CONF.rba.smtp_use_tls:
                        client.starttls()
                        client.ehlo()
                    if CONF.rba.email_host_password is not None:
                        client.login(CONF.rba.email_host_user,
                                     CONF.rba.email_host_password)
                    client.send_message(msg)
        except Exception as e:
            LOG.debug(e)
            raise exception.AuthPluginException('Sending passcode failed.')

