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

from oslo_config import cfg

from keystone import conf

CONF = conf.CONF

driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=conf.utils.fmt("""
Entry point for the risk-based authentication (RBA) backend driver in the
`keystone.rba` namespace. The extension only provides an `sql` driver and
unless you are providing a custom entry point there is no reason to change
this.
"""))
features = cfg.ListOpt(
    'features',
    default=['ip', 'rtt', 'ua'],
    help=conf.utils.fmt("""
Specify the features, that will be saved in a history after a successful login.
Currently, the following features are supported:
IP Address (ip),
Round Trip Time (rtt),
User Agent (ua).
"""))
maxmind_asn_db_path = cfg.StrOpt(
    'maxmind_asn_db_path',
    default=None,
    help=conf.utils.fmt("""
Provide the absolute path for the maxmind asn database to enable the
IP subfeature based on the Autonomous System Number (asn).
"""))
maxmind_country_db_path = cfg.StrOpt(
    'maxmind_country_db_path',
    default=None,
    help=conf.utils.fmt("""
Provide the absolute path for the maxmind country database to enable the
IP subfeature based on the ISO CountryCode (cc).
"""))
malicious_ip_list_path = cfg.StrOpt(
    'malicious_ip_list_path',
    default=None,
    help=conf.utils.fmt("""
Provide the absolute path of an IP address list known for malicious activities.
"""))
reject_threshold = cfg.FloatOpt(
    'reject_threshold',
    default=0.9,
    min=0.0,
    max=10.0,
    help=conf.utils.fmt("""
The reject threshold is the boundary beyond which a calculated risk score
leads to the direct failure of the login attempt.
A calculated risk score indicates a likelihood, where 1.0 is considered the
most likely attack and 0.0 the most likely legitimate login. Typically the
risk score takes a value between these limits, enabling actions from a
threshold value.
To deny all login attempts, the reject threshold can be set to its minimum
value 0.0. Setting up its maximum value 1.0, can be interpreted as disabling
the reject option, as it is not very likely that a calculated risk score will
ever reach this value. Note that it is possible to set the reject threshold
below the request threshold, resulting in the disabling of the further
information request option, as the rejection is evaluated before the request
option. Calculated risk scores highly depend on the entries and the history
size. Therefore should threshold be adjusted to fit the needs. To get an
indication, the risk scores of successful logins are stored beside the
features in the history."""))
request_threshold = cfg.FloatOpt(
    'request_threshold',
    default=0.4,
    min=0.0,
    max=10.0,
    help=conf.utils.fmt("""
The request threshold is the boundary beyond which a calculated
risk score leads to a request for further information. A calculated
risk score indicates a likelihood, where 1.0 is considered the most
likely attack and 0.0 the most likely legitimate login. Typically the
risk score takes a value between these limits, enabling actions from
a threshold value. To request further information at all login attempts,
the request threshold can be set to its minimum value 0.0. Setting up
its maximum value 1.0, can be interpreted as disabling the request
option, as it is not very likely that a calculated risk score will ever
reach this value. Note that it is possible to set the reject threshold
below the request threshold, resulting in the disabling of the further
information request option and therefore either in a successful login
or a rejection. Calculated risk scores highly depend on the entries and
the history size. Therefore should thresholds be adjusted to fit the
needs. To get an indication, the risk scores of successful logins are
stored beside the features in the history."""))
max_user_history_size = cfg.IntOpt(
    'max_user_history_size',
    default=100,
    min=0,
    help=conf.utils.fmt("""
Set the maximum amount of features history entries per user.
If this value exceeds, the oldest entry will be deleted to make space
for a new history entry to be stored. The minimum value that can
be set is 0 to skip entry storing and flushing existing entries on the
next successful login.
"""))
restrict_to_mfa = cfg.BoolOpt(
    'restrict_to_mfa',
    default=True,
    help=conf.utils.fmt("""
The risk-based authentication (RBA) is intended to be used as additional
factor besides an already accepted method by the user. By setting the
following option to true, the plugin enforces the restriction to multi-factor
authentication (MFA) by checking the `multi_factor_auth_enabled` user option
to prevent the use of RBA as single authentication method. It is highly
recommended to activate the option, otherwise it is possible to
successfully authenticate a user by only using the RBA method. In cases
for example, if a users RBA login history is empty, every attempt using RBA
will result in a successful authentication. This can be a serious threat and
may lead to loss of control over the users account. Unfortunately, it is
possible to define MFA rules as a single method. As Keystone users are
required to configure MFA on their own, it is therefore important to advise
users to define `multi_factor_auth_rules` with at least one other
authentication method in conjunction with RBA. The decision to not include
rule checks that prevent RBA as single method rule was made to avoid account
lock outs caused by rule misconfiguration.
"""))
contact_method = cfg.StrOpt(
    'contact_method',
    default='email',
    help=conf.utils.fmt("""
The contact_method specifies search term for the deposited type of addressing
the user, that is searched for in the user information. If contacting a user
is necessary and nothing could be found in the user information, then will the
authentification fail.
"""))
recipient_designator = cfg.StrOpt(
    'recipient_designator',
    default='name',
    help=conf.utils.fmt("""
The recipient_designator specifies the search term for the name to
be greeted in passcode message, that is searched for in the user
information. If nothing could be found in the user information, then
will the default_recipient be used to greet the user.
"""))
default_recipient = cfg.StrOpt(
    'default_recipient',
    default='customer',
    help=conf.utils.fmt("""
The default_recipient is used when a recipients name could not be
found in the user information using the recipient_designator. It lets
the 'smtp' messenger backend default to the greeting:
"Dear customer, ..."
"""))
include_contact = cfg.BoolOpt(
    'include_contact',
    default=False,
    help=conf.utils.fmt("""
If this option is set to True, it will force the to include the deposited
contact in the servers response error message. It will only has an
effect if a messenger is specifid and should only be used in
intermediary communication to give the user a hint to look for.
Otherwise it is not recommended, as it can leak sensitive contact
information, just as no messenger is specified.
"""))
messenger = cfg.StrOpt(
    'messenger',
    default=None,
    help=conf.utils.fmt("""
The messenger backend to send the passcode to the user. If its value
is None, then will the passcode and the deposited contact be included
into the unauthorized response message to let the applicant send the
message. This should only be used if Keystone is not direct reachable
for the user, as the passcode could be directly used in the next
authentication. Moreover it can leak the deposited recipient and its
contact which is why it should only be used in intermediary communication.
The extension provides a basic messenger backend called 'smtp'
that can be used to transmit passcodes to a SMTP server. It is not
assigned as default messenger because it will make use of the below
following options. Note that it is possible to provide an own messenger
 implementation. In any case, the contact_method option should be set
 accordingly.
"""))
email_host_user = cfg.StrOpt(
    'email_host_user',
    default=None,
    help=conf.utils.fmt("""
This option references the email address of the host user that shall be used
to send emails from.
"""))
email_host_password = cfg.StrOpt(
    'email_host_password',
    default=None,
    help=conf.utils.fmt("""
This option references the password to use for email_host_user.
"""))
smtp_host = cfg.IPOpt(
    'smtp_host',
    default=None,
    help=conf.utils.fmt("""
This option references the SMTP servers IP address or host name.
"""))
smtp_port = cfg.PortOpt(
    'smtp_port',
    default=25,
    help=conf.utils.fmt("""
This option references the SMTP servers port.
"""))
smtp_use_tls = cfg.BoolOpt(
    'smtp_use_tls',
    default=True,
    help=conf.utils.fmt("""
This option specifies if the communication to the SMTP servers shall be
encrypted using TLS.
"""))

GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    features,
    maxmind_asn_db_path,
    maxmind_country_db_path,
    malicious_ip_list_path,
    reject_threshold,
    request_threshold,
    max_user_history_size,
    restrict_to_mfa,
    contact_method,
    recipient_designator,
    default_recipient,
    include_contact,
    messenger,
    email_host_user,
    email_host_password,
    smtp_host,
    smtp_port,
    smtp_use_tls,
]


def list_opts():
    return [(GROUP_NAME, ALL_OPTS)]


def register_opts(config):
    config.register_opts(ALL_OPTS, group=GROUP_NAME)


register_opts(CONF)
