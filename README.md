# Risk Based Authentication (RBA) plugin for Keystone

This repository contains a RBA plugin implementation for the OpenStack identity service (Keystone).

It is intended to be used in Keystones multi-factor authentication mechanism, as the use as single factor would only consider the users environmental feature information, provided at the authentication attempt.

## Installation

The installation should be done with the same operating system user as the keystone installation itself. 

Clone the [keystone-rba-plugin](https://github.com/das-group/keystone-rba-plugin.git) extension repository and install it with pythons package manager [pip](https://pip.pypa.io/en/stable/) as one of the following.

Install via pip:

    cd keystone-rba-plugin
    pip install .

Install from local git branch using pip:
	`pip install git+file:///<Path_to_setup.py>@<branch>`

Or editable for development:
	`pip install -e git+file:///<Path_to_setup.py>/keystone_rba_plugin@<branch>#egg=keystone_rba_plugin`

The default installation expands the SQL database scheme with an additional table for the authentication history.

Keystone internally uses the [sqlalchemy-migrate](https://sqlalchemy-migrate.readthedocs.io/en/latest/) package to versionize schema changes in earlier releases. Therefore it may be possible that the distinction with the  `legacy_migrations` folder is not present and the destination path needs to be adjusted.


Place the database migration files from the repository:
`etc/sql/legacy_migrations/contract_repo/080_contract_add_rba_history_table.py`, 
`etc/sql/legacy_migrations/data_migration_repo/080_migrate_add_rba_history_table.py` and 
`etc/sql/legacy_migrations/expand_repo/080_expand_add_rba_history_table.py` 
Into the corresponding Keystone source folders:
`keystone/common/sql/legacy_migrations/contract_repo/versions/`, 
`keystone/common/sql/legacy_migrations/data_migration_repo/versions/` and 
`keystone/common/sql/legacy_migrations/expand_repo/versions/`.

Depending on your Keystone installation, it may be in the `site-packages` folder of the `pip` package manager.

If the Keystone schema version is already in use, it will be necessary to increment the preceding version number of the file names to the next unused number.

Likewise on the database initialization, use the following command to migrate the new table definition to the schema with the permission of the databases user:

    su -s /bin/sh -c "keystone-manage db_sync" keystone

It does not alter any other table and only references the user_id from the user table.
Therefore it is safe to drop the table to remove the changes or use the downgrade functionality of the sqlalchemy-migrate package.

Restart keystones web server to enable the configuration changes.

## Configuration

In order to enable RBA it is necessary to list `rba` in the allowed authentication `methods` of the `[auth]` option group in the `keystone.conf` file:

    [auth]

    methods = password,rba,token

To configure the plugin itself, add the `[rba]` option group from the `etc/keystone_rba_plugin.conf.sample` file to Keystones configuration and adjust the options as needed.
If the file does not exist, try to generate the sample file using the command `tox -e genconfig` in the plugin sources root directory.

The plugin supports the IP-Address based inclusion of the Country Code and Autonomous System Number (ASN) information, by the use of Maxmind lookup databases, that can be enabled by providing their path in the configuration  (optional).

The probability estimation of an attack for the IP-Address feature can be enabled by providing a file as reputation list containing malicious IP-Networks line by line (optional).
Such a list can be obtained from the [FireHOL](https://iplists.firehol.org/) firewall project and should kept up to date to include the most recent address spaces.

The RBA plugin is intended as additional factor alongside other authentication methods to identify a user.
Note, that Keystone allows the authentication of users with all allowed methods specified. Therefore, if a users RBA login history is empty, such as on the first login attempt using the RBA method, the authentication would succeed without further checks. A malicious attacker could fill up the login history with own feature values, resulting in the loss of control or even a lockout of the account.
To mitigate this threat, the plugin checks with the activated `restrict_to_mfa` option whether the user has enabled the use of Keystones Multi-Factor authentication mechanism and consequently denys RBA attempts until the options have been made.
By Keystones default, a user needs to define appropriate `multi_factor_auth_rules` and set the `multi_factor_auth_enabled` user option on the own responsibility to enable Multi-Factor authentication.


## Conception
The plugin is based on Keystones overall structure and is dynamically loaded via Keystones plugin mechanism using the configured setuptools entry points. For the history and messenger backends are interfaces and entry points defined to replace the default functionality with custom providers.

    keystone_rba_plugin
    ├── auth
    │   └── plugins
    │       ├── core.py
    │       └── rba.py
    ├── conf
    │   └── rba.py
    ├── rba
    │   ├── backends
    │   │   ├── base.py
    │   │   ├── smtp.py
    │   │   ├── sql_model.py
    │   │   └── sql.py
    │   └── core.py
    └── tests

Authentication is processed by `RBA` class defining the authentication method in `auth.plugins.rba`. The method validates the provided RBA authentication information such as from the following http POST request with the `RBAUserInfo` class in the `auth.plugins.core` module.

    { "auth": {
            "identity": {
                "methods": [
                    "password",
                    "rba"
                ],
                "password": {
                    "user": {
                        "id": "2ed179c6af12496cafa1d279cb51a78f",
                        "password": "012345"
                    }
                },
                "rba": {
                    "user": {
                        "id": "2ed179c6af12496cafa1d279cb51a78f",
                        "features": {
                            "ip": "10.0.1.2",
                            "rtt": "300"
                        }
                    }
                }
            }
        }
    }

The information is then passed to `RBAManager` class in the `rba.core` module that decides the authentications success in conjunction with the users history that is maintained by the default sql back end driver in the `rba.backends.sql` module and the ORM definition of the table model in `rba.backends.sql_model`. On sucess, the new features will be persistently stored in the users history. In case there is another authentication step needed, the manager generates credentials, that the user needs to confirm in another authentication step including a `"passcode": "<Passcode>"` entry in the provided authentication information. There are multiple ways to transmit the passcode to the user. The default will include the passcode in Keystones response and can be used to let intermediary services like Horizon decide. Another way is to set up the SMTP options in the configuration file to use a separate SMTP server. For flexibility is this back end based on an interface that can be used to create custom messenger classes with the defined entry point.
The options, that are  adjustable by the Keystone administrator using the configuration file, are defined in the `conf/rba` module.

## License

### Code

&copy; 2022 Vincent Unsel \& 2021 Stephan Wiefling/[Data and Application Security Group](https://das.h-brs.de)

The code in this repository is licensed under the Apache License 2.0.
See [LICENSE](LICENSE) for details.
