# Built-in/Generic Imports
from dataclasses import dataclass
from typing import Union
from typing_extensions import TypeAlias


__author__ = "IncognitoCoding"
__copyright__ = "Copyright 2023, common"
__credits__ = ["IncognitoCoding"]
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "IncognitoCoding"
__status__ = "Beta"

_PCTRTT: TypeAlias = tuple[tuple[str, str], ...]
_PCTRTTT: TypeAlias = tuple[_PCTRTT, ...]


@dataclass
class EmailSettings(object):
    """Stores email settings.

    Parameters
    ----------
    smtp : str
        `summary`: The smtp server or FQDN.
    authentication_required : bool
        `summary`: Enables if authentication is required.
    use_tls : bool
        `summary`: Enables TLS.
    username : str
        `summary`: Username for TLS.
    password : str
        `summary`: Password for TLS.
    from_email : str
        `summary`: From email address.
    to_email : str
        `summary`: To email address.
    """

    __slots__ = (
        "smtp",
        "authentication_required",
        "use_tls",
        "username",
        "password",
        "from_email",
        "to_email",
    )

    smtp: str
    authentication_required: bool
    use_tls: bool
    username: str
    password: str
    from_email: str
    to_email: str


@dataclass
class StartupSettings(object):
    """Stores startup settings from the YAML settings file.

    Parameters
    ----------
    continuous_monitoring : bool
        `summary`: Continue to run when enabled and sleep based on the monitor_sleep value.
    monitor_sleep : int
        `summary`: The number of seconds to sleep between log checks.
    email_alerts : bool
        `summary`: Sends email alerts.
    alert_program_errors : bool
        `summary`: Sends email alerts if an exception is thrown.
    buffer_days : int
        `summary`: Buffer days before certificate warnings start.
    time_zome : str
        `summary`: Running timezone.
    site_urls : list[str]
        `summary`: URLs that need to be checked.
    email_settings : EmailSettings
        `summary`: The email settings dataclass.
    """

    __slots__ = (
        "continuous_monitoring",
        "monitor_sleep",
        "email_alerts",
        "alert_program_errors",
        "buffer_days",
        "time_zome",
        "site_urls",
        "email_settings",
    )

    continuous_monitoring: bool
    monitor_sleep: int
    email_alerts: bool
    alert_program_errors: bool
    buffer_days: int
    time_zome: str
    site_urls: list[str]
    email_settings: EmailSettings


@dataclass
class SSLReturn(object):
    """Stores the SSL certificate information."""

    __slots__ = (
        "subject",
        "issuer",
        "version",
        "notBefore",
        "notAfter",
        "subjectAltName",
        "ocsp",
        "caIssuers",
        "crlDistributionPoints",
    )

    subject: Union[str, _PCTRTTT, _PCTRTT, None]
    issuer: Union[str, _PCTRTTT, _PCTRTT, None]
    version: Union[str, _PCTRTTT, _PCTRTT, None]
    notBefore: Union[str, _PCTRTTT, _PCTRTT, None]
    notAfter: Union[str, _PCTRTTT, _PCTRTT, None]
    subjectAltName: Union[str, _PCTRTTT, _PCTRTT, None]
    ocsp: Union[str, _PCTRTTT, _PCTRTT, None]
    caIssuers: Union[str, _PCTRTTT, _PCTRTT, None]
    crlDistributionPoints: Union[str, _PCTRTTT, _PCTRTT, None]


@dataclass
class ExpirationMsg(object):
    """The expiration message output.

    Parameters
    ----------
    status_message : str
        `summary`: The status of the message.
    expiration_days_away : str
        `summary`: The amount of days the certificate will expire.
    """

    __slots__ = "status_message", "expiration_days_away"

    status_message: str
    expiration_days_away: int
