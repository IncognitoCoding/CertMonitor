# Package/Modules
from dataclasses import asdict
import logging
import time
import ssl
import socket
import datetime
from typing import Union
from ictoolkit.directors.email_director import send_email

# Exceptions
from fexception import FCustomException

# Local Dataclasses
from certmonitor.dataclasses.common import StartupSettings, SSLReturn, ExpirationMsg

# Local Exceptions
from certmonitor.exceptions.exceptions import CertMonitorError

__author__ = "IncognitoCoding"
__copyright__ = "Copyright 2023, check"
__credits__ = ["IncognitoCoding"]
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "IncognitoCoding"
__status__ = "Beta"


def ssl_pull(site_url: str) -> Union[SSLReturn, None]:
    """Pulls the SSL website certificate expiration date.

    Parameters
    ----------
    site_url : str
        `summary`: The site URL

    Returns
    -------
    SSLReturn
        `summary`: The SSL certificate return information.

    Raises
    ------
    CertMonitorError : fexception
        `summary`: A failure occurred while getting SSL information for {site_url}.

    Examples
    --------
    >>> site_url = "www.google.com"
    >>> ssl_pull(site_url=site_url)
    SSLReturn(subject=((('commonName', 'www.google.com'),),), issuer=((('countryName', 'US'),), (('organizationName', 'Google Trust Services LLC'),), (('commonName', 'GTS CA 1C3'),)), version=3, notBefore='Mar  2 04:23:01 2023 GMT', notAfter='May 25 04:23:00 2023 GMT', subjectAltName=(('DNS', 'www.google.com'),), OCSP=('http://ocsp.pki.goog/gts1c3',), caIssuers=('http://pki.goog/repo/certs/gts1c3.der',), crlDistributionPoints=('http://crls.pki.goog/gts1c3/fVJxbV-Ktmk.crl',))
    """
    logger = logging.getLogger(__name__)

    ssl_info: Union[SSLReturn, None] = None
    context = ssl.create_default_context()
    try:

        with socket.create_connection((site_url, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=site_url) as ssock:
                logger.debug("Getting the SSL certificate information from the site_url")
                # Gets SSL certificate information from the site_url.
                """
                raw_ssl_info = {
                    "subject": ((("commonName", "www.google.com"),),),
                    "issuer": (
                        (("countryName", "US"),),
                        (("organizationName", "Google Trust Services LLC"),),
                        (("commonName", "GTS CA 1C3"),),
                    ),
                    "version": 3,
                    "serialNumber": "55F8229BC57763E10AA460054C87C84C",
                    "notBefore": "Mar  2 04:23:01 2023 GMT",
                    "notAfter": "May 25 04:23:00 2023 GMT",
                    "subjectAltName": (("DNS", "www.google.com"),),
                    "OCSP": ("http://ocsp.pki.goog/gts1c3",),
                    "caIssuers": ("http://pki.goog/repo/certs/gts1c3.der",),
                    "crlDistributionPoints": ("http://crls.pki.goog/gts1c3/fVJxbV-Ktmk.crl",),
                }
                """
                raw_ssl_info = ssock.getpeercert()
                logger.debug(f"SSL certificate info = {ssl_info}")

                if raw_ssl_info:
                    ssl_info = SSLReturn(
                        subject=raw_ssl_info.get("subject"),
                        issuer=raw_ssl_info.get("issuer"),
                        version=raw_ssl_info.get("version"),
                        notBefore=raw_ssl_info.get("notBefore"),
                        notAfter=raw_ssl_info.get("notAfter"),
                        subjectAltName=raw_ssl_info.get("subjectAltName"),
                        ocsp=raw_ssl_info.get("OCSP"),
                        caIssuers=raw_ssl_info.get("caIssuers"),
                        crlDistributionPoints=raw_ssl_info.get("crlDistributionPoints"),
                    )
        logger.debug("Returning the SSL certificate value objects")
        return ssl_info
    except Exception as exc:
        exc_args = {
            "main_message": f"A failure occurred while getting SSL information for {site_url}.",
            "custom_type": CertMonitorError,
            "returned_result": {exc},
            "suggested_resolution": "Please validate that the website is an HTTPS supported website.",
        }
        raise CertMonitorError(FCustomException(message_args=exc_args))


def get_url_certificate_info(site_url: str, buffer_days: int, time_zone: str) -> ExpirationMsg:
    """Gets SSL details from the URL and calculates if the certificate is expiring. Alerts are triggered based on the buffer_days.

    Parameters
    ----------
    site_url :str
        `summary`: A website URL.
    buffer_days : int
        `summary`: Days to buffer certificate expiring before notifying.
    time_zone : str
        `summary`: Time zone the program is running. The time zone is used for cleaner logging. If your time zone is not listed, choose any and convert log output manually.
        `extra1`: time_zone = CST, UTC, EST, MST, or PST

    Returns
    -------
    ExpirationMsg
        `summary`: The certificate expiration message

    Raises
    ------
    ValueError : fexception
        `summary`: A failure occurred while getting SSL information for {site_url}.
    ValueError : fexception
        `summary`: An incorrect time zone format was sent.
    """
    logger = logging.getLogger(__name__)
    try:
        logger.debug(f"Checking site {site_url} for SSL information")
        # Strips https if it exists.
        site_url = site_url.replace("https://", "")
        # Makes call to pull ssl.
        ssl_output = ssl_pull(site_url)
    except Exception as exc:
        raise exc

    ##########################################################
    #######Sets The Date Format Based On Running Timezone#####
    ##########################################################
    logger.debug("Setting the date format based on the running time zone")
    if "cst" == time_zone or "CST" == time_zone:
        date_format = "%a, %d %b %Y %H:%M:%S CST"
    elif "utc" == time_zone or "UTC" == time_zone:
        date_format = "%a, %d %b %Y %H:%M:%S UTC"
    elif "est" == time_zone or "EST" == time_zone:
        date_format = "%a, %d %b %Y %H:%M:%S EST"
    elif "mst" == time_zone or "MST" == time_zone:
        date_format = "%a, %d %b %Y %H:%M:%S MST"
    elif "pst" == time_zone or "PST" == time_zone:
        date_format = "%a, %d %b %Y %H:%M:%S PST"
    else:
        exc_args = {
            "main_message": "An incorrect time zone format was sent.",
            "custom_type": CertMonitorError,
            "suggested_resolution": "Please verify you entered the correct timezone abbreviation. Currently supported timezones are CST, UTC, EST, MST, and PST.",
        }
        raise ValueError(FCustomException(message_args=exc_args))

    logger.debug(f"Time zone is '{time_zone}'. date_format set to '{date_format}'")

    ##########################################################
    ###########Sets Expiration Date From SSL Output###########
    ##########################################################
    logger.debug("Setting the expiration date from SSL output")
    # Converts the certificate date from the class to an easily compareable format and sets to central time.
    ssl_date_fmt = r"%b %d %H:%M:%S %Y %Z"
    # Gets the raw certificate expiration date from the class.
    if ssl_output and ssl_output.notAfter:
        certificate_expiration = str(ssl_output.notAfter)
    else:
        exc_args = {
            "main_message": f"Failed to get the certificate expiration date for URL '{site_url}'.",
            "custom_type": CertMonitorError,
            "suggested_resolution": "Please report this error to the developer.",
        }
        raise ValueError(FCustomException(message_args=exc_args))
    # Gets the certral certificate expriation using the customized format.
    certificate_expiration1 = (datetime.datetime.strptime(certificate_expiration, ssl_date_fmt)).strftime(date_format)
    # Converts the string formatted expiration date back into a string parse time. Required for comparison.
    certificate_expiration = datetime.datetime.strptime(certificate_expiration1, date_format)
    logger.debug(f"Certificate expiration date is {certificate_expiration}")

    #############################################
    ################Sets Current Date############
    #############################################
    logger.debug("Setting the current date")
    # Sets the current date with central format
    current_datetime1 = datetime.datetime.now(datetime.timezone.utc).strftime(date_format)
    # Converts the string formatted date back into a string parse time. Required for comparison.
    current_datetime = datetime.datetime.strptime(current_datetime1, date_format)
    logger.debug(f"Current date is {current_datetime}")

    logger.debug("Calculating how many days remain before the certificate expires")
    # Gets how many days remain before the certificate expires.
    expiration_days_away = (certificate_expiration - current_datetime).days
    logger.debug(f"Expiration days away is {expiration_days_away}")
    # Checks if the certificate expiration showing the day it expires.
    if expiration_days_away == 0:
        logger.debug(
            f"Returning the expiration status message. Message = Warning: Certificate for {site_url} is expiring soon. The certificate will expire tomorrow"
        )
        status_message = f"Warning: Certificate for {site_url} is expring soon. The certificate will expire tomorrow."
        expiration_days_away = 0
        return ExpirationMsg(status_message=status_message, expiration_days_away=expiration_days_away)
    # Checks if the certificate expiration date has been met.
    elif expiration_days_away < 0:
        # Removes the negative sign.
        days_expired = str(expiration_days_away).replace("-", "")
        logger.debug(
            f"Returning the expiration status message. Message = Error: Certificate for {site_url} has expired! The certificate has been expired for {days_expired} days."
        )
        status_message = (
            f"Error: Certificate for {site_url} has expired! The certificate has been expired for {days_expired} days."
        )
        return ExpirationMsg(status_message=status_message, expiration_days_away=expiration_days_away)
    # Checks if the expiration days away has reached the buffer alert days.
    elif expiration_days_away <= buffer_days:
        logger.debug(
            f"Returning the expiration status message. Message = Warning: Certificate for {site_url} is expring soon. The certificate will expire in {expiration_days_away} days."
        )
        status_message = f"Warning: Certificate for {site_url} is expring soon. The certificate will expire in {expiration_days_away} days."
        return ExpirationMsg(status_message=status_message, expiration_days_away=expiration_days_away)
    else:
        logger.debug(
            f"Returning the expiration status message. Message = Info: Certificate for {site_url} is good. The certificate does not expire for {expiration_days_away} days."
        )
        status_message = f"Info: Certificate for {site_url} is good. The certificate does not expire for {expiration_days_away} days."
        return ExpirationMsg(status_message=status_message, expiration_days_away=expiration_days_away)


def cert_check(startup_settings: StartupSettings) -> None:
    """Checks and provides the URL certificate expiration date.

    Parameters
    ----------
    startup_settings : StartupSettings
        `summary`: The startup settings from the YAML.
    """
    logger = logging.getLogger(__name__)

    # Override created to change user defined sleep if a certificate expires within the time the program would sleep.
    # This will reset each loop and if a certificate expires within the sleep the override will be enabled and the program will loop every 24 hours.
    # For example: Alerts for certificates expring set at 15 days, but the program sleeps 30 days.
    override_sleep_seconds = None

    # Loops through each URL.
    for url in startup_settings.site_urls:

        try:

            # Gets the certificate info status.
            url_certificate_output = get_url_certificate_info(
                url, startup_settings.buffer_days, startup_settings.time_zome
            )
            # Checks return output for specific strings to create email specific messages.
            # The return output will contain "Info:, Warning:, or Error:" when returning.
            if "Warning:" in str(url_certificate_output.status_message):
                subject = "Website Certificate Expiring Soon"
                # Removes the warning part at the beginning of the return output.
                body = str(url_certificate_output.status_message).replace("Warning: ", "")
                logger.warning(body)

                # Converts the dataclass to a dictionary.
                email_settings_asdict: dict = asdict(startup_settings.email_settings)
                send_email(
                    email_settings=email_settings_asdict,
                    subject=subject,
                    body=body,
                )

                if override_sleep_seconds:
                    logger.info("24-hour sleep override is already set from the previous certificate check")
                elif not override_sleep_seconds:
                    # Sets the sleep override because the certificate expires soon. The override will override the user's pre-defined sleep and change the sleep to only sleep for 24 hours.
                    override_sleep_seconds = 86400
                    logger.info("Setting sleep override to 24 hour because the certificate expires soon")
            elif "Error:" in str(url_certificate_output.status_message):
                subject = "Website Certificate Expired"
                # Removes the warning part at the beginning of the return output.
                body = str(url_certificate_output.status_message).replace("Error: ", "")
                logger.error(body)

                # Converts the dataclass to a dictionary.
                email_settings_asdict: dict = asdict(startup_settings.email_settings)
                send_email(
                    email_settings=email_settings_asdict,
                    subject=subject,
                    body=body,
                )

                if override_sleep_seconds:
                    logger.info("24-hour sleep override is already set from the previous certificate check")
                elif not override_sleep_seconds:
                    # Sets the sleep override because the certificate expired. The override will override the user's pre-defined sleep and change the sleep to only sleep for 24 hours.
                    override_sleep_seconds = 86400
                    logger.info("Setting sleep override to 24 hour because the certificate expired")
            elif "Info:" in str(url_certificate_output.status_message):
                # Checks if the program should continue to loop and sleep based on the "monitoring_sleep" value and no sleep override has been set from a different certificate expring.
                # A certificate expiring or expired will override at 24 hours, which will be a quicker then the time delta below.
                if startup_settings.continuous_monitoring and not override_sleep_seconds:
                    # Converts seconds to full time output for clean log output.
                    sleep_time = datetime.timedelta(seconds=startup_settings.monitor_sleep)
                    # Checks if the sleep days exceeds the certificates expiration date to set override.
                    if sleep_time.days >= url_certificate_output.expiration_days_away:
                        # Gets the amount of days between the sleep time and certificate expiration.
                        sleep_time_to_expiration_delta = sleep_time.days - url_certificate_output.expiration_days_away
                        logger.info(
                            f"The user-defined sleep exceeds the certificate expiration. Enabling override to {sleep_time_to_expiration_delta} seconds."
                        )
                        override_sleep_seconds = sleep_time_to_expiration_delta
                logger.info(str(url_certificate_output.status_message).replace("Info: ", ""))
            else:
                # Checks if program error alerts should be emailed.
                if startup_settings.alert_program_errors:
                    subject = "certmonitor failed to validate returned SSL check"
                    body = f"The URL '{url}' failed to be checked because certmonitor failed to validate returned SSL check value. Return value = {url_certificate_output.status_message}"

                    # Converts the dataclass to a dictionary.
                    email_settings_asdict: dict = asdict(startup_settings.email_settings)

                    send_email(
                        email_settings=email_settings_asdict,
                        subject=subject,
                        body=body,
                    )

                    exc_args = {
                        "main_message": f"CertMonitor failed to validate returned SSL check for URL {url}.",
                        "custom_type": CertMonitorError,
                        "returned_result": {url_certificate_output.status_message},
                        "suggested_resolution": "Please report this error to the developer.",
                    }
                    logger.error(CertMonitorError(FCustomException(message_args=exc_args)))
                else:
                    exc_args = {
                        "main_message": f"CertMonitor failed to validate returned SSL check for URL {url}.",
                        "custom_type": CertMonitorError,
                        "returned_result": {url_certificate_output.status_message},
                        "suggested_resolution": "Please report this error to the developer.",
                    }
                    logger.error(CertMonitorError(FCustomException(message_args=exc_args)))
        except Exception as exc:
            # Checks for error specifics for notification.
            if "getaddrinfo failed" in str(exc):
                # Checks if program error alerts should be emailed.
                if startup_settings.alert_program_errors:
                    subject = "Website Certificate Validation Skipped"
                    body = f"The URL '{url}' is not reachable. This website may be offline or decommissioned. If the website is no longer available,"
                    " you will want to remove this URL from the configuration file to avoid these alerts from continuing."

                    # Converts the dataclass to a dictionary.
                    email_settings_asdict: dict = asdict(startup_settings.email_settings)

                    send_email(
                        email_settings=email_settings_asdict,
                        subject=subject,
                        body=body,
                    )

                exc_args = {
                    "main_message": "Website Certificate Validation Skipped",
                    "custom_type": CertMonitorError,
                    "returned_result": f"The URL '{url}' is not reachable. This website may be offline or decommissioned.",
                    "suggested_resolution": "If the website is no longer available, you will want to remove this URL from the configuration file to avoid these alerts from continuing.",
                }
                logger.error(CertMonitorError(FCustomException(message_args=exc_args, tb_limit=0)))
            # Checks for error specifics for notification.
            elif "unable to get local issuer certificate" in str(exc):
                # Checks if program error alerts should be emailed.
                if startup_settings.alert_program_errors:
                    subject = "Website Certificate Validation Skipped"
                    body = f"The URL '{url}' certificate verification failed. CertMonitor could not get the local issuer certificate."

                    # Converts the dataclass to a dictionary.
                    email_settings_asdict: dict = asdict(startup_settings.email_settings)

                    send_email(
                        email_settings=email_settings_asdict,
                        subject=subject,
                        body=body,
                    )

                exc_args = {
                    "main_message": "Website Certificate Validation Skipped",
                    "custom_type": CertMonitorError,
                    "returned_result": f"The URL '{url}' certificate verification failed. CertMonitor could not get the local issuer certificate.",
                    "suggested_resolution": "Please check the local issuer certificate",
                }
                logger.error(CertMonitorError(FCustomException(message_args=exc_args, tb_limit=0)))
            else:
                raise

    # Checks if the program should continue to loop and sleep based on the "monitoring_sleep" value.
    if startup_settings.continuous_monitoring:
        try:
            # Checks if sleep override has been set by the program.
            # Override is only enabled if the user sets a sleep larger than the expiration alert threshold or the expriation date is within the alert threshold.
            if override_sleep_seconds:
                # Sets seconds in days.
                seconds_in_day = 60 * 60 * 24
                # Gets how many days are in the sleep seconds.
                override_days = override_sleep_seconds // seconds_in_day
                logger.info(
                    f"The program has continuous monitoring enabled, and the override time has been set to alert every {override_sleep_seconds} seconds [{override_days} day(s)] because a certificate is expiring or is expired"
                )
                # Sleeps for adjusted override.
                time.sleep(override_sleep_seconds)
            else:
                # Converts seconds to full time output for clean log output.
                sleep_time = datetime.timedelta(seconds=startup_settings.monitor_sleep)
                logger.info(f"The program has continuous monitoring enabled. Waiting {sleep_time} until next check")
                # Sleeps based on the monitor sleep seconds entry.
                time.sleep(startup_settings.monitor_sleep)
        except Exception as exc:
            exc_args = {
                "main_message": "An error has occurred while putting the program to sleep.",
                "custom_type": CertMonitorError,
                "returned_result": {exc},
                "suggested_resolution": "Please make sure your time is not set past '49 days, 17:02:47' or 4,294,968 seconds.",
            }
            logger.error(CertMonitorError(FCustomException(message_args=exc_args)))
            exit()
    else:
        logger.info(f"Website SSL validation check has completed")
        # Exits because the program is a single run.
        exit()
