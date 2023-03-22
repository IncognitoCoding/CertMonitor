# Package/Modules
from dataclasses import asdict
from time import sleep
import os
import logging
import pathlib
from typing import Union
from fchecker.type import type_check
from ictoolkit.directors.yaml_director import read_yaml_config
from ictoolkit.directors.log_director import setup_logger_yaml
from ictoolkit.directors.email_director import send_email

# Exceptions
from fexception import FCustomException

# Local Package/Modules
from certmonitor.check.check import cert_check

# Local Dataclasses
from certmonitor.dataclasses.common import StartupSettings, EmailSettings

# Local Exceptions
from certmonitor.exceptions.exceptions import CertMonitorError

__author__ = "IncognitoCoding"
__copyright__ = "Copyright 2023, CertMonitor"
__credits__ = ["IncognitoCoding"]
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "IncognitoCoding"
__status__ = "Beta"


def get_startup_settings() -> StartupSettings:
    """Populates all hard-coded and yaml-configuration variables into a dataclass that is pulled into the main function.

    YAML entry validation checks are performed within this function. No manual configurations are setup within the program. All user settings are completed in the "settings.yaml" configuration file.

    Returns
    -------
    StartupSettings
        `summary`: The start settings from the YAML file.

    Raises
    ------
    FTypeError : fexception
        `summary`: The object value '{continuous_monitoring}' is not an instance of the required class(es) or subclass(es).
    FTypeError : fexception
        `summary`: The object value '{monitor_sleep}' is not an instance of the required class(es) or subclass(es).
    FTypeError : fexception
        `summary`: The object value '{email_alerts}' is not an instance of the required class(es) or subclass(es).
    FTypeError : fexception
        `summary`: The object value '{alert_program_errors}' is not an instance of the required class(es) or subclass(es).
    FTypeError : fexception
        `summary`: The object value '{buffer_days}' is not an instance of the required class(es) or subclass(es).
    FTypeError : fexception
        `summary`: The object value '{time_zome}' is not an instance of the required class(es) or subclass(es).
    FTypeError : fexception
        `summary`: The object value '{site_urls}' is not an instance of the required class(es) or subclass(es).
    """
    logger = logging.getLogger(__name__)

    # Initialized an empty dictionary for running variables.
    startup_variables: StartupSettings

    # This is required to start the program. The YAML file is read to set the required variables.
    # No file output or formatted console logging is completed in these variable population sections. Basic print statements will prompt an error.
    # Each configuration section is unique. To make the read easier, each sections will be comment blocked using ############.
    # Gets the config from the YAML file.
    # Gets the main program root directory.
    main_script_path = pathlib.Path.cwd()
    # Sets the reports directory save path.
    settings_path_name = os.path.abspath(f"{main_script_path}/settings.yaml")
    returned_yaml_read_config = read_yaml_config(settings_path_name, "FullLoader")

    # Validates required root keys exist in the YAML configuration.
    missing_key_msg: Union[str, None] = None
    if "general" not in returned_yaml_read_config:
        missing_key_msg = "The 'general' key is missing from the YAML file."
    if "site_urls" not in returned_yaml_read_config:
        missing_key_msg = "The 'site_urls' key is missing from the YAML file."
    if "email" not in returned_yaml_read_config:
        missing_key_msg = "The 'email' key is missing from the YAML file."

    if missing_key_msg:
        exc_args = {
            "main_message": missing_key_msg,
            "custom_type": CertMonitorError,
            "suggested_resolution": "Please verify you have set all required keys and try again.",
        }
        raise CertMonitorError(FCustomException(message_args=exc_args))
    ##############################################################################
    # Checks for continuous monitoring settings.
    #
    continuous_monitoring: bool = returned_yaml_read_config.get("general", {}).get("continuous_monitoring")  # type: ignore
    type_check(value=continuous_monitoring, required_type=bool)
    ##############################################################################
    ##############################################################################
    # Gets the monitoring sleep settings.
    #
    # Time is in seconds.
    monitor_sleep: int = returned_yaml_read_config.get("general", {}).get("monitor_sleep")  # type: ignore
    type_check(value=monitor_sleep, required_type=int)
    ##############################################################################
    # Gets the option to enable or not enable email alerts.
    email_alerts: bool = returned_yaml_read_config.get("general", {}).get("email_alerts")  # type: ignore
    type_check(value=email_alerts, required_type=bool)
    ##############################################################################
    # Gets the option to enable or not enable program error email alerts.
    #
    alert_program_errors: bool = returned_yaml_read_config.get("general", {}).get("alert_program_errors")  # type: ignore
    type_check(value=alert_program_errors, required_type=bool)
    ##############################################################################
    ##############################################################################
    # Gets buffer days before certificate warnings start.
    #
    buffer_days: int = returned_yaml_read_config.get("general", {}).get("buffer_days")  # type: ignore
    type_check(value=buffer_days, required_type=int)
    ##############################################################################
    ##############################################################################
    # Running timezone.
    time_zome: str = returned_yaml_read_config.get("general", {}).get("time_zome")  # type: ignore
    type_check(value=time_zome, required_type=str)
    ##############################################################################
    ##############################################################################
    # Gets URLs that need to be checked.
    site_urls: list[str] = returned_yaml_read_config.get("site_urls", {})  # type: ignore
    type_check(value=site_urls, required_type=list)
    ##############################################################################
    # Sets email values.
    smtp: str = returned_yaml_read_config.get("email", {}).get("smtp")  # type: ignore
    authentication_required: bool = returned_yaml_read_config.get("email", {}).get("authentication_required")  # type: ignore
    use_tls: bool = returned_yaml_read_config.get("email", {}).get("use_tls")  # type: ignore
    username: str = returned_yaml_read_config.get("email", {}).get("username")  # type: ignore
    password: str = returned_yaml_read_config.get("email", {}).get("password")  # type: ignore
    from_email: str = returned_yaml_read_config.get("email", {}).get("from_email")  # type: ignore
    to_email: str = returned_yaml_read_config.get("email", {}).get("to_email")  # type: ignore

    type_check(value=smtp, required_type=str)
    type_check(value=authentication_required, required_type=bool)
    type_check(value=use_tls, required_type=bool)
    type_check(value=username, required_type=str)
    type_check(value=password, required_type=str)
    type_check(value=from_email, required_type=str)
    type_check(value=to_email, required_type=str)
    ##############################################################################

    startup_variables = StartupSettings(
        continuous_monitoring=continuous_monitoring,
        monitor_sleep=monitor_sleep,
        email_alerts=email_alerts,
        alert_program_errors=alert_program_errors,
        buffer_days=buffer_days,
        time_zome=time_zome,
        site_urls=site_urls,
        email_settings=EmailSettings(
            smtp=smtp,
            authentication_required=authentication_required,
            use_tls=use_tls,
            username=username,
            password=password,
            from_email=from_email,
            to_email=to_email,
        ),
    )

    logger.debug(f"Returning value(s):\n  - {startup_variables}")

    # Returns the startup settings.
    return startup_variables


def main():
    # ############################################################################################
    # ######################Gets the programs main root directory/YAML File Path##################
    # ############################################################################################
    # Gets the main program root directory.
    main_script_path = pathlib.Path.cwd()

    # Checks that the main root program directory has the correct save folders created.
    # Sets the log directory save path.
    save_log_path = os.path.abspath(f"{main_script_path}/logs")

    # Checks if the save_log_path exists and if not it will be created.
    if not os.path.exists(save_log_path):
        os.makedirs(save_log_path)

    # Sets the log removal to False. Enable True for any debug testing.
    remove_log: bool = False
    if remove_log:
        # Removes existing log files if they exist.
        for file in os.listdir(save_log_path):
            filename = os.fsdecode(file)
            # Gets all log files.
            if filename.endswith(".log") or list(filename)[-1].isdigit():
                log_file_path = os.path.join(save_log_path, filename)
                os.remove(log_file_path)

    # Sets the YAML file configuration location.
    yaml_file_path = os.path.abspath(f"{main_script_path}/settings.yaml")

    try:
        # Calls function to setup the logging configuration with the YAML file.
        setup_logger_yaml(yaml_file_path)
    except FileNotFoundError:
        exc_args = {
            "main_message": "The settings.yaml file was not found.",
            "custom_type": CertMonitorError,
            "suggested_resolution": "Please verify you renamed the sample_settings.yaml file to settings.yaml and applied updates to the settings.",
        }
        raise CertMonitorError(FCustomException(message_args=exc_args))

    logger = logging.getLogger(__name__)

    logger.info("#" * 80)
    logger.info(" " * 34 + "CertMonitor" + " " * 34)
    logger.info("#" * 80)

    # Calls a function to pull in the startup variables.
    startup_variables = get_startup_settings()

    try:
        # Starts the check.
        cert_check(startup_settings=startup_variables)

        logger.info(f"{startup_variables.monitor_sleep} seconds until next torrent remove check")
        # Sleeps for the amount of seconds set in the YAML file.
        sleep(startup_variables.monitor_sleep)
    except Exception as exc:
        # Catches exceptions to email notifications.
        # Checks if program errors get emailed.
        if startup_variables.alert_program_errors:
            # Converts the dataclass to a dictionary.
            email_settings_asdict: dict = asdict(startup_variables.email_settings)

            send_email(
                email_settings=email_settings_asdict,
                subject="CertMonitor - Exiting Program Error Occurred",
                body=str(exc),
            )

        raise


# Checks that this is the main program that initiates the classes to start the functions.
if __name__ == "__main__":

    # Prints out at the start of the program.
    print("# " + "=" * 85)
    print("Author: " + __author__)
    print("Copyright: " + __copyright__)
    print("Credits: " + ", ".join(__credits__))
    print("License: " + __license__)
    print("Version: " + __version__)
    print("Maintainer: " + __maintainer__)
    print("Status: " + __status__)
    print("# " + "=" * 85)

    try:
        # Loops to keep the main program active.
        # The YAML configuration file will contain a sleep setting within the main function.
        while True:
            main()
            # 5-second delay sleep to prevent system resource issues if the function fails and the loop runs without any pause.
            sleep(5)
    # Catches ctrl + c
    except KeyboardInterrupt:
        print("\nKeyboard interruption. Exiting...")
        exit()
    # Catches ctrl + z
    # Input box failure (ex: ctrl + z) will throw this exception.
    except EOFError:
        print("Keyboard interruption. Exiting...")
        exit()
