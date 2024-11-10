# Copyright (c) 2024 @oikarinen

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


from enum import Enum

import logging


class Severity(Enum):
    """Severity levels for policy checks and validation rules.

    Defines the enforcement level for various security and compliance
    checks performed during GPG key and commit verification.

    Attributes:
        IGNORE (1): Check is performed but result is ignored
        WARN (2): Check failure generates a warning but doesn't block
        ERROR (3): Check failure causes verification to fail
    """

    IGNORE = 1
    WARN = 2
    ERROR = 3


def load_config(config_file: str = None) -> dict:
    """Load configuration from YAML file or return defaults.

    Args:
        config_file: Path to YAML configuration file. If None, uses default config.

    Returns:
        Dictionary containing configuration values with Severity enums resolved.
    """
    import os
    import yaml

    # Default configuration
    defaults = {
        # Should imported Yubikeys be accepted?
        "IMPORTED": "ERROR",
        # Should the developer be required to have been present to touch the key?
        "NO_TOUCH": "WARN",
        # See https://www.yubico.com/support/security-advisories/ysa-2024-03/
        "VULNERABLE": "WARN",
        # Allowed serial numbers, set to None to allow all.
        "SERIALS": "ERROR",
        "ALLOWED_SERIALS": [11545724],
        # Allowed email domains, set to None to allow all.
        "EMAIL_DOMAIN": "ERROR",
        "ALLOWED_EMAIL_DOMAINS": ["autolinkki.fi"],
        # Allow anonymous github email addresses, applied on top of EMAIL_DOMAINS.
        "ANONYMOUS_EMAIL": "WARN",
        # Should committer email match the public key email?
        "COMMITTER_EMAIL": "ERROR",
    }

    # Try to load from YAML file
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                yaml_config = yaml.safe_load(f)
                if yaml_config:
                    defaults.update(yaml_config)
        except (yaml.YAMLError, IOError) as e:
            # Log warning but continue with defaults
            import logging
            logging.getLogger(__name__).warning(f"Failed to load config from {config_file}: {e}")

    # Convert string severity values to Severity enums
    config = {}
    for key, value in defaults.items():
        if isinstance(value, str) and value.upper() in Severity.__members__:
            config[key] = Severity[value.upper()]
        else:
            config[key] = value

    return config


# Global configuration
CONFIG = load_config()


def reload_config(config_file: str = None) -> None:
    """Reload configuration from YAML file.

    Args:
        config_file: Path to YAML configuration file. If None, reloads with defaults.
    """
    global CONFIG
    CONFIG = load_config(config_file)


class Base:
    """Base class providing logging infrastructure.

    Provides a standardized logging setup for all application classes.
    Automatically creates a logger named after the class, enabling
    hierarchical logging configuration and consistent log formatting.

    Attributes:
        log: Logger instance configured for this class
    """

    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)


class BaseResult(Base):
    """Base class for operations that perform multiple validation checks.

    Extends Base with a result tracking system for cumulative validation.
    Supports both pass/fail result tracking and detailed check logging
    with configurable severity levels.

    Used for complex validation operations where multiple independent
    checks need to be performed and aggregated into an overall result.

    Attributes:
        result (bool): Overall validation result (True = passed, False = failed)
        checks (list): List of individual check results and messages
    """

    def __init__(self):
        super().__init__()
        self.result = True

    def check(self, check: str, message: str) -> bool:
        """Log a check at correct level and return the check result: pass = True, fail = False."""
        severity = CONFIG[check]
        match severity:
            case Severity.WARN:
                self.log.warning(message)
            case Severity.ERROR:
                self.log.error(message)
        this = severity != Severity.ERROR
        self.result = self.result and this
        return this

    def fail(self, message: str) -> bool:
        """Log a check as failed and return False."""
        self.log.error(message)
        self.result = False
        return False


class VerificationError(Exception):
    """Exception raised when cryptographic or attestation verification fails.

    Indicates that a verification operation (GPG signature, certificate
    validation, attestation check, etc.) failed due to policy violations,
    invalid signatures, or security requirements not being met.

    Unlike programming errors, VerificationError indicates expected
    validation failures that should be reported to users as security
    or compliance issues rather than bugs.
    """

    pass
