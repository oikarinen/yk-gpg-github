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
    """Severity levels for checks."""

    IGNORE = 1
    WARN = 2
    ERROR = 3


# Configure how strict the verification should be.
CONFIG = {
    # Should imported Yubikeys be accepted?
    "IMPORTED": Severity.ERROR,
    # Should the developer be required to have been present to touch the key?
    "NO_TOUCH": Severity.WARN,
    # See https://www.yubico.com/support/security-advisories/ysa-2024-03/
    "VULNERABLE": Severity.WARN,
    # Allowed serial numbers, set to None to allow all.
    "SERIALS": Severity.ERROR,
    "ALLOWED_SERIALS": [11545724],
    # Allowed email domains, set to None to allow all.
    "EMAIL_DOMAIN": Severity.ERROR,
    "ALLOWED_EMAIL_DOMAINS": ["autolinkki.fi"],
    # Allow anonymous github email addresses, applied on top of EMAIL_DOMAINS.
    "ANONYMOUS_EMAIL": Severity.WARN,
}


class Base:
    """Base class with logging."""

    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)


class BaseResult(Base):
    """Base class for checks. Optionally, hold the result of multiple checks."""

    def __init__(self):
        super().__init__()
        self.result = True

    def check(self, severity: Severity, message: str) -> bool:
        """Log a check at correct level and return the check result: pass = True, fail = False."""
        match CONFIG[severity]:
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

    def result(self) -> bool:
        """Return the result of multiple checks."""
        return self.result


class VerificationError(Exception):
    """Verification error that is expected."""

    pass
