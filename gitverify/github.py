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

from .common import Base
from .utils.https import HttpsClient

import re

# TODO is this correct?
GITHUB_USERNAME_REGEX = r"^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$"


def is_valid_username(user: str) -> bool:
    """Check if the username is valid."""
    return bool(re.match(GITHUB_USERNAME_REGEX, user))


class GithubPublicKey(Base):
    """GPG operations for a Github user public keys."""

    def __init__(self, *, user: str) -> None:
        super().__init__()
        if not is_valid_username(user):
            raise ValueError("Invalid Github username: %s" % user)
        self.user = user
        self.client = HttpsClient(base_url="https://github.com/")

    def download(self) -> str:
        """Download the public keys of a Github user."""
        return self.client.get(f"{self.user}.gpg")
