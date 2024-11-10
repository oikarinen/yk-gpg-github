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

from requests import Session
from requests.adapters import HTTPAdapter, Retry

import logging


class HttpsClient:
    """A simple HTTPS client with retries."""

    STATUS_FORCELIST = [429, 500, 502, 503, 504]

    def __init__(
        self,
        *,
        base_url: str,
        retries: int = 5,
        backoff_factor: float = 1,
        status_forcelist: list[int] = STATUS_FORCELIST,
    ) -> None:
        self.log = logging.getLogger(__name__).setLevel(logging.WARNING)
        if not base_url.startswith("https://"):
            raise ValueError("Only HTTPS is supported.")
        self.base_url = base_url
        if not self.base_url.endswith("/"):
            self.log.warning("Base URL should end with a slash: %s", self.base_url)
        self.session = Session()
        retries = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def get(self, url: str) -> str:
        """Get the content of a url."""
        response = self.session.get(f"{self.base_url}{url}")
        response.raise_for_status()
        return response.text

    # TODO implement other methods as needed
