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

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, UTC

import logging


# NOTE: would be nice to inherit from x509.Certificate but it's not possible as it's a Rust thing.
class Certificate:
    """X.509 certificate wrapper with additional validation methods.

    Extends the standard cryptography.x509.Certificate with convenience
    methods for common certificate operations used in YubiKey attestation
    validation. Provides high-level interfaces for certificate loading,
    signature verification, and validity checking.

    Designed to work with PEM-encoded certificates used in the
    YubiKey attestation certificate chain (attestation → intermediate → CA).

    Attributes:
        cert: Underlying cryptography.x509.Certificate object
    """

    def __init__(self, cert: x509.Certificate):
        self.cert = cert

    @classmethod
    def load_cert(cls, path: str) -> "Certificate":
        """Factory method to load a certificate from a file."""
        with open(path, "rb") as f:
            return cls(
                x509.load_pem_x509_certificate(
                    f.read(),
                    default_backend(),
                )
            )

    def write_cert(self, path: str, format: str = "PEM") -> None:
        """Write the certificate to a file."""
        with open(path, "wb") as f:
            f.write(self.cert.public_bytes(encoding=format))

    def verify_cert_signature(self, parent: "Certificate") -> bool:
        """Verify the signature of a certificate."""
        try:
            parent.cert.public_key().verify(
                self.cert.signature,
                self.cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                self.cert.signature_hash_algorithm,
            )
            logging.debug("Certificate signature verification succeeded.")
            return True
        except InvalidSignature as ex:
            logging.error("Certificate signature verification failed: %s." % ex)
            return False

    def verify_cert_validity(self, now: datetime = datetime.now(UTC)) -> bool:
        """Verify the validity of the certificate."""
        if self.cert.not_valid_before_utc <= now <= self.cert.not_valid_after_utc:
            logging.debug("Certificate is valid for the current time: %s UTC." % now)
            return True
        logging.error("Certificate is not valid for the current time: %s UTC." % now)
        return False
