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

from dataclasses import dataclass
from gnupg import GPG
from yubikit.openpgp import KEY_REF
from tempfile import NamedTemporaryFile, TemporaryDirectory

from .common import BaseResult, VerificationError
from .utils.x509 import Certificate
from .yk import YubikeyAttestationCertificate

import os
import re


attestation_file_name = "attestation-{key}.pem"
intermediate_file_name = "intermediate.pem"
public_key_file_name = "public_key.gpg"


@dataclass
class PublicKey(BaseResult):
    """GPG public key with attestation verification capabilities.

    Represents a GPG public key with associated metadata and provides
    methods for signature verification and attestation validation.
    Manages the relationship between GPG keys and their YubiKey attestation
    certificates.

    Supports lazy loading of key data from disk and caching of
    verification results for performance. Integrates with PublicKeyStore
    for key management and validation workflows.

    Attributes:
        path_prefix: Base path for key and certificate files
        email: Associated email address for the key
        fingerprint: GPG key fingerprint (loaded lazily)
        key: YubiKey key reference type (SIG/AUT/DEC)
        _cached: Whether verification results are cached
    """

    path_prefix: str
    email: str = None
    fingerprint: str = None
    key: KEY_REF = KEY_REF.SIG
    _cached: bool = False

    def __init__(
        self,
        *,
        path_prefix: str,
        email: str = None,
        fingerprint: str = None,
        key: KEY_REF = KEY_REF.SIG,
    ) -> None:
        super().__init__()
        self.path_prefix = path_prefix
        self.email = email
        self.fingerprint = fingerprint
        self.key = key
        self._cached = False

    def _with_path_prefix(self, filename: str) -> str:
        return self.path_prefix + os.sep + filename

    @property
    def _certs(self) -> dict:
        """Return the certificate paths."""
        return {
            "intermediate": {
                "path": self._with_path_prefix(intermediate_file_name),
                "parent": "ca",
            },
            "attestation": {
                "path": self._with_path_prefix(attestation_file_name.format(key=self.key.name)),
                "parent": "intermediate",
            },
        }

    @property
    def cached(self) -> bool:
        """Return if the attestation chain war already verified for this public key."""
        if self._cached:
            self.log.debug("Returning cached result %r for fingerprint %s." % (self.result, self.fingerprint))
        return self._cached

    @property
    def public_key_path(self) -> str:
        return self._with_path_prefix(public_key_file_name)

    def verify(self, *, ca: str) -> bool:
        """Verify the attestation chain."""

        # If the attestation chain has already been verified, return the cached result
        if self.cached:
            self.log.debug("Returning cached result %r for fingerprint %s." % (self.result, self.fingerprint))
            return self.result

        certs = self._certs
        certs["ca"] = {
            "path": ca,
            "parent": None,
        }
        for name, cert in certs.items():
            path = cert["path"]
            cert = YubikeyAttestationCertificate.load_cert(path) if name == "attestation" else Certificate.load_cert(path)
            certs[name]["cert"] = cert

        serial_number = None
        for name, cert in certs.items():
            self.log.debug("Verifying %s certificate." % name)
            if not cert["cert"].verify_cert_validity():
                self.fail("Certificate %s validity verification failed." % cert["path"])
            if cert["parent"] is None:
                # NOTE: The CA certificate in the repo is root of trust, so we only verify the validity
                continue
            if not cert["cert"].verify_cert_signature(certs[cert["parent"]]["cert"]):
                self.fail("%s certificate %s signature verification failed." % (name, cert["path"]))
            if name == "attestation":
                self.log.debug("Verifying the device settings from the attestation certificate.")
                if not cert["cert"].verify_device(fingerprint=self.fingerprint):
                    self.fail("Device verification failed for fingerprint %s." % cert["cert"].fingerprint)
                serial_number = cert["cert"].serial_number
        if self.result:
            self.log.info("Public key %s on yubikey #%s for <%s> verified successfully." % (self.fingerprint, serial_number, self.email))
        self._cached = True
        return self.result


class PublicKeyStore(BaseResult):
    """Repository-wide GPG public key management and validation.

    Manages a collection of GPG public keys for repository contributors,
    providing key loading, storage, and comprehensive validation against
    YubiKey attestation certificates. Supports both persistent and temporary
    key stores for different use cases.

    Key features:
    - Load keys from GPG keyrings or individual key files
    - Verify key signatures against trusted keys
    - Validate YubiKey attestation certificate chains
    - Support for temporary key stores (auto-cleanup)
    - Integration with organizational key policies

    Used by commit verification workflows to authenticate Git signatures
    and ensure cryptographic integrity of repository contributions.

    Attributes:
        temporary: Whether this is a temporary key store (auto-cleanup)
        gpg: GPG interface instance for key operations
        keys: Dictionary of loaded public keys
        ca: Path to CA certificate for attestation validation
    """

    def __init__(self, *, ca: str = None, path: str = None, temporary: bool = False) -> None:
        super().__init__()
        self.temporary = temporary
        if self.temporary:
            self._tmpdir = TemporaryDirectory()
            self.log.debug("Using temporary directory for gpg home: %s" % self._tmpdir)
        else:
            if not os.path.exists(path):
                raise FileNotFoundError("GPG home directory does not exist: %s" % path)
            self.log.debug("Using directory for gpg home: %s" % path)
        self.gpg = GPG(gnupghome=self._tmpdir.name if self.temporary else path)
        self.keys = {}
        self.ca = ca

    def close(self) -> None:
        """Cleanup the temporary directory."""
        if self.temporary:
            self.log.debug("Removing temporary directory: %s", self._tmpdir)
            self._tmpdir.cleanup()
        else:
            raise RuntimeError("Closing a non-temporary PublicKeyStore is not implemented")

    @classmethod
    def export(cls, *, path: str, keyid: str) -> int:
        """Export a public key from the gpg keyring."""
        keys = cls(path=path)
        public_keys = keys.gpg.export_keys(keyid, False)  # False => public keys
        if not public_keys:
            keys.fail("No public keys found for keyid %s" % keyid)
        print(public_keys)
        return 0

    @classmethod
    def load(cls, *, path: str, ca: str = None) -> "PublicKeyStore":
        """Factory method to create a temporary PublicKeyStore."""
        import_path = os.getcwd() + os.sep + path
        keys = cls(ca=ca, path=path, temporary=True)
        keys._load_public_keys(path=import_path)
        return keys

    def get(self, fingerprint: str) -> dict:
        """Get the public key for a fingerprint."""
        return self.keys.get(fingerprint, None)

    def import_public_key(self, key: str) -> str:
        """Import the public key into the gpg keyring."""
        result = self.gpg.import_keys(key)
        if not result:
            raise RuntimeError("No keys found in the public key: %s" % key)
        self.log.debug("Found %s keys with fingerprints: %r" % (result.count, result.fingerprints))
        if result.count > 1:
            raise RuntimeError("Multiple keys found in the public key: %s" % key)
        return result.fingerprints[0]

    @staticmethod
    def parse_email_from_uid(uid: str) -> str:
        """Parse the email from a uid."""
        return re.match(r"^(?P<name>.+) <(?P<email>.+)>$", uid).group("email")

    def email_for_fingerprint(self, fingerprint: str) -> str:
        """Get the author email for a fingerprint."""
        for key in self.gpg.list_keys():
            self.log.debug("Checking key: %r" % key)
            if key["fingerprint"] == fingerprint:
                self.log.debug("Found a public key for fingerprint %s: %r" % (fingerprint, key))
                return __class__.parse_email_from_uid(key["uids"][0])
        return None

    def _load_public_keys(self, *, path: str, key: KEY_REF = KEY_REF.SIG) -> None:
        """Load the public keys from the attestation certificates."""
        if not self.temporary:
            raise RuntimeError("Cannot load public keys from attestation certificates in a non-temporary PublicKeyStore")
        for p in os.listdir(path):
            path_prefix = path + os.sep + p
            if not os.path.isdir(path_prefix):
                self.log.debug("Skipping file: %s" % p)
                continue
            self.log.debug("Loading public key: %s" % p)
            key = PublicKey(key=key, path_prefix=path_prefix)
            with open(key.public_key_path, "r") as f:
                public_key = f.read()
                fingerprint = self.import_public_key(public_key)
                if self.keys.get(fingerprint):
                    raise ValueError("Duplicate fingerprint %s from attestation" % fingerprint)
                key.email = self.email_for_fingerprint(fingerprint)
                key.fingerprint = fingerprint
            self.keys[fingerprint] = key

    def verify(self) -> None:
        """Verify the attestation and the commits."""
        for fingerprint, public_key in self.keys.items():
            # First, verify that the attestation chains for all public keys in the repo are valid
            # and that the device information in the attestation certificate matches the policy
            if public_key.verify(ca=self.ca):
                self.log.info("Attestation verified successfully for fingerprint %s." % fingerprint)
            else:
                self.fail("Attestation verification failed for fingerprint %s." % fingerprint)
        if not self.result:
            raise VerificationError("Attestation verification failed for one or more public keys.")
        self.log.info("All attestation chains verified successfully.")

    def verify_signature(self, *, signature: str, data: str) -> str:
        """Verify the signature of the data."""
        # Verify the signature, verify_data() requires a file for the signature :(
        with NamedTemporaryFile() as f:
            f.write(signature.encode("utf-8"))
            f.seek(0)
            verified = self.gpg.verify_data(f.name, data)
            return verified.fingerprint
