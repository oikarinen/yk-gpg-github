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

import logging
import os
import json

from asn1 import Decoder
from binascii import hexlify
from enum import Enum
from ykman.device import list_all_devices
from ykman.base import YkmanDevice
from yubikit.core.smartcard import SmartCardConnection
from yubikit.openpgp import OpenPgpSession, KEY_REF

from .common import Base, BaseResult, CONFIG
from .github import is_valid_username
from . import gpg


from .utils.x509 import Certificate

class SupportedKeyRef(Enum):
    """Enumeration of supported YubiKey key reference types.

    Represents the three main key slots on a YubiKey that can be used
    for GPG operations and attestation verification.

    Attributes:
        SIG: Signature key slot (used for signing commits/tags)
        AUT: Authentication key slot (used for SSH authentication)
        DEC: Decryption key slot (used for encrypting/decrypting data)
    """
    SIG = KEY_REF.SIG
    AUT = KEY_REF.AUT
    DEC = KEY_REF.DEC

    @property
    def key_ref(self) -> KEY_REF:
        """Get the KEY_REF enum value (already stored as the enum value)."""
        return self.value

class YubikeyAttestationCertificate(BaseResult, Certificate):
    """YubiKey attestation certificate with device information extraction.

    Extends the base Certificate class to provide YubiKey-specific
    attestation certificate parsing and validation. Extracts device
    metadata like serial number, firmware version, and key generation
    source from the certificate extensions.

    Used internally by YubikeyGpg.verify_attestation() to validate
    certificate authenticity and extract device information.
    """

    @classmethod
    def load_cert(cls, path: str) -> "YubikeyAttestationCertificate":
        """Factory method to load an attestation certificate from a file."""
        cert = Certificate.load_cert(path)
        return cls(cert.cert)

    # See https://developers.yubico.com/PGP/Attestation.html
    _YK_OID_MAPPING = {
        "source": {
            "oid": "1.3.6.1.4.1.41482.5.2",
            "type": "integer",
            "values": {
                0x00: "imported (not permitted)",
                0x01: "generated",
            },
        },
        "fingerprint": {
            "oid": "1.3.6.1.4.1.41482.5.4",
            "type": "octet_string",
        },
        "firmware_version": {
            "oid": "1.3.6.1.4.1.41482.5.3",
            "type": "octet_string",
        },
        "serial_number": {
            "oid": "1.3.6.1.4.1.41482.5.7",
            "type": "integer",
        },
        "uif": {
            "oid": "1.3.6.1.4.1.41482.5.8",
            "type": "octet_string",
            "values": {
                "00": "never",
                "01": "once",
                "02": "always",
                "03": "cached",
                "04": "always, cached",
            },
        },
    }

    def __init__(self, cert: Certificate) -> None:
        super().__init__()
        self.cert = cert

    def _get_value(self, key: str) -> any:
        """Get the value of an OID for a key and convert it to a human-readable format."""

        def octet_to_string(value: bytes) -> str:
            return hexlify(value).decode("utf-8")

        def decode_der_integer(value: bytes) -> int:
            """Decode a DER-encoded integer."""
            decoder = Decoder()
            decoder.start(value)
            tag, value = decoder.read()
            return value

        m = self._YK_OID_MAPPING[key]
        for e in self.cert.extensions:
            self.log.debug("Extension: %s", e.oid.dotted_string)
            if e.oid.dotted_string == m["oid"]:
                value = None
                match m["type"]:
                    case "octet_string":
                        value = octet_to_string(decode_der_integer(e.value.value))
                    case "integer":
                        value = decode_der_integer(e.value.value)
                    case _:
                        raise ValueError("Unsupported type: %s", m["type"])

                if m.get("values"):
                    converted = m["values"].get(value)
                    return converted
                return value
        raise ValueError("OID %s not found in certificate.", m["oid"])

    @property
    def fingerprint(self) -> str:
        return self._get_value("fingerprint").upper()

    @property
    def firmware_version(self) -> str:
        return self._get_value("firmware_version")

    @property
    def serial_number(self) -> int:
        return self._get_value("serial_number")

    @property
    def touch_policy(self) -> str:
        return self._get_value("uif")

    @property
    def source(self) -> str:
        return self._get_value("source")

    def verify_device(self, *, fingerprint: str) -> bool:
        """Verify the Yubikey device information matches policy."""
        if self.source != "generated":
            self.check("IMPORTED", "Yubikey #%s was not generated: %s" % (self.serial_number, self.source))
        if self.firmware_version < "050700":  # 5.7.0
            self.check(
                "VULNERABLE", "Yubikey #%s has firmware version %s that is vulnerable to YSA-2024-03." % (self.serial_number, self.firmware_version)
            )
        if self.serial_number not in CONFIG["ALLOWED_SERIALS"]:
            self.check("SERIALS", "Serial number %s is not allowed." % self.serial_number)
        if self.touch_policy == "never":
            self.check("NO_TOUCH", "Yubikey #%s has touch policy is set to never." % self.serial_number)
        if self.fingerprint != fingerprint:
            self.fail("Device fingerprint %s for #%s does not match the public key %s." % (self.fingerprint, self.serial_number, fingerprint))
        return self.result


class YubikeyGpg(Base):
    """High-level interface for YubiKey GPG operations and attestation.

    Provides methods for interacting with YubiKey devices to perform
    GPG key operations and attestation certificate verification.
    Handles the complexities of YubiKey communication and certificate
    chain validation.

    Key operations:
        - attest: Export attestation certificates from YubiKey
        - verify_attestation: Validate attestation certificate chain
        - generate: Generate new GPG keys (not currently supported)

    All operations include comprehensive error handling and logging
    for troubleshooting YubiKey connectivity and certificate issues.
    """

    def __init__(self) -> None:
        super().__init__()

    def generate(self) -> bool:
        """Generate a new GPG key on the Yubikey."""
        raise NotImplementedError("Generating a new GPG key on the Yubikey is not supported.")

    @classmethod
    def attest(cls, *, path: str, user: str) -> None:
        """Export the attestation certificates from the Yubikey."""
        if not user or not is_valid_username(user):
            raise ValueError("Github username not provided.")

        # Export the attestation certificates
        for key in KEY_REF.AUT, KEY_REF.DEC, KEY_REF.SIG:
            attestation_path = path + os.sep + user + os.sep + gpg.PublicKey.attestation_file_name.format(key=key)
            cls.get_attestation_cert(key=key).write_cert(path=attestation_path)
            logging.info(f"Attestation certificate for slot {key.name} written to {attestation_path}.")

        # Export the intermediate certificate
        intermediate_path = path + os.sep + user + os.sep + gpg.PublicKey.intermediate_file_name
        cls.get_intermediate_cert().write_cert(path=intermediate_path)
        logging.info(f"Intermediate certificate written to {intermediate_path}.")

    @classmethod
    def verify_attestation(cls, *, attestation_path: str, key_ref: KEY_REF, ca_cert_path: str = None) -> dict:
        """Verify the attestation certificates for a user using pure Python implementation."""
        from .utils.x509 import Certificate

        # Check if required files exist
        attestation_file = f"{attestation_path}/attestation-{key_ref.name}.pem"
        intermediate_file = f"{attestation_path}/intermediate.pem"

        if not os.path.exists(attestation_file):
            raise FileNotFoundError(f"Attestation certificate not found: {attestation_file}")
        if not os.path.exists(intermediate_file):
            raise FileNotFoundError(f"Intermediate certificate not found: {intermediate_file}")

        # Load certificates
        attestation_cert = YubikeyAttestationCertificate.load_cert(attestation_file)
        intermediate_cert = Certificate.load_cert(intermediate_file)

        # Load CA certificate if provided
        ca_cert = None
        if ca_cert_path and os.path.exists(ca_cert_path):
            ca_cert = Certificate.load_cert(ca_cert_path)

        # Validate certificate chain
        if not attestation_cert.verify_cert_validity():
            raise RuntimeError("Attestation certificate is not valid")

        if not intermediate_cert.verify_cert_validity():
            raise RuntimeError("Intermediate certificate is not valid")

        if ca_cert and not ca_cert.verify_cert_validity():
            raise RuntimeError("CA certificate is not valid")

        # Verify certificate signatures
        if not attestation_cert.verify_cert_signature(intermediate_cert):
            raise RuntimeError("Attestation certificate signature verification failed")

        if ca_cert and not intermediate_cert.verify_cert_signature(ca_cert):
            raise RuntimeError("Intermediate certificate signature verification failed")

        # Check attestation policies
        if attestation_cert.source != "generated":
            raise RuntimeError(f"YubiKey key was not generated on device: {attestation_cert.source}")

        # Check firmware version for YSA-2024-03 vulnerability
        if attestation_cert.firmware_version < "050700":  # 5.7.0
            raise RuntimeError(f"YubiKey firmware {attestation_cert.firmware_version} is vulnerable to YSA-2024-03")

        # Extract attestation data
        serial = attestation_cert.serial_number
        fingerprint = attestation_cert.fingerprint

        # Parse firmware version
        major = int(attestation_cert.firmware_version[:2], 16)
        minor = int(attestation_cert.firmware_version[2:4], 16)
        patch = int(attestation_cert.firmware_version[4:6], 16) if len(attestation_cert.firmware_version) >= 6 else 0
        version = f"{major}.{minor}.{patch}"

        logging.info(f"Attestation verification successful for YubiKey #{serial} with firmware {version}")

        return {
            "serial": serial,
            "fingerprint": fingerprint,
            "version": version
        }

    @classmethod
    def get_attestation_cert(cls, *, key: KEY_REF = KEY_REF.SIG) -> Certificate:
        """Get the attestation certificate from the Yubikey."""
        with cls.get_single_device().open_connection(SmartCardConnection) as connection:
            session = OpenPgpSession(connection)
            # TODO read pin from user
            pin = ""
            raise NotImplementedError("Reading the pin from the user is not supported.")
            session.verify_pin(pin)
            return session.attest_key(key)

    @classmethod
    def get_intermediate_cert(cls) -> Certificate:
        """Get the intermediate certificate from the Yubikey."""
        with cls.get_single_device().open_connection(SmartCardConnection) as connection:
            session = OpenPgpSession(connection)
            return session.get_certificate(KEY_REF.ATT)

    @staticmethod
    def get_single_device() -> YkmanDevice:
        """Get the the Yubikey device or fail if multiple or none found."""
        devices = list_all_devices()
        if not devices:
            raise RuntimeError("No Yubikeys found.")
        if len(devices) > 1:
            raise RuntimeError("Multiple Yubikeys found: %r." % devices)
        device, _info = devices[0]
        return device
