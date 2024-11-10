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

from asn1 import Decoder
from binascii import hexlify
from ykman.device import list_all_devices
from ykman.base import YkmanDevice
from yubikit.core.smartcard import SmartCardConnection
from yubikit.openpgp import OpenPgpSession, KEY_REF

from .common import Base, BaseResult, CONFIG
from .github import is_valid_username
from . import gpg
from .utils.x509 import Certificate

import logging
import os


class YubikeyAttestationCertificate(BaseResult, Certificate):
    """Get the device information from a Yubikey attestation certificate."""

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
    """GPG key operations on a Yubikey."""

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
