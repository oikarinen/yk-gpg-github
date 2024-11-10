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

from contextlib import closing
from yubikit.openpgp import KEY_REF

from .cli import arg, CliBase
from .common import VerificationError
from .gpg import PublicKeyStore
from .git import CommitsVerifier
from .github import GithubPublicKey
from .yk import YubikeyGpg

import os

# Common or complex arguments
arg.github_user = arg(
    "--user",
    help="Github username",
    default=os.getenv("GITHUB_USERNAME", ""),
)
arg.gnupghome = arg(
    "--gnupghome",
    help="Path to the GPG home directory",
    default=os.getenv("HOME") + os.sep + ".gnupg",
)
arg.import_path = arg(
    "--path",
    help="Path to the attestation certificates",
    default="yubikeys",
)
arg.key_ref = arg(
    "--type",
    help="Type of attestation",
    default=KEY_REF.SIG,
    choices=[KEY_REF.AUT, KEY_REF.DEC, KEY_REF.SIG],
)
arg.ca = arg(
    "--ca",
    help="Path to the CA certificate",
    default="yubikeys/opgp-attestation-ca.pem",
)


class Cli(CliBase):
    """Verify the attestation of a Yubikey."""

    @arg.github_user
    @arg.import_path
    def attest(self) -> int:
        """Attest the Yubikey."""
        YubikeyGpg.attest(path=self.args.path, user=self.args.user)

    @arg.github_user
    def download(self) -> int:
        """Download the public key for a user from Github."""

        s = GithubPublicKey(user=self.args.user)
        result = s.download()
        if not result:
            s.log.error("Failed to download the public key for %s", self.args.user)
            return 1
        print(result)
        return 0

    @arg.gnupghome
    def generate(self) -> int:
        """Generate a new OpenGPG key on the Yubikey. The key never leaves the device."""
        YubikeyGpg().generate()

    @arg.gnupghome
    @arg("--keyid", help="Key ID to export")
    def export(self) -> int:
        """Export a public key from the GnuPG key store."""
        if not self.args.keyid:
            raise ValueError("Key ID is required")
        PublicKeyStore.export(keyid=self.args.keyid, path=self.args.gnupghome)

    @arg.key_ref
    @arg.ca
    @arg.import_path
    @arg("--commits", help="Commits range to verify")
    def verify(self) -> int:
        """Verify signatures and their attestation for a range of commits."""
        try:
            with closing(PublicKeyStore.load(ca=self.args.ca, path=self.args.path)) as keys:
                commits = CommitsVerifier(keys=keys, commits=self.args.commits)
                if commits.verify():
                    self.log.info("Git commits verified successfully.")
                return 0
        except ValueError as e:
            print("Failed to load the public keys: %s" % e)
            return 2
        except VerificationError as e:
            print("Commits verification failed: %s" % e)
            return 1

    def verify_keys(self) -> int:
        """Verify the keys in the GnuPG key store."""
        try:
            with closing(PublicKeyStore.load(ca=self.args.ca, path=self.args.path)) as keys:
                if keys.verify():
                    self.log.info("Public keys verified successfully.")
                    return 0
        except ValueError as e:
            print("Failed to load the public keys: %s" % e)
            return 2
        except VerificationError as e:
            print("Verification failed: %s" % e)
            return 1
