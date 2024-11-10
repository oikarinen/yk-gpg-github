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

from .cli import arg, CliBase, ExitCode
from .common import VerificationError
from .gpg import PublicKeyStore
from .git import CommitsVerifier
from .github import GithubPublicKey
from .yk import SupportedKeyRef, YubikeyGpg

import os
import glob

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
    help="Type of attestation (AUT, DEC, SIG)",
    default=KEY_REF.SIG.name,
    choices=[KEY_REF.AUT.name, KEY_REF.DEC.name, KEY_REF.SIG.name],
)
arg.ca = arg(
    "--ca",
    help="Path to the CA certificate",
    default="yubikeys/opgp-attestation-ca.pem",
)


class Cli(CliBase):
    """Main CLI class for YubiKey GPG Git verification commands.

    Provides a complete command-line interface for managing YubiKey-based
    GPG key attestation and Git commit verification. Supports the full
    workflow from key generation to commit verification.

    Available commands:
        attest: Export attestation certificates from YubiKey
        download: Download public keys from GitHub
        export: Export GPG keys from keyring
        generate: Generate new GPG key on YubiKey (not supported)
        verify: Verify Git commits using GPG signatures
        verify-attestation: Verify YubiKey attestation certificates
        verify-all-attestations: Verify all attestation certificates in directory
        verify-keys: Verify GPG public keys against attestation

    Each command includes comprehensive error handling and appropriate
    exit codes for automation and scripting use cases.
    """

    @arg.github_user
    @arg.import_path
    def attest(self) -> ExitCode:
        """Attest the Yubikey."""
        try:
            YubikeyGpg.attest(path=self.args.path, user=self.args.user)
            return ExitCode.SUCCESS
        except ValueError:
            return ExitCode.FAILURE

    def _verify_single_attestation(self, attestation_path: str, key_ref) -> bool:
        """Verify a single attestation and return success status."""
        try:
            result = YubikeyGpg.verify_attestation(
                attestation_path=attestation_path,
                key_ref=key_ref,
                ca_cert_path=self.args.ca
            )
            self.log.info("✓ %s verification successful for %s", key_ref.name, attestation_path)
            self.log.info("  Serial: %s", result['serial'])
            self.log.info("  Fingerprint: %s", result['fingerprint'])
            return True
        except (RuntimeError) as e:
            self.log.error("✗ %s verification failed: %s", key_ref.name, e)
            return False

    @arg.key_ref
    @arg.ca
    @arg.github_user
    @arg.import_path
    def verify_attestation(self) -> ExitCode:
        """Verify the attestation certificates for a user."""
        try:
            # Convert string to SupportedKeyRef enum, then get KEY_REF value
            supported_key_ref = getattr(SupportedKeyRef, self.args.type, None)
            if supported_key_ref is None:
                raise ValueError(f"Invalid key type: {self.args.type}")
            key_ref = supported_key_ref.key_ref

            if not self.args.user:
                raise ValueError("--user must be specified")
            from .github import is_valid_username
            if not is_valid_username(self.args.user):
                raise ValueError(f"Invalid GitHub username: {self.args.user}. Username must match GitHub's format.")

            attestation_path = self.args.path + os.sep + self.args.user + "-attestation"

            success = self._verify_single_attestation(attestation_path, key_ref)
            return ExitCode.SUCCESS if success else ExitCode.FAILURE
        except ValueError:
            return ExitCode.FAILURE

    @arg("--attestations-path", help="Path to the directory containing attestation directories", default="yubikeys")
    @arg.ca
    def verify_all_attestations(self) -> ExitCode:
        """Verify all attestation certificates in a directory."""
        attestations_path = self.args.attestations_path
        if not os.path.exists(attestations_path):
            raise FileNotFoundError("Attestations path does not exist: %s" % attestations_path)

        # Find all attestation directories
        pattern = os.path.join(attestations_path, "*-attestation")
        attestation_dirs = glob.glob(pattern)

        if not attestation_dirs:
            raise FileNotFoundError("No attestation directories found in %s" % attestations_path)

        count = 0
        for dir_path in attestation_dirs:
            self.log.info("Verifying attestation in: %s", dir_path)

            # Try each key type - at least one should succeed if certificates exist
            for supported_key_ref in SupportedKeyRef:
                if self._verify_single_attestation(dir_path, supported_key_ref.key_ref):
                    count += 1
                    break  # Success - exit the loop
            else:
                # This executes only if no key type succeeded
                self.log.error("✗ No valid attestation certificates found in %s", dir_path)

        total_count = len(attestation_dirs)
        self.log.info("Verification complete: %d/%d attestation directories verified successfully", count, total_count)
        if count == total_count:
            return ExitCode.SUCCESS

        self.log.error("%d attestation directories failed verification", total_count - count)
        return ExitCode.FAILURE  # Consider partial failure as overall failure

    @arg.github_user
    def download(self) -> ExitCode:
        """Download the public key for a user from Github."""

        try:
            s = GithubPublicKey(user=self.args.user)
            result = s.download()
            if not result:
                self.log.error("Failed to download the public key for %s", self.args.user)
                return ExitCode.FAILURE
            print(result)
            return ExitCode.SUCCESS
        except Exception as e:
            self.log.error("Failed to download the public key for %s: %s", self.args.user, e)
            return ExitCode.FAILURE

    @arg.gnupghome
    def generate(self) -> ExitCode:
        """Generate a new OpenGPG key on the Yubikey. The key never leaves the device."""
        try:
            YubikeyGpg().generate()
            return ExitCode.SUCCESS
        except Exception as e:
            self.log.error("Failed to generate YubiKey: %s", e)
            return ExitCode.FAILURE

    @arg.gnupghome
    @arg("--keyid", help="Key ID to export")
    def export(self) -> ExitCode:
        """Export a public key from the GnuPG key store."""
        try:
            if not self.args.keyid:
                raise ValueError("Key ID is required")
            PublicKeyStore.export(keyid=self.args.keyid, path=self.args.gnupghome)
            return ExitCode.SUCCESS
        except ValueError:
            return ExitCode.FAILURE
        except Exception as e:
            self.log.error("Failed to export key: %s", e)
            return ExitCode.FAILURE

    @arg.key_ref
    @arg.ca
    @arg.import_path
    @arg("--commits", help="Commits range to verify")
    def verify(self) -> ExitCode:
        """Verify signatures and their attestation for a range of commits."""
        try:
            with closing(PublicKeyStore.load(ca=self.args.ca, path=self.args.path)) as keys:
                commits = CommitsVerifier(keys=keys, commits=self.args.commits)
                if commits.verify():
                    self.log.info("Git commits verified successfully.")
                    return ExitCode.SUCCESS
        except VerificationError as e:
            self.log.error("Commits verification failure: %s" % e)

        self.log.error("Commits verification failed")
        return ExitCode.FAILURE

    def verify_keys(self) -> ExitCode:
        """Verify the keys in the GnuPG key store."""
        try:
            with closing(PublicKeyStore.load(ca=self.args.ca, path=self.args.path)) as keys:
                if keys.verify():
                    self.log.info("Public keys verified successfully.")
                    return ExitCode.SUCCESS
        except VerificationError as e:
            self.log.error("Verification failure: %s" % e)

        self.log.error("Verification failed")
        return ExitCode.FAILURE
