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

from git import Repo, Commit
from io import BytesIO

from .common import BaseResult, CONFIG
from .gpg import PublicKeyStore


class CommitsVerifier(BaseResult):
    """Batch verifier for Git commit signatures.

    Iterates through a range of Git commits and verifies each commit's
    GPG signature against a provided public key store. Performs comprehensive
    validation including signature verification, committer identity checks,
    and email domain validation.

    Designed for automated verification of commit ranges in CI/CD pipelines
    or security audits. Provides detailed logging of verification results
    and maintains verification state across multiple commits.

    Attributes:
        keys: PublicKeyStore containing trusted GPG public keys
        commits: Git revision range to verify (e.g., "HEAD~5..HEAD")
        repo: GitPython Repo object for the repository
    """

    def __init__(self, *, keys: PublicKeyStore, commits: any, path: str = ".") -> None:
        super().__init__()
        self.keys = keys
        self.commits = commits
        self.repo = Repo(path)

    def verify(self) -> bool:
        """Verify the signatures of a set of git commits."""
        for commit in self.repo.iter_commits(self.commits):
            verifier = CommitVerifier(commit, self.keys)
            if verifier.verify():
                self.log.info("Commit %s by <%s> verified succesfully." % (commit.hexsha, commit.committer.email))
            else:
                self.fail("Commit %s failed verification." % commit.hexsha)

        return self.result


class CommitVerifier(BaseResult):
    """Individual Git commit signature verifier.

    Performs comprehensive validation of a single Git commit's GPG signature
    and associated metadata. Checks signature cryptographic validity, key
    authenticity, and committer identity compliance with organizational policies.

    Validation includes:
    - GPG signature verification against trusted key store
    - Committer email domain validation
    - Anonymous GitHub email detection
    - Key attestation chain verification

    Provides detailed error reporting and policy violation logging
    for security auditing and compliance verification.

    Attributes:
        commit: GitPython Commit object to verify
        keys: PublicKeyStore for signature verification
    """

    def __init__(self, commit: Commit, keys: PublicKeyStore) -> None:
        super().__init__()
        self.commit = commit
        self.keys = keys

    @staticmethod
    def is_anonymous_email(email: str) -> bool:
        """Check if an email is an anonymous github email."""
        return email.endswith("@users.noreply.github.com")

    def _verify_signature(self) -> None:
        c = self.commit
        if c.gpgsig is None:
            self.fail("Commit %s is not signed." % c.hexsha)
        # Verify the signature and extract the fingerprint
        fingerprint = self.verify_commit_signature()
        # Check the fingerprint is in the list of public keys
        public_key = self.keys.get(fingerprint)
        # Check the committer email matches the public key email
        if c.committer.email != public_key.email:
            self.check("COMMITTER_EMAIL", "Committer email %s does not match %s" % (c.committer.email, public_key.email))
        if public_key is None:
            self.fail("No public key found for commit %s fingerprint %s" % (c.hexsha, fingerprint))
        # Check the public key is valid and has proper attestation chain
        if not public_key.verify(ca=self.keys.ca):
            self.fail("Public key %s verification failed for commit %s." % (public_key.fingerprint, c.hexsha))

    def _verify_committer_email(self) -> None:
        c = self.commit
        # Check the committer email is not an anonymous github email
        if __class__.is_anonymous_email(c.committer.email):
            self.check("ANONYMOUS_EMAIL", f"Committer email {c.committer.email} is an anonymous github email.")
        # Check the committer email matches our domain
        allowed_domains = CONFIG["ALLOWED_EMAIL_DOMAINS"]
        if not any([c.committer.email.endswith(f"@{domain}") for domain in allowed_domains]):
            self.check("EMAIL_DOMAIN", "Committer email %s does not match allowed domains %r." % (c.committer.email, allowed_domains))

    def verify(self) -> bool:
        """Verify the signature of a git commit."""
        # First check the commit has a signature
        self._verify_signature()
        self._verify_committer_email()
        return self.result

    def verify_commit_signature(self) -> str:
        """Verify the signature of a git commit."""

        # Create a copy of the commit object without the signature
        copy = Commit(
            repo=self.commit.repo,
            binsha=self.commit.binsha,
            tree=self.commit.tree,
            author=self.commit.author,
            authored_date=self.commit.authored_date,
            author_tz_offset=self.commit.author_tz_offset,
            committer=self.commit.committer,
            committed_date=self.commit.committed_date,
            committer_tz_offset=self.commit.committer_tz_offset,
            message=self.commit.message,
            encoding=self.commit.encoding,
            parents=self.commit.parents,
            gpgsig=None,  # exclude the signature from the data
        )
        # Serialize the commit to a stream
        data = None
        with BytesIO() as stream:
            copy._serialize(stream)
            streamlen = stream.tell()
            stream.seek(0)
            data = stream.read(streamlen)
        if data is None:
            raise RuntimeError("Failed to serialize commit %s" % self.commit.hexsha)

        self.log.debug("Verifying signature %s for commit %s" % (self.commit.gpgsig, self.commit))
        fingerprint = self.keys.verify_signature(signature=self.commit.gpgsig, data=data)
        self.log.debug("Verified signature for commit %s, good signature with fingerprint %s" % (self.commit, fingerprint))
        return fingerprint
