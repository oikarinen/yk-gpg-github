# gitverify

A tool for verifying Git commit signatures using YubiKey attestation and GitHub GPG keys.

## Overview

gitverify provides cryptographic verification of Git commits by validating signatures against attested YubiKey certificates and GitHub's GPG public keys. It ensures that commits were signed with properly attested hardware security keys, providing strong guarantees about commit authenticity and integrity.

## Features

- **YubiKey Attestation Verification**: Validates that GPG keys were generated on attested YubiKey devices
- **GitHub GPG Key Integration**: Downloads and validates public keys from GitHub user profiles
- **Comprehensive CLI**: Full command-line interface for all operations
- **Certificate Chain Validation**: Verifies X.509 certificate chains for hardware attestation
- **Git Integration**: Seamlessly integrates with Git repositories for commit verification

## Installation

### Requirements

- Python 3.12+
- YubiKey with OpenPGP support (optional, for key generation)
- GPG tools

### Setup

```bash
# Clone the repository
git clone https://github.com/oikarinen/gitverify.git
cd gitverify

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Usage

### Basic Commands

```bash
# Generate a new GPG key on YubiKey
gitverify generate

# Attest YubiKey and associate with GitHub user
gitverify attest --user your-github-username

# Download public key from GitHub
gitverify download --user your-github-username

# Export public key from local GPG store
gitverify export --keyid YOUR_KEY_ID

# Verify commit signatures and attestation
gitverify verify --commits HEAD~5..HEAD

# Verify attestation certificates for a user
gitverify verify-attestation --user your-github-username --type SIG

# Verify all attestation certificates in a directory
gitverify verify-all-attestations --attestations-path yubikeys

# Verify keys in GPG store
gitverify verify-keys
```

### YubiKey Attestation

The CLI provides comprehensive support for YubiKey attestation certificate management.

#### Export Attestation Certificates

Extract attestation certificates and signer certificates from your YubiKey:

```bash
# Export certificates for a GitHub user
gitverify attest --user your-github-username

# Creates certificates in: yubikeys/{user}-attestation/
# - attestation-AUT.pem, attestation-DEC.pem, attestation-SIG.pem
# - intermediate.pem (signer certificate)
```

#### Verify Attestation Certificates

Validate attestation certificate chains and check for known vulnerabilities:

```bash
# Verify certificates for a specific user and key type
gitverify verify-attestation --user your-github-username --type SIG

# Checks performed:
# - Certificate chain validation
# - YubiKey firmware vulnerability check (YSA-2024-03)
# - Attestation signature verification
```

### Configuration

The tool supports YAML-based configuration for customizing security policies and validation rules. Use the `--config` option to specify a configuration file.

#### Configuration File Format

Create a YAML file (e.g., `config.yaml`) with the following structure:

```yaml
# Security policy settings
IMPORTED: "ERROR"          # Should imported Yubikeys be accepted?
NO_TOUCH: "WARN"           # Should the developer be required to touch the key?
VULNERABLE: "ERROR"        # YubiKey firmware vulnerability check (YSA-2024-03)
SERIALS: "ERROR"           # Serial number validation
COMMITTER_EMAIL: "ERROR"   # Should committer email match the public key email?

# Allow anonymous GitHub email addresses (applied on top of EMAIL_DOMAINS)
ANONYMOUS_EMAIL: "WARN"

# Lists of allowed values
ALLOWED_SERIALS:
  - 11545724              # Add your organization's YubiKey serials
  - 12345678

ALLOWED_EMAIL_DOMAINS:
  - "yourcompany.com"     # Restrict to specific email domains
  - "yourdomain.org"
```

#### Severity Levels

- `"ERROR"`: Violations cause verification to fail
- `"WARN"`: Violations generate warnings but allow verification to continue
- `"IGNORE"`: Check is performed but results are ignored

#### Usage

```bash
# Use a custom configuration file
gitverify --config config.yaml verify-attestation --user username --type SIG

# Use default configuration (built-in defaults)
gitverify verify-attestation --user username --type SIG
```

#### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `IMPORTED` | Accept imported (non-generated) GPG keys | `"ERROR"` |
| `NO_TOUCH` | Require user presence for key operations | `"WARN"` |
| `VULNERABLE` | Check for known firmware vulnerabilities | `"WARN"` |
| `SERIALS` | Validate YubiKey serial numbers | `"ERROR"` |
| `EMAIL_DOMAIN` | Restrict allowed email domains | `"ERROR"` |
| `ANONYMOUS_EMAIL` | Handle GitHub anonymous emails | `"WARN"` |
| `COMMITTER_EMAIL` | Verify committer email matches key | `"ERROR"` |

#### Example Configuration

See `config.example.yaml` for a complete example configuration file.

## Architecture

### Core Modules

- **`gitverify.py`**: Main CLI entry point
- **`cli.py`**: Command-line interface framework
- **`common.py`**: Shared configuration and utilities
- **`git.py`**: Git repository integration and commit verification
- **`gpg.py`**: GPG key management and validation
- **`yk.py`**: YubiKey hardware interaction and attestation
- **`github.py`**: GitHub API integration for GPG keys
- **`utils/`**: Utility modules for HTTPS and X.509 operations

### Why gitverify?

### Limitations of Standard Git Signing Verification

Standard Git commit signing verification has significant limitations:

- **No Key Source Assurance**: Git signing only verifies that a commit was signed with a specific GPG key, but provides no guarantees about where or how that key was generated
- **GitHub Personal Account Risks**: Anyone can upload any GPG key to their GitHub personal account, including keys from compromised systems or generated elsewhere
- **Lack of Organizational Control**: Organizations cannot prevent contributors from uploading untrusted keys to their personal GitHub accounts
- **No Hardware Attestation**: Standard verification doesn't ensure keys were generated on secure hardware like YubiKeys - keys may be imported from unsafe sources
- **Single Point of Failure**: If a contributor removes their key from GitHub, all historical commit verifications become untrustworthy

### gitverify Security Model

gitverify addresses these limitations by implementing a comprehensive verification chain:

1. **Hardware Attestation**: Keys must be generated on attested YubiKey devices with verified certificate chains
2. **Certificate Validation**: X.509 certificates cryptographically prove hardware authenticity and origin
3. **Organizational Control**: Admins can configure allowed YubiKey serial numbers and email domains
4. **Key Source Verification**: Only keys with proper hardware attestation are accepted
5. **Tamper Detection**: Certificate chains prevent key substitution attacks
6. **Signature Verification**: Standard GPG signature validation as the final step

### Benefits for Organizations

- **Stronger Security Guarantees**: Hardware-backed key generation prevents key compromise
- **Nonrepudiation**: Cryptographic proof of commit authorship prevents developers from denying malicious actions:
  - Cannot claim "account was hacked" when hardware-attested keys prove authenticity
  - Clear attribution for code introducing malware, pirated code, or license violations
  - Forensic evidence for legal proceedings and compliance investigations
- **Audit Trail**: Certificate chains provide verifiable proof of key origin and usage history
- **Compliance**: Meets regulatory requirements for cryptographic key management and audit trails
- **Incident Response**: Immediate identification of compromised or malicious commits
- **Zero-Trust Model**: Every commit must prove its cryptographic authenticity

## Key Management Workflow

### Adding New Developer Keys

gitverify implements a secure, auditable process for adding new developer keys that leverages your existing pull request approval workflows:

#### For Developers: Key Submission Process

1. **Generate Attested Key**:
   ```bash
   # Generate new key on YubiKey
   gitverify generate

   # Attest the key and associate with your GitHub username
   gitverify attest --user your-github-username
   ```

2. **Export Public Materials**:
   ```bash
   # Export your public key
   gitverify export --keyid YOUR_KEY_ID > your-key.asc

   # The attestation process creates certificates in yubikeys/ directory
   ```

3. **Submit Pull Request**:
   - Create a branch: `git checkout -b add-key-yourusername`
   - Add your public key and attestation certificates
   - Submit PR with clear description of your key details

#### For Maintainers: Key Approval Process

1. **Review Key Materials**:
   ```bash
   # Verify the submitted key
   gpg --import your-key.asc
   gpg --list-keys YOUR_KEY_ID

   # Check attestation certificates
   openssl x509 -in yubikeys/your-attestation-cert.pem -text
   ```

2. **Validate Attestation**:
   ```bash
   # Run verification on a test commit
   gitverify verify --commits HEAD
   ```

3. **Approve and Merge**:
   - Review that certificates chain to trusted YubiKey roots
   - Verify key belongs to approved YubiKey serial numbers
   - Merge PR to add key to trusted store

#### Automated Key Validation

Organizations can implement CI/CD checks to automatically validate key submissions:

```yaml
# .github/workflows/validate-key-pr.yml
name: Validate Key Submission
on:
  pull_request:
    paths:
      - 'yubikeys/**'
      - 'keys/**'

jobs:
  validate-key:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Validate attestation certificates
        run: |
          python -m gitverify verify-keys
      - name: Test key verification
        run: |
          # Test verification with submitted key
          python -m gitverify verify --commits HEAD
```

### Benefits of PR-Based Key Management

- **Transparent Process**: All key additions are visible in git history
- **Peer Review**: Maintainers can review cryptographic materials
- **Audit Trail**: Complete history of who added which keys and when
- **Reversible**: Keys can be removed by reverting the PR that added them
- **Familiar Workflow**: Leverages existing code review processes
- **Automated Validation**: CI can prevent invalid keys from being merged

### Incident Response and Legal Protection

gitverify provides critical capabilities for handling security incidents and legal scenarios:

#### Malicious Code Attribution
When pirated code, malware, or incompatible licenses are discovered in commits:

1. **Immediate Identification**: Hardware attestation proves which specific YubiKey (and thus which developer) created the commits
2. **Tamper-Proof Evidence**: Certificate chains cannot be forged or altered after the fact
3. **No Deniability**: Developers cannot claim their credentials were compromised when hardware proves key usage
4. **Chain of Custody**: Complete cryptographic trail from key generation to commit signature

#### License Compliance
For organizations dealing with copyleft licenses or proprietary code:

- **Clear Attribution**: Know exactly who introduced GPL code into MIT-licensed projects
- **Audit Trail**: Historical record of all code contributions with cryptographic proof
- **Legal Evidence**: Court-admissible proof of code authorship and intent

#### Regulatory Compliance
- **SOX Compliance**: Cryptographic audit trails for financial systems
- **GDPR Compliance**: Clear data handling attribution for privacy regulations
- **Industry Standards**: Meets cryptographic requirements for healthcare, finance, and government systems

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-mock

# Run the test suite
pytest tests/

# Run with coverage
pytest --cov=gitverify tests/
```

### Project Structure

```
gitverify/
├── gitverify/          # Main package
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py          # CLI framework
│   ├── common.py       # Configuration and utilities
│   ├── git.py          # Git integration
│   ├── github.py       # GitHub API client
│   ├── gitverify.py    # Main CLI commands
│   ├── gpg.py          # GPG key management
│   ├── utils/          # Utility modules
│   │   ├── https.py    # HTTP client
│   │   └── x509.py     # Certificate utilities
│   └── yk.py           # YubiKey operations
├── tests/              # Test suite
├── yubikeys/           # Sample attestation data
├── attestation.sh      # YubiKey attestation utilities
├── pyproject.toml      # Project configuration
└── requirements.txt    # Python dependencies
```


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related Projects

- [YubiKey OpenPGP](https://developers.yubico.com/PGP/) - YubiKey PGP implementation
- [GPG](https://gnupg.org/) - GNU Privacy Guard
- [Git with GPG](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work) - Git signing documentation
- [Securing Git with SSH and FIDO2](https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html) - Alternative approach using SSH keys instead of GPG
- [yk-init](https://github.com/phiekl/yk-init) - YubiKey initialization and key generation tool
- [yubikey-agent](https://github.com/FiloSottile/yubikey-agent) - YubiKey SSH agent for Go