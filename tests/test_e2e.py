from pytest_mock import MockerFixture
from unittest.mock import MagicMock, patch, mock_open
import tempfile
import os

from gitverify.gitverify import Cli
from gitverify.common import VerificationError


def test_gitverify_attest(mocker: MockerFixture):
    """Test the attestation flow: attest Yubikey and associate with GitHub user."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.user = "testuser"
    mock_args.path = "/tmp/test_attest"

    # Mock YubikeyGpg.attest
    mock_attest = mocker.patch("gitverify.yk.YubikeyGpg.attest", return_value=True)

    cli = Cli()
    cli.args = mock_args

    result = cli.attest()

    # Verify attestation was called with correct parameters
    mock_attest.assert_called_once_with(path="/tmp/test_attest", user="testuser")
    assert result == 0  # Should return success


def test_gitverify_download(mocker: MockerFixture):
    """Test downloading public key from GitHub."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.user = "testuser"

    # Mock GithubPublicKey
    mock_github_key = MagicMock()
    mock_github_key.download.return_value = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest key\n-----END PGP PUBLIC KEY BLOCK-----"

    mock_github_class = mocker.patch("gitverify.gitverify.GithubPublicKey", return_value=mock_github_key)

    # Mock stdout
    mock_print = mocker.patch("builtins.print")

    cli = Cli()
    cli.args = mock_args

    result = cli.download()

    # Verify GithubPublicKey was created and download called
    mock_github_class.assert_called_once_with(user="testuser")
    mock_github_key.download.assert_called_once()
    mock_print.assert_called_once_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest key\n-----END PGP PUBLIC KEY BLOCK-----")
    assert result == 0


def test_gitverify_download_failure(mocker: MockerFixture):
    """Test downloading public key from GitHub when it fails."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.user = "invaliduser"

    # Mock GithubPublicKey with failed download
    mock_github_key = MagicMock()
    mock_github_key.download.return_value = None

    mock_github_class = mocker.patch("gitverify.gitverify.GithubPublicKey", return_value=mock_github_key)

    cli = Cli()
    cli.args = mock_args

    result = cli.download()

    # Verify GithubPublicKey was created and download called
    mock_github_class.assert_called_once_with(user="invaliduser")
    mock_github_key.download.assert_called_once()
    assert result == 1  # Should return error


def test_gitverify_generate(mocker: MockerFixture):
    """Test generating a new OpenGPG key on Yubikey."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.gnupghome = "/tmp/test_gnupg"

    # Mock YubikeyGpg.generate
    mock_generate = mocker.patch("gitverify.yk.YubikeyGpg.generate", return_value=True)

    cli = Cli()
    cli.args = mock_args

    result = cli.generate()

    # Verify generate was called
    mock_generate.assert_called_once()
    assert result == 0


def test_gitverify_export(mocker: MockerFixture):
    """Test exporting a public key from GnuPG key store."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.keyid = "ABC123"
    mock_args.gnupghome = "/tmp/test_gnupg"

    # Mock PublicKeyStore.export
    mock_export = mocker.patch("gitverify.gpg.PublicKeyStore.export", return_value=True)

    cli = Cli()
    cli.args = mock_args

    result = cli.export()

    # Verify export was called with correct parameters
    mock_export.assert_called_once_with(keyid="ABC123", path="/tmp/test_gnupg")
    assert result == 0


def test_gitverify_export_missing_keyid(mocker: MockerFixture):
    """Test exporting without keyid should fail."""
    # Mock CLI arguments with missing keyid
    mock_args = MagicMock()
    mock_args.keyid = None
    mock_args.gnupghome = "/tmp/test"

    cli = Cli()
    cli.args = mock_args

    result = cli.export()

    # Should return failure exit code
    assert result == 1  # ExitCode.FAILURE


def test_gitverify_verify_success(mocker: MockerFixture):
    """Test verifying commits with successful verification."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.key_ref = "sig"
    mock_args.ca = "/tmp/ca.pem"
    mock_args.path = "/tmp/keys"
    mock_args.commits = "HEAD~5..HEAD"

    # Mock the entire verification process
    mock_keys_context = MagicMock()
    mock_keys_context.__enter__ = MagicMock(return_value=MagicMock())
    mock_keys_context.__exit__ = MagicMock(return_value=None)

    mock_keys_load = mocker.patch("gitverify.gpg.PublicKeyStore.load", return_value=mock_keys_context)

    # Mock CommitsVerifier.verify to return True
    mock_verify = mocker.patch("gitverify.git.CommitsVerifier.verify", return_value=True)

    cli = Cli()
    cli.args = mock_args

    result = cli.verify()

    # Verify PublicKeyStore.load was called
    mock_keys_load.assert_called_once_with(ca="/tmp/ca.pem", path="/tmp/keys")

    # Verify verify was called
    mock_verify.assert_called_once()

    assert result == 0


def test_gitverify_verify_failure(mocker: MockerFixture):
    """Test verifying commits with failed verification."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.key_ref = "sig"
    mock_args.ca = "/tmp/ca.pem"
    mock_args.path = "/tmp/keys"
    mock_args.commits = "HEAD~5..HEAD"

    # Mock the entire verification process
    mock_keys_context = MagicMock()
    mock_keys_context.__enter__ = MagicMock(return_value=MagicMock())
    mock_keys_context.__exit__ = MagicMock(return_value=None)

    mock_keys_load = mocker.patch("gitverify.gpg.PublicKeyStore.load", return_value=mock_keys_context)

    # Mock CommitsVerifier.verify to return False
    mock_verify = mocker.patch("gitverify.git.CommitsVerifier.verify", return_value=False)

    cli = Cli()
    cli.args = mock_args

    result = cli.verify()

    assert result == 1  # Should return error


def test_gitverify_verify_keys_success(mocker: MockerFixture):
    """Test verifying keys with successful verification."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.ca = "/tmp/ca.pem"
    mock_args.path = "/tmp/keys"

    # Mock PublicKeyStore.load to return an object that can be used with closing()
    mock_keys = MagicMock()
    mock_keys.verify.return_value = True
    mock_keys.close = MagicMock()

    mock_keys_load = mocker.patch("gitverify.gpg.PublicKeyStore.load", return_value=mock_keys)

    cli = Cli()
    cli.args = mock_args

    result = cli.verify_keys()

    # Verify PublicKeyStore.load was called
    mock_keys_load.assert_called_once_with(ca="/tmp/ca.pem", path="/tmp/keys")

    assert result == 0


def test_gitverify_verify_keys_failure(mocker: MockerFixture):
    """Test verifying keys with failed verification."""
    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.ca = "/tmp/ca.pem"
    mock_args.path = "/tmp/keys"

    # Mock PublicKeyStore.load to return an object that can be used with closing()
    mock_keys = MagicMock()
    mock_keys.verify.return_value = False
    mock_keys.close = MagicMock()

    mock_keys_load = mocker.patch("gitverify.gpg.PublicKeyStore.load", return_value=mock_keys)

    cli = Cli()
    cli.args = mock_args

    result = cli.verify_keys()

    # The method should return 1 when verification fails
    assert result == 1  # Should return error


def test_gitverify_verify_attestation_success(mocker: MockerFixture):
    """Test verifying attestation certificates successfully."""
    from yubikit.openpgp import KEY_REF

    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.user = "testuser"
    mock_args.path = "/tmp/test_attest"
    mock_args.type = "SIG"
    mock_args.ca = "/tmp/ca.pem"

    # Mock YubikeyGpg.verify_attestation
    mock_verify_result = {"serial": "12345678", "fingerprint": "ABC123", "version": "5.7"}
    mock_verify = mocker.patch("gitverify.yk.YubikeyGpg.verify_attestation", return_value=mock_verify_result)

    cli = Cli()
    cli.args = mock_args

    # Mock the logger
    mock_log = mocker.patch.object(cli, 'log')

    result = cli.verify_attestation()

    # Verify verify_attestation was called with correct parameters
    mock_verify.assert_called_once_with(attestation_path="/tmp/test_attest/testuser-attestation", key_ref=KEY_REF.SIG, ca_cert_path="/tmp/ca.pem")

    # Verify logging was called
    mock_log.info.assert_any_call("✓ %s verification successful for %s", "SIG", "/tmp/test_attest/testuser-attestation")
    mock_log.info.assert_any_call("  Serial: %s", "12345678")
    mock_log.info.assert_any_call("  Fingerprint: %s", "ABC123")
    assert result == 0


def test_gitverify_verify_attestation_failure(mocker: MockerFixture):
    """Test verifying attestation certificates with failure."""
    from yubikit.openpgp import KEY_REF

    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.user = "testuser"
    mock_args.path = "/tmp/test_attest"
    mock_args.type = "SIG"
    mock_args.ca = "/tmp/ca.pem"

    # Mock YubikeyGpg.verify_attestation to raise exception
    mock_verify = mocker.patch("gitverify.yk.YubikeyGpg.verify_attestation", side_effect=RuntimeError("Verification failed"))

    cli = Cli()
    cli.args = mock_args

    # Mock the logger
    mock_log = mocker.patch.object(cli, 'log')

    result = cli.verify_attestation()

    # Verify verify_attestation was called
    mock_verify.assert_called_once_with(attestation_path="/tmp/test_attest/testuser-attestation", key_ref=KEY_REF.SIG, ca_cert_path="/tmp/ca.pem")

    # Verify the method returns failure exit code when attestation fails
    assert result == 1


def test_gitverify_verify_all_attestations(mocker: MockerFixture):
    """Test verifying all attestation certificates in a directory."""
    from yubikit.openpgp import KEY_REF

    # Mock CLI arguments
    mock_args = MagicMock()
    mock_args.attestations_path = "/tmp/test_attest"
    mock_args.ca = "/tmp/ca.pem"

    # Mock os.path.exists to return True
    mock_exists = mocker.patch("os.path.exists", return_value=True)

    # Mock glob.glob to return attestation directories
    mock_glob = mocker.patch("glob.glob", return_value=["/tmp/test_attest/user1-attestation"])

    # Mock YubikeyGpg.verify_attestation
    mock_verify_result = {"serial": "12345678", "fingerprint": "ABC123", "version": "5.7"}
    mock_verify = mocker.patch("gitverify.yk.YubikeyGpg.verify_attestation", return_value=mock_verify_result)

    cli = Cli()
    cli.args = mock_args

    result = cli.verify_all_attestations()

    # Should return 0 for successful verification
    assert result == 0

    # Verify os.path.exists was called
    mock_exists.assert_called_with("/tmp/test_attest")

    # Verify glob.glob was called
    mock_glob.assert_called_with("/tmp/test_attest/*-attestation")

    # Verify verify_attestation was called
    mock_verify.assert_called_with(attestation_path="/tmp/test_attest/user1-attestation", key_ref=KEY_REF.SIG, ca_cert_path="/tmp/ca.pem")


def test_gitverify_roundtrip_flow(mocker: MockerFixture):
    """Test complete roundtrip: generate -> export -> attest -> verify."""
    # This test simulates the full workflow

    # Mock all the components
    mock_generate = mocker.patch("gitverify.yk.YubikeyGpg.generate", return_value=True)
    mock_export = mocker.patch("gitverify.gpg.PublicKeyStore.export", return_value=True)
    mock_attest = mocker.patch("gitverify.yk.YubikeyGpg.attest", return_value=True)

    # Mock verification components
    mock_keys_context = MagicMock()
    mock_keys = MagicMock()
    mock_keys.verify.return_value = True
    mock_keys_context.__enter__ = MagicMock(return_value=mock_keys)
    mock_keys_context.__exit__ = MagicMock(return_value=None)

    mock_keys_load = mocker.patch("gitverify.gpg.PublicKeyStore.load", return_value=mock_keys_context)
    mock_verify_commits = mocker.patch("gitverify.git.CommitsVerifier.verify", return_value=True)

    cli = Cli()

    # Step 1: Generate key
    mock_args_gen = MagicMock()
    mock_args_gen.gnupghome = "/tmp/test_gnupg"
    cli.args = mock_args_gen
    result_gen = cli.generate()
    assert result_gen == 0

    # Step 2: Export key
    mock_args_exp = MagicMock()
    mock_args_exp.keyid = "ABC123"
    mock_args_exp.gnupghome = "/tmp/test_gnupg"
    cli.args = mock_args_exp
    result_exp = cli.export()
    assert result_exp == 0

    # Step 3: Attest
    mock_args_att = MagicMock()
    mock_args_att.user = "testuser"
    mock_args_att.path = "/tmp/test_attest"
    cli.args = mock_args_att
    result_att = cli.attest()
    assert result_att == 0

    # Step 4: Verify
    mock_args_ver = MagicMock()
    mock_args_ver.key_ref = "sig"
    mock_args_ver.ca = "/tmp/ca.pem"
    mock_args_ver.path = "/tmp/keys"
    mock_args_ver.commits = "HEAD"
    cli.args = mock_args_ver
    result_ver = cli.verify()
    assert result_ver == 0

    # Verify all steps were called
    mock_generate.assert_called_once()
    mock_export.assert_called_once_with(keyid="ABC123", path="/tmp/test_gnupg")
    mock_attest.assert_called_once_with(path="/tmp/test_attest", user="testuser")
    mock_keys_load.assert_called_with(ca="/tmp/ca.pem", path="/tmp/keys")
    mock_verify_commits.assert_called_once()


def test_gitverify_attest_invalid_username(mocker: MockerFixture):
    """Test attestation with invalid GitHub username."""
    mock_args = MagicMock()
    mock_args.user = "invalid-username!"
    mock_args.path = "/tmp/test"

    cli = Cli()
    cli.args = mock_args

    result = cli.attest()

    # Should fail due to invalid username
    assert result == 1  # ExitCode.FAILURE


def test_gitverify_download_network_error(mocker: MockerFixture):
    """Test download with network connectivity issues."""
    mock_args = MagicMock()
    mock_args.user = "testuser"

    # Mock GithubPublicKey to raise connection error
    mock_github_key = MagicMock()
    mock_github_key.download.side_effect = Exception("Network connection failed")

    mock_github_class = mocker.patch("gitverify.gitverify.GithubPublicKey", return_value=mock_github_key)

    cli = Cli()
    cli.args = mock_args

    result = cli.download()

    # Should fail due to network error
    assert result == 1  # ExitCode.FAILURE


def test_gitverify_generate_not_supported(mocker: MockerFixture):
    """Test generate command (currently not supported)."""
    mock_args = MagicMock()
    mock_args.gnupghome = "/tmp/test"

    cli = Cli()
    cli.args = mock_args

    result = cli.generate()

    # Should fail - YubiKey generation is not supported
    assert result == 1  # ExitCode.FAILURE


def test_gitverify_export_empty_keyring(mocker: MockerFixture):
    """Test export with empty GPG keyring."""
    mock_args = MagicMock()
    mock_args.keyid = "NONEXISTENT"
    mock_args.gnupghome = "/tmp/test_gpg"

    # Mock empty keyring
    mock_exists = mocker.patch("os.path.exists", return_value=True)
    mock_gpg = MagicMock()
    mock_gpg.list_keys.return_value = []
    mocker.patch("gnupg.GPG", return_value=mock_gpg)

    cli = Cli()
    cli.args = mock_args

    result = cli.export()

    # Should fail - no keys to export
    assert result == 1  # ExitCode.FAILURE


def test_gitverify_verify_invalid_key_type(mocker: MockerFixture):
    """Test attestation verification with invalid key type."""
    mock_args = MagicMock()
    mock_args.user = "testuser"
    mock_args.path = "/tmp/test"
    mock_args.type = "INVALID"
    mock_args.ca = "/tmp/ca.pem"

    cli = Cli()
    cli.args = mock_args

    result = cli.verify_attestation()

    # Should fail due to invalid key type
    assert result == 1  # ExitCode.FAILURE


def test_gitverify_complex_workflow_with_errors(mocker: MockerFixture):
    """Test complex workflow with various error conditions."""
    cli = Cli()

    # Test 1: Attest with invalid user
    mock_args_attest = MagicMock()
    mock_args_attest.user = "invalid-user!"
    mock_args_attest.path = "/tmp/test"
    cli.args = mock_args_attest
    result = cli.attest()
    assert result == 1  # Should fail

    # Test 2: Download with network error
    mock_args_download = MagicMock()
    mock_args_download.user = "testuser"
    cli.args = mock_args_download

    mock_github_key = MagicMock()
    mock_github_key.download.side_effect = Exception("Network connection failed")
    mocker.patch("gitverify.gitverify.GithubPublicKey", return_value=mock_github_key)

    result = cli.download()
    assert result == 1  # Should fail

    # Test 3: Generate (not supported)
    mock_args_generate = MagicMock()
    mock_args_generate.gnupghome = "/tmp/test"
    cli.args = mock_args_generate
    result = cli.generate()
    assert result == 1  # Should fail - not supported


def test_gitverify_verify_all_attestations_mixed_results(mocker: MockerFixture):
    """Test verify all attestations with some passing and some failing."""
    mock_args = MagicMock()
    mock_args.attestations_path = "/tmp/attestations"
    mock_args.ca = "/tmp/ca.pem"

    mock_exists = mocker.patch("os.path.exists", return_value=True)
    mock_glob = mocker.patch("glob.glob", return_value=["/tmp/attestations/user-attestation"])

    # Mock verification: SIG succeeds (first one tried)
    mock_verify = mocker.patch("gitverify.yk.YubikeyGpg.verify_attestation", return_value={"serial": "123", "fingerprint": "ABC", "version": "5.7"})

    cli = Cli()
    cli.args = mock_args

    result = cli.verify_all_attestations()

    # Should succeed - SIG verification succeeded
    assert result == 0  # ExitCode.SUCCESS
    # Only SIG should be called since it succeeds and we break
    mock_verify.assert_called_once()
