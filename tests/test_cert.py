from pytest_mock import MockerFixture
from unittest.mock import MagicMock, mock_open, ANY

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, UTC

from gitverify.utils.x509 import Certificate


def test_certificate_write_load(mocker: MockerFixture):
    # Mock the x509 certificate
    mock_x509_cert = MagicMock()
    mock_x509_cert.public_bytes.return_value = b"mock_certificate_data"

    # Mock file operations
    mock_file = mock_open()

    mocker.patch("builtins.open", mock_file)
    cert = Certificate(mock_x509_cert)
    cert.write_cert("test_path")

    # Verify write was called
    mock_file.assert_called_with("test_path", "wb")
    mock_x509_cert.public_bytes.assert_called_once()


def test_certificate_load(mocker: MockerFixture):
    # Mock the x509 certificate
    mock_x509_cert = MagicMock()

    # Mock file operations and x509 loading
    mock_file = mock_open(read_data=b"mock_certificate_data")

    mocker.patch("builtins.open", mock_file)
    mocker.patch("cryptography.x509.load_pem_x509_certificate", return_value=mock_x509_cert)

    cert = Certificate.load_cert("test_path")

    # Verify load was called and certificate was created
    assert isinstance(cert, Certificate)
    assert cert.cert == mock_x509_cert
    mock_file.assert_called_with("test_path", "rb")


def test_cert_signature_verification_success(mocker: MockerFixture):
    # Mock the certificates
    mock_parent_cert = MagicMock()
    mock_child_cert = MagicMock()

    # Mock public key verification (success case)
    mock_public_key = MagicMock()
    mock_parent_cert.public_key.return_value = mock_public_key

    parent = Certificate(mock_parent_cert)
    cert = Certificate(mock_child_cert)

    assert cert.verify_cert_signature(parent)

    # Verify the verification was called with correct parameters
    mock_public_key.verify.assert_called_once_with(
        mock_child_cert.signature,
        mock_child_cert.tbs_certificate_bytes,
        ANY,  # padding.PKCS1v15() creates a new instance each time
        mock_child_cert.signature_hash_algorithm,
    )


def test_cert_signature_verification_failure(mocker: MockerFixture):
    # Mock the certificates
    mock_parent_cert = MagicMock()
    mock_child_cert = MagicMock()

    # Mock public key verification (failure case)
    mock_public_key = MagicMock()
    mock_public_key.verify.side_effect = InvalidSignature("Invalid signature")
    mock_parent_cert.public_key.return_value = mock_public_key

    parent = Certificate(mock_parent_cert)
    cert = Certificate(mock_child_cert)

    assert not cert.verify_cert_signature(parent)


def test_cert_validity_current_time(mocker: MockerFixture):
    mock_x509_cert = MagicMock()
    now = datetime.now(UTC)
    past = now.replace(year=now.year - 1)
    future = now.replace(year=now.year + 1)

    mock_x509_cert.not_valid_before_utc = past
    mock_x509_cert.not_valid_after_utc = future

    cert = Certificate(mock_x509_cert)
    assert cert.verify_cert_validity(now)


def test_cert_validity_expired(mocker: MockerFixture):
    mock_x509_cert = MagicMock()
    now = datetime.now(UTC)
    past = now.replace(year=now.year - 2)
    past_recent = now.replace(year=now.year - 1)

    mock_x509_cert.not_valid_before_utc = past
    mock_x509_cert.not_valid_after_utc = past_recent

    cert = Certificate(mock_x509_cert)
    assert not cert.verify_cert_validity(now)


def test_cert_validity_not_yet_valid(mocker: MockerFixture):
    mock_x509_cert = MagicMock()
    now = datetime.now(UTC)
    future = now.replace(year=now.year + 2)
    future_recent = now.replace(year=now.year + 1)

    mock_x509_cert.not_valid_before_utc = future_recent
    mock_x509_cert.not_valid_after_utc = future

    cert = Certificate(mock_x509_cert)
    assert not cert.verify_cert_validity(now)
