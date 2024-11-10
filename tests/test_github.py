from pytest_mock import MockerFixture
import pytest
from requests.exceptions import HTTPError, Timeout, ConnectionError

import gitverify.github as github


def test_github_username():
    for username in [
        "test",
        "test123",
        "test-123",
    ]:
        assert github.is_valid_username(username)
    for username in [
        "test@123",
        "test#123",
        "test$123",
        "test%123",
        "test^123",
        "test_123",
        "test.123",
        "-test123",
    ]:
        assert not github.is_valid_username(username)


def test_download(mocker: MockerFixture):
    test_user = "test123"

    mock_session_get = mocker.patch("gitverify.utils.https.HttpsClient.get")
    github.GithubPublicKey(user=test_user).download()
    mock_session_get.assert_called_once_with(f"{test_user}.gpg")


def test_download_invalid_username():
    """Test that invalid usernames raise ValueError."""
    with pytest.raises(ValueError, match="Invalid Github username"):
        github.GithubPublicKey(user="invalid@user")


def test_download_http_404_error(mocker: MockerFixture):
    """Test download with HTTP 404 error."""
    test_user = "nonexistentuser"

    # Mock HttpsClient.get to raise HTTPError for 404
    mock_response = mocker.MagicMock()
    mock_response.raise_for_status.side_effect = HTTPError("404 Client Error: Not Found")
    mock_session = mocker.MagicMock()
    mock_session.get.return_value = mock_response

    mocker.patch("gitverify.utils.https.HttpsClient", return_value=mocker.MagicMock(session=mock_session))
    gpk = github.GithubPublicKey(user=test_user)
    with pytest.raises(HTTPError):
        gpk.download()


def test_download_http_500_error(mocker: MockerFixture):
    """Test download with HTTP 500 error."""
    test_user = "testuser"

    # Mock HttpsClient.get to raise HTTPError for 500
    mock_response = mocker.MagicMock()
    mock_response.raise_for_status.side_effect = HTTPError("500 Server Error: Internal Server Error")
    mock_session = mocker.MagicMock()
    mock_session.get.return_value = mock_response

    mocker.patch("gitverify.utils.https.HttpsClient", return_value=mocker.MagicMock(session=mock_session))
    gpk = github.GithubPublicKey(user=test_user)
    with pytest.raises(HTTPError):
        gpk.download()


def test_download_timeout_error(mocker: MockerFixture):
    """Test download with timeout error."""
    test_user = "testuser"

    # Mock the entire HttpsClient.get to raise Timeout
    mocker.patch("gitverify.utils.https.HttpsClient.get", side_effect=Timeout("Request timed out"))
    gpk = github.GithubPublicKey(user=test_user)
    with pytest.raises(Timeout):
        gpk.download()


def test_download_connection_error(mocker: MockerFixture):
    """Test download with connection error."""
    test_user = "testuser"

    # Mock the entire HttpsClient.get to raise ConnectionError
    mocker.patch("gitverify.utils.https.HttpsClient.get", side_effect=ConnectionError("Connection failed"))
    gpk = github.GithubPublicKey(user=test_user)
    with pytest.raises(ConnectionError):
        gpk.download()


def test_https_client_invalid_base_url():
    """Test HttpsClient validation of base URL."""
    from gitverify.utils.https import HttpsClient

    # Test that HttpsClient validates HTTPS URLs
    with pytest.raises(ValueError, match="Only HTTPS is supported"):
        HttpsClient(base_url="http://github.com/")
