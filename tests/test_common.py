from pytest_mock import MockerFixture
import os

import gitverify.common as common


def test_base_result(mocker: MockerFixture):
    base0 = common.BaseResult()
    assert base0.result
    error = mocker.patch("logging.Logger.error")
    info = mocker.patch("logging.Logger.info")
    warning = mocker.patch("logging.Logger.warning")
    base0.fail("test")
    error.assert_called()
    info.assert_not_called()
    warning.assert_not_called()
    error.reset_mock()
    assert not base0.result

    base = common.BaseResult()
    base.check("NO_TOUCH", "warning")
    error.assert_not_called()
    info.assert_not_called()
    warning.assert_called()
    assert base.result
    warning.reset_mock()
    base.check("IMPORTED", "error")
    error.assert_called()
    info.assert_not_called()
    warning.assert_not_called()
    assert not base.result


def test_load_config_defaults():
    """Test loading default configuration."""
    config = common.load_config()

    assert isinstance(config, dict)
    assert config["IMPORTED"] == common.Severity.ERROR
    assert config["VULNERABLE"] == common.Severity.WARN
    assert config["ALLOWED_SERIALS"] == [11545724]
    assert config["ALLOWED_EMAIL_DOMAINS"] == ["autolinkki.fi"]
    assert config["ANONYMOUS_EMAIL"] == common.Severity.WARN


def test_load_config_from_yaml():
    """Test loading configuration from YAML file."""
    import tempfile
    import yaml

    # Create a temporary YAML config file
    config_data = {
        "IMPORTED": "WARN",
        "VULNERABLE": "ERROR",
        "ALLOWED_SERIALS": [12345678, 87654321],
        "ALLOWED_EMAIL_DOMAINS": ["test.com", "example.org"],
        "ANONYMOUS_EMAIL": "ERROR"
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.safe_dump(config_data, f)
        config_file = f.name

    try:
        config = common.load_config(config_file)

        assert config["IMPORTED"] == common.Severity.WARN
        assert config["VULNERABLE"] == common.Severity.ERROR
        assert config["ALLOWED_SERIALS"] == [12345678, 87654321]
        assert config["ALLOWED_EMAIL_DOMAINS"] == ["test.com", "example.org"]
        assert config["ANONYMOUS_EMAIL"] == common.Severity.ERROR
        # Check that defaults are preserved for unspecified values
        assert config["COMMITTER_EMAIL"] == common.Severity.ERROR
    finally:
        os.unlink(config_file)


def test_load_config_invalid_file():
    """Test loading configuration from invalid file."""
    config = common.load_config("/nonexistent/file.yaml")

    # Should return defaults when file doesn't exist
    assert isinstance(config, dict)
    assert config["IMPORTED"] == common.Severity.ERROR


def test_reload_config():
    """Test reloading configuration."""
    # First load defaults
    config1 = common.CONFIG.copy()

    # Reload with test config
    common.reload_config("test_config.yaml")
    config2 = common.CONFIG

    # Check that config changed
    assert config1["IMPORTED"] == common.Severity.ERROR  # default
    assert config2["IMPORTED"] == common.Severity.WARN   # from test config
