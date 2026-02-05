import logging
import pytest
from unittest.mock import patch, MagicMock

from satosa.context import Context

from backends.cieoidc.utils.base_logger import BaseLogger

@pytest.fixture
def base_logger():
    return BaseLogger()

@pytest.fixture
def context():
    ctx = Context()
    ctx.state = "test-session"
    return ctx

@patch("backends.cieoidc.utils.base_logger.lu.get_session_id")
@patch("backends.cieoidc.utils.base_logger.logger")
def test_log_with_string_context(mock_logger, mock_get_session_id, base_logger):
    mock_get_session_id.return_value = "session-id"

    base_logger._log("scope", "info", "test-message")

    mock_logger.info.assert_called_once()
    args, _ = mock_logger.info.call_args

    assert "test-message" in args[0]
    assert "session-id" in args[0]

@patch("backends.cieoidc.utils.base_logger.lu.get_session_id")
@patch("backends.cieoidc.utils.base_logger.logger")
def test_log_with_context_object(mock_logger, mock_get_session_id, base_logger, context):
    mock_get_session_id.return_value = "ctx-session-id"

    base_logger._log(context, "debug", "debug-message")

    mock_logger.debug.assert_called_once()
    args, _ = mock_logger.debug.call_args

    assert "debug-message" in args[0]
    assert "ctx-session-id" in args[0]

@pytest.mark.parametrize(
    "method,level",
    [
        ("_log_debug", "debug"),
        ("_log_info", "info"),
        ("_log_warning", "warning"),
        ("_log_error", "error"),
        ("_log_critical", "critical"),
    ],
)
@patch("backends.cieoidc.utils.base_logger.BaseLogger._log")
def test_log_level_helpers(mock_log, base_logger, method, level, context):
    getattr(base_logger, method)(context, "hello")

    mock_log.assert_called_once_with(context, level, "hello")

@patch("backends.cieoidc.utils.base_logger.BaseLogger._log_debug")
def test_log_function_debug_without_args(mock_log_debug, base_logger, context):
    base_logger._log_function_debug("test_fn", context)

    mock_log_debug.assert_called_once()
    args, _ = mock_log_debug.call_args

    assert "test_fn" in args[1]
    assert "INCOMING REQUEST" in args[1]

@patch("backends.cieoidc.utils.base_logger.BaseLogger._log_debug")
def test_log_function_debug_with_args(mock_log_debug, base_logger, context):
    base_logger._log_function_debug(
        fn_name="test_fn",
        context=context,
        args_name="payload",
        args={"a": 1}
    )

    mock_log_debug.assert_called_once()
    args, _ = mock_log_debug.call_args

    assert "request" in args[1]


def test_effective_log_level_returns_logger_level(base_logger):
    level = base_logger.effective_log_level

    assert isinstance(level, int)
    assert level == logging.getLogger(
        "backends.cieoidc.utils.base_logger"
    ).getEffectiveLevel()
