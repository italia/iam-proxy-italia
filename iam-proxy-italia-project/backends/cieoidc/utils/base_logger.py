import logging

import satosa.logging_util as lu
from satosa.context import Context

logger = logging.getLogger(__name__)


class BaseLogger:
    def _log(self, context: str | Context, level: str, message: str) -> None:
        """
        Log a message with the given level.

        :param context: the request context or the scope of the class
        :type context: satosa.context.Context | str
        :param level: the log level
        :type level: str
        :param message: the message to log
        :type message: str
        """

        context = context if isinstance(context, str) else context.state

        log_level = getattr(logger, level)
        log_level(lu.LOG_FMT.format(id=lu.get_session_id(context), message=message))

    def _log_debug(self, context: str | Context, message: str) -> None:
        """
        Log a message with the DEBUG level.

        :param context: the request context or the scope of the class
        :type context: satosa.context.Context | str
        :param message: the message to log
        :type message: str
        """

        self._log(context, "debug", message)

    def _log_function_debug(
        self, fn_name: str, context: Context, args_name: str | None = None, args=None
    ) -> None:
        """
        Logs a message at the start of a backend function.

        :param fn_name: the name of the function
        :type fn_name: str
        :param context: the request context
        :param args_name: the name of the arguments field
        :type args_name: str | None
        :param args: the arguments provided to the function
        :type args: Any
        """

        args_str = f" and {args_name}: {args}" if not args_name else ""

        debug_message = (
            f"[INCOMING REQUEST] {fn_name} with Context: "
            f"{context.__dict__}{args_str}"
        )
        self._log_debug(context, debug_message)

    def _log_error(self, context: str | Context, message: str) -> None:
        """
        Log a message with the ERROR level.

        :param context: the request context or the scope of the class
        :type context: satosa.context.Context | str
        :param message: the message to log
        :type message: str
        """

        self._log(context, "error", message)

    def _log_warning(self, context: str | Context, message: str) -> None:
        """
        Log a message with the WARNING level.

        :param context: the request context or the scope of the class
        :type context: satosa.context.Context | str
        :param message: the message to log
        :type message: str
        """

        self._log(context, "warning", message)

    def _log_info(self, context: str | Context, message: str) -> None:
        """
        Log a message with the INFO level.

        :param context: the request context or the scope of the class
        :type context: satosa.context.Context | str
        :param message: the message to log
        :type message: str
        """

        self._log(context, "info", message)

    def _log_critical(self, context: str | Context, message: str) -> None:
        """
        Log a message with the CRITICAL level.

        :param context: the request context or the scope of the class
        :type context: satosa.context.Context | str
        :param message: the message to log
        :type message: str
        """

        self._log(context, "critical", message)

    @property
    def effective_log_level(self) -> int:
        """
        Returns the effective log level.

        :return: the effective log level
        :rtype: int
        """

        return logger.getEffectiveLevel()
