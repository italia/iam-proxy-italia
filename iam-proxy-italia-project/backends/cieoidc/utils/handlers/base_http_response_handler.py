from satosa.context import Context


from .response import JsonResponse
from ..base_logger import BaseLogger
from ..exceptions import EmptyHTTPError


class BaseHTTPResponseHandler(BaseLogger):
    def _serialize_error(
        self,
        context: Context,
        error: str,
        description: str,
        err: str,
        err_code: str,
        level: str,
    ) -> JsonResponse:
        """
        Serializes an error.

        :param context: the request context
        :type context: satosa.context.Context
        :param error: the error type
        :type error: str
        :param description: the error description
        :type description: str
        :param err: more info about the error
        :type err: str
        :param err_code: the error code
        :type err_code: str
        :param level: the log level
        :type level: str

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        _error = f"{error}:"
        if err:
            _error += f" {err}."
        self._log(context, level=level, message=f"{_error} {description}")

        return JsonResponse(
            {"error": error, "error_description": description}, status=err_code
        )

    def _handle_500(
            self, 
            context: Context, 
            description: str, 
            exc: Exception
        ) -> JsonResponse:
        """
        Handles a 500 error.

        :param context: the request context
        :type context: satosa.context.Context
        :param description: the error description
        :type description: str
        :param exc: the exception raised
        :type exc: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        return self._serialize_error(
            context,
            "server_error",
            f"{description}",
            f"{description}. {exc.__class__.__name__}: {exc}",
            "500",
            "error",
        )

    def _handle_40X(
        self,
        code_number: str,
        error: str,
        context: Context,
        description: str,
        exc: Exception,
    ) -> JsonResponse:
        """
        Handles a 40X error.

        :param code_number: the code number
        :type code_number: str
        :param error: the error type
        :type error: str
        :param context: the request context
        :type context: satosa.context.Context
        :param description: the error description
        :type description: str
        :param exc: the exception raised
        :type exc: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        return self._serialize_error(
            context,
            error,
            description,
            f"{exc.__class__.__name__}: {exc}",
            f"40{code_number}",
            "error",
        )

    def _handle_400(
        self, 
        context: Context, 
        description: str, 
        exc: Exception = EmptyHTTPError("")
    ) -> JsonResponse:
        """
        Handles a 400 error.

        :param context: the request context
        :type context: satosa.context.Context
        :param description: the error description
        :type description: str
        :param exc: the exception raised
        :type exc: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """
        return self._handle_40X("0", "invalid_request", context, description, exc)

    def _handle_401(
        self, context, description: str, exc: Exception = EmptyHTTPError("")
    ):
        """
        Handles a 401 error.

        :param context: the request context
        :type context: satosa.context.Context
        :param description: the error description
        :type description: str
        :param exc: the exception raised
        :type exc: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        return self._handle_40X("1", "invalid_client", context, description, exc)

    def _handle_403(
        self, 
        context, 
        description: str, 
        exc: Exception = EmptyHTTPError("")
    ):
        """
        Handles a 403 error.

        :param context: the request context
        :type context: satosa.context.Context
        :param description: the error description
        :type description: str
        :param exc: the exception raised
        :type exc: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        return self._handle_40X("3", "expired", context, description, exc)

    @staticmethod
    def _handle_204():
        return JsonResponse(status=204)

