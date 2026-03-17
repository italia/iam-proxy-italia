import json

from satosa.response import Response


class JsonResponse(Response):
    """
    A JSON response istance class.
    """

    _content_type = "application/json"

    def __init__(self, *args, **kwargs):
        """
        Creates an instance of JsonResponse.

        :param args: a list of arguments
        :type args: Any
        :param kwargs: a dictionary of arguments
        :type kwargs: Any
        """

        kwargs.get("headers", {}).update({"Content-Type": self._content_type})

        super().__init__(*args, **kwargs)

        if isinstance(self.message, list):
            self.message = self.message[0]

        if type(self.message) in (list, dict):
            self.message = json.dumps(self.message)
