from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape


class Jinja2TemplateHandler:
    """
    Jinja2 template handler
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Create an istance of Jinja2TemplateHandler

        :param config: a dictionary that contains the configuration for initalize the template handler.
        :type config: Dict[str, Any]
        """

        # error pages handler
        self.loader = Environment(
            loader=FileSystemLoader(searchpath=config["template_folder"]),
            autoescape=select_autoescape(["html"]),
        )
        _static_url = (
            config["static_storage_url"]
            if config["static_storage_url"][-1] == "/"
            else config["static_storage_url"] + "/"
        )
        self.loader.globals.update(
            {
                "static": _static_url,
            }
        )
        self.qrcode_page = self.loader.get_template(config["html_template"])
        self.authorization_error_response_page = self.loader.get_template(config["html_error_template"])
