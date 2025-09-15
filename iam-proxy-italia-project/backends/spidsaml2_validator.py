import datetime
import inspect
import logging

import pytz
from saml2 import samlp

# to load state from a cookie
# from satosa.base import SATOSABase
# from satosa.wsgi import satosa_config
# sb = SATOSABase(satosa_config)
# sb._load_state(context)

logger = logging.getLogger(__name__)
_ERROR_TROUBLESHOOT = " Contattare il supporto tecnico per eventuali chiarimenti"


class SPIDValidatorException(Exception):
    def __init__(self, message, errors=""):
        super().__init__(message)
        logger.error(message)
        self.errors = errors


class Saml2ResponseValidator(object):
    def __init__(
        self,
        authn_response="",
        issuer="",
        nameid_formats=["urn:oasis:names:tc:SAML:2.0:nameid-format:transient"],
        recipient="spidSaml2/acs/post",
        accepted_time_diff=1,
        in_response_to="",
        authn_context_class_ref="https://www.spid.gov.it/SpidL2",
        return_addrs=[],
        allowed_acrs=[],
        cie_mode=False
    ):

        self.response = samlp.response_from_string(authn_response)
        self.nameid_formats = nameid_formats
        self.recipient = recipient
        self.accepted_time_diff = accepted_time_diff
        self.authn_context_class_ref = authn_context_class_ref
        self.in_response_to = in_response_to
        self.return_addrs = return_addrs
        self.issuer = issuer
        self.allowed_acrs = allowed_acrs
        self.cie_mode = cie_mode

    # handled adding authn req arguments in the session state (cookie)
    def validate_in_response_to(self):
        """spid test 18"""
        if self.in_response_to != self.response.in_response_to:
            raise SPIDValidatorException(
                "In response To not valid: "
                f"{self.in_response_to} != {self.response.in_response_to}."
                f"{_ERROR_TROUBLESHOOT}"
            )

    def validate_destination(self):
        """spid test 19 e 20
        inutile se disabiliti gli unsolicited
        """
        if (
            not self.response.destination
            or self.response.destination not in self.return_addrs
        ):
            _msg = (
                f'Destination is not valid: {
                    self.response.destination or ""} not in {self.return_addrs}.'
                f"{_ERROR_TROUBLESHOOT}"
            )
            raise SPIDValidatorException(_msg)

    def validate_issuer(self):
        """spid saml check 30, 70, 71, 72
        <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://localhost:8443</saml:Issuer>
        """

        # 30
        # check that this issuer is in the metadata...
        # L'attributo Format di Issuer della Response deve essere omesso o assumere valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity. In questo test il valore è diverso. Risultato atteso: KO
        if hasattr(self.response.issuer, "format") and self.response.issuer.format:
            if (
                self.response.issuer.format
                != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
            ):
                raise SPIDValidatorException(
                    f"Issuer NameFormat is invalid: {
                        self.response.issuer.format} "
                    '!= "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"'
                )

        if not self.cie_mode:
            msg = "Issuer format is not valid: {}. {}"
            # 70, 71
            assiss = self.response.assertion[0].issuer
            if not hasattr(assiss, "format") or not getattr(assiss, "format", None):
                raise SPIDValidatorException(
                    msg.format(self.response.issuer.format,
                               _ERROR_TROUBLESHOOT)
                )

            # 72
            for i in self.response.assertion:
                if i.issuer.format != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity":
                    raise SPIDValidatorException(
                        msg.format(self.response.issuer.format,
                                   _ERROR_TROUBLESHOOT)
                    )

    def validate_assertion_version(self):
        """spid saml check 35"""
        for i in self.response.assertion:
            if i.version != "2.0":
                msg = (
                    f'validate_assertion_version failed on: "{i.version}".'
                    f"{_ERROR_TROUBLESHOOT}"
                )
                raise SPIDValidatorException(msg)

    def validate_issueinstant(self):
        """spid saml check 39, 40"""
        # Spid dt standard format
        for i in self.response.assertion:
            try:
                issueinstant_naive = datetime.datetime.strptime(
                    i.issue_instant, "%Y-%m-%dT%H:%M:%SZ"
                )
            except Exception:
                issueinstant_naive = datetime.datetime.strptime(
                    i.issue_instant, "%Y-%m-%dT%H:%M:%S.%fZ"
                )

            issuerinstant_aware = pytz.utc.localize(issueinstant_naive)
            now = pytz.utc.localize(datetime.datetime.utcnow())

            if now < issuerinstant_aware:
                seconds = (issuerinstant_aware - now).seconds
            else:
                seconds = (now - issuerinstant_aware).seconds

            if seconds > self.accepted_time_diff:
                msg = (
                    f"Not a valid issue_instant: {issueinstant_naive}"
                    f"{_ERROR_TROUBLESHOOT}"
                )
                raise SPIDValidatorException(msg)

    def validate_name_qualifier(self):
        """spid saml check 43, 45, 46, 47, 48, 49"""
        for i in self.response.assertion:
            if (
                not hasattr(i.subject.name_id, "name_qualifier")
                or not i.subject.name_id.name_qualifier
            ):
                raise SPIDValidatorException(
                    "Not a valid subject.name_id.name_qualifier"
                    f"{_ERROR_TROUBLESHOOT}"
                )
            if not i.subject.name_id.format:
                raise SPIDValidatorException(
                    "Not a valid subject.name_id.format" f"{
                        _ERROR_TROUBLESHOOT}"
                )
            if i.subject.name_id.format not in self.nameid_formats:
                msg = (
                    f"Not a valid subject.name_id.format: {
                        i.subject.name_id.format}"
                    f"{_ERROR_TROUBLESHOOT}"
                )
                raise SPIDValidatorException(msg)

    def validate_subject_confirmation_data(self):
        """spid saml check 59, 61, 62, 63, 64

        saml_response.assertion[0].subject.subject_confirmation[0].subject_confirmation_data.__dict__
        """
        for i in self.response.assertion:
            for subject_confirmation in i.subject.subject_confirmation:
                # 61
                if not hasattr(
                    subject_confirmation, "subject_confirmation_data"
                ) or not getattr(
                    subject_confirmation, "subject_confirmation_data", None
                ):
                    msg = "subject_confirmation_data not present"
                    raise SPIDValidatorException(
                        f"{msg}. {_ERROR_TROUBLESHOOT}")

                # 60
                if not subject_confirmation.subject_confirmation_data.in_response_to:
                    raise SPIDValidatorException(
                        "subject.subject_confirmation_data in response -> null data."
                        f"{_ERROR_TROUBLESHOOT}"
                    )

                # 62 avoided with allow_unsolicited set to false
                # (XML parse error: Unsolicited response: id-OsoMQGYzX4HGLsfL7)
                if self.in_response_to:
                    if (
                        subject_confirmation.subject_confirmation_data.in_response_to
                        != self.in_response_to
                    ):
                        raise Exception(
                            "subject.subject_confirmation_data in response to not valid"
                        )

                # 50
                if (
                    self.recipient
                    != subject_confirmation.subject_confirmation_data.recipient
                ):
                    msg = (
                        "subject_confirmation.subject_confirmation_data.recipient not valid:"
                        f" {subject_confirmation.subject_confirmation_data.recipient}."
                    )
                    raise SPIDValidatorException(f"{msg}{_ERROR_TROUBLESHOOT}")

                # 63 ,64
                if not hasattr(
                    subject_confirmation.subject_confirmation_data, "not_on_or_after"
                ) or not getattr(
                    subject_confirmation.subject_confirmation_data,
                    "not_on_or_after",
                    None,
                ):
                    raise SPIDValidatorException(
                        "subject.subject_confirmation_data not_on_or_after not valid. "
                        f"{_ERROR_TROUBLESHOOT}"
                    )

                if not hasattr(
                    subject_confirmation.subject_confirmation_data, "in_response_to"
                ) or not getattr(
                    subject_confirmation.subject_confirmation_data,
                    "in_response_to",
                    None,
                ):
                    raise SPIDValidatorException(
                        "subject.subject_confirmation_data in response to not valid. "
                        f"{_ERROR_TROUBLESHOOT}"
                    )

    def validate_assertion_conditions(self):
        """spid saml check 73, 74, 75, 76, 79, 80, 84, 85

        saml_response.assertion[0].conditions
        """
        for i in self.response.assertion:
            # 73, 74
            if not hasattr(i, "conditions") or not getattr(i, "conditions", None):
                # or not i.conditions.text.strip(' ').strip('\n'):
                raise SPIDValidatorException(
                    "Assertion conditions not present. " f"{
                        _ERROR_TROUBLESHOOT}"
                )

            # 75, 76
            if not hasattr(i.conditions, "not_before") or not getattr(
                i.conditions, "not_before", None
            ):
                # or not i.conditions.text.strip(' ').strip('\n'):
                raise SPIDValidatorException(
                    "Assertion conditions not_before not valid. "
                    f"{_ERROR_TROUBLESHOOT}"
                )

            # 79, 80
            if not hasattr(i.conditions, "not_on_or_after") or not getattr(
                i.conditions, "not_on_or_after", None
            ):
                # or not i.conditions.text.strip(' ').strip('\n'):
                raise SPIDValidatorException(
                    "Assertion conditions not_on_or_after not valid. "
                    f"{_ERROR_TROUBLESHOOT}"
                )

            # 84
            if not hasattr(i.conditions, "audience_restriction") or not getattr(
                i.conditions, "audience_restriction", None
            ):
                raise SPIDValidatorException(
                    "Assertion conditions without audience_restriction. "
                    f"{_ERROR_TROUBLESHOOT}"
                )

            # 85
            # already filtered by pysaml2: AttributeError: 'NoneType' object has no attribute 'strip'
            for aud in i.conditions.audience_restriction:
                if not getattr(aud, "audience", None):
                    raise SPIDValidatorException(
                        "Assertion conditions audience_restriction without audience."
                        f"{_ERROR_TROUBLESHOOT}"
                    )
                if not aud.audience[0].text:
                    raise SPIDValidatorException(
                        "Assertion conditions audience_restriction without audience. "
                        f"{_ERROR_TROUBLESHOOT}"
                    )

    def validate_assertion_authn_statement(self):
        """spid saml check 90, 92, 97, 98"""
        for i in self.response.assertion:
            if not hasattr(i, "authn_statement") or not getattr(
                i, "authn_statement", None
            ):
                raise SPIDValidatorException(
                    "Assertion authn_statement is missing/invalid. "
                    f"{_ERROR_TROUBLESHOOT}"
                )

            for authns in i.authn_statement:
                # 90, 92, 93
                if (
                    not hasattr(authns, "authn_context")
                    or not getattr(authns, "authn_context", None)
                    or not hasattr(authns.authn_context, "authn_context_class_ref")
                    or not getattr(
                        authns.authn_context, "authn_context_class_ref", None
                    )
                ):
                    raise SPIDValidatorException(
                        "Assertion authn_statement.authn_context_class_ref is missing/invalid. "
                        f"{_ERROR_TROUBLESHOOT}"
                    )

                # 94, 95, 96
                if (
                    authns.authn_context.authn_context_class_ref.text
                    != self.authn_context_class_ref
                ):
                    _msg = (
                        "Invalid Spid authn_context_class_ref, requested: "
                        f"{self.authn_context_class_ref}, got {
                            authns.authn_context.authn_context_class_ref.text}"
                    )
                    try:
                        level_sp = int(self.authn_context_class_ref[-1])
                        level_idp = int(
                            authns.authn_context.authn_context_class_ref.text.strip().replace(
                                "\n", ""
                            )[
                                -1
                            ]
                        )
                        if level_idp < level_sp:
                            raise SPIDValidatorException(_msg)
                    except Exception:
                        raise SPIDValidatorException(_msg)

                # 97
                if (
                    authns.authn_context.authn_context_class_ref.text
                    not in self.allowed_acrs
                ):
                    raise SPIDValidatorException(
                        "Assertion authn_statement.authn_context.authn_context_class_ref is missing/invalid. "
                        f"{_ERROR_TROUBLESHOOT}"
                    )
                # 98
                if not hasattr(i, "attribute_statement") or not getattr(
                    i, "attribute_statement", None
                ):
                    raise SPIDValidatorException(
                        "Assertion attribute_statement is missing/invalid. "
                        f"{_ERROR_TROUBLESHOOT}"
                    )

                for attri in i.attribute_statement:
                    if not attri.attribute:
                        raise SPIDValidatorException(
                            "Assertion attribute_statement.attribute is missing/invalid. "
                            f"{_ERROR_TROUBLESHOOT}"
                        )
                    # 99
                    for attro in attri.attribute:
                        if not attro.attribute_value:
                            raise SPIDValidatorException(
                                "Assertion attribute_value is missing/invalid. "
                                f"{_ERROR_TROUBLESHOOT}"
                            )

    def run(self, tests=[]):
        """run all tests/methods"""
        if not tests:
            tests = [
                i[0]
                for i in inspect.getmembers(self, predicate=inspect.ismethod)
                if not i[0].startswith("_")
            ]
            tests.remove("run")

            # tests.remove('validate_issuer')

        for element in tests:
            getattr(self, element)()
