import inspect
import json
import logging
import re

import saml2
import satosa.util as util
from jinja2 import Environment, FileSystemLoader, select_autoescape
from saml2.authn_context import requested_authn_context
from saml2.metadata import entity_descriptor, sign_entity_descriptor
from saml2.response import StatusAuthnFailed
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.sigver import SignatureError, security_context
from saml2.validate import valid_instance
from satosa.backends.saml2 import SAMLBackend
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError
from satosa.response import Response
from satosa.saml_util import make_saml_response
from six import text_type

from .spidsaml2_validator import Saml2ResponseValidator

logger = logging.getLogger(__name__)


#
# Messaggi di Errore SPID
#
# Ref: https://docs.italia.it/italia/spid/spid-regole-tecniche/it/stabile/messaggi-errore.html
#
SPID_ANOMALIES = {
    19: {
        "message": "Autenticazione fallita per ripetuta sottomissione di credenziali errate",
        "troubleshoot": "Inserire credenziali corrette",
    },
    20: {
        "message": (
            "Utente privo di credenziali compatibili con "
            "il livello di autenticazione richiesto"
        ),
        "troubleshoot": "Acquisire credenziali di livello idoneo all'accesso al servizio",
    },
    21: {
        "message": "Timeout durante l'autenticazione utente",
        "troubleshoot": (
            "Si ricorda che l'operazione di autenticazione deve "
            "essere completata entro un determinato periodo di tempo"
        ),
    },
    22: {
        "message": "L'utente nega il consenso all'invio di dati al fornitore del servizio",
        "troubleshoot": "È necessario dare il consenso per poter accedere al servizio",
    },
    23: {"message": "Utente con identità sospesa/revocata o con credenziali bloccate"},
    25: {"message": "Processo di autenticazione annullato dall'utente"},
    30: {
        "message": "L'identità digitale utilizzata non è un'identità digitale del tipo atteso",
        "troubleshoot": (
            "È necessario eseguire l'autenticazione con le credenziali "
            "del corretto tipo di identità digitale richiesto"
        ),
    },
}

_TROUBLESHOOT_MSG = (
    "È stato riscontrato un problema di validazione "
    "della risposta proveniente dal "
    "Provider di Identità. "
    " Contattare il supporto tecnico per eventuali chiarimenti"
)


class SpidSAMLBackend(SAMLBackend):
    """
    A saml2 backend module (acting as a SPID SP).
    """

    _authn_context = "https://www.spid.gov.it/SpidL1"

    def __init__(self, *args, **kwargs):

        logger.debug(
            f"Initializing: {self.__class__.__name__}. Params[args: {args}, kwargs: {kwargs}]"
        )

        super().__init__(*args, **kwargs)

        # error pages handler
        self.template_loader = Environment(
            loader=FileSystemLoader(searchpath=self.config["template_folder"]),
            autoescape=select_autoescape(["html"]),
        )
        _static_url = (
            self.config["static_storage_url"]
            if self.config["static_storage_url"][-1] == "/"
            else self.config["static_storage_url"] + "/"
        )
        self.template_loader.globals.update(
            {
                "static": _static_url,
            }
        )
        self.error_page = self.template_loader.get_template(
            self.config["error_template"]
        )

        logger.debug("inizializing metadata xmldoc")
        self.xmldoc = self.create_metadata(self.sp.config)

    def _metadata_contact_person(self, metadata, conf):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params[ metadata: {metadata}, conf: {conf}]"
        )
        ##############
        # avviso 29 v3
        #
        # https://www.agid.gov.it/sites/default/files/repository_files/spid-avviso-n29v3-specifiche_sp_pubblici_e_privati_0.pdf
        # Avviso 29v3
        SPID_PREFIXES = dict(
            spid="https://spid.gov.it/saml-extensions",
            fpa="https://spid.gov.it/invoicing-extensions",
        )
        saml2.md.SamlBase.register_prefix(SPID_PREFIXES)
        metadata.contact_person = []
        contact_map = conf.contact_person
        metadata.contact_person = []
        for contact in contact_map:
            spid_contact = saml2.md.ContactPerson()
            spid_contact.contact_type = contact["contact_type"]
            contact_kwargs = {
                key: contact[key]
                for key in ["email_address", "telephone_number", "company"]
                if key in contact
            }
            spid_extensions = saml2.ExtensionElement(
                "Extensions", namespace="urn:oasis:names:tc:SAML:2.0:metadata"
            )

            if contact["contact_type"] == "other":
                spid_contact.loadd(contact_kwargs)
                contact_kwargs["contact_type"] = contact["contact_type"]
                for k, v in contact.items():
                    if k in contact_kwargs:
                        continue
                    ext = saml2.ExtensionElement(
                        k, namespace=SPID_PREFIXES["spid"], text=v
                    )
                    # Avviso SPID n. 19 v.4 per enti AGGREGATORI il tag ContactPerson
                    # deve avere l’attributo spid:entityType valorizzato come spid:aggregator
                    if k == "PublicServicesFullAggregator":
                        spid_contact.extension_attributes = {
                            "spid:entityType": "spid:aggregator"
                        }
                    if k == "Aggregated":
                        spid_contact.extension_attributes = {
                            "spid:entityType": "spid:aggregated"
                        }
                        continue
                    spid_extensions.children.append(ext)

                spid_contact.extensions = spid_extensions

            elif contact["contact_type"] == "billing":
                contact_kwargs["company"] = contact["company"]
                spid_contact.loadd(contact_kwargs)

                elements = {}
                for k, v in contact.items():
                    if k in contact_kwargs:
                        continue
                    ext = saml2.ExtensionElement(
                        k, namespace=SPID_PREFIXES["fpa"], text=v
                    )
                    elements[k] = ext

                # DatiAnagrafici
                IdFiscaleIVA = saml2.ExtensionElement(
                    "IdFiscaleIVA",
                    namespace=SPID_PREFIXES["fpa"],
                )
                Anagrafica = saml2.ExtensionElement(
                    "Anagrafica",
                    namespace=SPID_PREFIXES["fpa"],
                )
                Anagrafica.children.append(elements["Denominazione"])

                IdFiscaleIVA.children.append(elements["IdPaese"])
                IdFiscaleIVA.children.append(elements["IdCodice"])
                DatiAnagrafici = saml2.ExtensionElement(
                    "DatiAnagrafici",
                    namespace=SPID_PREFIXES["fpa"],
                )
                if elements.get("CodiceFiscale"):
                    DatiAnagrafici.children.append(elements["CodiceFiscale"])
                DatiAnagrafici.children.append(IdFiscaleIVA)
                DatiAnagrafici.children.append(Anagrafica)
                CessionarioCommittente = saml2.ExtensionElement(
                    "CessionarioCommittente",
                    namespace=SPID_PREFIXES["fpa"],
                )
                CessionarioCommittente.children.append(DatiAnagrafici)

                # Sede
                Sede = saml2.ExtensionElement(
                    "Sede",
                    namespace=SPID_PREFIXES["fpa"],
                )
                Sede.children.append(elements["Indirizzo"])
                Sede.children.append(elements["NumeroCivico"])
                Sede.children.append(elements["CAP"])
                Sede.children.append(elements["Comune"])
                Sede.children.append(elements["Provincia"])
                Sede.children.append(elements["Nazione"])
                CessionarioCommittente.children.append(Sede)

                spid_extensions.children.append(CessionarioCommittente)

            spid_contact.extensions = spid_extensions
            metadata.contact_person.append(spid_contact)
        #
        # fine avviso 29v3
        ###################

    def _metadata_endpoint(self, context):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params[ context: {context}]."
        )
        """
        Endpoint for retrieving the backend metadata
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response with metadata
        """
        logger.debug("Sending metadata response")
        return Response(
            text_type(self.xmldoc).encode("utf-8"), content="text/xml; charset=utf8"
        )

    def get_kwargs_sign_dig_algs(self):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params[ self]"
        )
        kwargs = {}
        # backend support for selectable sign/digest algs
        alg_dict = dict(signing_algorithm="sign_alg",
                        digest_algorithm="digest_alg")
        for alg in alg_dict:
            selected_alg = self.config["sp_config"]["service"]["sp"].get(alg)
            if not selected_alg:
                continue
            kwargs[alg_dict[alg]] = selected_alg
        return kwargs

    def check_blacklist(self, context, entity_id):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params[ context: {context}, entity_id: {entity_id}]"
        )
        # If IDP blacklisting is enabled and the selected IDP is blacklisted,
        # stop here
        if self.idp_blacklist_file:
            with open(self.idp_blacklist_file) as blacklist_file:
                blacklist_array = json.load(blacklist_file)["blacklist"]
                if entity_id in blacklist_array:
                    logger.debug(
                        "IdP with EntityID {} is blacklisted".format(entity_id)
                    )
                    raise SATOSAAuthenticationError(
                        context.state, "Selected IdP is blacklisted for this backend"
                    )

    def authn_request(self, context, entity_id):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params[ context: {context}, entity_id: {entity_id}]"
        )
        """
        Do an authorization request on idp with given entity id.
        This is the start of the authorization.

        :type context: satosa.context.Context
        :type entity_id: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param entity_id: Target IDP entity id
        :return: response to the user agent
        """
        self.check_blacklist(context, entity_id)
        kwargs = {}
        # fetch additional kwargs
        kwargs.update(self.get_kwargs_sign_dig_algs())

        authn_context = self.construct_requested_authn_context(entity_id)
        req_authn_context = authn_context or requested_authn_context(
            class_ref=self._authn_context
        )
        req_authn_context.comparison = self.config.get(
            "spid_acr_comparison", "minimum")

        # force_auth = true only if SpidL >= 2
        if "SpidL1" in authn_context.authn_context_class_ref[0].text:
            force_authn = "false"
        else:
            force_authn = "true"

        try:
            binding = saml2.BINDING_HTTP_POST
            destination = context.internal_data.get(
                "target_entity_id", entity_id)
            # SPID CUSTOMIZATION
            # client = saml2.client.Saml2Client(conf)
            client = self.sp

            logger.debug(f"binding: {binding}, destination: {destination}")

            # acs_endp, response_binding = self.sp.config.getattr("endpoints", "sp")["assertion_consumer_service"][0]
            # req_id, req = self.sp.create_authn_request(
            # destination, binding=response_binding, **kwargs)

            logger.debug(f"Redirecting user to the IdP via {binding} binding.")
            # use the html provided by pysaml2 if no template was specified or it didn't exist

            # SPID want the fqdn of the IDP as entityID, not the SSO endpoint
            # 'http://idpspid.testunical.it:8088'
            # dovrebbe essere destination ma nel caso di spid-testenv2 è entityid...
            # binding, destination = self.sp.pick_binding("single_sign_on_service", None, "idpsso", entity_id=entity_id)
            location = client.sso_location(destination, binding)
            # location = client.sso_location(entity_id, binding)

            # not used anymore thanks to avviso 11
            # location_fixed = destination  # entity_id
            # ...hope to see the SSO endpoint soon in spid-testenv2
            # returns 'http://idpspid.testunical.it:8088/sso'
            # fixed: https://github.com/italia/spid-testenv2/commit/6041b986ec87ab8515dd0d43fed3619ab4eebbe9

            # verificare qui
            # acs_endp, response_binding = self.sp.config.getattr("endpoints", "sp")["assertion_consumer_service"][0]

            authn_req = saml2.samlp.AuthnRequest()
            authn_req.force_authn = force_authn
            authn_req.destination = location
            # spid-testenv2 preleva l'attribute consumer service dalla authnRequest
            # (anche se questo sta già nei metadati...)
            # Imposta il consuming_service_index in base al default di ficep per le richieste ficep, oppure a '0' per le richieste spid
            authn_req.attribute_consuming_service_index = str(
                self.config["sp_config"].get("acs_index") or
                self.config["sp_config"].get("ficep_default_acs_index") or
                "0"
            )
            issuer = saml2.saml.Issuer()
            issuer.name_qualifier = client.config.entityid
            issuer.text = client.config.entityid
            issuer.format = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
            authn_req.issuer = issuer

            # message id
            authn_req.id = saml2.s_utils.sid()
            authn_req.version = saml2.VERSION  # "2.0"
            authn_req.issue_instant = saml2.time_util.instant()

            name_id_policy = saml2.samlp.NameIDPolicy()
            # del(name_id_policy.allow_create)
            name_id_policy.format = NAMEID_FORMAT_TRANSIENT
            authn_req.name_id_policy = name_id_policy

            # TODO: use a parameter instead
            authn_req.requested_authn_context = req_authn_context
            authn_req.protocol_binding = binding

            assertion_consumer_service_url = client.config._sp_endpoints[
                "assertion_consumer_service"
            ][0][0]
            authn_req.assertion_consumer_service_url = (
                assertion_consumer_service_url  # 'http://sp-fqdn/saml2/acs/'
            )

            authn_req_signed = client.sign(
                authn_req,
                sign_prepare=False,
                sign_alg=kwargs["sign_alg"],
                digest_alg=kwargs["digest_alg"],
            )
            authn_req.id

            _req_str = authn_req_signed
            logger.debug(f"AuthRequest to {destination}: {_req_str}")

            relay_state = util.rndstr()
            ht_args = client.apply_binding(
                binding,
                _req_str,
                location,
                sign=True,
                sigalg=kwargs["sign_alg"],
                relay_state=relay_state,
            )

            if self.sp.config.getattr("allow_unsolicited", "sp") is False:
                if authn_req.id in self.outstanding_queries:
                    errmsg = "Request with duplicate id {}".format(
                        authn_req.id)
                    logger.debug(errmsg)
                    raise SATOSAAuthenticationError(context.state, errmsg)
                self.outstanding_queries[authn_req.id] = authn_req_signed

            context.state[self.name] = {"relay_state": relay_state}
            # these will give the way to check compliances between the req and resp
            context.state["req_args"] = {"id": authn_req.id}

            logger.info(f"SAMLRequest: {ht_args}")
            return make_saml_response(binding, ht_args)

        except Exception as exc:
            logger.debug("Failed to construct the AuthnRequest for state")
            raise SATOSAAuthenticationError(
                context.state, "Failed to construct the AuthnRequest"
            ) from exc

    def handle_error(
        self,
        message: str,
        troubleshoot: str = "",
        err="",
        template_path="templates",
        error_template="spid_login_error.html",
    ):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params[ message: {message}, troubleshoot: {troubleshoot}]"
        )
        """
        Todo: Jinja2 tempalte loader and rendering :)
        """
        logger.error(f"Failed to parse authn request: {message} {err}")
        result = self.error_page.render(
            {"message": message, "troubleshoot": troubleshoot}
        )
        # the raw way :)
        # msg = (
        # f'<b>{message}</b><br>'
        # f'{troubleshoot}'
        # )
        # result = text_type(msg).encode('utf-8')
        return Response(result, content="text/html; charset=utf8", status="403")

    def handle_spid_anomaly(self, err_number, err):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params[ err_number: {err_number}, err: {err}]"
        )
        return self.handle_error(**SPID_ANOMALIES[int(err_number)])

    def authn_response(self, context, binding):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params[ context: {context}, binding: {binding}]"
        )
        """
        Endpoint for the idp response
        :type context: satosa.context,Context
        :type binding: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param binding: The saml binding type
        :return: response
        """
        if not context.request["SAMLResponse"]:
            logger.debug("Missing Response for state")
            raise SATOSAAuthenticationError(context.state, "Missing Response")

        try:
            authn_response = self.sp.parse_authn_request_response(
                context.request["SAMLResponse"],
                binding,
                outstanding=self.outstanding_queries,
            )
        except StatusAuthnFailed as err:
            erdict = re.search(r"ErrorCode nr(?P<err_code>\d+)", str(err))
            if erdict:
                return self.handle_spid_anomaly(erdict.groupdict()["err_code"], err)
            else:
                return self.handle_error(
                    **{
                        "err": err,
                        "message": "Autenticazione fallita",
                        "troubleshoot": (
                            "Anomalia riscontrata durante la fase di Autenticazione. "
                            f"{_TROUBLESHOOT_MSG}"
                        ),
                    }
                )
        except SignatureError as err:
            return self.handle_error(
                **{
                    "err": err,
                    "message": "Autenticazione fallita",
                    "troubleshoot": (
                        "La firma digitale della risposta ottenuta "
                        f"non risulta essere corretta. {_TROUBLESHOOT_MSG}"
                    ),
                }
            )
        except Exception as err:
            return self.handle_error(
                **{
                    "err": err,
                    "message": "Anomalia riscontrata nel processo di Autenticazione",
                    "troubleshoot": _TROUBLESHOOT_MSG,
                }
            )

        if self.sp.config.getattr("allow_unsolicited", "sp") is False:
            req_id = authn_response.in_response_to
            if req_id not in self.outstanding_queries:
                errmsg = ("No request with id: {}".format(req_id),)
                logger.debug(errmsg)
                return self.handle_error(
                    **{"message": errmsg, "troubleshoot": _TROUBLESHOOT_MSG}
                )
            del self.outstanding_queries[req_id]

        # Context validation
        if not context.state.get(self.name):
            _msg = f"context.state[self.name] KeyError: where self.name is {
                self.name}"
            logger.error(_msg)
            return self.handle_error(
                **{"message": _msg, "troubleshoot": _TROUBLESHOOT_MSG}
            )
        # check if the relay_state matches the cookie state
        if context.state[self.name]["relay_state"] != context.request["RelayState"]:
            _msg = "State did not match relay state for state"
            return self.handle_error(
                **{"message": _msg, "troubleshoot": _TROUBLESHOOT_MSG}
            )

        # Spid and SAML2 additional tests
        _sp_config = self.config["sp_config"]
        accepted_time_diff = _sp_config["accepted_time_diff"]
        recipient = _sp_config["service"]["sp"]["endpoints"][
            "assertion_consumer_service"
        ][0][0]

        # ACR
        issuer = authn_response.response.issuer.text.strip()
        acr_map: dict = {}

        try:
            acr_map = self.config["acr_mapping"]
        except Exception:
            logger.warning(
                "acr_mapping not defined in the spid backend"
            )
            return self.handle_error(
                **{
                    "message": "acr_mapping not defined in the spid backend",
                    "troubleshoot": "Please contact the administrators of the platform and tell them to configure properly the acr_mapping in the SPID/CIE backend"
                }
            )
        acr_default = acr_map.get("", "https://www.spid.gov.it/SpidL2")
        authn_context_classref = acr_map.get(issuer, acr_default)

        # this will get the entity name in state
        if len(context.state.keys()) < 2:
            _msg = "Inconsistent context.state"
            return self.handle_error(
                **{"message": _msg, "troubleshoot": _TROUBLESHOOT_MSG}
            )

        list(context.state.keys())[1]
        # deprecated
        # if not context.state.get('Saml2IDP'):
        # _msg = "context.state['Saml2IDP'] KeyError"
        # logger.error(_msg)
        # raise SATOSAStateError(context.state, "State without Saml2IDP")
        in_response_to = context.state["req_args"]["id"]

        # some debug
        if authn_response.ava:
            logging.debug(
                f"Attributes to {authn_response.return_addrs} "
                f"in_response_to {authn_response.in_response_to}: "
                f'{",".join(authn_response.ava.keys())}'
            )

        validator = Saml2ResponseValidator(
            authn_response=authn_response.xmlstr,
            recipient=recipient,
            in_response_to=in_response_to,
            accepted_time_diff=accepted_time_diff,
            authn_context_class_ref=authn_context_classref,
            return_addrs=authn_response.return_addrs,
            allowed_acrs=self.config["spid_allowed_acrs"],
        )
        try:
            validator.run()
        except Exception as e:
            logger.error(e)
            return self.handle_error(e)

        context.decorate(Context.KEY_BACKEND_METADATA_STORE, self.sp.metadata)
        if self.config.get(SAMLBackend.KEY_MEMORIZE_IDP):
            issuer = authn_response.response.issuer.text.strip()
            context.state[Context.KEY_MEMORIZED_IDP] = issuer
        context.state.pop(self.name, None)
        context.state.pop(Context.KEY_FORCE_AUTHN, None)

        logger.info(f"SAMLResponse{authn_response.xmlstr}")
        return self.auth_callback_func(
            context, self._translate_response(authn_response, context.state)
        )

    def __create_metadata(self, conf):
        """
        method __create_metadata private
        Create metadata for SpidSaml2

        :param self: Instance for SpidSaml2
        :param conf: Configuration for SpidSaml2
        :return: xmldoc
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [conf: {conf}]"
        )
        metadata = entity_descriptor(conf)

        # creare gli attribute_consuming_service
        metadata.spsso_descriptor.attribute_consuming_service[0].index = '0'
        metadata.spsso_descriptor.attribute_consuming_service[0].service_name[0].lang = "it"
        metadata.spsso_descriptor.attribute_consuming_service[
            0].service_name[0].text = metadata.entity_id
        for reqattr in metadata.spsso_descriptor.attribute_consuming_service[0].requested_attribute:
            reqattr.name_format = None
            reqattr.friendly_name = None

        metadata.spsso_descriptor.assertion_consumer_service[0].index = '0'
        metadata.spsso_descriptor.assertion_consumer_service[0].is_default = 'true'

        if self.config["sp_config"]["ficep_enable"] is True:
            # Aggiungere CIE 99
            metadata.spsso_descriptor.attribute_consuming_service.append(
                saml2.md.AttributeConsumingService())
            metadata.spsso_descriptor.attribute_consuming_service[1].index = '99'
            metadata.spsso_descriptor.attribute_consuming_service[1].service_name.append(
                saml2.md.ServiceName())
            metadata.spsso_descriptor.attribute_consuming_service[1].service_name[0].lang = "it"
            metadata.spsso_descriptor.attribute_consuming_service[1].service_name[
                0].text = "eIDAS Natural Person Minimum Attribute Set"
            metadata.spsso_descriptor.attribute_consuming_service[1].requested_attribute = [
                saml2.md.RequestedAttribute('true', None, 'spidCode'),
                saml2.md.RequestedAttribute('true', None, 'name'),
                saml2.md.RequestedAttribute('true', None, 'familyName'),
                saml2.md.RequestedAttribute('true', None, 'dateOfBirth'),
            ]

            metadata.spsso_descriptor.assertion_consumer_service[1].index = '99'
            metadata.spsso_descriptor.assertion_consumer_service[1].is_default = None

            # Aggiungere CIE 100
            metadata.spsso_descriptor.attribute_consuming_service.append(
                saml2.md.AttributeConsumingService())
            metadata.spsso_descriptor.attribute_consuming_service[2].index = '100'
            metadata.spsso_descriptor.attribute_consuming_service[2].service_name.append(
                saml2.md.ServiceName())
            metadata.spsso_descriptor.attribute_consuming_service[2].service_name[0].lang = "it"
            metadata.spsso_descriptor.attribute_consuming_service[2].service_name[
                0].text = "eIDAS Natural Person Full Attribute Set"
            metadata.spsso_descriptor.attribute_consuming_service[2].requested_attribute = [
                saml2.md.RequestedAttribute('true', None, 'spidCode'),
                saml2.md.RequestedAttribute('true', None, 'name'),
                saml2.md.RequestedAttribute('true', None, 'familyName'),
                saml2.md.RequestedAttribute('true', None, 'dateOfBirth'),
                saml2.md.RequestedAttribute('true', None, 'placeOfBirth'),
                saml2.md.RequestedAttribute('true', None, 'address'),
                saml2.md.RequestedAttribute('true', None, 'gender'),
            ]

            metadata.spsso_descriptor.assertion_consumer_service[2].index = '100'
            metadata.spsso_descriptor.assertion_consumer_service[2].is_default = None

        # load ContactPerson Extensions
        self._metadata_contact_person(metadata, conf)

        # metadata signature
        secc = security_context(conf)
        #
        sign_dig_algs = self.get_kwargs_sign_dig_algs()
        eid, xmldoc = sign_entity_descriptor(
            metadata, None, secc, **sign_dig_algs)

        valid_instance(eid)

        return xmldoc
