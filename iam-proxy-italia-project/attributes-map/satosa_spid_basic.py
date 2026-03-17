ATTRS = [
    "spidCode",
    "name",
    "familyName",
    # Collides with eIDAS ...
    # "FamilyName",
    "placeOfBirth",
    "countyOfBirth",
    "dateOfBirth",
    "gender",
    "companyName",
    "registeredOffice",
    "fiscalNumber",
    "ivaCode",
    "idCard",
    "mobilePhone",
    "email",
    "address",
    "expirationDate",
    "digitalAddress",
]


MAP = {
    "identifier": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
    "fro": {k: k for k in ATTRS},
    "to": {k: k for k in ATTRS},
}
