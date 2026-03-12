
## TEST

The following document is intended to guide the use of the various tests included 
in the "iam-proxy-italia" project.

## Table of Contents

1. [Prerequisites](#Prerequisites)
2. [Virtual Environment](#test_venv)
3. [TEST_CALLBACK_HANDLER](#test_callback_handler)
   1. [Dependencies](#Dependencies)
   2. [RUN](#TCH-run)
   3. [TEST-COVERAGE](#TCH-Test-Coverage)
      1. [US01-Happy path–Authorization callback](#TCH-US01)
      2. [US02-Invalid requeste](#TCH-US02)
   4. [NOTES](#Notes-TCH)
4. [TEST_AUTHORIZATION_HANDLER](#test_authorization_handler)
   1. [Dependencies](#TAH-Dependencies)
   2. [RUN](#TAH-run)
   3. [TEST-COVERAGE](#TAH-Test-Coverage)
      1. [US01-Configuration validation (success)](#TAH-US01)
      2. [US02-Configuration validation (failure)](#TAH-US02)
      3. [US03-Happy path](#TAH-US03)
      4. [US04-PKCE configuration](#TAH-US04)
      5. [US05-URI generation](#TAH-US05)
      6. [US06-Private insert method](#TAH-US06)
   4. [NOTES](#Notes-TAH)
5. [TEST_FEDERATION](#test_federation)
   1. [Dependencies](#TFD-Dependencies)
   2. [RUN](#TFD-run)
   3. [TEST-COVERAGE](#TFD-Test-Coverage)
      1. [US01-is_leaf (success)](#TFD-US01)
      2. [US02-is_leaf (failure)](#TFD-US02)
      3. [US03-public_jwks](#TFD-US03)
      4. [US04-pems_as_dict](#TFD-US04)
      5. [US05-pems_as_json](#TFD-US05)
      6. [US06-kids](#TFD-US06)
      7. [US07-type_property](#TFD-US07)
      8. [US08-is_leaf_property](#TFD-US08)
      9. [US09-entity_configuration_as_dict](#TFD-US09)
      10. [US10-entity_configuration_as_json](#TFD-US10)
      11. [US11-entity_configuration_as_jws](#TFD-US11)
      12. [US12-fetch_endpoint](#TFD-US12)
      13. [US13-set_jwks_as_array](#TFD-US13)
   4. [NOTES](#Notes-TFD)
6. [TEST_HTTP_UTILS](#test_http_utils)
   1. [Dependencies](#THTTP-Dependencies)
   2. [RUN](#THTTP-run)
   3. [TEST-COVERAGE](#THTTP-Test-Coverage)
      1. [US01-http_get_sync (success)](#THTTP-US01)
      2. [US02-http_get_sync (failure)](#THTTP-US02)
      3. [US03-http_get_sync (failure)](#THTTP-US03)
      4. [US04-http_get_sync (success)](#THTTP-US04)
      5. [US05-http_get_async (failure)](#THTTP-US05)
      6. [US06-cacheable_get_http_url (success)](#THTTP-US06)
      7. [US07-cacheable_get_http_url (failure)](#THTTP-US07)
   4. [NOTES](#Notes-THTTP)
7. [TEST_JWK_UTILS](#test_jwk_utils)
   1. [Dependencies](#TJWK-Dependencies)
   2. [RUN](#TJWK-run)
   3. [TEST-COVERAGE](#TJWK-Test-Coverage)
      1. [US01-create_jwk](#TJWK-US01)
      2. [US02-public_jwk_from_private_jwk](#TJWK-US02)
      3. [US03-private_pem_from_jwk](#TJWK-US03)
      4. [US04-public_pem_from_jwk](#TJWK-US04)
   4. [NOTES](#Notes-TJWK)
8. [TEST_JWT_UTILS](#test_jwt_utils)
   1. [Dependencies](#TJWT-Dependencies)
   2. [RUN](#TJWT-run)
   3. [TEST-COVERAGE](#TJWT-Test-Coverage)
      1. [US01-unpad_jwt_payload](#TJWT-US01)
      2. [US02-create_jws](#TJWT-US02)
      3. [US03-verify_at_hash (success)](#TJWT-US03)
      4. [US04-verify_at_hash (failure)](#TJWT-US04)
      5. [US05-base64url decoding](#TJWT-US05)
      6. [US06-JWE creation (JSON)](#TJWT-US06)
      7. [US07-JWE creation (None)](#TJWT-US07)
      8. [US08-JWE creation (non-JSON-serializable)](#TJWT-US08)
      9. [US09-JWE decryption (success)](#TJWT-US09)
      10. [US10-JWE decryption (failure)](#TJWT-US10)
      11. [US11-at_hash generation (success)](#TJWT-US11)
      12. [US12-access token verification (failure)](#TJWT-US12)
   4. [NOTES](#Notes-TJWT)
9. [TEST_MISC_UTILS](#test_misc_utils)
   1. [Dependencies](#TMSC-Dependencies)
   2. [RUN](#TMSC-run)
   3. [TEST-COVERAGE](#TMSC-Test-Coverage)
      1. [US01-make_timezone_aware (success)](#TMSC-US01)
      2. [US02-make_timezone_aware (failure)](#TMSC-US02)
      3. [US03-random_token generates string](#TMSC-US03)
      4. [US04-get_pkce generates code_verifier and code_challenge](#TMSC-US04)
      5. [US05-http_dict_to_redirect_uri_path converts dictionary to query string](#TMSC-US05)
   4. [NOTES](#Notes-TMSC)
10. [TEST_MONGO_STORAGE](#test_mongo_storage)
    1. [Dependencies](#TMSTO-Dependencies)
    2. [RUN](#TMSTO-run)
    3. [TEST-COVERAGE](#TMSTO-Test-Coverage)
       1. [US01-connect](#TMSTO-US01)
       2. [US02-close](#TMSTO-US02)
       3. [US03-is_connected (failure)](#TMSTO-US03)
       4. [US04-is_connected (failure)](#TMSTO-US04)
       5. [US05-is_connected (success)](#TMSTO-US05)
       6. [US06-to_doc_with_uuid](#TMSTO-US06)
       7. [US07-from_doc_with_binary_id](#TMSTO-US07)
       8. [US08-add (success)](#TMSTO-US08)
       9. [US09-add (failure)](#TMSTO-US09)
       10. [US10-update (failure)](#TMSTO-US10)
       11. [US11-update (success)](#TMSTO-US11)
       12. [US12-remove_with_objectid](#TMSTO-US12)
       13. [US13-find_by_id (failure)](#TMSTO-US13)
       14. [US14-find_all](#TMSTO-US14)
       15. [US15-add_session](#TMSTO-US15)
       16. [US16-update_session](#TMSTO-US16)
       17. [US17-to_uuid (success)](#TMSTO-US17)
       18. [US18-to_uuid (failure)](#TMSTO-US18)
    4. [NOTES](#Notes-TMSTO)
11. [TEST_OIDC_DB_ENGINE](#test_oidc_db_engine)
    1. [Dependencies](#TDBE-Dependencies)
    2. [RUN](#TDBE-run)
    3. [TEST-COVERAGE](#TDBE-Test-Coverage)
       1. [US01-connect](#TDBE-US01)
       2. [US02-close](#TDBE-US02)
       3. [US03-is_connected](#TDBE-US03)
       4. [US04-add_session](#TDBE-US04)
       5. [US05-update_session (failure)](#TDBE-US05)
       6. [US06-update_session (success)](#TDBE-US06)
       7. [US07-get_sessions](#TDBE-US07)
       8. [US08-prepare_for_insert](#TDBE-US08)
    4. [NOTES](#Notes-TDBE)
12. [TEST_ENTITY_CONFIGURATION](#test_entity_configuration)
    1. [Dependencies](#TEC-Dependencies)
    2. [RUN](#TEC-run)
    3. [TEST-COVERAGE](#TEC-Test-Coverage)
       1. [US01-initialization and validation](#TEC-US01)
       2. [US02-metadata property](#TEC-US02)
       3. [US03-get_entity_configuration (JSON)](#TEC-US03)
       4. [US04-get_entity_configuration (JWS)](#TEC-US04)
       5. [US05-federation entity configuration integration](#TEC-US05)
       6. [US06-JWKS exposure](#TEC-US06)
    4. [NOTES](#Notes-TEC)
13. [TEST_CIEOIDC](#test_cieoidc)
     1. [Dependencies](#TCOB-Dependencies)
     2. [RUN](#TCOB-run)
     3. [TEST-COVERAGE](#TCOB-Test-Coverage)
        1. [US01-backend initialization sets client_id](#TCOB-US01)
        2. [US02-trust chain generation is triggered on initialization](#TCOB-US02)
        3. [US03-start_auth without authorization endpoint (failure)](#TCOB-US03)
        4. [US04-start_auth delegates to authorization endpoint](#TCOB-US04)
        5. [US05-endpoint registration via EndpointsLoader](#TCOB-US05)
        6. [US06-metadata descriptor generation](#TCOB-US06)
        7. [US07-trust chains generation for providers](#TCOB-US07)
        8. [US08-single trust chain generation logic](#TCOB-US08)
     4. [NOTES](#Notes-TCOB)
14. [TEST_OIDC](#test_oidc)
     1. [Dependencies](#TOIDC-Dependencies)
     2. [RUN](#TOIDC-run)
     3. [TEST-COVERAGE](#TOIDC-Test-Coverage)
        1. [US01-get_userinfo_plain_json](#TOIDC-US01)
        2. [US02-get_userinfo_http (failure)](#TOIDC-US02)
        3. [US03-get_userinfo_jwe_jws](#TOIDC-US03)
        4. [US04-get_userinfo_unknown_kid](#TOIDC-US04)
        5. [US05-get_userinfo_key_error](#TOIDC-US05)
     4. [NOTES](#Notes-TOIDC)
15. [TEST_OAUTH2_AUTHORIZATION](#test_oauth2_authorization)
     1. [Dependencies](#TOACG-Dependencies)
     2. [RUN](#TOACG-run)
     3. [TEST-COVERAGE](#TOACG-Test-Coverage)
        1. [US01-access_token_request (success)](#TOACG-US01)
        2. [US02-access_token_request (failure)](#TOACG-US02)
        3. [US03-refresh_token (success)](#TOACG-US03)
        4. [US04-refresh_token_without_token_endpoint](#TOACG-US04)
        5. [US05-get_rp_conf_returns_dict](#TOACG-US05)
     4. [NOTES](#Notes-TOACG)
16. [TEST_VALIDATOR](#test_validator)
     1. [Dependencies](#TVAL-Dependencies)
     2. [RUN](#TVAL-run)
     3. [TEST-COVERAGE](#TVAL-Test-Coverage)
        1. [US01-validate_public_jwks (success)](#TVAL-US01)
        2. [US02-validate_public_jwks_private_key_rejected (failure)](#TVAL-US02)
        3. [US03-validate_public_jwks_invalid_jwk (failure)](#TVAL-US03)
        4. [US04-validate_private_jwks (success)](#TVAL-US04)
        5. [US05-validate_private_jwks_public_key_rejected (failure)](#TVAL-US05)
        6. [US06-validate_private_jwks_invalid_jwk (failure)](#TVAL-US06)
        7. [US07-validate_metadata_algs (success)](#TVAL-US07)
        8. [US08-single trust chain generation logic](#TVAL-US08)
     4. [NOTES](#Notes-TVAL)

### Prerequisites

All runtime dependencies are defined in `pyproject.toml`. Test-related tools (pytest, pytest-cov, flake8, spid-sp-test) are in the optional dependency group `test`, aligned with the [GitHub Actions workflows](../.github/workflows/) (lint, docker-compose-test, cie-oidc-backend).

From the project root, install dependencies with Poetry (recommended, same as [setup](setup.md)):

```bash
poetry install --extras test
```

This installs all dependencies from `pyproject.toml` plus the test extras. Use a dedicated virtual environment (e.g. `poetry config virtualenvs.in-project true` then `poetry install`) and recreate it for each test session to avoid conflicts.

**Optional (for CI-aligned SPID tests):** install system dependency `xmlsec1` if you run spid-sp-test locally:

```bash
sudo apt install -y xmlsec1
```

### test_venv

Install virtual environment support (example on Debian/Ubuntu):

```bash
sudo apt install python3.12-venv
```

Create the virtual environment (Python 3.10+ as per `pyproject.toml`), for example `test_venv`:

```bash
python3.12 -m venv test_venv
```

Activate it:

```bash
source test_venv/bin/activate
```

Then install the project and test dependencies as in [Prerequisites](#Prerequisites):

```bash
poetry install --extras test
```
 

### test_callback_handler

This test suite validates the authorization callback endpoint logic, simulating a full OIDC callback flow.
The endpoint behavior is tested by mocking all external dependencies (JWKS retrieval, JWT verification, token exchange, and 
userinfo retrieval).

#### Dependencies

Use the same setup as [Prerequisites](#Prerequisites): activate the virtual environment and ensure dependencies are installed with test extras (`poetry install --extras test`). All required dependencies (SATOSA, pydantic, aiohttp, pymongo, pyeudiw, etc.) are defined in `pyproject.toml`.

#### TCH-run

```bash
pytest backends/cieoidc/tests/test_callback_handler.py -v
``` 

#### TCH-Test-Coverage
##### TCH-US01
This test validates the successful execution of the authorization callback endpoint.
Covered aspects:
- Query string parameter handling (state, code, iss)
- JWKS retrieval and key resolution
- JWT signature verification
- ID Token payload validation
- Access token request handling
- UserInfo retrieval
- Attribute processing
- Final response generation
All external interactions are mocked to isolate endpoint logic.

##### TCH-US02
Validates request failure scenarios. An exception is expected when:
- Query string parameters are missing or invalid
- Issuer does not match the expected provider
- Authorization state is missing from storage

#### Notes-TCH
- This test simulates an OIDC authorization callback flow.
- Cryptographic validation and HTTP calls are mocked.
- The test validates endpoint orchestration rather than cryptographic correctness.
- Intended as an integration-style unit test.


### test_authorization_handler

#### TAH-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TAH-run

```bash
pytest backends/cieoidc/tests/test_authorization_handler.py -v
``` 
#### TAH-Test-Coverage
##### TAH-US01
Validates the validate_configs method with a correct configuration.

##### TAH-US02
Validates behavior when a required configuration field is missing.
An exception is expected.

##### TAH-US03
Tests the standard authorization flow.

##### TAH-US04
Validates PKCE length configuration.

##### TAH-US05
Tests the URI generation logic.

##### TAH-US06
Tests the internal insert method.

#### Notes-TAH
- Tests rely on real dependencies (SATOSA, MongoDB driver, cryptography stack).
- These tests should be treated as integration-level tests.
- Suitable for local execution and CI pipelines.



### test_federation
### TFD-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TFD-run

```bash
pytest backends/cieoidc/tests/utils/models/test_federation.py
``` 
#### TFD-Test-Coverage
##### TFD-US01
Validates that the `is_leaf` helper function returns `True` when metadata contains a valid OpenID leaf entity type (e.g. openid_relying_party).

##### TFD-US02
Validates that the `is_leaf` helper function returns `None` when metadata does not represent a leaf entity.

##### TFD-US03
Validates the `public_jwks` property:
- Private RSA JWKs are converted to public keys
- Only public key material is exposed
- The `kid` value is preserved
All key conversion and serialization logic is mocked.

##### TFD-US04
Validates the `pems_as_dict` property:
- PEMs are indexed by `kid`
- Each key contains both `private` and `public` PEM values
PEM generation helpers are mocked.

##### TFD-US05
Validates JSON serialization of PEM data:
- `pems_as_json` returns a valid JSON string
- The JSON payload matches the dictionary returned by `pems_as_dict`

##### TFD-US06
Validates the `kids` property:
- Returns the list of key identifiers extracted from the configured JWKS

##### TFD-US07
Validates the `type` property:
- Returns the list of entity types derived from metadata keys

##### TFD-US08
Validates the `is_leaf` property on the entity instance:
- Correctly reflects leaf entity status based on metadata

##### TFD-US09
Validates `entity_configuration_as_dict`:
- `exp` is generated via `exp_from_now`
- `iat` is generated via `iat_now`
- `iss` matches the entity subject (sub)
- Public JWKS are included
- Metadata is preserved
Time helpers are mocked for deterministic output.
##### TFD-US10
Validates JSON serialization of the entity configuration:
- Returned value is valid JSON
- JSON content matches the source dictionary

##### TFD-US11
Validates signed entity configuration generation:
- Signing is delegated to the create_jws helper
- A non-empty JWS string is returned
- The signing helper is invoked exactly once
No real cryptographic signing is performed.

##### TFD-US12
Validates federation metadata handling:
- fetch_endpoint is correctly extracted from federation_entity metadata when present

##### TFD-US13
Validates JWKS normalization logic:
- `jwks_core` is converted to a list when provided as a dictionary
- `jwks_fed` is converted to a list when provided as a dictionary


#### Notes-TFD
- Tests JWT manipulation and verification.

### test_jwt_utils
### TJWT-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TJWT-run

```bash
pytest backends/cieoidc/tests/utils/test_jwt.py -v
``` 
#### TJWT-Test-Coverage
##### TJWT-US01
`unpad_jwt_payload` extracts JWT payload

##### TJWT-US02
`create_jws` generates JWS

##### TJWT-US03
`verify_at_hash` process success

##### TJWT-US04
`verify_at_hash` failure process return exception

##### TJWT-US05
Verifies correct base64url decoding and padding handling for JWT headers and payloads.

##### TJWT-US06
Ensures JWE creation succeeds with a valid JSON payload and RSA public key.

##### TJWT-US07
Confirms JWE creation works with a None payload.

##### TJWT-US08
Validates JWE creation with non-JSON-serializable inputs (e.g. set), ensuring graceful handling.

##### TJWT-US09
Tests successful JWE decryption using supported encryption algorithms.

##### TJWT-US10
Verifies that JWE decryption fails when the encryption algorithm is not supported.

##### TJWT-US11
Confirms correct at_hash generation and validation for access tokens.

##### TJWT-US12
Ensures access token hash verification fails on invalid at_hash values.

#### Notes-TJWT
- Tests JWT manipulation and verification.

### test_http_utils
### THTTP-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### THTTP-run

```bash
pytest backends/cieoidc/tests/utils/test_http.py -v
``` 
#### THTTP-Test-Coverage
##### THTTP-US01
`http_get_sync` process success

##### THTTP-US02
`http_get_sync` get 404 return `HttpError`

##### THTTP-US03
`http_get_sync` get ConnectionError return `HttpError`

##### THTTP-US04
`http_get_async` process success

##### THTTP-US05
`http_get_async` connection error return `HttpError`

##### THTTP-US06
`cacheable_get_http_url` OK

##### THTTP-US07
`cacheable_get_http_url` invalid parameters return `ValueError`

#### Notes-THTTP
- Tests synchronous and asynchronous HTTP handling.
- Tests the cacheable URL function.

### test_jwk_utils
### TJWK-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TJWK-run

```bash
pytest backends/cieoidc/tests/utils/test_jwk.py -v
``` 
#### TJWK-Test-Coverage
##### TJWK-US01
`create_jwk` generates RSA JWK with `kid`

##### TJWK-US02
`public_jwk_from_private_jwk` removes d, keeps `kid`

##### TJWK-US03
`private_pem_from_jwk` generates private PEM

##### TJWK-US04
`public_pem_from_jwk` generates public PEM

#### Notes-TJWK
- Tests RSA key creation and conversion.

### test_jwt_utils
### TJWT-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TJWT-run

```bash
pytest backends/cieoidc/tests/utils/test_jwt.py -v
``` 
#### TJWT-Test-Coverage
##### TJWT-US01
`unpad_jwt_payload` extracts JWT payload

##### TJWT-US02
`create_jws` generates JWS

##### TJWT-US03
`verify_at_hash` process success

##### TJWT-US04
`verify_at_hash` failure process return exception

##### TJWT-US05
Verifies correct base64url decoding and padding handling for JWT headers and payloads.

##### TJWT-US06
Ensures JWE creation succeeds with a valid JSON payload and RSA public key.

##### TJWT-US07
Confirms JWE creation works with a None payload.

##### TJWT-US08
Validates JWE creation with non-JSON-serializable inputs (e.g. set), ensuring graceful handling.

##### TJWT-US09
Tests successful JWE decryption using supported encryption algorithms.

##### TJWT-US10
Verifies that JWE decryption fails when the encryption algorithm is not supported.

##### TJWT-US11
Confirms correct at_hash generation and validation for access tokens.

##### TJWT-US12
Ensures access token hash verification fails on invalid at_hash values.

#### Notes-TJWT
- Tests JWT manipulation and verification.

### test_misc_utils
### TMSC-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TMSC-run

```bash
pytest backends/cieoidc/tests/utils/test_misc.py -v
``` 
#### TMSC-Test-Coverage
##### TMSC-US01
`make_timezone_aware` (success, tzinfo set)

##### TMSC-US02
`make_timezone_aware` (failure, ValueError)

##### TMSC-US03
`random_token` generates string

##### TMSC-US04
`get_pkce` generates `code_verifier` and `code_challenge`

##### TMSC-US05
`http_dict_to_redirect_uri_path` converts dictionary to query string

#### TMSC-US06
`datetime/timestamp roundtrip`
- Validates conversion between `datetime` and UNIX timestamp:
  - `timestamp_from_datetime` correctly produces integer timestamps
  - `datetime_from_timestamp` produces UTC-aware `datetime`
  - Roundtrip conversions are consistent and timezone-aware
- Covers naive and UTC-aware `datetime` objects
- Ensures no offset discrepancies due to local timezone

#### Notes-TMSC
- Tests general utility functions.
- No network or cryptography required.
- Supports OIDC flows and internal data handling.



### test_mongo_storage
### TMSTO-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TMSTO-run

```bash
pytest backends/cieoidc/tests/utils/storage/test_mongo_storage.py -v
``` 
#### TMSTO-Test-Coverage
#### TMSTO-US01
Validates that the MongoDB client initialization logic is correctly invoked by mocking pymongo.MongoClient.

#### TMSTO-US02
Ensures that the MongoDB client is properly closed and the internal client reference is reset to None.

#### TMSTO-US03
Verifies that is_connected() returns False when no MongoDB client is initialized.

#### TMSTO-US04
Checks that is_connected() returns False when the MongoDB client raises an InvalidOperation exception.

#### TMSTO-US05
Confirms that is_connected() returns True when the MongoDB client responds correctly to server_info().

#### TMSTO-US06
Validates the conversion of an entity containing a UUID string into a MongoDB document:
- UUID is converted into a BSON Binary
- id field is removed
- _id field is correctly populated

#### TMSTO-US07
Ensures that a MongoDB document containing a BSON Binary UUID is correctly converted back into a domain entity,
with the UUID restored as a string.

#### TMSTO-US08
Tests successful insertion of a document into MongoDB and verifies that a string ID is returned.

#### TMSTO-US09
Validates graceful failure handling when MongoDB raises a PyMongoError during insert operations.

#### TMSTO-US10
Ensures that update operations fail when the entity does not contain an id.

#### TMSTO-US11
Validates successful update behavior when a valid UUID is provided and at least one document is modified.

#### TMSTO-US12
Confirms correct handling of delete operations when removing a document by ObjectId.

#### TMSTO-US13
Ensures that None is returned when a document with the given ID does not exist.

#### TMSTO-US14
Tests retrieval of multiple documents matching a query filter and correct conversion into domain entities.

#### TMSTO-US15
Validates the high-level add_session wrapper method, ensuring it correctly delegates to the internal _add method.

#### TMSTO-US16
Validates the high-level update_session wrapper method and correct propagation of update results.

#### TMSTO-US17
Ensures that valid UUID strings are correctly parsed and converted into UUID objects.

#### TMSTO-US18
Validates that invalid UUID strings are safely rejected and return None.

#### Notes-TMSTO
- All MongoDB operations are fully mocked using unittest.mock.
- No real database connection is required.
- Tests focus on data conversion, error handling, and repository logic.
- This suite provides high-confidence unit coverage for the MongoDB storage abstraction layer.

### test_oidc_db_engine
### TDBE-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TDBE-run

```bash
pytest backends/cieoidc/tests/utils/storage/test_oidc_db_engine.py -v
``` 
#### TDBE-Test-Coverage
#### TDBE-US01
Validates that the `connect()` method correctly delegates the call to the underlying storage backend.

#### TDBE-US02
Ensures that the `close()` method invokes the corresponding storage backend cleanup logic.

#### TDBE-US03
Confirms that the engine correctly reflects the connection status reported by the storage backend.

#### TDBE-US04
Tests the insertion of a new OIDC authentication session:
- The session is delegated to the storage backend
- A numeric result is returned
- The entity id is generated and assigned if missing

#### TDBE-US05
Ensures that update operations are rejected when the entity does not contain an id,
returning 0 without invoking the storage backend.

#### TDBE-US06
Validates successful update behavior when the entity contains a valid UUID.

#### TDBE-US07
Tests retrieval of sessions by state, verifying correct delegation to the storage backend
and propagation of results.

#### TDBE-US08
Validates entity preprocessing before persistence:
- created timestamp is set if missing
- modified timestamp is always updated
- Both fields are valid datetime instances
- 
#### Notes-TDBE
- The storage backend is dynamically loaded and fully mocked using unittest.mock.
- No real database or external services are required.
- Tests focus on delegation logic, entity lifecycle handling, and defensive checks.
- This suite ensures correctness of the persistence orchestration layer independently from storage implementations.

### test_entity_configuration
### TEC-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TEC-run

```bash
pytest backends/cieoidc/tests/test_entity_configuration.py -v
``` 
#### TEC-Test-Coverage
#### TEC-US01
Validates that, during handler initialization:
- Private JWKS are validated
- Entity metadata is validated
- No exception is raised for a minimal valid configuration
All validation logic is mocked to isolate handler behavior.

#### TEC-US02
Tests the internal metadata generation logic:
- Ensures the correct entity type is present
- Confirms client_id propagation
- Verifies that private JWKS are converted into public JWKS
- Ensures only public key material is exposed in metadata

#### TEC-US03
Validates generation of the entity configuration as a plain JSON document:
- Returned value is JSON-serializable
- Document structure conforms to expected format

#### TEC-US04
Validates generation of the entity configuration as a JWS-signed document:
- Cryptographic signing is delegated to helper utilities
- A non-empty JWS string is returned

#### TEC-US05
Ensures that federation-specific entity configuration handling is correctly invoked
when building the final entity configuration document.

#### TEC-US06
Validates correct handling of OpenID JWKS:
- Private keys are never exposed
- Public keys are correctly derived and included
- Key identifiers `(kid)` are preserved

#### Notes-TEC
- All cryptographic operations (JWKS validation, JWS creation) are fully mocked.
- No real cryptographic signing or federation resolution is performed.
- Tests focus on correctness of metadata composition and handler orchestration.
- This suite provides high-confidence unit coverage for OpenID Federation entity configuration generation.

### test_cieoidc
### TCOB-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TCOB-run

```bash
pytest backends/cieoidc/tests/test_entity_configuration.py -v
``` 
#### TEC-Test-Coverage
#### TCOB-US01
Validates that the backend correctly extracts and stores the `client_id` from the
OpenID relying party metadata during initialization.
Covered aspects:
- Metadata parsing
- Internal 'client_id` attribute initialization

#### TCOB-US02
Ensures that `generate_trust_chains` is invoked exactly once during backend construction.
Covered aspects:
- Initialization side effects
- Trust chain bootstrap logic
The trust chain generation method is fully mocked.

#### TCOB-US03
Validates that calling `start_auth` without a registered authorization endpoint
raises a ValueError.
Covered aspects:
- Defensive checks
- Error handling when mandatory endpoints are missing

#### TCOB-US04
Tests the happy path of the `authorization` flow orchestration.
Covered aspects:
- Delegation to the authorization endpoint
- Correct propagation of the returned response
- The authorization endpoint is mocked.

#### TCOB-US05
Validates that backend endpoints are correctly registered using the
`EndpointsLoader`.
Covered aspects:
- Dynamic `endpoint` loading
- Population of the internal endpoints dictionary
All endpoint loading logic is mocked.

#### TCOB-US06
Ensures that `get_metadata_desc` correctly delegates metadata generation
to the helper function.
Covered aspects:
- Proper propagation of `client_id` and backend configuration
- Correct return value handling
The metadata helper is mocked.

#### TCOB-US07
Validates the full `_generate_trust_chain`s logic for configured providers.
Covered aspects:
- Retrieval of entity configurations
- EntityStatement instantiation
- Self-validation of trust anchor entity configuration
- Trust chain generation per provider
- Correct mapping between provider URL and generated trust chain
All federation resolution and cryptographic validation logic is mocked.

#### TCOB-US08
Validates the static `generate_trust_chain` method.
Covered aspects:
- Correct instantiation of `TrustChainBuilder`
- Invocation of:
  -  `start`
  - `apply_metadata_policy`
- Correct return of the built trust chain object
No real federation resolution is performed.

#### Notes-TCOB
- All cryptographic operations (JWKS validation, JWS creation) are fully mocked.
- No real cryptographic signing or federation resolution is performed.
- Tests focus on correctness of metadata composition and handler orchestration.
- This suite provides high-confidence unit coverage for OpenID Federation entity configuration generation.


### test_oidc
### TOIDC-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TOIDC-run

```bash
pytest backends/cieoidc/tests/client/test_oidc.py
``` 
#### TOIDC-Test-Coverage
#### TOIDC-US01
Validates successful retrieval of UserInfo when the endpoint returns plain JSON.
Covered aspects:
-HTTP GET request execution
-Authorization header generation (`Bearer <access_token>`)
-JSON response parsing
-Correct propagation of the UserInfo payload
All external calls are mocked.

#### TOIDC-US02
Validates behavior when the UserInfo endpoint responds with an HTTP error status.
Covered aspects:
- Detection of non-200 HTTP responses
- Graceful failure handling
Method returns `False` on HTTP error

#### TOIDC-US03
Validates handling of JWE + JWS protected UserInfo responses.
Covered aspects:
- Detection of non-JSON response body
- JWE header extraction via `unpad_jwt_head`
- JWE decryption
- JWS header extraction
- JWKS retrieval for signature verification
- JWS verification
- Correct extraction of the decrypted UserInfo payload
All cryptographic helpers and JWKS retrieval are fully mocked.

#### TOIDC-US04
Validates behavior when an unknown `kid` is encountered during key resolution.
Covered aspects:
- Handling of `UnknownKid` exception
- Defensive error handling
- Method returns `False` when key lookup fails

#### TOIDC-US05
Validates behavior when malformed or incomplete JWT/JWE headers are encountered.
Covered aspects:
- Handling of `KeyError` during header parsing
- Graceful failure without exception propagation
- Method returns `False`

#### Notes-TOIDC
All HTTP calls are fully mocked using `unittest.mock`.
- No real JWT verification, JWE decryption, or JWKS resolution is performed.
- Tests focus on:
  - UserInfo response format detection (JSON vs encrypted)
  - Orchestration logic
- Error handling and defensive behavior
- Intended as unit-level tests, not integration or end-to-end OIDC tests.
- This suite provides high-confidence coverage for the `OidcUserInfo` client behavior.

### test_oauth2_authorization
### TOACG-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TOACG-run

```bash
pytest backends/cieoidc/tests/client/test_oauth2_authorization.py
``` 
#### TOACG-Test-Coverage
#### TOACG-US01
Validates successful access token request using the Authorization Code grant.
Covered aspects:
- Client assertion generation (JWS creation)
- `iat` and `exp` claim generation
- Signing key resolution from core JWKS
- HTTP POST request execution to the token endpoint
- Correct handling of a 200 OK response
- JSON parsing of the access token response
All external interactions and cryptographic helpers are mocked.

#### TOACG-US02
Validates behavior when the token endpoint returns an HTTP error response.
Covered aspects:
- Detection of non-200 HTTP responses
- No JSON parsing attempt on error payload
Raw HTTP response is returned to the caller

#### TOACG-US03
Validates successful refresh token request flow.
Covered aspects:
- Client assertion generation for refresh token grant
- Retrieval of token endpoint from provider configuration
- HTTP POST request execution
Correct propagation of the HTTP response

#### TOACG-US04
Validates behavior when the token endpoint is missing from the provider configuration.
Covered aspects:
- Defensive checks on provider configuration
- No HTTP request execution
Method returns `None` when the token endpoint is not available

#### TOACG-US05
Validates internal relying party configuration retrieval.
Covered aspects:
- Invocation of the private `get_rp_conf` method
- Returned value is a dictionary
- Ensures default RP configuration structure is correctly generated

#### Notes-TOACG
- All HTTP requests are fully mocked using `unittest.mock`.
- No real JWT signing, key lookup, or OAuth2 server interaction is performed.
- Tests focus on:
  - OAuth2 Authorization Code grant orchestration
  - Client authentication via JWT assertion
- Defensive handling of misconfigurations and error responses
- Intended as unit-level tests, not integration or end-to-end OAuth2/OIDC flows.
- This suite provides high-confidence coverage for the `OAuth2AuthorizationCodeGrant` client logic.

### test_validator
### TVAL-Dependencies

Same as [Prerequisites](#Prerequisites): activate the virtual environment and install dependencies with test extras (`poetry install --extras test`). Dependencies are defined in `pyproject.toml`.

#### TVAL-run

```bash
pytest backends/cieoidc/tests/test_validator.py
``` 
#### TVAL-Test-Coverage
#### TVAL-US01
Validates successful validation of public JWKS.
Covered aspects:
- Acceptance of public RSA JWKs
- Support for both dictionary and list input formats
- No exception raised when all keys are public

#### TVAL-US02
Validates rejection of private JWKS when public keys are expected.
Covered aspects:
- Detection of private key material
- Generation of a helpful validation error message
- Defensive handling of invalid public JWKS input

#### TVAL-US03
Validates behavior when invalid JWK structures are provided.
Covered aspects:
- Exception handling during JWK parsing
- Conversion of low-level errors into `ValidationError`

#### TVAL-US04
Validates successful validation of private JWKS.
Covered aspects:
- Acceptance of private RSA JWKs
- Support for both dictionary and list input formats

#### TVAL-US05
Validates rejection of public JWKS when private keys are required.
Covered aspects:
- Detection of missing private key material
- Proper error propagation via `ValidationError`

#### TVAL-US06
Validates metadata algorithm constraints using default supported algorithms.
Covered aspects:
- Validation of signing algorithms
- Validation of encryption algorithms and encodings
- Proper handling of OpenID Provider metadata
- Rejection of unsupported algorithm values

#### TVAL-US07
Validates metadata algorithm constraints using custom supported algorithm lists (`v1`).
Covered aspects:
- Enforcement of caller-provided signing algorithms
- Enforcement of caller-provided encryption algorithms
- Rejection of unsupported algorithm values
- Backward-compatible behavior with partial metadata

#### TVAL-US08
Validates defensive behavior when OpenID Provider metadata is missing.
Covered aspects:
- Metadata is ignored if `openid_provider` is not present
- No exception is raised for unrelated entity metadata
- 
#### Notes-TVAL
- All cryptographic operations (cryptojwt, key parsing, serialization) are fully mocked.
- No real JWKS parsing, validation, or cryptographic computation is performed.
- Tests focus on:
  - Validation logic correctness
  - Defensive error handling
- Strict enforcement of supported algorithm policies
- Intended as unit-level tests, not integration or federation validation tests.
- This suite provides high-confidence unit coverage for metadata and JWKS validation helpers.