
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

### Prerequisites

Each unit test requires the installation of specific dependencies.
Below, each unit test will be described along with the dependencies that need to be installed.
It is recommended to remove the related environment every time a test is completed.

Pytest is required:
 ````
pip install pytest
 ````
### test_venv

Install virtual environment support:
````
 sudo apt install python3.12-venv
 ````
Create the virtual environment, for example test_venv:
````
 python3.12 -m venv test_venv
 ````
Activate it:
````
 source test_venv/bin/activate
````
All dependencies must be installed inside this environment.
It is recommended to recreate the environment for each test session to avoid conflicts.
 

### test_callback_handler

This test suite validates the authorization callback endpoint logic, simulating a full OIDC callback flow.
The endpoint behavior is tested by mocking all external dependencies (JWKS retrieval, JWT verification, token exchange, and 
userinfo retrieval).

#### Dependencies
Activate the virtual environment, then install:
````
pip install git+https://github.com/peppelinux/SATOSA@pplnx-v8.5.2
````
````
pip install pydantic aiohttp cryptography
````
````
pip install git+https://github.com/italia/eudi-wallet-it-python
````
```` 
pip install pymongo==4.10.1
````
#### TCH-run
run:
```` 
pytest backends/cieoidc/tests/test_callback_handler.py -v
```` 

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

#### Notes-TCH

- This test simulates an OIDC authorization callback flow.
- Cryptographic validation and HTTP calls are mocked.
- The test validates endpoint orchestration rather than cryptographic correctness.
- Intended as an integration-style unit test.


### test_authorization_handler
#### TAH-Dependencies
Activate the virtual environment, then install:
````
pip install git+https://github.com/peppelinux/SATOSA@pplnx-v8.5.2
````
````
pip install pydantic aiohttp cryptography
````
````
pip install git+https://github.com/italia/eudi-wallet-it-python
````
```` 
pip install pymongo==4.10.1
````
#### TAH-run
run:
```` 
pytest backends/cieoidc/tests/test_authorization_handler.py -v
```` 
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
