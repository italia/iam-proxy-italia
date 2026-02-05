
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

### Prerequisites

All runtime dependencies are defined in `pyproject.toml`. Test-related tools (pytest, pytest-cov, flake8, spid-sp-test) are in the optional dependency group `test`, aligned with the [GitHub Actions workflows](.github/workflows/lint.yml) (lint) and [docker-compose-test.yml](.github/workflows/docker-compose-test.yml) (integration tests).

From the project root, install dependencies with Poetry (recommended, same as [README-Setup.md](README-Setup.md)):

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

Validates request.
An exception is expected.

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
