
## TEST

The following document is intended to guide the use of the various tests included 
in the "iam-proxy-italia" project.

## Table of Contents

1. [Prerequisites](#Prerequisites)
2. [Virtual Environment](#test_venv)
3. [TEST_CALLBACK_HANDLER](#test_callback_handler)
   1. [Dependencies](#Dependencies)
   2. [RUN](#run)
4. [TEST_AUTHORIZATION_HANDLER](#test_authorization_handler)
   1. [Dependencies](#TAH-Dependencies)
   2. [RUN](#TAH-run)
   3. [US01](#TAH-US01)
   4. [US02](#TAH-US02)

### Prerequisites

Each unit test requires the installation of specific dependencies.
Below, each unit test will be described along with the dependencies that need to be installed.
It is recommended to remove the related environment every time a test is completed.

To run the following tests, pytest is required:
 ````
pip install pytest
 ````
### test_venv

We need to install the virtual environment, as follows:
````
 sudo apt install python3.12-venv
 ````
Create our test_venv:
````
 python3.12 -m venv test_env
 ````
Activate the environment:
````
 source test_env/bin/activate
````
Inside it, we will install the required dependencies for each reference class.
This is delegated to the class under test.
 

### test_callback_handler
#### Dependencies
To test the following class, we need to install the dependencies listed below.
After activating our virtual environment ([test_venv]), install the following packages:
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
#### run
To execute the test cases, run the following command:
```` 
pytest backends/cieoidc/tests/test_callback_handler.py -v
```` 

### test_authorization_handler
#### TAH-Dependencies
To test the following class, we need to install the dependencies listed below.
After activating our virtual environment ([test_venv]), install the following packages:
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
To execute the test cases, run the following command:
```` 
pytest backends/cieoidc/tests/test_authorization_handler.py -v
```` 

#### TAH-US01
This use case, US01, is used to test the validate_configs method. We expect a successful result.

#### TAH-US02
This use case (US02) is used to test a missing field in the validate_configs method. We expect an exception to be raised.
