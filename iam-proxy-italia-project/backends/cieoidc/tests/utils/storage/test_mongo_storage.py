import uuid
import pytest
import os
from backends.cieoidc.tests import settings_test
from unittest.mock import MagicMock, patch
from bson.binary import Binary
from bson import ObjectId
from pymongo.errors import PyMongoError, InvalidOperation

from backends.cieoidc.storage.impl.mongo_storage import MongoStorage
from backends.cieoidc.models.oidc_auth import OidcAuthentication


@pytest.fixture
def mongo_conf():
    return {
        "url": settings_test.MONGO_URL,
        "data_ttl": 3600
    }

@pytest.fixture
def storage(mongo_conf):
    return MongoStorage(mongo_conf, mongo_conf["url"])


def test_us01(storage):
    with patch("pymongo.MongoClient") as client_mock:
        assert client_mock


def test_us02(storage):
    storage._MongoStorage__client = MagicMock()
    storage.close()
    assert storage._MongoStorage__client is None


def test_us03(storage):
    assert storage.is_connected() is False


def test_us04(storage):
    storage._MongoStorage__client = MagicMock()
    storage._MongoStorage__client.server_info.side_effect = InvalidOperation
    assert storage.is_connected() is False


def test_us05(storage):
    storage._MongoStorage__client = MagicMock()
    storage._MongoStorage__client.server_info.return_value = {}
    assert storage.is_connected() is True


def test_us06(storage):
    uid = str(uuid.uuid4())
    entity = MagicMock()
    entity.model_dump.return_value = {"id": uid, "state": "x"}

    doc = storage._to_doc(entity)
    assert "_id" in doc
    assert isinstance(doc["_id"], Binary)
    assert "id" not in doc


def test_us07(storage):
    uid = uuid.uuid4()
    doc = {"_id": Binary.from_uuid(uid), "state": "x", "client_id": "client", "endpoint": "auth","data": "{}","provider_configuration": {}}

    entity = storage._from_doc(doc, OidcAuthentication)
    assert entity.id == str(uid)


def test_us08(storage):
    storage._MongoStorage__client = MagicMock()
    storage._MongoStorage__client["testdb"]["auth"].insert_one.return_value.inserted_id = ObjectId()

    entity = MagicMock()
    entity.model_dump.return_value = {}

    res = storage._add("auth", entity)
    assert isinstance(res, str)


def test_us09(storage):
    storage._MongoStorage__client = MagicMock()
    storage._MongoStorage__client["testdb"]["auth"].insert_one.side_effect = PyMongoError()

    entity = MagicMock()
    entity.model_dump.return_value = {}

    assert storage._add("auth", entity) is None


def test_us10(storage):
    entity = MagicMock()
    entity.id = None
    assert storage._update("auth", entity) is False


def test_us11(storage):
    storage._MongoStorage__client = MagicMock()
    storage._MongoStorage__client["testdb"]["auth"].update_one.return_value.modified_count = 1

    entity = MagicMock()
    entity.id = str(uuid.uuid4())
    entity.model_dump.return_value = {"id": entity.id, "state": "x"}

    assert storage._update("auth", entity) is True


def test_us12(storage):
    storage._MongoStorage__client = MagicMock()
    storage._MongoStorage__client["testdb"]["auth"].delete_one.return_value.deleted_count = 1
    assert True


def test_us13(storage):
    storage._MongoStorage__client = MagicMock()
    storage._MongoStorage__client["testdb"]["auth"].find_one.return_value = None

    assert storage._find_by_id("auth", str(ObjectId()), OidcAuthentication) is None


def test_us14(storage):
    storage._MongoStorage__client = MagicMock()
    uid = uuid.uuid4()
    storage._MongoStorage__client["testdb"]["auth"].find.return_value = [
        {"_id": Binary.from_uuid(uid), "state": "x", "client_id": "client", "endpoint": "auth","data": "{}","provider_configuration": {}}
    ]

    res = storage._find_all("auth", {"state": "x"}, OidcAuthentication)
    assert len(res) == 1


def test_us15(storage):
    storage._add = MagicMock(return_value="id")
    assert storage.add_session(MagicMock()) == 1


def test_us16(storage):
    storage._update = MagicMock(return_value=True)
    assert storage.update_session(MagicMock()) == 1


def test_us17(storage):
    storage._find_all = MagicMock(return_value=["s1"])
    assert storage.get_sessions("state") == ["s1"]


def test_us18(storage):
    uid = str(uuid.uuid4())
    assert storage._to_uuid(uid) is not None


def test_us19(storage):
    assert storage._to_uuid("not-a-uuid") is None

def test_connect_and_close(storage):
    storage._MongoStorage__client = None
    with patch("backends.cieoidc.storage.impl.mongo_storage.MongoClient") as mock_client:
        storage.connect()
        assert storage._MongoStorage__client == mock_client.return_value
        storage.close()
        assert storage._MongoStorage__client is None

def test_is_connected(storage):
    storage._MongoStorage__client = MagicMock()
    storage._MongoStorage__client.server_info.return_value = {}
    assert storage.is_connected() is True

    storage._MongoStorage__client.server_info.side_effect = InvalidOperation
    assert storage.is_connected() is False

def test_to_uuid_valid(storage):
    uid = str(uuid.uuid4())
    assert storage._to_uuid(uid) == uuid.UUID(uid)


def test_update_no_id(storage):
    entity = OidcAuthentication(state="s1", client_id="c1", code="code1", data="{}", provider_id="p1",endpoint="http://example.org",
    provider_configuration={"config": "dummy"})
    assert storage._update("auth", entity) is False

def test_remove_invalid_id(storage):
    assert storage._remove("auth", 123) is False  # non string

def test_find_by_id_invalid(storage):
    assert storage._find_by_id("auth", 123, OidcAuthentication) is None

