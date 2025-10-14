




from backends.cieoidc.storage.entities.oidc_auth import OidcAuthentication
from backends.cieoidc.storage.mongo_db.connection import MongoConnection
from backends.cieoidc.storage.mongo_db.repository import MongoBaseRepository



if __name__ == "__main__":

    conn=MongoConnection("mongodb://satosa:thatpassword@localhost:27017/")
    repo = MongoBaseRepository(conn, "iam", "testiamo", OidcAuthentication)
    oid= OidcAuthentication(
                            id="2",
                            name="state",
                            client_id ="endpoint",
                            state= "data",
                            endpoint="False",
                            data = "provider_id",
                            successful=False,
                            provider_id =       "created",

        provider_configuration=       {},
        created=       "",
        modified=       ""
    )
    repo.add(oid)

    p=repo.find_all({})
    ...