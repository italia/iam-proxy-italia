"""
Minimal OIDC Relying Party: auth code flow + PKCE (S256).
Standalone, env-configured; no idpyoidc/jwtconnect dependency.
For use with satosa-oidcop frontend (pre-registered client in MongoDB).
"""
from __future__ import annotations

from dotenv import load_dotenv, find_dotenv


dotenv_path = find_dotenv()
load_dotenv(dotenv_path)


import base64
import hashlib
import logging
import os
import secrets
from pathlib import Path
from urllib.parse import urlencode
import gettext
import httpx
import json
import jwt
from fastapi import Cookie, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from settings import settings


# Required env vars
ENV_VARS = {
    "CLIENT_ID",
    "CLIENT_SECRET",
    "WELL_KNOW_OPENID_CONFIGURATION",
    "URL_CALLBACK",
    "URL_REDIRECT",
    "SCOPE"
}

CONFIG: dict[str, str] = {k: os.environ.get(k, "") for k in ENV_VARS}
CONFIG.setdefault("DEBUG", "false")

logging.basicConfig(
    level=logging.DEBUG if CONFIG.get("DEBUG", "").lower() in ("1", "true", "yes") else logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
)
LOG = logging.getLogger("oidc_rp")

HTTPX_TIMEOUT = httpx.Timeout(15.0, read=60.0)


def _pkce_code_verifier() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def _pkce_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _load_oidc_config() -> None:
    with httpx.Client(verify=False, timeout=HTTPX_TIMEOUT) as client:
        r = client.get(CONFIG["WELL_KNOW_OPENID_CONFIGURATION"])
    if r.status_code != 200:
        raise RuntimeError(f"OIDC discovery failed: {r.status_code}")
    data = r.json()
    CONFIG["url_auth"] = data.get("authorization_endpoint", "")
    CONFIG["url_token"] = data.get("token_endpoint", "")
    CONFIG["url_revoke"] = data.get("revocation_endpoint", "")
    CONFIG["url_userinfo"] = data.get("userinfo_endpoint", "")
    LOG.info("OIDC config loaded from %s", CONFIG["WELL_KNOW_OPENID_CONFIGURATION"])


_load_oidc_config()

app = FastAPI(title="OIDC RP (auth code + PKCE)")

# JINJA2
templates = Jinja2Templates(directory="templates")
templates.env.add_extension("jinja2.ext.i18n")
translations = gettext.translation(
    "messages",
    localedir="i18n",
    languages=["it"],
    fallback=True
)
templates.env.install_gettext_translations(translations)
# END JINJA2
# Resolve static dir relative to this file so it works regardless of CWD (e.g. in Docker)
_STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


def render_template(template_name: str, request: Request, context: dict = {}):
    context.update({"request": request, "settings": settings})
    return templates.TemplateResponse(template_name, context)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    id_token = request.cookies.get("id_token")
    logging.info(f"Entering method: index.")
    access_token = request.cookies.get("access_token")
    user = None
    if access_token:
        if CONFIG["url_userinfo"]:
            async with httpx.AsyncClient(headers={"Authorization": f"Bearer {access_token}"},
                                         verify=False,
                                         timeout=HTTPX_TIMEOUT, ) as userinfo_client:
                response = await userinfo_client.post(CONFIG["url_userinfo"])
        if response.status_code != 200:
            LOG.error("url_userinfo error: %s %s", response.status_code, response.text)
            raise HTTPException(502, f"url_userinfo failed: {response.status_code}")
        user = response.json()
        return render_template("echo_attributes.html", request=request, context={"id_token": id_token, "user": user})

    return render_template("base.html", request=request, context={"id_token": id_token, "user": user})



@app.get("/login")
async def login():
    logging.info(f"Enterin method: login.")
    state = secrets.token_urlsafe(32)
    code_verifier = _pkce_code_verifier()
    code_challenge = _pkce_code_challenge(code_verifier)
    params = {
        "client_id": CONFIG["CLIENT_ID"],
        "response_type": "code",
        "redirect_uri": CONFIG["URL_CALLBACK"],
        "scope": CONFIG["SCOPE"],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "consent"
    }
    url = CONFIG["url_auth"] + ("&" if "?" in CONFIG["url_auth"] else "?") + urlencode(params)
    resp = RedirectResponse(url)
    resp.set_cookie("oidc_state", state, max_age=300, httponly=True, secure=True)
    resp.set_cookie("oidc_code_verifier", code_verifier, max_age=300, httponly=True, secure=True)
    return resp


async def _handle_callback(
    state: str,
    code: str,
    oidc_state: str,
    oidc_code_verifier: str,
):
    logging.info(f"Enterin method: _handle_callback. "
                 f"Params [state: {state}, code: {code}, oidc_state:{oidc_state}, oidc_code_verifier:{oidc_code_verifier} ]")

    if not oidc_state or not secrets.compare_digest(oidc_state, state):
        raise HTTPException(403, "state mismatch")
    if not code:
        raise HTTPException(400, "missing code")
    if not oidc_code_verifier:
        raise HTTPException(400, "missing code_verifier (session expired?)")

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CONFIG["URL_CALLBACK"],
        "code_verifier": oidc_code_verifier,
    }
    auth = httpx.BasicAuth(CONFIG["CLIENT_ID"], CONFIG["CLIENT_SECRET"])

    async with httpx.AsyncClient(auth=auth, verify=False, timeout=HTTPX_TIMEOUT) as client:
        r = await client.post(CONFIG["url_token"], data=data)
    if r.status_code != 200:
        LOG.error("token error: %s %s", r.status_code, r.text)
        raise HTTPException(502, f"token exchange failed: {r.status_code}")

    body = r.json()
    id_token = body.get("id_token", "")
    access_token = body.get("access_token", "")

    if not CONFIG.get("URL_REDIRECT"):
        return JSONResponse({"id_token": id_token, "access_token": access_token})

    resp = RedirectResponse(CONFIG["URL_REDIRECT"])
    for key, val, max_age in (
        ("id_token", id_token, 3600),
        ("access_token", access_token, 3600),
        ("logged_in", "true", 3600),
    ):
        resp.set_cookie(key, val, max_age=max_age, httponly=(key != "logged_in"), secure=True)
    resp.delete_cookie("oidc_state")
    resp.delete_cookie("oidc_code_verifier")
    return resp


@app.get("/callback")
@app.get("/authz_cb/satosa")
async def callback(
    state: str = "",
    code: str = "",
    oidc_state: str = Cookie(""),
    oidc_code_verifier: str = Cookie(""),
):
    logging.info(f"Entering method: callback. "
                 f"Params [state: {state}, code: {code}, oidc_state:{oidc_state}, oidc_code_verifier:{oidc_code_verifier} ]")
    return await _handle_callback(state, code, oidc_state, oidc_code_verifier)




@app.get("/token")
async def token(id_token: str = Cookie(""), access_token: str = Cookie("")):
    logging.info(f"Enterin method: token. "
                 f"Params [id_token: {id_token}, access_token: {access_token}]")
    return JSONResponse({"id_token": id_token, "access_token": access_token})


@app.get("/userinfo")
async def userinfo(access_token: str = Cookie("")):
    logging.info(f"Enterin method: token. "
                 f"Params [access_token: {access_token}]")


    logging.info(f"CONFIG[url_userinfo]: {CONFIG["url_userinfo"]}]")
    if not access_token:
        raise HTTPException(401, "not logged in")
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {access_token}"},
        verify=False,
        timeout=HTTPX_TIMEOUT,
    ) as client:
        r = await client.get(CONFIG["url_userinfo"])
    if r.status_code != 200:
        raise HTTPException(502, f"userinfo failed: {r.status_code}")
    return r.json()


@app.get("/logout")
async def logout(
    id_token: str = Cookie(""),
    access_token: str = Cookie(""),
):
    logging.info(f"Enterin method: token. "
                 f"Params [id_token: {access_token}, access_token: {access_token}]")
    if CONFIG.get("url_revoke"):
        auth = httpx.BasicAuth(CONFIG["CLIENT_ID"], CONFIG["CLIENT_SECRET"])
        async with httpx.AsyncClient(auth=auth, verify=False, timeout=HTTPX_TIMEOUT) as client:
            for t in (id_token, access_token):
                if t:
                    await client.post(
                        CONFIG["url_revoke"],
                        data={"token": t, "token_type_hint": "access_token" if "ey" in t else "id_token"},
                    )
    resp = RedirectResponse(CONFIG.get("URL_REDIRECT", "/"))
    for key in ("id_token", "access_token", "logged_in"):
        resp.delete_cookie(key)
    return resp


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8090"))
    uvicorn.run(app, host="0.0.0.0", port=port)
