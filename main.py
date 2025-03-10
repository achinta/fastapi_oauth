from typing import Annotated, Union
from fastapi import FastAPI, Request, Header, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
import secrets
import hashlib
import base64
from uuid import uuid4
from urllib.parse import urlencode
import httpx
import os
import jwt

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="your-secret-key-here")

templates = Jinja2Templates(directory="templates")

# OAuth2 helper functions
def generate_code_verifier() -> str:
    return secrets.token_urlsafe(32)

def generate_code_challenge(code_verifier: str) -> str:
    sha256 = hashlib.sha256(code_verifier.encode()).digest()
    b64 = base64.urlsafe_b64encode(sha256).decode().rstrip("=")
    return b64

# Authentication dependency
def get_current_user(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

class Todo(BaseModel):
    title: str

todos = [Todo(title="Buy groceries")]

# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"user": user},
    )

@app.get("/login")
async def login(request: Request):
    auth_url = os.getenv("AUTH_URL")
    if not auth_url:
        raise HTTPException(status_code=500, detail="AUTH_URL is not set")
    redirect_uri = os.getenv("REDIRECT_URI")
    if not redirect_uri:
        raise HTTPException(status_code=500, detail="REDIRECT_URI is not set")
    client_id = os.getenv("CLIENT_ID")
    if not client_id:
        raise HTTPException(status_code=500, detail="CLIENT_ID is not set")

    state = str(uuid4())
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    request.session["state"] = state
    request.session["code_verifier"] = code_verifier
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
    }
    redirect_url = f"{auth_url}?{urlencode(params)}"
    return RedirectResponse(redirect_url)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str, state: str):
    if state != request.session.get("state"):
        raise HTTPException(status_code=400, detail="State mismatch")
    code_verifier = request.session.get("code_verifier")
    token_url = os.getenv("TOKEN_URL")
    if not token_url:
        raise HTTPException(status_code=500, detail="TOKEN_URL is not set")
    redirect_uri = os.getenv("REDIRECT_URI")
    if not redirect_uri:
        raise HTTPException(status_code=500, detail="REDIRECT_URI is not set")
    client_id = os.getenv("CLIENT_ID")
    if not client_id:
        raise HTTPException(status_code=500, detail="CLIENT_ID is not set")
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to obtain access token")
        token_data = response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token in response")

        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        request.session["user"] = decoded_token
    return RedirectResponse(url="/", headers={"HX-Redirect": "/"})

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")