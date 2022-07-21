import base64
import hashlib
import secrets
import jwt
import os
import requests
from fastapi import FastAPI, HTTPException
from fastapi_oidc import OktaIDToken
from fastapi_oidc import get_auth
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OpenIdConnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi import status
from jwt import decode

from okta.client import Client

import uvicorn

app = FastAPI()

app.mount('/static', StaticFiles(directory='templates'))

templates = Jinja2Templates(directory='templates')


fake_session = {}

config = {
    "auth_uri": os.environ['AUTH_URI'],
    "client_id": os.environ['CLIENT_ID'],
    "client_secret": os.environ['CLIENT_SECRET'],
    "redirect_uri": os.environ['REDIRECT_URI'],
    "issuer": os.environ['ISSUER'],
    "token_uri": os.environ['TOKEN_URI'],
    "userinfo_uri": os.environ['USERINFO_URI']
}

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl=config["token_uri"])


@app.get('/', response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse('homepage.html', {'request': request})


@app.get('/login')
async def login(request: Request):
    # store app state and code verifier in session
    fake_session['code_verifier'] = secrets.token_urlsafe(64)
    fake_session['app_state'] = secrets.token_urlsafe(64)

    # calculate code challenge
    hashed = hashlib.sha256(
        fake_session['code_verifier'].encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode('ascii').strip('=')

    # get request params
    query_params = {
        'client_id': config["client_id"],
        'redirect_uri': config["redirect_uri"],
        'scope': "openid email profile",
        'state': fake_session['app_state'],
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'response_type': 'code',
        'response_mode': 'query'
    }

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=requests.compat.urlencode(query_params)
    )

    return RedirectResponse(url=request_uri)


@app.get('/oidc/callback/')
async def callback(request: Request, code: str = None, state: str = None):
    # check app state
    if not state or state != fake_session['app_state']:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid state")
    # check code
    if not code:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid code")
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    query_params = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': request.url._url.split('?')[0][:-1],
        'code_verifier': fake_session['code_verifier'],
    }
    # print(query_params)
    query_params = requests.compat.urlencode(query_params)

    # Get token
    token_response = requests.post(
        url=config['token_uri'],
        headers=headers,
        data=query_params,
        auth=(config['client_id'], config['client_secret'])
    ).json()

    # print(token_response)

    if not token_response.get('token_type'):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Invalid token_type')

    access_token = token_response['access_token']
    id_token = token_response['id_token']
    print(id_token)
    print(decode(id_token, options={"verify_signature": False}))

    # If the function reached here it means that the user authentication from okta is successful.
    # Collect the user data and proceed with login or register
    headers = {'Authorization': f'Bearer {access_token}'}
    userinfo_response = requests.get(
        url=config['userinfo_uri'], headers=headers).json()

    unique_id = userinfo_response['sub']
    user_email = userinfo_response['email']
    user_name = userinfo_response['given_name']

    return 'Success'


@app.get('/logout')
async def logout():
    fake_session.clear()
    return {'message': 'Logged Out'}


# app = CORSMiddleware(app=app, allow_origins=['http://localhost:8080'], allow_credentials=True, allow_headers=['*'], allow_methods=['*'])


if __name__ == "__main__":
    uvicorn.run(app="main:app", reload=True)
