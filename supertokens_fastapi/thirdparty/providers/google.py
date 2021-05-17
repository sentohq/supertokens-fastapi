"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from __future__ import annotations
from supertokens_fastapi.thirdparty.provider import Provider
from typing import List, Union, Dict, Callable, TYPE_CHECKING
from supertokens_fastapi.thirdparty.types import UserInfo, AccessTokenAPI, AuthorisationRedirectAPI, UserInfoEmail
from httpx import AsyncClient
if TYPE_CHECKING:
    from fastapi.requests import Request


class Google(Provider):
    def __init__(self, client_id: str, client_secret: str, scope: List[str] = None, authorisation_redirect: Dict[str, Union[str, Callable[[Request], str]]] = None):
        super().__init__('google')
        if scope is None:
            scope = []
        self.client_id = client_id
        self.client_secret = client_secret
        default_scopes = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
        self.scopes = list(set(default_scopes + scope))
        self.access_token_api_url = 'https://accounts.google.com/o/oauth2/token'
        self.authorisation_redirect_url = 'https://accounts.google.com/o/oauth2/v2/auth'
        self.authorisation_redirect_params = {}
        if authorisation_redirect is not None:
            self.authorisation_redirect_params = authorisation_redirect

    async def get_profile_info(self, auth_code_response: any) -> UserInfo:
        access_token: str = auth_code_response['access_token']
        params = {
            'alt': 'json'
        }
        headers = {
            'Authorization': 'Bearer ' + access_token
        }
        async with AsyncClient() as client:
            response = await client.get(url='https://www.googleapis.com/oauth2/v1/userinfo', params=params, headers=headers)
            user_info = response.json()
            user_id = user_info['id']
            if 'email' not in user_info or user_info['email'] is None:
                return UserInfo(user_id)
            is_email_verified = user_info['verified_email'] if 'verified_email' in user_info else False
            return UserInfo(user_id, UserInfoEmail(user_info['email'], is_email_verified))

    def get_authorisation_redirect_api_info(self) -> AuthorisationRedirectAPI:
        params = {
            'scope': ' '.join(self.scopes),
            'response_type': 'code',
            'client_id': self.client_id,
            'access_type': 'offline',
            'include_granted_scopes': 'true',
            **self.authorisation_redirect_params
        }
        return AuthorisationRedirectAPI(self.authorisation_redirect_url, params)

    def get_access_token_api_info(self, redirect_uri: str, auth_code_from_request: str) -> AccessTokenAPI:
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': auth_code_from_request,
            'redirect_uri': redirect_uri
        }
        return AccessTokenAPI(self.access_token_api_url, params)
