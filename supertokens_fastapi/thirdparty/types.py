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
from typing import Callable, Union, List, Dict
from fastapi.requests import Request

type_string = {
    'type': 'string'
}

type_boolean = {
    'type': 'boolean'
}

type_number = {
    'type': 'number'
}

type_any = {}

SESSION_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'set_jwt_payload': type_any,
        'set_session_data': type_any
    },
    'additionalProperties': False
}

SIGN_IN_AND_UP_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'handle_post_sign_up_in': type_any,
        'providers': {
            'type': 'array'
        }
    },
    'required': ['providers'],
    'additionalProperties': False
}

SIGN_OUT_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean
    },
    'additionalProperties': False
}

EMAIL_VERIFICATION_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'get_email_verification_url': type_any,
        'create_and_send_custom_email': type_any,
        'handle_post_email_verification': type_any
    },
    'additionalProperties': False
}

INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'session_feature': SESSION_FEATURE_INPUT_SCHEMA,
        'sign_in_and_up_feature': SIGN_IN_AND_UP_FEATURE_INPUT_SCHEMA,
        'sign_out_feature': SIGN_OUT_FEATURE_INPUT_SCHEMA,
        'email_verification_feature': EMAIL_VERIFICATION_FEATURE_INPUT_SCHEMA
    },
    'additionalProperties': False
}


class ThirdPartyInfo:
    def __init__(self, third_party_user_id: str, third_party_id: str):
        self.user_id = third_party_user_id
        self.id = third_party_id


class User:
    def __init__(self, user_id: str, email: str, time_joined: int, third_party_info: ThirdPartyInfo):
        self.user_id = user_id
        self.email = email
        self.time_joined = time_joined
        self.third_party_info = third_party_info


class UserInfoEmail:
    def __init__(self, email: str, email_verified: bool):
        self.id = email
        self.is_verified = email_verified


class UserInfo:
    def __init__(self, user_id: str, email: Union[UserInfoEmail, None] = None):
        self.user_id = user_id
        self.email = email


class AccessTokenAPI:
    def __init__(self, url: str, params: Dict[str, str]):
        self.url = url
        self.params = params


class AuthorisationRedirectAPI:
    def __init__(self, url: str, params: Dict[str, Union[str, Callable[[Request], str]]]):
        self.url = url
        self.params = params


class SignInUpResponse:
    def __init__(self, user: User, is_new_user: bool):
        self.user = user
        self.is_new_user = is_new_user


class UsersResponse:
    def __init__(self, users: List[User], next_pagination_token: Union[str, None]):
        self.users = users
        self.next_pagination_token = next_pagination_token
