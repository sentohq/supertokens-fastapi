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
from typing import Union, List
from supertokens_fastapi.emailpassword.types import FormField

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

SIGN_UP_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'form_fields': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'id': type_string,
                    'validate': type_any,
                    'optional': type_boolean
                },
                'required': ['id'],
                'additionalProperties': False
            }
        },
        'handle_post_sign_up': type_any
    },
    'additionalProperties': False
}

SIGN_IN_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'handle_post_sign_in': type_any
    },
    'additionalProperties': False
}

SIGN_OUT_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean
    },
    'additionalProperties': False
}

RESET_PASSWORD_USING_TOKEN_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'get_reset_password_url': type_any,
        'create_and_send_custom_email': type_any
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

PROVIDERS_INPUT_SCHEMA = {
    'type': 'array'
}

INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'session_feature': SESSION_FEATURE_INPUT_SCHEMA,
        'sign_up_feature': SIGN_UP_FEATURE_INPUT_SCHEMA,
        'sign_in_feature': SIGN_IN_FEATURE_INPUT_SCHEMA,
        'sign_out_feature': SIGN_OUT_FEATURE_INPUT_SCHEMA,
        'reset_password_using_token_feature': RESET_PASSWORD_USING_TOKEN_FEATURE_INPUT_SCHEMA,
        'email_verification_feature': EMAIL_VERIFICATION_FEATURE_INPUT_SCHEMA,
        'providers': PROVIDERS_INPUT_SCHEMA
    },
    'additionalProperties': False
}


class ThirdPartyInfo:
    def __init__(self, third_party_user_id: str, third_party_id: str):
        self.user_id = third_party_user_id
        self.id = third_party_id


class User:
    def __init__(self, user_id: str, email: str, time_joined: int, third_party_info: Union[ThirdPartyInfo, None] = None):
        self.user_id = user_id
        self.email = email
        self.time_joined = time_joined
        self.third_party_info = third_party_info


class SignInUpResponse:
    def __init__(self, user: User, is_new_user: bool):
        self.user = user
        self.is_new_user = is_new_user


class UsersResponse:
    def __init__(self, users: List[User], next_pagination_token: Union[str, None]):
        self.users = users
        self.next_pagination_token = next_pagination_token


class EmailPasswordSignInContext:
    def __init__(self):
        pass


class EmailPasswordSignUpContext:
    def __init__(self, form_fields: List[FormField]):
        self.form_fields = form_fields


class EmailPasswordSessionDataAndJWTContext:
    def __init__(self, form_fields: List[FormField]):
        self.form_fields = form_fields


class ThirdPartyContext:
    def __init__(self, third_party_auth_code_response: any):
        self.third_party_auth_code_response = third_party_auth_code_response


class NextPaginationToken:
    def __init__(self, third_party_pagination_token: Union[str, None], email_password_pagination_token: Union[str, None]):
        self.third_party_pagination_token = third_party_pagination_token
        self.email_password_pagination_token = email_password_pagination_token
