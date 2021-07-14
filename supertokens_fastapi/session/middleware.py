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
from typing import Union
from supertokens_fastapi.utils import normalise_http_method
from .session_class import Session
from .session_recipe import SessionRecipe
from fastapi.requests import Request
from supertokens_fastapi.normalised_url_path import NormalisedURLPath


def verify_session(recipe: SessionRecipe, anti_csrf_check: Union[bool, None] = None, session_required: bool = True):
    async def func(request: Request) -> Union[Session, None]:
        method = normalise_http_method(request.method)
        if method == 'options' or method == 'trace':
            return None
        incoming_path = NormalisedURLPath(recipe, request.url.path)
        refresh_token_path = recipe.config.refresh_token_path
        if incoming_path.equals(refresh_token_path) and method == 'post':
            request.state.supertokens = await recipe.refresh_session(request)
        else:
            request.state.supertokens = await recipe.get_session(request, anti_csrf_check, session_required)
        return request.state.supertokens

    return func


async def supertokens_session(request: Request):
    enable_anti_csrf_check = request.method != "GET"
    return await __supertokens_session(request, enable_anti_csrf_check)


async def supertokens_session_with_anti_csrf(request: Request):
    return await __supertokens_session(request, True)


async def supertokens_session_without_anti_csrf(request: Request):
    return await __supertokens_session(request, False)


async def __supertokens_session(request: Request, anti_csrf_check: bool) -> Union[Session, None]:
    recipe = SessionRecipe.get_instance()
    method = normalise_http_method(request.method)
    if method == 'options' or method == 'trace':
        return None
    incoming_path = NormalisedURLPath(recipe, request.url.path)
    refresh_token_path = recipe.config.refresh_token_path
    if incoming_path.equals(refresh_token_path) and method == 'post':
        request.state.supertokens = await recipe.refresh_session(request)
    else:
        request.state.supertokens = await recipe.get_session(request, anti_csrf_check, True)
    return request.state.supertokens
