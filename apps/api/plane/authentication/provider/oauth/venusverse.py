# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse
import pytz
import requests

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)


class VenusVerseOAuthProvider(OauthAdapter):
    """Generic OIDC provider for the VenusVerse SSO.

    Based on the Gitea adapter, with two differences: standard OIDC endpoint
    paths (/oauth/*) and PKCE S256, which VenusVerse requires for all clients.
    """

    provider = "venusverse"
    scope = "openid profile email"

    def __init__(self, request, code=None, state=None, callback=None):
        (VENUS_CLIENT_ID, VENUS_CLIENT_SECRET, VENUS_HOST) = get_configuration_value(
            [
                {
                    "key": "VENUS_CLIENT_ID",
                    "default": os.environ.get("VENUS_CLIENT_ID"),
                },
                {
                    "key": "VENUS_CLIENT_SECRET",
                    "default": os.environ.get("VENUS_CLIENT_SECRET"),
                },
                {
                    "key": "VENUS_HOST",
                    "default": os.environ.get("VENUS_HOST"),
                },
            ]
        )

        if not (VENUS_CLIENT_ID and VENUS_CLIENT_SECRET and VENUS_HOST):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["VENUSVERSE_NOT_CONFIGURED"],
                error_message="VENUSVERSE_NOT_CONFIGURED",
            )

        # Enforce scheme and normalize trailing slash(es)
        parsed = urlparse(VENUS_HOST)
        if not parsed.scheme or parsed.scheme not in ("https", "http"):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["VENUSVERSE_NOT_CONFIGURED"],
                error_message="VENUSVERSE_NOT_CONFIGURED",
            )
        VENUS_HOST = VENUS_HOST.rstrip("/")

        # Set URLs based on the host (standard OIDC paths)
        self.token_url = f"{VENUS_HOST}/oauth/token"
        self.userinfo_url = f"{VENUS_HOST}/oauth/userinfo"
        self.authorize_url = f"{VENUS_HOST}/oauth/authorize"

        client_id = VENUS_CLIENT_ID
        client_secret = VENUS_CLIENT_SECRET

        redirect_uri = f"{'https' if request.is_secure() else 'http'}://{request.get_host()}/auth/venusverse/callback/"

        # PKCE S256 — VenusVerse SSO requires it for every client. The verifier
        # survives the round-trip in the session and is sent on token exchange.
        code_verifier = request.session.get("venus_pkce_verifier") or secrets.token_urlsafe(64)
        request.session["venus_pkce_verifier"] = code_verifier
        code_challenge = self._s256(code_verifier)

        url_params = {
            "client_id": client_id,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = f"{self.authorize_url}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            client_secret,
            code,
            callback=callback,
        )

    @staticmethod
    def _s256(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def set_token_data(self):
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": self.request.session.pop("venus_pkce_verifier", None),
        }
        headers = {"Accept": "application/json"}
        token_response = self.get_user_token(data=data, headers=headers)
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("expires_in"))
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": (
                    datetime.fromtimestamp(token_response.get("refresh_token_expired_at"), tz=pytz.utc)
                    if token_response.get("refresh_token_expired_at")
                    else None
                ),
                "id_token": token_response.get("id_token", ""),
            }
        )

    def set_user_data(self):
        user_info_response = self.get_user_response()

        # The SSO userinfo endpoint returns verified claims directly; still
        # reject explicitly-unverified emails rather than trusting the flag.
        email = user_info_response.get("email")
        if not email or user_info_response.get("email_verified") is False:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OAUTH_PROVIDER_UNVERIFIED_EMAIL"],
                error_message="OAUTH_PROVIDER_UNVERIFIED_EMAIL",
            )

        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": str(user_info_response.get("sub")),
                    "email": email,
                    "avatar": user_info_response.get("picture"),
                    "first_name": user_info_response.get("name"),
                    "last_name": "",
                    "is_password_autoset": True,
                },
            }
        )
