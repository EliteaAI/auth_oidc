#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Route """

import urllib
import datetime

import requests  # pylint: disable=E0401
import flask  # pylint: disable=E0401
import jwt  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611
from pylon.core.tools import web  # pylint: disable=E0611,E0401

from tools import auth_core  # pylint: disable=E0401


class Route:  # pylint: disable=E1101,R0903
    """
        Route Resource

        self is pointing to current Module instance

        By default routes are prefixed with module name
        Example:
        - pylon is at "https://example.com/"
        - module name is "demo"
        - route is "/"
        Route URL: https://example.com/demo/

        web.route decorator takes the same arguments as Flask route
        Note: web.route decorator must be the last decorator (at top)
    """

    @web.route("/login")
    def login(self):
        """ Login """
        target_token = flask.request.args.get("target_to", "")
        #
        if "auth_oidc" not in flask.session:
            flask.session["auth_oidc"] = {}
        #
        while True:
            state_uuid, target_state = self.generate_state_id()
            if state_uuid not in flask.session["auth_oidc"]:
                break
        #
        flask.session["auth_oidc"][state_uuid] = {}
        flask.session["auth_oidc"][state_uuid]["target_token"] = target_token
        flask.session.modified = True
        #
        target_response_type = self.descriptor.config.get("target_response_type", "code")
        target_parameters = [
            {
                "name": "response_type",
                "value": target_response_type,
            },
            {
                "name": "client_id",
                "value": self.descriptor.config["client_id"],
            },
            {
                "name": "redirect_uri",
                "value": self.get_url("auth_oidc.login_callback"),
            },
            {
                "name": "scope",
                "value": self.descriptor.config.get("target_scope", "openid profile email"),
            },
            {
                "name": "state",
                "value": target_state,
            },
        ]
        #
        if target_response_type == "id_token":
            target_parameters.append({
                "name": "response_mode",
                "value": "form_post",
            })
        #
        login_mode = self.descriptor.config.get("login_mode", "post")
        #
        if login_mode == "get":
            target_params_dict = {item["name"]: item["value"] for item in target_parameters}
            url_params = urllib.parse.urlencode(target_params_dict)
            return flask.redirect(
                f'{self.descriptor.config["authorization_endpoint"]}?{url_params}'
            )
        #
        return self.descriptor.render_template(
            "redirect.html",
            action=self.descriptor.config["authorization_endpoint"],
            parameters=target_parameters,
        )

    @web.route("/login_callback", methods=["GET", "POST"])
    def login_callback(self):  # pylint: disable=R0912,R0914,R0915,R0911
        """ Login callback """
        if flask.request.method == "POST":
            args = flask.request.form
        else:
            args = flask.request.args
        #
        log.debug("Callback arguments: %s", args)
        #
        if "state" not in args:
            log.error("No state in OIDC callback")
            return auth_core.access_denied_reply()
        #
        target_state = args["state"]
        #
        try:
            state_uuid = self.get_state_id(target_state)
            if state_uuid not in flask.session["auth_oidc"]:
                raise ValueError("Unknown state")
        except:  # pylint: disable=W0702
            log.exception("Invalid state")
            return auth_core.access_denied_reply()
        #
        oidc_state = flask.session["auth_oidc"].pop(state_uuid)
        flask.session.modified = True
        #
        target_token = oidc_state.get("target_token", "")
        #
        target_response_type = self.descriptor.config.get("target_response_type", "code")
        #
        if target_response_type == "code":
            if "code" not in args:
                log.error("No code in OIDC callback")
                return auth_core.access_denied_reply()
            #
            oidc_code = args["code"]
            #
            try:
                token_endpoint_auth = self.descriptor.config.get("token_endpoint_auth", "basic")
                if token_endpoint_auth == "basic":
                    oidc_token = requests.post(
                        self.descriptor.config["token_endpoint"],
                        data={
                            "grant_type": "authorization_code",
                            "code": oidc_code,
                            "redirect_uri": self.get_url("auth_oidc.login_callback"),
                        },
                        auth=(
                            self.descriptor.config["client_id"],
                            self.descriptor.config["client_secret"],
                        ),
                        verify=self.descriptor.config.get("token_endpoint_verify", True),
                    ).json()
                elif token_endpoint_auth == "data":
                    oidc_token = requests.post(
                        self.descriptor.config["token_endpoint"],
                        data={
                            "grant_type": "authorization_code",
                            "client_id": self.descriptor.config["client_id"],
                            "client_secret": self.descriptor.config["client_secret"],
                            "code": oidc_code,
                            "redirect_uri": self.get_url("auth_oidc.login_callback"),
                        },
                        verify=self.descriptor.config.get("token_endpoint_verify", True),
                    ).json()
                else:
                    raise ValueError("Invalid token_endpoint_auth")
            except:  # pylint: disable=W0702
                log.error("Failed to get token")
                return auth_core.access_denied_reply()
            #
            log.debug("Token: %s", oidc_token)
            #
            if "error" in oidc_token:
                log.error("Error in OIDC token: %s", oidc_token.get("error_description", "unknown"))
                return auth_core.access_denied_reply()
            #
            if "id_token" not in oidc_token:
                log.error("Invalid OIDC token: no id_tokeb")
                return auth_core.access_denied_reply()
            #
            id_token = oidc_token["id_token"]
        #
        else:  # target_response_type == id_token
            if "id_token" not in args:
                log.error("No id_token in OIDC callback")
                return auth_core.access_denied_reply()
            #
            id_token = args["id_token"]
        #
        if self.rsa_public_key is not None:
            id_data = jwt.decode(
                id_token, self.rsa_public_key,
                audience=self.descriptor.config["client_id"],
                algorithms=["RS256"],
            )
        else:
            id_data = jwt.decode(id_token, options={"verify_signature": False})
        #
        log.debug("ID data: %s", id_data)
        #
        if "sub" not in id_data:
            log.error("Invalid ID token: no sub")
            return auth_core.access_denied_reply()
        #
        if self.descriptor.config.get("require_email_verified", False):
            if "email_verified" not in id_data or not id_data["email_verified"]:
                log.error("Email verification required and email is not verified")
                return auth_core.access_denied_reply()
        #
        oidc_sub = id_data["sub"]
        #
        auth_ok = True
        #
        if "preferred_username" not in id_data:
            auth_name = oidc_sub
        else:
            auth_name = id_data["preferred_username"]
        #
        auth_attributes = id_data
        #
        auth_sessionindex = id_token
        #
        exp_override = self.descriptor.config.get("expiration_override", None)
        #
        if exp_override is not None:
            auth_exp = datetime.datetime.now() + datetime.timedelta(seconds=int(exp_override))
        elif "exp" not in id_data:
            auth_exp = datetime.datetime.now() + datetime.timedelta(seconds=86400)  # 24h
        else:
            auth_exp = datetime.datetime.fromtimestamp(id_data["exp"])
        #
        try:
            auth_user_id = auth_core.get_user_from_provider(auth_name)["id"]
        except:  # pylint: disable=W0702
            auth_user_id = None
        #
        auth_ctx = auth_core.get_auth_context()
        auth_ctx["done"] = auth_ok
        auth_ctx["error"] = ""
        auth_ctx["expiration"] = auth_exp
        auth_ctx["provider"] = "oidc"
        auth_ctx["provider_attr"]["nameid"] = auth_name
        auth_ctx["provider_attr"]["attributes"] = auth_attributes
        auth_ctx["provider_attr"]["sessionindex"] = auth_sessionindex
        auth_ctx["user_id"] = auth_user_id
        auth_core.set_auth_context(auth_ctx)
        #
        log.debug("Context: %s", auth_ctx)
        #
        return auth_core.access_success_redirect(target_token)
