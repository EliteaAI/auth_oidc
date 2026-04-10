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

import flask  # pylint: disable=E0611,E0401

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

    @web.route("/logout")
    def logout(self):
        """ Logout """
        target_token = flask.request.args.get("target_to", "")
        auth_ctx = auth_core.get_auth_context()
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
        logout_mode = self.descriptor.config.get("logout_mode", "get")
        #
        if logout_mode == "get":
            url_params = urllib.parse.urlencode({
                "id_token_hint": auth_ctx["provider_attr"].get("sessionindex", ""),
                "post_logout_redirect_uri": self.get_url("auth_oidc.logout_callback"),
                "state": target_state,
            })
            return flask.redirect(f'{self.descriptor.config["end_session_endpoint"]}?{url_params}')
        #
        if logout_mode == "post":
            return self.descriptor.render_template(
                "redirect.html",
                action=self.descriptor.config["end_session_endpoint"],
                parameters=[
                    {
                        "name": "id_token_hint",
                        "value": auth_ctx["provider_attr"].get("sessionindex", ""),
                    },
                    {
                        "name": "post_logout_redirect_uri",
                        "value": self.get_url("auth_oidc.logout_callback"),
                    },
                    {
                        "name": "state",
                        "value": target_state,
                    },
                ],
            )
        #
        if logout_mode == "local":
            return auth_core.logout_success_redirect(target_token)
        #
        return auth_core.access_denied_reply()

    @web.route("/logout_callback")
    def logout_callback(self):  # pylint: disable=R0912,R0914,R0915
        """ Logout callback """
        log.debug("GET arguments: %s", flask.request.args)
        #
        if "state" not in flask.request.args:
            log.error("No state in OIDC callback")
            return auth_core.access_denied_reply()
        #
        target_state = flask.request.args["state"]
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
        return auth_core.logout_success_redirect(target_token)
