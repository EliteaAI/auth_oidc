#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0116,W0201

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

""" Method """

import uuid

import requests  # pylint: disable=E0401
import flask  # pylint: disable=E0611,E0401
import jwt  # pylint: disable=E0401

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.method()
    def get_url(self, endpoint):
        url_mode = self.descriptor.config.get("url_mode", "default")
        #
        if url_mode == "request":
            return f'{flask.request.host_url.rstrip("/")}{flask.url_for(endpoint)}'
        #
        if url_mode == "external":
            return flask.url_for(endpoint, _external=True)
        #
        return flask.url_for(endpoint)  # default

    @web.method()
    def get_metadata(self):
        metadata_endpoint = self.descriptor.config.get("metadata_endpoint", "").strip()
        if metadata_endpoint:
            log.info("Getting metadata")
            #
            metadata = requests.get(
                metadata_endpoint,
                verify=self.descriptor.config.get("metadata_endpoint_verify", True),
            ).json()
            #
            for endpoint in [
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
                "end_session_endpoint",
            ]:
                if endpoint in metadata:
                    log.info("Using %s: %s", endpoint, metadata[endpoint])
                    self.descriptor.config[endpoint] = metadata[endpoint]

    @web.method()
    def generate_state_id(self):
        """ Make and sign state id """
        state_uuid = str(uuid.uuid4())
        return state_uuid, jwt.encode(
            {"uuid": state_uuid},
            self.context.app.secret_key,
            algorithm="HS512",
        )

    @web.method()
    def get_state_id(self, target_state):
        """ Verify and get state UUID """
        try:
            state_data = jwt.decode(
                target_state, self.context.app.secret_key, algorithms=["HS512"]
            )
        except:
            raise ValueError("Invalid state")  # pylint: disable=W0707
        #
        return state_data["uuid"]
