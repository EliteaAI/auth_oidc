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

""" Module """

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from tools import auth_core  # pylint: disable=E0401


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor

    #
    # Module
    #

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Init
        self.descriptor.init_all(
            url_prefix=auth_core.get_relative_url_prefix(
                self.descriptor, self.descriptor.config.get("url_prefix", None)
            ),
        )
        # Register auth provider
        auth_core.register_auth_provider(
            "oidc",
            login_route="auth_oidc.login",
            logout_route="auth_oidc.logout",
        )
        # Use metadata endpoint if set in config
        self.get_metadata()

    def reconfig(self):
        """ Re-config module """
        log.info("Re-configuring module")
        # Re-get metadata
        self.get_metadata()

    def deinit(self):
        """ De-init module """
        log.info("De-initializing module")
        # Unregister auth provider
        auth_core.unregister_auth_provider("oidc")
        # De-init
        self.descriptor.deinit_all()
