#!/usr/bin/env python3
"""
Test runner for the auth_oidc plugin.
Installs Pylon stubs before running pytest so plugin modules can be imported.

Usage:
    python3 tests/run_tests.py -v                                     # All tests
    python3 tests/run_tests.py -m integration -v                      # By marker
    python3 tests/run_tests.py integration/test_id_token_validation.py  # One file
"""
import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

os.chdir(TESTS_DIR)
sys.path.insert(0, TESTS_DIR)

from fixtures import helpers  # noqa: E402  pylint: disable=C0413

if __name__ == "__main__":
    helpers.install_pylon_stubs()

    import pytest

    sys.exit(pytest.main(["."] + sys.argv[1:]))
