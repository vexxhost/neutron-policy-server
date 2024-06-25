# SPDX-License-Identifier: Apache-2.0

"""Base classes for our unit tests."""
from unittest import mock

import testtools


@mock.patch("neutron.common.config")
class TestCase(testtools.TestCase):
    """Test case base class for all unit tests."""

    pass
