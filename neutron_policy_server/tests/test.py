# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Base classes for our unit tests.

Allows overriding of CONF for use of fakes, and some black magic for
inline callbacks.

"""
from unittest import mock

import fixtures
import testtools
from oslo_config import cfg

CONF = cfg.CONF


@mock.patch("neutron.common.config")
class TestCase(testtools.TestCase):
    """Test case base class for all unit tests."""

    def override_config(self, name, override, group=None):
        """Cleanly override CONF variables."""
        CONF.set_override(name, override, group)
        self.addCleanup(CONF.clear_override, name, group)

    def flags(self, **kw):
        """Override CONF variables for a test."""
        group = kw.pop("group", None)
        for k, v in kw.items():
            self.override_config(k, v, group)

    def mock_object(self, obj, attr_name, *args, **kwargs):
        """Use python mock to mock an object attribute

        Mocks the specified objects attribute with the given value.
        Automatically performs 'addCleanup' for the mock.

        """
        patcher = mock.patch.object(obj, attr_name, *args, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def patch(self, path, *args, **kwargs):
        """Use python mock to mock a path with automatic cleanup."""
        patcher = mock.patch(path, *args, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def assertTrue(self, x, *args, **kwargs):
        """Assert that value is True.

        If original behavior is required we will need to do:
            assertTrue(bool(result))
        """
        # assertTrue uses msg but assertIs uses message keyword argument
        args = list(args)
        msg = kwargs.pop("msg", args.pop(0) if args else "")
        kwargs.setdefault("message", msg)
        self.assertIs(True, x, *args, **kwargs)

    def assertFalse(self, x, *args, **kwargs):
        """Assert that value is False.

        If original behavior is required we will need to do:
            assertFalse(bool(result))
        """
        # assertTrue uses msg but assertIs uses message keyword argument
        args = list(args)
        msg = kwargs.pop("msg", args.pop(0) if args else "")
        kwargs.setdefault("message", msg)
        self.assertIs(False, x, *args, **kwargs)

    def stub_out(self, old, new):
        """Replace a function for the duration of the test.

        Use the monkey patch fixture to replace a function for the
        duration of a test. Useful when you want to provide fake
        methods instead of mocks during testing.
        This should be used instead of self.stubs.Set (which is based
        on mox) going forward.
        """
        self.useFixture(fixtures.MonkeyPatch(old, new))
