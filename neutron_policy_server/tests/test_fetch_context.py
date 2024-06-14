# SPDX-License-Identifier: Apache-2.0
from unittest import mock

from neutron_policy_server.tests import test
from neutron_policy_server import wsgi


class TestFetchContext(test.TestCase):
    def test_fetch_context(self):
        class fakeRequestURLencoded():
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            form = mock.Mock()
            form.to_dict.return_value = {
                'target': '{"port_id": "bar"}',
                'credentials': '{"user_id": "foo", "project_id": "fake_proj"}',
                'rule': '"rule1"'
            }

        class fakeRequestJson():
            headers = {"Content-Type": "application/json"}
            json = {
                'target': {"port_id": "bar"},
                'credentials': {"user_id": "foo", "project_id": "fake_proj"},
                'rule': 'rule1'
            }
        reqURLencoded = fakeRequestURLencoded()
        reqJson = fakeRequestJson()

        rule, target, ctx = wsgi._fetch_context(reqURLencoded)
        self.assertEqual({"port_id": "bar"}, target)
        self.assertEqual('foo', ctx.user_id)
        self.assertEqual('fake_proj', ctx.project_id)
        self.assertEqual('rule1', rule)

        rule, target, ctx = wsgi._fetch_context(reqJson)
        self.assertEqual({"port_id": "bar"}, target)
        self.assertEqual('foo', ctx.user_id)
        self.assertEqual('fake_proj', ctx.project_id)
        self.assertEqual('rule1', rule)
