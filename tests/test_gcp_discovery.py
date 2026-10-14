"""Offline tests for the parts of gcp_discovery.py that shape the output.

    python3 -m unittest discover -s tests
"""

import collections
import io
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import gcp_discovery as gd  # noqa: E402


class MetadataTest(unittest.TestCase):
    def test_keeps_settings_counts_keys_and_drops_values(self):
        out = gd.metadata_summary([
            {"key": "enable-oslogin", "value": "TRUE"},
            {"key": "ssh-keys", "value": "alice:ssh-rsa AAAA alice@example.com\nbob:ssh-ed25519 BBBB\n\n"},
            {"key": "startup-script", "value": "export TOKEN=secret"},
        ])
        self.assertEqual(out["settings"], {"enable-oslogin": "TRUE"})
        self.assertEqual(out["ssh_keys"], 2)
        self.assertEqual(out["ssh_usernames"], ["alice", "bob"])
        self.assertEqual(out["other_keys"], ["startup-script"])
        self.assertNotIn("secret", repr(out))
        self.assertNotIn("AAAA", repr(out))

    def test_empty(self):
        self.assertEqual(gd.metadata_summary(None)["ssh_keys"], 0)


class ChannelTest(unittest.TestCase):
    def test_webhook_url_and_token_are_dropped(self):
        out = gd.channel_summary({"type": "webhook_tokenauth", "labels": {"url": "https://x/?token=abc"}})
        self.assertEqual(out["labels"], {})
        self.assertEqual(out["other_label_keys"], ["url"])

    def test_email_is_kept(self):
        out = gd.channel_summary({"type": "email", "labels": {"email_address": "ops@example.com"}})
        self.assertEqual(out["labels"], {"email_address": "ops@example.com"})


class MemberTest(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(gd.member_parts("user:Ann@Example.com"), ("user", "Ann@Example.com", "example.com"))
        self.assertEqual(gd.member_parts("domain:example.com"), ("domain", "example.com", "example.com"))
        self.assertEqual(gd.member_parts("deleted:user:old@example.com?uid=123"),
                         ("deleted:user", "old@example.com", "example.com"))
        self.assertEqual(gd.member_parts("allUsers"), ("allUsers", "", ""))
        self.assertEqual(gd.member_parts("projectOwner:my-project"), ("projectOwner", "my-project", ""))

    def test_index_collects_grants_exemptions_and_denials(self):
        idx = gd.principal_index(
            [{"resource": "organizations/1", "bindings": [{"role": "roles/owner", "members": ["user:a@x.com"]}],
              "auditConfigs": [{"service": "allServices", "auditLogConfigs": [
                  {"logType": "DATA_READ", "exemptedMembers": ["user:a@x.com"]}]}]}],
            [{"resource": "//storage.googleapis.com/b", "bindings": [
                {"role": "roles/storage.admin", "members": ["group:g@x.com"], "condition": {"expression": "true"}}]}],
            [{"attachedTo": "organizations/1", "rules": [{"denyRule": {"deniedPrincipals": ["principal://goog/subject/a@x.com"]}}]}],
        )
        by = {e["member"]: e for e in idx}
        self.assertEqual(len(by["user:a@x.com"]["grants"]), 2)
        self.assertTrue(by["group:g@x.com"]["grants"][0]["conditional"])
        self.assertIn("principal://goog/subject/a@x.com", by)


class ErrorTest(unittest.TestCase):
    def test_reason_and_quota_metadata(self):
        body = (b'{"error":{"code":429,"message":"Quota exceeded","status":"RESOURCE_EXHAUSTED","details":['
                b'{"reason":"RATE_LIMIT_EXCEEDED","metadata":{"quota_limit_value":"10","quota_unit":"1/min/{project}/{user}"}}]}}')
        e = gd.parse_error(429, body, "https://iam.googleapis.com/v2/x")
        self.assertEqual(e.reason, "RATE_LIMIT_EXCEEDED")
        self.assertEqual(e.meta["quota_limit_value"], "10")

    def test_disabled_api(self):
        body = b'{"error":{"code":403,"message":"Compute Engine API has not been used in project 1","errors":[{"reason":"accessNotConfigured"}]}}'
        self.assertTrue(gd.parse_error(403, body, "u").service_disabled)

    def test_permissions_in_message(self):
        msg = "Permission 'resourcemanager.folders.list' denied on resource; also lacks orgpolicy.policy.get"
        self.assertEqual(gd.permissions_in(msg), ["orgpolicy.policy.get", "resourcemanager.folders.list"])

    def test_host_names_are_not_permissions(self):
        msg = "Enable billing by visiting https://console.developers.google.com/billing; pool x.svc.id.goog"
        self.assertEqual(gd.permissions_in(msg), [])

    def test_rate_key(self):
        self.assertEqual(gd.rate_key("https://iam.googleapis.com/v2/policies/a/denypolicies"), "iam.googleapis.com/v2")


class ActivityTest(unittest.TestCase):
    def test_counts_per_principal_and_impersonation(self):
        stats = {}
        entry = {
            "timestamp": "2026-10-01T10:00:00Z", "resource": {"labels": {"project_id": "p1"}},
            "protoPayload": {
                "serviceName": "compute.googleapis.com", "methodName": "v1.compute.instances.insert",
                "authenticationInfo": {"principalEmail": "sa@p1.iam.gserviceaccount.com",
                                       "serviceAccountDelegationInfo": [{"firstPartyPrincipal": {"principalEmail": "ann@x.com"}}]},
                "requestMetadata": {"callerSuppliedUserAgent": "Terraform/1.9"},
            },
        }
        gd.add_activity(stats, entry, "activity")
        gd.add_activity(stats, {**entry, "timestamp": "2026-10-02T10:00:00Z"}, "data_access")
        robot = {**entry, "protoPayload": {**entry["protoPayload"], "authenticationInfo": {
            "principalEmail": "sa@p1.iam.gserviceaccount.com",
            "serviceAccountDelegationInfo": [{"firstPartyPrincipal": {"principalEmail": "service-1@compute-system.iam.gserviceaccount.com"}}]}}}
        gd.add_activity(stats, robot, "activity")  # a Google service agent, not a person: ignored
        own = {"timestamp": "2026-10-03T10:00:00Z", "protoPayload": {
            "authenticationInfo": {"principalEmail": "ann@x.com"},
            "requestMetadata": {"callerSuppliedUserAgent": "gcp-discovery/1.0.0,gzip(gfe)"}}}
        gd.add_activity(stats, own, "data_access")  # this script's own earlier run: ignored
        self.assertNotIn("ann@x.com", stats)
        s = stats["sa@p1.iam.gserviceaccount.com"]
        self.assertEqual(s["entries"], 2)
        self.assertEqual((s["first"], s["last"]), ("2026-10-01T10:00:00Z", "2026-10-02T10:00:00Z"))
        self.assertEqual(s["impersonated"], collections.Counter({"ann@x.com": 2}))
        self.assertEqual(s["agents"]["Terraform/1.9"], 2)


class LogQueryTest(unittest.TestCase):
    def test_windows_cover_the_period_newest_first(self):
        import datetime as dt
        now = dt.datetime(2026, 10, 31, tzinfo=dt.timezone.utc)
        w = gd.time_slices(30, now)
        self.assertEqual(len(w), 15)
        self.assertEqual(w[0][1], "2026-10-31T00:00:00Z")
        self.assertEqual(w[-1][0], "2026-10-01T00:00:00Z")
        self.assertTrue(all(a[0] == b[1] for a, b in zip(w, w[1:])))
        self.assertEqual(len(gd.time_slices(2, now)), 2)

    def test_filter_leaves_out_service_agents(self):
        f = gd.activity_filter("activity", "a", "b")
        self.assertIn('NOT protoPayload.authenticationInfo.principalEmail:"gserviceaccount.com"', f)
        self.assertIn("cloudaudit.googleapis.com%2Factivity", f)


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = gd.Run(Path(self.tmp.name) / "out", assume_yes=True)
        self.api = gd.Api(self.out)
        self.api.token, self.api.token_at = "t", 1e12

    def tearDown(self):
        self.out.log_file.close()
        self.tmp.cleanup()

    def _http_error(self, code, body):
        return urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(body))

    def test_retries_through_an_org_project_when_an_api_requires_a_quota_project(self):
        self.api.candidates["billingbudgets.googleapis.com"] = ["qp"]
        seen = []

        def fake(req, timeout):
            seen.append(req.headers.get("X-goog-user-project"))
            if len(seen) == 1:
                raise self._http_error(403, b'{"error":{"code":403,"message":"The billingbudgets.googleapis.com API requires a quota project","status":"PERMISSION_DENIED"}}')
            resp = mock.MagicMock()
            resp.__enter__.return_value = resp
            resp.read.return_value = b'{"budgets":[]}'
            resp.status = 200
            return resp

        with mock.patch("urllib.request.urlopen", fake):
            self.assertEqual(self.api.get("https://billingbudgets.googleapis.com/v1/x"), {"budgets": []})
        self.assertEqual(seen, [None, "qp"])
        self.assertEqual(self.api.quota["billingbudgets.googleapis.com"], "qp")  # remembered for later calls

    def test_rate_limit_sets_pacing(self):
        body = (b'{"error":{"code":429,"message":"Quota exceeded","details":[{"reason":"RATE_LIMIT_EXCEEDED",'
                b'"metadata":{"quota_limit_value":"10","quota_unit":"1/min/{project}/{user}"}}]}}')
        calls = []

        def fake(req, timeout):
            calls.append(1)
            if len(calls) == 1:
                raise self._http_error(429, body)
            resp = mock.MagicMock()
            resp.__enter__.return_value = resp
            resp.read.return_value = b"{}"
            resp.status = 200
            return resp

        with mock.patch("urllib.request.urlopen", fake), mock.patch("time.sleep"):
            self.api.get("https://iam.googleapis.com/v2/policies/x/denypolicies")
        self.assertAlmostEqual(self.api.min_interval["iam.googleapis.com/v2"], 6.6, places=1)

    def test_compute_off_in_a_project_means_not_used(self):
        g = gd.Group(self.out, "x")

        def boom():
            raise gd.ApiError(403, "SERVICE_DISABLED", "off", "https://compute.googleapis.com/compute/v1/projects/p")

        self.assertEqual(g.attempt("thing", "p", boom, []), [])
        self.assertEqual(g.not_collected, [])

    def test_api_off_for_the_caller_is_a_gap_never_silent(self):
        g = gd.Group(self.out, "x")

        def boom():
            raise gd.ApiError(403, "SERVICE_DISABLED", "Organization Policy API has not been used in project 7",
                              "https://orgpolicy.googleapis.com/v2/organizations/1/policies",
                              {"service": "orgpolicy.googleapis.com", "consumer": "projects/7"})

        self.assertEqual(g.attempt("org policies", "organizations/1", boom, []), [])
        self.assertIn("orgpolicy.googleapis.com API is off in projects/7", g.not_collected[0]["why"])

    def test_api_off_for_the_caller_is_retried_through_an_org_project(self):
        self.api.candidates["orgpolicy.googleapis.com"] = ["has-it-on"]
        seen = []

        def fake(req, timeout):
            seen.append(req.headers.get("X-goog-user-project"))
            if len(seen) == 1:
                raise self._http_error(403, b'{"error":{"code":403,"message":"Organization Policy API has not been used in project 7","status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED","metadata":{"consumer":"projects/7"}}]}}')
            resp = mock.MagicMock()
            resp.__enter__.return_value = resp
            resp.read.return_value = b'{"policies":[]}'
            resp.status = 200
            return resp

        with mock.patch("urllib.request.urlopen", fake):
            self.api.get("https://orgpolicy.googleapis.com/v2/organizations/1/policies")
        self.assertEqual(seen, [None, "has-it-on"])

    def test_denied_read_is_listed_with_its_permission(self):
        g = gd.Group(self.out, "x")

        def boom():
            raise gd.ApiError(403, "IAM_PERMISSION_DENIED", "Permission 'cloudsql.users.list' denied", "u")

        g.attempt("Cloud SQL users", "p/i", boom)
        self.assertEqual(g.not_collected[0]["what"], "Cloud SQL users")
        self.assertIn("cloudsql.users.list", self.out.missing_permissions)


class ParallelTest(unittest.TestCase):
    def test_pmap_keeps_order(self):
        self.assertEqual(gd.pmap(lambda x: x * 2, range(20)), [x * 2 for x in range(20)])

    def test_log_batch_falls_back_to_one_resource_at_a_time(self):
        tmp = tempfile.TemporaryDirectory()
        out = gd.Run(Path(tmp.name) / "out", assume_yes=True)
        api = mock.MagicMock()

        def request(method, url, params=None, body=None):
            if len(body["resourceNames"]) > 1:
                raise gd.ApiError(403, "PERMISSION_DENIED", "Permission 'logging.logEntries.list' denied", url)
            if body["resourceNames"] == ["projects/secret"]:
                raise gd.ApiError(403, "PERMISSION_DENIED", "Permission 'logging.logEntries.list' denied", url)
            return {"entries": [{"timestamp": "2026-10-01T00:00:00Z",
                                 "protoPayload": {"authenticationInfo": {"principalEmail": "ann@x.com"}}}]}

        api.request.side_effect = request
        g = gd.read_activity(out, api, "organizations/1", [], [{"projectId": "open"}, {"projectId": "secret"}], 2, 1)
        out.log_file.close()
        tmp.cleanup()
        self.assertEqual([p["principal"] for p in g.data["principals"]], ["ann@x.com"])
        self.assertTrue(any("projects/secret" in n["where"] for n in g.not_collected))
        self.assertFalse(any("projects/open" in n["where"] for n in g.not_collected))


class SummaryTest(unittest.TestCase):
    def test_a_missing_read_never_looks_like_zero_or_nowhere(self):
        tmp = tempfile.TemporaryDirectory()
        out = gd.Run(Path(tmp.name) / "out", assume_yes=True)
        groups = {n: gd.Group(out, n) for n in ("hierarchy", "iam", "access-paths", "guardrails", "move-blockers", "notifications", "activity")}
        groups["iam"].data = {"principals": [], "resourcePolicies": None}
        groups["guardrails"].data = {"orgPolicies": []}
        groups["guardrails"].not_collected.append({"what": "org policies", "where": "organizations/1", "why": "x"})
        groups["move-blockers"].not_collected.append({"what": "custom roles", "where": "organizations/1", "why": "x"})
        groups["notifications"].data = {"budgets": None}
        text = gd.summary_text({"name": "organizations/1", "displayName": "x"}, groups, out)
        out.log_file.close()
        tmp.cleanup()
        self.assertIn("Domain restricted sharing set at: not read.", text)
        self.assertIn("Custom roles: not read.", text)
        self.assertIn("IAM on individual resources wasn't read", text)
        self.assertIn("Budgets: not read.", text)


    def test_shared_vpc_hosts_are_listed_with_their_service_projects(self):
        tmp = tempfile.TemporaryDirectory()
        out = gd.Run(Path(tmp.name) / "out", assume_yes=True)
        groups = {n: gd.Group(out, n) for n in ("hierarchy", "iam", "access-paths", "guardrails", "move-blockers", "notifications", "activity")}
        vm = {"metadata": {"settings": {}, "ssh_keys": 0}, "instances": []}
        groups["access-paths"].data = {"compute": [
            {**vm, "projectId": "net-host", "sharedVpc": "HOST", "sharedVpcServiceProjects": ["app-1", "app-2"]},
            {**vm, "projectId": "net-host-2", "sharedVpc": "HOST", "sharedVpcServiceProjects": []},
            {**vm, "projectId": "app-1", "sharedVpc": None},
        ]}
        groups["access-paths"].not_collected.append({"what": "Shared VPC service projects", "where": "net-host-2", "why": "x"})
        text = gd.summary_text({"name": "organizations/1", "displayName": "x"}, groups, out)
        groups["access-paths"].data = {"compute": []}
        groups["access-paths"].not_collected[:] = [{"what": "Compute project settings", "where": "p", "why": "x"}]
        unread = gd.summary_text({"name": "organizations/1", "displayName": "x"}, groups, out)
        out.log_file.close()
        tmp.cleanup()
        self.assertIn("Shared VPC host projects: net-host (2 service projects), net-host-2 (service projects not read).", text)
        self.assertIn("Shared VPC host projects: none found (1 project not read: p).", unread)

class NeverEnableTest(unittest.TestCase):
    def test_compute_sql_gke_are_refused(self):
        with self.assertRaises(AssertionError):
            gd.enable_api(mock.MagicMock(), mock.MagicMock(), "p", "compute.googleapis.com")


if __name__ == "__main__":
    unittest.main()
