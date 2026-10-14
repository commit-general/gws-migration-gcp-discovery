#!/usr/bin/env python3
"""Read-only discovery of a Google Cloud organization, run before its Google
Workspace moves to a new account.

Start it with ./gcp_discovery.sh (see tutorial.md). It reads the organization
with your own Google identity and writes a zip in the current directory.

It changes nothing. The one exception is optional: budgets can only be read
through a project where the Cloud Billing Budget API is on. If no project has
it on, the script asks whether to turn it on in one project you pick, and
skips budgets if you say no.

Standard library only, so it runs anywhere gcloud and Python 3.8+ are installed.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

VERSION = "1.0.0"
USER_AGENT_NAME = "gcp-discovery"  # sent with every call, so the script can skip its own runs in the audit logs
HERE = Path(__file__).resolve().parent

# The script never turns these on, in any project. It reads them only where they're already on.
NEVER_ENABLE = {"compute.googleapis.com", "sqladmin.googleapis.com", "container.googleapis.com"}
BUDGET_API = "billingbudgets.googleapis.com"

# Metadata keys whose values are settings, not secrets. Every other key is recorded by name only.
SAFE_METADATA = {
    "enable-oslogin",
    "enable-oslogin-2fa",
    "enable-oslogin-sk",
    "block-project-ssh-keys",
    "enable-windows-ssh",
}

# Roles that would fix a failed read, shown in the access check.
ROLE_HINTS = {
    "org": "roles/browser",
    "iam": "roles/iam.securityReviewer",
    "asset": "roles/cloudasset.viewer",
    "orgpolicy": "roles/orgpolicy.policyViewer",
    "vpcsc": "roles/accesscontextmanager.policyReader",
    "roles": "roles/iam.securityReviewer",
    "logging": "roles/iam.securityReviewer (or roles/logging.viewer)",
    "billing": "roles/billing.viewer on each billing account",
    "contacts": "roles/iam.securityReviewer (or roles/essentialcontacts.viewer)",
}


# ─────────────────────────────── Output and prompts ───────────────────────────────


class Run:
    """The run log, console output and the user's answers."""

    def __init__(self, out_dir: Path, assume_yes: bool):
        self.out_dir = out_dir
        self.assume_yes = assume_yes
        out_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = (out_dir / "run.log").open("w", encoding="utf-8")
        self.missing_permissions: set[str] = set()
        self.started = utcnow()
        self.lock = threading.Lock()

    def log(self, msg: str) -> None:
        with self.lock:
            self.log_file.write(f"{utcnow()} {msg}\n")
            self.log_file.flush()

    def say(self, msg: str = "") -> None:
        print(msg, flush=True)
        if msg:
            self.log(msg)

    def ask(self, prompt: str, default: str | None = None) -> str:
        if self.assume_yes and default is not None:
            self.say(f"{prompt} {default} (from the command line)")
            return default
        try:
            answer = input(f"{prompt} ").strip()
        except EOFError:
            if default is None:
                raise SystemExit(f"\n{prompt}\nThis needs an answer; run the script in a terminal.")
            answer = ""
        self.log(f"{prompt} -> {answer!r}")
        return answer or (default or "")

    def confirm(self, prompt: str, default_yes_flag: bool | None = None) -> bool:
        """True only for an explicit YES. default_yes_flag answers it from the command line."""
        if default_yes_flag is not None:
            self.say(f"{prompt} {'YES' if default_yes_flag else 'NO'} (from the command line)")
            return default_yes_flag
        while True:
            a = self.ask(prompt).upper()
            if a in ("YES", "NO"):
                return a == "YES"
            print("Please type YES or NO.")


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────── API client ───────────────────────────────────


class ApiError(Exception):
    def __init__(self, status: int, reason: str, message: str, url: str, meta: dict | None = None):
        super().__init__(f"{status} {reason}: {message}")
        self.status, self.reason, self.message, self.url = status, reason, message, url
        self.meta = meta or {}

    @property
    def service_disabled(self) -> bool:
        return self.reason in ("SERVICE_DISABLED", "accessNotConfigured") or "has not been used in project" in self.message

    @property
    def not_used(self) -> bool:
        """The API is off in the project being read, so that project doesn't use the service.

        Only Compute Engine and GKE reads of a project check their API in that project. "API off"
        anywhere else means the project the credentials bill calls to lacks it: a gap, not an answer.
        """
        return self.service_disabled and project_scoped(self.url)

    def explain(self) -> str:
        if self.reason == "BILLING_DISABLED":
            return "billing is off in this project"
        if self.reason == "SECURITY_POLICY_VIOLATED" or "VPC Service Controls" in self.message:
            return "blocked by VPC Service Controls"
        if self.service_disabled:
            api = self.meta.get("service") or urllib.parse.urlsplit(self.url).netloc
            consumer = self.meta.get("consumer", "the project these credentials use")
            return (f"the {api} API is off in {consumer}, which these credentials bill API calls to, and no project "
                    "of this organization where it's on could be used instead. Sign in as a user (gcloud auth login) and run again.")
        if self.reason == "USER_PROJECT_DENIED":
            return "these credentials may not bill API calls to the project tried: " + self.message[:200]
        return f"{self.reason}: {self.message[:300]}"

    @property
    def permission_denied(self) -> bool:
        return self.status == 403 and self.reason in ("PERMISSION_DENIED", "IAM_PERMISSION_DENIED", "forbidden")

    @property
    def needs_quota_project(self) -> bool:
        return "requires a quota project" in self.message


def parse_error(status: int, body: bytes, url: str) -> ApiError:
    try:
        err = json.loads(body.decode("utf-8")).get("error", {})
    except (ValueError, UnicodeDecodeError, AttributeError):
        return ApiError(status, "HTTP_ERROR", body[:200].decode("utf-8", "replace"), url)
    reason, meta = err.get("status") or "HTTP_ERROR", {}
    for d in err.get("details") or []:
        if d.get("reason"):
            reason, meta = d["reason"], d.get("metadata") or {}
            break
    for e in err.get("errors") or []:
        if e.get("reason") == "accessNotConfigured":
            reason = "accessNotConfigured"
    return ApiError(status, reason, err.get("message", ""), url, meta)


PROJECT_SCOPED_HOSTS = {"compute.googleapis.com", "container.googleapis.com"}


def project_scoped(url: str) -> bool:
    """A Compute Engine or GKE read of one project, which needs that API on in that project."""
    parts = urllib.parse.urlsplit(url)
    return parts.netloc in PROJECT_SCOPED_HOSTS and "/projects/" in parts.path


def rate_key(url: str) -> str:
    """Quotas are per API, so pacing is too: 'iam.googleapis.com/v2'."""
    parts = urllib.parse.urlsplit(url)
    return parts.netloc + "/" + parts.path.strip("/").split("/")[0]


DOMAIN_ENDINGS = (".com", ".goog", ".net", ".org", ".io", ".dev", ".cloud")


def permissions_in(message: str) -> list[str]:
    """Permission names in an error message, such as 'resourcemanager.folders.list'. Host names don't count."""
    found = re.findall(r"\b[a-z][a-zA-Z]+\.[a-zA-Z]+\.[a-zA-Z]+(?:\.[a-zA-Z]+)?\b", message)
    return sorted({f for f in found if not f.endswith(DOMAIN_ENDINGS) and "google" not in f})


class Api:
    """Google REST APIs with the gcloud user's token.

    Calls carry no quota project: they count against gcloud's own client project, so it doesn't
    matter which APIs are on in the customer's projects. Only Compute Engine and GKE check their
    own API in the project they read, and the script treats an API that's off there as not used.

    An API that insists on a quota project (budgets always; others with some kinds of credentials)
    is retried through one of the org's projects where that API is already on. Nothing is turned on.
    """

    def __init__(self, run: Run):
        self.run = run
        self.token = ""
        self.token_at = 0.0
        self.quota: dict[str, str] = {}             # API host -> the project its calls are billed to
        self.candidates: dict[str, list[str]] = {}  # API host -> org projects where it's on
        self.calls = 0
        # Without a quota project, calls count against gcloud's own per-user quotas, some as low as
        # 10 a minute. A 429 says what the limit is; later calls to that API are spaced to fit it.
        self.min_interval: dict[str, float] = {}
        self.last_call: dict[str, float] = {}
        self.lock = threading.Lock()  # the audit-log read runs in several threads

    def _pace(self, key: str) -> None:
        with self.lock:
            now = time.time()
            slot = max(now, self.last_call.get(key, 0) + self.min_interval.get(key, 0))
            self.last_call[key] = slot
        if slot > now:
            time.sleep(slot - now)

    def _rate_limited(self, key: str, err: ApiError) -> None:
        limit = int(err.meta.get("quota_limit_value") or 0)
        per_minute = "/min/" in err.meta.get("quota_unit", "/min/")
        if limit and per_minute:
            with self.lock:
                self.min_interval[key] = max(self.min_interval.get(key, 0), 60 / limit * 1.1)
            self.run.log(f"pacing {key} to {limit} calls a minute")
        start = int(err.meta.get("window_start_time") or 0)
        wait = (start + 61 - time.time()) if start else 61
        time.sleep(min(max(wait, 5), 65))

    def _token(self, refresh: bool = False) -> str:
        with self.lock:
            if refresh or not self.token or time.time() - self.token_at > 30 * 60:
                self.token = gcloud("auth", "print-access-token").strip()
                self.token_at = time.time()
            return self.token

    def request(self, method: str, url: str, params: dict | None = None, body: dict | None = None) -> dict:
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        data = json.dumps(body).encode() if body is not None else None
        host = urllib.parse.urlsplit(url).netloc
        quota_project = self.quota.get(host)
        untried = [p for p in self.candidates.get(host, []) if p != quota_project]
        key = rate_key(url)
        refresh = False
        for attempt in range(8):
            self._pace(key)
            headers = {"Authorization": f"Bearer {self._token(refresh)}",
                       "Content-Type": "application/json", "User-Agent": f"{USER_AGENT_NAME}/{VERSION}"}
            if quota_project:
                headers["x-goog-user-project"] = quota_project
            refresh = False
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            with self.lock:
                self.calls += 1
            try:
                with urllib.request.urlopen(req, timeout=90) as r:
                    payload = r.read()
                    self.run.log(f"{method} {url} -> {r.status}" + (f" (quota project {quota_project})" if quota_project else ""))
                    if quota_project and self.quota.get(host) != quota_project:
                        with self.lock:
                            self.quota[host] = quota_project
                    return json.loads(payload) if payload else {}
            except urllib.error.HTTPError as e:
                err = parse_error(e.code, e.read(), url)
                self.run.log(f"{method} {url} -> {e.code} {err.reason}")
                if e.code == 401 and attempt == 0:
                    refresh = True
                    continue
                # This API wants a quota project, or can't use the one tried: try the next org
                # project that has the API on, and remember the one that works.
                wrong_consumer = err.needs_quota_project or (err.service_disabled and not err.not_used) or (
                    quota_project and err.reason in ("USER_PROJECT_DENIED", "PERMISSION_DENIED"))
                if e.code == 403 and wrong_consumer and untried:
                    quota_project = untried.pop(0)
                    continue
                if e.code == 429 or (e.code == 403 and "Quota exceeded" in err.message):
                    self._rate_limited(key, err)
                    continue
                if e.code in (500, 502, 503, 504) and attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise err
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                self.run.log(f"{method} {url} -> network error {e}")
                if attempt < 3:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise ApiError(0, "NETWORK", str(e), url)
        raise ApiError(429, "RETRIES_EXHAUSTED", "gave up after repeated retries", url)

    def get(self, url: str, **params) -> dict:
        return self.request("GET", url, params=params or None)

    def pages(self, url: str, key: str, params: dict | None = None, max_pages: int = 1000) -> list:
        items, params = [], dict(params or {})
        for _ in range(max_pages):
            data = self.request("GET", url, params=params)
            got = data.get(key) or []
            items.extend(got.values() if isinstance(got, dict) else got)
            token = data.get("nextPageToken")
            if not token:
                return items
            params["pageToken"] = token
        return items


def gcloud(*args: str) -> str:
    env = dict(os.environ, CLOUDSDK_CORE_DISABLE_PROMPTS="1")
    r = subprocess.run(["gcloud", *args], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise SystemExit(f"gcloud {' '.join(args)} failed:\n{r.stderr.strip()}")
    return r.stdout


CRM = "https://cloudresourcemanager.googleapis.com/v3"
BILLING = "https://cloudbilling.googleapis.com/v1"
BUDGETS = "https://billingbudgets.googleapis.com/v1"
ASSET = "https://cloudasset.googleapis.com/v1"
IAM = "https://iam.googleapis.com"
ORGPOLICY = "https://orgpolicy.googleapis.com/v2"
ACM = "https://accesscontextmanager.googleapis.com/v1"
LOGGING = "https://logging.googleapis.com/v2"
MONITORING = "https://monitoring.googleapis.com/v3"
CONTACTS = "https://essentialcontacts.googleapis.com/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"
SQL = "https://sqladmin.googleapis.com/v1"
GKE = "https://container.googleapis.com/v1"
SERVICEUSAGE = "https://serviceusage.googleapis.com/v1"


# ───────────────────────────── Collecting with gaps ─────────────────────────────


class Group:
    """One output file. Reads that fail are listed in not_collected instead of stopping the run."""

    def __init__(self, run: Run, name: str):
        self.run, self.name = run, name
        self.data: dict = {}
        self.not_collected: list[dict] = []

    def attempt(self, what: str, where: str, fn, default=None) -> Any:
        try:
            return fn()
        except ApiError as e:
            self.record(what, where, e)
            return default

    def record(self, what: str, where: str, e: ApiError) -> None:
        if e.not_used:
            self.run.log(f"{what} @ {where}: API off in this project, so it isn't used there")
            return
        why = e.explain()
        with self.run.lock:
            self.not_collected.append({"what": what, "where": where, "why": why})
            if e.permission_denied:
                self.run.missing_permissions.update(permissions_in(e.message))

    def output(self) -> dict:
        return {**self.data, "not_collected": self.not_collected}


# ─────────────────────────────── Sanitizing helpers ───────────────────────────────


def metadata_summary(items: list[dict] | None) -> dict:
    """Settings keep their value; ssh-keys keep only usernames and a count; any other key only its name."""
    out: dict = {"settings": {}, "ssh_keys": 0, "ssh_usernames": [], "other_keys": []}
    for it in items or []:
        key, value = it.get("key", ""), it.get("value") or ""
        if key in SAFE_METADATA:
            out["settings"][key] = value
        elif key in ("ssh-keys", "sshKeys"):
            lines = [ln for ln in value.splitlines() if ln.strip()]
            out["ssh_keys"] += len(lines)
            out["ssh_usernames"] += sorted({ln.split(":", 1)[0] for ln in lines if ":" in ln})
        else:
            out["other_keys"].append(key)
    out["ssh_usernames"] = sorted(set(out["ssh_usernames"]))
    return out


def channel_summary(ch: dict) -> dict:
    """Notification channels keep their email or number; other labels (URLs, tokens) only their names."""
    labels = ch.get("labels") or {}
    keep = {k: v for k, v in labels.items() if k in ("email_address", "number", "channel_name")}
    return {
        "name": ch.get("name"), "type": ch.get("type"), "displayName": ch.get("displayName"),
        "enabled": ch.get("enabled", True), "verification": ch.get("verificationStatus"),
        "labels": keep, "other_label_keys": sorted(set(labels) - set(keep)),
    }


def member_parts(member: str) -> tuple[str, str, str]:
    """'user:a@b.com' -> ('user', 'a@b.com', 'b.com'). Deleted members keep their type after 'deleted:'."""
    kind, _, rest = member.partition(":")
    if kind == "deleted":
        sub_kind, _, rest = rest.partition(":")
        kind = f"deleted:{sub_kind}"
        rest = rest.split("?uid=")[0]
    if not rest:
        return kind, "", ""
    if kind == "domain":
        return kind, rest, rest.lower()
    domain = rest.rsplit("@", 1)[1].lower() if "@" in rest else ""
    return kind, rest, domain


def top(counter: collections.Counter, n: int) -> dict:
    return dict(counter.most_common(n))


# ──────────────────────────────────── Reads ────────────────────────────────────


def pick_org(run: Run, api: Api, wanted: str | None) -> dict:
    if wanted:
        return api.get(f"{CRM}/organizations/{wanted.split('/')[-1]}")
    orgs = api.pages(f"{CRM}/organizations:search", "organizations")
    if not orgs:
        raise SystemExit("Your account can't see any Google Cloud organization. Sign in with an org admin account.")
    if len(orgs) == 1:
        run.say(f"Organization: {orgs[0]['displayName']} ({orgs[0]['name']})")
        return orgs[0]
    run.say("Your account can see these organizations:")
    for i, o in enumerate(orgs, 1):
        run.say(f"  {i}. {o['displayName']} ({o['name']})")
    while True:
        a = run.ask("Which one? Type its number:")
        if a.isdigit() and 1 <= int(a) <= len(orgs):
            return orgs[int(a) - 1]


def pmap(fn, items, workers: int = 8) -> list:
    """fn over items in parallel threads, results in order. API quotas are kept by Api's pacing."""
    items = list(items)
    if len(items) <= 1:
        return [fn(i) for i in items]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        return list(pool.map(fn, items))


def flat(lists) -> list:
    return [x for sub in lists for x in sub]


def access_check(run: Run, api: Api, org: str) -> list[dict]:
    """One small read per area, so the lead sees up front which parts will be partial."""
    checks = [
        ("Folders and projects", "org", lambda: api.request("GET", f"{CRM}/folders", params={"parent": org, "pageSize": 1})),
        ("IAM policies", "iam", lambda: api.request("POST", f"{CRM}/{org}:getIamPolicy", body={"options": {"requestedPolicyVersion": 3}})),
        ("IAM on individual resources", "asset", lambda: api.get(f"{ASSET}/{org}:searchAllIamPolicies", pageSize=1)),
        ("Organization policies", "orgpolicy", lambda: api.get(f"{ORGPOLICY}/{org}/policies", pageSize=1)),
        ("VPC Service Controls", "vpcsc", lambda: api.get(f"{ACM}/accessPolicies", parent=org, pageSize=1)),
        ("Custom roles", "roles", lambda: api.get(f"{IAM}/v1/{org}/roles", pageSize=1)),
        ("Audit logs", "logging", lambda: api.request("POST", f"{LOGGING}/entries:list", body={"resourceNames": [org], "pageSize": 1})),
        ("Billing accounts", "billing", lambda: api.get(f"{BILLING}/billingAccounts", pageSize=1)),
        ("Essential contacts", "contacts", lambda: api.get(f"{CONTACTS}/{org}/contacts", pageSize=1)),
    ]

    def check(c):
        label, key, fn = c
        try:
            fn()
            return {"area": label, "ok": True, "why": "", "role_that_fixes_it": ""}
        except ApiError as e:
            if e.permission_denied:
                with run.lock:
                    run.missing_permissions.update(permissions_in(e.message))
            consumer_problem = e.service_disabled or e.needs_quota_project or e.reason == "USER_PROJECT_DENIED"
            fix = "sign in as a user with gcloud auth login" if consumer_problem else ROLE_HINTS[key]
            return {"area": label, "ok": False, "why": e.reason, "role_that_fixes_it": fix}

    run.say("\nChecking access, one small read per area:")
    results = pmap(check, checks)
    for r in results:
        run.say(f"  {'✓' if r['ok'] else '✗'} {r['area']}" + ("" if r["ok"] else f": will be partial ({r['why']}). Fix: {r['role_that_fixes_it']}"))
    return results


def read_hierarchy(run: Run, api: Api, org: dict) -> tuple[Group, list[dict], list[dict]]:
    g = Group(run, "hierarchy")
    org_name = org["name"]
    g.data["organization"] = {k: org.get(k) for k in ("name", "displayName", "directoryCustomerId", "state", "createTime")}

    def children(parent: str):
        return (g.attempt("folders", parent, lambda: api.pages(f"{CRM}/folders", "folders", {"parent": parent}), []),
                g.attempt("projects", parent, lambda: api.pages(f"{CRM}/projects", "projects", {"parent": parent}), []))

    folders, projects, level = [], [], [org_name]
    while level:  # one level of the tree at a time, each level in parallel
        found = pmap(children, level)
        level = []
        for fs, ps in found:
            for f in fs:
                folders.append({k: f.get(k) for k in ("name", "displayName", "parent", "state", "createTime")})
                level.append(f["name"])
            for p in ps:
                projects.append({
                    "projectId": p.get("projectId"), "number": p["name"].split("/")[-1], "displayName": p.get("displayName"),
                    "parent": p.get("parent"), "state": p.get("state"), "labels": p.get("labels", {}),
                    "createTime": p.get("createTime"),
                })

    def project_details(p: dict) -> None:
        info = g.attempt("billing info", p["projectId"], lambda: api.get(f"{BILLING}/projects/{p['projectId']}/billingInfo"), {})
        p["billingAccount"] = (info.get("billingAccountName") or "").split("/")[-1] or None
        p["billingEnabled"] = info.get("billingEnabled", False) if info else None
        services = g.attempt("enabled APIs", p["projectId"], lambda: api.pages(
            f"{SERVICEUSAGE}/projects/{p['number']}/services", "services", {"filter": "state:ENABLED", "pageSize": 200}))
        p["enabledApis"] = sorted(s["config"]["name"] for s in services) if services is not None else None

    pmap(project_details, projects)
    run.say(f"  {len(folders)} folders, {len(projects)} projects")

    # Only the billing accounts this org's projects use, or that the org owns. An admin may see
    # many more (a reseller's, for example), which aren't part of this org.
    visible = {a["name"].split("/")[-1]: a for a in g.attempt(
        "billing accounts you can see", "billingAccounts", lambda: api.pages(f"{BILLING}/billingAccounts", "billingAccounts"), [])
        if a.get("parent") == org_name}
    ours = {p["projectId"] for p in projects}

    def account(acc_id: str) -> dict:
        a = visible.get(acc_id) or g.attempt("billing account", acc_id, lambda: api.get(f"{BILLING}/billingAccounts/{acc_id}"), {})
        policy = g.attempt("billing account IAM", acc_id, lambda: api.get(f"{BILLING}/billingAccounts/{acc_id}:getIamPolicy"), {})
        return {
            "id": acc_id, "displayName": a.get("displayName"), "open": a.get("open"),
            "parent": a.get("parent"), "masterBillingAccount": a.get("masterBillingAccount"),
            "projects": sorted(p["projectId"] for p in projects if p.get("billingAccount") == acc_id),
            "sharedWithOtherOrganizations": g.attempt("billing account projects", acc_id, lambda: pays_for_others(api, acc_id, ours)),
            "iamBindings": policy.get("bindings", []) if policy else None,
        }

    ids = sorted({p["billingAccount"] for p in projects if p.get("billingAccount")} | set(visible))
    g.data["folders"], g.data["projects"], g.data["billingAccounts"] = folders, projects, pmap(account, ids)
    return g, folders, projects


def pays_for_others(api: Api, account: str, ours: set[str]) -> bool:
    """True if the billing account also pays for projects outside this org. Stops at the first one."""
    params: dict = {"pageSize": 200}
    while True:
        data = api.request("GET", f"{BILLING}/billingAccounts/{account}/projects", params=params)
        if any(b.get("projectId") not in ours for b in data.get("projectBillingInfo", [])):
            return True
        if not data.get("nextPageToken"):
            return False
        params["pageToken"] = data["nextPageToken"]


def levels(org: str, folders: list[dict], projects: list[dict] | None = None) -> list[str]:
    """The org, its folders and (optionally) its projects, as resource names."""
    return [org] + [f["name"] for f in folders] + [f"projects/{p['projectId']}" for p in projects or []]


def read_iam(run: Run, api: Api, org: str, folders: list[dict], projects: list[dict]) -> Group:
    g = Group(run, "iam")
    body = {"options": {"requestedPolicyVersion": 3}}
    resources = levels(org, folders, projects)

    def policy(resource: str):
        pol = g.attempt("IAM policy", resource, lambda: api.request("POST", f"{CRM}/{resource}:getIamPolicy", body=body))
        return None if pol is None else {"resource": resource, "bindings": pol.get("bindings", []),
                                         "auditConfigs": pol.get("auditConfigs", [])}

    def deny_policies(resource: str) -> list[dict]:
        point = urllib.parse.quote(f"cloudresourcemanager.googleapis.com/{resource}", safe="")
        out = []
        for pol in g.attempt("IAM deny policies", resource, lambda: api.pages(f"{IAM}/v2/policies/{point}/denypolicies", "policies"), []):
            full = g.attempt("IAM deny policy rules", pol["name"], lambda: api.get(f"{IAM}/v2/{pol['name']}"), pol)
            out.append({"attachedTo": resource, "name": full.get("name"), "displayName": full.get("displayName"),
                        "rules": full.get("rules", [])})
        return out

    # IAM on individual resources (buckets, datasets, service accounts, secrets, Cloud Run services…)
    # comes from Asset Inventory in one paged search, read alongside the per-level policies.
    def resource_iam():
        return g.attempt("IAM on individual resources", org, lambda: api.pages(
            f"{ASSET}/{org}:searchAllIamPolicies", "results", {"pageSize": 500}))

    tasks = [("policy", r) for r in resources] + [("deny", r) for r in resources] + [("asset", org)]
    results = pmap(lambda t: policy(t[1]) if t[0] == "policy" else deny_policies(t[1]) if t[0] == "deny" else resource_iam(), tasks)
    hierarchy_policies = [r for r in results[:len(resources)] if r is not None]
    deny = flat(results[len(resources):2 * len(resources)])
    found = results[-1]
    skip_types = {"cloudresourcemanager.googleapis.com/Organization", "cloudresourcemanager.googleapis.com/Folder",
                  "cloudresourcemanager.googleapis.com/Project"}
    resource_policies = [
        {"resource": r.get("resource"), "assetType": r.get("assetType"), "project": r.get("project"),
         "bindings": (r.get("policy") or {}).get("bindings", [])}
        for r in (found or []) if r.get("assetType") not in skip_types
    ]
    g.data.update({"hierarchyPolicies": hierarchy_policies,
                   "resourcePolicies": resource_policies if found is not None else None,
                   "denyPolicies": deny,
                   "principals": principal_index(hierarchy_policies, resource_policies, deny)})
    run.say(f"  IAM: policies on {len(hierarchy_policies)} of {len(resources)} org, folder and project levels, "
            f"{'not read' if found is None else len(resource_policies)} individual resources, {len(deny)} deny policies")
    return g


def principal_index(hierarchy: list[dict], resources: list[dict], deny: list[dict]) -> list[dict]:
    """Every principal named in IAM, with where it holds which role."""
    index: dict[str, dict] = {}

    def add(member: str, role: str, resource: str, conditional: bool) -> None:
        kind, ident, domain = member_parts(member)
        e = index.setdefault(member, {"member": member, "type": kind, "id": ident, "domain": domain, "grants": []})
        e["grants"].append({"role": role, "resource": resource, **({"conditional": True} if conditional else {})})

    for pol in hierarchy + resources:
        for b in pol.get("bindings", []):
            for m in b.get("members", []):
                add(m, b["role"], pol["resource"], bool(b.get("condition")))
        for ac in pol.get("auditConfigs", []) or []:
            for lc in ac.get("auditLogConfigs", []):
                for m in lc.get("exemptedMembers", []):
                    add(m, f"auditLogExemption:{lc.get('logType')}", pol["resource"], False)
    for d in deny:
        for rule in d.get("rules", []):
            for m in (rule.get("denyRule") or {}).get("deniedPrincipals", []):
                add(m, "denyPolicy", d["attachedTo"], False)
    return sorted(index.values(), key=lambda e: (e["type"], e["member"]))


def read_access_paths(run: Run, api: Api, projects: list[dict]) -> Group:
    """What breaks when an account's email changes: OS Login and SSH, Cloud SQL IAM users, GKE."""
    g = Group(run, "access-paths")

    def uses(p: dict, api_name: str) -> bool:
        # Unknown (the enabled-API list couldn't be read): try, and treat "API off" as not used.
        return p.get("enabledApis") is None or api_name in p["enabledApis"]

    def compute(p: dict) -> list[dict]:
        pid = p["projectId"]
        if not uses(p, "compute.googleapis.com"):
            return []
        proj = g.attempt("Compute project settings", pid, lambda: api.get(f"{COMPUTE}/projects/{pid}"))
        if not proj:
            return []
        entry = {"projectId": pid, "metadata": metadata_summary((proj.get("commonInstanceMetadata") or {}).get("items")),
                 "sharedVpc": proj.get("xpnProjectStatus"), "instances": []}
        if proj.get("xpnProjectStatus") == "HOST":
            res = g.attempt("Shared VPC service projects", pid, lambda: api.pages(f"{COMPUTE}/projects/{pid}/getXpnResources", "resources"), [])
            entry["sharedVpcServiceProjects"] = [r.get("id") for r in res]
        zones = g.attempt("VM instances", pid, lambda: api.pages(
            f"{COMPUTE}/projects/{pid}/aggregated/instances", "items", {"returnPartialSuccess": "true"}), [])
        for z in zones:
            for vm in z.get("instances", []):
                entry["instances"].append({
                    "name": vm.get("name"), "zone": (vm.get("zone") or "").split("/")[-1], "status": vm.get("status"),
                    "metadata": metadata_summary((vm.get("metadata") or {}).get("items")),
                    "serviceAccounts": [s.get("email") for s in vm.get("serviceAccounts", [])],
                })
        return [entry]

    def cloud_sql(p: dict) -> list[dict]:
        pid = p["projectId"]
        if not uses(p, "sqladmin.googleapis.com"):
            return []
        out = []
        for inst in g.attempt("Cloud SQL instances", pid, lambda: api.pages(f"{SQL}/projects/{pid}/instances", "items"), []):
            flags = (inst.get("settings") or {}).get("databaseFlags", [])
            entry = {
                "projectId": pid, "instance": inst.get("name"), "databaseVersion": inst.get("databaseVersion"),
                "region": inst.get("region"), "state": inst.get("state"),
                "iamAuthenticationFlags": {f["name"]: f.get("value") for f in flags if "iam" in f.get("name", "")},
                "users": None,
            }
            if inst.get("state") == "RUNNABLE":
                users = g.attempt("Cloud SQL users", f"{pid}/{inst.get('name')}", lambda: api.pages(
                    f"{SQL}/projects/{pid}/instances/{inst['name']}/users", "items"))
                if users is not None:
                    entry["users"] = [{"name": u.get("name"), "type": u.get("type", "BUILT_IN")} for u in users]
            else:
                entry["usersNote"] = "the instance isn't running, so its users can't be listed"
            out.append(entry)
        return out

    def gke(p: dict) -> list[dict]:
        pid = p["projectId"]
        if not uses(p, "container.googleapis.com"):
            return []
        data = g.attempt("GKE clusters", pid, lambda: api.get(f"{GKE}/projects/{pid}/locations/-/clusters"), {})
        return [{
            "projectId": pid, "name": c.get("name"), "location": c.get("location"), "status": c.get("status"),
            "version": c.get("currentMasterVersion"),
            "googleGroupsForRbac": (c.get("authenticatorGroupsConfig") or {}).get("securityGroup"),
            "workloadIdentityPool": (c.get("workloadIdentityConfig") or {}).get("workloadPool"),
            "privateEndpoint": (c.get("privateClusterConfig") or {}).get("enablePrivateEndpoint", False),
            "authorizedNetworks": (c.get("masterAuthorizedNetworksConfig") or {}).get("enabled", False),
            "legacyAbac": (c.get("legacyAbac") or {}).get("enabled", False),
            "clientCertificate": ((c.get("masterAuth") or {}).get("clientCertificateConfig") or {}).get("issueClientCertificate", False),
        } for c in (data or {}).get("clusters", [])]

    readers = [compute, cloud_sql, gke]
    results = pmap(lambda t: readers[t[0]](t[1]), [(i, p) for i in range(3) for p in projects])
    n = len(projects)
    vms, sql, clusters = flat(results[:n]), flat(results[n:2 * n]), flat(results[2 * n:])
    g.data.update({"compute": vms, "cloudSql": sql, "gkeClusters": clusters,
                   "note": "Kubernetes RBAC bindings live inside each cluster and aren't visible to this script."})
    run.say(f"  Access paths: {sum(len(c['instances']) for c in vms)} VMs in {len(vms)} projects, "
            f"{len(sql)} Cloud SQL instances, {len(clusters)} GKE clusters")
    return g


def read_guardrails(run: Run, api: Api, org: str, folders: list[dict], projects: list[dict]) -> Group:
    g = Group(run, "guardrails")
    parents = levels(org, folders, projects)
    constraints = ("iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers", "compute.requireOsLogin")
    set_policies = pmap(lambda parent: [{"attachedTo": parent, **pol} for pol in g.attempt(
        "org policies", parent, lambda: api.pages(f"{ORGPOLICY}/{parent}/policies", "policies"), [])], parents)
    effective = pmap(lambda c: g.attempt("effective org policy", f"{org}/{c}", lambda: api.get(
        f"{ORGPOLICY}/{org}/policies/{c}:getEffectivePolicy")), constraints)

    def access_policy(ap: dict) -> dict:
        return {
            "policy": ap.get("name"), "title": ap.get("title"), "scopes": ap.get("scopes", []),
            "servicePerimeters": g.attempt("service perimeters", ap["name"], lambda: api.pages(f"{ACM}/{ap['name']}/servicePerimeters", "servicePerimeters")),
            "accessLevels": g.attempt("access levels", ap["name"], lambda: api.pages(f"{ACM}/{ap['name']}/accessLevels", "accessLevels")),
        }

    perimeters = pmap(access_policy, g.attempt("access policies", org, lambda: api.pages(
        f"{ACM}/accessPolicies", "accessPolicies", {"parent": org}), []))
    g.data.update({
        "orgPolicies": flat(set_policies),
        "effectiveAtOrg": dict(zip(constraints, effective)),
        "customConstraints": g.attempt("custom constraints", org, lambda: api.pages(f"{ORGPOLICY}/{org}/customConstraints", "customConstraints")),
        "vpcServiceControls": perimeters,
    })
    run.say(f"  Guardrails: {len(g.data['orgPolicies'])} org policies set, {len(perimeters)} VPC Service Controls access policies")
    return g


def read_move_blockers(run: Run, api: Api, org: str, folders: list[dict], projects: list[dict]) -> Group:
    """Things tied to the organization or its folders, which don't move with projects."""
    g = Group(run, "move-blockers")
    org_and_folders = levels(org, folders)

    def sinks(parent: str) -> list[dict]:
        return [{"parent": parent, **{k: s.get(k) for k in ("name", "destination", "filter", "includeChildren", "disabled", "writerIdentity")}}
                for s in g.attempt("log sinks", parent, lambda: api.pages(f"{LOGGING}/{parent}/sinks", "sinks"), [])]

    def firewall_policies(parent: str) -> list[dict]:
        return [{"parent": parent, "name": p.get("name"), "displayName": p.get("displayName") or p.get("shortName"),
                 "rules": len(p.get("rules", [])), "associations": [a.get("attachmentTarget") for a in p.get("associations", [])]}
                for p in g.attempt("hierarchical firewall policies", parent, lambda: api.pages(
                    f"{COMPUTE}/locations/global/firewallPolicies", "items", {"parentId": parent}), [])]

    def tag(k: dict) -> dict:
        values = g.attempt("tag values", k["name"], lambda: api.pages(f"{CRM}/tagValues", "tagValues", {"parent": k["name"]}), [])
        return {"key": k.get("shortName"), "name": k.get("name"), "purpose": k.get("purpose"), "values": [v.get("shortName") for v in values]}

    def workload_pools(p: dict) -> list[dict]:
        pid, out = p["projectId"], []
        for pool in g.attempt("workload identity pools", pid, lambda: api.pages(
                f"{IAM}/v1/projects/{pid}/locations/global/workloadIdentityPools", "workloadIdentityPools"), []):
            gke = pool["name"].endswith(".svc.id.goog")  # GKE's own pool: it has no providers to list
            providers = [] if gke else g.attempt("workload identity providers", pool["name"], lambda: api.pages(
                f"{IAM}/v1/{pool['name']}/providers", "workloadIdentityPoolProviders"), [])
            out.append({"projectId": pid, "name": pool.get("name"), "state": pool.get("state"), "disabled": pool.get("disabled", False),
                        "gkeWorkloadIdentity": gke, "providers": [provider_summary(x) for x in providers]})
        return out

    def workforce_pool(pool: dict) -> dict:
        providers = g.attempt("workforce identity providers", pool["name"], lambda: api.pages(
            f"{IAM}/v1/{pool['name']}/providers", "workforcePoolProviders"), [])
        return {"name": pool.get("name"), "displayName": pool.get("displayName"), "state": pool.get("state"),
                "providers": [provider_summary(x) for x in providers]}

    roles = g.attempt("custom roles", org, lambda: api.pages(f"{IAM}/v1/{org}/roles", "roles", {"view": "FULL"}), [])
    log_sinks = flat(pmap(sinks, org_and_folders))
    fw = flat(pmap(firewall_policies, org_and_folders))
    tags = pmap(tag, g.attempt("tag keys", org, lambda: api.pages(f"{CRM}/tagKeys", "tagKeys", {"parent": org}), []))
    pools = flat(pmap(workload_pools, projects))
    wf = pmap(workforce_pool, g.attempt("workforce identity pools", org, lambda: api.pages(
        f"{IAM}/v1/locations/global/workforcePools", "workforcePools", {"parent": org}), []))
    g.data.update({
        "orgCustomRoles": [{"name": r.get("name"), "title": r.get("title"), "stage": r.get("stage"),
                            "deleted": r.get("deleted", False), "permissions": r.get("includedPermissions", [])} for r in roles],
        "orgAndFolderLogSinks": log_sinks, "firewallPolicies": fw, "tags": tags,
        "workloadIdentityPools": pools, "workforceIdentityPools": wf,
    })
    run.say(f"  Move blockers: {len(roles)} custom roles, {len(log_sinks)} org/folder log sinks, {len(fw)} firewall policies, "
            f"{len(tags)} tag keys, {len(pools)} workload and {len(wf)} workforce identity pools")
    return g


def provider_summary(p: dict) -> dict:
    """Identity providers keep their issuer, never client secrets or keys."""
    kind = next((k for k in ("oidc", "saml", "aws", "x509") if k in p), "unknown")
    return {"name": p.get("name"), "state": p.get("state"), "disabled": p.get("disabled", False), "type": kind,
            "issuer": (p.get("oidc") or {}).get("issuerUri") or ((p.get("aws") or {}).get("accountId")),
            "attributeCondition": p.get("attributeCondition")}


def read_notifications(run: Run, api: Api, org: str, folders: list[dict], projects: list[dict],
                       billing_accounts: list[dict], read_budgets: bool) -> Group:
    g = Group(run, "notifications")
    contacts = flat(pmap(lambda parent: [
        {"parent": parent, "email": c.get("email"), "categories": c.get("notificationCategorySubscriptions", []),
         "validationState": c.get("validationState")}
        for c in g.attempt("essential contacts", parent, lambda: api.pages(f"{CONTACTS}/{parent}/contacts", "contacts"), [])
    ], levels(org, folders, projects)))

    def monitoring(p: dict) -> tuple[list, list]:
        pid = p["projectId"]
        if p.get("enabledApis") is not None and "monitoring.googleapis.com" not in p["enabledApis"]:
            return [], []
        channels = [{"projectId": pid, **channel_summary(ch)} for ch in g.attempt(
            "alert channels", pid, lambda: api.pages(f"{MONITORING}/projects/{pid}/notificationChannels", "notificationChannels"), [])]
        alerts = [{"projectId": pid, "name": a.get("name"), "displayName": a.get("displayName"),
                   "enabled": a.get("enabled", True), "notificationChannels": a.get("notificationChannels", [])}
                  for a in g.attempt("alert policies", pid, lambda: api.pages(f"{MONITORING}/projects/{pid}/alertPolicies", "alertPolicies"), [])]
        return channels, alerts

    org_projects = {f"projects/{p['number']}" for p in projects}

    def budgets_of(acc: dict) -> list[dict]:
        out = []
        for b in g.attempt("budgets", acc["id"], lambda: api.pages(f"{BUDGETS}/billingAccounts/{acc['id']}/budgets", "budgets"), []):
            # A billing account shared with other organizations also has their budgets: keep only
            # budgets for this org's projects, and leave out the other projects they name.
            scoped = (b.get("budgetFilter") or {}).get("projects") or []
            if acc.get("sharedWithOtherOrganizations") is not False:
                if not set(scoped) & org_projects:
                    continue
                b["budgetFilter"]["projects"] = sorted(set(scoped) & org_projects)
            out.append({"billingAccount": acc["id"], **{k: b.get(k) for k in ("name", "displayName", "budgetFilter", "amount", "thresholdRules", "notificationsRule")}})
        return out

    mon = pmap(monitoring, projects)
    budgets = flat(pmap(budgets_of, billing_accounts)) if read_budgets else None
    if not read_budgets:
        g.not_collected.append({"what": "budgets", "where": "billing accounts",
                                "why": "skipped: no project with the Cloud Billing Budget API on was used"})
    g.data.update({"essentialContacts": contacts, "alertChannels": flat(c for c, _ in mon),
                   "alertPolicies": flat(a for _, a in mon), "budgets": budgets})
    run.say(f"  Notifications: {len(contacts)} essential contacts, {len(g.data['alertChannels'])} alert channels, "
            f"{'no' if budgets is None else len(budgets)} budgets")
    return g


def activity_filter(log: str, start: str, end: str) -> str:
    """People, and service accounts a person acted through. Google's service agents, and this
    script's own earlier runs, are left out."""
    who = "protoPayload.authenticationInfo.principalEmail"
    via = "protoPayload.authenticationInfo.serviceAccountDelegationInfo.firstPartyPrincipal.principalEmail"
    return (f'timestamp>="{start}" AND timestamp<"{end}" AND logName:"cloudaudit.googleapis.com%2F{log}" AND '
            f'(({who}:"@" AND NOT {who}:"gserviceaccount.com") OR ({via}:"@" AND NOT {via}:"gserviceaccount.com")) '
            f'AND NOT protoPayload.requestMetadata.callerSuppliedUserAgent:"{USER_AGENT_NAME}/"')


def time_slices(days: int, now: dt.datetime, n: int = 15) -> list[tuple[str, str]]:
    """The last `days` days in n equal windows, newest first."""
    n = max(1, min(n, days))
    step = dt.timedelta(days=days) / n
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return [((now - step * (i + 1)).strftime(fmt), (now - step * i).strftime(fmt)) for i in range(n)]


def read_activity(run: Run, api: Api, org: str, folders: list[dict], projects: list[dict], days: int,
                  minutes: float) -> Group:
    """Which people were active in the audit logs, and which service accounts they acted through.

    Kept as counts per principal, never as raw log entries. Service accounts acting on their own are
    left out: they don't depend on anyone's Workspace account, and Google's service agents alone can
    write tens of thousands of entries a day.

    Cloud Logging scans the logs slowly, a few seconds a page, so the period is read as several time
    windows in parallel, within a time budget. A window cut short by the budget is listed in
    `truncated` with how far back it got.
    """
    g = Group(run, "activity")
    now = dt.datetime.now(dt.timezone.utc)
    names = [org] + [f["name"] for f in folders] + [f"projects/{p['projectId']}" for p in projects]
    batches = [names[i:i + 50] for i in range(0, len(names), 50)]
    tasks = [(log, start, end, batch) for start, end in time_slices(days, now)
             for log in ("activity", "data_access") for batch in batches]
    deadline = time.time() + minutes * 60
    stats: dict[str, dict] = {}
    lock = threading.Lock()

    def work(task) -> list[dict]:
        """Reads one window; returns the parts cut short by the time limit."""
        log, start, end, batch = task
        body = {"resourceNames": batch, "filter": activity_filter(log, start, end), "pageSize": 1000, "orderBy": "timestamp desc"}
        oldest = end
        while True:
            if time.time() > deadline:
                return [{"log": log, "window": [start, end], "readBackTo": oldest, "resources": batch}]
            try:
                data = api.request("POST", f"{LOGGING}/entries:list", body=body,
                                   params={"fields": "entries(timestamp,logName,resource,protoPayload),nextPageToken"})
            except ApiError as e:
                # One project the user can't read fails the whole batch: read the batch one by one instead.
                if e.permission_denied and len(batch) > 1:
                    return flat(work((log, start, end, [r])) for r in batch)
                g.record(f"{log} audit logs", f"{', '.join(batch)} ({start} to {end})", e)
                return []
            with lock:
                for e in data.get("entries", []):
                    add_activity(stats, e, log)
                    oldest = e.get("timestamp") or oldest
            if not data.get("nextPageToken"):
                return []
            body["pageToken"] = data["nextPageToken"]

    # Many small windows keep 8 readers busy until the end; Cloud Logging allows 60 reads a minute.
    truncated = flat(pmap(work, tasks, workers=8))

    principals = []
    for email, s in sorted(stats.items()):
        principals.append({
            "principal": email,
            "type": "serviceAccount" if is_service_account(email) else "user",
            "entries": s["entries"], "firstSeen": s["first"], "lastSeen": s["last"], "byLog": dict(s["logs"]),
            "projects": sorted(s["projects"])[:50], "services": top(s["services"], 10), "methods": top(s["methods"], 10),
            "userAgents": top(s["agents"], 5), "impersonated": top(s["impersonated"], 10),
        })
    g.data.update({"days": days, "since": time_slices(days, now)[-1][0], "principals": principals, "truncated": truncated})
    users = sum(1 for p in principals if p["type"] == "user")
    run.say(f"  Activity: {users} people active in the last {days} days, and {len(principals) - users} service accounts they acted through"
            + (f" ({len(truncated)} of {len(tasks)} log windows cut short by the {minutes:g}-minute limit, see activity.json)" if truncated else ""))
    return g


def add_activity(stats: dict, entry: dict, log: str) -> None:
    pp = entry.get("protoPayload") or {}
    auth = pp.get("authenticationInfo") or {}
    email = auth.get("principalEmail")
    people = [w for w in ((d.get("firstPartyPrincipal") or {}).get("principalEmail")
                          for d in auth.get("serviceAccountDelegationInfo") or []) if w and not is_service_account(w)]
    agent = ((pp.get("requestMetadata") or {}).get("callerSuppliedUserAgent") or "")[:120]
    if not email or (is_service_account(email) and not people) or agent.startswith(USER_AGENT_NAME + "/"):
        return
    s = stats.setdefault(email, {"entries": 0, "first": None, "last": None, "logs": collections.Counter(),
                                 "projects": set(), "services": collections.Counter(), "methods": collections.Counter(),
                                 "agents": collections.Counter(), "impersonated": collections.Counter()})
    ts = entry.get("timestamp")
    s["entries"] += 1
    s["logs"][log] += 1
    if ts:
        s["first"] = min(filter(None, [s["first"], ts]))
        s["last"] = max(filter(None, [s["last"], ts]))
    pid = ((entry.get("resource") or {}).get("labels") or {}).get("project_id")
    if pid:
        s["projects"].add(pid)
    if pp.get("serviceName"):
        s["services"][pp["serviceName"]] += 1
    if pp.get("methodName"):
        s["methods"][pp["methodName"]] += 1
    if agent:
        s["agents"][agent] += 1
    # A person acting through a service account shows up as the first link of the delegation chain.
    for who in people:
        s["impersonated"][who] += 1


def is_service_account(email: str) -> bool:
    return email.endswith(".gserviceaccount.com")


# ─────────────────────────── The one optional change ───────────────────────────


def plan_budgets(run: Run, api: Api, projects: list[dict], args) -> tuple[bool, list[str]]:
    """Budgets need a quota project with the Budget API on. Use one that has it, or ask to turn it on in one.

    Returns whether budgets will be read, and the APIs this run turned on.
    """
    if args.skip_budgets:
        return False, []
    ready = [p["projectId"] for p in projects if p.get("enabledApis") and BUDGET_API in p["enabledApis"]]
    if args.api_project in ready:
        ready.remove(args.api_project)
        ready.insert(0, args.api_project)
    if ready:
        api.candidates[BUDGET_API] = ready[:5]
        run.say(f"  Budgets will be read through {ready[0]}, where the Cloud Billing Budget API is already on.")
        return True, []
    known = any(p.get("enabledApis") is not None for p in projects)
    run.say("\nBudgets can only be read through a project where the Cloud Billing Budget API is on, and "
            + ("none is." if known else "this account can't see which projects have it on."))
    run.say("Turning it on is free, changes only the project you pick, and you can turn it off afterwards.")
    if not run.confirm("Turn it on in one project? Type YES to pick a project, or NO to skip budgets:",
                       True if args.api_project and args.enable_budget_api else (False if args.assume_yes else None)):
        return False, []
    pid = args.api_project
    if not pid:
        candidates = sorted(p["projectId"] for p in projects if p.get("state") == "ACTIVE")
        for i, c in enumerate(candidates, 1):
            run.say(f"  {i}. {c}")
        while not pid:
            a = run.ask("Which project? Type its number:")
            if a.isdigit() and 1 <= int(a) <= len(candidates):
                pid = candidates[int(a) - 1]
    if not enable_api(run, api, pid, BUDGET_API):
        return False, []
    api.quota[BUDGET_API] = pid
    return True, [f"{BUDGET_API} in {pid}"]


def enable_api(run: Run, api: Api, project: str, service: str) -> bool:
    assert service not in NEVER_ENABLE
    try:
        op = api.request("POST", f"{SERVICEUSAGE}/projects/{project}/services/{service}:enable", body={})
        deadline = time.time() + 600
        while not op.get("done"):
            if time.time() > deadline:
                run.say("  Still waiting after 10 minutes; skipping budgets.")
                return False
            time.sleep(10)
            op = api.get(f"{SERVICEUSAGE}/{op['name']}")
        if op.get("error"):
            run.say(f"  Couldn't turn it on: {op['error'].get('message')}. Skipping budgets.")
            return False
    except ApiError as e:
        run.say(f"  Couldn't turn it on ({e.reason}: {e.message[:200]}). Skipping budgets.")
        return False
    run.say(f"  Turned on {service} in {project}.")
    time.sleep(30)  # let the change reach the Budget API before the first read
    return True


# ────────────────────────────────── Packaging ──────────────────────────────────


def plural(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def summary_text(org: dict, groups: dict[str, Group], run: Run) -> str:
    h, iam, ap = groups["hierarchy"].data, groups["iam"].data, groups["access-paths"].data
    gr, mb, nt, ac = groups["guardrails"].data, groups["move-blockers"].data, groups["notifications"].data, groups["activity"].data
    principals = iam.get("principals", [])
    kinds = {"user": "people", "group": "groups", "domain": "domain-wide grants", "serviceAccount": "service accounts",
             "principal": "workload identities", "principalSet": "workload identities",
             "projectOwner": "legacy bucket ACL members", "projectEditor": "legacy bucket ACL members",
             "projectViewer": "legacy bucket ACL members"}
    by_type = collections.Counter(kinds.get(p["type"].replace("deleted:", ""), "other") for p in principals)
    deleted = sum(1 for p in principals if p["type"].startswith("deleted:"))
    principal_counts = ", ".join(f"{by_type[k]} {k}" for k in [*dict.fromkeys(kinds.values()), "other"] if by_type[k])
    if deleted:
        principal_counts += f"; {deleted} of them deleted"
    user_domains = collections.Counter(p["domain"] for p in principals if p["type"] in ("user", "group") and p["domain"])
    org_admins = sorted({p["member"] for p in principals for gr_ in p["grants"]
                         if gr_["resource"] == org["name"] and gr_["role"] in ("roles/owner", "roles/resourcemanager.organizationAdmin")})
    drs = [p for p in gr.get("orgPolicies", []) if p["name"].endswith("/iam.allowedPolicyMemberDomains")]
    sql_iam = sum(1 for i in ap.get("cloudSql", []) for u in (i["users"] or []) if u["type"].startswith("CLOUD_IAM"))
    oslogin = sum(1 for c in ap.get("compute", []) if c["metadata"]["settings"].get("enable-oslogin", "").upper() == "TRUE")
    ssh = sum(c["metadata"]["ssh_keys"] + sum(i["metadata"]["ssh_keys"] for i in c["instances"]) for c in ap.get("compute", []))
    ap_gaps = groups["access-paths"].not_collected
    unread_service_projects = {n["where"] for n in ap_gaps if n["what"] == "Shared VPC service projects"}
    vpc_hosts = [c["projectId"] + (" (service projects not read)" if c["projectId"] in unread_service_projects
                                   else f" ({plural(len(c.get('sharedVpcServiceProjects', [])), 'service project')})")
                 for c in ap.get("compute", []) if c.get("sharedVpc") == "HOST"]
    unread_compute = sorted({n["where"] for n in ap_gaps if n["what"] == "Compute project settings"})
    vpc_text = ", ".join(vpc_hosts) or "none found"
    if unread_compute:
        vpc_text += f"; {plural(len(unread_compute), 'project')} not read: {', '.join(unread_compute)}"
    act = ac.get("principals", [])
    not_collected = sum(len(g.not_collected) for g in groups.values())

    def read(value, group: str, *whats: str) -> str:
        """A count, marked when any read behind it failed: a missing read must never look like zero."""
        gaps = [n for n in groups[group].not_collected if n["what"] in whats]
        if not gaps:
            return str(value)
        return "not read" if not value else f"{value} (partly read)"

    drs_text = ", ".join(p["attachedTo"] for p in drs) or "nowhere"
    lines = [
        f"Organization: {org.get('displayName')} ({org['name']}), customer ID {org.get('directoryCustomerId')}",
        f"Folders: {read(len(h.get('folders', [])), 'hierarchy', 'folders')}. "
        f"Projects: {read(len(h.get('projects', [])), 'hierarchy', 'projects')}, "
        f"{sum(1 for p in h.get('projects', []) if p.get('billingEnabled') is False)} without billing.",
        f"Billing accounts: {read(len(h.get('billingAccounts', [])), 'hierarchy', 'billing account', 'billing account IAM')}.",
        "",
        f"Principals in IAM: {principal_counts}"
        + (". IAM on individual resources wasn't read" if iam.get("resourcePolicies") is None else "")
        + (". Some IAM policies weren't read" if any(n["what"] == "IAM policy" for n in groups["iam"].not_collected) else "") + ".",
        f"Domains of users and groups: {', '.join(f'{d} ({n})' for d, n in user_domains.most_common()) or 'none'}.",
        f"Owners and organization admins at the org: {', '.join(org_admins) or 'none found'}.",
        f"Domain restricted sharing set at: {drs_text if drs or not any(n['what'] == 'org policies' for n in groups['guardrails'].not_collected) else 'not read'}.",
        "",
        f"VMs: {read(sum(len(c['instances']) for c in ap.get('compute', [])), 'access-paths', 'Compute project settings', 'VM instances')}; "
        f"projects with OS Login on: {oslogin}; SSH keys in metadata: {ssh}.",
        f"Shared VPC host projects: {vpc_text}.",
        f"Cloud SQL instances: {read(len(ap.get('cloudSql', [])), 'access-paths', 'Cloud SQL instances')}, with "
        f"{read(sql_iam, 'access-paths', 'Cloud SQL users')} IAM database users. "
        f"GKE clusters: {read(len(ap.get('gkeClusters', [])), 'access-paths', 'GKE clusters')}.",
        f"VPC Service Controls access policies: {read(len(gr.get('vpcServiceControls', [])), 'guardrails', 'access policies')}.",
        f"Custom roles: {read(len(mb.get('orgCustomRoles', [])), 'move-blockers', 'custom roles')}. "
        f"Org and folder log sinks: {read(len(mb.get('orgAndFolderLogSinks', [])), 'move-blockers', 'log sinks')}. "
        f"Firewall policies: {read(len(mb.get('firewallPolicies', [])), 'move-blockers', 'hierarchical firewall policies')}. "
        f"Tag keys: {read(len(mb.get('tags', [])), 'move-blockers', 'tag keys')}. "
        f"Identity pools: {read(len(mb.get('workloadIdentityPools', [])), 'move-blockers', 'workload identity pools')} workload, "
        f"{read(len(mb.get('workforceIdentityPools', [])), 'move-blockers', 'workforce identity pools')} workforce.",
        f"Essential contacts: {read(len(nt.get('essentialContacts', [])), 'notifications', 'essential contacts')}. "
        f"Alert channels: {read(len(nt.get('alertChannels', [])), 'notifications', 'alert channels')}. "
        f"Budgets: {'not read' if nt.get('budgets') is None else read(len(nt['budgets']), 'notifications', 'budgets')}.",
        f"Active in the last {ac.get('days')} days: "
        f"{read(sum(1 for p in act if p['type'] == 'user'), 'activity', 'activity audit logs', 'data_access audit logs')} people; "
        f"{plural(sum(1 for p in act if p['type'] == 'serviceAccount'), 'service account')} people acted through"
        + (" (the time limit cut some of the logs short)" if ac.get("truncated") else "") + ".",
        "",
        f"Reads not collected: {not_collected}" + (" (listed in manifest.json)" if not_collected else "") + ".",
    ]
    return "\n".join(lines) + "\n"


def git_info() -> dict:
    def g(*a: str) -> str:
        try:
            return subprocess.run(["git", "-C", str(HERE), *a], capture_output=True, text=True, check=True).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return ""
    return {"commit": g("rev-parse", "--short", "HEAD"), "branch": g("rev-parse", "--abbrev-ref", "HEAD"),
            "modified": bool(g("status", "--porcelain", "--untracked-files=no"))}


def package(run: Run, org: dict, groups: dict[str, Group], manifest: dict) -> Path:
    for name, g in groups.items():
        (run.out_dir / f"{name}.json").write_text(json.dumps(g.output(), indent=1, ensure_ascii=False), encoding="utf-8")
    summary = summary_text(org, groups, run)
    (run.out_dir / "summary.txt").write_text(summary, encoding="utf-8")
    (run.out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    run.log_file.close()
    zip_path = run.out_dir.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(run.out_dir.iterdir()):
            z.write(f, f"{run.out_dir.name}/{f.name}")
    return zip_path


# ──────────────────────────────────── Main ────────────────────────────────────


BANNER = """
GCP discovery for a Google Workspace migration · version {version}{commit}

This script reads your Google Cloud organization with your own sign-in, and
writes what it finds to a zip file in this session. It changes nothing.

It reads folders and projects, billing accounts, IAM at every level and on
individual resources, org policies, VPC Service Controls, OS Login and SSH key
settings, Cloud SQL IAM users, GKE clusters, custom roles, log sinks, firewall
policies, tags, identity pools, essential contacts, alert channels, budgets,
and who was active in the audit logs over the last {days} days.

It never writes secrets: metadata values, keys and tokens are left out, only
their names and counts. The zip holds the email addresses of people and
service accounts, so share it only through the form you were sent.

One optional question comes later: budgets can only be read through a project
where the Cloud Billing Budget API is on. If none has it on, you choose
whether to turn it on in one project, or skip budgets.
"""


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Read-only discovery of a Google Cloud organization.")
    p.add_argument("--org", help="organization ID; asked if you can see more than one")
    p.add_argument("--days", type=int, default=30, help="days of audit logs to read (default 30)")
    p.add_argument("--log-minutes", type=float, default=8, help="time limit for reading the audit logs (default 8)")
    p.add_argument("--api-project", help="project to read budgets through")
    p.add_argument("--enable-budget-api", action="store_true", help="with --api-project: turn the Budget API on there if it's off")
    p.add_argument("--skip-budgets", action="store_true", help="don't read budgets")
    p.add_argument("--yes", dest="assume_yes", action="store_true", help="don't ask to continue; answer NO to turning any API on")
    p.add_argument("--no-download", action="store_true", help="don't offer to download the zip at the end")
    p.add_argument("--out-dir", default=".", help="where to write the output (default: current directory)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if not shutil.which("gcloud"):
        print("gcloud isn't installed. Run this in Cloud Shell, or install the Google Cloud CLI.")
        return 1
    account = gcloud("auth", "list", "--filter=status:ACTIVE", "--format=value(account)").strip()
    if not account:
        print("No one is signed in to gcloud. Run:  gcloud auth login\nthen start this script again.")
        return 1
    acting_as = os.environ.get("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT") or gcloud(
        "config", "get-value", "auth/impersonate_service_account").strip()

    git = git_info()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    run = Run(Path(args.out_dir).resolve() / f"gcp-discovery-{stamp}", args.assume_yes)
    commit = f" (commit {git['commit']}{', ' + git['branch'] if git['branch'] else ''}{', modified' if git['modified'] else ''})" if git["commit"] else ""
    run.say(BANNER.format(version=VERSION, commit=commit, days=args.days))
    run.say(f"Signed in as: {account}" + (f", acting as {acting_as}" if acting_as else ""))
    if not run.confirm("\nType YES to continue, or NO to stop:", True if args.assume_yes else None):
        run.say("Stopped. Nothing was read.")
        run.log_file.close()
        shutil.rmtree(run.out_dir, ignore_errors=True)
        return 1

    api = Api(run)
    started = time.time()
    org = pick_org(run, api, args.org)
    org_name = org["name"]
    run.out_dir = run.out_dir.rename(run.out_dir.with_name(f"gcp-discovery-{org_name.split('/')[-1]}-{stamp}"))

    run.say("\nReading folders, projects and billing…")
    hierarchy, folders, projects = read_hierarchy(run, api, org)
    # If an API ever insists on a quota project, or is off in the project the credentials bill calls
    # to, calls are retried through the org's projects where it's already on.
    for p in projects:
        for svc in p.get("enabledApis") or []:
            if len(api.candidates.setdefault(svc, [])) < 3:
                api.candidates[svc].append(p["projectId"])
    access = access_check(run, api, org_name)
    read_budgets, enabled = plan_budgets(run, api, projects, args)  # the only question, asked before the long part

    run.say(f"\nReading the rest in parallel. The audit logs take longest: up to {args.log_minutes:g} minutes…")
    billing_accounts = hierarchy.data["billingAccounts"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            "activity": pool.submit(read_activity, run, api, org_name, folders, projects, args.days, args.log_minutes),
            "iam": pool.submit(read_iam, run, api, org_name, folders, projects),
            "access-paths": pool.submit(read_access_paths, run, api, projects),
            "guardrails": pool.submit(read_guardrails, run, api, org_name, folders, projects),
            "move-blockers": pool.submit(read_move_blockers, run, api, org_name, folders, projects),
            "notifications": pool.submit(read_notifications, run, api, org_name, folders, projects, billing_accounts, read_budgets),
        }
        results = {name: f.result() for name, f in futures.items()}
    groups: dict[str, Group] = {"hierarchy": hierarchy, **{k: results[k] for k in
                                ("iam", "access-paths", "guardrails", "move-blockers", "notifications", "activity")}}

    manifest = {
        "script": "gcp_discovery", "version": VERSION, **git,
        "startedAt": run.started, "finishedAt": utcnow(), "durationSeconds": round(time.time() - started),
        "account": account, "actingAs": acting_as or None, "organization": org_name,
        "options": {"days": args.days, "logMinutes": args.log_minutes},
        "apisTurnedOn": enabled, "quotaProjectsUsed": dict(api.quota), "apiCalls": api.calls,
        "accessCheck": access, "missingPermissions": sorted(run.missing_permissions),
        "notCollected": {name: g.not_collected for name, g in groups.items() if g.not_collected},
        "python": sys.version.split()[0],
    }
    zip_path = package(run, org, groups, manifest)
    print("\n" + (run.out_dir / "summary.txt").read_text(encoding="utf-8"))
    print(f"Done in {manifest['durationSeconds'] // 60} min {manifest['durationSeconds'] % 60} s. The zip is:\n  {zip_path}\n")
    if shutil.which("cloudshell") and not args.no_download:
        print("Cloud Shell deletes it when this session ends, so download it now.")
        if args.assume_yes or input("Download it to your computer now? Type YES or NO: ").strip().upper() == "YES":
            subprocess.run(["cloudshell", "download", str(zip_path)])
    else:
        print("Upload this zip in the form.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(130)
