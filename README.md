# Google Cloud discovery for a Workspace migration

A read-only script that describes a Google Cloud organization before its
Google Workspace moves to a new account: who has access to what, and what is
tied to the company's accounts and domain. It runs with the user's own
sign-in, in Cloud Shell, and writes one zip.

## Run it

Open it in Cloud Shell, with a step-by-step tutorial beside the terminal:

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/commit-general/gws-migration-gcp-discovery&cloudshell_git_branch=release/v1&cloudshell_tutorial=tutorial.md)

Or on any machine with the Google Cloud CLI and Python 3.8 or later:

```bash
git clone -b release/v1 https://github.com/commit-general/gws-migration-gcp-discovery
cd gws-migration-gcp-discovery
gcloud auth login
./gcp_discovery.sh
```

`./gcp_discovery.sh --help` lists the options, such as `--org` and `--days`.

## What it reads

| Area | What | File |
|---|---|---|
| Hierarchy and billing | The organization and its customer ID, folders, projects, the APIs each project has on, billing accounts and their IAM | `hierarchy.json` |
| IAM | IAM policies on the organization, every folder and project, and individual resources (buckets, datasets, service accounts, secrets…); deny policies; audit-log exemptions; an index of every principal and where it holds which role | `iam.json` |
| Access paths | OS Login and SSH key settings on projects and VMs, Shared VPC host projects and their service projects, Cloud SQL instances and their IAM database users, GKE clusters and how people sign in to them | `access-paths.json` |
| Guardrails | Organization policies at every level, including domain restricted sharing; custom constraints; VPC Service Controls | `guardrails.json` |
| What doesn't move with projects | Organization custom roles, org and folder log sinks, hierarchical firewall policies, tags, workload and workforce identity pools | `move-blockers.json` |
| Notifications | Essential contacts, alert channels and policies, budgets | `notifications.json` |
| Activity | Who was active in the Admin Activity and Data Access audit logs over the last 30 days, as counts per person or service account | `activity.json` |

The zip also holds `summary.txt`, the run log, and `manifest.json`: the
script's version and commit, the access check, the permissions that were
missing, and every read that couldn't be collected.

## What it never does

- **Changes nothing.** It only lists, gets and searches. Calls carry no quota
  project: they count against the Google Cloud CLI's own project, so it
  doesn't matter which APIs are on in your projects. Compute Engine and GKE
  are the exception: they're read only where their API is on, and a project
  where it's off is treated as not using them. If an API ever insists on a
  quota project, the call is retried through one of your projects where that
  API is already on.
- **One optional exception.** Budgets can only be read through a project where
  the Cloud Billing Budget API is on. If no project has it on, the script asks
  whether to turn it on in one project the user picks. Turning it on is free.
  Answering NO skips budgets. Compute Engine, Cloud SQL and Kubernetes Engine
  APIs are never turned on: they're read only in projects where they're
  already on.
- **No secrets.** Metadata values, startup scripts, SSH public keys, webhook
  URLs, client secrets and tokens are never written: only their names and
  counts. SSH keys keep their usernames, because those show whose access
  depends on an account name.
- **No raw logs.** Audit logs are reduced to counts per principal: entries,
  first and last seen, top services, methods and user agents, and who acted
  through a service account.
- **No other organizations' data.** A billing account can also pay for other
  organizations' projects, for example through a reseller. Then only budgets
  for this organization's projects are kept, and the other projects aren't
  named.
- **Nothing leaves the session** except the zip the user downloads. No service
  account or key is created.

The zip does hold personal data: the email addresses of people and service
accounts in IAM, contacts and audit logs.

## Roles

Ask for these roles before the run: in some companies granting them needs
a change approval. Run it as a person (`gcloud auth login`), not as a service
account. A service
account bills API calls to its own project, so any read whose API is off there
comes back as a gap.

The access check at the start shows which areas a user can't read, and the
role that would fix it. Full coverage takes these predefined roles, granted on
the organization unless noted. All are read-only.

| Role | Covers |
|---|---|
| `roles/browser` | Folders and projects |
| `roles/iam.securityReviewer` | IAM policies at every level, deny policy list, organization custom roles, audit logs including Data Access, log sinks, essential contacts, alert channels and policies, identity pools, Cloud SQL users, GKE clusters, enabled APIs |
| `roles/cloudasset.viewer` | IAM on individual resources |
| `roles/orgpolicy.policyViewer` | Organization policies and custom constraints |
| `roles/accesscontextmanager.policyReader` | VPC Service Controls |
| `roles/compute.viewer` | OS Login and SSH key settings, VMs, Shared VPC, hierarchical firewall policies |
| `roles/iam.denyReviewer` | The rules inside deny policies (without it, only their names) |
| `roles/billing.viewer`, on each billing account | Billing accounts, their IAM, and budgets |
| `roles/serviceusage.serviceUsageConsumer`, on the project budgets are read through | Budgets. `roles/serviceusage.serviceUsageAdmin` there if the script is to turn the Budget API on |

An organization admin usually has most of these through
`roles/resourcemanager.organizationAdmin` or Owner.

## Limits

- Kubernetes RBAC bindings live inside each cluster; the script lists the
  clusters, not who can use them.
- It can't see VPNs, bastion hosts, or internal tools that use Google sign-in.
  The form asks about those.
- Data Access audit logs appear only where they're turned on. Cloud Logging
  scans logs slowly, so the script reads them for at most 8 minutes
  (`--log-minutes` changes it). `activity.json` lists any time window that was
  cut short, and how far back it got.
- Audit logs show people, and service accounts a person acted through.
  Service accounts acting on their own are left out.
- Without a quota project, calls count against per-minute quotas per user
  (deny policies: 10 reads a minute, about 2 minutes for 20 projects). Reads
  run in parallel and slow down to fit those quotas, so large organizations
  take longer. A run takes about 10 minutes, longer in organizations with
  hundreds of projects; most of it is the audit logs.

## Development

```bash
python3 -m unittest discover -s tests
```

Customers run only the protected `release/v1` branch; changes reach it through
reviewed pull requests. The script prints its version and commit at the start
and writes both to the manifest.
