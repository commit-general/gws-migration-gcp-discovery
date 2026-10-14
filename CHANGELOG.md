# Changelog

## 1.0.0

First release.

- Reads the organization with the user's own sign-in and no quota project, so no API has to be turned on anywhere.
- The one optional change: turning on the Cloud Billing Budget API in one project, after the user types YES, when no project has it on. Skipped otherwise.
- Reads in parallel, and paces itself to the per-minute quotas reported by Google's APIs.
- Works whatever APIs are on in the organization's projects; reads that can't be done are listed in the manifest.
- Writes one JSON file per area, a summary, a run log and a manifest, in one zip.
- The summary lists Shared VPC host projects and how many service projects each has.
