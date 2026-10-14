#!/usr/bin/env bash
# Starts the discovery. All the logic is in gcp_discovery.py, next to this file.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1  # the only questions are the script's own

if ! command -v gcloud >/dev/null 2>&1; then
  echo "gcloud isn't installed. Run this in Cloud Shell, or install the Google Cloud CLI." >&2
  exit 1
fi

# Any Python 3.8+ works. Without one on the PATH, use the Python that ships with gcloud.
py="$(command -v python3 || true)"
if [ -z "$py" ]; then
  py="$(gcloud info --format='value(basic.python_location)')"
fi

exec "$py" "$here/gcp_discovery.py" "$@"
