"""Central configuration for CyberScore Lite.

Every network limit lives here so the tool's footprint on a target is easy to
review: a handful of DNS queries, at most three TLS handshakes and a small,
hard-capped number of HTTP requests on ports 80/443 only.
"""

from __future__ import annotations

APP_NAME = "CyberScore Lite"
VERSION = "1.0.0"
USER_AGENT = f"CyberScoreLite/{VERSION} (non-intrusive security posture check)"

# --- DNS -------------------------------------------------------------------
DNS_TIMEOUT_SECONDS = 3.0  # per nameserver attempt
DNS_LIFETIME_SECONDS = 6.0  # total budget for one query, retries included
DNS_MAX_TREE_WALK = 4  # parent domains climbed for DMARC / CAA discovery

# --- Network connections ---------------------------------------------------
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 8.0
HTTP_PORT = 80
HTTPS_PORT = 443
# The user can never choose a port, scheme or path: only these are reachable.
ALLOWED_PORTS = frozenset({HTTP_PORT, HTTPS_PORT})
MAX_TARGET_ADDRESSES = 8  # resolved addresses kept (all must be public)
MAX_CONNECT_ATTEMPTS = 2  # distinct pinned addresses tried per connection

# --- HTTP ------------------------------------------------------------------
MAX_HTTP_REQUESTS = 8  # hard budget for the whole HTTP module
MAX_HTTP_REDIRECTS = 3  # only same-host HTTPS redirects are followed
MAX_REDIRECT_PATH_LENGTH = 1024
MAX_EVIDENCE_VALUE_LENGTH = 1024  # header values are truncated in evidence

# --- Evaluation thresholds -------------------------------------------------
CERT_EXPIRY_WARNING_DAYS = 30
# 6 months: commonly used minimum (e.g. Mozilla HTTP Observatory).
HSTS_MIN_MAX_AGE_SECONDS = 15_768_000
SPF_MAX_DNS_LOOKUPS = 10  # RFC 7208 section 4.6.4

# --- Scoring ---------------------------------------------------------------
MIN_RELIABLE_COVERAGE_PERCENT = 80.0

# --- UI --------------------------------------------------------------------
ASSESSMENT_COOLDOWN_SECONDS = 15
