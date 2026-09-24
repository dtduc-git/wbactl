"""Pinned Web Bot Auth spec facts.

Spec revision: draft-ietf-webbotauth-httpsig-protocol-00 (2026-09-01).
Everything in this module is version-pinned; bump deliberately when the draft
changes and update the conformance fixtures in the same commit.
"""

DRAFT = "draft-ietf-webbotauth-httpsig-protocol-00"
DRAFT_DATE = "2026-09-01"
TAG = "web-bot-auth"
ALG = "ed25519"
WELL_KNOWN_PATH = "/.well-known/http-message-signatures-directory"
REQUIRED_COMPONENTS = ("@authority", "signature-agent")
DEFAULT_LIFETIME_SECONDS = 300
CLOCK_SKEW_SECONDS = 60
MAX_SIGNATURE_AGE_SECONDS = 24 * 60 * 60
MAX_DIRECTORY_BYTES = 64 * 1024
