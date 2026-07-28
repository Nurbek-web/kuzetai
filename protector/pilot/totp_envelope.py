"""Versioned structural boundary for encrypted TOTP seed envelopes."""

from __future__ import annotations

import base64
import binascii

TOTP_ENVELOPE_PREFIX = "totp:v1:"
TOTP_ENVELOPE_VERSION = b"\x01"
TOTP_ENVELOPE_MINIMUM_BYTES = 1 + 16 + 1 + 32
TOTP_ROTATION_INSTRUCTION = (
    "legacy or invalid TOTP seed detected; rotate TOTP seeds before upgrading "
    "and store only totp:v1 encrypted envelopes"
)


def encode_totp_envelope(authenticated_envelope: bytes) -> str:
    if (
        len(authenticated_envelope) < TOTP_ENVELOPE_MINIMUM_BYTES
        or authenticated_envelope[:1] != TOTP_ENVELOPE_VERSION
    ):
        raise ValueError("invalid encrypted TOTP envelope")
    return TOTP_ENVELOPE_PREFIX + base64.urlsafe_b64encode(authenticated_envelope).decode()


def decode_totp_envelope(value: str) -> bytes:
    if not value.startswith(TOTP_ENVELOPE_PREFIX):
        raise ValueError(TOTP_ROTATION_INSTRUCTION)
    encoded = value.removeprefix(TOTP_ENVELOPE_PREFIX)
    try:
        envelope = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(TOTP_ROTATION_INSTRUCTION) from exc
    if (
        len(envelope) < TOTP_ENVELOPE_MINIMUM_BYTES
        or envelope[:1] != TOTP_ENVELOPE_VERSION
    ):
        raise ValueError(TOTP_ROTATION_INSTRUCTION)
    return envelope


def validate_totp_envelope(value: str) -> None:
    decode_totp_envelope(value)
