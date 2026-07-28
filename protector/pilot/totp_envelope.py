"""Structural parsing and keyed authentication for encrypted TOTP seeds."""

from __future__ import annotations

import base64
import binascii
import hmac
import secrets
import string

TOTP_ENVELOPE_PREFIX = "totp:v1:"
TOTP_ENVELOPE_VERSION = b"\x01"
TOTP_NONCE_BYTES = 16
TOTP_SECRET_BYTES = 32
TOTP_TAG_BYTES = 32
TOTP_ENVELOPE_BYTES = 1 + TOTP_NONCE_BYTES + TOTP_SECRET_BYTES + TOTP_TAG_BYTES
TOTP_ENCODED_BYTES = 108
TOTP_STORED_LENGTH = len(TOTP_ENVELOPE_PREFIX) + TOTP_ENCODED_BYTES
TOTP_URLSAFE_CHARACTERS = frozenset(string.ascii_letters + string.digits + "-_")
TOTP_ROTATION_INSTRUCTION = (
    "legacy, malformed, unsupported, or unauthenticated TOTP seed detected; "
    "rotate TOTP seeds before upgrading or fix encrypted rows, and store only "
    "authenticated totp:v1 envelopes"
)
TOTP_MIGRATION_KEY_INSTRUCTION = (
    "existing TOTP envelopes require PILOT_TOTP_ENCRYPTION_KEY or "
    "/run/secrets/totp_encryption_key for authenticated migration"
)

_AAD = b"kuzet-ai:totp-seed:v1"
_VERSION_SECOND_CHARACTERS = "QRSTUVWXYZabcdef"


def _portable_character_check() -> str:
    remainder = "substr(totp_secret_encrypted, 9)"
    for character in string.ascii_letters + string.digits + "-_":
        remainder = f"replace({remainder}, '{character}', '')"
    return f"length({remainder}) = 0"


PORTABLE_TOTP_ENVELOPE_CHECK = (
    "totp_secret_encrypted IS NULL OR ("
    f"length(totp_secret_encrypted) = {TOTP_STORED_LENGTH} AND "
    f"substr(totp_secret_encrypted, 1, 8) = '{TOTP_ENVELOPE_PREFIX}' AND "
    f"{_portable_character_check()} AND "
    "substr(totp_secret_encrypted, 9, 1) = 'A' AND "
    f"substr(totp_secret_encrypted, 10, 1) IN "
    f"({', '.join(repr(character) for character in _VERSION_SECOND_CHARACTERS)})"
    ")"
)
SQLITE_TOTP_ENVELOPE_PREDICATE = (
    f"length(totp_secret_encrypted) = {TOTP_STORED_LENGTH} AND "
    f"substr(totp_secret_encrypted, 1, 8) = '{TOTP_ENVELOPE_PREFIX}' AND "
    "substr(totp_secret_encrypted, 9) NOT GLOB '*[^A-Za-z0-9_-]*' AND "
    "substr(totp_secret_encrypted, 9, 1) = 'A' AND "
    f"instr('{_VERSION_SECOND_CHARACTERS}', "
    "substr(totp_secret_encrypted, 10, 1)) > 0"
)
POSTGRESQL_TOTP_ENVELOPE_PREDICATE = (
    f"length(totp_secret_encrypted) = {TOTP_STORED_LENGTH} AND "
    f"left(totp_secret_encrypted, 8) = '{TOTP_ENVELOPE_PREFIX}' AND "
    f"substring(totp_secret_encrypted FROM 9) ~ "
    f"'^[A-Za-z0-9_-]{{{TOTP_ENCODED_BYTES}}}$' AND "
    "octet_length(decode(translate(substring(totp_secret_encrypted FROM 9), "
    "'-_', '+/'), 'base64')) = "
    f"{TOTP_ENVELOPE_BYTES} AND "
    "get_byte(decode(translate(substring(totp_secret_encrypted FROM 9), "
    "'-_', '+/'), 'base64'), 0) = 1"
)


def encode_totp_envelope(authenticated_envelope: bytes) -> str:
    if (
        len(authenticated_envelope) != TOTP_ENVELOPE_BYTES
        or authenticated_envelope[:1] != TOTP_ENVELOPE_VERSION
    ):
        raise ValueError("invalid encrypted TOTP envelope")
    return TOTP_ENVELOPE_PREFIX + base64.urlsafe_b64encode(authenticated_envelope).decode()


def parse_totp_envelope(value: str) -> bytes:
    """Parse the strongest keyless structure without claiming authenticity."""

    if not value.startswith(TOTP_ENVELOPE_PREFIX):
        raise ValueError(TOTP_ROTATION_INSTRUCTION)
    encoded = value.removeprefix(TOTP_ENVELOPE_PREFIX)
    if (
        len(encoded) != TOTP_ENCODED_BYTES
        or any(character not in TOTP_URLSAFE_CHARACTERS for character in encoded)
    ):
        raise ValueError(TOTP_ROTATION_INSTRUCTION)
    try:
        envelope = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(TOTP_ROTATION_INSTRUCTION) from exc
    if (
        len(envelope) != TOTP_ENVELOPE_BYTES
        or envelope[:1] != TOTP_ENVELOPE_VERSION
    ):
        raise ValueError(TOTP_ROTATION_INSTRUCTION)
    return envelope


class TotpEnvelopeProtector:
    """Encrypt, authenticate, and decrypt fixed-size TOTP seed envelopes."""

    def __init__(self, encryption_key: str) -> None:
        try:
            key = base64.b64decode(encryption_key, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("TOTP encryption key must be URL-safe base64") from exc
        if len(key) != 32:
            raise ValueError("TOTP encryption key must decode to exactly 32 bytes")
        self._encryption_key = hmac.digest(key, b"encryption", "sha256")
        self._authentication_key = hmac.digest(key, b"authentication", "sha256")

    def encrypt_secret(self, secret: str) -> str:
        try:
            plaintext = secret.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("TOTP secret must contain only ASCII characters") from exc
        if len(plaintext) != TOTP_SECRET_BYTES:
            raise ValueError("TOTP secret must encode to exactly 32 bytes")
        nonce = secrets.token_bytes(TOTP_NONCE_BYTES)
        ciphertext = self._xor_stream(plaintext, nonce)
        authenticated = TOTP_ENVELOPE_VERSION + nonce + ciphertext
        tag = hmac.digest(
            self._authentication_key,
            _AAD + authenticated,
            "sha256",
        )
        return encode_totp_envelope(authenticated + tag)

    def authenticate(self, encrypted: str) -> bytes:
        """Return version/nonce/ciphertext only after constant-time MAC verification."""

        try:
            envelope = parse_totp_envelope(encrypted)
            authenticated = envelope[:-TOTP_TAG_BYTES]
            provided_tag = envelope[-TOTP_TAG_BYTES:]
            expected_tag = hmac.digest(
                self._authentication_key,
                _AAD + authenticated,
                "sha256",
            )
            if not hmac.compare_digest(provided_tag, expected_tag):
                raise ValueError
            return authenticated
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid encrypted TOTP secret") from exc

    def decrypt_secret(self, encrypted: str) -> str:
        authenticated = self.authenticate(encrypted)
        nonce = authenticated[1 : 1 + TOTP_NONCE_BYTES]
        ciphertext = authenticated[1 + TOTP_NONCE_BYTES :]
        try:
            return self._xor_stream(ciphertext, nonce).decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid encrypted TOTP secret") from exc

    def _xor_stream(self, value: bytes, nonce: bytes) -> bytes:
        output = bytearray()
        for counter in range((len(value) + 31) // 32):
            output.extend(
                hmac.digest(
                    self._encryption_key,
                    _AAD + nonce + counter.to_bytes(4, "big"),
                    "sha256",
                )
            )
        return bytes(left ^ right for left, right in zip(value, output, strict=False))

    def __repr__(self) -> str:
        return "TotpEnvelopeProtector(configured=True)"
