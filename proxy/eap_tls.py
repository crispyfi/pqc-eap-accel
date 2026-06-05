"""
eap_tls.py — Isolated EAP-TLS (RFC 5216, Type 13) fragmentation core.

This module is deliberately dependency-free: no sockets, no RADIUS, no I/O.
It deals only in bytes and decisions, so it ports cleanly to a C
implementation later.

The two jobs it does:
  1. REASSEMBLY  — accumulate inbound EAP-TLS fragments into a complete
                   TLS message ("record group"), per the L/M bit rules.
  2. FRAGMENTATION — chop a complete TLS message back into EAP-TLS
                   fragments of a target size for the other direction.

It treats the TLS payload as fully OPAQUE. It never parses, validates, or
alters a single byte of the TLS records — it only reads/writes the EAP-TLS
framing (the EAP header, the flags octet, and the optional 4-octet TLS
Message Length) that wraps them. This is what keeps the end-to-end TLS
handshake transcript intact through the proxy.

EAP packet layout (RFC 3748 §4):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |   Flags       |   TLS Message Length ...      |  (Type=13)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   TLS Message Length (cont)   |   TLS Data ...                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Flags octet (RFC 5216 §3.1):
    0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+
   |L M S R R R R R|
   +-+-+-+-+-+-+-+-+
   L = Length included  (4-octet TLS Message Length present; MUST be set on
                         the first fragment of a fragmented message)
   M = More fragments   (set on all but the last fragment)
   S = EAP-TLS Start    (server -> peer only)
"""

from dataclasses import dataclass, field
from enum import IntEnum


# --- EAP constants (RFC 3748) ---------------------------------------------

class EapCode(IntEnum):
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4


EAP_TYPE_TLS = 13           # RFC 5216
EAP_HEADER_LEN = 4          # Code(1) + Identifier(1) + Length(2)
EAP_TLS_FLAGS_LEN = 1       # Flags octet
EAP_TLS_MSGLEN_LEN = 4      # optional TLS Message Length field

# --- Flag bit masks (RFC 5216 §3.1) ---------------------------------------

FLAG_LENGTH_INCLUDED = 0x80   # L
FLAG_MORE_FRAGMENTS = 0x40    # M
FLAG_START = 0x20             # S
# remaining bits 0x1F are reserved; MUST be zero on send, ignored on receipt


class EapTlsError(Exception):
    """Malformed EAP-TLS framing. Never raised for TLS-payload content —
    the payload is opaque and never inspected."""


# --- Parsed view of a single EAP-TLS packet -------------------------------

@dataclass
class EapTlsPacket:
    """A single decoded EAP-TLS packet (one fragment, or a whole unfragmented
    message). `tls_data` is the opaque TLS payload carried in this packet."""
    code: int
    identifier: int
    length_included: bool
    more_fragments: bool
    start: bool
    tls_message_length: int | None   # only meaningful when length_included
    tls_data: bytes                  # opaque

    @property
    def is_ack(self) -> bool:
        """An EAP-TLS fragment ACK is a packet with no TLS data and no flags
        of substance (no L/M/S) — i.e. an empty EAP-TLS packet (RFC 5216
        §2.1.5)."""
        return (
            not self.length_included
            and not self.more_fragments
            and not self.start
            and len(self.tls_data) == 0
        )


def parse(packet: bytes) -> EapTlsPacket:
    """Decode an EAP-TLS packet from raw EAP bytes. Validates only the
    framing; the TLS data is taken verbatim."""
    if len(packet) < EAP_HEADER_LEN + 1:
        raise EapTlsError(f"EAP-TLS packet too short: {len(packet)} bytes")

    code = packet[0]
    identifier = packet[1]
    declared_len = int.from_bytes(packet[2:4], "big")
    eap_type = packet[4]

    if eap_type != EAP_TYPE_TLS:
        raise EapTlsError(f"not EAP-TLS: type={eap_type}")
    if declared_len != len(packet):
        # tolerate trailing link-layer padding per RFC 3748, but flag shrinkage
        if declared_len > len(packet):
            raise EapTlsError(
                f"EAP Length {declared_len} exceeds buffer {len(packet)}"
            )

    flags = packet[5]
    length_included = bool(flags & FLAG_LENGTH_INCLUDED)
    more_fragments = bool(flags & FLAG_MORE_FRAGMENTS)
    start = bool(flags & FLAG_START)

    offset = 6
    tls_message_length = None
    if length_included:
        if len(packet) < offset + EAP_TLS_MSGLEN_LEN:
            raise EapTlsError("L bit set but TLS Message Length truncated")
        tls_message_length = int.from_bytes(
            packet[offset:offset + EAP_TLS_MSGLEN_LEN], "big"
        )
        offset += EAP_TLS_MSGLEN_LEN

    # TLS data runs to the end of the declared EAP length (ignore padding).
    tls_data = packet[offset:declared_len] if declared_len else packet[offset:]

    return EapTlsPacket(
        code=code,
        identifier=identifier,
        length_included=length_included,
        more_fragments=more_fragments,
        start=start,
        tls_message_length=tls_message_length,
        tls_data=tls_data,
    )


def build(code: int, identifier: int, tls_data: bytes,
          more_fragments: bool = False,
          tls_message_length: int | None = None,
          start: bool = False) -> bytes:
    """Encode a single EAP-TLS packet. Set `tls_message_length` (which sets
    the L bit) only on the first fragment of a fragmented message."""
    flags = 0
    if tls_message_length is not None:
        flags |= FLAG_LENGTH_INCLUDED
    if more_fragments:
        flags |= FLAG_MORE_FRAGMENTS
    if start:
        flags |= FLAG_START

    body = bytes([EAP_TYPE_TLS, flags])
    if tls_message_length is not None:
        body += tls_message_length.to_bytes(EAP_TLS_MSGLEN_LEN, "big")
    body += tls_data

    total_len = EAP_HEADER_LEN + len(body)
    header = bytes([code, identifier]) + total_len.to_bytes(2, "big")
    return header + body


def build_ack(code: int, identifier: int) -> bytes:
    """Build an empty EAP-TLS packet to serve as a fragment ACK (RFC 5216
    §2.1.5). The Identifier MUST echo the fragment being acknowledged."""
    return build(code=code, identifier=identifier, tls_data=b"")


# --- Reassembly state machine ---------------------------------------------

class ReassemblyState(IntEnum):
    IDLE = 0          # nothing buffered
    IN_PROGRESS = 1   # received first fragment (M set), awaiting more
    COMPLETE = 2      # full message reassembled, ready to hand off


@dataclass
class Reassembler:
    """Accumulates inbound EAP-TLS fragments into one complete TLS message.

    Used independently for EACH direction by the proxy:
      - one Reassembler for supplicant -> server fragments
      - one Reassembler for server -> supplicant fragments

    `max_message_len` guards against reassembly-lockup / DoS (RFC 5216 §3.1
    advises a max group size). Set generously for PQC-sized chains via config.
    """
    max_message_len: int = 256 * 1024
    state: ReassemblyState = ReassemblyState.IDLE
    _buffer: bytearray = field(default_factory=bytearray)
    _expected_len: int | None = None
    fragment_count: int = 0

    def reset(self) -> None:
        self.state = ReassemblyState.IDLE
        self._buffer = bytearray()
        self._expected_len = None
        self.fragment_count = 0

    def ingest(self, pkt: EapTlsPacket) -> bytes | None:
        """Feed one parsed fragment in. Returns the complete reassembled TLS
        message (bytes) when the final fragment arrives, else None (meaning:
        more fragments expected, caller should emit a fragment ACK).

        ACK packets (empty) are not data fragments and are ignored here — the
        caller handles ACK semantics at the session layer."""
        if pkt.is_ack:
            return None

        # First fragment of a (possibly fragmented) message.
        if self.state in (ReassemblyState.IDLE, ReassemblyState.COMPLETE):
            self.reset()
            if pkt.length_included and pkt.tls_message_length is not None:
                self._expected_len = pkt.tls_message_length
                if self._expected_len > self.max_message_len:
                    raise EapTlsError(
                        f"declared TLS message length {self._expected_len} "
                        f"exceeds max {self.max_message_len}"
                    )
            self.state = ReassemblyState.IN_PROGRESS

        self._buffer += pkt.tls_data
        self.fragment_count += 1

        if len(self._buffer) > self.max_message_len:
            raise EapTlsError("reassembly buffer exceeded max message length")

        if pkt.more_fragments:
            # Not done; caller must ACK and wait for the next fragment.
            return None

        # Last fragment (M not set) -> message complete.
        if self._expected_len is not None and len(self._buffer) != self._expected_len:
            # Not fatal in practice (some stacks omit/misreport), but worth
            # surfacing. We trust the M-bit as the authoritative end marker.
            pass

        self.state = ReassemblyState.COMPLETE
        return bytes(self._buffer)


# --- Fragmentation helper --------------------------------------------------

def fragment(tls_message: bytes, fragment_size: int) -> list[bytes]:
    """Split a complete opaque TLS message into payload chunks no larger than
    `fragment_size`. Returns a list of TLS-data byte chunks (NOT yet wrapped
    in EAP framing — the caller wraps them, setting L on the first and M on
    all but the last, and assigning Identifiers).

    `fragment_size` here is the TLS-data budget per EAP-TLS packet, i.e. the
    space left after the EAP header, flags octet, and (on the first fragment)
    the 4-octet TLS Message Length.

    A single chunk return means the message fits in one packet (no L/M needed
    unless the caller chooses to include length)."""
    if fragment_size <= 0:
        raise EapTlsError("fragment_size must be positive")
    if not tls_message:
        return [b""]
    return [
        tls_message[i:i + fragment_size]
        for i in range(0, len(tls_message), fragment_size)
    ]
