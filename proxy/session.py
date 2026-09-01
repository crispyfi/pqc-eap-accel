"""
session.py — Per-authentication session state for the bidirectional proxy.

Each EAP-TLS authentication in flight gets one Session. It holds:

  * TWO reassemblers — the proxy is a full EAP-TLS intermediary, so it
    reassembles fragments arriving from BOTH directions:
      - up_reasm:   supplicant -> server  (fragments coming from the AP side)
      - down_reasm: server -> supplicant  (fragments coming from RadSec side)

  * the outbound re-fragmentation queues for each direction (when a complete
    record from one side must be chopped to the other side's fragment size)

  * correlation keys (RADIUS State, identifiers) tying the AP-side RADIUS
    conversation to the RadSec-side conversation

  * measurement counters and timing — the actual research payload: how many
    fragments, how many round-trips, total auth wall-time, per-leg latency.

Sessions are keyed by the RADIUS State attribute where present, falling back
to (AP source, EAP conversation) for the very first round-trip before a State
has been assigned.
"""

import time
from dataclasses import dataclass, field

import proxy.eap_tls as eap_tls


@dataclass
class DirectionMetrics:
    """Counters for one direction of the exchange."""
    fragments_in: int = 0          # fragments received on this leg
    fragments_out: int = 0         # fragments we emitted on this leg
    acks_generated: int = 0        # local ACKs we produced (the collapsed RTTs)
    bytes_reassembled: int = 0     # total opaque TLS bytes carried


@dataclass
class Session:
    key: str
    mode: str                      # "reassemble" or "passthrough"
    upstream_fragment_size: int    # TLS-data budget per packet toward server
    downstream_fragment_size: int  # TLS-data budget per packet toward supplicant
    max_message_len: int

    # State correlation. Two independent RADIUS conversations meet here, so
    # there are TWO State tokens in flight for each session:
    #   radius_state     — the UPSTREAM server's State, echoed back upstream
    #                      on each subsequent Access-Request we send it.
    #   downstream_state — the State we MINT ourselves and put in our
    #                      Access-Challenges to the AP, so the AP echoes it
    #                      back and we can re-find this session.
    # Conflating them would corrupt either correlation as soon as the two
    # State values diverge (which they do almost immediately).
    radius_state: bytes | None = None
    downstream_state: bytes | None = None
    ap_address: tuple | None = None

    # Attributes captured verbatim from the AP's first Access-Request and
    # re-applied to every upstream Access-Request the proxy originates.
    # ClearPass (and any real RADIUS server) keys NAD/service policy on
    # NAS-IP-Address, NAS-Port-Type, Service-Type, etc — if the upstream
    # packet is missing them it falls into a default reject path. Stable
    # for the life of one auth, so capture once and reuse on every round.
    # Excludes things WE manage: User-Name, EAP-Message, State,
    # Message-Authenticator.
    ap_attrs: dict = field(default_factory=dict)

    # MS-MPPE-Send-Key / MS-MPPE-Recv-Key (RFC 2548 §2.4, vendor 311) carry
    # the MSK halves on the upstream Access-Accept, salt-encrypted under
    # the Request Authenticator of the upstream Access-Request + shared
    # secret. We avoid decrypt+re-encrypt by mirroring the AP's Request
    # Authenticator on the upstream leg (see last_ap_authenticator below),
    # so the encrypted blob is bound to the AP's authenticator end-to-end
    # and can be forwarded verbatim. We just shuttle the raw on-the-wire
    # bytes here.
    ms_mppe_send_key: bytes | None = None
    ms_mppe_recv_key: bytes | None = None

    # The AP's Request Authenticator from the most recent Access-Request.
    # Mirrored onto the upstream Access-Request so ClearPass salt-encrypts
    # MS-MPPE-* under a value the AP knows. Refreshed every round (the AP
    # picks a new one per request); ClearPass sees them as distinct nonces
    # like any other upstream client.
    last_ap_authenticator: bytes | None = None

    # The EAP Identifier of the most recent EAP-Request received from
    # upstream. The proxy MUST echo it on its next EAP-Response upstream
    # (RFC 3748 §4.2); failing to do so makes ClearPass return
    # "EAP-response to an unknown EAP-request". Captured automatically on
    # every upstream reply that carries an EAP-Request. Used in reassemble
    # mode where the mediator builds upstream EAP packets itself; in
    # passthrough mode it's unused (the supplicant's bytes are relayed
    # verbatim and the Identifier rides along).
    upstream_last_eap_req_id: int | None = None

    # Mirror image of the above for the supplicant leg: the Identifier of the
    # most recent EAP-Request the SUPPLICANT saw, learned from the Identifier
    # it echoes on each Response (RFC 3748 §4.1). The terminal EAP-Success /
    # EAP-Failure we hand back MUST carry this value (§4.2). In reassemble
    # mode it differs from the upstream server's Identifier because locally
    # minted ACKs and re-fragmented Requests advance the downstream counter
    # independently of the upstream one; unused in passthrough, where the
    # server's terminal packet is relayed verbatim.
    down_last_req_id: int | None = None

    # Reassembly (one per direction) — built lazily so max_message_len applies
    up_reasm: eap_tls.Reassembler = field(default=None)
    down_reasm: eap_tls.Reassembler = field(default=None)

    # Pending outbound fragment queues (chunks already sized, awaiting ACKs)
    up_outbox: list = field(default_factory=list)    # toward server
    down_outbox: list = field(default_factory=list)  # toward supplicant

    # EAP Identifier tracking per leg (must increment per emitted fragment)
    up_next_id: int = 0
    down_next_id: int = 0

    # Metrics
    up: DirectionMetrics = field(default_factory=DirectionMetrics)
    down: DirectionMetrics = field(default_factory=DirectionMetrics)
    started_at: float = field(default_factory=time.monotonic)
    completed_at: float | None = None
    upstream_round_trips: int = 0  # actual RADIUS/RadSec exchanges to server
    result: str | None = None      # "accept" | "reject" | None (in progress)
    # Terminal EAP packet from upstream, held until the supplicant has drained
    # the last server->supplicant fragment and asks for it.
    _pending_success: bytes | None = None
    _pending_failure: bytes | None = None

    def __post_init__(self):
        if self.up_reasm is None:
            self.up_reasm = eap_tls.Reassembler(max_message_len=self.max_message_len)
        if self.down_reasm is None:
            self.down_reasm = eap_tls.Reassembler(max_message_len=self.max_message_len)

    def next_down_id(self) -> int:
        self.down_next_id = (self.down_next_id + 1) & 0xFF
        return self.down_next_id

    def next_up_id(self) -> int:
        self.up_next_id = (self.up_next_id + 1) & 0xFF
        return self.up_next_id

    def finish(self, result: str) -> None:
        self.completed_at = time.monotonic()
        self.result = result

    @property
    def duration_ms(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at) * 1000.0

    def summary(self) -> dict:
        """The per-auth measurement record — emitted to the log on completion.
        This is the data you graph: reassemble vs passthrough."""
        return {
            "key": self.key,
            "mode": self.mode,
            "result": self.result,
            "duration_ms": round(self.duration_ms, 2) if self.duration_ms else None,
            "upstream_round_trips": self.upstream_round_trips,
            "downstream_fragment_size": self.downstream_fragment_size,
            "upstream_fragment_size": self.upstream_fragment_size,
            "supplicant_to_server": {
                "fragments_in": self.up.fragments_in,
                "acks_generated": self.up.acks_generated,
                "bytes": self.up.bytes_reassembled,
            },
            "server_to_supplicant": {
                "fragments_out": self.down.fragments_out,
                "acks_generated": self.down.acks_generated,
                "bytes": self.down.bytes_reassembled,
            },
        }


class SessionTable:
    """Holds in-flight sessions and handles key lookup/eviction."""

    def __init__(self, mode, upstream_fragment_size, downstream_fragment_size,
                 max_message_len, idle_timeout_s=30.0):
        self.mode = mode
        self.upstream_fragment_size = upstream_fragment_size
        self.downstream_fragment_size = downstream_fragment_size
        self.max_message_len = max_message_len
        self.idle_timeout_s = idle_timeout_s
        self._sessions: dict[str, Session] = {}

    def get_or_create(self, key: str, ap_address=None) -> Session:
        s = self._sessions.get(key)
        if s is None:
            s = Session(
                key=key,
                mode=self.mode,
                upstream_fragment_size=self.upstream_fragment_size,
                downstream_fragment_size=self.downstream_fragment_size,
                max_message_len=self.max_message_len,
                ap_address=ap_address,
            )
            self._sessions[key] = s
        return s

    def rekey(self, old_key: str, new_key: str) -> None:
        """When a RADIUS State attribute is assigned mid-conversation, move the
        session to be keyed on it."""
        if old_key in self._sessions and old_key != new_key:
            self._sessions[new_key] = self._sessions.pop(old_key)
            self._sessions[new_key].key = new_key

    def drop(self, key: str) -> None:
        self._sessions.pop(key, None)

    def reap_idle(self) -> None:
        now = time.monotonic()
        stale = [
            k for k, s in self._sessions.items()
            if s.completed_at is None and (now - s.started_at) > self.idle_timeout_s
        ]
        for k in stale:
            self._sessions.pop(k, None)
