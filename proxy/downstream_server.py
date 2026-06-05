"""
downstream_server.py — The NAS-facing UDP RADIUS server leg.

This module terminates the NAS's RADIUS conversation and mediates it to the upstream client (radsecproxy) via the Mediator class.
  EAP-TLS frames (EAP Type 13)  -> mediator.handle_supplicant_eap
                                   (local ACKs / reassembly / re-fragmentation)
  Everything else (notably the  -> upstream_client.send_eap verbatim
   opening EAP-Response/Identity)  (no fragment work, just forward)

State correlation
-----------------
There are two independent RADIUS conversations now (NAS<->proxy and
proxy<->radsecproxy), so each session carries two State tokens:

  * session.radius_state     — set by the upstream server, echoed back on
                               each upstream Access-Request we send.
  * session.downstream_state — minted by us, sent to the NAS in our
                               Access-Challenges; the NAS echoes it on its
                               next request and we look the session up by it.

For the very first Access-Request of a session there is no State yet, so we
key on (NAS source addr, Calling-Station-Id or EAP Identifier) just long
enough to mint a downstream_state and rekey the SessionTable.

Message-Authenticator (RFC 3579 §3.2)
-------------------------------------
When EAP-Message is present, Message-Authenticator MUST be present and valid.
We verify via pyrad's built-in if the installed version exposes it; otherwise
we at least require the attribute to be present (with a loud log warning) —
this is a lab tool, not an internet-facing server.
"""

import io
import logging
import secrets
import socket

from pyrad.dictionary import Dictionary
from pyrad import packet as pyradpkt

import proxy.eap_tls as eap_tls

log = logging.getLogger("downstream")


# Minimal RADIUS dictionary — just the IETF attributes we read off the NAS's
# request or set on our own replies. Anything not listed here is invisible
# to pyrad (it won't decode by name).
_DICT_DATA = """
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	NAS-IP-Address		4	ipaddr
ATTRIBUTE	NAS-Port		5	integer
ATTRIBUTE	Service-Type		6	integer
ATTRIBUTE	Framed-MTU		12	integer
ATTRIBUTE	State			24	octets
ATTRIBUTE	Class			25	octets
ATTRIBUTE	Called-Station-Id	30	string
ATTRIBUTE	Calling-Station-Id	31	string
ATTRIBUTE	NAS-Identifier		32	string
ATTRIBUTE	NAS-Port-Type		61	integer
ATTRIBUTE	EAP-Message		79	octets
ATTRIBUTE	Message-Authenticator	80	octets

VENDOR		Microsoft		311
BEGIN-VENDOR Microsoft
ATTRIBUTE	MS-MPPE-Send-Key	16	octets
ATTRIBUTE	MS-MPPE-Recv-Key	17	octets
END-VENDOR Microsoft
"""

_FORWARDED_ATTRS = (
    "NAS-IP-Address",
    "NAS-Identifier",
    "NAS-Port",
    "NAS-Port-Type",
    "Framed-MTU",
    "Service-Type",
)


def _build_dictionary() -> Dictionary:
    return Dictionary(io.StringIO(_DICT_DATA))


class DownstreamServer:
    """UDP RADIUS server bound to listen_host:listen_port."""

    def __init__(self, listen_host: str, listen_port: int,
                 shared_secret, mediator, upstream, sessions, reporter):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.secret = (shared_secret if isinstance(shared_secret, bytes)
                       else shared_secret.encode())
        self.mediator = mediator
        self.upstream = upstream
        self.sessions = sessions
        self.reporter = reporter
        self.dict = _build_dictionary()
        self._sock: socket.socket | None = None

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.listen_host, self.listen_port))
        log.info("downstream RADIUS listening on %s:%d",
                 self.listen_host, self.listen_port)
        while True:
            data, addr = self._sock.recvfrom(65535)
            try:
                self._handle_datagram(data, addr)
            except Exception:
                # One bad packet must not kill the proxy. Log and continue.
                log.exception("error handling datagram from %s", addr)

    def _handle_datagram(self, data: bytes, addr) -> None:
        req = pyradpkt.AuthPacket(secret=self.secret, dict=self.dict,
                                  packet=data)
        if req.code != pyradpkt.AccessRequest:
            log.warning("ignoring non-Access-Request code=%s from %s",
                        req.code, addr)
            return

        if "EAP-Message" not in req:
            log.warning("Access-Request with no EAP-Message from %s — dropping",
                        addr)
            return

        # RFC 3579 §3.2: Message-Authenticator MUST accompany EAP-Message.
        if not _check_message_authenticator(req):
            log.warning("bad/missing Message-Authenticator from %s — dropping",
                        addr)
            return

        username = _get_str(req, "User-Name") or ""
        calling = _get_str(req, "Calling-Station-Id")
        called = _get_str(req, "Called-Station-Id")
        state = _get_bytes(req, "State")
        eap_bytes = b"".join(req["EAP-Message"])

        session, was_new = self._lookup_session(state, addr, calling, eap_bytes)

        # Mirror this Access-Request's Authenticator onto the next upstream
        # Access-Request the proxy originates. Lets MS-MPPE-* keys from the
        # upstream Access-Accept be forwarded to the AP verbatim — they're
        # salt-encrypted under the AP's authenticator end-to-end. Updated
        # every round; only the FINAL round's value matters for MSK
        # delivery, but refreshing each time keeps the bookkeeping trivial.
        session.last_ap_authenticator = req.authenticator

        # Capture AP attributes once per session for verbatim forwarding to
        # the upstream server. Stable across rounds — capture on first sight
        # and reuse — so we don't get tripped up if the AP omits an attribute
        # on a later round (some APs do this once State carries context).
        if not session.ap_attrs:
            for name in _FORWARDED_ATTRS:
                if name in req:
                    session.ap_attrs[name] = req[name][0]

        # Route by EAP type. The EAP packet layout is Code(1) Id(1) Len(2) Type(1)..
        eap_type = eap_bytes[4] if len(eap_bytes) >= 5 else None
        if eap_type == eap_tls.EAP_TYPE_TLS:
            outcome = self.mediator.handle_supplicant_eap(
                session, eap_bytes, username, calling, called,
            )
        else:
            # Identity (type 1) and any other non-TLS EAP we may see in this
            # lab gets forwarded upstream as-is. The mediator never sees it.
            outcome = self._passthrough_non_tls(
                session, eap_bytes, username, calling, called,
            )

        reply = self._build_reply(req, session, outcome)
        self._sock.sendto(reply.ReplyPacket(), addr)

        # Once a session has reached a terminal result and its final reply
        # has been sent, drop it so the table doesn't grow unbounded.
        if session.result in ("accept", "reject"):
            # Print the readable summary block and write the JSON record.
            self.reporter.report(session.summary())
            self.sessions.drop(session.key)

    # ---- session lookup ----------------------------------------------------

    def _lookup_session(self, state: bytes | None, addr, calling: str | None,
                        eap_bytes: bytes):
        """Find the session for this request, or create one.

        Keying:
          - If the AP echoed a State, use State as the key (this is what we
            minted last round).
          - Otherwise this is the first Access-Request for a fresh auth.
            Use a synthetic key so we have somewhere to hang the session
            until we mint a downstream_state on the way back out.
        """
        if state is not None:
            key = "st:" + state.hex()
            return self.sessions.get_or_create(key, ap_address=addr), False

        # No State yet — synthetic key. Calling-Station-Id (the supplicant's
        # MAC) is the most stable disambiguator; fall back to (addr, eap-id)
        # if the AP didn't include it.
        if calling:
            key = f"new:{calling}"
        else:
            eap_id = eap_bytes[1] if len(eap_bytes) >= 2 else 0
            key = f"new:{addr[0]}:{addr[1]}:{eap_id}"
        return self.sessions.get_or_create(key, ap_address=addr), True

    # ---- non-TLS passthrough -----------------------------------------------

    def _passthrough_non_tls(self, session, eap_bytes, username, calling, called):
        """Forward non-EAP-TLS frames (e.g. EAP-Response/Identity) upstream
        verbatim. The mediator is intentionally not involved — there's no
        fragmentation here. We normalise the upstream reply to the same
        outcome dict shape the mediator returns so _build_reply stays
        uniform.
        """
        reply = self.upstream.send_eap(
            session, eap_bytes, username, session.radius_state, calling, called,
        )
        session.radius_state = reply["state"]
        eap = reply["eap_messages"][0] if reply["eap_messages"] else None

        if reply["accept"]:
            session.finish("accept")
            return {"action": "accept", "eap_bytes": eap, "echo_id": None}
        if reply["reject"]:
            session.finish("reject")
            return {"action": "reject", "eap_bytes": eap, "echo_id": None}
        return {"action": "challenge", "eap_bytes": eap, "echo_id": None}

    # ---- reply assembly ----------------------------------------------------

    def _build_reply(self, req, session, outcome):
        reply = req.CreateReply()
        action = outcome["action"]

        if action == "accept":
            reply.code = pyradpkt.AccessAccept
            # Hand the MSK halves to the AP. pyrad encrypts these under the
            # AP's original Request Authenticator (reply is created from req
            # via CreateReply, so that context is preserved) and the
            # downstream shared secret. Without these the supplicant can't
            # complete the 802.11 4-way handshake.
            if session.ms_mppe_send_key is not None:
                reply["MS-MPPE-Send-Key"] = session.ms_mppe_send_key
            if session.ms_mppe_recv_key is not None:
                reply["MS-MPPE-Recv-Key"] = session.ms_mppe_recv_key
        elif action == "reject":
            reply.code = pyradpkt.AccessReject
        else:
            # "ack" or "challenge" — both come back to the AP as an
            # Access-Challenge; the difference is internal to the mediator
            # (an "ack" challenge carries the proxy's local EAP-TLS ACK).
            reply.code = pyradpkt.AccessChallenge
            # Mint the downstream State on the first Challenge of this
            # session, then keep echoing it. Rekey the session table so
            # subsequent lookups find us by the State the AP will quote.
            if session.downstream_state is None:
                session.downstream_state = secrets.token_bytes(16)
                new_key = "st:" + session.downstream_state.hex()
                self.sessions.rekey(session.key, new_key)
            reply["State"] = session.downstream_state

        eap_bytes = outcome.get("eap_bytes")
        if eap_bytes:
            for chunk in _split_eap_message(eap_bytes):
                reply.AddAttribute("EAP-Message", chunk)
            # Message-Authenticator MUST be present whenever EAP-Message is
            # (RFC 3579 §3.2). pyrad fills it in over the wire on send.
            reply.add_message_authenticator()

        return reply


# --- helpers ----------------------------------------------------------------

def _split_eap_message(eap_bytes: bytes, size: int = 253) -> list[bytes]:
    """RFC 3579 §3.1: EAP packets >253 octets are carried in multiple
    EAP-Message attributes within ONE RADIUS packet (no extra RTTs)."""
    if not eap_bytes:
        return [b""]
    return [eap_bytes[i:i + size] for i in range(0, len(eap_bytes), size)]


def _check_message_authenticator(req) -> bool:
    """Best-effort Message-Authenticator validation.

    Newer pyrad exposes AuthPacket.verify_message_authenticator(); use it if
    available. Older versions don't, in which case we at least require the
    attribute to be present and log that we're not cryptographically
    verifying it. Lab-tool tradeoff — tighten before any non-lab use.
    """
    if "Message-Authenticator" not in req:
        return False
    verifier = getattr(req, "verify_message_authenticator", None)
    if callable(verifier):
        try:
            return bool(verifier())
        except Exception:
            log.exception("verify_message_authenticator raised")
            return False
    log.warning("pyrad lacks verify_message_authenticator; accepting on presence only")
    return True


def _get_str(req, name: str) -> str | None:
    if name not in req:
        return None
    v = req[name][0]
    return v.decode() if isinstance(v, (bytes, bytearray)) else v


def _get_bytes(req, name: str) -> bytes | None:
    if name not in req:
        return None
    v = req[name][0]
    return v if isinstance(v, (bytes, bytearray)) else v.encode()
