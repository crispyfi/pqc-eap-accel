"""
upstream_radius.py — The auth-server-facing leg of the proxy.

In the lab topology this emits STANDARD RADIUS over UDP to a local radsecproxy
instance, which does the RadSec (RADIUS-over-TLS) transport to FreeRADIUS. 
So this module is "be a correct RADIUS client to localhost" — the
TLS/cert plumbing lives entirely in radsecproxy, not here.

This leg is where the proxy acts as the EAP-TLS *peer* toward the real auth
server: it originates its OWN RADIUS Access-Request conversation (independent
of the AP-side conversation), carries the opaque reassembled TLS records in
EAP-Message attributes, tracks the server's State attribute, and feeds the
server's EAP-TLS fragments into the session's down-direction reassembler.

"""

import time
import struct
import logging

from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad import packet

import proxy.eap_tls as eap_tls

log = logging.getLogger("upstream")


class _BigReplyClient(Client):
    """pyrad's Client._SendPacket hardcodes ``recv(4096)``. On a UDP socket a
    larger datagram is silently TRUNCATED by the kernel, so DecodePacket then
    raises ``PacketError('Packet has invalid length')`` — which _SendPacket
    swallows (``except packet.PacketError: pass``) and retries until it raises
    ``Timeout``. The result is a hang with no error in the log.

    Large PQC server-cert flights arrive on this leg as >4096-byte RADIUS
    Access-Challenges (once radsecproxy's RAD_Max_Length / udp.c cap is lifted
    to 65535). So we override the one method with a full-datagram buffer; UDP's
    max datagram is 65535, which is also the RADIUS 16-bit Length-field max, so
    a single recv always pulls a whole packet.

    NOTE: this body is copied verbatim from pyrad 2.5.4 Client._SendPacket with
    ONLY the recv() size changed (4096 -> 65535). requirements.txt pins
    pyrad==2.5.4 so this copy can't silently drift from upstream. If you bump
    pyrad, re-diff this method against the new Client._SendPacket."""

    def _SendPacket(self, pkt, port):
        self._SocketOpen()
        for attempt in range(self.retries):
            if attempt and pkt.code == packet.AccountingRequest:
                if "Acct-Delay-Time" in pkt:
                    pkt["Acct-Delay-Time"] = pkt["Acct-Delay-Time"][0] + self.timeout
                else:
                    pkt["Acct-Delay-Time"] = self.timeout
            now = time.time()
            waitto = now + self.timeout
            self._socket.sendto(pkt.RequestPacket(), (self.server, port))
            while now < waitto:
                ready = self._poll.poll((waitto - now) * 1000)
                if ready:
                    rawreply = self._socket.recv(65535)   # pyrad ships recv(4096)
                else:
                    now = time.time()
                    continue
                try:
                    reply = pkt.CreateReply(packet=rawreply)
                    if pkt.VerifyReply(reply, rawreply):
                        if hasattr(pkt, 'authenticator'):
                            reply.request_authenticator = pkt.authenticator
                        return reply
                except packet.PacketError:
                    pass
                now = time.time()
        raise Timeout


def _decode_packet_allow_large(self, raw):
    """Drop-in replacement for pyrad.packet.Packet.DecodePacket that lifts its
    hardcoded ``length > 8192`` rejection (packet.py) to the RADIUS 16-bit
    Length maximum (65535).

    Without this, a large PQC server-cert Access-Challenge (>8192 bytes, once
    radsecproxy + FreeRADIUS are patched to emit them) is thrown away HERE —
    before a single EAP-Message byte is extracted — then swallowed by
    Client._SendPacket's ``except PacketError: pass``, so the proxy times out
    with nothing to re-fragment to the supplicant (server_to_supplicant
    bytes=0). 8192 is exactly why eap fragment_size breaks at 8077: an 8076
    fragment yields a 8192-byte challenge (passes), 8077 yields 8193 (rejected).

    Body copied verbatim from pyrad 2.5.4 Packet.DecodePacket with ONLY the 8192
    literal raised to 65535 (and the `packet` arg renamed `raw` to avoid
    shadowing this module's `from pyrad import packet`). requirements.txt pins
    pyrad==2.5.4 so this copy can't silently drift — re-diff against
    Packet.DecodePacket if you bump pyrad. Pairs with _BigReplyClient (the
    recv(4096)->recv(65535) fix); 65535 is the hard ceiling in both."""
    try:
        (self.code, self.id, length, self.authenticator) = \
            struct.unpack('!BBH16s', raw[0:20])
    except struct.error:
        raise packet.PacketError('Packet header is corrupt')
    if len(raw) != length:
        raise packet.PacketError('Packet has invalid length')
    if length > 65535:                       # pyrad ships `> 8192`
        raise packet.PacketError('Packet length is too long (%d)' % length)

    self.clear()

    raw = raw[20:]
    while raw:
        try:
            (key, attrlen) = struct.unpack('!BB', raw[0:2])
        except struct.error:
            raise packet.PacketError('Attribute header is corrupt')

        if attrlen < 2:
            raise packet.PacketError('Attribute length is too small (%d)' % attrlen)

        value = raw[2:attrlen]
        if key == 26:
            for (key, value) in self._PktDecodeVendorAttribute(value):
                self.setdefault(key, []).append(value)
        elif key == 80:
            # POST: Message Authenticator AVP is present.
            self.message_authenticator = True
            self.setdefault(key, []).append(value)
        elif self._PktIsTlvAttribute(key):
            self._PktDecodeTlvAttribute(key, value)
        else:
            self.setdefault(key, []).append(value)

        raw = raw[attrlen:]


# Lift pyrad's 8192-byte decode cap for this process (see docstring above). Bound
# on the base Packet class so AuthPacket replies — which is what the upstream leg
# decodes — inherit it. Applied once, at import.
packet.Packet.DecodePacket = _decode_packet_allow_large


# Minimal in-memory RADIUS dictionary — just the attributes we touch. Avoids
# shipping a full dictionary file for the lab.
_DICT = Dictionary()
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
# No encrypt=2 above: we don't want pyrad to attempt RFC 2548 salt-crypto
# (its support is patchy across versions). Instead the proxy mirrors the
# AP's Request Authenticator onto the upstream Access-Request, so the
# encrypted bytes pyrad sees here are bound to the AP's authenticator and
# can be forwarded verbatim to the AP without any decrypt/re-encrypt.


def _build_dictionary() -> Dictionary:
    import io
    return Dictionary(io.StringIO(_DICT_DATA))


class UpstreamClient:
    """Drives the proxy's own RADIUS conversation with the upstream server
    (via local radsecproxy). One instance per proxy process; per-auth state
    lives in the Session, not here."""

    def __init__(self, host: str, port: int, secret: bytes,
                 timeout_s: float = 10.0,
                 framed_mtu_override: int | None = None):
        self.host = host
        self.port = port
        self.secret = secret if isinstance(secret, bytes) else secret.encode()
        self.timeout_s = timeout_s
        # None  -> forward AP's Framed-MTU verbatim (passthrough-correct).
        # int   -> rewrite to this value on every upstream Access-Request, so
        #          FreeRADIUS's min(fragment_size, Framed-MTU) isn't pinned to
        #          the small AP-link MTU when we're reassembling locally.
        self.framed_mtu_override = framed_mtu_override
        self.dict = _build_dictionary()
        # _BigReplyClient (not Client) so >4096-byte upstream Access-Challenges
        # carrying large PQC server-cert fragments aren't truncated on recv.
        self._client = _BigReplyClient(
            server=host, authport=port,
            secret=self.secret, dict=self.dict,
        )
        self._client.timeout = timeout_s

    def send_eap(self, session, eap_payload: bytes,
                 username: str, state: bytes | None,
                 calling_station: str | None = None,
                 called_station: str | None = None) -> dict:
        """Send one Access-Request carrying `eap_payload` (a complete EAP-TLS
        packet's bytes — already framed by our re-fragmentation toward the
        server) and return a normalised reply dict:

            {
              "code": <RADIUS code>,
              "eap_messages": [bytes, ...],   # EAP-Message attrs, in order
              "state": bytes | None,          # server State to echo next time
              "accept": bool, "reject": bool, "challenge": bool,
            }

        EAP-Message attributes >253 bytes are split across multiple
        EAP-Message attributes (RFC 3579 §3.1); we both split on send and
        concatenate on receive.
        """
        req = self._client.CreateAuthPacket(code=packet.AccessRequest)
        # Mirror the AP's Request Authenticator so MS-MPPE-Send/Recv-Key in
        # the eventual Access-Accept are salt-encrypted under the same
        # 16-octet value the AP knows, and can be forwarded verbatim. MUST
        # be set BEFORE add_message_authenticator below, since the HMAC
        # input covers the authenticator field.
        if session.last_ap_authenticator is not None:
            req.authenticator = session.last_ap_authenticator
        req["User-Name"] = username
        if calling_station:
            req["Calling-Station-Id"] = calling_station
        if called_station:
            req["Called-Station-Id"] = called_station
        if state is not None:
            req["State"] = state
        # Replay the attributes captured from the AP's request (NAS-IP-Address,
        # NAS-Port-Type, Service-Type, etc) so the upstream server sees the
        # same NAS/service context as in the direct AP->radsecproxy baseline.
        #
        # Framed-MTU is the one attribute we may rewrite, and ONLY in reassemble
        # mode. The override decouples upstream-leg fragmentation from the
        # AP-side link MTU — fine when the proxy reassembles whatever the auth
        # server sends and re-fragments to the AP per `downstream.fragment_size`.
        # In passthrough mode the proxy does NOT re-fragment, so a 4000-byte
        # upstream fragment ends up being forwarded verbatim to an AP whose
        # link MTU is ~1100; the AP can't deliver it as a single EAPOL frame
        # and the auth stalls. So in passthrough we always forward the AP's
        # real Framed-MTU regardless of config.yaml. See config.yaml comment.
        apply_mtu_override = (
            self.framed_mtu_override is not None
            and session.mode == "reassemble"
        )
        for name, value in session.ap_attrs.items():
            if name == "Framed-MTU" and apply_mtu_override:
                req[name] = self.framed_mtu_override
            else:
                req[name] = value

        # Split EAP payload into <=253-byte EAP-Message attributes.
        for chunk in _split_eap_message(eap_payload):
            req.AddAttribute("EAP-Message", chunk)

        # pyrad adds Message-Authenticator automatically for EAP when present;
        # ensure it's there (required with EAP-Message, RFC 3579 §3.2).
        req.add_message_authenticator()

        session.upstream_round_trips += 1

        t0 = time.monotonic()
        reply = self._client.SendPacket(req)
        rtt = (time.monotonic() - t0) * 1000.0
        log.debug("upstream RTT %.1f ms (code=%s)", rtt, reply.code)

        eap_messages = _concat_eap_messages(reply)
        new_state = reply["State"][0] if "State" in reply else None

        # If upstream sent us an EAP-Request, remember its Identifier so the
        # mediator can echo it on its next EAP-Response upstream (RFC 3748
        # §4.2). Single capture point that covers every code path that
        # ingests an upstream reply — _handle_upstream_reply, intermediate
        # ACKs in _forward_record_upstream's multi-chunk loop,
        # _drain_upstream_fragments, the final-supplicant-ACK upstream poll.
        # No need to fully parse the EAP-TLS packet here: byte 0 is the EAP
        # code (1 = Request), byte 1 is the Identifier.
        if eap_messages and len(eap_messages[0]) >= 2 and eap_messages[0][0] == 1:
            session.upstream_last_eap_req_id = eap_messages[0][1]

        # On Access-Accept, capture the raw on-the-wire MS-MPPE-* bytes
        # (2-octet salt || ciphertext). These were salt-encrypted by
        # ClearPass under THIS upstream Access-Request's Authenticator,
        # which we mirrored from the AP — so the same encrypted bytes
        # decrypt cleanly at the AP. The downstream server forwards them
        # verbatim. Without this end-to-end Request-Authenticator alignment
        # the AP derives the wrong PMK and the 4-way handshake times out
        # (Windows event id 11006 "Dynamic key exchange did not succeed").
        if reply.code == packet.AccessAccept:
            if "MS-MPPE-Send-Key" in reply:
                session.ms_mppe_send_key = reply["MS-MPPE-Send-Key"][0]
            if "MS-MPPE-Recv-Key" in reply:
                session.ms_mppe_recv_key = reply["MS-MPPE-Recv-Key"][0]

        return {
            "code": reply.code,
            "eap_messages": eap_messages,
            "state": new_state,
            "accept": reply.code == packet.AccessAccept,
            "reject": reply.code == packet.AccessReject,
            "challenge": reply.code == packet.AccessChallenge,
        }


def _split_eap_message(eap_bytes: bytes, size: int = 253) -> list[bytes]:
    """RFC 3579 §3.1: an EAP packet longer than 253 octets is carried in
    multiple EAP-Message attributes. This is attribute-level chunking within
    ONE RADIUS packet — it costs no EAP round-trips."""
    if not eap_bytes:
        return [b""]
    return [eap_bytes[i:i + size] for i in range(0, len(eap_bytes), size)]


def _concat_eap_messages(pkt) -> list[bytes]:
    """Reassemble the (possibly multiple) EAP-Message attributes from one
    RADIUS packet back into a single EAP packet's bytes. pyrad returns each
    attribute value separately and in order."""
    if "EAP-Message" not in pkt:
        return []
    joined = b"".join(pkt["EAP-Message"])
    return [joined] if joined else []
