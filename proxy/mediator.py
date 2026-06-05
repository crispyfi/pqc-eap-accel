"""
mediator.py — The bidirectional EAP-TLS mediation logic.

This is the conceptual heart of the proxy. It sits between the two legs:

    supplicant <--RADIUS--> [downstream server] <--> MEDIATOR <--> [upstream client] <--RADIUS--> radsecproxy --RadSec--> auth server

For each EAP-TLS authentication it runs TWO reassembly contexts (in the
Session) and bridges opaque TLS records between the two RADIUS conversations:

  SUPPLICANT -> SERVER direction:
    - supplicant sends EAP-TLS fragments (M-bit ratchet) via the NAS
    - in REASSEMBLE mode the proxy locally ACKs each non-final fragment
      (collapsing those round-trips on the fast LAN side) and accumulates
      them; once complete, it hands the whole opaque record to the upstream
      client, which re-fragments toward the server at upstream.fragment_size
      (large, to exploit RadSec/TCP streaming)
    - in PASSTHROUGH mode each fragment is forwarded upstream as-is, so the
      ACK ratchet runs across the latent upstream leg (the baseline; latency
      is applied with netem, see latency.sh / the `latency` command)

  SERVER -> SUPPLICANT direction:
    - the server's reply (also fragmented, esp. with a big/PQC cert) is
      reassembled from the upstream leg, then re-fragmented toward the
      supplicant at downstream.fragment_size, with the proxy driving the
      ACK exchange with the supplicant locally

The TLS payload is opaque throughout — only EAP/EAP-TLS framing is touched.

This module is transport-agnostic: it's handed already-parsed EAP-TLS packets
and a way to talk upstream, and it returns the EAP-TLS bytes to send back to
the supplicant. The downstream server module owns the actual RADIUS sockets.
"""

import logging

import proxy.eap_tls as eap_tls

log = logging.getLogger("mediator")


class Mediator:
    def __init__(self, upstream_client):
        self.upstream = upstream_client

    def handle_supplicant_eap(self, session, eap_bytes: bytes,
                              username: str,
                              calling_station: str | None,
                              called_station: str | None) -> dict:
        """Process one inbound EAP-TLS packet from the supplicant side.

        Returns a dict describing what the downstream server should send back
        to the supplicant:
            {
              "action": "ack" | "challenge" | "accept" | "reject",
              "eap_bytes": bytes | None,   # EAP-TLS to send to supplicant
              "echo_id": int | None,       # EAP Identifier to use
            }
        """
        pkt = eap_tls.parse(eap_bytes)
        session.up.fragments_in += 1

        # Sync the downstream EAP Identifier counter with what the supplicant
        # has actually seen. pkt.identifier is the supplicant's Response id,
        # which by RFC 3748 §4.1 is exactly the Identifier of the last
        # EAP-Request the supplicant received. The next downstream Request we
        # mint MUST be different from that, or the supplicant treats it as a
        # duplicate retransmit (RFC 3748 §4.2) and retransmits its previous
        # Response instead of progressing — the auth then hangs.
        #
        # Without this sync, an interleaved local ACK can shift down_next_id
        # into a range that collides with an EAP-Request id the supplicant
        # has already seen. The pathological case in the lab: the NAS itself
        # does upstream-direction EAP-TLS reassembly+refragmentation (its
        # "EAP fragmentation MTU" knob is wired up that way), so the proxy
        # has to emit a local ACK between the supplicant's ClientHello
        # fragments, which consumes down_next_id=1, leaving down_next_id=2
        # for the first server fragment — colliding with the EAP-TLS Start
        # at id=2 and stalling the auth.
        #
        # Resetting to pkt.identifier here guarantees next_down_id() returns
        # pkt.identifier+1, strictly distinct from anything the supplicant
        # has previously been Requested with. Safe in passthrough too because
        # passthrough never calls next_down_id() (it relays Identifiers
        # verbatim).
        session.down_next_id = pkt.identifier

        # Passthrough mode is byte-transparent in BOTH directions — including
        # data fragments AND fragment-ACKs. The supplicant's EAP Identifier
        # already echoes the upstream server's last EAP-Request Identifier
        # (because we forwarded that EAP-Request verbatim downstream), so
        # any rewriting here breaks RFC 3748 §4.2 Identifier correlation
        # (ClearPass returns "EAP-response to an unknown EAP-request").
        # Handle passthrough as an early-out so the reassemble-mode local
        # ACK logic below can't accidentally touch it.
        if session.mode == "passthrough":
            return self._passthrough_upstream(
                session, eap_bytes, username, calling_station, called_station
            )

        # --- REASSEMBLE mode below ---

        # If the supplicant is ACKing one of OUR downstream fragments, feed the
        # next queued downstream fragment rather than going upstream.
        if pkt.is_ack:
            if session.down_outbox:
                return self._send_next_downstream_fragment(session, pkt.identifier)
            # No more downstream fragments queued: the supplicant has received
            # our entire server->supplicant record. If the upstream auth has
            # already concluded, deliver that terminal result now.
            if session.result == "accept":
                return {"action": "accept", "eap_bytes": session._pending_success,
                        "echo_id": None}
            if session.result == "reject":
                return {"action": "reject", "eap_bytes": None, "echo_id": None}
            # Otherwise poll upstream once more: the supplicant's receipt of the
            # server's flight lets the server proceed to its terminal decision.
            # We send an empty EAP-TLS response upstream to advance it,
            # echoing the upstream server's last EAP-Request Identifier.
            up_id = session.upstream_last_eap_req_id
            if up_id is None:
                up_id = session.next_up_id()  # safety; shouldn't reach here
            ack = eap_tls.build_ack(eap_tls.EapCode.RESPONSE, up_id)
            reply = self.upstream.send_eap(
                session, ack, username, session.radius_state,
                calling_station, called_station)
            session.radius_state = reply["state"]
            return self._handle_upstream_reply(
                session, reply, username, calling_station, called_station)

        # --- REASSEMBLE mode: supplicant -> server ---
        complete = session.up_reasm.ingest(pkt)
        if complete is None:
            # More fragments coming: locally ACK and wait (collapsed RTT).
            # next_down_id() yields pkt.identifier+1 (we reset down_next_id
            # above), guaranteeing the supplicant sees this as a fresh
            # Request rather than a duplicate of the previous one.
            session.up.acks_generated += 1
            ack_id = session.next_down_id()
            ack = eap_tls.build_ack(eap_tls.EapCode.REQUEST, ack_id)
            return {"action": "ack", "eap_bytes": ack, "echo_id": ack_id}

        # Full record reassembled -> hand opaque record upstream.
        session.up.bytes_reassembled += len(complete)
        return self._forward_record_upstream(
            session, complete, username, calling_station, called_station
        )

    def _forward_record_upstream(self, session, tls_record: bytes,
                                 username, calling_station, called_station):
        """Re-fragment the opaque record toward the server (large fragments),
        run the upstream RADIUS exchange, and prepare the server's response
        for the supplicant.

        Each chunk we send must echo the EAP Identifier of upstream's most
        recent EAP-Request (RFC 3748 §4.2):
          - First chunk responds to upstream's previous EAP-Request (the
            EAP-TLS Start, or the last fragment-ACK from the prior flight).
          - Each subsequent chunk responds to the intermediate fragment-ACK
            upstream returned for the previous chunk.
        upstream_radius.send_eap refreshes session.upstream_last_eap_req_id
        on every reply that contains an EAP-Request, so the value is always
        current the next time we read it here.
        """
        # In reassemble mode upstream.fragment_size is large, so this is
        # typically a single chunk -> one upstream packet.
        chunks = eap_tls.fragment(tls_record, session.upstream_fragment_size)

        reply = None
        for idx, chunk in enumerate(chunks):
            more = idx < len(chunks) - 1
            tml = len(tls_record) if idx == 0 else None
            up_id = session.upstream_last_eap_req_id
            if up_id is None:
                up_id = session.next_up_id()  # safety fallback
            eap_frag = eap_tls.build(
                eap_tls.EapCode.RESPONSE, up_id, chunk,
                more_fragments=more, tls_message_length=tml,
            )
            session.up.fragments_out += 1
            reply = self.upstream.send_eap(
                session, eap_frag, username, session.radius_state,
                calling_station, called_station,
            )
            session.radius_state = reply["state"]
            # If upstream needs to ACK our intermediate fragments it returns a
            # challenge with empty EAP-TLS; the loop continues sending chunks.
            # upstream.send_eap has already refreshed upstream_last_eap_req_id
            # from that intermediate ACK by the time we re-enter the loop.

        return self._handle_upstream_reply(
            session, reply, username, calling_station, called_station)

    def _handle_upstream_reply(self, session, reply,
                               username, calling_station, called_station):
        """Take the upstream server's reply, reassemble its EAP-TLS fragments
        (server -> supplicant direction), and set up re-fragmentation toward
        the supplicant.

        The auth-context triple (username/calling/called) is threaded through
        so that any intermediate ACKs we have to send upstream while draining
        a multi-fragment server flight carry the SAME User-Name and station
        IDs as the initial Access-Request."""
        if reply is None:
            return {"action": "reject", "eap_bytes": None, "echo_id": None}

        if reply["accept"]:
            session.finish("accept")
            eap = reply["eap_messages"][0] if reply["eap_messages"] else None
            session._pending_success = eap
            return {"action": "accept", "eap_bytes": eap, "echo_id": None}

        if reply["reject"]:
            session.finish("reject")
            eap = reply["eap_messages"][0] if reply["eap_messages"] else None
            return {"action": "reject", "eap_bytes": eap, "echo_id": None}

        # Challenge: server sent (part of) an EAP-TLS message. Reassemble it.
        if not reply["eap_messages"]:
            # Empty challenge = upstream ACK of our fragment; nothing for the
            # supplicant yet. Caller treats this as "continue".
            return {"action": "ack", "eap_bytes": None, "echo_id": None}

        server_pkt = eap_tls.parse(reply["eap_messages"][0])
        complete = session.down_reasm.ingest(server_pkt)
        if complete is None:
            # Server has more fragments; we must ACK upstream and keep pulling.
            # Drive the upstream ACK loop until the server's record is whole.
            complete = self._drain_upstream_fragments(
                session, server_pkt, username, calling_station, called_station)
            if complete is None:
                # Drainer hit a terminal upstream reply (accept/reject) mid-way
                # and already called session.finish(). Surface it directly —
                # never forward the half-reassembled buffer to the supplicant,
                # which would arrive as a TLS message shorter than its declared
                # length and fail as SEC_E_INCOMPLETE_MESSAGE on Windows.
                action = "accept" if session.result == "accept" else "reject"
                return {"action": action, "eap_bytes": None, "echo_id": None}

        session.down.bytes_reassembled += len(complete)
        # Re-fragment the server's record toward the supplicant.
        return self._begin_downstream_fragmentation(session, complete)

    def _drain_upstream_fragments(self, session, last_pkt,
                                  username, calling_station, called_station):
        """Server is sending a multi-fragment record. ACK upstream (empty
        EAP-TLS response) until the final fragment, accumulating into the
        down-direction reassembler. Returns the complete record, or None if
        upstream returned a terminal Access-Accept/Reject mid-drain (in
        which case session.finish() has already been called).

        Each ACK echoes the Identifier of the most recent upstream EAP-
        Request (the fragment we're acknowledging). upstream_radius keeps
        session.upstream_last_eap_req_id current as each new fragment
        arrives.

        The auth-context (username + station IDs) MUST be the same as on
        the initial Access-Request for this EAP conversation.
        """
        while last_pkt.more_fragments:
            ack_id = session.upstream_last_eap_req_id
            if ack_id is None:
                ack_id = session.next_up_id()  # safety fallback
            ack = eap_tls.build_ack(eap_tls.EapCode.RESPONSE, ack_id)
            # These ACKs collapse server->supplicant fragment round-trips
            # (we ACK upstream so the supplicant doesn't have to), so they
            # belong under down.acks_generated, not up. The "up" prefix
            # tracks ACKs we send the SUPPLICANT for its outbound fragments.
            session.down.acks_generated += 1
            reply = self.upstream.send_eap(
                session, ack, username, session.radius_state,
                calling_station, called_station,
            )
            session.radius_state = reply["state"]
            if reply["accept"] or reply["reject"]:
                session.finish("accept" if reply["accept"] else "reject")
                return None
            if not reply["eap_messages"]:
                break
            last_pkt = eap_tls.parse(reply["eap_messages"][0])
            done = session.down_reasm.ingest(last_pkt)
            if done is not None:
                return done
        # Final fragment already ingested by caller's ingest() path.
        return bytes(session.down_reasm._buffer)

    def _begin_downstream_fragmentation(self, session, tls_record: bytes):
        """Chop the server's complete record into supplicant-sized fragments,
        queue them, and send the first one as a challenge."""
        chunks = eap_tls.fragment(tls_record, session.downstream_fragment_size)
        session.down_outbox = list(enumerate(chunks))
        session._down_total = len(tls_record)
        session._down_nchunks = len(chunks)
        return self._send_next_downstream_fragment(session, None, first=True)

    def _send_next_downstream_fragment(self, session, acked_id, first=False):
        """Emit the next queued server->supplicant fragment as an EAP-Request
        challenge. The supplicant ACKs each non-final fragment, which re-enters
        handle_supplicant_eap as an is_ack packet and calls back here."""
        if not session.down_outbox:
            # Nothing queued — shouldn't happen on a well-formed exchange.
            return {"action": "ack", "eap_bytes": None, "echo_id": None}

        idx, chunk = session.down_outbox.pop(0)
        more = idx < session._down_nchunks - 1
        tml = session._down_total if idx == 0 else None
        down_id = session.next_down_id()
        eap_frag = eap_tls.build(
            eap_tls.EapCode.REQUEST, down_id, chunk,
            more_fragments=more, tls_message_length=tml,
        )
        session.down.fragments_out += 1
        if more:
            session.down.acks_generated += 1
        return {"action": "challenge", "eap_bytes": eap_frag, "echo_id": down_id}

    def _passthrough_upstream(self, session, eap_bytes, username,
                              calling_station, called_station):
        """Baseline mode: relay the supplicant's EAP packet verbatim upstream
        and the upstream's reply verbatim back to the AP. The proxy never
        touches EAP Identifiers or framing — both legs see the same packet
        the other side sent. The fragment ACK ratchet therefore runs end-to-
        end across the latent upstream leg (latency via netem), which is the
        whole point of this mode (the number we compare reassemble against)."""
        session.up.fragments_out += 1
        reply = self.upstream.send_eap(
            session, eap_bytes, username, session.radius_state,
            calling_station, called_station,
        )
        session.radius_state = reply["state"]

        if reply["accept"]:
            session.finish("accept")
            eap = reply["eap_messages"][0] if reply["eap_messages"] else None
            return {"action": "accept", "eap_bytes": eap, "echo_id": None}
        if reply["reject"]:
            session.finish("reject")
            return {"action": "reject", "eap_bytes": None, "echo_id": None}

        eap = reply["eap_messages"][0] if reply["eap_messages"] else None
        if eap:
            session.down.fragments_out += 1
            return {"action": "challenge", "eap_bytes": eap, "echo_id": None}
        return {"action": "ack", "eap_bytes": None, "echo_id": None}
