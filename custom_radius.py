#!/usr/bin/env python3
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from OpenSSL import SSL


DEFAULT_ENV_PATH = "/etc/custom-radius/radius.env"


ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11
ATTR_STATE = 24
ATTR_CALLING_STATION_ID = 31
ATTR_VENDOR_SPECIFIC = 26
ATTR_EAP_MESSAGE = 79
ATTR_MESSAGE_AUTHENTICATOR = 80

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_NAK = 3
EAP_PEAP = 25
EAP_MSCHAPV2 = 26
EAP_TLV = 33

TLS_LENGTH_INCLUDED = 0x80
TLS_MORE_FRAGMENTS = 0x40
TLS_START = 0x20
MAX_TLS_FRAGMENT = 900


def load_env(path):
    result = {}
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key.strip()] = value
    return result


def parse_allowed_clients(value):
    """RADIUS_CLIENT_IP: "*" allows any source, otherwise a comma-separated
    list of IPs and/or CIDR networks, e.g. "192.0.2.10,198.51.100.0/24".
    Returns None for "allow all", else a list of ip_network objects.
    """
    value = (value or "*").strip()
    if value == "*":
        return None
    networks = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        networks.append(ipaddress.ip_network(part, strict=False))
    return networks


def client_allowed(source_ip, allowed_networks):
    if allowed_networks is None:
        return True
    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return any(addr in network for network in allowed_networks)


def attr(kind, value):
    if len(value) > 253:
        raise ValueError("RADIUS attribute value is too large")
    return bytes((kind, len(value) + 2)) + value


def eap_packet(code, identifier, eap_type=None, data=b""):
    if code in (EAP_SUCCESS, EAP_FAILURE):
        return struct.pack("!BBH", code, identifier, 4)
    body = bytes((eap_type,)) + data
    return struct.pack("!BBH", code, identifier, 4 + len(body)) + body


def parse_eap(packet):
    if len(packet) < 4:
        raise ValueError("short EAP packet")
    code, identifier, length = struct.unpack("!BBH", packet[:4])
    if length != len(packet) or length < 4:
        raise ValueError("invalid EAP length")
    if code in (EAP_SUCCESS, EAP_FAILURE):
        return code, identifier, None, b""
    if length < 5:
        raise ValueError("EAP type is missing")
    return code, identifier, packet[4], packet[5:]


def parse_radius(packet):
    if len(packet) < 20:
        raise ValueError("short RADIUS packet")
    code, identifier, length = struct.unpack("!BBH", packet[:4])
    if length != len(packet):
        raise ValueError("invalid RADIUS length")
    attrs = []
    offset = 20
    while offset < length:
        if offset + 2 > length:
            raise ValueError("truncated attribute")
        kind, size = packet[offset], packet[offset + 1]
        if size < 2 or offset + size > length:
            raise ValueError("invalid attribute length")
        attrs.append((kind, packet[offset + 2:offset + size], offset))
        offset += size
    return code, identifier, packet[4:20], attrs


def verify_message_authenticator(packet, attrs, secret):
    matches = [(value, offset) for kind, value, offset in attrs
               if kind == ATTR_MESSAGE_AUTHENTICATOR]
    if len(matches) != 1 or len(matches[0][0]) != 16:
        return False
    supplied, offset = matches[0]
    candidate = bytearray(packet)
    candidate[offset + 2:offset + 18] = bytes(16)
    expected = hmac.new(secret, candidate, hashlib.md5).digest()
    return hmac.compare_digest(supplied, expected)


def radius_response(code, identifier, request_authenticator, values, secret):
    encoded = bytearray()
    has_eap = False
    for kind, value in values:
        if kind == ATTR_EAP_MESSAGE:
            has_eap = True
            for start in range(0, len(value), 253):
                encoded += attr(kind, value[start:start + 253])
        else:
            encoded += attr(kind, value)
    ma_offset = None
    if has_eap:
        ma_offset = len(encoded)
        encoded += attr(ATTR_MESSAGE_AUTHENTICATOR, bytes(16))
    length = 20 + len(encoded)
    prefix = struct.pack("!BBH", code, identifier, length)
    if ma_offset is not None:
        temporary = prefix + request_authenticator + encoded
        digest = hmac.new(secret, temporary, hashlib.md5).digest()
        encoded[ma_offset + 2:ma_offset + 18] = digest
    response_authenticator = hashlib.md5(
        prefix + request_authenticator + encoded + secret
    ).digest()
    return prefix + response_authenticator + encoded


def encrypt_mppe_key(key, secret, request_authenticator):
    salt = struct.pack("!H", 0x8000 | secrets.randbelow(0x8000))
    plain = bytes((len(key),)) + key
    plain += bytes((-len(plain)) % 16)
    result = bytearray()
    previous = request_authenticator + salt
    for start in range(0, len(plain), 16):
        block = plain[start:start + 16]
        mask = hashlib.md5(secret + previous).digest()
        cipher = bytes(a ^ b for a, b in zip(block, mask))
        result += cipher
        previous = cipher
    return salt + result


def microsoft_vsa(vendor_type, value):
    vendor = struct.pack("!I", 311)
    inner = bytes((vendor_type, len(value) + 2)) + value
    return vendor + inner


def strip_domain(raw):
    # wpa_supplicant (and MS clients) only strip a NetBIOS "DOMAIN\" prefix
    # before computing the MSCHAPv2 ChallengeHash; an "@realm" UPN suffix is
    # left in place. The server must mirror that exactly here, or the hash
    # it computes will never match the client's, and AD will reject a
    # perfectly correct password as invalid.
    return raw.rsplit(b"\\", 1)[-1]


def normalize_username(raw):
    # For AD account lookup (case-insensitive) it is safe to also strip an
    # "@domain"/UPN suffix, fold case, and trim whitespace, so
    # DOMAIN\user, user@domain and plain user all resolve to the same
    # account regardless of how the client formats it.
    text = strip_domain(raw).decode("utf-8", "replace").strip()
    return text.split("@", 1)[0].lower()


def normalize_mac(raw):
    """Calling-Station-Id formats differ by vendor ("aabbccddeeff",
    "AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff", ...). Normalize to
    AA:BB:CC:DD:EE:FF so the same device is not counted twice under two
    spellings. Returns "" for anything that is not 12 hex digits."""
    hex_only = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(hex_only) != 12:
        return ""
    hex_only = hex_only.upper()
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))


def challenge_hash(peer_challenge, auth_challenge, username):
    return hashlib.sha1(peer_challenge + auth_challenge + username).digest()[:8]


def authenticator_response(password_hash_hash, nt_response, peer_challenge,
                           auth_challenge, username):
    magic1 = b"Magic server to client signing constant"
    magic2 = b"Pad to make it do more than one iteration"
    digest = hashlib.sha1(password_hash_hash + nt_response + magic1).digest()
    challenge = challenge_hash(peer_challenge, auth_challenge, username)
    return hashlib.sha1(digest + challenge + magic2).hexdigest().upper()


@dataclass
class Session:
    token: bytes
    tls: SSL.Connection
    # Serializes work on this session. The TLS connection and the phase
    # machine below are not thread safe, and an access point retransmits
    # while the server is still busy with the previous packet.
    lock: threading.Lock = field(default_factory=threading.Lock)
    created: float = field(default_factory=time.monotonic)
    outer_id: int = 0
    inner_id: int = 0
    phase: str = "tls"
    tls_in: bytearray = field(default_factory=bytearray)
    tls_in_expected: int | None = None
    tls_out: bytes = b""
    tls_out_offset: int = 0
    inner_in: bytearray = field(default_factory=bytearray)
    auth_challenge: bytes | None = None
    accept_ready: bool = False
    username: str = ""
    # Calling-Station-Id (RFC 2865 5.31), normally the client's MAC as sent
    # by the access point. Refreshed from every request that carries it,
    # since some APs only include it on the outer identity request.
    calling_station: str = ""

    def next_outer_id(self):
        self.outer_id = (self.outer_id + 1) & 0xff
        return self.outer_id

    def next_inner_id(self):
        self.inner_id = (self.inner_id + 1) & 0xff
        return self.inner_id


class RadiusServer:
    def __init__(self, config):
        self.cfg = config
        self.secret = config["RADIUS_SHARED_SECRET"].encode()
        if not self.secret:
            raise ValueError("RADIUS_SHARED_SECRET is empty")
        self.sessions = {}
        self.responses = {}
        # Guards the two dictionaries above only. It is never held across
        # ntlm_auth, so a slow domain controller cannot stall other users.
        self.lock = threading.Lock()
        self.ttl = int(config.get("RADIUS_SESSION_TTL_SECONDS", "120"))
        self.duplicate_window = int(config.get("RADIUS_DUPLICATE_WINDOW_SECONDS", "30"))
        self.ntlm_timeout = int(config.get("RADIUS_REQUEST_TIMEOUT_SECONDS", "5"))
        self.workers = int(config.get("RADIUS_WORKER_THREADS", "16"))
        self.allowed_clients = parse_allowed_clients(config.get("RADIUS_CLIENT_IP", "*"))
        self.context = SSL.Context(SSL.TLS_SERVER_METHOD)
        # use_certificate_chain_file (not use_certificate_file) so any
        # intermediate CA certificates after the leaf in the PEM file are
        # sent to the client too - EAP supplicants generally don't fetch
        # missing intermediates online the way browsers do.
        self.context.use_certificate_chain_file(config["RADIUS_TLS_CERT_FILE"])
        self.context.use_privatekey_file(config["RADIUS_TLS_KEY_FILE"])
        self.context.check_privatekey()
        # Pinned to TLS 1.2 on purpose, not out of caution: PEAPv0 derives
        # its MPPE keys from the TLS 1.2 PRF with the "client EAP
        # encryption" label. TLS 1.3 changes key derivation and has no
        # standardised PEAPv0 binding, so it is neither a min nor a max
        # this server can be configured into.
        self.context.set_min_proto_version(SSL.TLS1_2_VERSION)
        self.context.set_max_proto_version(SSL.TLS1_2_VERSION)
        self.context.set_cipher_list(b"HIGH:!aNULL:!MD5:!RC4")
        self.context.set_options(SSL.OP_NO_COMPRESSION)

    def new_session(self, response_id):
        token = secrets.token_bytes(24)
        connection = SSL.Connection(self.context, None)
        connection.set_accept_state()
        session = Session(token=token, tls=connection, outer_id=response_id)
        with self.lock:
            self.sessions[token] = session
        return session

    def drop_session(self, token):
        with self.lock:
            self.sessions.pop(token, None)

    def cleanup(self):
        now = time.monotonic()
        with self.lock:
            for token, session in list(self.sessions.items()):
                if now - session.created > self.ttl:
                    del self.sessions[token]
            for key, (created, _) in list(self.responses.items()):
                if now - created > self.duplicate_window:
                    del self.responses[key]

    def attributes(self, attrs, kind):
        return [value for attr_kind, value, _ in attrs if attr_kind == kind]

    def challenge(self, radius_id, request_auth, session, eap):
        values = [(ATTR_STATE, session.token), (ATTR_EAP_MESSAGE, eap)]
        return radius_response(ACCESS_CHALLENGE, radius_id, request_auth,
                               values, self.secret)

    def reject(self, radius_id, request_auth, eap_id):
        eap = eap_packet(EAP_FAILURE, eap_id)
        return radius_response(ACCESS_REJECT, radius_id, request_auth,
                               [(ATTR_EAP_MESSAGE, eap)], self.secret)

    def accept(self, radius_id, request_auth, session, eap_id):
        key_material = session.tls.export_keying_material(
            b"client EAP encryption", 64, None
        )
        recv_key, send_key = key_material[:32], key_material[32:64]
        attrs = [
            # Echo the identifier of the response we are acknowledging
            # rather than our own counter; they agree today, but a
            # supplicant that drops an EAP-Success with a mismatched
            # identifier is within its rights.
            (ATTR_EAP_MESSAGE,
             eap_packet(EAP_SUCCESS, eap_id)),
            (ATTR_VENDOR_SPECIFIC, microsoft_vsa(
                17, encrypt_mppe_key(recv_key, self.secret, request_auth))),
            (ATTR_VENDOR_SPECIFIC, microsoft_vsa(
                16, encrypt_mppe_key(send_key, self.secret, request_auth))),
        ]
        self.drop_session(session.token)
        logging.info("access accepted user=%s mac=%s",
                     session.username, session.calling_station or "-")
        return radius_response(ACCESS_ACCEPT, radius_id, request_auth,
                               attrs, self.secret)

    def tls_output(self, session):
        chunks = []
        while True:
            try:
                chunks.append(session.tls.bio_read(65535))
            except SSL.WantReadError:
                break
        if chunks:
            session.tls_out += b"".join(chunks)

    def next_tls_fragment(self, session):
        remaining = len(session.tls_out) - session.tls_out_offset
        if remaining <= 0:
            session.tls_out = b""
            session.tls_out_offset = 0
            return None
        first = session.tls_out_offset == 0
        size = min(MAX_TLS_FRAGMENT, remaining)
        fragment = session.tls_out[session.tls_out_offset:
                                   session.tls_out_offset + size]
        session.tls_out_offset += size
        more = session.tls_out_offset < len(session.tls_out)
        flags = TLS_MORE_FRAGMENTS if more else 0
        prefix = b""
        if first and more:
            flags |= TLS_LENGTH_INCLUDED
            prefix = struct.pack("!I", len(session.tls_out))
        if not more:
            session.tls_out = b""
            session.tls_out_offset = 0
        return bytes((flags,)) + prefix + fragment

    def queue_inner(self, session, packet):
        offset = 0
        while offset < len(packet):
            try:
                offset += session.tls.send(packet[offset:])
            except SSL.WantWriteError:
                self.tls_output(session)
        self.tls_output(session)

    def ntlm_auth(self, username, challenge, response):
        short = normalize_username(username)
        command = [
            "ntlm_auth",
            "--request-nt-key",
            "--domain=" + self.cfg["AD_NETBIOS_DOMAIN"],
            "--username=" + short,
            "--challenge=" + challenge.hex(),
            "--nt-response=" + response.hex(),
        ]
        group = self.cfg.get("AD_ALLOWED_GROUP", "-")
        if group and group != "-":
            command.append("--require-membership-of=" +
                           self.cfg["AD_NETBIOS_DOMAIN"] + "\\" + group)
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=self.ntlm_timeout)
        except subprocess.TimeoutExpired:
            logging.warning("ntlm_auth timed out after %ds (AD/winbind unresponsive)",
                            self.ntlm_timeout)
            return False, None
        nt_key = None
        for line in result.stdout.splitlines():
            if line.startswith("NT_KEY: "):
                nt_key = bytes.fromhex(line.split(":", 1)[1].strip())
        if result.returncode != 0 or nt_key is None:
            detail = " | ".join((result.stdout + result.stderr).splitlines())
            logging.warning("ntlm_auth rc=%d: %s", result.returncode, detail[:500])
        return result.returncode == 0 and nt_key is not None, nt_key

    def handle_inner(self, session, packet):
        code, identifier, kind, data = parse_eap(packet)
        if session.phase == "identity":
            if code != EAP_RESPONSE or kind != EAP_IDENTITY:
                raise ValueError("expected inner identity")
            session.auth_challenge = secrets.token_bytes(16)
            inner_id = session.next_inner_id()
            name = self.cfg.get("RADIUS_SERVER_NAME", "radius").encode()
            mschap_length = 5 + 16 + len(name)
            payload = struct.pack("!BBHB", 1, inner_id, mschap_length, 16)
            payload += session.auth_challenge + name
            session.phase = "mschap_response"
            return eap_packet(EAP_REQUEST, inner_id, EAP_MSCHAPV2, payload)

        if session.phase == "mschap_response":
            if code != EAP_RESPONSE or kind != EAP_MSCHAPV2 or len(data) < 54:
                raise ValueError("expected MSCHAPv2 response")
            opcode, mschap_id, mschap_length, value_size = struct.unpack(
                "!BBHB", data[:5]
            )
            if opcode != 2 or value_size != 49 or mschap_length > len(data):
                raise ValueError("invalid MSCHAPv2 response")
            value = data[5:54]
            peer_challenge = value[:16]
            nt_response = value[24:48]
            username = data[54:mschap_length]
            clean_username = strip_domain(username)
            # Some clients pad the MSCHAPv2 Name field; RFC 2759 does
            # not require it to be exact, so strip before it ends up in
            # logs or the admin panel's device table as a distinct row.
            session.username = username.decode("utf-8", "replace").strip()
            challenge = challenge_hash(peer_challenge,
                                       session.auth_challenge, clean_username)
            ok, nt_key = self.ntlm_auth(username, challenge, nt_response)
            if not ok:
                logging.warning(
                    "AD authentication or group policy rejected: user=%s mac=%s",
                    session.username, session.calling_station or "-")
                raise PermissionError("AD rejected credentials")
            response = authenticator_response(
                nt_key, nt_response, peer_challenge,
                session.auth_challenge, clean_username
            )
            message = ("S=" + response + " M=Access granted").encode()
            body = struct.pack("!BBH", 3, mschap_id, 4 + len(message)) + message
            session.phase = "mschap_success"
            return eap_packet(EAP_REQUEST, identifier, EAP_MSCHAPV2, body)

        if session.phase == "mschap_success":
            if code != EAP_RESPONSE or kind != EAP_MSCHAPV2 or not data or data[0] != 3:
                raise ValueError("expected MSCHAPv2 success acknowledgement")
            session.phase = "result_tlv"
            result_tlv = struct.pack("!HHH", 0x8003, 2, 1)
            return eap_packet(EAP_REQUEST, identifier, EAP_TLV, result_tlv)

        if session.phase == "result_tlv":
            if code != EAP_RESPONSE or kind != EAP_TLV or len(data) < 6:
                raise ValueError("expected protected Result TLV")
            tlv_type, tlv_length, tlv_status = struct.unpack("!HHH", data[:6])
            if (tlv_type & 0x3fff) != 3 or tlv_length != 2 or tlv_status != 1:
                raise PermissionError("client rejected protected result")
            session.accept_ready = True
            return None

        raise ValueError("unexpected inner state")

    def process_tls(self, session, tls_data):
        logging.debug("TLS input phase=%s bytes=%d", session.phase, len(tls_data))
        if tls_data:
            session.tls.bio_write(tls_data)
        if session.phase == "tls":
            try:
                session.tls.do_handshake()
                # Flush ChangeCipherSpec+Finished on its own and start
                # phase 2 only once the client has acknowledged it.
                #
                # Piggybacking the tunnelled EAP-Identity request onto the
                # same TLS flight deadlocks iOS: it processes the
                # handshake, discards the trailing application data, sends
                # the empty PEAP ACK the RFC prescribes and waits for phase
                # 2 to begin - while the server, having already flushed the
                # Identity request, has nothing left to send and ACKs back.
                # Both sides then wait until the supplicant times out.
                # Android happens to tolerate the piggyback, which is why
                # it authenticated while iOS never got past the handshake.
                session.phase = "start_phase2"
            except (SSL.WantReadError, SSL.WantWriteError):
                pass
            self.tls_output(session)
            return

        if session.phase == "start_phase2":
            session.phase = "identity"
            inner_id = session.next_inner_id()
            self.queue_inner(session, eap_packet(
                EAP_REQUEST, inner_id, EAP_IDENTITY, b""
            ))
            self.tls_output(session)
            logging.debug("phase 2 started, output bytes=%d", len(session.tls_out))
            return

        while True:
            try:
                clear = session.tls.recv(65535)
                if not clear:
                    break
                logging.debug("TLS decrypted bytes=%d", len(clear))
                if (len(clear) < 4 or clear[0] not in
                        (EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS, EAP_FAILURE) or
                        struct.unpack("!H", clear[2:4])[0] != len(clear)):
                    packet = eap_packet(EAP_RESPONSE, session.inner_id,
                                        clear[0], clear[1:])
                    logging.debug("headerless PEAPv0 inner response type=%d",
                                  clear[0])
                    reply = self.handle_inner(session, packet)
                    if reply is not None:
                        self.queue_inner(session, reply[4:])
                else:
                    session.inner_in += clear
            except SSL.WantReadError:
                break
        while len(session.inner_in) >= 4:
            inner_length = struct.unpack("!H", session.inner_in[2:4])[0]
            if inner_length < 4 or inner_length > 65535:
                raise ValueError("invalid inner EAP length")
            if len(session.inner_in) < inner_length:
                break
            packet = bytes(session.inner_in[:inner_length])
            del session.inner_in[:inner_length]
            logging.debug("inner EAP phase=%s bytes=%d", session.phase, len(packet))
            reply = self.handle_inner(session, packet)
            if reply is not None:
                self.queue_inner(session, reply[4:])
        self.tls_output(session)
        logging.debug("TLS output bytes=%d phase=%s", len(session.tls_out), session.phase)

    def handle_peap(self, radius_id, request_auth, session, outer_id, data):
        if not data:
            raise ValueError("PEAP flags are missing")
        flags = data[0]
        offset = 1
        if flags & TLS_LENGTH_INCLUDED:
            if len(data) < 5:
                raise ValueError("PEAP TLS length is missing")
            session.tls_in_expected = struct.unpack("!I", data[1:5])[0]
            offset = 5
        tls_fragment = data[offset:]

        if session.tls_out and not tls_fragment and flags == 0:
            outgoing = self.next_tls_fragment(session)
            eap = eap_packet(EAP_REQUEST, session.next_outer_id(),
                             EAP_PEAP, outgoing)
            return self.challenge(radius_id, request_auth, session, eap)

        session.tls_in += tls_fragment
        if flags & TLS_MORE_FRAGMENTS:
            ack = eap_packet(EAP_REQUEST, session.next_outer_id(),
                             EAP_PEAP, b"\x00")
            return self.challenge(radius_id, request_auth, session, ack)

        if session.tls_in_expected is not None and \
                len(session.tls_in) != session.tls_in_expected:
            raise ValueError("incomplete PEAP TLS message")
        complete = bytes(session.tls_in)
        session.tls_in.clear()
        session.tls_in_expected = None
        self.process_tls(session, complete)

        outgoing = self.next_tls_fragment(session)
        if outgoing is not None:
            eap = eap_packet(EAP_REQUEST, session.next_outer_id(),
                             EAP_PEAP, outgoing)
            return self.challenge(radius_id, request_auth, session, eap)
        if session.accept_ready:
            return self.accept(radius_id, request_auth, session, outer_id)
        ack = eap_packet(EAP_REQUEST, session.next_outer_id(),
                         EAP_PEAP, b"\x00")
        return self.challenge(radius_id, request_auth, session, ack)

    def handle(self, packet, peer):
        code, radius_id, request_auth, attrs = parse_radius(packet)
        if code != ACCESS_REQUEST:
            raise ValueError("not an Access-Request")
        if not client_allowed(peer[0], self.allowed_clients):
            raise PermissionError("unknown RADIUS client")
        if not verify_message_authenticator(packet, attrs, self.secret):
            raise PermissionError("invalid Message-Authenticator")

        # Duplicate suppression per RFC 5080 2.2.2, deliberately consulted
        # only after the shared secret has been proven. Answering from the
        # cache first would let anyone who can observe a request replay it
        # and pull responses out of the server without knowing the secret.
        cache_key = (peer, radius_id, request_auth)
        with self.lock:
            cached = self.responses.get(cache_key)
        if cached is not None:
            return cached[1]

        response = self.build_response(radius_id, request_auth, attrs, peer)
        if response is not None:
            with self.lock:
                self.responses[cache_key] = (time.monotonic(), response)
        return response

    def build_response(self, radius_id, request_auth, attrs, peer):
        eap_values = self.attributes(attrs, ATTR_EAP_MESSAGE)
        if not eap_values:
            raise ValueError("EAP-Message is missing")
        eap_raw = b"".join(eap_values)
        eap_code, eap_id, eap_type, data = parse_eap(eap_raw)
        if eap_code != EAP_RESPONSE:
            raise ValueError("expected EAP Response")

        # The AP resends Calling-Station-Id (the client's MAC) on every
        # Access-Request. Keep it refreshed on the session so the admin
        # panel can show which device a login came from, not just which
        # account - some APs only populate it on the outer identity
        # request, others on every one.
        calling_values = self.attributes(attrs, ATTR_CALLING_STATION_ID)
        calling_station = (normalize_mac(
            calling_values[0].decode("utf-8", "replace")) if calling_values
            else "")

        state_values = self.attributes(attrs, ATTR_STATE)
        if not state_values:
            if eap_type != EAP_IDENTITY:
                return self.reject(radius_id, request_auth, eap_id)
            session = self.new_session(eap_id)
            session.calling_station = calling_station
            start = eap_packet(EAP_REQUEST, session.next_outer_id(),
                               EAP_PEAP, bytes((TLS_START,)))
            return self.challenge(radius_id, request_auth, session, start)

        with self.lock:
            session = self.sessions.get(state_values[0])
        if session is None:
            return self.reject(radius_id, request_auth, eap_id)
        if calling_station:
            session.calling_station = calling_station
        if eap_type == EAP_NAK:
            return self.reject(radius_id, request_auth, eap_id)
        if eap_type != EAP_PEAP:
            raise ValueError("expected PEAP")

        # One packet at a time per session. A retransmit that arrives while
        # the previous one is still in ntlm_auth is dropped rather than
        # queued: the access point will retransmit again, and by then the
        # duplicate cache above usually has the answer.
        if not session.lock.acquire(blocking=False):
            logging.debug("session busy, dropping retransmit from %s", peer[0])
            return None
        try:
            return self.handle_peap(radius_id, request_auth, session,
                                    eap_id, data)
        except PermissionError:
            self.drop_session(session.token)
            return self.reject(radius_id, request_auth, eap_id)
        finally:
            session.lock.release()

    def serve(self):
        address = self.cfg.get("RADIUS_LISTEN_IP", "127.0.0.1")
        port = int(self.cfg.get("RADIUS_AUTH_PORT", "1812"))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((address, port))
        logging.info("custom RADIUS listening on %s:%d (%d worker threads)",
                     address, port, self.workers)
        # Requests are handled off the receive loop because ntlm_auth is a
        # blocking subprocess call: on a single thread one slow winbind
        # lookup stalled every other user's authentication for up to
        # RADIUS_REQUEST_TIMEOUT_SECONDS.
        with ThreadPoolExecutor(max_workers=self.workers,
                                thread_name_prefix="radius") as pool:
            while True:
                packet, peer = sock.recvfrom(65535)
                pool.submit(self.serve_one, sock, packet, peer)

    def serve_one(self, sock, packet, peer):
        try:
            self.cleanup()
            response = self.handle(packet, peer)
            if response is not None:
                sock.sendto(response, peer)
        except Exception as exc:
            logging.warning("request from %s rejected: %s", peer[0], exc)


def main():
    env_path = os.environ.get("RADIUS_ENV", DEFAULT_ENV_PATH)
    try:
        config = load_env(env_path)
    except OSError as exc:
        sys.exit(f"cannot read config {env_path}: {exc}\n"
                 f"Set RADIUS_ENV=/path/to/radius.env or create "
                 f"{DEFAULT_ENV_PATH} from .env.example.")
    logging.basicConfig(
        level=getattr(logging, config.get("RADIUS_LOG_LEVEL", "INFO").upper()),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    RadiusServer(config).serve()


if __name__ == "__main__":
    main()
