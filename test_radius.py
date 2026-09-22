#!/usr/bin/env python3
"""Tests for the custom RADIUS server.

Self-contained: generates its own throwaway certificate, talks to no
network and needs no Active Directory. Run with:

    python3 -m unittest -v test_radius
"""
import hashlib
import hmac
import sqlite3
import struct
import tempfile
import textwrap
import unittest
from pathlib import Path

from OpenSSL import SSL, crypto

import admin_web
import custom_radius as cr


def make_cert(directory):
    """Throwaway self-signed certificate so tests need no fixtures."""
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "radius.test"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(3600)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    cert_path = Path(directory) / "server.crt"
    key_path = Path(directory) / "server.key"
    cert_path.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    key_path.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    return cert_path, key_path


class MschapV2Vectors(unittest.TestCase):
    """RFC 2759 section 9 worked example. If these drift, every password
    in the domain starts being reported as wrong."""

    AUTH = bytes.fromhex("5B5D7C7D7B3F2F3E3C2C602132262628")
    PEER = bytes.fromhex("21402324255E262A28295F2B3A337C7E")
    USER = b"User"
    NT_RESPONSE = bytes.fromhex(
        "82309ECD8D708B5EA08FAA3981CD835442 33114A3D85D6DF".replace(" ", ""))
    PASSWORD_HASH_HASH = bytes.fromhex("41C00C584BD2D91C4017A2A12FA59F3F")

    def test_challenge_hash(self):
        self.assertEqual(
            cr.challenge_hash(self.PEER, self.AUTH, self.USER).hex().upper(),
            "D02E4386BCE91226")

    def test_authenticator_response(self):
        self.assertEqual(
            cr.authenticator_response(self.PASSWORD_HASH_HASH, self.NT_RESPONSE,
                                      self.PEER, self.AUTH, self.USER),
            "407A5589115FD0D6209F510FE9C04566932CDA56")


class UsernameNormalisation(unittest.TestCase):
    def test_strip_domain_keeps_upn_suffix(self):
        # The MSCHAPv2 ChallengeHash must be computed over exactly what the
        # client used: NetBIOS prefix removed, @realm suffix left alone.
        self.assertEqual(cr.strip_domain(rb"EXAMPLE\ivan"), b"ivan")
        self.assertEqual(cr.strip_domain(b"ivan@example.com"), b"ivan@example.com")

    def test_all_formats_resolve_to_one_account(self):
        for raw in (b"ivan", b"ivan@example.com", rb"EXAMPLE\ivan",
                    rb"EXAMPLE\Ivan@example.com", b"  IVAN  "):
            self.assertEqual(cr.normalize_username(raw), "ivan", raw)


class MacNormalisation(unittest.TestCase):
    def test_common_ap_formats_collapse_to_one_spelling(self):
        for raw in ("aabbccddeeff", "AA-BB-CC-DD-EE-FF",
                    "aa:bb:cc:dd:ee:ff", "AABB.CCDD.EEFF"):
            self.assertEqual(cr.normalize_mac(raw), "AA:BB:CC:DD:EE:FF", raw)

    def test_garbage_normalizes_to_empty(self):
        for raw in ("", "not-a-mac", "aabbccddee"):  # too short
            self.assertEqual(cr.normalize_mac(raw), "", raw)


class ClientFiltering(unittest.TestCase):
    def test_wildcard_allows_everything(self):
        self.assertIsNone(cr.parse_allowed_clients("*"))
        self.assertTrue(cr.client_allowed("8.8.8.8", None))

    def test_list_and_cidr(self):
        nets = cr.parse_allowed_clients("192.0.2.10, 198.51.100.0/24")
        self.assertTrue(cr.client_allowed("192.0.2.10", nets))
        self.assertTrue(cr.client_allowed("198.51.100.7", nets))
        self.assertFalse(cr.client_allowed("198.51.101.7", nets))
        self.assertFalse(cr.client_allowed("not-an-ip", nets))


class RadiusFraming(unittest.TestCase):
    SECRET = b"testing123"

    def build_request(self, ident=7, eap=b"\x02\x01\x00\x06\x01x"):
        auth = bytes(range(16))
        body = cr.attr(cr.ATTR_EAP_MESSAGE, eap)
        ma_offset = len(body)
        body += cr.attr(cr.ATTR_MESSAGE_AUTHENTICATOR, bytes(16))
        packet = bytearray(struct.pack("!BBH", 1, ident, 20 + len(body)) + auth + body)
        digest = hmac.new(self.SECRET, bytes(packet), hashlib.md5).digest()
        packet[20 + ma_offset + 2:20 + ma_offset + 18] = digest
        return bytes(packet), auth

    def test_message_authenticator_accepts_genuine_packet(self):
        packet, _ = self.build_request()
        _, _, _, attrs = cr.parse_radius(packet)
        self.assertTrue(cr.verify_message_authenticator(packet, attrs, self.SECRET))

    def test_message_authenticator_rejects_tampering(self):
        packet, _ = self.build_request()
        for index in (1, 25, len(packet) - 1):
            broken = bytearray(packet)
            broken[index] ^= 0xFF
            try:
                _, _, _, attrs = cr.parse_radius(bytes(broken))
            except ValueError:
                continue  # malformed is rejected even earlier
            self.assertFalse(
                cr.verify_message_authenticator(bytes(broken), attrs, self.SECRET),
                f"tampering at byte {index} went unnoticed")

    def test_message_authenticator_rejects_wrong_secret(self):
        packet, _ = self.build_request()
        _, _, _, attrs = cr.parse_radius(packet)
        self.assertFalse(cr.verify_message_authenticator(packet, attrs, b"wrong"))

    def test_long_eap_message_is_split_into_253_byte_attributes(self):
        payload = bytes(600)
        response = cr.radius_response(cr.ACCESS_CHALLENGE, 1, bytes(16),
                                      [(cr.ATTR_EAP_MESSAGE, payload)], self.SECRET)
        _, _, _, attrs = cr.parse_radius(response)
        chunks = [v for k, v, _ in attrs if k == cr.ATTR_EAP_MESSAGE]
        self.assertEqual(len(chunks), 3)
        self.assertEqual(b"".join(chunks), payload)

    def test_response_authenticator_is_valid(self):
        request_auth = bytes(range(16))
        response = cr.radius_response(cr.ACCESS_ACCEPT, 5, request_auth,
                                      [(cr.ATTR_EAP_MESSAGE, b"\x03\x01\x00\x04")],
                                      self.SECRET)
        expected = hashlib.md5(
            response[:4] + request_auth + response[20:] + self.SECRET).digest()
        self.assertEqual(response[4:20], expected)

    def test_attribute_value_cannot_overflow(self):
        with self.assertRaises(ValueError):
            cr.attr(cr.ATTR_STATE, bytes(254))


class MppeKeys(unittest.TestCase):
    SECRET = b"testing123"

    def test_key_survives_a_round_trip(self):
        # Decrypt with the RFC 2548 procedure to prove the AP will recover
        # exactly the key material the TLS exporter produced.
        key = bytes(range(32))
        request_auth = bytes(range(16, 32))
        blob = cr.encrypt_mppe_key(key, self.SECRET, request_auth)
        salt, cipher = blob[:2], blob[2:]
        plain, previous = bytearray(), request_auth + salt
        for start in range(0, len(cipher), 16):
            block = cipher[start:start + 16]
            mask = hashlib.md5(self.SECRET + previous).digest()
            plain += bytes(a ^ b for a, b in zip(block, mask))
            previous = block
        self.assertEqual(plain[0], len(key))
        self.assertEqual(bytes(plain[1:1 + len(key)]), key)

    def test_salt_has_high_bit_set_and_varies(self):
        salts = {cr.encrypt_mppe_key(bytes(32), self.SECRET, bytes(16))[:2]
                 for _ in range(50)}
        self.assertGreater(len(salts), 1)
        for salt in salts:
            self.assertTrue(salt[0] & 0x80)


class PeapPhaseTwo(unittest.TestCase):
    """Regression test for the iOS deadlock.

    iOS discards application data that arrives in the same EAP message as
    the TLS Finished, then sends a bare PEAP ACK and waits for phase 2.
    The server must therefore keep the tunnelled EAP-Identity request back
    until that ACK arrives. Android tolerated the piggyback, so this bug
    looked like "iOS is broken" rather than a server fault.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cert, key = make_cert(self.tmp.name)
        self.server = cr.RadiusServer({
            "RADIUS_SHARED_SECRET": "testing123",
            "RADIUS_TLS_CERT_FILE": str(cert),
            "RADIUS_TLS_KEY_FILE": str(key),
            "AD_NETBIOS_DOMAIN": "EXAMPLE",
        })

    def handshake(self):
        """Drive a real TLS handshake into a fresh session."""
        session = self.server.new_session(1)
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        context.set_min_proto_version(SSL.TLS1_2_VERSION)
        context.set_max_proto_version(SSL.TLS1_2_VERSION)
        client = SSL.Connection(context, None)
        client.set_connect_state()

        for _ in range(20):
            try:
                client.do_handshake()
            except (SSL.WantReadError, SSL.WantWriteError):
                pass
            outgoing = b""
            while True:
                try:
                    outgoing += client.bio_read(65535)
                except SSL.WantReadError:
                    break
            if not outgoing:
                break
            self.server.process_tls(session, outgoing)
            pending = session.tls_out[session.tls_out_offset:]
            session.tls_out, session.tls_out_offset = b"", 0
            if pending:
                client.bio_write(pending)
        return session, client

    def test_finished_flight_carries_no_application_data(self):
        session, client = self.handshake()
        self.assertEqual(session.phase, "start_phase2")
        # The client completed the handshake but must have nothing to read:
        # an Identity request here is exactly what iOS throws away.
        with self.assertRaises(SSL.WantReadError):
            client.recv(65535)

    def test_identity_request_is_sent_after_the_bare_ack(self):
        session, client = self.handshake()
        self.server.process_tls(session, b"")   # the empty PEAP ACK
        self.assertEqual(session.phase, "identity")
        self.assertTrue(session.tls_out, "server sent nothing — this is the deadlock")
        client.bio_write(session.tls_out)
        inner = client.recv(65535)
        # PEAPv0 strips the 4-byte EAP header: type byte then payload.
        self.assertEqual(inner[0], cr.EAP_IDENTITY)


class StateDatabase(unittest.TestCase):
    """RADIUS_STATE_DB is optional and best-effort: a hiccup here must
    never break authentication, and the admin panel must fall back to
    parsing the journal when the DB is absent or unreadable."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cert, key = make_cert(self.tmp.name)
        self.db_path = str(Path(self.tmp.name) / "state.db")
        self.server = cr.RadiusServer({
            "RADIUS_SHARED_SECRET": "x",
            "RADIUS_TLS_CERT_FILE": str(cert),
            "RADIUS_TLS_KEY_FILE": str(key),
            "AD_NETBIOS_DOMAIN": "T",
            "RADIUS_STATE_DB": self.db_path,
        })

    def test_without_state_db_configured_server_still_starts(self):
        cert, key = make_cert(self.tmp.name)
        server = cr.RadiusServer({
            "RADIUS_SHARED_SECRET": "x",
            "RADIUS_TLS_CERT_FILE": str(cert),
            "RADIUS_TLS_KEY_FILE": str(key),
            "AD_NETBIOS_DOMAIN": "T",
        })
        self.assertIsNone(server.db)
        server.record_login("ivan", "-", True, "Access-Accept")  # must not raise

    def test_record_login_writes_a_row(self):
        self.server.record_login("ivan", "AA:BB:CC:DD:EE:01", True, "Access-Accept")
        rows = self.server.db.execute(
            "SELECT user, mac, ok, detail FROM logins").fetchall()
        self.assertEqual(rows, [("ivan", "AA:BB:CC:DD:EE:01", 1, "Access-Accept")])

    def test_second_connection_sees_writes_from_the_first(self):
        # Simulates admin_web.py, a separate process, reading the file
        # custom_radius.py just wrote to - this is what WAL mode is for.
        self.server.record_login("ivan", "-", False, "AD rejected")
        reader = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        count = reader.execute("SELECT COUNT(*) FROM logins").fetchone()[0]
        self.assertEqual(count, 1)

    def test_admin_panel_reads_the_same_rows_the_server_wrote(self):
        self.server.record_login("arman.b", "AA:BB:CC:DD:EE:01", True, "Access-Accept")
        self.server.record_login("arman.b", "AA:BB:CC:DD:EE:02", False, "AD rejected")
        events = admin_web.query_events_from_db(self.db_path)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["user"], "arman.b")
        devices = admin_web.device_stats(events)
        self.assertEqual(len(devices), 2)

    def test_missing_db_file_falls_back_to_none(self):
        events = admin_web.query_events_from_db("/no/such/path.db")
        self.assertIsNone(events, "render_page must fall back to the journal on this")

    def test_prune_removes_rows_past_retention(self):
        self.server.db.execute(
            "INSERT INTO logins (ts, user, mac, ok, detail) VALUES (?,?,?,?,?)",
            ("2000-01-01T00:00:00+0000", "old", "-", 1, "Access-Accept"))
        self.server.db.commit()
        self.server.db_retention_days = 90
        self.server.last_prune = 0.0  # force the throttle to allow this run
        self.server.prune_state_db()
        remaining = self.server.db.execute(
            "SELECT COUNT(*) FROM logins WHERE user='old'").fetchone()[0]
        self.assertEqual(remaining, 0)


class MschapUsernameHygiene(unittest.TestCase):
    """A client that pads the MSCHAPv2 Name field must not turn into a
    lookalike duplicate account in logs or the admin panel's device
    table (e.g. "ivan" and "ivan " as two separate rows)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cert, key = make_cert(self.tmp.name)
        self.server = cr.RadiusServer({
            "RADIUS_SHARED_SECRET": "x",
            "RADIUS_TLS_CERT_FILE": str(cert),
            "RADIUS_TLS_KEY_FILE": str(key),
            "AD_NETBIOS_DOMAIN": "T",
        })

    def test_padded_username_is_stripped_before_it_is_stored(self):
        session = self.server.new_session(1)
        session.phase = "mschap_response"
        session.auth_challenge = bytes(16)
        username = b"ivan.petrov "  # trailing pad, as a real client sent
        value = bytes(16) + bytes(8) + bytes(24) + bytes(1)  # peer_challenge+reserved+nt_response+flags (49 bytes)
        mschap_length = 5 + 49 + len(username)
        packet = (struct.pack("!BBHB", 2, 1, mschap_length, 49) + value
                 + username)
        eap = cr.eap_packet(cr.EAP_RESPONSE, 1, cr.EAP_MSCHAPV2, packet)
        with self.assertRaises(PermissionError):  # no real ntlm_auth here
            self.server.handle_inner(session, eap)
        self.assertEqual(session.username, "ivan.petrov")


class CallingStationTracking(unittest.TestCase):
    """The admin panel maps logins to devices by Calling-Station-Id, so a
    server that stops recording it silently breaks that mapping."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cert, key = make_cert(self.tmp.name)
        self.server = cr.RadiusServer({
            "RADIUS_SHARED_SECRET": "x",
            "RADIUS_TLS_CERT_FILE": str(cert),
            "RADIUS_TLS_KEY_FILE": str(key),
            "AD_NETBIOS_DOMAIN": "T",
        })

    def test_mac_is_captured_on_session_start(self):
        eap = cr.eap_packet(cr.EAP_RESPONSE, 1, cr.EAP_IDENTITY, b"anonymous")
        attrs = [(cr.ATTR_EAP_MESSAGE, eap, 0),
                 (cr.ATTR_CALLING_STATION_ID, b"AA-BB-CC-DD-EE-01", 0)]
        self.server.build_response(1, bytes(16), attrs, ("127.0.0.1", 1))
        session, = self.server.sessions.values()
        self.assertEqual(session.calling_station, "AA:BB:CC:DD:EE:01")

    def test_mac_refreshes_on_a_later_request_in_the_same_session(self):
        eap = cr.eap_packet(cr.EAP_RESPONSE, 1, cr.EAP_IDENTITY, b"anonymous")
        attrs = [(cr.ATTR_EAP_MESSAGE, eap, 0),
                 (cr.ATTR_CALLING_STATION_ID, b"AA-BB-CC-DD-EE-01", 0)]
        self.server.build_response(1, bytes(16), attrs, ("127.0.0.1", 1))
        session, = self.server.sessions.values()

        eap2 = cr.eap_packet(cr.EAP_RESPONSE, 1, cr.EAP_NAK, b"")
        attrs2 = [(cr.ATTR_EAP_MESSAGE, eap2, 0),
                 (cr.ATTR_STATE, session.token, 0),
                 (cr.ATTR_CALLING_STATION_ID, b"aabbccddee02", 0)]
        self.server.build_response(2, bytes(16), attrs2, ("127.0.0.1", 1))
        self.assertEqual(session.calling_station, "AA:BB:CC:DD:EE:02")

    def test_missing_attribute_leaves_mac_blank_not_crashing(self):
        eap = cr.eap_packet(cr.EAP_RESPONSE, 1, cr.EAP_IDENTITY, b"anonymous")
        attrs = [(cr.ATTR_EAP_MESSAGE, eap, 0)]  # no Calling-Station-Id at all
        self.server.build_response(1, bytes(16), attrs, ("127.0.0.1", 1))
        session, = self.server.sessions.values()
        self.assertEqual(session.calling_station, "")


class AdminPanel(unittest.TestCase):
    def test_journal_is_parsed_into_events(self):
        journal = textwrap.dedent("""\
            2026-09-21T05:03:17+0000 h p[1]: INFO access accepted user=ivan@example.com mac=AA:BB:CC:DD:EE:01
            2026-09-21T05:04:00+0000 h p[1]: WARNING AD authentication or group policy rejected: user=petr mac=AA:BB:CC:DD:EE:02
            2026-09-21T05:05:00+0000 h p[1]: WARNING request from 10.0.0.9 rejected: unknown RADIUS client
            2026-09-21T05:06:00+0000 h p[1]: WARNING ntlm_auth timed out after 5s
            2026-09-21T05:07:00+0000 h p[1]: DEBUG TLS input phase=tls bytes=131
        """)
        events = admin_web.parse_events(journal)
        self.assertEqual(len(events), 4, "debug chatter must not become an event")
        self.assertEqual([e["ok"] for e in events], [True, False, False, False])
        self.assertEqual(events[0]["user"], "ivan@example.com")
        self.assertEqual(events[0]["mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(events[2]["user"], "10.0.0.9")
        self.assertEqual(events[2]["mac"], "-", "no MAC available for a pre-EAP rejection")

    def test_double_space_before_mac_still_parses(self):
        # A handful of real production lines had "user=x  mac=y" (two
        # spaces) from before the MSCHAPv2 username-padding fix landed.
        journal = ("2026-09-22T05:08:24+0000 h p[1]: INFO access accepted "
                  "user=ivan@example.com  mac=B2:F6:A2:FB:C8:03\n")
        events = admin_web.parse_events(journal)
        self.assertEqual(events[0]["mac"], "B2:F6:A2:FB:C8:03")

    def test_old_journal_lines_without_mac_still_parse(self):
        # Lines written before Calling-Station-Id tracking was added must
        # not start throwing or silently dropping events after an upgrade.
        journal = "2026-09-21T05:03:17+0000 h p[1]: INFO access accepted user=ivan\n"
        events = admin_web.parse_events(journal)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["mac"], "-")

    def test_device_stats_separates_two_devices_of_one_user(self):
        events = [
            {"ts": "2026-01-01T00:00:00", "user": "a", "mac": "AA:BB:CC:DD:EE:01", "ok": True},
            {"ts": "2026-01-01T00:01:00", "user": "a", "mac": "AA:BB:CC:DD:EE:01", "ok": True},
            {"ts": "2026-01-01T00:02:00", "user": "a", "mac": "AA:BB:CC:DD:EE:02", "ok": False},
        ]
        devices = admin_web.device_stats(events)
        self.assertEqual(len(devices), 2, "one phone, one laptop must stay separate rows")
        by_mac = {d["mac"]: d for d in devices}
        self.assertEqual(by_mac["AA:BB:CC:DD:EE:01"]["accepted"], 2)
        self.assertEqual(by_mac["AA:BB:CC:DD:EE:02"]["rejected"], 1)
        # most recently active device first
        self.assertEqual(devices[0]["mac"], "AA:BB:CC:DD:EE:02")

    def test_mac_kind_flags_randomized_addresses(self):
        # iOS/Android per-network MAC randomization sets the locally
        # administered bit (0x02) on the first octet.
        self.assertEqual(admin_web.mac_kind("02:11:22:33:44:55"), "случайный")
        self.assertEqual(admin_web.mac_kind("00:1A:11:AA:BB:CC"), "заводской")
        self.assertEqual(admin_web.mac_kind("-"), "")
        self.assertEqual(admin_web.mac_kind(""), "")

    def test_apply_commands_append_a_missing_key(self):
        # A bare sed exits 0 and changes nothing when the key is absent;
        # the generated command must cover that case.
        commands = admin_web.build_apply_commands({"RADIUS_CLIENT_IP": "10.0.0.0/8"})
        self.assertIn("grep -q '^RADIUS_CLIENT_IP='", commands[0])
        self.assertIn("tee -a", commands[0])
        self.assertIn("sudo systemctl restart custom-radius", commands[-1])

    def test_apply_commands_escape_slashes_for_sed(self):
        commands = admin_web.build_apply_commands({"RADIUS_CLIENT_IP": "10.0.0.0/8"})
        self.assertIn(r"10.0.0.0\/8", commands[0])

    def test_secrets_are_never_displayable(self):
        for key in admin_web.SAFE_CONFIG_KEYS + list(admin_web.EDITABLE_KEYS):
            self.assertNotIn("SECRET", key)
            self.assertNotIn("PASSWORD", key)
            self.assertNotIn("KEY_FILE", key)


if __name__ == "__main__":
    unittest.main()
