#!/usr/bin/env python3
"""Build a .mobileconfig for iOS that bundles a CA certificate and the
Wi-Fi/PEAP-MSCHAPv2 settings in one payload.

Only needed when the RADIUS server presents a certificate from a private
CA. Installing this single profile trusts that CA *only for this Wi-Fi
network* (via TLSTrustedServerNames), so the separate "Certificate Trust
Settings" step that trips people up on iOS is not needed.

With a publicly trusted certificate (Let's Encrypt, Sectigo, ...) no
profile is required at all - iOS validates the chain on its own.

Every value comes from the environment file; nothing site-specific is
hard-coded here. Usage:

    python3 gen_ios_profile.py [--env PATH] [--out PATH] [SSID]
"""
import argparse
import plistlib
import subprocess
import sys
import uuid
from pathlib import Path

DEFAULT_ENV_PATH = "/etc/custom-radius/radius.env"


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


def cert_to_der(pem_path):
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(pem_path), "-outform", "der"],
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.exit(f"cannot read CA certificate {pem_path}: "
                 + proc.stderr.decode("utf-8", "replace").strip())
    return proc.stdout


def build_profile(ssid, server_names, ca_der, organization, prefix):
    cert_uuid = str(uuid.uuid4())
    wifi_uuid = str(uuid.uuid4())
    profile_uuid = str(uuid.uuid4())

    cert_payload = {
        "PayloadType": "com.apple.security.root",
        "PayloadIdentifier": f"{prefix}.cacert.{cert_uuid}",
        "PayloadUUID": cert_uuid,
        "PayloadDisplayName": f"{organization} RADIUS CA",
        "PayloadVersion": 1,
        "PayloadCertificateFileName": "ca.crt",
        "PayloadContent": ca_der,
    }

    wifi_payload = {
        "PayloadType": "com.apple.wifi.managed",
        "PayloadIdentifier": f"{prefix}.wifi.{wifi_uuid}",
        "PayloadUUID": wifi_uuid,
        "PayloadDisplayName": f"Wi-Fi: {ssid}",
        "PayloadVersion": 1,
        "SSID_STR": ssid,
        "HIDDEN_NETWORK": False,
        "EncryptionType": "WPA2",
        "AutoJoin": True,
        "EAPClientConfiguration": {
            "AcceptEAPTypes": [25],  # PEAP
            "TLSTrustedServerNames": server_names,
            "TTLSInnerAuthentication": "MSCHAPv2",
            "OuterIdentity": "anonymous",
            "PayloadCertificateAnchorUUID": [cert_uuid],
        },
    }

    return {
        "PayloadType": "Configuration",
        "PayloadIdentifier": f"{prefix}.{profile_uuid}",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
        "PayloadDisplayName": f"{organization} Wi-Fi ({ssid})",
        "PayloadDescription": (
            "Устанавливает CA-сертификат RADIUS-сервера и настраивает "
            f"подключение к Wi-Fi «{ssid}» (PEAP-MSCHAPv2). "
            "Логин и пароль AD вводятся при первом подключении."),
        "PayloadOrganization": organization,
        "PayloadContent": [cert_payload, wifi_payload],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ssid", nargs="?", help="Wi-Fi SSID (default: WIFI_SSID)")
    parser.add_argument("--env", default=DEFAULT_ENV_PATH,
                        help=f"config file (default: {DEFAULT_ENV_PATH})")
    parser.add_argument("--out", help="output path (default: <SSID>.mobileconfig)")
    args = parser.parse_args()

    try:
        cfg = load_env(args.env)
    except OSError as exc:
        sys.exit(f"cannot read config {args.env}: {exc}")

    ssid = args.ssid or cfg.get("WIFI_SSID", "")
    if not ssid:
        sys.exit("SSID not given and WIFI_SSID is not set in " + args.env)

    # iOS matches TLSTrustedServerNames against the DNS names in the
    # certificate's CN/SAN. An IP address literal never matches, so a
    # server certificate issued to a bare IP cannot be trusted this way.
    server_names = [n.strip() for n in
                    cfg.get("RADIUS_SERVER_NAME", "").split(",") if n.strip()]
    if not server_names:
        sys.exit("RADIUS_SERVER_NAME is not set in " + args.env)
    literal_ips = [n for n in server_names if n.replace(".", "").isdigit()]
    server_names = [n for n in server_names if n not in literal_ips]
    for name in literal_ips:
        print(f"warning: dropping {name} from TLSTrustedServerNames - iOS "
              "matches DNS names from the certificate CN/SAN only, never an "
              "IP address literal.", file=sys.stderr)
    if not server_names:
        sys.exit("RADIUS_SERVER_NAME contains only IP addresses. iOS cannot "
                 "match those, so the profile would never trust the server. "
                 "Add the DNS name from the certificate SAN, for example "
                 "RADIUS_SERVER_NAME=radius.example.com")

    ca_file = cfg.get("RADIUS_TLS_CA_FILE", "")
    if not ca_file:
        sys.exit("RADIUS_TLS_CA_FILE is not set in " + args.env)

    organization = cfg.get("PROFILE_ORGANIZATION", "RADIUS")
    prefix = cfg.get("PROFILE_IDENTIFIER_PREFIX", "local.radius")

    profile = build_profile(ssid, server_names, cert_to_der(ca_file),
                            organization, prefix)

    out_path = Path(args.out) if args.out else Path(f"{ssid}.mobileconfig")
    with open(out_path, "wb") as fh:
        plistlib.dump(profile, fh)
    print(f"written: {out_path}")


if __name__ == "__main__":
    main()
