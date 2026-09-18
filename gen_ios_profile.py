#!/usr/bin/env python3
"""Build a .mobileconfig for iOS that bundles the lab CA certificate and the
Wi-Fi/PEAP-MSCHAPv2 settings in one payload.

Installing this single profile trusts the CA *only for this Wi-Fi network*
(via TrustedServerNames), so the extra "Certificate Trust Settings" step
that trips people up on iOS is not needed.
"""
import base64
import plistlib
import subprocess
import sys
import uuid
from pathlib import Path

LAB_DIR = Path("/home/dev/radius-lab")


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
        capture_output=True, check=True,
    )
    return proc.stdout


def build_profile(ssid, server_names, ca_der):
    cert_uuid = str(uuid.uuid4())
    wifi_uuid = str(uuid.uuid4())
    profile_uuid = str(uuid.uuid4())

    cert_payload = {
        "PayloadType": "com.apple.security.root",
        "PayloadIdentifier": f"com.evrika.radiuslab.cacert.{cert_uuid}",
        "PayloadUUID": cert_uuid,
        "PayloadDisplayName": "Custom RADIUS Lab CA",
        "PayloadVersion": 1,
        "PayloadCertificateFileName": "ca.crt",
        "PayloadContent": ca_der,
    }

    wifi_payload = {
        "PayloadType": "com.apple.wifi.managed",
        "PayloadIdentifier": f"com.evrika.radiuslab.wifi.{wifi_uuid}",
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

    profile = {
        "PayloadType": "Configuration",
        "PayloadIdentifier": f"com.evrika.radiuslab.{profile_uuid}",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
        "PayloadDisplayName": f"Evrika Wi-Fi ({ssid})",
        "PayloadDescription": ("Устанавливает CA-сертификат лаборатории RADIUS "
                               f"и настраивает подключение к Wi-Fi «{ssid}» "
                               "(PEAP-MSCHAPv2). Логин и пароль AD вводятся "
                               "при первом подключении."),
        "PayloadOrganization": "Evrika",
        "PayloadContent": [cert_payload, wifi_payload],
    }
    return profile


def main():
    cfg = load_env(LAB_DIR / ".env")
    ssid = sys.argv[1] if len(sys.argv) > 1 else "wifi.evrika.services"
    server_names = [cfg.get("RADIUS_SERVER_NAME", "10.10.1.164"), "sev.evrika.com"]
    server_names = list(dict.fromkeys(n for n in server_names if n))

    ca_der = cert_to_der(cfg.get("RADIUS_TLS_CA_FILE", str(LAB_DIR / "certs/ca.crt")))
    profile = build_profile(ssid, server_names, ca_der)

    out_path = LAB_DIR / "evrika-wifi.mobileconfig"
    with open(out_path, "wb") as fh:
        plistlib.dump(profile, fh)
    print(f"written: {out_path}")


if __name__ == "__main__":
    main()
