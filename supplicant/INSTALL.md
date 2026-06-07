# Supplicant setup

Runs **wpa_supplicant** with EAP-TLS 1.3.

**wpa_supplicant 2.11** is built from source and patched for large PQC certificate
chains.

Includes **liboqs** + **oqs-provider** with a corresponding OpenSSL configuration file.

Tested on Raspberry Pi 4 Model B + COMFAST CF-953AX running Raspberry Pi OS (2026-04-21).

Requirements:
- PQC client certificates generated and copied via SCP during **auth-server** setup

## 1. Run setup script

```bash
git clone https://github.com/crispyfi/pqc-eap-accel.git
cd pqc-eap-accel/supplicant
./setup.sh
```

## 2. Select PQC algorithm for testing

The `algorithm` command copies one algorithm's chain into the live wpa_supplicant cert paths.

```bash
algorithm <name>        # e.g. mldsa87
algorithm --help        # list available algorithms
```

## 3. Connect

Edit [`wlan.conf`](wlan.conf) with your `ssid`, `interface name`, and `country`.

Set `country` to your 2-letter ISO 3166-1 code (e.g. `US`, `GB`, `DE`).

Then connect using wpa_supplicant with `connect`:

```bash
connect
```
