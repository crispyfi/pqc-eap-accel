# Proxy VM setup

Runs the **`eap-accel`** proxy and **radsecproxy**.

The proxy sends RADIUS/UDP to the local radsecproxy instance, which carries it over RadSec/TLS to the auth server.

Tested on Ubuntu 26.04 Server (minimized). 

Requirements:
- RadSec client certificates generated and copied via SCP during **auth-server** setup
- IP address of **auth-server**

## 1. Run setup script

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/crispyfi/pqc-eap-accel.git
cd pqc-eap-accel/proxy
AUTH_SERVER_IP=x.x.x.x ./setup.sh    # Set your auth-server IP address
```

## 2. Install radsecproxy certificates

Move the certs copied from the auth server into the local radsecproxy cert directory:

```bash
cd ~
RSP=/usr/local/etc/radsecproxy/certs
sudo install -m 0644 ca.pem      "$RSP/ca.pem"
sudo install -m 0644 client.pem  "$RSP/client.pem"
sudo install -m 0600 client.key  "$RSP/client.key"
```

## 3. (Optional) inject latency

Introduce latency on outbound RadSec traffic.

```bash
latency set 50
latency show
latency clear
```

Set `latency set 50` on both the proxy and the auth server to simulate ~100 ms
real-world round-trip, as you'd see with ping.

## 4. Start radsecproxy and the proxy

For better logging visibility each command should be run from its own shell.

```bash
sudo radsecproxy -f -d 5
eap-accel --mode <passthrough | reassemble>
```

`passthrough` forwards fragments verbatim.

`reassemble` enables EAP reassembly.
