# Authentication Server VM setup

Runs **radsecproxy** + **FreeRADIUS**, both built from source and patched for large PQC
certificate chains. Includes **liboqs** + **oqs-provider** with a corresponding OpenSSL configuration file.

Tested on Ubuntu 26.04 Server (minimized).

## 1. Run setup script

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/crispyfi/pqc-eap-accel.git
cd pqc-eap-accel/auth-server
./setup.sh
```

## 2. Generate the certificate chains

`generate.sh` builds a CA/server/client chain for every
supported algorithm (see [`README.md`](README.md)) and
stores  them in `certs_all/`.

```bash
cd /usr/local/etc/raddb
sudo OPENSSL_CONF=/usr/local/etc/raddb/openssl.conf ./generate.sh
```

## 3. Install radsecproxy certificates

RSA certificates are used for RadSec TLS connection between the proxy and auth-server VMs.

Copy the CA cert, server cert and key to the local radsecproxy cert directory:

```bash
RSP=/usr/local/etc/radsecproxy/certs
sudo cp certs_all/ca_rsa.pem      "$RSP/ca.pem"
sudo cp certs_all/server_rsa.pem  "$RSP/server-cert.pem"
sudo cp certs_all/server_rsa.key  "$RSP/server-key.pem"
```

Copy the CA cert, client cert and key to the proxy VM via SCP:


```bash
sudo scp certs_all/ca_rsa.pem      <user@proxy>:ca.pem
sudo scp certs_all/client_rsa.pem  <user@proxy>:client.pem
sudo scp certs_all/client_rsa.key  <user@proxy>:client.key
```
These must be moved into the local radsecproxy cert directory on the proxy VM.

## 4. Transfer client certificates

Copy the full set of client and CA certificates to the supplicant:

```bash
sudo scp -r certs_all/client_* <user@supplicant>:certs_all/
sudo scp -r certs_all/ca_* <user@supplicant>:certs_all/
```

## 5. Select PQC algorithm for testing

The `algorithm` command copies one algorithm's chain into the live FreeRADIUS cert paths.

```bash
algorithm <name>        # e.g. mldsa87
algorithm --help        # list available algorithms
```

## 6. (Optional) inject RadSec-leg latency

Introduce latency for outbound RadSec traffic.

```bash
latency set 50        # 50ms outbound
latency show
latency clear
```
To better simulate real-world latency, outbound latency should also be set on the proxy.

Use `latency set 50` on the auth server and proxy to simulate 100ms real-world latency as you would see with ping.


## 7. Start radsecproxy and FreeRADIUS

For better logging visibility each command should be run from its own shell.

```bash
sudo radsecproxy -f -d 5
freeradius-pqc
```