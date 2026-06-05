######################################################################
#
#	Make file to be installed in /etc/raddb/certs to enable
#	the easy creation of certificates.
#
#	See the README file in this directory for more information.
#
#	$Id: 1b6b944ee3ad2512cba7803db7cb013706318bec $
#
######################################################################

DH_KEY_SIZE	= 2048
OPENSSL		= openssl
EXTERNAL_CA	= $(wildcard external_ca.*)

ifneq "$(EXTERNAL_CA)" ""
PARTIAL		= -partial_chain
endif

#
#  Set the passwords
#
include passwords.mk

######################################################################
#
#  Make the necessary files, but not client certificates.
#
######################################################################
.PHONY: all
all: index.txt serial ca server client

.PHONY: client
client: client_$(name).pem

.PHONY: ca
ca: ca_$(name).der ca_$(name).crl

.PHONY: server
server: server_$(name).pem server.vrfy

.PHONY: inner-server
inner-server: inner-server_$(name).pem inner-server.vrfy

.PHONY: verify
verify: server.vrfy client.vrfy

passwords.mk: server.cnf ca.cnf client.cnf inner-server.cnf
	@echo "PASSWORD_SERVER	= '$(shell grep output_password server.cnf | sed 's/.*=//;s/^ *//')'"		> $@
	@echo "PASSWORD_INNER	= '$(shell grep output_password inner-server.cnf | sed 's/.*=//;s/^ *//')'"	>> $@
	@echo "PASSWORD_CA	= '$(shell grep output_password ca.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "PASSWORD_CLIENT	= '$(shell grep output_password client.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "USER_NAME	= '$(shell grep emailAddress client.cnf | grep '@' | sed 's/.*=//;s/^ *//')'"	>> $@
	@echo "CA_DEFAULT_DAYS  = '$(shell grep default_days ca.cnf | sed 's/.*=//;s/^ *//')'"			>> $@

######################################################################
#
#  Diffie-Hellman parameters
#
######################################################################
dh:
	$(OPENSSL) dhparam -out dh -2 $(DH_KEY_SIZE)

######################################################################
#
#  Create a new self-signed CA certificate
#
######################################################################
ca_$(name).key ca_$(name).pem: ca.cnf
	@[ -f index.txt ] || $(MAKE) index.txt
	@[ -f serial ] || $(MAKE) serial
	$(OPENSSL) req -new -newkey $(name) -x509 -keyout ca_$(name).key -out ca_$(name).pem \
		-days $(CA_DEFAULT_DAYS) -config ./ca.cnf \
		-passin pass:$(PASSWORD_CA) -passout pass:$(PASSWORD_CA)
	chmod g+r ca_$(name).key

ca_$(name).der: ca_$(name).pem
	$(OPENSSL) x509 -inform PEM -outform DER -in ca_$(name).pem -out ca_$(name).der

ca_$(name).crl: ca_$(name).pem
	$(OPENSSL) ca -gencrl -keyfile ca_$(name).key -cert ca_$(name).pem -config ./ca.cnf -out ca-crl.pem -key $(PASSWORD_CA)
	$(OPENSSL) crl -in ca-crl.pem -outform der -out ca_$(name).crl
	rm ca-crl.pem

######################################################################
#
#  Create a new server certificate, signed by the above CA.
#
######################################################################
server_$(name).csr server_$(name).key: server.cnf
	$(OPENSSL) req -new -newkey $(name) -out server_$(name).csr -keyout server_$(name).key -config ./server.cnf
	chmod g+r server_$(name).key

server_$(name).crt: ca_$(name).key ca_$(name).pem server_$(name).csr
	$(OPENSSL) ca -batch -keyfile ca_$(name).key -cert ca_$(name).pem -in server_$(name).csr  -key $(PASSWORD_CA) -out server_$(name).crt -extensions xpserver_ext -extfile xpextensions -config ./server.cnf

server_$(name).p12: server_$(name).crt
	$(OPENSSL) pkcs12 -export -in server_$(name).crt -inkey server_$(name).key -out server_$(name).p12  -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)
	chmod g+r server_$(name).p12

server_$(name).der: server_$(name).pem
	$(OPENSSL) x509 -inform PEM -outform DER -in server_$(name).pem -out server_$(name).der

server_$(name).pem: server_$(name).p12
	$(OPENSSL) pkcs12 -in server_$(name).p12 -out server_$(name).pem -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)
	chmod g+r server_$(name).pem

.PHONY: server.vrfy
server.vrfy: ca_$(name).pem
	@$(OPENSSL) verify $(PARTIAL) -CAfile ca_$(name).pem server_$(name).pem

######################################################################
#
#  Create a new client certificate, signed by the the above server
#  certificate.
#
######################################################################
client_$(name).csr client_$(name).key: client.cnf
	$(OPENSSL) req -new -newkey $(name) -out client_$(name).csr -keyout client_$(name).key -config ./client.cnf
	chmod g+r client_$(name).key

client_$(name).crt: ca_$(name).key ca_$(name).pem client_$(name).csr
	$(OPENSSL) ca -batch -keyfile ca_$(name).key -cert ca_$(name).pem -in client_$(name).csr  -key $(PASSWORD_CA) -out client_$(name).crt -extensions xpclient_ext -extfile xpextensions -config ./client.cnf

client_$(name).p12: client_$(name).crt
	$(OPENSSL) pkcs12 -export -in client_$(name).crt -inkey client_$(name).key -out client_$(name).p12  -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	chmod g+r client_$(name).p12
	cp client_$(name).p12 $(USER_NAME)_$(name).p12

client_$(name).pem: client_$(name).p12
	$(OPENSSL) pkcs12 -in client_$(name).p12 -out client_$(name).pem -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	chmod g+r client_$(name).pem
	cp client_$(name).pem $(USER_NAME)_$(name).pem

.PHONY: client.vrfy
client.vrfy: ca_$(name).pem client_$(name).pem
	c_rehash .
	$(OPENSSL) verify -CApath . client_$(name).pem

######################################################################
#
#  Create a new inner-server certificate, signed by the above CA.
#
######################################################################
inner-server_$(name).csr inner-server_$(name).key: inner-server.cnf
	$(OPENSSL) req -new  -out inner-server_$(name).csr -keyout inner-server_$(name).key -config ./inner-server.cnf
	chmod g+r inner-server_$(name).key

inner-server_$(name).crt: ca_$(name).key ca_$(name).pem inner-server_$(name).csr
	$(OPENSSL) ca -batch -keyfile ca_$(name).key -cert ca_$(name).pem -in inner-server_$(name).csr  -key $(PASSWORD_CA) -out inner-server_$(name).crt -extensions xpserver_ext -extfile xpextensions -config ./inner-server.cnf

inner-server_$(name).p12: inner-server_$(name).crt
	$(OPENSSL) pkcs12 -export -in inner-server_$(name).crt -inkey inner-server_$(name).key -out inner-server_$(name).p12  -passin pass:$(PASSWORD_INNER) -passout pass:$(PASSWORD_INNER)
	chmod g+r inner-server_$(name).p12

inner-server_$(name).pem: inner-server_$(name).p12
	$(OPENSSL) pkcs12 -in inner-server_$(name).p12 -out inner-server_$(name).pem -passin pass:$(PASSWORD_INNER) -passout pass:$(PASSWORD_INNER)
	chmod g+r inner-server_$(name).pem

.PHONY: inner-server.vrfy
inner-server.vrfy: ca_$(name).pem
	@$(OPENSSL) verify $(PARTIAL) -CAfile ca_$(name).pem inner-server_$(name).pem

######################################################################
#
#  Miscellaneous rules.
#
######################################################################
index.txt:
	@touch index.txt

serial:
	@echo '01' > serial

print:
	$(OPENSSL) x509 -text -in server.crt

printca:
	$(OPENSSL) x509 -text -in ca.pem

clean:
	@rm -f *~ *old client.csr client.key client.crt client.p12 client.pem

#
#	Make a target that people won't run too often.
#
destroycerts:
	rm -f *~ dh *.csr *.crl *.crt *.p12 *.der *.pem *.key index.txt* \
		serial*  *\.0 *\.1 ca-crl.pem ca.crl