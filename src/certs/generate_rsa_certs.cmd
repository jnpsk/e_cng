@echo OFF

set OPENSSL_DIR=%1
set OPENSSL_CONF=%OPENSSL_DIR%\apps\openssl.cnf
set OPENSSL_APP=%OPENSSL_DIR%\apps\openssl.exe
set CERT_DIR=certs

cd %CERT_DIR%

%OPENSSL_APP% genrsa -out ca_rsa.key
%OPENSSL_APP% req -x509 -new -key ca_rsa.key -out ca_rsa.pem -days 365 -subj "/C=CZ/ST=Project/O=CNG/CN=TestAuthorityRSA"

%OPENSSL_APP% genrsa -out server_rsa.key
%OPENSSL_APP% req -new -key server_rsa.key -subj "/C=CZ/ST=Project/O=ServerRSA/CN=localhostServerRSA" -out server_rsa.csr
%OPENSSL_APP% x509 -req -in server_rsa.csr -days 365 -CA ca_rsa.pem -CAkey ca_rsa.key -CAcreateserial -out server_rsa.pem

%OPENSSL_APP% genrsa -out client_rsa.key
%OPENSSL_APP% req -new -key client_rsa.key -subj "/C=CZ/ST=Project/O=ClientRSA/CN=localhostClientRSA" -out client_rsa.csr
%OPENSSL_APP% x509 -req -in client_rsa.csr -days 365 -CA ca_rsa.pem -CAkey ca_rsa.key -CAcreateserial -out client_rsa.pem

%OPENSSL_APP% pkcs12 -export -inkey server_rsa.key -in server_rsa.pem -out server_rsa.pfx -passout pass:
%OPENSSL_APP% pkcs12 -export -inkey client_rsa.key -in client_rsa.pem -out client_rsa.pfx -passout pass:

certutil -user -p "" -csp "Microsoft Enhanced RSA and AES Cryptographic Provider" -importpfx server_rsa.pfx AT_KEYEXCHANGE,NoProtect
certutil -user -p "" -csp "Microsoft Enhanced RSA and AES Cryptographic Provider" -importpfx client_rsa.pfx AT_KEYEXCHANGE,NoProtect
