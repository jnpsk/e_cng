@echo OFF

set OPENSSL_DIR=%1
set OPENSSL_CONF=%OPENSSL_DIR%\apps\openssl.cnf
set OPENSSL_APP=%OPENSSL_DIR%\apps\openssl.exe
set CERT_DIR=certs

cd %CERT_DIR%

%OPENSSL_APP% ecparam -name prime256v1 -genkey -out ca_ecdsa.key
%OPENSSL_APP% req -x509 -new -key ca_ecdsa.key -out ca_ecdsa.pem -days 365 -subj "/C=CZ/ST=Project/O=CNG/CN=TestAuthorityECDSA"

%OPENSSL_APP% ecparam -name prime256v1 -genkey -out server_ecdsa.key
%OPENSSL_APP% req -new -key server_ecdsa.key -subj "/C=CZ/ST=Project/O=ServerECDSA/CN=localhostServerECDSA" -out server_ecdsa.csr
%OPENSSL_APP% x509 -req -in server_ecdsa.csr -days 365 -CA ca_ecdsa.pem -CAkey ca_ecdsa.key -CAcreateserial -out server_ecdsa.pem

%OPENSSL_APP% ecparam -name prime256v1 -genkey -out client_ecdsa.key
%OPENSSL_APP% req -new -key client_ecdsa.key -subj "/C=CZ/ST=Project/O=ClientECDSA/CN=localhostClientECDSA" -out client_ecdsa.csr
%OPENSSL_APP% x509 -req -in client_ecdsa.csr -days 365 -CA ca_ecdsa.pem -CAkey ca_ecdsa.key -CAcreateserial -out client_ecdsa.pem

%OPENSSL_APP% pkcs12 -export -inkey server_ecdsa.key -in server_ecdsa.pem -out server_ecdsa.pfx -passout pass:
%OPENSSL_APP% pkcs12 -export -inkey client_ecdsa.key -in client_ecdsa.pem -out client_ecdsa.pfx -passout pass:

powershell "Import-PfxCertificate -FilePath server_ecdsa.pfx -CertStoreLocation Cert:\CurrentUser\My"
powershell "Import-PfxCertificate -FilePath client_ecdsa.pfx -CertStoreLocation Cert:\CurrentUser\My"
