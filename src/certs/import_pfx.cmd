@echo OFF

certutil -user -p "" -csp "Microsoft Enhanced RSA and AES Cryptographic Provider" -importpfx server_rsa.pfx AT_KEYEXCHANGE,NoProtect
certutil -user -p "" -csp "Microsoft Enhanced RSA and AES Cryptographic Provider" -importpfx client_rsa.pfx AT_KEYEXCHANGE,NoProtect


powershell "Import-PfxCertificate -FilePath server_ecdsa.pfx -CertStoreLocation Cert:\CurrentUser\My"
powershell "Import-PfxCertificate -FilePath client_ecdsa.pfx -CertStoreLocation Cert:\CurrentUser\My"
