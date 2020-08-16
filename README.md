# OpenSSL Engine supporting CryptoAPI: Next Generation

## Introduction
The [OpenSSL](https://github.com/openssl/openssl) consists of three layers -- libcrypto, libssl and cli application. The first one can be considered as a core product of OpenSSL project, as it implements cryptographic functionality. Libcrypto itself is divided into many parts, each represented by API. One of such interface is called Engine API, which can be seen as compatibility layer between external device or library and OpenSSL. Engine structure was not documented when I was writing this code. However as a by-product a documentation of OpenSSL architecture and Engine API was created. 

Right now the documentation exists in Czech language only, but I am currently working on translation.

## Project structure
```
ecng
+-- docs/
+-- src/
    +-- makefile
    +-- engine/
        +-- e_capi.c
        +-- e_cng.c
    +-- test/
        +-- client.c
        +-- server.c
        +-- eng_loader.c
        +-- conf/
            +--- example.conf
    +-- certs/
        +--- generate_ecdsa_certs.cmd
        +--- generate_rsa_certs.cmd
```

## OpenSSL Build

Clone OpenSSL project to any directory, lets say %OPENSSL_DIR%.  
`git clone https://github.com/openssl/openssl.git %OPENSSL_DIR%`
Because master branch do not contain LTS version, do a checkout
to 'OpenSSL_1_1_1-stable' branch.
You need a few tools to build OpenSSL successfully.
- Perl. Choose between ActiveState Perl (https://www.activestate.com/ActivePerl) and Strawberry Perl (http://strawberryperl.com). Also get Perl module Text::Template accessible from CPAN.
- Microsoft Visual C compiler.
- Netwide Assembler (https://www.nasm.us)  

See %OPENSSL_DIR%\NOTES.WIN for more information.  

Then OpenSSL instance should be configured. See
%OPENSSL_DIR%\INSTALL. Command bellow was used when 
I was developing cng engine.    
`perl Configure VC-WIN32 --prefix=%OPENSSL_DIR% --openssldir=%OPENSSL_DIR%`  

Then just run `nmake` to compile whole OpenSSL into %OPENSSL_DIR%.

## Test Env Build

Clone this project into some directory %CNG_DIR%.  
Go to %CNG_DIR%\src\ path and edit first line of
makefile so variable OPENSSL_DIR contains real
path to OpenSSL project directory (%OPENSSL_DIR%).
After that, makefile should be correctly configured
and runnable using commands below.

`nmake generate` runs cmd scripts saved in certs\,
openssl app will be used to generate RSA, ECDSA keys
and certificates. New pairs will be merged into
pfx format and imported into Windows cert store
using certutil or Import-Pfx.

`nmake engines` create shared objects (dlls) of cng and
capi engine into .\engine\ directory.

`nmake tests` compiles server, client and eng_loader apps
into test\\.

`nmake copy_libs` copies libraries libcrypto.dll a libssl.dll
from OpenSSL dir into current directory. Their presence is 
necessary to run compiled apps.

`nmake all` runs all of commands above.

## Run Tests

App eng_loader.exe expects path to engine dll.
This will print some general info about specified engine.
`.\test\eng_loader.exe .\engine\capi.dll`  

App server.exe runs a virtual server on localhost:27015 by default.
After running client.exe, client-server connection should be
established, which will be confirmed by messages printed on stdout.  
`.\test\server.exe` or `.\test\client.exe`  

Both server and client are configurable using conf file.
Config file sample is available in .\example.conf. It
also contains brief description of each parameter. To
override default settings with the config file, specify
this file as server/client parameter.  
`.\test\server.exe .\example.conf`  
`.\test\client.exe .\example.conf`

To make it all more simple, script `_run.cmd` was created,
which starts server and client in new tab. This script can
be also called with config file path as a parameter, then
the specified setting will be applied on both apps.  
`_run.cmd example.conf`.


| key                | description                                         | default value                   |
|--------------------|-----------------------------------------------------|-----------------------------------|
| MAX_TLS_VERSION    | Upper bound for TLS version                         | 1.2                               |
| RSA_CA_PATH        | path to RSA key signed CA                           | "certs\\ca_rsa.pem"               |
| ECDSA_CA_PATH      | path to ECDSA key signed CA                         | "certs\\ca_ecdsa.pem"             |
| SERVER_ENGINE_PATH | path to engine shared object used by server         | "engine\\cng.dll"                 |
| CLIENT_ENGINE_PATH | path to engine shared object used by client         | "engine\\cng.dll"                 |
| SERVER_RSA_CERT    | name of RSA server cert in store                    | "localhostServerRSA"              |
| SERVER_ECDSA_CERT  | name of ECDSA server cert in store                  | "localhostServerECDSA"            |
| ECDSA_ONLY         | only ECDSA will be used to establish connection     |                                   |
| RSA_ONLY           | only RSA will be used to establish connection       |                                   |
| NO_RSA_PSS         | RSA-PSS won't be included to handshake              |                                   |
| CERT_REQUEST       | server sends CertificateRequest                     |                                   |

Four last configurable parameters are not used by default,
they behave like binary flags (key specified in file or not),
any value specified will be ignored.
