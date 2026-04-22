# TLS Tools

Tools for testing TLS/SSL configurations and HTTP security features.

## TLS-checker.ps1

Cross-platform PowerShell script that tests TLS versions, HTTP versions, compression, QUIC, and HSTS using a self-contained cURL binary.

**Requirements:** PowerShell 7.5+

```powershell
.\TLS-checker.ps1 -Domain "example.com" -TestType All
.\TLS-checker.ps1 -Domain "example.com" -TestType TLS -Quiet
```

## testssl.sh

Really strong TLS/SSL scanner. This one is included as a submodule from a project that I like. It scans ciphers, protocols, certificates, and vulnerabilities.

Currently, the Git submodule is pinned at a specific version. If missing after cloning, run:

```bash
git submodule update --init
```

**Requirements:** Bash 3.2+, OpenSSL

```bash
./testssl.sh/testssl.sh example.com
./testssl.sh/testssl.sh --vulnerable example.com
./testssl.sh/testssl.sh example.com:8443
```

Developed and maintained by Dirk Wetter — [github.com/testssl/testssl.sh](https://github.com/testssl/testssl.sh) — GNU GPL v2.
