# TLS Tools

A collection of tools for testing TLS/SSL configurations and HTTP security features.

---

## TLS-checker.ps1

A cross-platform PowerShell script that tests TLS versions, HTTP versions, compression, QUIC, and HSTS for a given domain using a self-contained cURL binary.

**Requirements:** PowerShell 7.5.0+

```powershell
# Test everything for a domain
.\TLS-checker.ps1 -Domain "example.com" -TestType All

# Test only TLS, suppress detailed output
.\TLS-checker.ps1 -Domain "example.com" -TestType TLS -Quiet
```

---

## testssl.sh (v3.2.3)

A comprehensive command-line tool for checking a server's TLS/SSL configuration — ciphers, protocols, certificate details, vulnerabilities (Heartbleed, BEAST, POODLE, etc.), and much more.

**Requirements:** Bash 3.2+, OpenSSL (bundled Linux binary included in `bin/`)

```bash
# Full scan of a domain
./testssl.sh-3.2.3/testssl.sh example.com

# Check only for vulnerabilities
./testssl.sh-3.2.3/testssl.sh --vulnerable example.com

# Check specific port
./testssl.sh-3.2.3/testssl.sh example.com:8443
```

See `testssl.sh-3.2.3/CREDITS.md` for the full list of contributors.

### Credits & License

testssl.sh is developed and maintained by **Dirk Wetter** and contributors.

- **Repository:** https://github.com/testssl/testssl.sh
- **Release:** [v3.2.3](https://github.com/testssl/testssl.sh/releases/tag/v3.2.3)
- **License:** GNU GPL v2 — see `testssl.sh-3.2.3/LICENSE`
