# VPN-Webpage-API
API for distributing certs for a VPN. Goes with [Soham3-1415/VPN-Webpage](https://github.com/soham3-1415/VPN-Webpage)

# Purpose
- learn to create APIs
- work with ReCaptcha
- use Hashicorp's Vault to run a PKI
- use Node.js
- practice writing secure code
- scale an OpenVPN instance

# Expectations
- Don't expect security.
- Don't expect privacy.
- Don't expect reliability.

This project has not been audited.

# Current Features
- use Hashicorp's Vault for pki
- provide access to certificates
- anonymously stores email address for certificate retrieval
- generate PKCS12 file or sign CSR
- retrieve certificate only for the owner
- prevent others from associating certificate with email address

# Future Work
- comment code
- investigate potential BREACH vulnerability with use of compression and transmission of secret code
- refactor to reduce redundancy
- allow users to set a code
- add payment gateway
- certificate renewal
- variable certificate expiration
- add certificate revocation
- add selection of RSA key size for server side key generation
- elliptic curve certificates

# Certificate Signing Procedure
1. Enter email
2. Request certificate
3. Enter email
4. Enter code (emailed)
5. Request and complete challenge (currently doesn't exist)
6. Upload CSR (optional)
7. Request certificate

# Certificate Retrieval Procedure
1. Enter email
2. Enter secret code
3. Request certificate

# How Email Addresses are Anonymously Stored
- randomly generated bits are add to the email address before hashing
- sha384 is used
  - a slow hashing algorithm is not needed because the email address is combined with many randomly generated bits
- first 63 characters of the base64 encoded hash become the common name
- using the email address and the randomly generated bits, the common name can be derived
- only the recipient is provided the randomly generated bits; they are not stored on the server
- the randomly generated bits are *like* a password
  - keeping them a secret preserves the anonymity of the certificate
  - they ensure that the person paying for the certificate is they same person that is issued the certificate
  - after the certificate is issued, exposure of the randomly generated bits can only result in the certificate becoming associated with an email address
