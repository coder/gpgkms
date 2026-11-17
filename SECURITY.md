# Security

gpgkms runs inside release jobs that can sign with Coder's release keys. Report a vulnerability
privately to security@coder.com or through GitHub's "Report a vulnerability" on this repository,
not in a public issue.

Consumers pin this module by commit, so a change only reaches a signing job after its owners bump
the pin. Treat every change here like a change to release signing.
