# CS6903 Network Security — Programming Assignment 2: DNS and DNSSEC

## Assignment Overview

**Course:** CS6903 Network Security, 2025-26, IIT Hyderabad  
**Deadline:** 22 April 2026, 11:59 PM  
**Submission:** `cs25mtech11022.tar.gz` via Moodle  
**Language:** Python 3  
**Version control:** GitHub

## Questions Summary

| Q | File | Description |
|---|------|-------------|
| Q1 | `q1_dnssec_validator.py` | Core DNSSEC validation module (imported by all others) |
| Q2 | `q2_resolver.py` | Recursive resolver: Root → TLD → Authoritative with DNSSEC |
| Q3 | `q3_nsec_resolver.py` | Negative proof: NSEC/NSEC3 for non-existent domains/types |
| Q4 | `q4_key_lifecycle.py` | Real-world key lifecycle analysis (rollover detection) |
| Q5 | `q5_tamper_demo/` | Docker+BIND9 local env; tamper A record, show detection |

## Module Dependency Graph

```
q2_resolver.py       ──┐
q3_nsec_resolver.py  ──┤──► q1_dnssec_validator.py  (core)
q4_key_lifecycle.py  ──┤
q5_tamper_demo/      ──┘
```

## Key Technical References

- **RFC 4033** — DNS Security Introduction and Requirements
- **RFC 4034** — Resource Records for DNS Security Extensions
- **RFC 4035** — Protocol Modifications for DNS Security Extensions
- **RFC 5155** — NSEC3 (DNS Security Hashed Authenticated Denial of Existence)

### DNSSEC Algorithm Numbers
| Number | Algorithm |
|--------|-----------|
| 5 | RSA/SHA-1 |
| 7 | RSASHA1-NSEC3-SHA1 |
| 8 | RSA/SHA-256 |
| 10 | RSA/SHA-512 |
| 13 | ECDSA/P-256/SHA-256 |
| 14 | ECDSA/P-384/SHA-384 |

### DS Digest Types
| Number | Digest |
|--------|--------|
| 1 | SHA-1 |
| 2 | SHA-256 |
| 4 | SHA-384 |

### DNSKEY Flags
- `256` = ZSK (Zone Signing Key)
- `257` = KSK (Key Signing Key)

### Root Trust Anchor
- Key Tag: 20326, Algorithm: 8 (RSA/SHA-256)

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running Each Question

```bash
# Q1 — validate a domain
python q1_dnssec_validator.py example.com A

# Q2 — recursive resolve
python q2_resolver.py example.com A

# Q3 — negative proof
python q3_nsec_resolver.py doesnotexist.example.com A

# Q4 — key lifecycle
python q4_key_lifecycle.py cloudflare.com

# Q5 — tamper demo (requires Docker)
cd q5_tamper_demo && docker-compose up -d
python tamper_demo.py
```

## Q5 Environment Notes

- Uses Docker + BIND9 with a locally-signed `example.edu` zone
- Requires Docker and docker-compose installed
- Zone is signed with `dnssec-keygen` + `dnssec-signzone` inside the container
- Tamper script modifies the A record IP without re-signing to trigger validation failure
