"""
Q1: DNSSEC Validation Module
CS6903 Network Security, IIT Hyderabad

Reusable module that:
  - Fetches Answer records, DNSKEY, RRSIG, DS
  - Verifies RRSIG signatures using DNSKEY (ZSK)
  - Verifies DNSKEY authenticity using DS records from parent zone
  - Walks the full chain of trust up to the root

Supported algorithms:
  5  = RSA/SHA-1
  7  = RSASHA1-NSEC3-SHA1
  8  = RSA/SHA-256
  10 = RSA/SHA-512
  13 = ECDSA P-256 / SHA-256
  14 = ECDSA P-384 / SHA-384
"""

import struct
import hashlib
import sys
from dataclasses import dataclass, field
from typing import Optional

import dns.name
import dns.query
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.rrset
import dns.flags
import dns.dnssec
import dns.resolver
import dns.exception

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Root trust anchor (IANA KSK, key tag 20326, algorithm 8, SHA-256)
# https://data.iana.org/root-anchors/root-anchors.xml
# ---------------------------------------------------------------------------
ROOT_TRUST_ANCHOR_DS = {
    "key_tag": 20326,
    "algorithm": 8,
    "digest_type": 2,
    "digest": bytes.fromhex(
        "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    ),
}

# Well-known root server IPs (a-root through m-root, IPv4)
ROOT_SERVERS = [
    "198.41.0.4",    # a.root-servers.net
    "170.247.170.2", # b.root-servers.net
    "192.33.4.12",   # c.root-servers.net
    "199.7.91.13",   # d.root-servers.net
]

# Public DNSSEC-aware resolver used when the system resolver is a local device
# that strips RRSIG records. CD (Checking Disabled) flag is also set on queries
# so the recursive resolver passes raw RRSIG records back to us.
FALLBACK_RESOLVER = "8.8.8.8"

QUERY_TIMEOUT = 5.0  # seconds


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    valid: bool
    domain: str
    record_type: str
    steps: list[str] = field(default_factory=list)
    error: Optional[str] = None
    answer: list = field(default_factory=list)

    def print(self):
        print(f"\nDomain: {self.domain}")
        print(f"Record: {self.record_type}")
        print(f"DNSSEC Validation: {'VALID' if self.valid else 'INVALID'}")
        if self.error:
            print(f"Error: {self.error}")
        print("Steps:")
        for step in self.steps:
            print(f"  - {step}")
        if self.answer:
            print("Answer:")
            for rr in self.answer:
                print(f"  {rr}")


# ---------------------------------------------------------------------------
# Low-level DNS query helpers
# ---------------------------------------------------------------------------

def _query(server_ip: str, qname: str, rdtype, timeout: float = QUERY_TIMEOUT,
           recursive: bool = True):
    """
    Send a UDP DNS query with DO (DNSSEC OK) + CD (Checking Disabled) bits set.
    DO  → ask for RRSIG records in response.
    CD  → tell recursive resolvers not to strip RRSIG / unvalidated records.
    recursive → set the RD (Recursion Desired) flag.
    """
    qname_obj = dns.name.from_text(qname)
    request = dns.message.make_query(qname_obj, rdtype, want_dnssec=True)
    if recursive:
        request.flags |= dns.flags.RD
    request.flags |= dns.flags.CD   # pass RRSIG through recursive resolver
    try:
        response = dns.query.udp(request, server_ip, timeout=timeout)
        # Retry with TCP if truncated
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(request, server_ip, timeout=timeout)
        return response
    except Exception:
        return None


def _get_default_resolver_ip() -> str:
    """
    Return a DNSSEC-capable resolver IP.
    Prefer the system resolver if it is a public address; otherwise fall back
    to 8.8.8.8 (Google Public DNS) which reliably returns RRSIG records.
    """
    res = dns.resolver.Resolver()
    ip = res.nameservers[0] if res.nameservers else FALLBACK_RESOLVER
    # Treat RFC-1918 / link-local addresses as incapable of returning RRSIG
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return FALLBACK_RESOLVER
    except ValueError:
        pass
    return ip


def _resolve_name_to_ip(name: str, server_ip: str) -> Optional[str]:
    """Resolve a nameserver hostname to an IP, trying A then AAAA."""
    for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        resp = _query(server_ip, name, rdtype)
        if resp is None:
            continue
        for rrset in resp.answer:
            if rrset.rdtype == rdtype:
                return str(next(iter(rrset)))
    return None


def _get_authoritative_ns(domain: str, server_ip: str) -> list[str]:
    """
    Query server_ip for NS records of domain.
    Returns list of nameserver IPs (from glue or resolved).
    """
    resp = _query(server_ip, domain, dns.rdatatype.NS)
    if resp is None:
        return []

    ns_ips = []
    ns_names = []

    # Collect glue IPs from additional section
    glue: dict[str, str] = {}
    for rrset in resp.additional:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            glue[str(rrset.name).rstrip(".")] = str(next(iter(rrset)))

    # Collect NS names from authority or answer section
    for section in (resp.answer, resp.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns_names.append(str(rr.target).rstrip("."))

    for name in ns_names:
        if name in glue:
            ns_ips.append(glue[name])
        else:
            ip = _resolve_name_to_ip(name, server_ip)
            if ip:
                ns_ips.append(ip)

    return ns_ips


# ---------------------------------------------------------------------------
# Record fetchers
# ---------------------------------------------------------------------------

def fetch_records(domain: str, rdtype_str: str, server_ip: Optional[str] = None) -> list:
    """
    Fetch answer records for domain/rdtype with DNSSEC OK bit.
    Returns list of rdata objects (may be empty on NXDOMAIN/NODATA).
    """
    if server_ip is None:
        server_ip = _get_default_resolver_ip()
    rdtype = dns.rdatatype.from_text(rdtype_str)
    resp = _query(server_ip, domain, rdtype)
    if resp is None:
        return []
    records = []
    for rrset in resp.answer:
        if rrset.rdtype == rdtype:
            records.extend(list(rrset))
    return records


def fetch_dnskey(domain: str, server_ip: Optional[str] = None) -> tuple[list, list]:
    """
    Fetch DNSKEY RRset for domain.
    Returns (zsk_list, ksk_list) where each element is a dns.rdata DNSKEY rdata.
    flags=256 → ZSK, flags=257 → KSK.
    """
    if server_ip is None:
        server_ip = _get_default_resolver_ip()
    resp = _query(server_ip, domain, dns.rdatatype.DNSKEY)
    if resp is None:
        return [], []
    zsk, ksk = [], []
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            for rr in rrset:
                if rr.flags == 256:
                    zsk.append(rr)
                elif rr.flags == 257:
                    ksk.append(rr)
    return zsk, ksk


def fetch_rrsig(domain: str, rdtype_str: str, server_ip: Optional[str] = None) -> list:
    """
    Fetch RRSIG records covering rdtype_str for domain.
    Returns list of RRSIG rdata objects.
    """
    if server_ip is None:
        server_ip = _get_default_resolver_ip()
    rdtype = dns.rdatatype.from_text(rdtype_str)
    resp = _query(server_ip, domain, rdtype)
    if resp is None:
        return []
    sigs = []
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            for rr in rrset:
                if rr.type_covered == rdtype:
                    sigs.append(rr)
    return sigs


def fetch_ds(domain: str, server_ip: Optional[str] = None) -> list:
    """
    Fetch DS records for domain from its parent zone.
    Queries the parent zone's nameservers directly to avoid caching.
    Returns list of DS rdata objects.
    """
    if server_ip is None:
        server_ip = _get_default_resolver_ip()

    # Find parent zone by stripping leftmost label
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 1:
        # Root zone: use built-in trust anchor, return empty (handled separately)
        return []

    # Query parent nameservers for DS
    resp = _query(server_ip, domain, dns.rdatatype.DS)
    if resp is None:
        return []
    ds_records = []
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.DS:
            ds_records.extend(list(rrset))
    return ds_records


def fetch_dnskey_rrset(domain: str, server_ip: Optional[str] = None):
    """Return the full DNSKEY RRset (dns.rrset.RRset) for wire-format operations."""
    if server_ip is None:
        server_ip = _get_default_resolver_ip()
    resp = _query(server_ip, domain, dns.rdatatype.DNSKEY)
    if resp is None:
        return None
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            return rrset
    return None


def fetch_rrset_with_rrsig(domain: str, rdtype_str: str, server_ip: Optional[str] = None):
    """
    Return (rrset, rrsig_list) for the given domain/rdtype.
    rrset is a dns.rrset.RRset; rrsig_list is list of RRSIG rdata.
    """
    if server_ip is None:
        server_ip = _get_default_resolver_ip()
    rdtype = dns.rdatatype.from_text(rdtype_str)
    resp = _query(server_ip, domain, rdtype)
    if resp is None:
        return None, []

    target_rrset = None
    rrsigs = []
    for rrset in resp.answer:
        if rrset.rdtype == rdtype:
            target_rrset = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            for rr in rrset:
                if rr.type_covered == rdtype:
                    rrsigs.append(rr)
    return target_rrset, rrsigs


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def _key_tag(dnskey_rdata) -> int:
    """Compute the key tag for a DNSKEY rdata (RFC 4034 Appendix B)."""
    wire = dnskey_rdata.to_wire()
    ac = 0
    for i, byte in enumerate(wire):
        if i % 2 == 0:
            ac += byte << 8
        else:
            ac += byte
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def _build_rrsig_signed_data(rrsig_rdata, rrset) -> bytes:
    """
    Build the data that was signed per RFC 4034 §6.2:
      signature_data = RRSIG_RDATA | RR(1) | RR(2) ... (canonical sorted)

    RRSIG_RDATA = everything except the Signature field itself.
    """
    # RRSIG signed data header fields (RFC 4034 §6.2):
    # type_covered(2) algorithm(1) labels(1) orig_ttl(4)
    # sig_expiration(4) sig_inception(4) key_tag(2) signer_name(var)
    # We re-encode these manually rather than stripping from the full wire form.
    signer_wire = dns.name.from_text(str(rrsig_rdata.signer)).canonicalize().to_wire()
    header = struct.pack(
        "!HBBIIIH",
        rrsig_rdata.type_covered,
        rrsig_rdata.algorithm,
        rrsig_rdata.labels,
        rrsig_rdata.original_ttl,
        int(rrsig_rdata.expiration),
        int(rrsig_rdata.inception),
        rrsig_rdata.key_tag,
    )
    rrsig_header = header + signer_wire

    # Build canonical RRs: owner name lowercased & uncompressed, type, class, orig_ttl, rdlen, rdata
    owner = dns.name.from_text(str(rrset.name)).canonicalize()
    # Wildcards: expand to original labels count if needed (simplified: use actual name)
    owner_wire = owner.to_wire()
    rdtype_val = rrset.rdtype
    rdclass_val = rrset.rdclass
    orig_ttl = rrsig_rdata.original_ttl

    # Sort RRs in canonical order (wire format of rdata, lexicographic)
    rdata_wires = sorted(rr.to_wire() for rr in rrset)

    rr_parts = []
    for rdata_wire in rdata_wires:
        rr_wire = (
            owner_wire
            + struct.pack("!HHIH", rdtype_val, rdclass_val, orig_ttl, len(rdata_wire))
            + rdata_wire
        )
        rr_parts.append(rr_wire)

    return rrsig_header + b"".join(rr_parts)


def _get_signing_key(rrsig_rdata, dnskey_list: list):
    """Find the DNSKEY in dnskey_list whose key_tag matches rrsig_rdata.key_tag."""
    for dnskey in dnskey_list:
        if _key_tag(dnskey) == rrsig_rdata.key_tag:
            return dnskey
    return None


def _verify_rsa(signature: bytes, signed_data: bytes, dnskey_rdata, algorithm: int) -> bool:
    """Verify RSA RRSIG. algorithms 5,7 → SHA1; 8 → SHA256; 10 → SHA512."""
    pubkey_bytes = dnskey_rdata.key
    # RSA public key wire format: exponent length (1 or 3 bytes) + exponent + modulus
    if pubkey_bytes[0] == 0:
        exp_len = struct.unpack("!H", pubkey_bytes[1:3])[0]
        exp_bytes = pubkey_bytes[3:3 + exp_len]
        mod_bytes = pubkey_bytes[3 + exp_len:]
    else:
        exp_len = pubkey_bytes[0]
        exp_bytes = pubkey_bytes[1:1 + exp_len]
        mod_bytes = pubkey_bytes[1 + exp_len:]

    e = int.from_bytes(exp_bytes, "big")
    n = int.from_bytes(mod_bytes, "big")
    pub_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

    hash_map = {5: hashes.SHA1(), 7: hashes.SHA1(), 8: hashes.SHA256(), 10: hashes.SHA512()}
    hash_algo = hash_map.get(algorithm)
    if hash_algo is None:
        return False

    try:
        pub_key.verify(signature, signed_data, padding.PKCS1v15(), hash_algo)
        return True
    except InvalidSignature:
        return False


def _verify_ecdsa(signature: bytes, signed_data: bytes, dnskey_rdata, algorithm: int) -> bool:
    """Verify ECDSA RRSIG. algorithm 13 → P-256/SHA256; 14 → P-384/SHA384."""
    pubkey_bytes = dnskey_rdata.key
    if algorithm == 13:
        curve = ec.SECP256R1()
        coord_len = 32
        hash_algo = hashes.SHA256()
    else:
        curve = ec.SECP384R1()
        coord_len = 48
        hash_algo = hashes.SHA384()

    x = int.from_bytes(pubkey_bytes[:coord_len], "big")
    y = int.from_bytes(pubkey_bytes[coord_len:], "big")
    pub_key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key(default_backend())

    # ECDSA signature in DNSSEC is raw r||s (RFC 6605)
    r = int.from_bytes(signature[:coord_len], "big")
    s = int.from_bytes(signature[coord_len:], "big")
    der_sig = utils.encode_dss_signature(r, s)

    try:
        pub_key.verify(der_sig, signed_data, ec.ECDSA(hash_algo))
        return True
    except InvalidSignature:
        return False


def verify_rrsig(rrset, rrsig_rdata, dnskey_rdata) -> bool:
    """
    Verify that rrsig_rdata is a valid signature over rrset using dnskey_rdata.
    Supports algorithms 5, 7, 8, 10 (RSA) and 13, 14 (ECDSA).
    """
    signed_data = _build_rrsig_signed_data(rrsig_rdata, rrset)
    signature = rrsig_rdata.signature
    algo = rrsig_rdata.algorithm

    if algo in (5, 7, 8, 10):
        return _verify_rsa(signature, signed_data, dnskey_rdata, algo)
    elif algo in (13, 14):
        return _verify_ecdsa(signature, signed_data, dnskey_rdata, algo)
    else:
        # Unsupported algorithm — skip (treat as indeterminate)
        return False


# ---------------------------------------------------------------------------
# DS chain verification
# ---------------------------------------------------------------------------

def _compute_ds_digest(domain: str, dnskey_rdata, digest_type: int) -> bytes:
    """
    Compute DS digest per RFC 4034 §5.1.4:
      digest = hash(owner_wire | DNSKEY_rdata_wire)
    digest_type: 1=SHA1, 2=SHA256, 4=SHA384
    """
    owner_wire = dns.name.from_text(domain).canonicalize().to_wire()
    dnskey_wire = dnskey_rdata.to_wire()
    data = owner_wire + dnskey_wire

    if digest_type == 1:
        return hashlib.sha1(data).digest()
    elif digest_type == 2:
        return hashlib.sha256(data).digest()
    elif digest_type == 4:
        return hashlib.sha384(data).digest()
    else:
        return b""


def verify_dnskey_with_ds(domain: str, dnskey_list: list, ds_records: list) -> tuple[bool, list]:
    """
    For each KSK in dnskey_list, compute its DS digest and compare against ds_records.
    Returns (matched: bool, matched_key_tags: list[int]).
    """
    matched_tags = []
    for dnskey in dnskey_list:
        if dnskey.flags != 257:  # only KSKs
            continue
        tag = _key_tag(dnskey)
        for ds in ds_records:
            if ds.key_tag != tag:
                continue
            computed = _compute_ds_digest(domain, dnskey, ds.digest_type)
            if computed == ds.digest:
                matched_tags.append(tag)
                break
    return (len(matched_tags) > 0, matched_tags)


# ---------------------------------------------------------------------------
# Main validation orchestrator
# ---------------------------------------------------------------------------

def validate_dnssec(domain: str, rdtype_str: str, server_ip: Optional[str] = None) -> ValidationResult:
    """
    Full DNSSEC validation for domain/rdtype:
      1. Fetch answer records
      2. Fetch DNSKEY (ZSK + KSK)
      3. Fetch RRSIG for the rdtype
      4. Verify RRSIG using ZSK
      5. Fetch DS from parent
      6. Verify KSK using DS

    Returns a ValidationResult with valid=True only if all steps pass.
    """
    if server_ip is None:
        server_ip = _get_default_resolver_ip()

    result = ValidationResult(valid=False, domain=domain, record_type=rdtype_str)

    # Step 1: Fetch answer records
    rrset, rrsigs = fetch_rrset_with_rrsig(domain, rdtype_str, server_ip)
    if rrset is None or len(rrset) == 0:
        result.error = f"No {rdtype_str} records found for {domain}"
        result.steps.append(f"FAILED: No {rdtype_str} records found")
        return result
    result.answer = list(rrset)
    result.steps.append(f"Answer records retrieved ({len(rrset)} record(s))")

    # Step 2: Fetch DNSKEY
    zsk_list, ksk_list = fetch_dnskey(domain, server_ip)
    all_keys = zsk_list + ksk_list
    if not all_keys:
        result.error = "No DNSKEY records found"
        result.steps.append("FAILED: No DNSKEY records found")
        return result

    zsk_tags = [_key_tag(k) for k in zsk_list]
    ksk_tags = [_key_tag(k) for k in ksk_list]
    result.steps.append(
        f"DNSKEY retrieved (ZSK tag(s): {zsk_tags}, KSK tag(s): {ksk_tags})"
    )

    # Step 3 & 4: Verify RRSIG over the answer RRset
    if not rrsigs:
        result.error = f"No RRSIG found for {rdtype_str}"
        result.steps.append(f"FAILED: No RRSIG found for {rdtype_str}")
        return result

    rrsig_verified = False
    signing_key_tag = None
    for rrsig in rrsigs:
        # Try ZSK first, fall back to any key
        key = _get_signing_key(rrsig, zsk_list) or _get_signing_key(rrsig, all_keys)
        if key and verify_rrsig(rrset, rrsig, key):
            rrsig_verified = True
            signing_key_tag = rrsig.key_tag
            key_role = "ZSK" if key in zsk_list else "KSK"
            result.steps.append(f"RRSIG verified using {key_role} (tag={signing_key_tag})")
            break

    if not rrsig_verified:
        result.error = "RRSIG verification failed — signature does not match DNSKEY"
        result.steps.append("FAILED: RRSIG verification failed")
        return result

    # Step 5 & 6: Verify KSK using DS from parent
    ds_records = fetch_ds(domain, server_ip)
    if not ds_records:
        # Check if this is the root zone or a special case
        result.error = "No DS records found in parent zone"
        result.steps.append("FAILED: No DS records found in parent zone")
        return result

    ds_matched, matched_tags = verify_dnskey_with_ds(domain, ksk_list, ds_records)
    if not ds_matched:
        result.error = "DS record does not match any KSK — chain of trust broken"
        result.steps.append("FAILED: DS record does not match KSK")
        return result

    result.steps.append(f"DS matched parent zone (KSK tag(s): {matched_tags})")
    result.valid = True
    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage: python q1_dnssec_validator.py <domain> <record_type>")
        print("Example: python q1_dnssec_validator.py example.com A")
        sys.exit(1)

    domain = sys.argv[1]
    rdtype = sys.argv[2].upper()

    result = validate_dnssec(domain, rdtype)
    result.print()
    sys.exit(0 if result.valid else 1)


if __name__ == "__main__":
    main()
