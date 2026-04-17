"""
Q3: NSEC/NSEC3 Authenticated Denial of Existence
CS6903 Network Security, IIT Hyderabad

Extends Q2 to handle non-existent domains/types securely by:
  1. Detecting NXDOMAIN (domain does not exist) and NODATA (type does not exist)
  2. Retrieving NSEC or NSEC3 records from the authority section
  3. Validating the RRSIG over NSEC/NSEC3 (reuses Q1 verify_rrsig)
  4. Verifying that the NSEC/NSEC3 record covers (proves absence of) the queried name

NSEC  — covers a range [owner_name, next_name) in canonical DNS name order
NSEC3 — covers a range [hash(owner), hash(next)) using SHA-1 with salt/iterations

References: RFC 4034 §6 (NSEC), RFC 5155 (NSEC3)
"""

import hashlib
import base64
import sys
import struct
from dataclasses import dataclass, field
from typing import Optional

import dns.name
import dns.rdatatype
import dns.rcode
import dns.message

from q1_dnssec_validator import (
    _query,
    _key_tag,
    fetch_dnskey,
    verify_rrsig,
    FALLBACK_RESOLVER,
)
from q2_resolver import resolve_iterative, ResolverResult


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NegativeResult:
    query: str
    rdtype: str
    exists: bool = True                      # False when NXDOMAIN or NODATA
    negative_type: Optional[str] = None      # "NXDOMAIN" or "NODATA"
    proof_type: Optional[str] = None         # "NSEC" or "NSEC3"
    proof_valid: bool = False
    steps: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def print(self):
        print(f"\nQuery: {self.query} {self.rdtype}")
        if self.exists:
            print("Result: EXISTS")
        else:
            print(f"Result: DOES NOT EXIST ({self.negative_type})")
            proof_status = "VALID" if self.proof_valid else "INVALID"
            print(f"Proof: {proof_status} ({self.proof_type})" if self.proof_type
                  else f"Proof: {proof_status}")
        if self.error:
            print(f"Error: {self.error}")
        print("Steps:")
        for step in self.steps:
            print(f"  - {step}")


# ---------------------------------------------------------------------------
# Canonical DNS name ordering (RFC 4034 §6.1)
# ---------------------------------------------------------------------------

def _canonical_name_key(name: str) -> list[bytes]:
    """
    Convert a DNS name to its canonical sort key (RFC 4034 §6.1):
    - Labels are compared right-to-left (TLD first, then SLD, etc.)
    - Each label is compared octet-by-octet, case-insensitively (lowercased)
    Returns a list of label bytes in comparison order (rightmost first).
    """
    labels = dns.name.from_text(name).labels  # tuple of bytes, root label last
    # labels = (b'www', b'example', b'com', b'')  for www.example.com
    # Reverse so root (b'') is first, then TLD, SLD, etc.
    # Then drop the root label for comparison
    reversed_labels = list(reversed(labels))
    # Drop empty root label at position 0
    if reversed_labels and reversed_labels[0] == b'':
        reversed_labels = reversed_labels[1:]
    return [label.lower() for label in reversed_labels]


def _name_in_nsec_range(qname: str, owner: str, next_name: str) -> bool:
    """
    Check if qname is covered by the NSEC record [owner, next_name).
    In canonical order: owner < qname < next_name  (or wrap-around for last NSEC)

    Returns True if the NSEC record proves qname does not exist.
    """
    q_key = _canonical_name_key(qname)
    o_key = _canonical_name_key(owner)
    n_key = _canonical_name_key(next_name)

    if o_key < n_key:
        # Normal range: owner < qname < next_name
        return o_key < q_key < n_key
    else:
        # Wrap-around: last NSEC in zone covers [owner, zone_apex)
        # qname is covered if qname > owner OR qname < next_name
        return q_key > o_key or q_key < n_key


# ---------------------------------------------------------------------------
# NSEC3 hashing (RFC 5155 §5)
# ---------------------------------------------------------------------------

def _nsec3_hash(name: str, salt_hex: str, iterations: int) -> str:
    """
    Compute the NSEC3 hash of a DNS name per RFC 5155 §5:
      IH(0) = H(name_wire || salt)
      IH(k) = H(IH(k-1) || salt)
    where H = SHA-1.
    Returns the hash as uppercase base32 (without padding).
    """
    name_wire = dns.name.from_text(name).canonicalize().to_wire()
    salt = bytes.fromhex(salt_hex) if salt_hex and salt_hex != "-" else b""

    digest = hashlib.sha1(name_wire + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()

    return base64.b32encode(digest).decode().rstrip("=").upper()


def _name_in_nsec3_range(qname_hash: str, owner_hash: str, next_hash: str) -> bool:
    """
    Check if qname_hash falls in the NSEC3 range (owner_hash, next_hash].
    Hashes are base32-encoded uppercase strings.
    Returns True if the NSEC3 record covers the queried name.
    """
    if owner_hash < next_hash:
        return owner_hash < qname_hash <= next_hash
    else:
        # Wrap-around (last NSEC3 in zone)
        return qname_hash > owner_hash or qname_hash <= next_hash


# ---------------------------------------------------------------------------
# NSEC/NSEC3 extraction and validation
# ---------------------------------------------------------------------------

def _validate_nsec_rrsig(nsec_rrset, zone: str) -> tuple[bool, str]:
    """
    Validate the RRSIG covering an NSEC or NSEC3 rrset using Q1's verify_rrsig.
    Returns (valid: bool, detail: str).
    """
    # Get RRSIG records for this rrset from the same response section
    # (We pass them in via the response object)
    return False, "no rrsig provided"


def _nsec_type_list(nsec_rdata) -> list[str]:
    """Return list of type names present in the NSEC type bitmap."""
    types = []
    for window, bitmap in nsec_rdata.windows:
        for i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    rdtype_val = window * 256 + i * 8 + bit
                    types.append(dns.rdatatype.to_text(rdtype_val))
    return types


def _find_rrsig_for_rrset(rrset, authority_section) -> list:
    """Find RRSIG records in the authority section that cover the given rrset."""
    rrsigs = []
    for section_rrset in authority_section:
        if section_rrset.rdtype == dns.rdatatype.RRSIG:
            for rr in section_rrset:
                if rr.type_covered == rrset.rdtype:
                    rrsigs.append(rr)
    return rrsigs


def _verify_nsec_signature(nsec_rrset, rrsigs: list, zone: str) -> tuple[bool, str]:
    """
    Verify RRSIG over NSEC or NSEC3 rrset using the zone's DNSKEY.
    Returns (verified: bool, detail: str).
    """
    if not rrsigs:
        return False, "No RRSIG found for NSEC/NSEC3 record"

    zsk_list, ksk_list = fetch_dnskey(zone, FALLBACK_RESOLVER)
    all_keys = zsk_list + ksk_list
    if not all_keys:
        return False, f"No DNSKEY found for zone {zone}"

    for rrsig in rrsigs:
        key = next((k for k in all_keys if _key_tag(k) == rrsig.key_tag), None)
        if key and verify_rrsig(nsec_rrset, rrsig, key):
            role = "ZSK" if key in zsk_list else "KSK"
            return True, f"RRSIG over {dns.rdatatype.to_text(nsec_rrset.rdtype)} verified using {role} (tag={rrsig.key_tag})"

    return False, "RRSIG verification failed for NSEC/NSEC3"


def _get_zone_from_rrsig(rrsigs: list) -> Optional[str]:
    """Extract the signing zone name from an RRSIG record."""
    if rrsigs:
        return str(rrsigs[0].signer).rstrip(".")
    return None


# ---------------------------------------------------------------------------
# Main negative response validator
# ---------------------------------------------------------------------------

def validate_negative_response(domain: str, rdtype_str: str) -> NegativeResult:
    """
    Query for domain/rdtype and handle NXDOMAIN or NODATA responses.
    Validates NSEC or NSEC3 records that prove non-existence.
    """
    result = NegativeResult(query=domain, rdtype=rdtype_str)
    rdtype = dns.rdatatype.from_text(rdtype_str)

    # Query with CD+DO to get NSEC/NSEC3 records
    response = _query(FALLBACK_RESOLVER, domain, rdtype, recursive=True)
    if response is None:
        result.error = "No response from resolver"
        return result

    rcode = response.rcode()

    # Check if domain actually exists
    if rcode == dns.rcode.NOERROR and response.answer:
        result.exists = True
        result.steps.append(f"{domain} {rdtype_str} EXISTS — no negative proof needed")
        return result

    # Determine negative type
    if rcode == dns.rcode.NXDOMAIN:
        result.exists = False
        result.negative_type = "NXDOMAIN"
        result.steps.append(f"NXDOMAIN received: {domain} does not exist")
    elif rcode == dns.rcode.NOERROR and not response.answer:
        result.exists = False
        result.negative_type = "NODATA"
        result.steps.append(f"NODATA received: {domain} exists but has no {rdtype_str} records")
    else:
        result.error = f"Unexpected rcode: {dns.rcode.to_text(rcode)}"
        return result

    # Extract NSEC and NSEC3 records from authority section
    nsec_rrsets = []
    nsec3_rrsets = []

    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            nsec_rrsets.append(rrset)
        elif rrset.rdtype == dns.rdatatype.NSEC3:
            nsec3_rrsets.append(rrset)

    if not nsec_rrsets and not nsec3_rrsets:
        result.error = "No NSEC/NSEC3 records found in authority section"
        result.steps.append("FAILED: No denial-of-existence proof in response")
        return result

    # --- Handle NSEC ---
    if nsec_rrsets:
        result.proof_type = "NSEC"
        result.steps.append(f"Found {len(nsec_rrsets)} NSEC record(s) in authority section")

        all_valid = True
        coverage_found = False

        for nsec_rrset in nsec_rrsets:
            owner = str(nsec_rrset.name).rstrip(".")
            for rr in nsec_rrset:
                next_name = str(rr.next).rstrip(".")
                result.steps.append(f"NSEC: {owner} → {next_name}")

                # Validate RRSIG
                rrsigs = _find_rrsig_for_rrset(nsec_rrset, response.authority)
                zone = _get_zone_from_rrsig(rrsigs) or owner
                sig_ok, sig_detail = _verify_nsec_signature(nsec_rrset, rrsigs, zone)
                result.steps.append(f"  Signature: {'OK' if sig_ok else 'FAILED'} — {sig_detail}")
                if not sig_ok:
                    all_valid = False

                # Coverage check depends on negative type:
                if result.negative_type == "NODATA":
                    # NODATA: NSEC owner = queried name; queried type absent from bitmap
                    owner_matches = owner.lower() == domain.lower()
                    existing_types = _nsec_type_list(rr)
                    type_absent = dns.rdatatype.to_text(rdtype) not in existing_types
                    result.steps.append(
                        f"  NODATA check: owner matches={owner_matches}, "
                        f"{dns.rdatatype.to_text(rdtype)} absent from bitmap={type_absent}"
                    )
                    result.steps.append(f"  Types present at {owner}: {existing_types}")
                    if owner_matches and type_absent:
                        coverage_found = True
                else:
                    # NXDOMAIN: queried name falls between owner and next_name
                    covers = _name_in_nsec_range(domain, owner, next_name)
                    result.steps.append(
                        f"  Coverage: {domain} {'IS' if covers else 'is NOT'} in range "
                        f"({owner}, {next_name})"
                    )
                    if covers:
                        coverage_found = True

        result.proof_valid = all_valid and coverage_found
        if not coverage_found:
            result.steps.append("WARNING: No NSEC record covers the queried name")

    # --- Handle NSEC3 ---
    elif nsec3_rrsets:
        result.proof_type = "NSEC3"
        result.steps.append(f"Found {len(nsec3_rrsets)} NSEC3 record(s) in authority section")

        all_valid = True
        coverage_found = False

        for nsec3_rrset in nsec3_rrsets:
            owner_hash = str(nsec3_rrset.name).split(".")[0].upper()

            for rr in nsec3_rrset:
                # rr.next is bytes; encode as base32
                next_hash = base64.b32encode(rr.next).decode().rstrip("=").upper()
                salt_hex = rr.salt.hex() if rr.salt else "-"
                iterations = rr.iterations

                result.steps.append(
                    f"NSEC3: hash={owner_hash} → {next_hash} "
                    f"(salt={salt_hex}, iterations={iterations})"
                )

                # Compute hash of query name
                qname_hash = _nsec3_hash(domain, salt_hex, iterations)
                result.steps.append(f"  Hash of {domain}: {qname_hash}")

                # Validate RRSIG
                rrsigs = _find_rrsig_for_rrset(nsec3_rrset, response.authority)
                zone = _get_zone_from_rrsig(rrsigs)
                if zone:
                    sig_ok, sig_detail = _verify_nsec_signature(nsec3_rrset, rrsigs, zone)
                    result.steps.append(f"  Signature: {'OK' if sig_ok else 'FAILED'} — {sig_detail}")
                    if not sig_ok:
                        all_valid = False

                # Check coverage
                covers = _name_in_nsec3_range(qname_hash, owner_hash, next_hash)
                result.steps.append(
                    f"  Coverage: {qname_hash} {'IS' if covers else 'is NOT'} in range "
                    f"({owner_hash}, {next_hash})"
                )
                if covers:
                    coverage_found = True

        result.proof_valid = all_valid and coverage_found
        if not coverage_found:
            result.steps.append("NOTE: Name hash not directly in NSEC3 range (closest encloser proof may apply)")

    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage: python q3_nsec_resolver.py <domain> <record_type>")
        print("Example: python q3_nsec_resolver.py doesnotexist.example.com A")
        sys.exit(1)

    domain = sys.argv[1]
    rdtype = sys.argv[2].upper()

    result = validate_negative_response(domain, rdtype)
    result.print()

    # Exit 0 if negative proof is valid, 1 otherwise
    sys.exit(0 if (not result.exists and result.proof_valid) else 1)


if __name__ == "__main__":
    main()
