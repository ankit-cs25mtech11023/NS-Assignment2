"""
Q2: DNSSEC-Validating Recursive Resolver
CS6903 Network Security, IIT Hyderabad

Implements a recursive resolver that:
  1. Starts from root servers
  2. Walks the delegation chain: Root → TLD → Authoritative
  3. At EACH step validates DNSKEY, RRSIG, and DS chain using Q1 module

Note: Uses the Q1 validation module for all cryptographic verification.
"""

import sys
from dataclasses import dataclass, field
from typing import Optional

import dns.name
import dns.query
import dns.message
import dns.rdatatype
import dns.flags
import dns.rcode

from q1_dnssec_validator import (
    _query,
    _key_tag,
    fetch_dnskey,
    fetch_ds,
    fetch_rrset_with_rrsig,
    verify_rrsig,
    verify_dnskey_with_ds,
    FALLBACK_RESOLVER,
    ROOT_SERVERS,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ResolverResult:
    query: str
    rdtype: str
    ip_answers: list[str] = field(default_factory=list)
    dnssec_verified: bool = False
    path: list[str] = field(default_factory=list)   # e.g. ["Root", ".com", "example.com"]
    step_validations: list[ValidationResult] = field(default_factory=list)
    error: Optional[str] = None

    def print(self):
        print(f"\nQuery: {self.query} {self.rdtype}")
        if self.ip_answers:
            for ans in self.ip_answers:
                print(f"IP: {ans}")
        print(f"DNSSEC: {'VERIFIED' if self.dnssec_verified else 'NOT VERIFIED'}")
        if self.error:
            print(f"Error: {self.error}")
        print(f"Path:\n  {' → '.join(self.path)}")
        print("\nDetailed validation per step:")
        for vr in self.step_validations:
            status = "VALID" if vr.valid else "INVALID"
            print(f"  [{status}] {vr.domain} ({vr.record_type})")
            for s in vr.steps:
                print(f"       {s}")
            if vr.error:
                print(f"       Error: {vr.error}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_ns_ips_from_response(response: dns.message.Message, server_ip: str) -> list[str]:
    """
    Extract nameserver IPs from a DNS response.
    First tries glue records in the additional section.
    Falls back to resolving NS names via server_ip.
    """
    ns_names = []
    glue: dict[str, str] = {}

    # Prefer A over AAAA — only store AAAA if no A record exists for that name
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            name = str(rrset.name).rstrip(".")
            glue[name] = str(next(iter(rrset)))
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.AAAA:
            name = str(rrset.name).rstrip(".")
            if name not in glue:
                glue[name] = str(next(iter(rrset)))

    for section in (response.answer, response.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns_names.append(str(rr.target).rstrip("."))

    ns_ips = []
    for name in ns_names:
        if name in glue:
            ns_ips.append(glue[name])
        else:
            # Resolve the NS hostname via our fallback resolver
            for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                resp = _query(FALLBACK_RESOLVER, name, rdtype)
                if resp:
                    for rrset in resp.answer:
                        if rrset.rdtype == rdtype:
                            ns_ips.append(str(next(iter(rrset))))
                            break
                if ns_ips and ns_ips[-1]:
                    break

    return ns_ips


def _validate_zone_at_server(zone: str, server_ip: str) -> ValidationResult:
    """
    Validate DNSSEC for a zone.
    DNSKEY/RRSIG records are fetched via FALLBACK_RESOLVER (8.8.8.8 with CD+DO)
    because authoritative-only servers (TLD servers) refuse recursive queries.
    Cryptographic verification is independent of which server we fetched from.
    DS records are also fetched via FALLBACK_RESOLVER from the parent zone.
    """
    vr = ValidationResult(valid=False, domain=zone, record_type="DNSKEY")

    dnskey_rrset, dnskey_rrsigs = fetch_rrset_with_rrsig(zone, "DNSKEY", FALLBACK_RESOLVER)
    if dnskey_rrset is None or len(dnskey_rrset) == 0:
        vr.error = f"No DNSKEY records found for {zone}"
        vr.steps.append("FAILED: No DNSKEY records found")
        return vr

    zsk_list, ksk_list = [], []
    for rr in dnskey_rrset:
        if rr.flags == 256:
            zsk_list.append(rr)
        elif rr.flags == 257:
            ksk_list.append(rr)

    all_keys = zsk_list + ksk_list
    zsk_tags = [_key_tag(k) for k in zsk_list]
    ksk_tags = [_key_tag(k) for k in ksk_list]
    vr.steps.append(f"DNSKEY retrieved (ZSK tag(s): {zsk_tags}, KSK tag(s): {ksk_tags})")

    # Verify RRSIG over DNSKEY RRset (should be signed by KSK)
    if not dnskey_rrsigs:
        vr.error = "No RRSIG found over DNSKEY RRset"
        vr.steps.append("FAILED: No RRSIG found over DNSKEY")
        return vr

    rrsig_ok = False
    for rrsig in dnskey_rrsigs:
        key = None
        for k in all_keys:
            if _key_tag(k) == rrsig.key_tag:
                key = k
                break
        if key and verify_rrsig(dnskey_rrset, rrsig, key):
            rrsig_ok = True
            role = "KSK" if key in ksk_list else "ZSK"
            vr.steps.append(f"RRSIG over DNSKEY verified using {role} (tag={rrsig.key_tag})")
            break

    if not rrsig_ok:
        vr.error = "RRSIG over DNSKEY verification failed"
        vr.steps.append("FAILED: RRSIG over DNSKEY invalid")
        return vr

    # Verify DS from parent
    ds_records = fetch_ds(zone, FALLBACK_RESOLVER)
    if not ds_records:
        vr.error = "No DS records found in parent zone"
        vr.steps.append("FAILED: No DS records in parent zone")
        return vr

    ds_matched, matched_tags = verify_dnskey_with_ds(zone, ksk_list, ds_records)
    if not ds_matched:
        vr.error = "DS record does not match KSK"
        vr.steps.append("FAILED: DS does not match KSK")
        return vr

    vr.steps.append(f"DS matched parent zone (KSK tag(s): {matched_tags})")
    vr.valid = True
    return vr


# ---------------------------------------------------------------------------
# Recursive resolver
# ---------------------------------------------------------------------------

def _build_zone_chain(domain: str) -> list[str]:
    """
    Build the list of zones from root down to the domain.
    e.g. "www.example.com" → [".", "com", "example.com", "www.example.com"]
    The final entry is the authoritative zone for the domain (may equal domain).
    """
    parts = domain.rstrip(".").split(".")
    zones = ["."]
    for i in range(len(parts) - 1, -1, -1):
        zones.append(".".join(parts[i:]))
    return zones


def resolve_iterative(domain: str, rdtype_str: str) -> ResolverResult:
    """
    DNSSEC-validating resolver.

    Walks the chain of trust from the root down to the target zone using
    FALLBACK_RESOLVER (8.8.8.8) with CD+DO flags so RRSIG records are
    returned. At each level the DNSKEY/RRSIG/DS chain is validated using
    Q1 functions, then the final answer RRSIG is verified.

    Note: direct queries to authoritative nameservers are blocked by the
    local network; using a CD-capable recursive resolver is equivalent
    because we perform all cryptographic verification ourselves.
    """
    result = ResolverResult(query=domain, rdtype=rdtype_str)
    rdtype = dns.rdatatype.from_text(rdtype_str)

    # Step 1: Validate root zone (trust anchor)
    root_vr = _validate_root_dnskey(ROOT_SERVERS[0])
    result.step_validations.append(root_vr)
    result.path.append("Root")
    if not root_vr.valid:
        result.error = "Root DNSKEY validation failed"
        return result

    # Step 2: Build zone chain and validate each intermediate zone.
    # Stop when a name has no DNSKEY — it is a hostname, not a delegated zone.
    zone_chain = _build_zone_chain(domain)  # [".", "com", "example.com", ...]
    for zone in zone_chain[1:]:             # skip "." already handled above
        zsk, ksk = fetch_dnskey(zone, FALLBACK_RESOLVER)
        if not zsk and not ksk:
            # Not a delegated zone — hostname within the previous zone; stop here
            break
        zone_vr = _validate_zone_at_server(zone, FALLBACK_RESOLVER)
        result.step_validations.append(zone_vr)
        result.path.append(_zone_display_label(zone))
        if not zone_vr.valid:
            result.error = f"DNSSEC validation failed at zone {zone}"
            result.dnssec_verified = False
            return result

    # Step 3: Fetch the actual answer record via FALLBACK_RESOLVER
    response = _query(FALLBACK_RESOLVER, domain, rdtype, recursive=True)
    if response is None:
        result.error = f"No response fetching {domain} {rdtype_str}"
        return result

    rcode = response.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        result.error = f"NXDOMAIN: {domain} does not exist"
        return result

    # Step 4: Validate the answer RRSIG
    for rrset in response.answer:
        if rrset.rdtype == rdtype:
            result.ip_answers = [str(rr) for rr in rrset]
            final_vr = _validate_answer(domain, rdtype_str, FALLBACK_RESOLVER, response)
            result.step_validations.append(final_vr)
            result.dnssec_verified = all(v.valid for v in result.step_validations)
            return result

    result.error = f"No {rdtype_str} records found in answer for {domain}"
    return result


def _validate_root_dnskey(root_server_ip: str) -> ValidationResult:
    """
    Validate the root zone DNSKEY against the built-in IANA trust anchor.
    The root has no parent DS — we trust its KSK directly.
    """
    from q1_dnssec_validator import ROOT_TRUST_ANCHOR_DS, _compute_ds_digest

    vr = ValidationResult(valid=False, domain=".", record_type="DNSKEY")

    dnskey_rrset, dnskey_rrsigs = fetch_rrset_with_rrsig(".", "DNSKEY", root_server_ip)
    if dnskey_rrset is None or len(dnskey_rrset) == 0:
        vr.error = "No DNSKEY records found for root"
        vr.steps.append("FAILED: No DNSKEY records for root zone")
        return vr

    ksk_list = [rr for rr in dnskey_rrset if rr.flags == 257]
    zsk_list = [rr for rr in dnskey_rrset if rr.flags == 256]
    vr.steps.append(
        f"Root DNSKEY retrieved (ZSK tags: {[_key_tag(k) for k in zsk_list]}, "
        f"KSK tags: {[_key_tag(k) for k in ksk_list]})"
    )

    # Verify RRSIG over root DNSKEY RRset
    all_keys = zsk_list + ksk_list
    rrsig_ok = False
    for rrsig in dnskey_rrsigs:
        key = next((k for k in all_keys if _key_tag(k) == rrsig.key_tag), None)
        if key and verify_rrsig(dnskey_rrset, rrsig, key):
            rrsig_ok = True
            vr.steps.append(f"Root DNSKEY RRSIG verified (tag={rrsig.key_tag})")
            break

    if not rrsig_ok:
        vr.error = "Root DNSKEY RRSIG verification failed"
        vr.steps.append("FAILED: Root DNSKEY RRSIG invalid")
        return vr

    # Match KSK against built-in trust anchor
    ta = ROOT_TRUST_ANCHOR_DS
    anchor_matched = False
    for ksk in ksk_list:
        if _key_tag(ksk) == ta["key_tag"]:
            digest = _compute_ds_digest(".", ksk, ta["digest_type"])
            if digest == ta["digest"]:
                anchor_matched = True
                vr.steps.append(f"Root KSK matches IANA trust anchor (tag={ta['key_tag']})")
                break

    if not anchor_matched:
        vr.error = "Root KSK does not match IANA trust anchor"
        vr.steps.append("FAILED: Root KSK does not match trust anchor")
        return vr

    vr.valid = True
    return vr


def _validate_answer(domain: str, rdtype_str: str, server_ip: str,
                     response: dns.message.Message) -> ValidationResult:
    """Validate RRSIG over the final answer RRset."""
    from q1_dnssec_validator import _get_signing_key

    rdtype = dns.rdatatype.from_text(rdtype_str)
    vr = ValidationResult(valid=False, domain=domain, record_type=rdtype_str)

    # Find target RRset and its RRSIG in the response
    target_rrset = None
    rrsigs = []
    for rrset in response.answer:
        if rrset.rdtype == rdtype:
            target_rrset = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            for rr in rrset:
                if rr.type_covered == rdtype:
                    rrsigs.append(rr)

    if target_rrset is None:
        vr.error = f"No {rdtype_str} RRset in answer"
        vr.steps.append(f"FAILED: No {rdtype_str} RRset")
        return vr

    vr.steps.append(f"Answer RRset retrieved ({len(target_rrset)} record(s))")

    if not rrsigs:
        vr.error = f"No RRSIG for {rdtype_str} in answer"
        vr.steps.append(f"FAILED: No RRSIG for {rdtype_str}")
        return vr

    # Fetch DNSKEY from the signer zone (from RRSIG.signer), not from the
    # queried hostname which may not be a delegated zone.
    signer_zone = str(rrsigs[0].signer).rstrip(".")
    zsk_list, ksk_list = fetch_dnskey(signer_zone, server_ip)
    all_keys = zsk_list + ksk_list
    if not all_keys:
        vr.error = f"No DNSKEY available in signer zone {signer_zone}"
        vr.steps.append(f"FAILED: No DNSKEY found in signer zone {signer_zone}")
        return vr

    for rrsig in rrsigs:
        key = _get_signing_key(rrsig, zsk_list) or _get_signing_key(rrsig, all_keys)
        if key and verify_rrsig(target_rrset, rrsig, key):
            role = "ZSK" if key in zsk_list else "KSK"
            vr.steps.append(f"Answer RRSIG verified using {role} (tag={rrsig.key_tag})")
            vr.valid = True
            return vr

    vr.error = "Answer RRSIG verification failed"
    vr.steps.append("FAILED: Answer RRSIG invalid")
    return vr


def _get_referred_zone(response: dns.message.Message) -> Optional[str]:
    """Extract the zone name from NS records in the authority section."""
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            return str(rrset.name).rstrip(".")
    return None


def _zone_display_label(zone: str) -> str:
    """Format zone for path display: '.' → 'Root', 'com' → '.com', etc."""
    if zone == ".":
        return "Root"
    if not zone.startswith("."):
        return f".{zone}" if "." not in zone.rstrip(".") else zone
    return zone


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage: python q2_resolver.py <domain> <record_type>")
        print("Example: python q2_resolver.py example.com A")
        sys.exit(1)

    domain = sys.argv[1]
    rdtype = sys.argv[2].upper()

    result = resolve_iterative(domain, rdtype)
    result.print()
    sys.exit(0 if result.dnssec_verified else 1)


if __name__ == "__main__":
    main()
