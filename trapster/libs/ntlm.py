"""
Helpers for building and parsing NTLM messages over LDAP (Sicily and SASL/SPNEGO).

References:
  [MS-NLMP] NT LAN Manager (NTLM) Authentication Protocol
  [MS-SPNG] Simple and Protected GSS-API Negotiation Mechanism (SPNEGO)
"""

import os
import struct


# ---------------------------------------------------------------------------
# DER length encoding (used by SPNEGO wrapper)
# ---------------------------------------------------------------------------

def der_len(n):
    """Encode an integer as a DER length field."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, n >> 8, n & 0xff])


# ---------------------------------------------------------------------------
# NTLM message helpers
# ---------------------------------------------------------------------------

def extract_ntlm(data):
    """Find and return the raw NTLM message inside SPNEGO-wrapped data or as-is."""
    pos = data.find(b'NTLMSSP\x00')
    return data[pos:] if pos >= 0 else None


def build_ntlm_type2(challenge, hostname, fqdn, dc_parts):
    """
    Build a minimal NTLM Type 2 (Challenge) message.

    Layout (no Version field):
      0-7   Signature  "NTLMSSP\\0"
      8-11  MessageType  2
      12-19 TargetNameFields  (len, maxLen, offset)
      20-23 NegotiateFlags
      24-31 ServerChallenge  (8 bytes)
      32-39 Reserved  (8 zero bytes)
      40-47 TargetInfoFields  (len, maxLen, offset)
      48+   Payload  (TargetName, then TargetInfo AV pairs)
    """
    def av(av_id, value_bytes):
        return struct.pack('<HH', av_id, len(value_bytes)) + value_bytes

    nb_domain  = dc_parts[0].upper().encode('utf-16-le')          # e.g. b"CORP"
    nb_host    = hostname.upper().encode('utf-16-le')              # e.g. b"DC01"
    dns_domain = fqdn.encode('utf-16-le')                          # e.g. b"corp.local"
    dns_host   = f"{hostname}.{fqdn}".encode('utf-16-le')          # e.g. b"DC01.corp.local"

    target_info = (
        av(1, nb_host)   +           # MsvAvNbComputerName
        av(2, nb_domain) +           # MsvAvNbDomainName
        av(3, dns_host)  +           # MsvAvDnsComputerName  (NTLMSSP_AV_DNS_HOSTNAME)
        av(4, dns_domain) +          # MsvAvDnsDomainName
        struct.pack('<HH', 0, 0)     # MsvAvEOL
    )

    target = nb_domain  # TargetName = NetBIOS domain name
    flags = struct.pack('<I',
        0x00000001 |   # NTLMSSP_NEGOTIATE_UNICODE
        0x00000200 |   # NTLMSSP_NEGOTIATE_NTLM
        0x00008000 |   # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        0x00010000 |   # NTLMSSP_TARGET_TYPE_DOMAIN
        0x00800000 |   # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        0x20000000 |   # NTLMSSP_NEGOTIATE_128
        0x80000000     # NTLMSSP_NEGOTIATE_56
    )

    target_offset = 48              # fixed header size without Version field
    info_offset   = 48 + len(target)

    return (
        b'NTLMSSP\x00'
        b'\x02\x00\x00\x00'
        + struct.pack('<HHI', len(target), len(target), target_offset)
        + flags
        + challenge
        + b'\x00' * 8
        + struct.pack('<HHI', len(target_info), len(target_info), info_offset)
        + target
        + target_info
    )


def wrap_spnego(ntlm_bytes):
    """
    Wrap a raw NTLM message in a minimal SPNEGO NegTokenResp for SASL responses.

    Structure (DER):
      [1] NegTokenResp
        [0] negState  ENUMERATED  accept-incomplete (1)
        [2] responseToken  OCTET STRING  <ntlm_bytes>
    """
    d = der_len
    octet = b'\x04' + d(len(ntlm_bytes)) + ntlm_bytes
    token = b'\xa2' + d(len(octet)) + octet
    state = b'\xa0\x03\x0a\x01\x01'   # negState = accept-incomplete (ENUMERATED tag 0x0a)
    seq   = b'\x30' + d(len(state + token)) + state + token
    return  b'\xa1' + d(len(seq)) + seq


def parse_ntlm_type3(data):
    """
    Extract (username, domain) from a raw NTLM Type 3 (Authenticate) message.
    Returns ('', '') on any parse error.
    """
    try:
        flags = struct.unpack_from('<I', data, 60)[0]
        enc = 'utf-16-le' if (flags & 0x01) else 'ascii'

        domain_len = struct.unpack_from('<H', data, 28)[0]
        domain_off = struct.unpack_from('<I', data, 32)[0]
        domain = data[domain_off:domain_off + domain_len].decode(enc, errors='replace')

        user_len = struct.unpack_from('<H', data, 36)[0]
        user_off = struct.unpack_from('<I', data, 40)[0]
        username = data[user_off:user_off + user_len].decode(enc, errors='replace')

        return username, domain
    except Exception:
        return '', ''
