from trapster.modules.base import BaseProtocol, BaseHoneypot

import asyncio
import datetime
import os
import re
import ssl
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

# RDP Security Protocol constants (MS-RDPBCGR 2.2.1.2.1)
PROTOCOL_RDP      = 0x00000000
PROTOCOL_SSL      = 0x00000001
PROTOCOL_HYBRID   = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008


class RdpProtocol(BaseProtocol):

    def __init__(self, config=None):
        self.config = config or {}
        self.protocol_name = "rdp"
        self.state = "CR"
        self.username = ""
        self.ntlm_challenge = os.urandom(8)

        self.versions = {
            "winxp":  (5,  1, 2600),   # Windows XP SP3
            "win7":   (6,  1, 7601),   # Windows 7 SP1 / Server 2008 R2
            "win81":  (6,  3, 9600),   # Windows 8.1 / Server 2012 R2
            "win10":  (10, 0, 19041),  # Windows 10 20H1
            "win11":  (10, 0, 26200),  # Windows 11 25H2
            "2012":   (6,  2, 9200),   # Windows Server 2012
            "2012r2": (6,  3, 9600),   # Windows Server 2012 R2
            "2016":   (10, 0, 14393),  # Windows Server 2016
            "2019":   (10, 0, 17763),  # Windows Server 2019
            "2022":   (10, 0, 20348),  # Windows Server 2022
        }
        self._version_key = self.config.get("version", "2019")
        self.os_version = self.versions.get(self._version_key, self.versions["2019"])

        # XP and early systems don't support NLA/TLS negotiation
        self._nla_supported = self._version_key not in ('winxp',)

    def connection_made(self, transport):
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

    def data_received(self, data):
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)

        if self.state == "CR":
            self._handle_cr(data)
        elif self.state == "NLA":
            self._handle_nla(data)

    # ---- Connection Request / Confirm ----

    def _parse_cr(self, data):
        """Extract SRC-REF and requestedProtocols from the X.224 CR TPDU."""
        src_ref = b'\x00\x00'
        requested_protocols = None

        if len(data) < 11:
            return src_ref, requested_protocols

        # TPKT header: 4 bytes. X.224 fixed: LI(1)+type(1)+DST-REF(2)+SRC-REF(2)+CLASS(1)
        src_ref = data[7:9]

        # Variable data starts at offset 11 (4 TPKT + 7 X.224 fixed)
        var_data = data[11:]

        # Skip routing token / cookie (terminated by \r\n)
        crlf = var_data.find(b'\r\n')
        after_cookie = var_data[crlf + 2:] if crlf != -1 else var_data

        # Type_RDP_NEG_REQ = 0x01, then flags(1)+length(2)+requestedProtocols(4)
        if len(after_cookie) >= 8 and after_cookie[0] == 0x01:
            requested_protocols = struct.unpack('<I', after_cookie[4:8])[0]

        return src_ref, requested_protocols

    _neg_flags_map = {
        'winxp':  0x00,
        'win7':   0x07,
        'win81':  0x0f,
        'win10':  0x1f,
        'win11':  0x1f,
        '2012':   0x0f,
        '2012r2': 0x0f,
        '2016':   0x1f,
        '2019':   0x1f,
        '2022':   0x1f,
    }

    def _build_cc(self, src_ref, selected_protocol):
        """Build X.224 Connection Confirm (CC) TPDU."""
        # RDP Negotiation Response (Type_RDP_NEG_RSP = 0x02)
        flags = self._neg_flags_map.get(self._version_key, 0x1f)
        neg_rsp = struct.pack('<BBHI', 0x02, flags, 8, selected_protocol) \
            if selected_protocol is not None else b''

        # X.224 CC: type(0xD0) + DST-REF(echoes client SRC-REF) + SRC-REF + CLASS + [neg_rsp]
        # Real Windows always sends SRC-REF 0x1234; nmap's fingerprint matches on this exact value.
        x224_body = b'\xd0' + src_ref + b'\x12\x34' + b'\x00' + neg_rsp
        li = len(x224_body)
        x224 = bytes([li]) + x224_body

        tpkt = struct.pack('>BBH', 3, 0, 4 + len(x224))
        return tpkt + x224

    def _handle_cr(self, data):
        decoded = data.decode('utf-8', errors='ignore')
        match = re.search(r'mstshash=(?P<username>[a-zA-Z0-9-_@.]*)', decoded)
        self.username = match.group('username') if match else ''

        src_ref, requested_protocols = self._parse_cr(data)

        self.logger.log(
            self.protocol_name + '.' + self.logger.LOGIN,
            self.transport,
            extra={'username': self.username, 'password': ''},
        )

        # Select the best matching security protocol
        if requested_protocols is None or not self._nla_supported:
            selected = PROTOCOL_RDP
            include_neg = False
        else:
            include_neg = True
            if requested_protocols & PROTOCOL_HYBRID_EX:
                selected = PROTOCOL_HYBRID_EX
            elif requested_protocols & PROTOCOL_HYBRID:
                selected = PROTOCOL_HYBRID
            elif requested_protocols & PROTOCOL_SSL:
                selected = PROTOCOL_SSL
            else:
                selected = PROTOCOL_RDP

        self.transport.write(self._build_cc(src_ref, selected if include_neg else None))

        if selected in (PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
            self.state = 'TLS'
            asyncio.get_running_loop().create_task(self._start_tls())
        else:
            self.transport.close()

    # ---- TLS upgrade ----

    async def _start_tls(self):
        key_path = self.config.get('key_path')
        cert_path = self.config.get('cert_path')
        if not key_path or not cert_path:
            self.transport.close()
            return

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        except Exception:
            self.transport.close()
            return

        loop = asyncio.get_running_loop()
        try:
            new_transport = await loop.start_tls(
                self.transport, self, ssl_ctx, server_side=True
            )
            self.transport = new_transport
            self.state = 'NLA'
        except Exception:
            self.transport.close()

    # ---- NLA / CredSSP / NTLM ----

    def _asn1_tlv(self, tag, value):
        n = len(value)
        if n < 0x80:
            return bytes([tag, n]) + value
        elif n < 0x100:
            return bytes([tag, 0x81, n]) + value
        else:
            return bytes([tag, 0x82, n >> 8, n & 0xff]) + value

    def _build_ntlm_challenge(self):
        """Build an NTLM Type 2 (Challenge) message with realistic OS/host metadata."""
        hostname = self.config.get('ntlm_hostname', 'WIN-RDP').encode('utf-16-le')
        domain   = self.config.get('ntlm_domain',   'WORKGROUP').encode('utf-16-le')

        def av_pair(av_id, value):
            return struct.pack('<HH', av_id, len(value)) + value

        # Windows FILETIME: 100-ns intervals since 1601-01-01
        filetime = (int(__import__('time').time()) + 11644473600) * 10_000_000

        target_info = (
            av_pair(0x0002, domain)                          # MsvAvNbDomainName
            + av_pair(0x0001, hostname)                        # MsvAvNbComputerName
            + av_pair(0x0004, domain)                          # MsvAvDnsDomainName
            + av_pair(0x0003, hostname)                        # MsvAvDnsComputerName
            + av_pair(0x0007, struct.pack('<Q', filetime))     # MsvAvTimestamp
            + av_pair(0x0006, struct.pack('<I', 0x00000002))   # MsvAvFlags (MIC present)
            + struct.pack('<HH', 0, 0)                         # MsvAvEOL
        )

        # target_name = server NetBIOS name (TARGET_TYPE_SERVER)
        target_name = hostname

        # Flags matching a typical Windows Server 2019 NTLM challenge
        flags = (
            0x00000001 |   # NTLMSSP_NEGOTIATE_UNICODE
            0x00000004 |   # NTLMSSP_REQUEST_TARGET
            0x00000010 |   # NTLMSSP_NEGOTIATE_SIGN
            0x00000020 |   # NTLMSSP_NEGOTIATE_SEAL
            0x00000200 |   # NTLMSSP_NEGOTIATE_NTLM
            0x00008000 |   # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            0x00020000 |   # NTLMSSP_TARGET_TYPE_SERVER
            0x00080000 |   # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            0x00800000 |   # NTLMSSP_NEGOTIATE_TARGET_INFO
            0x02000000 |   # NTLMSSP_NEGOTIATE_VERSION
            0x20000000 |   # NTLMSSP_NEGOTIATE_128
            0x40000000 |   # NTLMSSP_NEGOTIATE_KEY_EXCH
            0x80000000     # NTLMSSP_NEGOTIATE_56
        )

        # Fixed header is always 56 bytes (incl. Version)
        target_name_offset = 56
        target_info_offset = target_name_offset + len(target_name)

        # Version: Windows Server 2019 (10.0 build 17763), NTLMRevisionCurrent=0x0f
        major, minor, build = self.os_version
        version = struct.pack('<BBHBBBB', major, minor, build, 0, 0, 0, 0x0f)

        return (
            b'NTLMSSP\x00'
            + struct.pack('<I', 2)
            + struct.pack('<HHI', len(target_name), len(target_name), target_name_offset)
            + struct.pack('<I', flags)
            + self.ntlm_challenge
            + b'\x00' * 8  # Reserved
            + struct.pack('<HHI', len(target_info), len(target_info), target_info_offset)
            + version
            + target_name
            + target_info
        )

    def _build_spnego_neg_token_resp(self, ntlm_msg):
        """Wrap an NTLM message in a SPNEGO NegTokenResp."""
        tlv = self._asn1_tlv
        ntlmssp_oid = b'\x06\x09\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'

        neg_state      = tlv(0xa0, tlv(0x0a, b'\x01'))          # [0] accept-incomplete
        supported_mech = tlv(0xa1, ntlmssp_oid)                  # [1] NTLMSSP OID
        response_token = tlv(0xa2, tlv(0x04, ntlm_msg))          # [2] OCTET STRING

        seq = tlv(0x30, neg_state + supported_mech + response_token)
        return tlv(0xa1, seq)  # [1] NegTokenResp

    def _wrap_credssp_token(self, token):
        """Wrap a token (SPNEGO or raw NTLM) in a CredSSP TSRequest."""
        tlv = self._asn1_tlv

        # NegoToken ::= SEQUENCE { negoToken [0] OCTET STRING }
        negotoken   = tlv(0x30, tlv(0xa0, tlv(0x04, token)))
        # NegoData  ::= SEQUENCE OF NegoToken
        nego_data   = tlv(0x30, negotoken)

        version     = tlv(0xa0, tlv(0x02, b'\x06'))  # [0] INTEGER 6
        nego_tokens = tlv(0xa1, nego_data)             # [1] NegoData

        return tlv(0x30, version + nego_tokens)        # TSRequest SEQUENCE

    def _wrap_credssp(self, ntlm_msg):
        """Wrap an NTLM message in a SPNEGO NegTokenResp inside a CredSSP TSRequest."""
        return self._wrap_credssp_token(self._build_spnego_neg_token_resp(ntlm_msg))

    def _parse_ntlm_type3(self, ntlm_data):
        """Extract credentials from an NTLM Type 3 (Authenticate) message."""
        try:
            if ntlm_data[:8] != b'NTLMSSP\x00':
                return None
            if struct.unpack('<I', ntlm_data[8:12])[0] != 3:
                return None

            nt_len,  _, nt_off  = struct.unpack('<HHI', ntlm_data[20:28])
            dom_len, _, dom_off = struct.unpack('<HHI', ntlm_data[28:36])
            usr_len, _, usr_off = struct.unpack('<HHI', ntlm_data[36:44])

            domain   = ntlm_data[dom_off:dom_off + dom_len].decode('utf-16-le', errors='ignore')
            username = ntlm_data[usr_off:usr_off + usr_len].decode('utf-16-le', errors='ignore')
            nt_resp  = ntlm_data[nt_off:nt_off + nt_len]

            # NetNTLMv2 hash format (hashcat mode 5600)
            ntlm_hash = None
            if nt_len > 24:
                ntlm_hash = (
                    f"{username}::{domain}:{self.ntlm_challenge.hex()}"
                    f":{nt_resp[:16].hex()}:{nt_resp[16:].hex()}"
                )

            return {'username': username, 'domain': domain, 'ntlm_hash': ntlm_hash}
        except Exception:
            return None

    def _build_credssp_error(self, error_code):
        """Build a CredSSP TSRequest carrying an errorCode (early user auth result).
        Allows clients to exit cleanly instead of getting an abrupt transport error.
        Use 0xC000006D (NTSTATUS STATUS_LOGON_FAILURE) to mimic a real Windows server.
        """
        tlv = self._asn1_tlv
        # NTSTATUS codes have the high bit set (e.g. 0xC000006D), which would require
        # 5 bytes as an unsigned DER INTEGER. xfreerdp's ASN.1 parser only handles
        # up to 4 bytes, so encode as signed 32-bit two's complement instead —
        # this matches what a real Windows server sends.
        signed = error_code if error_code < 0x80000000 else error_code - 0x100000000
        ec_bytes = signed.to_bytes(4, byteorder='big', signed=True)
        version    = tlv(0xa0, tlv(0x02, b'\x06'))    # [0] INTEGER 6
        error      = tlv(0xa4, tlv(0x02, ec_bytes))   # [4] INTEGER errorCode
        return tlv(0x30, version + error)

    def _handle_nla(self, data):
        # CredSSP/SPNEGO wraps NTLM; locate the NTLMSSP signature within the blob
        idx = data.find(b'NTLMSSP\x00')
        if idx == -1 or len(data) - idx < 12:
            self.transport.close()
            return

        ntlm_data = data[idx:]
        msg_type = struct.unpack('<I', ntlm_data[8:12])[0]

        if msg_type == 1:
            # NTLM Negotiate → send Challenge
            # Detect whether the client wrapped NTLM in SPNEGO (NEGOTIATE package) or
            # sent raw NTLM (NTLM package directly, e.g. xfreerdp with WinPR SSPI).
            # The SPNEGO OID 1.3.6.1.5.5.2 appears before the NTLMSSP signature
            # when SPNEGO is used.
            _SPNEGO_OID = b'\x06\x06\x2b\x06\x01\x05\x05\x02'
            is_spnego = _SPNEGO_OID in data[:idx]

            challenge = self._build_ntlm_challenge()
            if is_spnego:
                self.transport.write(self._wrap_credssp(challenge))
            else:
                # Raw NTLM: put the challenge directly into the negoToken OCTET STRING
                self.transport.write(self._wrap_credssp_token(challenge))

        elif msg_type == 3:
            # NTLM Authenticate → extract and log credentials
            creds = self._parse_ntlm_type3(ntlm_data)
            if creds and creds.get('ntlm_hash'):
                self.logger.log(
                    self.protocol_name + '.' + self.logger.LOGIN,
                    self.transport,
                    extra={
                        'username': f"{creds['domain']}\\{creds['username']}",
                        'password': creds['ntlm_hash'],
                    },
                )
            # Reply with a CredSSP wrong-password error (NTSTATUS STATUS_LOGON_FAILURE).
            # Without this, xfreerdp gets an abrupt EOF while waiting for
            # the server's pubKeyAuth and reports ERRCONNECT_CONNECT_TRANSPORT_FAILED.
            # 0xC000006D is what a real Windows server returns for bad credentials.
            self.transport.write(self._build_credssp_error(0xC000006D))
            self.transport.close()

        else:
            self.transport.close()


class RdpHoneypot(BaseHoneypot):
    service_name = "rdp"

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)

        self.key_path  = Path(config.get("key",         "trapster/data/ssl/rdp/key.pem"))
        self.cert_path = Path(config.get("certificate", "trapster/data/ssl/rdp/certificate.pem"))
        self.generate_certificate(config)

        config["key_path"]  = str(self.key_path)
        config["cert_path"] = str(self.cert_path)

        self.handler = lambda: RdpProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config

    def generate_certificate(self, config):
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.cert_path.parent.mkdir(parents=True, exist_ok=True)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, config.get('ntlm_hostname', 'WIN-RDP')),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        with open(self.cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
