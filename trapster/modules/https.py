from trapster.modules.http import HttpHandler, HttpHoneypot, HeaderCapitalizationMiddleware

import asyncio
from fastapi import Request
from pathlib import Path
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID


def _has_content(path):
    """True when *path* is an existing file with data (empty files don't count)."""
    return path.is_file() and path.stat().st_size > 0


class HttpsHandler(HttpHandler):
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.protocol_name = "https"

class HttpsHoneypot(HttpHoneypot):
    """common class to all trapster instance"""
    service_name = "https"

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = HttpsHandler(config=config, logger=logger)
        self.COUNTRY_NAME = config.get("country_name") or None
        self.STATE_OR_PROVINCE_NAME = config.get("state_or_province_name") or None
        self.LOCALITY_NAME = config.get("locality_name") or None
        self.ORGANIZATION_NAME = config.get("organization_name") or None
        self.COMMON_NAME = config.get("common_name") or "server.internal"
        self.NOT_VALID_BEFORE = config.get("not_valid_before")
        self.NOT_VALID_AFTER = config.get("not_valid_after")

        self.key_path = Path(config.get("key") or "trapster/data/ssl/https/key.pem")
        self.certificate_path = Path(config.get("certificate") or "trapster/data/ssl/https/certificate.pem")

        self.generate_certificate()
    
    async def _start_server(self):
        # TLS via Hypercorn. http_version: "2" enables ALPN h2 (falling back to
        # http/1.1); otherwise http/1.1 only. The per-request middleware adapts
        # casing/Date to whichever protocol the client negotiates.
        config = self._hypercorn_config()
        config.certfile = str(self.certificate_path)
        config.keyfile = str(self.key_path)
        config.alpn_protocols = ["h2", "http/1.1"] if self.handler.http2 else ["http/1.1"]
        return await self._serve_hypercorn(config)

    def generate_certificate(self):
        '''
        Use the configured key/certificate files when both already exist.
        Otherwise generate a self-signed pair (and write it to those paths).
        '''
        if _has_content(self.key_path) and _has_content(self.certificate_path):
            return

        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.certificate_path.parent.mkdir(parents=True, exist_ok=True)

        key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()        
        ))

        name_attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.COUNTRY_NAME) if self.COUNTRY_NAME else None,
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.STATE_OR_PROVINCE_NAME) if self.STATE_OR_PROVINCE_NAME else None,
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.LOCALITY_NAME) if self.LOCALITY_NAME else None,
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.ORGANIZATION_NAME) if self.ORGANIZATION_NAME else None,
            x509.NameAttribute(NameOID.COMMON_NAME, self.COMMON_NAME),
        ]
        subject = issuer = x509.Name(filter(None, name_attributes))

        alt_names = x509.SubjectAlternativeName([x509.DNSName('localhost'),])

        certification = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.fromisoformat(self.NOT_VALID_BEFORE) if self.NOT_VALID_BEFORE else datetime.datetime.now())
            .not_valid_after(datetime.datetime.fromisoformat(self.NOT_VALID_AFTER) if self.NOT_VALID_AFTER else datetime.datetime.now() + datetime.timedelta(days=3650))
            .add_extension(alt_names, False)
            .sign(key, hashes.SHA256(), default_backend())
        )

        with open(self.certificate_path, "wb") as f:
            f.write(certification.public_bytes(serialization.Encoding.PEM))
