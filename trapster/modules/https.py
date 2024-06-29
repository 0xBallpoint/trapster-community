from .http import HttpProtocol
from .base import BaseHoneypot

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pathlib import Path
import ssl
import datetime
import os
import asyncio

class HttpsProtocol(HttpProtocol):
    def __init__(self, config=None, event_loop=None, timeout=10):
        super().__init__(config, event_loop, timeout)
        self.protocol_name = "https"

class HttpsHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: HttpsProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config

        self.COUNTRY_NAME = config.get("country_name", "FR")
        self.STATE_OR_PROVINCE_NAME = config.get("state_or_province_name", "Paris")
        self.LOCALITY_NAME = config.get("locality_name", "Paris")
        self.ORGANIZATION_NAME = config.get("organization_name", "organisatio")
        self.COMMON_NAME = config.get("common_name", "www.organization.org")
        
        self.key_path = Path(config.get("key", "/etc/trapster/ssl/key.pem"))
        self.certificate_path = Path(config.get("certificate", "/etc/trapster/ssl/certificate.pem"))

        self.generate_certificate()
    
    async def _start_server(self):
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.certificate_path, keyfile=self.key_path)

        loop = asyncio.get_running_loop()
        try:
            self.server = await loop.create_server(self.handler, host=self.bindaddr, port=self.port, ssl=ssl_context)
            await self.server.serve_forever()
        except OSError as e:
            if e.errno == self.port:
                print("port already in use")
                print(e)
        except asyncio.CancelledError:
            raise

    def generate_certificate(self):
        if self.certificate_path.exists() and self.key_path.exists():
            return
        else:
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

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.COUNTRY_NAME),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.STATE_OR_PROVINCE_NAME),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.LOCALITY_NAME),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.ORGANIZATION_NAME),
                x509.NameAttribute(NameOID.COMMON_NAME, self.COMMON_NAME),
            ])

            alt_names = x509.SubjectAlternativeName([x509.DNSName("172.20.10.2"),
                                                    x509.DNSName("127.0.0.1")
            ])
            certification = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now())
                .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=90))
                .add_extension(alt_names, False)
                .sign(key, hashes.SHA256(), default_backend())
            )

            with open(self.certificate_path, "wb") as f:
                f.write(certification.public_bytes(serialization.Encoding.PEM))
