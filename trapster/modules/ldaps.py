import asyncio
import datetime
import logging
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from trapster.modules.ldap import LdapHoneypot, LdapProtocol


def _has_content(path):
    """True when *path* is an existing file with data (empty files don't count)."""
    return path.is_file() and path.stat().st_size > 0


class LdapsProtocol(LdapProtocol):
    def __init__(self, config=None):
        super().__init__(config=config)
        self.protocol_name = "ldaps"


class LdapsHoneypot(LdapHoneypot):
    service_name = "ldaps"

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: LdapsProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config

        self.key_path  = Path(config.get("key")         or "trapster/data/ssl/ldaps/key.pem")
        self.cert_path = Path(config.get("certificate") or "trapster/data/ssl/ldaps/certificate.pem")

        cn = f"{config.get('hostname', 'DC01')}.{config.get('domain', 'corp.local')}"
        self.generate_certificate(cn)

    def generate_certificate(self, cn):
        '''
        Use the configured key/certificate files when both already exist.
        Otherwise generate a self-signed pair (and write it to those paths).
        '''
        if _has_content(self.key_path) and _has_content(self.cert_path):
            return

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
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        with open(self.cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    async def _start_server(self):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        loop = asyncio.get_running_loop()
        try:
            self.server = await loop.create_server(
                self.handler, host=self.bindaddr, port=self.port, ssl=ssl_ctx
            )
            await self.server.serve_forever()
        except asyncio.CancelledError:
            raise
        except OSError as e:
            self._log_bind_error(e)
            return False
        except Exception as e:
            logging.error(e)
            return False
