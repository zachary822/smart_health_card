import json
import zlib
from abc import ABC, abstractmethod
from base64 import urlsafe_b64encode
from hashlib import sha256
from operator import attrgetter, methodcaller
from typing import TypedDict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

json_encoder = json.JSONEncoder(separators=(",", ":"), sort_keys=True)


class ThumbPrintDict(TypedDict):
    crv: str
    kty: str
    x: str
    y: str


class JWKABC(ABC):
    @property
    @abstractmethod
    def payload(self) -> ThumbPrintDict:
        pass

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def thumbprint(self) -> bytes:
        pass

    @abstractmethod
    def export(self) -> dict:
        pass


class JWK(JWKABC):
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self.private_key = private_key

    @property
    def payload(self) -> ThumbPrintDict:
        x, y = map(
            methodcaller("decode", "utf-8"),
            map(
                urlsafe_b64encode,
                map(
                    methodcaller("to_bytes", 32, "big"),
                    attrgetter("x", "y")(
                        self.private_key.public_key().public_numbers()
                    ),
                ),
            ),
        )

        return {
            "crv": "P-256",
            "kty": "EC",
            "x": x,
            "y": y,
        }

    def export(self):
        return {
            **self.payload,
            "kid": self.thumbprint(),
            "use": "sig",
            "alg": "ES256",
        }

    def thumbprint(self) -> str:
        h = sha256()
        h.update(json_encoder.encode(self.payload).encode())
        return urlsafe_b64encode(h.digest()).decode("utf-8")

    def sign(self, data: bytes) -> bytes:
        return b"".join(
            map(
                methodcaller("to_bytes", 32, "big"),
                decode_dss_signature(
                    self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
                ),
            )
        )

    def verify(self, signature: bytes, data: bytes):
        self.private_key.public_key().verify(signature, data, ec.ECDSA(hashes.SHA256()))


class SmartHealthCard:
    def __init__(self, payload, jwk: JWKABC):
        self.payload = payload
        self.jwk = jwk

    @property
    def header(self):
        return {
            "alg": "ES256",
            "zip": "DEF",
            "typ": "JWT",
            "kid": self.jwk.thumbprint(),
        }

    @staticmethod
    def _b64encode(s: bytes):
        return urlsafe_b64encode(s).rstrip(b"=")

    def _compressed_payload(self) -> bytes:
        compress = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        compressed_payload = compress.compress(
            json_encoder.encode(self.payload).encode("utf-8")
        )
        compressed_payload += compress.flush()

        return compressed_payload

    def _body(self) -> bytes:
        return (
            self._b64encode(json_encoder.encode(self.header).encode("utf-8"))
            + b"."
            + self._b64encode(self._compressed_payload())
        )

    def _signature(self) -> bytes:
        return self._b64encode(self.jwk.sign(self._body()))

    def __bytes__(self):
        return self._body() + b"." + self._signature()

    def __str__(self):
        return self.__bytes__().decode("utf-8")
