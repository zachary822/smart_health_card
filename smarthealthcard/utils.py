from smarthealthcard import SmartHealthCard
from typing import Iterable
from math import ceil

MAX_CHUNK_SIZE = 1191


class SmartHealthCardURI:
    def __init__(self, shc: SmartHealthCard):
        self.shc = shc

    def _to_uri(self):
        return "".join(format(ord(s) - 45, "02") for s in str(self.shc))

    def __str__(self):
        return f"shc:/{self._to_uri()}"

    def iterchunks(self, chunks: int = None) -> Iterable[str]:
        uri = self._to_uri()

        if chunks is None:
            chunks = ceil(len(uri) / MAX_CHUNK_SIZE)

        chunk_size = ceil(len(uri) / chunks)

        for i in range(0, chunks):
            yield f"shc:/{i + 1}/{chunks}/{uri[i * chunk_size: (i + 1) * chunk_size]}"
