"""Read-only Linux listening-socket inventory for BIOAEGIS."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Listener:
    protocol: str
    address: str
    port: int
    state: str


class NetworkScanner:
    """Read /proc socket tables; never opens, closes, or probes sockets."""

    TABLES = (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"), ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6"))

    def scan(self) -> list[Listener]:
        listeners: list[Listener] = []
        for protocol, filename in self.TABLES:
            listeners.extend(self._read_table(protocol, Path(filename)))
        return listeners

    def _read_table(self, protocol: str, path: Path) -> list[Listener]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[1:]
        except (OSError, PermissionError):
            return []
        results: list[Listener] = []
        for line in lines:
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[1]
            state = fields[3]
            if protocol.startswith("tcp") and state != "0A":
                continue
            try:
                address_hex, port_hex = local.rsplit(":", 1)
                port = int(port_hex, 16)
                address = self._decode_address(address_hex, protocol.endswith("6"))
            except ValueError:
                continue
            results.append(Listener(protocol, address, port, state))
        return results

    @staticmethod
    def _decode_address(value: str, ipv6: bool) -> str:
        raw = bytes.fromhex(value)
        if ipv6:
            if len(raw) != 16:
                raise ValueError("invalid IPv6 address length")
            raw = b"".join(raw[offset : offset + 4][::-1] for offset in range(0, 16, 4))
            return socket.inet_ntop(socket.AF_INET6, raw)
        if len(raw) != 4:
            raise ValueError("invalid IPv4 address length")
        return socket.inet_ntoa(raw[::-1])
