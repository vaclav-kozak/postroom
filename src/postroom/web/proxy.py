"""The real client address behind a reverse proxy, without trusting spoofable headers.

`postroom serve` turns uvicorn's own proxy-header handling off; this middleware decides instead,
so one setting (`POSTROOM_TRUSTED_PROXIES`) governs both the ASGI client address (used by the
auth rate limit) and the `X-Real-IP` header (used by the login lockout).

- The peer is a trusted proxy: the client is the right-most `X-Forwarded-For` entry that is not
  itself a trusted proxy (entries further left are client-supplied and ignored); without
  `X-Forwarded-For`, `X-Real-IP`; failing both, the peer. `X-Forwarded-Proto` sets the scheme.
- Any other peer: the forwarding headers are dropped, so a client that reaches the server
  directly cannot claim another address.

Afterwards `scope["client"]` and a single `X-Real-IP` header both carry the resolved address.
Pure ASGI middleware: it never buffers, so streaming MCP responses are unaffected.
"""

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

from starlette.types import ASGIApp, Receive, Scope, Send

type IPAddress = IPv4Address | IPv6Address
type IPNetwork = IPv4Network | IPv6Network

FORWARDING_HEADERS = frozenset(
    {b"x-forwarded-for", b"x-real-ip", b"x-forwarded-proto", b"x-forwarded-host", b"forwarded"}
)


def parse_ip(value: str) -> IPAddress | None:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        ip = ip_address(value)
    except ValueError:
        return None
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


class ClientAddressMiddleware:
    def __init__(self, app: ASGIApp, trusted_proxies: Iterable[IPNetwork]):
        self.app = app
        self.trusted = tuple(trusted_proxies)

    def _is_trusted(self, ip: IPAddress) -> bool:
        return any(ip in net for net in self.trusted)

    def _forwarded_client(self, headers: list[tuple[bytes, bytes]]) -> IPAddress | None:
        xff = ",".join(v.decode("latin-1") for k, v in headers if k == b"x-forwarded-for")
        entries = [e for e in (e.strip() for e in xff.split(",")) if e]
        if entries:
            for entry in reversed(entries):
                ip = parse_ip(entry)
                if ip is None:
                    return None  # a trusted proxy passed garbage: fall back to the peer
                if not self._is_trusted(ip):
                    return ip
            return parse_ip(entries[0])  # every hop is a trusted proxy
        real = [v.decode("latin-1") for k, v in headers if k == b"x-real-ip"]
        return parse_ip(real[-1]) if real else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])
        peer = scope.get("client")
        peer_ip = parse_ip(peer[0]) if peer else None
        client = str(peer_ip) if peer_ip is not None else (peer[0] if peer else None)
        scheme = scope.get("scheme")

        if peer_ip is not None and self._is_trusted(peer_ip):
            forwarded = self._forwarded_client(headers)
            if forwarded is not None:
                client = str(forwarded)
            protos = [v.decode("latin-1") for k, v in headers if k == b"x-forwarded-proto"]
            proto = protos[-1].split(",")[-1].strip().lower() if protos else ""
            if scope["type"] == "http" and proto in ("http", "https"):
                scheme = proto

        new_headers = [(k, v) for k, v in headers if k not in FORWARDING_HEADERS]
        if client:
            new_headers.append((b"x-real-ip", client.encode("latin-1", "replace")))
        scope = dict(scope)
        scope["headers"] = new_headers
        if client:
            scope["client"] = (client, peer[1] if peer else 0)
        if scheme:
            scope["scheme"] = scheme
        await self.app(scope, receive, send)
