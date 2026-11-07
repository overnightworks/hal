"""What a network namespace can reach and what listens in it, as plain observations.

The one owner of these observations: `probe/agent-service/litellm_stack.py` (its `Client`)
imports it and sends its source to `python -I -` inside the container, so it needs nothing but
the standard library of the service image. It judges nothing; the probe keeps its own verdicts.
`lan_address` runs on the host only.
"""

import errno
import socket

PUBLIC_RESOLVER = "1.1.1.1"  # NOSONAR(S1313) a deliberate unreachable target for E6
PUBLIC_RESOLVER_V6 = "2606:4700:4700::1111"  # NOSONAR(S1313) a deliberate unreachable target for E8
# What `tcp_connect` answers for an address with no route to it.
UNREACHABLE = ("ENETUNREACH", "EHOSTUNREACH", "EADDRNOTAVAIL")


def tcp_connect(address, port):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as attempt:
        attempt.settimeout(8)  # an address nobody owns answers after the ARP retries, ~3 s
        code = attempt.connect_ex((address, int(port)))
    return {"result": "connected" if code == 0 else errno.errorcode.get(code, str(code))}


def udp_connect(address, port):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as attempt:
        try:
            attempt.connect((address, int(port)))
        except OSError as error:
            return {"result": errno.errorcode.get(error.errno or 0, str(error.errno))}
    return {"result": "routable"}


def default_routes():
    with open("/proc/net/route") as table:
        rows = [line.split() for line in table.read().splitlines()[1:]]
    return {"default_routes": [row[0] for row in rows if row[1] == "00000000"]}


def ipv6_interfaces():
    try:
        with open("/proc/net/if_inet6") as table:
            return {"interfaces": sorted({line.split()[-1] for line in table if line.strip()})}
    except FileNotFoundError:
        return {"interfaces": []}


def resolve_name(name):
    try:
        found = socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as error:
        return {"addresses": [], "error": errno.errorcode.get(error.errno or 0, str(error))}
    return {"addresses": sorted({entry[4][0] for entry in found})}


def listening_sockets():
    found = {"tcp": [], "udp": []}
    for protocol in ("tcp", "udp"):
        for table, version in ((protocol, 4), (protocol + "6", 6)):
            with open(f"/proc/net/{table}") as sockets:
                rows = [line.split() for line in sockets.read().splitlines()[1:]]
            for row in rows:
                if protocol == "udp" or row[3] == "0A":
                    found[protocol].append(socket_name(row[1], version))
    return found


def socket_name(hexadecimal, version):
    address, port = hexadecimal.split(":")
    if version == 4:
        return f"{socket.inet_ntoa(bytes.fromhex(address)[::-1])}:{int(port, 16)}"
    words = [bytes.fromhex(address[at : at + 8])[::-1] for at in range(0, 32, 8)]
    return f"[{socket.inet_ntop(socket.AF_INET6, b''.join(words))}]:{int(port, 16)}"


def lan_address():
    """The address the host would use to reach the internet; a UDP connect sends nothing."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((PUBLIC_RESOLVER, 53))
        return route.getsockname()[0]
