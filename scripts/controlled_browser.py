"""Controlled, tunnel-pinned host Chromium launcher for Claude Docker accounts.

Routes all browser TCP/DNS traffic into the account's `proxy` container loopback
SOCKS5/mixed listener (`127.0.0.1:10800` -> `PROXY_URI`, pinned to `EXPECTED_EXIT_IP`)
over an unexposed `docker exec -i` multiplexed stream, while isolating cookies/state
per account and optionally bridging `localhost` OAuth callbacks into `claude`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit


BROWSER_CONTAINER_PORT = 10800
MUX_MAGIC = b"CDMX"
MUX_HEADER = struct.Struct("!4sBIH")
MAX_MUX_CHUNK = 32768

CMD_OPEN = 1
CMD_DATA = 2
CMD_EOF = 3
CMD_CLOSE = 4
CMD_PING = 5
CMD_PONG = 6
CMD_OPEN_OK = 7
CMD_OPEN_ERR = 8

BOGON_AND_PRIVATE_CIDRS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

LOCAL_SPECIAL_TLDS = (".localhost", ".local", ".internal", ".home.arpa")

PROXY_ENV_STRIP_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SOCKS_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "socks_proxy",
)

CONTAINER_MUX_SCRIPT = r"""
import os
import queue
import socket
import struct
import sys
import threading

MAGIC = b"CDMX"
HEADER = struct.Struct("!4sBIH")
MAX_CHUNK = 32768

CMD_OPEN = 1
CMD_DATA = 2
CMD_EOF = 3
CMD_CLOSE = 4
CMD_PING = 5
CMD_PONG = 6
CMD_OPEN_OK = 7
CMD_OPEN_ERR = 8


def parse_port_spec(spec: str):
    ranges = []
    exact = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            ranges.append((lo, hi))
        else:
            exact.add(int(part))

    def allowed(port: int) -> bool:
        if port < 1 or port > 65535:
            return False
        if port in exact:
            return True
        return any(lo <= port <= hi for lo, hi in ranges)

    return allowed


is_allowed = parse_port_spec(sys.argv[1])
in_fd = 0
out_fd = 1
write_lock = threading.Lock()
streams = {}
streams_lock = threading.Lock()
alive = True


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    sent = 0
    total = len(data)
    while sent < total:
        n = os.write(fd, view[sent:])
        if n <= 0:
            raise OSError("short write on mux stdout")
        sent += n


def send_frame(cmd: int, sid: int, payload: bytes = b"") -> bool:
    global alive
    if not alive:
        return False
    frame = HEADER.pack(MAGIC, cmd, sid, len(payload)) + payload
    with write_lock:
        try:
            write_all(out_fd, frame)
            return True
        except OSError:
            alive = False
            return False


def read_exact(fd: int, length: int):
    buf = bytearray()
    while len(buf) < length:
        chunk = os.read(fd, length - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def handle_stream(sid: int, port: int, rx_q: "queue.Queue[tuple[int, bytes]]") -> None:
    if not is_allowed(port):
        with streams_lock:
            streams.pop(sid, None)
        send_frame(CMD_OPEN_ERR, sid, b"denied")
        return

    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(None)
    except OSError:
        with streams_lock:
            streams.pop(sid, None)
        send_frame(CMD_OPEN_ERR, sid, b"refused")
        return

    if not send_frame(CMD_OPEN_OK, sid):
        sock.close()
        return

    def abort_sock() -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def pump_in_to_sock() -> None:
        try:
            while True:
                cmd, data = rx_q.get()
                if cmd == CMD_DATA:
                    sock.sendall(data)
                elif cmd == CMD_EOF:
                    try:
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    break
                elif cmd == CMD_CLOSE:
                    abort_sock()
                    break
        except OSError:
            abort_sock()

    writer = threading.Thread(target=pump_in_to_sock, daemon=True)
    writer.start()

    try:
        while True:
            chunk = sock.recv(MAX_CHUNK)
            if not chunk:
                send_frame(CMD_EOF, sid)
                break
            if not send_frame(CMD_DATA, sid, chunk):
                abort_sock()
                break
    except OSError:
        send_frame(CMD_CLOSE, sid)
        rx_q.put((CMD_CLOSE, b""))
    finally:
        writer.join(timeout=5.0)
        with streams_lock:
            streams.pop(sid, None)
        try:
            sock.close()
        except OSError:
            pass


def main() -> None:
    global alive
    try:
        while alive:
            raw_hdr = read_exact(in_fd, HEADER.size)
            if raw_hdr is None:
                break
            magic, cmd, sid, length = HEADER.unpack(raw_hdr)
            if magic != MAGIC or length > MAX_CHUNK:
                break
            payload = read_exact(in_fd, length) if length else b""
            if payload is None:
                break
            if cmd == CMD_PING:
                send_frame(CMD_PONG, sid, payload)
            elif cmd == CMD_OPEN:
                if len(payload) != 2:
                    send_frame(CMD_OPEN_ERR, sid, b"bad_open")
                    continue
                (port,) = struct.unpack("!H", payload)
                rx_q: "queue.Queue[tuple[int, bytes]]" = queue.Queue()
                with streams_lock:
                    streams[sid] = rx_q
                threading.Thread(target=handle_stream, args=(sid, port, rx_q), daemon=True).start()
            elif cmd in (CMD_DATA, CMD_EOF, CMD_CLOSE):
                with streams_lock:
                    rx_q = streams.get(sid)
                    if cmd == CMD_CLOSE and rx_q is not None:
                        streams.pop(sid, None)
                if rx_q is not None:
                    rx_q.put((cmd, payload))
    finally:
        alive = False
        with streams_lock:
            active = list(streams.values())
            streams.clear()
        for rx_q in active:
            rx_q.put((CMD_CLOSE, b""))


if __name__ == "__main__":
    main()
"""


class BrowserError(RuntimeError):
    pass


@dataclass(frozen=True)
class BrowserOptions:
    check_only: bool = False
    claude_localhost: bool = True
    oauth_ports: tuple[int, ...] = ()
    browser_override: str = ""
    reset_profile: bool = False
    start_url: str = "about:blank"


class MuxStream:
    def __init__(self, mux: ContainerLoopbackMux, sid: int) -> None:
        self._mux = mux
        self.sid = sid
        self.open_event = threading.Event()
        self.open_ok = False
        self.rx_queue: queue.Queue[tuple[int, bytes]] = queue.Queue()
        self._closed = False
        self._lock = threading.Lock()

    def send_data(self, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(data):
            chunk = bytes(view[offset : offset + MAX_MUX_CHUNK])
            if not self._mux.send_frame(CMD_DATA, self.sid, chunk):
                raise ConnectionError("mux channel closed")
            offset += len(chunk)

    def send_eof(self) -> None:
        self._mux.send_frame(CMD_EOF, self.sid)

    def abort(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._mux.drop_stream(self.sid)
        self._mux.send_frame(CMD_CLOSE, self.sid)
        self.rx_queue.put((CMD_CLOSE, b""))

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._mux.drop_stream(self.sid)
        self._mux.send_frame(CMD_CLOSE, self.sid)


class ContainerLoopbackMux:
    """Multiplexed binary TCP tunnel into a container's 127.0.0.1 over a single `docker exec -i`."""

    def __init__(self, label: str, exec_command: list[str]) -> None:
        self.label = label
        self._exec_command = exec_command
        self._proc: subprocess.Popen[bytes] | None = None
        self._write_lock = threading.Lock()
        self._streams_lock = threading.Lock()
        self._streams: dict[int, MuxStream] = {}
        self._next_sid = 1
        self._pong_event = threading.Event()
        self._alive = False

    def start(self, timeout: float = 10.0) -> None:
        try:
            self._proc = subprocess.Popen(
                self._exec_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except FileNotFoundError as exc:
            raise BrowserError(f"找不到命令: {self._exec_command[0]}") from exc

        self._alive = True
        threading.Thread(target=self._reader_loop, daemon=True).start()
        if not self.send_frame(CMD_PING, 0, b"ready"):
            self.close()
            raise BrowserError(f"无法初始化 {self.label} 隧道管道")
        if not self._pong_event.wait(timeout=timeout) or not self._alive:
            stderr_text = ""
            if self._proc and self._proc.stderr:
                try:
                    if self._proc.poll() is not None:
                        stderr_text = self._proc.stderr.read().decode("utf-8", errors="replace").strip()
                except OSError:
                    pass
            self.close()
            detail = f": {stderr_text}" if stderr_text else ""
            raise BrowserError(f"{self.label} 隧道握手超时或异常退出{detail}")

    def is_alive(self) -> bool:
        return self._alive and self._proc is not None and self._proc.poll() is None

    def send_frame(self, cmd: int, sid: int, payload: bytes = b"") -> bool:
        if not self._alive or self._proc is None or self._proc.stdin is None:
            return False
        frame = MUX_HEADER.pack(MUX_MAGIC, cmd, sid, len(payload)) + payload
        with self._write_lock:
            try:
                self._proc.stdin.write(frame)
                self._proc.stdin.flush()
                return True
            except OSError:
                self._alive = False
                return False

    def drop_stream(self, sid: int) -> None:
        with self._streams_lock:
            self._streams.pop(sid, None)

    def open_stream(self, port: int, timeout: float = 8.0) -> MuxStream:
        if not self.is_alive():
            raise ConnectionError(f"{self.label} 隧道已断开")
        with self._streams_lock:
            sid = self._next_sid
            self._next_sid = 1 if self._next_sid >= 0x7FFFFFFF else self._next_sid + 1
            stream = MuxStream(self, sid)
            self._streams[sid] = stream
        if not self.send_frame(CMD_OPEN, sid, struct.pack("!H", port)):
            self.drop_stream(sid)
            raise ConnectionError(f"{self.label} 隧道发送失败")
        if not stream.open_event.wait(timeout=timeout) or not stream.open_ok:
            self.drop_stream(sid)
            raise ConnectionRefusedError(f"{self.label} 拒绝连接端口 127.0.0.1:{port}")
        return stream

    def _read_exact(self, length: int) -> bytes | None:
        assert self._proc is not None and self._proc.stdout is not None
        buf = bytearray()
        while len(buf) < length:
            chunk = self._proc.stdout.read(length - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _reader_loop(self) -> None:
        try:
            while self._alive:
                raw_hdr = self._read_exact(MUX_HEADER.size)
                if raw_hdr is None:
                    break
                magic, cmd, sid, length = MUX_HEADER.unpack(raw_hdr)
                if magic != MUX_MAGIC or length > MAX_MUX_CHUNK:
                    break
                payload = self._read_exact(length) if length else b""
                if payload is None:
                    break
                if cmd == CMD_PONG:
                    self._pong_event.set()
                    continue
                with self._streams_lock:
                    stream = self._streams.get(sid)
                    if cmd in (CMD_OPEN_ERR, CMD_CLOSE) and stream is not None:
                        self._streams.pop(sid, None)
                if stream is None:
                    continue
                if cmd == CMD_OPEN_OK:
                    stream.open_ok = True
                    stream.open_event.set()
                elif cmd == CMD_OPEN_ERR:
                    stream.open_ok = False
                    stream.open_event.set()
                elif cmd in (CMD_DATA, CMD_EOF, CMD_CLOSE):
                    stream.rx_queue.put((cmd, payload))
        except OSError:
            pass
        finally:
            self._alive = False
            self._pong_event.set()
            with self._streams_lock:
                pending = list(self._streams.values())
                self._streams.clear()
            for stream in pending:
                stream.open_event.set()
                stream.rx_queue.put((CMD_CLOSE, b""))

    def close(self) -> None:
        self._alive = False
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        if proc.stdin:
            try:
                proc.stdin.close()
            except OSError:
                pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("unexpected EOF during SOCKS5 handshake")
        buf.extend(chunk)
    return bytes(buf)


class ControlledSocksServer:
    """Host loopback SOCKS5 server enforcing proxy-only egress and container-only OAuth callbacks."""

    def __init__(
        self,
        *,
        proxy_mux: ContainerLoopbackMux,
        claude_mux: ContainerLoopbackMux | None,
        claude_port_allowed: Callable[[int], bool],
        blocked_networks: tuple[ipaddress.IPv4Network, ...],
    ) -> None:
        self._proxy_mux = proxy_mux
        self._claude_mux = claude_mux
        self._claude_port_allowed = claude_port_allowed
        self._blocked_networks = blocked_networks
        self._server_sock: socket.socket | None = None
        self._active_sockets: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._closed = False
        self.port = 0

    def start(self) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        host, port = srv.getsockname()
        if host != "127.0.0.1":
            srv.close()
            raise BrowserError(f"本地代理监听地址异常: {host}")
        srv.listen(128)
        self._server_sock = srv
        self.port = int(port)
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self.port

    def _accept_loop(self) -> None:
        assert self._server_sock is not None
        while not self._closed:
            try:
                client_sock, _ = self._server_sock.accept()
            except OSError:
                break
            with self._lock:
                if self._closed:
                    client_sock.close()
                    break
                self._active_sockets.add(client_sock)
            threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()

    def _is_loopback_target(self, host: str) -> bool:
        lowered = host.lower().rstrip(".")
        if lowered == "localhost" or lowered.endswith(".localhost"):
            return True
        try:
            addr = ipaddress.ip_address(lowered)
            return addr.version == 4 and addr.is_loopback
        except ValueError:
            return False

    def _is_blocked_destination(self, host: str) -> bool:
        lowered = host.lower().rstrip(".")
        if any(lowered == tld[1:] or lowered.endswith(tld) for tld in LOCAL_SPECIAL_TLDS):
            return True
        try:
            addr = ipaddress.ip_address(lowered)
        except ValueError:
            return False
        if addr.version != 4:
            return True
        return any(addr in net for net in self._blocked_networks)

    @staticmethod
    def _send_socks_reply(sock: socket.socket, rep: int) -> None:
        try:
            sock.sendall(bytes((0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0)))
        except OSError:
            pass

    def _relay(self, client_sock: socket.socket, stream: MuxStream) -> None:
        client_sock.settimeout(None)

        def stream_to_client() -> None:
            try:
                while True:
                    cmd, data = stream.rx_queue.get()
                    if cmd == CMD_DATA:
                        client_sock.sendall(data)
                    elif cmd == CMD_EOF:
                        try:
                            client_sock.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        break
                    elif cmd == CMD_CLOSE:
                        try:
                            client_sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        break
            except OSError:
                stream.abort()

        down_thread = threading.Thread(target=stream_to_client, daemon=True)
        down_thread.start()
        try:
            while True:
                chunk = client_sock.recv(MAX_MUX_CHUNK)
                if not chunk:
                    stream.send_eof()
                    break
                stream.send_data(chunk)
        except OSError:
            stream.abort()
        finally:
            down_thread.join(timeout=5.0)
            stream.close()

    def _handle_client(self, client_sock: socket.socket) -> None:
        try:
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_sock.settimeout(10.0)

            greeting = _recv_exact(client_sock, 2)
            if greeting[0] != 0x05 or greeting[1] == 0:
                return
            methods = _recv_exact(client_sock, greeting[1])
            if 0x00 not in methods:
                client_sock.sendall(b"\x05\xff")
                return
            client_sock.sendall(b"\x05\x00")

            req_head = _recv_exact(client_sock, 4)
            ver, cmd, _rsv, atyp = req_head
            if ver != 0x05:
                return

            if atyp == 0x01:
                raw_addr = _recv_exact(client_sock, 4)
                host = socket.inet_ntoa(raw_addr)
                addr_wire = raw_addr
            elif atyp == 0x03:
                alen = _recv_exact(client_sock, 1)
                raw_domain = _recv_exact(client_sock, alen[0])
                host = raw_domain.decode("utf-8", errors="strict").strip()
                if not host:
                    self._send_socks_reply(client_sock, 0x04)
                    return
                addr_wire = alen + raw_domain
            elif atyp == 0x04:
                _recv_exact(client_sock, 16)
                _recv_exact(client_sock, 2)
                self._send_socks_reply(client_sock, 0x08)
                return
            else:
                self._send_socks_reply(client_sock, 0x08)
                return

            raw_port = _recv_exact(client_sock, 2)
            (dst_port,) = struct.unpack("!H", raw_port)

            if cmd != 0x01 or dst_port == 0:
                self._send_socks_reply(client_sock, 0x07)
                return

            if self._is_loopback_target(host):
                if self._claude_mux is not None and self._claude_port_allowed(dst_port):
                    try:
                        stream = self._claude_mux.open_stream(dst_port)
                    except ConnectionRefusedError:
                        self._send_socks_reply(client_sock, 0x05)
                        return
                    except ConnectionError:
                        self._send_socks_reply(client_sock, 0x01)
                        return
                    client_sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                    self._relay(client_sock, stream)
                    return
                self._send_socks_reply(client_sock, 0x02)
                return

            if self._is_blocked_destination(host):
                self._send_socks_reply(client_sock, 0x02)
                return

            try:
                stream = self._proxy_mux.open_stream(BROWSER_CONTAINER_PORT)
            except ConnectionError:
                self._send_socks_reply(client_sock, 0x01)
                return

            try:
                raw_connect = req_head + addr_wire + raw_port
                stream.send_data(b"\x05\x01\x00" + raw_connect)
                greet_buf = bytearray()
                while len(greet_buf) < 2:
                    try:
                        cmd_type, chunk = stream.rx_queue.get(timeout=10.0)
                    except queue.Empty:
                        stream.abort()
                        self._send_socks_reply(client_sock, 0x01)
                        return
                    if cmd_type != CMD_DATA or not chunk:
                        stream.abort()
                        self._send_socks_reply(client_sock, 0x01)
                        return
                    greet_buf.extend(chunk)
                if greet_buf[:2] != b"\x05\x00":
                    stream.abort()
                    self._send_socks_reply(client_sock, 0x01)
                    return
                if len(greet_buf) > 2:
                    client_sock.sendall(bytes(greet_buf[2:]))
            except OSError:
                stream.abort()
                return

            self._relay(client_sock, stream)
        except (ConnectionError, OSError, UnicodeDecodeError):
            pass
        finally:
            with self._lock:
                self._active_sockets.discard(client_sock)
            try:
                client_sock.close()
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            self._closed = True
            srv = self._server_sock
            self._server_sock = None
            active = list(self._active_sockets)
            self._active_sockets.clear()
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        for sock in active:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def browser_state_root(host_home: Path) -> Path:
    xdg = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg and Path(xdg).expanduser().is_absolute() else (host_home / ".local" / "state")
    return base / "claude-docker" / "browsers"


def browser_profile_dir(account: str, host_home: Path) -> Path:
    return browser_state_root(host_home) / account


def detect_chromium_binary(override: str, host_home: Path) -> Path:
    raw = override.strip() or os.environ.get("CLAUDE_DOCKER_BROWSER", "").strip()
    if raw:
        if "safari" in raw.lower():
            raise BrowserError(
                "Safari 不支持单进程代理与禁本地 DNS 参数；请使用 Chrome / Brave / Edge / Chromium"
            )
        candidate = Path(raw).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        resolved = shutil.which(raw)
        if resolved:
            return Path(resolved)
        raise BrowserError(f"指定的浏览器可执行文件不存在或不可执行: {raw}")

    if sys.platform == "darwin":
        app_relatives = (
            ("Google Chrome.app", "Google Chrome"),
            ("Brave Browser.app", "Brave Browser"),
            ("Microsoft Edge.app", "Microsoft Edge"),
            ("Chromium.app", "Chromium"),
        )
        for app_root in (Path("/Applications"), host_home / "Applications"):
            for bundle, binary in app_relatives:
                candidate = app_root / bundle / "Contents" / "MacOS" / binary
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return candidate

    for cmd_name in (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "brave-browser",
        "microsoft-edge",
        "microsoft-edge-stable",
    ):
        resolved = shutil.which(cmd_name)
        if resolved:
            return Path(resolved)

    raise BrowserError(
        "未探测到 Chromium 内核浏览器（Chrome / Brave / Edge / Chromium）；"
        "请先安装，或通过 --browser <可执行文件路径> 指定"
    )


def _merge_json_file(path: Path, patch: dict[str, dict[str, object]]) -> None:
    data: dict[str, object] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}
    for section, values in patch.items():
        existing = data.get(section)
        merged = dict(existing) if isinstance(existing, dict) else {}
        merged.update(values)
        data[section] = merged
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    tmp_path.chmod(0o600)
    tmp_path.replace(path)


def prepare_browser_profile(
    profile_dir: Path, uid: int, *, reset: bool, check_only: bool = False
) -> None:
    if check_only and reset:
        raise BrowserError("--check-only 不能与 --reset-profile 同时使用")

    parent = profile_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    parent.chmod(0o700)

    lock_path = profile_dir / "SingletonLock"
    if profile_dir.exists():
        meta = profile_dir.stat()
        if meta.st_uid != uid:
            raise BrowserError(f"浏览器配置目录所有者异常: {profile_dir} (uid={meta.st_uid})")
        if not check_only:
            if lock_path.is_symlink():
                target = os.readlink(lock_path)
                pid_part = target.rsplit("-", 1)[-1]
                if pid_part.isdigit():
                    ps_check = subprocess.run(
                        ["ps", "-ww", "-p", pid_part, "-o", "args="],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    if ps_check.returncode == 0 and str(profile_dir) in ps_check.stdout:
                        raise BrowserError(
                            f"该账号的受控浏览器已在运行 (PID={pid_part})；"
                            "请先退出该浏览器实例 (Cmd+Q) 再重新启动，以确保新隧道端口生效"
                        )
                for stale_name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
                    (profile_dir / stale_name).unlink(missing_ok=True)

            if reset:
                shutil.rmtree(profile_dir)

    profile_dir.mkdir(parents=True, exist_ok=True)
    profile_dir.chmod(0o700)
    if stat.S_IMODE(profile_dir.stat().st_mode) & 0o077:
        raise BrowserError(f"无法将浏览器配置目录权限收紧为 0700: {profile_dir}")

    if not check_only:
        _merge_json_file(
            profile_dir / "Local State",
            {
                "dns_over_https": {"mode": "off"},
                "intl": {"app_locale": "en-US"},
            },
        )
        _merge_json_file(
            profile_dir / "Default" / "Preferences",
            {
                "webrtc": {"ip_handling_policy": "disable_non_proxied_udp"},
                "intl": {
                    "accept_languages": "en-US,en",
                    "selected_languages": "en-US,en",
                },
            },
        )


def parse_browser_args(extra: list[str]) -> BrowserOptions:
    check_only = False
    claude_localhost = True
    oauth_ports: list[int] = []
    browser_override = ""
    reset_profile = False
    urls: list[str] = []

    idx = 0
    while idx < len(extra):
        arg = extra[idx]
        if arg == "--check-only":
            check_only = True
        elif arg == "--claude-localhost":
            claude_localhost = True
        elif arg == "--no-claude-localhost":
            claude_localhost = False
        elif arg == "--reset-profile":
            reset_profile = True
        elif arg in {"--oauth-port", "--browser", "--url"}:
            if idx + 1 >= len(extra):
                raise BrowserError(f"{arg} 需要提供参数值")
            val = extra[idx + 1]
            idx += 1
            if arg == "--oauth-port":
                if not val.isdigit() or not (1 <= int(val) <= 65535):
                    raise BrowserError(f"无效的 --oauth-port 端口: {val}")
                oauth_ports.append(int(val))
            elif arg == "--browser":
                browser_override = val
            elif arg == "--url":
                urls.append(val)
        elif arg.startswith("-"):
            raise BrowserError(
                f"未知的 browser 参数: {arg}（支持 --check-only / --oauth-port <端口> / "
                "--no-claude-localhost / --browser <路径> / --reset-profile / [初始URL]）"
            )
        else:
            urls.append(arg)
        idx += 1

    if len(urls) > 1:
        raise BrowserError("最多只能指定一个初始 URL")
    start_url = urls[0] if urls else "about:blank"
    if start_url != "about:blank":
        parsed = urlsplit(start_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise BrowserError(f"初始 URL 仅支持 http://、https:// 或 about:blank: {start_url}")

    return BrowserOptions(
        check_only=check_only,
        claude_localhost=claude_localhost,
        oauth_ports=tuple(dict.fromkeys(oauth_ports)),
        browser_override=browser_override,
        reset_profile=reset_profile,
        start_url=start_url,
    )


def _socks5_probe_rejected(socks_port: int, host: str, port: int) -> bool:
    """Return True iff the local SOCKS5 server refuses/blocks connecting to (host, port)."""
    host_bytes = host.encode("utf-8")
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5.0) as sock:
        sock.settimeout(5.0)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            return True
        req = b"\x05\x01\x00\x03" + bytes((len(host_bytes),)) + host_bytes + struct.pack("!H", port)
        sock.sendall(req)
        reply = _recv_exact(sock, 10)
        return reply[1] != 0x00


def verify_browser_tunnel(
    *,
    socks_port: int,
    expected_exit_ip: str,
    exit_check_url: str,
    country_denylist: str,
    private_allowlist: str,
) -> tuple[str, str]:
    """Verify pinned exit IP, country policy, private CIDR block, and host-loopback isolation."""
    if not _socks5_probe_rejected(socks_port, "10.0.0.1", 80):
        raise BrowserError("安全自检失败: 私网地址 10.0.0.1 未被受控代理阻断")

    first_allow = private_allowlist.replace(",", " ").split()
    if first_allow:
        priv_host_raw, priv_port_raw = first_allow[0].rsplit(":", 1)
        priv_host = priv_host_raw.split("/", 1)[0]
        if not _socks5_probe_rejected(socks_port, priv_host, int(priv_port_raw)):
            raise BrowserError(
                f"安全自检失败: PRIVATE_TCP_ALLOWLIST ({priv_host}:{priv_port_raw}) 未对浏览器隔离"
            )

    # `<socks_port>` is actively listening on the host's 127.0.0.1 right now; verifying that
    # `localhost:<socks_port>` fails proves browser `localhost` cannot reach host loopback.
    if not _socks5_probe_rejected(socks_port, "localhost", socks_port):
        raise BrowserError("安全自检失败: 浏览器 localhost 请求意外穿透到了宿主机自身回环")

    curl_bin = shutil.which("curl")
    if not curl_bin:
        raise BrowserError("宿主机缺少 curl，无法执行开窗前出口 IP 强校验")

    probe = subprocess.run(
        [
            curl_bin,
            "-fsS",
            "--connect-timeout",
            "8",
            "--max-time",
            "20",
            "--socks5-hostname",
            f"127.0.0.1:{socks_port}",
            exit_check_url,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if probe.returncode != 0:
        detail = probe.stderr.strip() or probe.stdout.strip() or f"exit={probe.returncode}"
        raise BrowserError(f"受控浏览器隧道出口探测失败 ({exit_check_url}): {detail}")

    values: dict[str, str] = {}
    for line in probe.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()

    actual_ip = values.get("ip", "")
    country = values.get("loc", "").upper()
    if actual_ip != expected_exit_ip:
        raise BrowserError(
            f"受控浏览器出口 IP 与 EXPECTED_EXIT_IP 不一致 "
            f"(expected={expected_exit_ip}, actual={actual_ip or '<empty>'})；已阻断启动"
        )

    denied = {
        item.strip().upper()
        for item in country_denylist.replace(",", " ").split()
        if item.strip()
    }
    if denied:
        if len(country) != 2 or not country.isalpha():
            raise BrowserError("无法从出口探测结果确认国家代码；已阻断启动")
        if country in denied:
            raise BrowserError(f"受控浏览器出口国家命中黑名单 ({country})；已阻断启动")

    return actual_ip, country or "unknown"


def build_chromium_command(
    *,
    browser_bin: Path,
    profile_dir: Path,
    socks_port: int,
    start_url: str,
) -> list[str]:
    return [
        str(browser_bin),
        f"--user-data-dir={profile_dir}",
        f"--proxy-server=socks5://127.0.0.1:{socks_port}",
        "--proxy-bypass-list=<-loopback>",
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
        "--disable-quic",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-features=DnsOverHttps",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--no-first-run",
        "--no-default-browser-check",
        "--lang=en-US",
        "--accept-lang=en-US,en",
        "--",
        start_url,
    ]


def build_browser_environment(timezone: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in PROXY_ENV_STRIP_KEYS}
    env["TZ"] = timezone
    env["LANG"] = "en_US.UTF-8"
    env["LC_ALL"] = "en_US.UTF-8"
    return env


def run_controlled_browser(
    *,
    account: str,
    environment: dict[str, str],
    locked_subnet: ipaddress.IPv4Network,
    proxy_container: str,
    claude_container: str,
    uid: int,
    host_home: Path,
    check_container_healthy: Callable[[str], bool],
    extra_args: list[str],
) -> None:
    options = parse_browser_args(extra_args)
    browser_bin = detect_chromium_binary(options.browser_override, host_home)
    profile_dir = browser_profile_dir(account, host_home)
    prepare_browser_profile(
        profile_dir, uid, reset=options.reset_profile, check_only=options.check_only
    )

    blocked_cidrs = list(BOGON_AND_PRIVATE_CIDRS) + [
        cidr.strip()
        for cidr in environment["BLOCK_PRIVATE_CIDRS"].split(",")
        if cidr.strip()
    ]
    blocked_cidrs.append(str(locked_subnet))
    blocked_networks = tuple(
        ipaddress.ip_network(cidr, strict=False) for cidr in dict.fromkeys(blocked_cidrs)
    )

    if options.oauth_ports:
        allowed_ports_set = set(options.oauth_ports)
        claude_spec = ",".join(str(p) for p in options.oauth_ports)
        claude_port_allowed = lambda p: p in allowed_ports_set
        localhost_mode = f"仅转发指定端口 ({claude_spec}) -> claude:127.0.0.1"
        enable_claude_mux = True
    elif options.claude_localhost:
        claude_spec = "1024-65535"
        claude_port_allowed = lambda p: 1024 <= p <= 65535
        localhost_mode = "自动桥接 localhost:1024-65535 -> claude:127.0.0.1 (宿主机自身回环已隔离)"
        enable_claude_mux = True
    else:
        claude_spec = ""
        claude_port_allowed = lambda _p: False
        localhost_mode = "已完全禁用"
        enable_claude_mux = False

    proxy_mux = ContainerLoopbackMux(
        "proxy",
        [
            "docker",
            "exec",
            "-i",
            proxy_container,
            "python3",
            "-u",
            "-c",
            CONTAINER_MUX_SCRIPT,
            str(BROWSER_CONTAINER_PORT),
        ],
    )
    claude_mux = (
        ContainerLoopbackMux(
            "claude",
            [
                "docker",
                "exec",
                "-i",
                claude_container,
                "/usr/local/bin/claude-exec",
                "python3",
                "-u",
                "-c",
                CONTAINER_MUX_SCRIPT,
                claude_spec,
            ],
        )
        if enable_claude_mux
        else None
    )

    socks_server: ControlledSocksServer | None = None
    browser_proc: subprocess.Popen[bytes] | None = None
    try:
        proxy_mux.start()
        if claude_mux is not None:
            claude_mux.start()

        socks_server = ControlledSocksServer(
            proxy_mux=proxy_mux,
            claude_mux=claude_mux,
            claude_port_allowed=claude_port_allowed,
            blocked_networks=blocked_networks,
        )
        socks_port = socks_server.start()

        actual_ip, country = verify_browser_tunnel(
            socks_port=socks_port,
            expected_exit_ip=environment["EXPECTED_EXIT_IP"],
            exit_check_url=environment.get(
                "EXIT_CHECK_URL", "https://www.cloudflare.com/cdn-cgi/trace"
            ),
            country_denylist=environment.get("EXIT_COUNTRY_DENYLIST", ""),
            private_allowlist=environment.get("PRIVATE_TCP_ALLOWLIST", ""),
        )

        print(f"受控浏览器预检通过 ({account}):")
        print(f"  浏览器程序: {browser_bin}")
        print(f"  隔离配置目录: {profile_dir} (mode=0700)")
        print(
            f"  临时受控入口: socks5://127.0.0.1:{socks_port} "
            "(禁本地 DNS / 禁 QUIC / 禁 WebRTC / 禁私网与宿主回环)"
        )
        print(f"  实测出口 IP: {actual_ip} (loc={country}, 严格匹配 EXPECTED_EXIT_IP)")
        print(f"  时区与语言: TZ={environment['TZ']}, LANG=en_US.UTF-8")
        print(f"  OAuth 回调: {localhost_mode}")

        if options.check_only:
            print("✓ --check-only 自检完成（未启动图形窗口，隧道已安全回收）")
            return

        cmd = build_chromium_command(
            browser_bin=browser_bin,
            profile_dir=profile_dir,
            socks_port=socks_port,
            start_url=options.start_url,
        )
        browser_proc = subprocess.Popen(
            cmd,
            env=build_browser_environment(environment["TZ"]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print("浏览器已启动；保持本终端运行，退出浏览器 (Cmd+Q) 或按 Ctrl+C 后隧道自动销毁。")

        last_health_probe = time.monotonic()
        while True:
            rc = browser_proc.poll()
            if rc is not None:
                if rc != 0:
                    raise BrowserError(f"受控浏览器进程异常退出 (exit={rc})")
                break
            if not proxy_mux.is_alive():
                raise BrowserError("proxy 隧道连接中断，已立即关闭本地代理并终止受控浏览器 (Fail-Closed)")
            if claude_mux is not None and not claude_mux.is_alive():
                raise BrowserError("claude 回调隧道中断，已立即关闭本地代理并终止受控浏览器")
            now = time.monotonic()
            if now - last_health_probe >= 5.0:
                last_health_probe = now
                if not check_container_healthy(proxy_container):
                    raise BrowserError(
                        "检测到 proxy 容器健康状态异常，已立即熔断本地代理并关闭受控浏览器"
                    )
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n收到中断信号，正在关闭受控浏览器与临时隧道…")
    finally:
        if socks_server is not None:
            socks_server.close()
        if browser_proc is not None and browser_proc.poll() is None:
            browser_proc.terminate()
            try:
                browser_proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                browser_proc.kill()
                browser_proc.wait(timeout=2.0)
        if claude_mux is not None:
            claude_mux.close()
        proxy_mux.close()
