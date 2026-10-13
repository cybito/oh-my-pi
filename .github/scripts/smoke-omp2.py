#!/usr/bin/env python3
"""Drive the production binary with existing QA's scripted HTTP provider.

Inputs: binary path, evidence directory. Output: print results and PTY frames.
Side effects: isolated /tmp project/home/data, temporary loopback HTTP server,
real PTY and ordinary child processes. No keys or real vendor calls; no root.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/qa"))
import harness  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def private_environment(home: Path) -> dict[str, str]:
    # Each QA fixture supplies its own model-bearing OMP_DATA_DIR.
    return {
        "HOME": str(home),
        "OMP_CONFIG_DIR": str(home / "config"),
        "OMP_STATE_DIR": str(home / "state"),
        "OMP_CACHE_DIR": str(home / "cache"),
        "OMP_PROFILE": "default",
    }


def print_smoke(binary: Path, evidence: Path, home: Path) -> None:
    harness.OMP_BINARY = binary
    result = harness.drive(
        harness.call("bash", command="printf '%s-%s' native print-ok", i="Running native smoke"),
        "native-turn-complete",
        prompt="Run the supplied native shell command.",
        args=["--no-ext"],
        timeout=60,
        env=private_environment(home),
    )
    (evidence / "print.stdout").write_text(result.stdout)
    (evidence / "print.stderr").write_text(result.stderr)
    if result.mock is not None:
        (evidence / "print.requests.json").write_text(json.dumps(result.mock["captures"], indent=2))
    require(not result.timed_out and result.exit_code == 0, f"print failed: {result.exit_code}\n{result.stderr}\n{result.stdout}")
    require(bool(result.of_type("agent_end")), "print did not settle agent_end")
    require(result.mock is not None and result.mock["served"] == 2, "tool loop did not complete exactly two requests")
    executions = result.of_type("tool_execution_end")
    require(
        len(executions) == 1 and executions[0].get("isError") is False,
        "native shell execution did not succeed",
    )
    # The command constructs this marker; its arguments do not contain it.
    # Do not assume a transport-specific message role for the forwarded result.
    require(
        "native-print-ok" in json.dumps(result.mock["captures"][1]),
        "native tool output did not reach the next provider request",
    )
    print("PASS: native print → envd → shell → follow-up → clean exit", flush=True)


def pty_smoke(binary: Path, evidence: Path, root: Path, home: Path) -> None:
    project = root / "project"
    data = root / "data"
    project.mkdir()
    data.mkdir()
    model = harness.MockModel("native-pty-ok")
    (data / "models.toml").write_text(harness.MODELS_TOML.format(port=model.port))
    (data / "config.toml").write_text(harness.CONFIG_TOML)
    debug = root / "tui.sock"
    master, slave = pty.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    fcntl.ioctl(slave, termios.FIONREAD, struct.pack("i", 0))
    before = termios.tcgetattr(slave)
    (evidence / "termios.before.txt").write_text(repr(before))
    raw = bytearray()
    stop = threading.Event()

    def collect() -> None:
        while not stop.is_set():
            if not select.select([master], [], [], 0.1)[0]:
                continue
            try:
                chunk = os.read(master, 16384)
            except OSError:
                break
            if not chunk:
                break
            raw.extend(chunk)

    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    process = None
    channel = None
    stream = None
    try:
        with (evidence / "chat.stdout").open("wb") as stdout, (evidence / "chat.stderr").open("wb") as stderr:
            process = subprocess.Popen(
                [str(binary), "chat", "--no-ext", "--model", "mock"],
                cwd=project,
                env={**os.environ, **private_environment(home), "OMP_DATA_DIR": str(data),
                     "TERM": "xterm-256color", "NO_COLOR": "1",
                     "OMP_TTY": os.ttyname(slave), "OMP_TUI_DEBUG": str(debug)},
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                # A Darwin session leader's exit revokes its controlling PTY.
                # Keep this session alive while still isolating the kill group.
                process_group=0,
            )
            deadline = time.monotonic() + 40
            while True:
                require(process.poll() is None, "chat exited before its native debug surface became ready")
                try:
                    channel = socket.socket(socket.AF_UNIX)
                    channel.settimeout(2)
                    channel.connect(str(debug))
                    stream = channel.makefile("rwb")
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    channel.close()
                    channel = None
                    require(time.monotonic() < deadline, "chat startup timed out")
                    time.sleep(0.05)

            def request(op: str) -> dict:
                stream.write(json.dumps({"op": op}).encode() + b"\n")
                stream.flush()
                response = json.loads(stream.readline())
                require(response.get("ok") is True, f"native debug request failed: {response}")
                return response

            def wait_surface(needles: tuple[str, ...], name: str) -> str:
                end = time.monotonic() + 40
                while True:
                    surface = "\n".join(request("text").get("lines", []))
                    (evidence / name).write_text(surface + "\n")
                    if all(needle in surface for needle in needles):
                        return surface
                    require(process.poll() is None and time.monotonic() < end, f"native surface missing {needles}:\n{surface}")
                    time.sleep(0.05)

            welcome = wait_surface(("Welcome back!", "omp v", "Ask anything"), "welcome.txt")
            print("NATIVE PTY WELCOME:\n" + welcome, flush=True)
            (evidence / "termios.ready.txt").write_text(repr(termios.tcgetattr(slave)))
            os.write(master, b"Reply with a short acknowledgement.")
            wait_surface(("Reply with a short acknowledgement.",), "input.txt")
            os.write(master, b"\r")
            response = wait_surface(("native-pty-ok",), "response.txt")
            end = time.monotonic() + 40
            while request("values").get("values", {}).get("turn_active") is not False:
                require(process.poll() is None and time.monotonic() < end, "interactive turn did not settle")
                time.sleep(0.05)
            require(model.served == 1, "interactive input did not make exactly one provider request")
            require("Reply with a short acknowledgement." in json.dumps(model.captures), "ordinary PTY input did not reach the provider")
            print("NATIVE PTY RESPONSE:\n" + response, flush=True)
            os.write(master, b"\x04")
            require(process.wait(timeout=15) == 0, "chat did not exit cleanly after Ctrl-D")
            stop.set()
            reader.join(timeout=2)
            require(not reader.is_alive(), "PTY capture thread did not stop")
            while select.select([master], [], [], 0)[0]:
                chunk = os.read(master, 16384)
                if not chunk:
                    break
                raw.extend(chunk)
            # XNU queues PENDIN on raw → canonical transitions. FIONREAD lets
            # the line discipline process it; do not mask flags or reset modes.
            queued = fcntl.ioctl(slave, termios.FIONREAD, struct.pack("i", 0))
            require(struct.unpack("i", queued)[0] == 0, "chat left readable terminal input")
            after = termios.tcgetattr(slave)
            (evidence / "termios.after.txt").write_text(repr(after))
            require(after == before, f"chat did not restore termios:\nbefore={before!r}\nafter={after!r}")
            for mode in (1049, 1000, 1002, 1003, 1006):
                entered = raw.rfind(f"\x1b[?{mode}h".encode())
                exited = raw.rfind(f"\x1b[?{mode}l".encode())
                require(entered < 0 or exited > entered, f"terminal mode {mode} was not restored")
            hidden = raw.rfind(b"\x1b[?25l")
            shown = raw.rfind(b"\x1b[?25h")
            require(shown >= 0 and shown > hidden, "terminal cursor was not restored")
            print("PASS: real PTY welcome → typed input → response → Ctrl-D → terminal restore", flush=True)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if stream is not None:
            stream.close()
        if channel is not None:
            channel.close()
        stop.set()
        reader.join(timeout=2)
        (evidence / "chat.pty").write_bytes(raw)
        (evidence / "chat.requests.json").write_text(json.dumps(model.captures, indent=2))
        os.close(master)
        os.close(slave)
        model.close()


def main() -> None:
    binary = Path(sys.argv[1]).resolve()
    evidence = Path(sys.argv[2]).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(binary), "--version"], check=True, timeout=10)
    subprocess.run([str(binary), "--help"], check=True, timeout=10, stdout=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory(prefix="omp2-smoke-", dir="/tmp") as temporary:
        root = Path(temporary)
        home = root / "home"
        home.mkdir()
        print_smoke(binary, evidence, home)
        pty_smoke(binary, evidence, root, home)


if __name__ == "__main__":
    main()
