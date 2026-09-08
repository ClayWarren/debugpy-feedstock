"""Exercise installed Windows native modules and a DAP breakpoint session."""
import importlib
import json
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import sysconfig
import tempfile
import time

import debugpy
import debugpy._vendored.force_pydevd  # noqa: F401

machine = 0xAA64 if sysconfig.get_platform() == "win-arm64" else 0x8664
root = Path(debugpy.__file__).parent / "_vendored" / "pydevd"
print(f"Python={sys.version}; platform={sysconfig.get_platform()}; machine={platform.machine()}")
for name in ("_pydevd_bundle.pydevd_cython", "_pydevd_sys_monitoring._pydevd_sys_monitoring_cython"):
    if "sys_monitoring" in name and sys.version_info < (3, 12):
        continue
    module = importlib.import_module(name)
    assert str(module.__file__).endswith(".pyd"), module.__file__
    print(f"Native extension imported: {module.__file__}")

binaries = [p for p in root.rglob("*") if p.suffix in (".pyd", ".dll", ".exe")]
assert len(binaries) >= 4, binaries
for binary in binaries:
    data = binary.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0", binary
    actual = struct.unpack_from("<H", data, pe + 4)[0]
    assert actual == machine, (str(binary), hex(actual), hex(machine))
    print(f"PE {actual:#06x}: {binary.relative_to(root)}")

with debugpy._vendored.vendored("pydevd"):
    from pydevd_attach_to_process.add_code_to_python_process import get_target_filename
for prefix, extension in (("attach_", ".dll"), ("run_code_on_dllmain_", ".dll"), ("inject_dll_", ".exe")):
    assert get_target_filename(True, prefix, extension), (prefix, extension)


class DAP:
    def __init__(self, connection):
        self.connection = connection
        self.reader = connection.makefile("rb")
        self.seq = 0
        self.pending = []

    def send(self, command, arguments):
        self.seq += 1
        payload = json.dumps(dict(seq=self.seq, type="request", command=command, arguments=arguments)).encode()
        self.connection.sendall(f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)
        return self.seq

    def wait(self, predicate):
        for i, message in enumerate(self.pending):
            if predicate(message):
                return self.pending.pop(i)
        while True:
            headers = {}
            while True:
                line = self.reader.readline()
                if not line:
                    raise EOFError("Debugger closed DAP stream")
                if line == b"\r\n":
                    break
                key, value = line.decode().split(":", 1)
                headers[key.lower()] = value.strip()
            message = json.loads(self.reader.read(int(headers["content-length"])))
            if predicate(message):
                return message
            self.pending.append(message)

    def response(self, seq):
        message = self.wait(lambda m: m.get("type") == "response" and m.get("request_seq") == seq)
        assert message["success"], message
        return message.get("body", {})

    def request(self, command, arguments):
        return self.response(self.send(command, arguments))

    def event(self, name):
        return self.wait(lambda m: m.get("type") == "event" and m.get("event") == name)


with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    target = directory / "target.py"
    target.write_text('answer = 42\nprint(answer, flush=True)\n')
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with (directory / "debuggee.log").open("w+") as output:
        process = subprocess.Popen([sys.executable, "-m", "debugpy", "--listen", f"127.0.0.1:{port}", "--wait-for-client", str(target)], stdout=output, stderr=subprocess.STDOUT)
        connection = None
        try:
            deadline = time.monotonic() + 40
            while connection is None:
                assert process.poll() is None, "debuggee exited before connection"
                try:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("debugpy listener did not start")
                    time.sleep(0.1)
            connection.settimeout(30)
            dap = DAP(connection)
            dap.request("initialize", {"adapterID": "debugpy", "clientID": "conda-native-test", "pathFormat": "path", "linesStartAt1": True, "columnsStartAt1": True})
            attach = dap.send("attach", {"justMyCode": True})
            dap.event("initialized")
            result = dap.request("setBreakpoints", {"source": {"path": str(target)}, "breakpoints": [{"line": 2}]})
            assert result["breakpoints"][0]["verified"], result
            dap.request("configurationDone", {})
            dap.response(attach)
            stopped = dap.event("stopped")["body"]
            assert stopped["reason"] == "breakpoint", stopped
            stack = dap.request("stackTrace", {"threadId": stopped["threadId"]})
            frame = stack["stackFrames"][0]
            assert frame["line"] == 2, frame
            value = dap.request("evaluate", {"expression": "answer", "frameId": frame["id"], "context": "watch"})
            assert value["result"] == "42", value
            dap.request("continue", {"threadId": stopped["threadId"]})
            dap.event("terminated")
            assert process.wait(timeout=15) == 0
            print("DAP breakpoint, stack trace, variable evaluation, and continuation passed")
        finally:
            if connection is not None:
                connection.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            output.seek(0)
            print(output.read())
