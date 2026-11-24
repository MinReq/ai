#!/usr/bin/env python3
"""Request-shape tests for didww-to-openai-realtime/scripts/gptlive_call.py.
Stubs urllib.request.urlopen and the sideband WebSocket; no network, fake keys."""
import contextlib, importlib.util, io, json, os, socket, stat, struct, sys, tempfile, threading, urllib.request
sys.dont_write_bytecode = True  # keep __pycache__ out of the skill folders
P = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "gptlive_call.py"); results = []
def check(name, ok, detail=""):
    results.append(bool(ok)); print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail if not ok else ''}")
spec = importlib.util.spec_from_file_location("gptlive_call", P); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
FAKE = {"OPENAI_API_KEY": "sk-test-FAKEKEY", "DIDWW_SIP_USERNAME": "fakeuser123", "DIDWW_SIP_PASSWORD": "fakepass456"}
for k in FAKE: os.environ.pop(k, None)
tmp = tempfile.mkdtemp(); envp = os.path.join(tmp, "didww-openai.env")
os.environ["HOME"] = tmp  # files given on the command line must be in the home or current directory

class Clock:  # instant deadlines: the fake sideband advances this clock
    now = 1000.0
    def time(self): return self.now
mod.time = Clock()
calls = []
class Resp:
    def __init__(s, status, body): s.status, s.body = status, body
    def __enter__(s): return s
    def __exit__(s, *a): pass
    def read(s): return s.body
def fake_urlopen(req, timeout=None):
    calls.append({"url": req.full_url, "auth": req.get_header("Authorization"), "body": json.loads(req.data) if req.data else None})
    if req.full_url.endswith("/v1/live/sessions"):
        return Resp(201, json.dumps({"session": {"id": "live_test1"}, "transport": {"type": "sip"}}).encode())
    return Resp(200, b"{}")
urllib.request.urlopen = fake_urlopen
EVENTS, sent = [], []
class FakeSideband:
    def __init__(self, sid): self.q = [json.dumps(e) for e in EVENTS]
    def recv(self, wait):
        if self.q: return self.q.pop(0)
        mod.time.now += wait; return None
    def send(self, ev): sent.append(ev)
    def close(self): pass
mod.Sideband = FakeSideband
def run(*argv):
    sys.argv = ["gptlive_call.py", *argv]; out = io.StringIO(); calls.clear(); sent.clear()
    with contextlib.redirect_stdout(out):
        try: code = mod.main()
        except SystemExit as e: code = e.code
        except OSError as e: code = f"OSError: {e}"  # e.g. a symlink loop: a failure, not a crash of the suite
    return code, out.getvalue()
BASE = ("--env-file", envp, "--to", "+15105550199", "--from", "+15105550100")

with contextlib.redirect_stdout(io.StringIO()): mod.init_env(envp)
check("init-env: template created with mode 600", stat.S_IMODE(os.stat(envp).st_mode) == 0o600)
code, out = run("--init-env", envp)
check("init-env: an existing file is never overwritten", code not in (0, None), out)
with open(envp, "w") as f: f.write("".join(f"{k}={v}\n" for k, v in FAKE.items()) + "OPENAI_WEBHOOK_SECRET=\n")
code, out = run(*BASE, "--check")
check("--check: exits 0 and places no call", code == 0 and not calls, (code, calls))
check("--check: output carries no credential", not any(v in out for v in FAKE.values()), out)
for label, extra in (("number without +", ("--to", "15105550199")), ("same number both ways", ("--to", "+15105550100")),
                     ("gateway with a path", ("--gateway", "fra.eu.out.didww.com/x")), ("max-seconds below 10", ("--max-seconds", "5"))):
    code, out = run(*BASE, *extra, "--check")
    check(f"validation: {label} refused", code not in (0, None) and not calls, out)
os.chmod(envp, 0o644); code, out = run(*BASE, "--check"); os.chmod(envp, 0o600)
check("credentials: warns when the env file is readable by others", "chmod 600" in out, out)
# Paths: HOME is tmp; "outside" is a second temp folder that is neither home nor the current directory.
outside = tempfile.mkdtemp(); secretp = os.path.join(outside, "secret.txt")
with open(secretp, "w") as f: f.write("OUTSIDE-FILE-CONTENT-1234\n")  # 25 chars once stripped
def path_refused(code, out): return code not in (0, None) and "instructions=25 chars" not in out and not calls
agentp, linkp = os.path.join(tmp, "agent.txt"), os.path.join(tmp, "escape.txt")
with open(agentp, "w") as f: f.write("Test instructions.\n")
os.symlink(secretp, linkp)
code, out = run(*BASE, "--instructions-file", agentp, "--check")
check("paths: --instructions-file in the home directory is read", code == 0 and "instructions=18 chars" in out, (code, out))
code, out = run(*BASE, "--instructions-file", secretp, "--check")
check("paths: --instructions-file outside home and the current directory refused", path_refused(code, out) and "home directory" in str(code), (code, out))
code, out = run(*BASE, "--instructions-file", linkp, "--check")
check("paths: a symlink pointing outside is refused", path_refused(code, out) and "is a link to" in str(code), (code, out))
os.symlink("loop", os.path.join(tmp, "loop")); os.symlink(secretp, os.path.join(tmp, "evil")); os.symlink("loop/../evil", os.path.join(tmp, "trick.txt"))
code, out = run(*BASE, "--instructions-file", os.path.join(tmp, "trick.txt"), "--check")
check("paths: a symlink loop cannot smuggle in an outside file", path_refused(code, out), (code, out))
# realpath() guesses on over-long paths; simulate that by making it name an inside decoy for the outside link.
decoy = os.path.join(tmp, "decoy.txt")
with open(decoy, "w") as f: f.write("Test instructions.\n")
real_realpath = os.path.realpath
decoy_real = real_realpath(decoy)
os.path.realpath = lambda p, *a, **k: decoy_real if str(p).endswith("escape.txt") else real_realpath(p, *a, **k)
try: code, out = run(*BASE, "--instructions-file", linkp, "--check")
finally: os.path.realpath = real_realpath
os.remove(decoy)
check("paths: a link that realpath() misreads is refused (the kernel's file is checked)", path_refused(code, out) and "cannot confirm" in str(code), (code, out))
subdir = os.path.join(tmp, "prompts"); os.mkdir(subdir); subp = os.path.join(subdir, "agent.txt")
with open(subp, "w") as f: f.write("Test instructions.\n")
code, out = run(*BASE, "--instructions-file", subp, "--check")
check("paths: a file in a subfolder is refused with how to fix it", "run from its folder" in str(code) and '--instructions "$(cat FILE)"' in str(code) and not calls, (code, out))
cwd0 = os.getcwd(); os.chdir(subdir)
code, out = run(*BASE, "--instructions-file", "agent.txt", "--check")
os.chdir(cwd0)
check("paths: a relative file in the current directory is read", code == 0 and "instructions=18 chars" in out, (code, out))
realp, dotlink = os.path.join(subdir, "real.env"), os.path.join(tmp, ".linked-openai.env")
os.rename(envp, realp); os.symlink(realp, dotlink)  # dotfile managers link the home file into a subfolder
code, out = run("--env-file", dotlink, *BASE[2:], "--check")
os.remove(dotlink); os.rename(realp, envp)
check("paths: --env-file linked from home into a home subfolder is read", code == 0 and "check OK" in out, (code, out))
code, out = run("--env-file", secretp, *BASE[2:], "--check")
check("paths: --env-file outside home and the current directory refused", "home directory" in str(code) and "environment" in str(code) and not calls, (code, out))
code, out = run("--init-env", os.path.join(outside, "new.env"))
check("paths: --init-env outside home and the current directory refused", "home directory" in str(code) and not os.path.exists(os.path.join(outside, "new.env")), (code, out))
dangling = os.path.join(tmp, ".dangling.env"); os.symlink(os.path.join(tmp, "nowhere.env"), dangling)
code, out = run("--init-env", dangling)
check("paths: --init-env on a dangling link is refused and creates nothing", "already exists" in str(code) and not os.path.exists(os.path.join(tmp, "nowhere.env")), (code, out))
gone = tempfile.mkdtemp(); os.chdir(gone); os.rmdir(gone)
code, out = run(*BASE, "--check")
code2, out2 = run(*BASE, "--instructions-file", "agent.txt", "--check")
os.chdir(cwd0)
check("paths: a deleted current directory still allows a file in home", code == 0 and "check OK" in out, (code, out))
check("paths: a deleted current directory refuses a relative name with a message", "no longer exists" in str(code2), (code2, out2))
for p in (agentp, linkp, dangling, subp, *(os.path.join(tmp, n) for n in ("loop", "evil", "trick.txt"))):
    os.remove(p)
os.rmdir(subdir); os.remove(secretp); os.rmdir(outside)

EVENTS[:] = [
    {"type": "error", "event_id": "e0", "error": {"code": "missing_scope", "message": "History compaction is disabled"}},
    {"type": "session.started", "event_id": "e1"}, {"type": "transport.ringing", "event_id": "e2"},
    {"type": "transport.answered", "event_id": "e3"}, {"type": "transport.answered", "event_id": "e3"},
    {"type": "session.output_transcript.delta", "event_id": "e4", "delta": "Hello, this is "},
    {"type": "session.output_transcript.delta", "event_id": "e5", "delta": "Alex."},
    {"type": "session.input_audio.append", "event_id": "e6"}, {"type": "session.input_audio.append", "event_id": "e6b"},
    {"type": "session.input_transcript.delta", "event_id": "e7", "delta": "Which countries do you cover?"},
    {"type": "session.delegation.created", "event_id": "e8", "offset_ms": 9000, "delegation": {"id": "item_ABC", "type": "delegation", "target": "client"}},
    {"type": "session.closed", "event_id": "e9", "reason": "remote_hangup"}]
code, out = run(*BASE, "--instructions", "Test agent.")
check("call: exactly one POST /v1/live/sessions, no retry, no hangup after session.closed",
      [c["url"] for c in calls] == ["https://api.openai.com/v1/live/sessions"] and code == 0, (code, calls))
check("call: request body is DIDWW's documented shape", calls and calls[0]["body"] == {
    "session": {"model": "gpt-live-1", "instructions": "Test agent.", "audio": {"output": {"voice": "marin"}}, "delegation": {"type": "client"}},
    "transport": {"type": "sip", "destination": "+15105550199", "trunk": {"provider_url": "sips:fra.eu.out.didww.com:5061",
                  "auth": {"type": "digest", "username": "fakeuser123", "password": "fakepass456"}, "caller_number": "+15105550100"}}}, calls)
check("call: bearer API key on the request", calls and calls[0]["auth"] == "Bearer sk-test-FAKEKEY")
check("delegation: answered once, same delegation_id, spoken result",
      len(sent) == 1 and sent[0]["type"] == "session.commentary.append" and sent[0]["delegation_id"] == "item_ABC" and sent[0]["content"] and sent[0]["event_id"], sent)
check("transcript: deltas joined into lines per speaker", "agent: Hello, this is Alex." in out and "person: Which countries do you cover?" in out, out)
check("events: duplicates by event_id ignored, audio logged once", out.count("answered\n") == 1 and out.count("session.input_audio.append") == 1, out)
check("logs: no credential in the output", not any(v in out for v in FAKE.values()), out)
EVENTS[:] = [{"type": "transport.ringing", "event_id": "r1"}]
code, out = run(*BASE, "--max-seconds", "10")
check("deadline: hangs up once with the session ID, exit 2 when unanswered",
      [c["url"] for c in calls] == ["https://api.openai.com/v1/live/sessions", "https://api.openai.com/v1/live/sessions/live_test1/hangup"] and code == 2, (code, calls))
EVENTS[:] = [{"type": "transport.failed", "event_id": "f1", "error": {"message": "Invite failed with response: SIP/2.0 403 Forbidden", "code": "provider_invite_failed"}},
             {"type": "session.closed", "event_id": "f2", "reason": "transport_failed"}]
code, out = run(*BASE)
check("failure: logs DIDWW's SIP response, no hangup, no retry",
      "403 Forbidden" in out and [c["url"] for c in calls] == ["https://api.openai.com/v1/live/sessions"] and code == 2, (code, out))
def no_attach(sid): raise ConnectionError("HTTP/1.1 404 Not Found")
mod.Sideband = no_attach
code, out = run(*BASE)
check("attach failure: hangs up so the call does not run unattended",
      [c["url"] for c in calls][-1:] == ["https://api.openai.com/v1/live/sessions/live_test1/hangup"] and code == 2, (code, calls))

# The real Sideband frame reader: fragments, pings, 64-bit lengths, timeouts, close.
def frame(op, data, fin=True):
    n = len(data); head = bytes([(0x80 if fin else 0) | op])
    return head + (bytes([n]) if n < 126 else bytes([126]) + struct.pack(">H", n) if n < 65536 else bytes([127]) + struct.pack(">Q", n)) + data
class Plain:  # a socket pair end standing in for the TLS socket
    def __init__(s, sock): s.sock = sock
    def pending(s): return 0
    def fileno(s): return s.sock.fileno()
    def recv(s, n): return s.sock.recv(n)
    def sendall(s, b): s.sock.sendall(b)
    def close(s): s.sock.close()
a, b = socket.socketpair()
real = importlib.util.module_from_spec(spec); spec.loader.exec_module(real)  # unpatched copy
sb = object.__new__(real.Sideband); sb.s, sb.parts = Plain(a), []
big = json.dumps({"type": "x", "pad": "y" * 70000}).encode()
threading.Thread(target=b.sendall, daemon=True, args=(frame(0x1, b'{"type":', fin=False) + frame(0x9, b"hi") + frame(0x0, b'"one"}') + frame(0x1, big),)).start()
check("sideband: fragmented message joined", json.loads(sb.recv(5)) == {"type": "one"})
pong = b.recv(16)
check("sideband: ping answered with a masked pong", pong[0] == 0x8A and pong[1] & 0x80)
check("sideband: 64-bit length frame read whole", len(sb.recv(5)) == len(big))
check("sideband: no data within the wait -> None", sb.recv(0.1) is None)
b.sendall(frame(0x8, b""))
try: sb.recv(5); check("sideband: close frame raises", False)
except ConnectionError: check("sideband: close frame raises", True)
a.close(); b.close(); os.remove(envp); os.rmdir(tmp)
print(f"\n{sum(results)}/{len(results)} passed"); sys.exit(0 if all(results) else 1)
