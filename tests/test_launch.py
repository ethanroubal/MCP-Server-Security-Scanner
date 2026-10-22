import pytest

from mcpscan.core.launch import argv_pointer, docker_run, package_ref
from mcpscan.core.models import Launch

DIGEST = "sha256:" + "ab" * 32


def _launch(*argv: str) -> Launch:
    return Launch(transport="stdio", command=argv[0], args=list(argv[1:]))


@pytest.mark.parametrize(
    ("argv", "registry", "name", "spec", "pinned"),
    [
        (["npx", "-y", "pkg"], "npm", "pkg", None, False),
        (["npx", "-y", "@scope/pkg@1.2.3"], "npm", "@scope/pkg", "1.2.3", True),
        (["npx", "@scope/pkg@^1.2"], "npm", "@scope/pkg", "^1.2", False),
        (["npx", "-p", "@scope/pkg@2.0.0", "run-it"], "npm", "@scope/pkg", "2.0.0", True),
        (["npm", "exec", "-y", "--", "pkg@latest"], "npm", "pkg", "latest", False),
        (["pnpm", "dlx", "pkg@1.0.0"], "npm", "pkg", "1.0.0", True),
        (["bunx", "pkg"], "npm", "pkg", None, False),
        (["/usr/local/bin/npx", "-y", "pkg@1.0.0-beta.2"], "npm", "pkg", "1.0.0-beta.2", True),
        (["cmd", "/c", "npx", "-y", "pkg"], "npm", "pkg", None, False),
        (["npx.cmd", "-y", "pkg@1.0.0"], "npm", "pkg", "1.0.0", True),
        (["uvx", "mcp-server-git"], "pypi", "mcp-server-git", None, False),
        (["uvx", "mcp-server-git==1.2.3"], "pypi", "mcp-server-git", "==1.2.3", True),
        (["uvx", "mcp-server-git@1.2.3"], "pypi", "mcp-server-git", "@1.2.3", True),
        (["uvx", "--from", "mcp-server-git>=1", "git-mcp"], "pypi", "mcp-server-git", ">=1", False),
        (["uvx", "--python", "3.12", "pkg[cli]==2.0"], "pypi", "pkg", "==2.0", True),
        (["uv", "tool", "run", "pkg==1.0"], "pypi", "pkg", "==1.0", True),
        (["pipx", "run", "--spec", "pkg==2.0", "pkg"], "pypi", "pkg", "==2.0", True),
        (["docker", "run", "-i", "--rm", "-e", "X=1", "img:1.4"], "docker", "img", "1.4", False),
        (["docker", "run", "--env=A", f"ghcr.io/a/b@{DIGEST}"], "docker", "ghcr.io/a/b", DIGEST,
         True),
        (["podman", "run", "-i", "localhost:5000/a/b"], "docker", "localhost:5000/a/b", None,
         False),
    ],
)  # fmt: skip
def test_package_ref(argv: list[str], registry: str, name: str, spec: str | None, pinned: bool
                     ) -> None:  # fmt: skip
    ref = package_ref(_launch(*argv))
    assert ref is not None
    assert (ref.registry, ref.name, ref.spec, ref.pinned) == (registry, name, spec, pinned)


@pytest.mark.parametrize(
    "argv", [["node", "./server.js"], ["npx", "./local-dir"], ["npx", "github:a/b"], ["python"]]
)
def test_not_a_registry_package(argv: list[str]) -> None:
    assert package_ref(_launch(*argv)) is None


def test_remote_server_has_no_package() -> None:
    assert package_ref(Launch(transport="http", url="https://x.example/mcp")) is None


def test_argv_pointer_accounts_for_cmd_wrapper() -> None:
    launch = _launch("cmd", "/c", "npx", "-y", "pkg")
    ref = package_ref(launch)
    assert ref is not None
    assert argv_pointer(launch, ref.argv_index) == "/launch/args/3"
    assert argv_pointer(_launch("npx", "pkg"), 0) == "/launch/command"


def test_docker_options() -> None:
    run = docker_run(_launch("docker", "run", "--privileged", "-v", "/:/host", "--net=host", "img"))
    assert run is not None
    assert run.options == [("--privileged", None), ("-v", "/:/host"), ("--net", "host")]
    assert run.image == "img"


def test_uvx_with_requirements() -> None:
    ref = package_ref(
        _launch("uvx", "--with", "edgartools[ai]==5.62.0", "edgartools==5.62.0", "mcp")
    )
    assert ref is not None
    assert (ref.name, ref.with_requirements, ref.rest_index) == (
        "edgartools",
        ("edgartools[ai]==5.62.0",),
        4,
    )
