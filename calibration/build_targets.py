"""Build calibration/targets.json: the most-downloaded stdio MCP servers in the official registry.

Usage: uv run python calibration/build_targets.py [--npm 60] [--pypi 25] [--oci 15] [--refresh]

Popularity is last-month downloads: npm's downloads API, hugovk's top-PyPI dataset for PyPI,
and Docker Hub pull counts for docker.io images (other OCI registries publish no counts, so
they rank last).
Each target is pinned to the registry's version and gets a client-style launch config, with
dummy values for the env vars the registry marks as required and the declared package arguments.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
CACHE = HERE / ".cache"
REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
DUMMY = "mcpscan-calibration-dummy"
USER_AGENT = "mcpscan-calibration (https://github.com/ethanroubal/MCP-Server-Security-Scanner)"


class RateLimited(Exception):
    pass


def get_json(url: str, *, attempts: int = 7) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(attempts):
        wait = 2.0**attempt
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code not in (429, 500, 502, 503, 504):
                raise
            retry_after = exc.headers.get("Retry-After", "")
            if retry_after.isdigit():
                wait = max(wait, float(retry_after))
            if attempt == attempts - 1:
                if exc.code == 429:
                    raise RateLimited(url) from exc
                raise
        except OSError:  # URLError, timeouts, dropped connections
            if attempt == attempts - 1:
                raise
        time.sleep(min(wait, 60.0))
    return None


def registry_servers(refresh: bool) -> list[dict[str, Any]]:
    cached = CACHE / "registry.json"
    if cached.is_file() and not refresh:
        return json.loads(cached.read_text(encoding="utf-8"))
    servers: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        query = {"limit": "100", **({"cursor": cursor} if cursor else {})}
        page = get_json(f"{REGISTRY}?{urllib.parse.urlencode(query)}")
        servers += page["servers"]
        cursor = page["metadata"].get("nextCursor")
        if not cursor:
            break
    latest = [s for s in servers
              if s.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
              .get("isLatest")]  # fmt: skip
    CACHE.mkdir(exist_ok=True)
    cached.write_text(json.dumps(latest), encoding="utf-8")
    print(f"registry: {len(servers)} versions, {len(latest)} latest")
    return latest


def stdio_packages(servers: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    packages: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in servers:
        server = entry["server"]
        for package in server.get("packages", []):
            kind = package.get("registryType")
            if (
                kind not in ("npm", "pypi", "oci")
                or package.get("transport", {}).get("type") != "stdio"
            ):
                continue
            packages.setdefault(
                (kind, package["identifier"]), {**package, "server": server["name"]}
            )
    return packages


def npm_downloads(name: str) -> int:
    data = get_json(
        f"https://api.npmjs.org/downloads/point/last-month/{urllib.parse.quote(name, safe='@')}"
    )
    return int((data or {}).get("downloads") or 0)


def npm_bulk_downloads(names: list[str]) -> dict[str, int]:
    """Unscoped names, up to 128 per request (npm's bulk endpoint doesn't take scoped ones)."""
    data = get_json(f"https://api.npmjs.org/downloads/point/last-month/{','.join(names)}") or {}
    return {n: int((data.get(n) or {}).get("downloads") or 0) for n in names}


TOP_PYPI = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
_top_pypi: dict[str, int] | None = None


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi_downloads(name: str) -> int:
    """Last-30-day downloads from hugovk's top-PyPI dataset (top 15k projects, one request).
    pypistats.org asks for one request per second, too slow for thousands of packages; anything
    outside the top 15k is far below the cut for calibration anyway."""
    global _top_pypi
    if _top_pypi is None:
        rows = (get_json(TOP_PYPI) or {}).get("rows", [])
        _top_pypi = {_pep503(r["project"]): int(r["download_count"]) for r in rows}
    return _top_pypi.get(_pep503(name), 0)


def oci_pulls(identifier: str) -> int:
    image = (
        identifier.split("@", 1)[0].rsplit(":", 1)[0]
        if ":" in identifier.split("/")[-1]
        else identifier
    )
    host, _, path = image.partition("/")
    if host != "docker.io" or path.count("/") != 1:
        return 0
    data = get_json(f"https://hub.docker.com/v2/repositories/{path}/")
    return int((data or {}).get("pull_count") or 0)


_SUBCOMMAND_HINTS = frozenset({"mcp", "serve", "server", "stdio", "start", "run"})


def arguments(entries: list[dict[str, Any]]) -> list[str]:
    args: list[str] = []
    for arg in entries:
        value = arg.get("value") or arg.get("default")
        if (
            value is None
            and arg.get("type") == "positional"
            and arg.get("valueHint") in (_SUBCOMMAND_HINTS)
        ):
            value = arg["valueHint"]  # e.g. scrapling: a literal `mcp` subcommand given as a hint
        if value is None and arg.get("isRequired"):
            value = DUMMY
        if value is None:
            continue
        if arg.get("type") == "named":
            args += [arg["name"], str(value)]
        else:
            args.append(str(value))
    return args


def dummy_env(package: dict[str, Any]) -> dict[str, str]:
    """Dummies for required and secret env vars (registries often mark tokens secret but not
    required), with a placeholder URL for URL-looking ones so servers don't reject the format."""
    env: dict[str, str] = {}
    for var in package.get("environmentVariables", []):
        name = var["name"]
        # Optional connection strings are validated on startup (a dummy makes the server exit
        # where leaving it unset doesn't), so only optional tokens and keys get a dummy.
        token_like = re.search(r"TOKEN|KEY|SECRET|PASSWORD|_PAT$", name) and not re.search(
            r"CONNECTION|_URI|_DSN|_URL", name
        )
        if var.get("isRequired") or (var.get("isSecret") and token_like):
            env[name] = "https://example.invalid" if name.endswith(("_URL", "_HOST")) else DUMMY
    return env


def launch_config(kind: str, package: dict[str, Any]) -> dict[str, Any]:
    identifier, version = package["identifier"], package.get("version")
    env = dummy_env(package)
    package_args = arguments(package.get("packageArguments", []))
    runtime_args = arguments(package.get("runtimeArguments", []))
    if kind == "npm":  # npm runtime args are npx flags like -y, which are always passed anyway
        spec = f"{identifier}@{version}" if version else identifier
        return {"command": "npx", "args": ["-y", spec, *package_args], "env": env}
    if kind == "pypi":  # runtime args are uvx flags, e.g. --with pkg[extra]
        spec = f"{identifier}=={version}" if version else identifier
        if "--from" in runtime_args:  # they already name the package and the command to run
            return {"command": "uvx", "args": [*runtime_args, *package_args], "env": env}
        return {"command": "uvx", "args": [*runtime_args, spec, *package_args], "env": env}
    image = (
        identifier if ":" in identifier.split("/")[-1] or not version else f"{identifier}:{version}"
    )
    forwarded = [flag for name in env for flag in ("-e", name)]
    args = ["run", "-i", "--rm", *runtime_args, *forwarded, image, *package_args]
    return {"command": "docker", "args": args, "env": env}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--npm", type=int, default=60)
    parser.add_argument("--pypi", type=int, default=25)
    parser.add_argument("--oci", type=int, default=15)
    parser.add_argument("--refresh", action="store_true", help="re-download the registry")
    options = parser.parse_args()

    packages = stdio_packages(registry_servers(options.refresh))
    counts_path = CACHE / "downloads.json"
    counts: dict[str, int | None] = (
        json.loads(counts_path.read_text(encoding="utf-8")) if counts_path.is_file() else {}
    )
    counters = {"npm": npm_downloads, "pypi": pypi_downloads, "oci": oci_pulls}
    workers = {"npm": 2, "pypi": 1, "oci": 4}
    limits = {"npm": options.npm, "pypi": options.pypi, "oci": options.oci}

    def counted(kind: str, identifier: str) -> int | None:
        try:
            return counters[kind](identifier)
        except (RateLimited, OSError):
            return None  # unknown; retried on the next run

    targets: list[dict[str, Any]] = []
    for kind in counters:
        identifiers = [i for (k, i) in packages if k == kind]
        todo = [i for i in identifiers if counts.get(f"{kind}:{i}") is None]
        if kind == "npm":
            unscoped = [i for i in todo if not i.startswith("@")]
            for start in range(0, len(unscoped), 100):
                batch = unscoped[start : start + 100]
                with contextlib.suppress(RateLimited, OSError):  # left unknown; retried next run
                    counts.update({f"npm:{n}": c for n, c in npm_bulk_downloads(batch).items()})
            counts_path.write_text(json.dumps(counts), encoding="utf-8")
            todo = [i for i in todo if i.startswith("@")]
        with ThreadPoolExecutor(workers[kind]) as pool:
            results = pool.map(lambda i, k=kind: counted(k, i), todo)
            for done, (identifier, n) in enumerate(zip(todo, results, strict=True), 1):
                counts[f"{kind}:{identifier}"] = n
                if done % 25 == 0:  # keep progress if the run is interrupted
                    counts_path.write_text(json.dumps(counts), encoding="utf-8")
        counts_path.write_text(json.dumps(counts), encoding="utf-8")

        known = {i: counts.get(f"{kind}:{i}") for i in identifiers}
        unknown = sum(n is None for n in known.values())
        ranked = sorted(identifiers, key=lambda i: -(known[i] or 0))
        top = known[ranked[0]] if ranked else 0
        print(f"{kind}: {len(identifiers)} stdio packages, top downloads {top}, unknown {unknown}")
        for identifier in ranked[: limits[kind]]:
            package = packages[(kind, identifier)]
            targets.append({
                "server": package["server"],
                "registry": kind,
                "package": identifier,
                "version": package.get("version"),
                "monthly_downloads": known[identifier],
                "config": launch_config(kind, package),
            })  # fmt: skip

    out = HERE / "targets.json"
    out.write_text(json.dumps(targets, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(targets)} targets to {out}")


if __name__ == "__main__":
    main()
