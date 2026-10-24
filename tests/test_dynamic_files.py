"""Descriptor lifetime, aliases and data-free syscall evidence for the dynamic sensor."""

from __future__ import annotations

from mcpiranha.core.models import DynamicObservation, Origin, ServerSnapshot
from mcpiranha.core.pipeline import scan
from mcpiranha.dynamic.trace import observations
from mcpiranha.rules import load_rules


def trace(*lines: str) -> list[DynamicObservation]:
    return observations(
        "\n".join(f"1 1800000000.{i:06} {line}" for i, line in enumerate(lines)), []
    )


def test_inherited_duplicated_reads_and_readable_mappings() -> None:
    events = observations(
        "\n".join(
            [
                '1 1800000000.001 open("/tmp/mcpiranha-home/.ssh/id_rsa", O_RDONLY) = 3',
                "1 1800000000.002 dup(3) = 4",
                "1 1800000000.003 close(3) = 0",
                "1 1800000000.004 clone(child_stack=NULL, flags=SIGCHLD) = 2",
                "2 1800000000.005 read(0x4, 0xdeadbeef, 0x100) = 0x21",
                "2 1800000000.006 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 4, 0) = 0x7fff0000",
                "2 1800000000.007 close(4) = 0",
                "2 1800000000.008 read(0x4, 0xdeadbeef, 0x100) = -1 EBADF (Bad file descriptor)",
            ]
        ),
        [],
    )
    accesses = [e for e in events if e.kind == "file_access"]
    assert [e.syscall for e in accesses] == ["read", "mmap"]
    assert accesses[0].byte_count == 33
    assert all(e.honeytoken == "/tmp/mcpiranha-home/.ssh/id_rsa" for e in accesses)
    assert not any("SYNTHETIC_ONLY" in e.detail for e in events)


def test_descriptor_sharing_and_close_on_exec_prevent_stale_attribution() -> None:
    shared = observations(
        "\n".join(
            [
                '1 1800000000.001 open("/tmp/mcpiranha-home/.env", O_RDONLY) = 3',
                "1 1800000000.002 clone(flags=CLONE_FILES|CLONE_VM) = 2",
                "2 1800000000.003 close(3) = 0",
                "1 1800000000.004 read(0x3, 0xdeadbeef, 0x100) = 0x10",
            ]
        ),
        [],
    )
    assert not any(e.kind == "file_access" for e in shared)
    events = trace(
        'open("/tmp/mcpiranha-home/.env", O_RDONLY|O_CLOEXEC) = 3',
        "dup3(3, 9, O_CLOEXEC) = 9",
        'execve("/usr/bin/program", ["program"], []) = 0',
        "read(0x9, 0xdeadbeef, 0x100) = 0x10",
        'open("/tmp/ordinary", O_RDONLY) = 3',
        "read(0x3, 0xdeadbeef, 0x100) = 0x10",
    )
    assert not any(e.kind == "file_access" for e in events)


def test_hardlink_and_rename_aliases_retain_identity_but_replacement_does_not() -> None:
    events = trace(
        'link("/tmp/mcpiranha-home/.ssh/id_rsa", "/tmp/alias") = 0',
        'rename("/tmp/alias", "/tmp/moved") = 0',
        'open("/tmp/moved", O_RDONLY) = 3',
        "read(0x3, 0xdeadbeef, 0x100) = 0x21",
        "close(3) = 0",
        'unlink("/tmp/moved") = 0',
        'open("/tmp/moved", O_CREAT|O_WRONLY, 0600) = 3',
        "close(3) = 0",
        'open("/tmp/moved", O_RDONLY) = 3',
        "read(0x3, 0xdeadbeef, 0x100) = 0x20",
    )
    access = [e for e in events if e.kind == "file_access"]
    assert len(access) == 1 and access[0].path == "/tmp/moved"
    snapshot = ServerSnapshot(
        id="test", name="test", origin=Origin(kind="path", ref="test"), observations=events
    )
    findings = scan([snapshot], load_rules(plugins=False)).findings
    assert any(
        f.rule_id == "MCP-DY-003" and any("rename" in e.text for e in f.evidence) for f in findings
    )


def test_unreadable_or_failed_mappings_do_not_claim_data_access() -> None:
    events = trace(
        'open("/tmp/mcpiranha-home/.env", O_RDONLY) = 3',
        "read(0x3, 0xdeadbeef, 0x100) = 0",
        "mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE, 3, 0) = 0x7fff0000",
        "mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3, 0) = -1 ENOMEM (Out of memory)",
        "mmap(NULL, 4096, PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0) = 0x7fff0000",
    )
    assert not any(e.kind == "file_access" for e in events)


def test_split_clone_is_applied_before_child_reads_and_directory_rename_is_followed() -> None:
    events = observations(
        "\n".join(
            [
                '1 1800000000.001 rename("/tmp/mcpiranha-home/.ssh", "/tmp/stolen") = 0',
                '1 1800000000.002 open("/tmp/stolen/id_rsa", O_RDONLY) = 3',
                "1 1800000000.003 clone(flags=SIGCHLD <unfinished ...>",
                "2 1800000000.004 read(0x3, 0xdeadbeef, 0x100) = 0x21",
                "1 1800000000.005 <... clone resumed>) = 2",
            ]
        ),
        [],
    )
    access = next(e for e in events if e.kind == "file_access")
    assert access.path == "/tmp/stolen/id_rsa"
    assert access.honeytoken == "/tmp/mcpiranha-home/.ssh/id_rsa"
    snapshot = ServerSnapshot(
        id="test", name="test", origin=Origin(kind="path", ref="test"), observations=events
    )
    findings = [
        f for f in scan([snapshot], load_rules(plugins=False)).findings if f.rule_id == "MCP-DY-003"
    ]
    assert len(findings) == 1 and "read 33 byte" in findings[0].rationale


def test_close_range_dup2_self_and_unshared_tables() -> None:
    events = observations(
        "\n".join(
            [
                '1 1800000000.001 open("/tmp/mcpiranha-home/.env", O_RDONLY) = 3',
                "1 1800000000.002 clone(flags=CLONE_FILES|CLONE_VM) = 2",
                "2 1800000000.003 close_range(3, 20, CLOSE_RANGE_UNSHARE) = 0",
                "1 1800000000.004 read(0x3, 0xdeadbeef, 0x100) = 0x10",
                "2 1800000000.005 read(0x3, 0xdeadbeef, 0x100) = 0x10",
                "1 1800000000.006 fcntl(3, F_SETFD, FD_CLOEXEC) = 0",
                "1 1800000000.007 dup2(3, 3) = 3",
                '1 1800000000.008 execve("/usr/bin/program", ["program"], []) = 0',
                "1 1800000000.009 read(0x3, 0xdeadbeef, 0x100) = 0x10",
            ]
        ),
        [],
    )
    assert len([e for e in events if e.kind == "file_access"]) == 1


def test_flag_like_alias_names_do_not_change_descriptor_lifetime() -> None:
    events = trace(
        'link("/tmp/mcpiranha-home/.env", "/tmp/O_CLOEXEC_FD_CLOEXEC") = 0',
        'open("/tmp/O_CLOEXEC_FD_CLOEXEC", O_RDONLY) = 3</tmp/O_CLOEXEC_FD_CLOEXEC>',
        "dup(3</tmp/O_CLOEXEC_FD_CLOEXEC>) = 4</tmp/O_CLOEXEC_FD_CLOEXEC>",
        "fcntl(4</tmp/O_CLOEXEC_FD_CLOEXEC>, F_SETFD, 0) = 0",
        'execve("/usr/bin/program", ["program"], []) = 0',
        "read(0x4, 0xdeadbeef, 0x100) = 0x20",
        "close_range(3, ~0U, 0) = 0",
        "read(0x4, 0xdeadbeef, 0x100) = 0x20",
    )
    assert len([event for event in events if event.kind == "file_access"]) == 1
