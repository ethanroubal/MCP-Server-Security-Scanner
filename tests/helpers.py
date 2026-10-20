from mcpscan.core.models import Origin, ServerSnapshot, ToolDef


def snapshot_with_description(description: str, *, name: str = "test") -> ServerSnapshot:
    return ServerSnapshot(
        id=f"t-{name}",
        name=name,
        origin=Origin(kind="snapshot", ref="tests"),
        tools=[ToolDef(name="tool", description=description)],
    )
