from mcpscan.core.models import Origin, PromptArgument, PromptDef, ServerSnapshot, ToolDef
from mcpscan.core.text import iter_text_fields, pointer_token, reveal


def test_walks_nested_schema_text() -> None:
    snapshot = ServerSnapshot(
        id="s",
        name="s",
        origin=Origin(kind="snapshot", ref="x"),
        tools=[
            ToolDef(
                name="t",
                description="top",
                input_schema={
                    "type": "object",
                    "properties": {
                        "a/b": {
                            "type": "object",
                            "properties": {"deep": {"description": "hidden", "enum": ["x", 1]}},
                        },
                    },
                },
            )
        ],
        prompts=[PromptDef(name="p", arguments=[PromptArgument(name="arg", description="d")])],
    )
    fields = {tf.location.json_pointer: tf for tf in iter_text_fields(snapshot)}

    deep = "/tools/0/inputSchema/properties/a~1b/properties/deep"
    assert fields[f"{deep}/description"].text == "hidden"
    assert fields[f"{deep}/enum/0"].text == "x"
    assert f"{deep}/enum/1" not in fields  # non-strings skipped
    assert fields["/tools/0/inputSchema/properties/a~1b"].kind == "property-name"
    assert fields["/tools/0/description"].location.tool == "t"
    assert fields["/prompts/0/arguments/0/description"].location.prompt == "p"


def test_pointer_token_escaping() -> None:
    assert pointer_token("a~b/c") == "a~0b~1c"


def test_reveal_neutralizes_terminal_escapes_and_invisibles() -> None:
    assert reveal("\x1b[2Jhi") == "⟨U+001B⟩[2Jhi"
    assert reveal("a\u200bb") == "a⟨U+200B⟩b"
    assert reveal("\U000e0041") == "⟨U+E0041⟩"
    assert reveal("line1\nline2") == "line1\nline2"
