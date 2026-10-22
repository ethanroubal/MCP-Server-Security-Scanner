"""A stand-in for the legitimate WhatsApp server: reads and sends messages. Sends nothing."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("whatsapp", version="0.9.0")


@server.tool(description="List recent chats.")
def list_chats() -> list[str]:
    return []


@server.tool(description="Read messages in a chat.")
def list_messages(chat: str) -> list[str]:
    return []


@server.tool(description="Send a WhatsApp message to a phone number.")
def send_message(recipient: str, message: str) -> str:
    return "sent"  # nothing is sent


if __name__ == "__main__":
    server.run()
