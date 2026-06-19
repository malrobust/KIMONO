from typing import Any, Callable, Dict, List

from toride.guard import AgentGuard
from toride.policy import Decision
from toride.provenance import Source


class RequireApprovalError(Exception):
    """Raised when an action requires human approval."""

    def __init__(self, action_type: str, payload: Any, source_content_ids: List[str]):
        self.action_type = action_type
        self.payload = payload
        self.source_content_ids = source_content_ids
        super().__init__(f"Action '{action_type}' requires human approval.")


def determine_source_from_message(message: Any) -> Source:
    """
    Heuristically maps a LangGraph/LangChain message object or dictionary to a Source enum.
    """
    msg_type = ""
    if hasattr(message, "type"):
        msg_type = message.type
    elif isinstance(message, dict):
        msg_type = message.get("type", "")

    class_name = message.__class__.__name__

    if msg_type == "human" or "HumanMessage" in class_name:
        return Source.USER
    elif msg_type == "system" or "SystemMessage" in class_name:
        return Source.SYSTEM
    elif msg_type == "tool" or "ToolMessage" in class_name:
        tool_name = ""
        if hasattr(message, "name"):
            tool_name = message.name
        elif isinstance(message, dict):
            tool_name = message.get("name", "")

        if tool_name:
            tool_name_lower = tool_name.lower()
            if any(w in tool_name_lower for w in ["web", "fetch", "curl", "http"]):
                return Source.WEB_FETCH
            elif any(w in tool_name_lower for w in ["file", "read"]):
                return Source.FILE_READ
            elif "mail" in tool_name_lower:
                return Source.EMAIL
        return Source.TOOL_OUTPUT

    return Source.USER


def get_message_content(message: Any) -> str:
    """Helper to extract content string from a message object or dictionary."""
    if hasattr(message, "content"):
        return str(message.content)
    elif isinstance(message, dict):
        return str(message.get("content", ""))
    return str(message)


class LangGraphAgentGuardAdapter:
    def __init__(self, guard: AgentGuard):
        self.guard = guard
        # Avoid duplicate ingestion by mapping message ID/hash to registered TaggedContent ID
        self.message_to_tagged_id: Dict[str, str] = {}

    def sync_state(self, messages: List[Any]) -> List[str]:
        """
        Synchronizes LangGraph/LangChain messages with the AgentGuard taint registry.

        Returns list of TaggedContent IDs for all messages in the conversation history.
        """
        tagged_ids = []
        parent_ids = []

        for idx, msg in enumerate(messages):
            msg_content = get_message_content(msg)

            # Identify message uniqueness
            msg_id = getattr(msg, "id", None) or (
                isinstance(msg, dict) and msg.get("id")
            )
            if not msg_id:
                msg_id = f"msg_{idx}_{hash(msg_content)}"

            if msg_id in self.message_to_tagged_id:
                tagged_ids.append(self.message_to_tagged_id[msg_id])
                parent_ids.append(self.message_to_tagged_id[msg_id])
                continue

            source = determine_source_from_message(msg)
            class_name = msg.__class__.__name__
            msg_type = getattr(msg, "type", "")
            is_ai = msg_type == "ai" or "AIMessage" in class_name

            if is_ai:
                # AI Message propagates previous taint (parent_ids represent conversation history)
                tagged = self.guard.ingest(
                    content=msg_content,
                    source=Source.SYSTEM,
                    parent_ids=list(parent_ids),
                )
            else:
                tagged = self.guard.ingest(
                    content=msg_content, source=source, parent_ids=list(parent_ids)
                )

            self.message_to_tagged_id[msg_id] = tagged.id
            tagged_ids.append(tagged.id)
            parent_ids.append(tagged.id)

        return tagged_ids

    def check_tool_call(
        self, tool_name: str, tool_args: Any, messages: List[Any]
    ) -> Decision:
        """
        Intercepts a tool call, computes taint across the message history,
        and evaluates it through AgentGuard.

        Raises BlockedActionError on Decision.BLOCK.
        Raises RequireApprovalError on Decision.REQUIRE_APPROVAL.
        """
        tagged_ids = self.sync_state(messages)
        decision = self.guard.check_action(
            action_type=tool_name, payload=tool_args, source_content_ids=tagged_ids
        )

        if decision == Decision.REQUIRE_APPROVAL:
            raise RequireApprovalError(tool_name, tool_args, tagged_ids)

        return decision


def guard_tool(guard: AgentGuard) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    A decorator to wrap individual tool functions with AgentGuard.
    Expects a keyword argument 'messages' representing the context history.
    """
    adapter = LangGraphAgentGuardAdapter(guard)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages", [])
            payload = {
                "args": args,
                "kwargs": {k: v for k, v in kwargs.items() if k != "messages"},
            }

            adapter.check_tool_call(
                tool_name=func.__name__, tool_args=payload, messages=messages
            )
            return func(*args, **kwargs)

        return wrapper

    return decorator
