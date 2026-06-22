"""
Demo agent showing the agent-governance-toolkit policy engine.

Two tools are registered:
  - web_search   → allowed by policy
  - run_shell    → blocked by policy

The policy engine evaluates every tool call before execution.
"""

import json
from datetime import datetime, timezone
from agent_os.policies import PolicyEvaluator


# ---------------------------------------------------------------------------
# Tool registry — plain Python callables, no framework needed
# ---------------------------------------------------------------------------

def web_search(query: str) -> str:
    """Simulate a web search (safe tool)."""
    return f"[web_search] Results for '{query}': 3 articles found about '{query}'."


def read_file(path: str) -> str:
    """Simulate reading a file (safe tool)."""
    return f"[read_file] Contents of '{path}': <sample file content here>."


def run_shell(command: str) -> str:
    """Simulate running a shell command (dangerous — should be blocked)."""
    return f"[run_shell] $ {command}"


TOOLS = {
    "web_search": web_search,
    "read_file": read_file,
    "run_shell": run_shell,
}


# ---------------------------------------------------------------------------
# Policy-gated agent
# ---------------------------------------------------------------------------

class PolicyGatedAgent:
    def __init__(self, policy_dir: str):
        self.evaluator = PolicyEvaluator()
        self.evaluator.load_policies(policy_dir)
        self.tool_call_count = 0
        self.audit_log: list[dict] = []

    def call_tool(self, tool_name: str, args: dict, token_count: int = 100) -> dict:
        """Evaluate policy before executing a tool call."""
        self.tool_call_count += 1

        context = {
            "tool_name": tool_name,
            "token_count": token_count,
            "tool_call_count": self.tool_call_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        decision = self.evaluator.evaluate(context)

        # Always record to our local audit log
        self.audit_log.append({
            "tool": tool_name,
            "allowed": decision.allowed,
            "action": decision.action,
            "rule": decision.matched_rule,
            "reason": decision.reason,
        })

        if not decision.allowed:
            return {
                "status": "BLOCKED",
                "rule": decision.matched_rule,
                "reason": decision.reason,
            }

        # Execute the tool
        fn = TOOLS.get(tool_name)
        if fn is None:
            return {"status": "ERROR", "reason": f"Unknown tool: {tool_name}"}

        result = fn(**args)
        return {
            "status": "OK",
            "rule": decision.matched_rule,
            "output": result,
        }

    def print_audit_log(self):
        print("\n--- Audit Log ---")
        for entry in self.audit_log:
            mark = "✓" if entry["allowed"] else "✗"
            print(f"  [{mark}] {entry['tool']:20s}  action={entry['action']:6s}  rule={entry['rule']}")


# ---------------------------------------------------------------------------
# Demo run
# ---------------------------------------------------------------------------

def run_demo():
    agent = PolicyGatedAgent(policy_dir="./policies/")

    calls = [
        # Allowed: web_search
        ("web_search", {"query": "agent governance best practices"}),
        # Allowed: read_file
        ("read_file", {"path": "README.md"}),
        # BLOCKED: run_shell
        ("run_shell", {"command": "rm -rf /tmp/data"}),
        # Denied: token_count over limit
        ("web_search", {"query": "huge request"}, 5000),
    ]

    print("=== Policy Engine Demo ===\n")
    for item in calls:
        tool_name = item[0]
        args = item[1]
        token_count = item[2] if len(item) > 2 else 100

        result = agent.call_tool(tool_name, args, token_count=token_count)
        print(f"Tool: {tool_name}({json.dumps(args)})")
        print(f"  → status : {result['status']}")
        if result["status"] == "OK":
            print(f"  → output : {result['output']}")
        else:
            print(f"  → reason : {result['reason']}")
        print()

    agent.print_audit_log()


if __name__ == "__main__":
    run_demo()
