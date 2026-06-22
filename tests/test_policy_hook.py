"""Tests for PolicyEnforcementHook — YAML policy evaluation via Strands hooks."""

import pytest
from strands.agent import Agent

from strands_agent import PolicyEnforcementHook, read_file, run_shell, web_search

POLICY_DIR = "./policies/"


@pytest.fixture
def agent_with_policy():
    hook = PolicyEnforcementHook(policy_dir=POLICY_DIR)
    agent = Agent(model=None, tools=[web_search, read_file, run_shell], hooks=[hook])
    return agent, hook


def _text(result: dict) -> str:
    content = result.get("content", [])
    return content[0].get("text", "") if content else ""


class TestAllowedTools:
    def test_web_search_is_allowed(self, agent_with_policy):
        agent, hook = agent_with_policy
        result = agent.tool.web_search(query="governance")
        assert result["status"] == "success"
        assert "[web_search]" in _text(result)

    def test_read_file_is_allowed(self, agent_with_policy):
        agent, hook = agent_with_policy
        result = agent.tool.read_file(path="README.md")
        assert result["status"] == "success"
        assert "[read_file]" in _text(result)

    def test_allowed_tool_logged_in_audit(self, agent_with_policy):
        agent, hook = agent_with_policy
        agent.tool.web_search(query="test")
        entry = hook.audit_log[-1]
        assert entry["allowed"] is True
        assert entry["rule"] == "allow_web_search"
        assert entry["action"] == "allow"


class TestBlockedTools:
    def test_run_shell_is_blocked(self, agent_with_policy):
        agent, hook = agent_with_policy
        result = agent.tool.run_shell(command="ls")
        text = _text(result)
        assert result["status"] == "error"
        assert "[POLICY]" in text
        assert "block_shell" in text

    def test_run_shell_logged_as_blocked(self, agent_with_policy):
        agent, hook = agent_with_policy
        agent.tool.run_shell(command="ls")
        entry = hook.audit_log[-1]
        assert entry["allowed"] is False
        assert entry["rule"] == "block_shell"
        assert entry["action"] == "block"


class TestTokenLimit:
    def test_over_limit_is_denied(self, agent_with_policy):
        agent, hook = agent_with_policy
        result = agent.tool.web_search(query="big", token_count=5000)
        text = _text(result)
        assert result["status"] == "error"
        assert "[POLICY]" in text
        assert "token_limit" in text

    def test_at_limit_is_allowed(self, agent_with_policy):
        agent, hook = agent_with_policy
        result = agent.tool.web_search(query="ok", token_count=4096)
        assert result["status"] == "success"

    def test_under_limit_is_allowed(self, agent_with_policy):
        agent, hook = agent_with_policy
        result = agent.tool.web_search(query="ok", token_count=100)
        assert result["status"] == "success"


class TestAuditLog:
    def test_every_call_is_logged(self, agent_with_policy):
        agent, hook = agent_with_policy
        agent.tool.web_search(query="a")
        agent.tool.read_file(path="b.txt")
        agent.tool.run_shell(command="c")
        assert len(hook.audit_log) == 3

    def test_log_entries_have_required_fields(self, agent_with_policy):
        agent, hook = agent_with_policy
        agent.tool.web_search(query="test")
        entry = hook.audit_log[0]
        for field in ("layer", "tool", "allowed", "action", "rule", "reason"):
            assert field in entry

    def test_call_count_increments(self, agent_with_policy):
        agent, hook = agent_with_policy
        agent.tool.web_search(query="first")
        agent.tool.web_search(query="second")
        assert hook._call_count == 2
