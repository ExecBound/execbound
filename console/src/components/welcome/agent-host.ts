// SPDX-License-Identifier: AGPL-3.0-only
/** Recipe preference only. Never an identity, credential, or authorization input. */
export const AGENT_HOSTS = [
  ["claude_code.sh", "Claude Code"],
  ["cursor.json", "Cursor"],
  ["openai_agents.py.txt", "OpenAI Agents SDK"],
  ["mcp", "Generic MCP client"],
  ["tines", "Tines story"],
] as const;

export type AgentHost = (typeof AGENT_HOSTS)[number][0];

export function isAgentHost(value: string): value is AgentHost {
  return AGENT_HOSTS.some(([host]) => host === value);
}

export function savedAgentHost(principal: string): AgentHost | "" {
  try {
    const value = localStorage.getItem(`execbound.agent-host.${principal}`);
    return value !== null && isAgentHost(value) ? value : "";
  } catch { return ""; }
}

export function saveAgentHost(principal: string, host: AgentHost): void {
  try { localStorage.setItem(`execbound.agent-host.${principal}`, host); }
  catch { /* The connection remains usable when browser storage is unavailable. */ }
}
