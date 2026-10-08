#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python3 -c 'import json, pathlib; json.loads(pathlib.Path(".codex/hooks.json").read_text())' \
  2>/dev/null || { echo "FAIL: invalid .codex/hooks.json" >&2; exit 1; }
python3 -c 'import pathlib, tomllib; tomllib.loads(pathlib.Path(".codex/config.toml").read_text())' \
  2>/dev/null || { echo "FAIL: invalid .codex/config.toml" >&2; exit 1; }

IWE_ROOT="$REPO_ROOT" bash "$REPO_ROOT/scripts/sync-agent-instructions.sh" --check >/dev/null
bash "$REPO_ROOT/scripts/sync-codex-skills.sh" --check >/dev/null
bash -n "$REPO_ROOT/scripts/codex-headless-adapter.sh"
bash -n "$REPO_ROOT/scripts/install-codex-runtime.sh"

install_target="$(mktemp -d)"
trap 'rm -rf "$install_target"' EXIT
IWE_CLAUDE_MEMORY_DIR="$install_target/.test-claude-memory" \
  bash "$REPO_ROOT/scripts/install-codex-runtime.sh" "$install_target" >/dev/null
[ -f "$install_target/AGENTS.md" ]
[ -f "$install_target/.agents/skills/day-open/SKILL.md" ]
[ -f "$install_target/.codex/config.toml" ]
[ -f "$install_target/.codex/hooks/iwe-hook-adapter.py" ]
[ -L "$install_target/memory" ]
[ -L "$install_target/.codex/iwe-memory" ]

check_engineering_guardrails() {
  local agents_file="$1"
  local verify_file="$2"
  local pr_template="$3"

  grep -Fq 'воспроизводимый сигнал перед исправлением' "$agents_file" &&
    grep -Fq 'две независимые оси' "$verify_file" &&
    grep -Fq 'общий агрегированный verdict не формируется' "$verify_file" &&
    grep -Fq 'дешёвая автоматическая защита' "$pr_template"
}

check_behaviour_protection_tracking() {
  local sandbox="$install_target/behaviour-report-fixture"
  local period="2099-01"
  local report=""

  mkdir -p "$sandbox/.claude/logs" "$sandbox/incidents" "$sandbox/guards" "$sandbox/tests"
  printf '%s\n' \
    '{"payload":{"pattern":"P42_repeat"}}' \
    '{"payload":{"pattern":"P42_repeat"}}' \
    > "$sandbox/incidents/incident-log-${period}.md"

  report=$(WORKSPACE_DIR="$sandbox" IWE_ROOT="$sandbox" \
    bash "$REPO_ROOT/.claude/lib/behaviour-report.sh" --period "$period" --json)
  echo "$report" | jq -e '
    .threshold == 2 and
    any(.patterns[]; .pattern == "P42_repeat" and .protection_state == "missing") and
    any(.recommendations[]; .pattern == "P42_repeat" and .action == "create_guardrail")
  ' >/dev/null

  : > "$sandbox/guards/P42_repeat.sh"
  : > "$sandbox/tests/P42_repeat-negative.sh"
  printf '%s\n' \
    '{"kind":"protection","pattern":"P42_repeat","guardrail_path":"guards/P42_repeat.sh","negative_self_test_path":"tests/P42_repeat-negative.sh"}' \
    > "$sandbox/.claude/logs/gate_log.jsonl"

  report=$(WORKSPACE_DIR="$sandbox" IWE_ROOT="$sandbox" \
    bash "$REPO_ROOT/.claude/lib/behaviour-report.sh" --period "$period" --json)
  echo "$report" | jq -e '
    any(.patterns[]; .pattern == "P42_repeat" and .protection_state == "registered") and
    all(.recommendations[]; .pattern != "P42_repeat" or .action != "create_guardrail")
  ' >/dev/null

  # Negative self-test: deleting its evidence must reopen the protection finding.
  rm -f "$sandbox/tests/P42_repeat-negative.sh"
  report=$(WORKSPACE_DIR="$sandbox" IWE_ROOT="$sandbox" \
    bash "$REPO_ROOT/.claude/lib/behaviour-report.sh" --period "$period" --json)
  echo "$report" | jq -e '
    any(.patterns[]; .pattern == "P42_repeat" and .protection_state == "incomplete") and
    any(.recommendations[]; .pattern == "P42_repeat" and .action == "complete_guardrail_evidence")
  ' >/dev/null
}

check_engineering_guardrails \
  "$install_target/AGENTS.md" \
  "$install_target/.agents/skills/verify/SKILL.md" \
  "$REPO_ROOT/.github/PULL_REQUEST_TEMPLATE.md"

# The guard must fail if a mandatory rule disappears from a direct consumer.
tampered_agents="$install_target/AGENTS-without-repro-rule.md"
grep -Fv 'воспроизводимый сигнал перед исправлением' \
  "$install_target/AGENTS.md" > "$tampered_agents"
if check_engineering_guardrails \
  "$tampered_agents" \
  "$install_target/.agents/skills/verify/SKILL.md" \
  "$REPO_ROOT/.github/PULL_REQUEST_TEMPLATE.md"; then
  echo "FAIL: engineering guardrail detector accepted a missing repro rule" >&2
  exit 1
fi

check_behaviour_protection_tracking

# Existing user config is seed-only and must survive a refresh.
printf '# user config\n' > "$install_target/.codex/config.toml"
IWE_CLAUDE_MEMORY_DIR="$install_target/.test-claude-memory" \
  bash "$REPO_ROOT/scripts/install-codex-runtime.sh" "$install_target" >/dev/null
grep -q '^# user config$' "$install_target/.codex/config.toml"
grep -q '^memories = true$' "$install_target/.codex/config.toml"

source_skill_count="$(find "$REPO_ROOT/.claude/skills" -mindepth 1 -maxdepth 1 -type d | wc -l)"
codex_skill_count="$(find "$REPO_ROOT/.agents/skills" -mindepth 1 -maxdepth 1 -type d | wc -l)"
if [ "$source_skill_count" -ne "$codex_skill_count" ]; then
  echo "FAIL: Codex skill inventory differs from canonical inventory" >&2
  exit 1
fi

if rg -n '^  executor: (opus|sonnet|haiku)$|^  model: (opus|sonnet|haiku)$' \
  "$REPO_ROOT/.agents/skills" --glob 'SKILL.md' >/dev/null; then
  echo "FAIL: generated skills contain provider-specific execution metadata" >&2
  exit 1
fi

if printf '%s\n' '{"tool_input":{"command":"git reset --hard HEAD"}}' \
  | bash "$REPO_ROOT/.claude/hooks/destructive-guard.sh" >/dev/null 2>&1; then
  echo "FAIL: destructive guard allowed git reset --hard" >&2
  exit 1
fi

printf '%s\n' '{"tool_input":{"command":"git status --short"}}' \
  | bash "$REPO_ROOT/.claude/hooks/destructive-guard.sh" >/dev/null

echo "PASS: Codex config, generated skills, adapter, and safety hook"
