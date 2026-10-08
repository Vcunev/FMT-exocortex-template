#!/usr/bin/env bash
# behaviour-report.sh
# see DP.SC.026 (мониторинг поведения агента), WP-229 Ф8
# Агрегатор паттернов: читает gate_log + все incident-log → сводка по P{N}.
#
# Поддерживает три формата:
#   (A) JSON payload из автодетекторов: {"payload": {"pattern": "P1_not_capturing"}}
#   (B) YAML-блок из ручных записей:   pattern: P5
#   (C) JSON-регистрацию защиты в gate_log.jsonl:
#       {"kind":"protection","pattern":"P5","guardrail_path":"...","negative_self_test_path":"..."}
#
# Использование:
#   behaviour-report.sh [--period YYYY-MM] [--threshold N] [--json]
#
#   --period YYYY-MM   период (default: текущий месяц)
#   --threshold N      порог обязательной автоматической защиты (default: 2)
#   --json             вывод в JSON вместо текста

set -uo pipefail
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

# Load unified environment: WORKSPACE_DIR, IWE_ROOT, IWE_SCRIPTS, etc.
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./iwe-env-bootstrap.sh
source "$LIB_DIR/iwe-env-bootstrap.sh" || exit 1
PERIOD=$(date +%Y-%m)
THRESHOLD=2
OUTPUT_JSON=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --period) PERIOD="$2"; shift 2 ;;
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --json) OUTPUT_JSON=1; shift ;;
    *) shift ;;
  esac
done

# Временные файлы для агрегации (key=паттерн, value=count через sort|uniq -c)
TMP_GATE_ALL=$(mktemp /tmp/br_gate_all.XXXX)
TMP_GATE_FIRED=$(mktemp /tmp/br_gate_fired.XXXX)
TMP_INCIDENTS=$(mktemp /tmp/br_incidents.XXXX)
TMP_PROTECTIONS=$(mktemp /tmp/br_protections.XXXX)
trap "rm -f $TMP_GATE_ALL $TMP_GATE_FIRED $TMP_INCIDENTS $TMP_PROTECTIONS" EXIT

# --- Шаг 1: gate_log ---
GATE_LOG="$IWE_ROOT/.claude/logs/gate_log.jsonl"
if [ -f "$GATE_LOG" ]; then
  while IFS= read -r line; do
    kind=$(echo "$line" | jq -r '.kind // empty' 2>/dev/null)
    if [ "$kind" = "protection" ]; then
      protection=$(echo "$line" | jq -c '
        select((.pattern // "") != "") |
        {
          pattern: .pattern,
          guardrail_path: (.guardrail_path // ""),
          negative_self_test_path: (.negative_self_test_path // "")
        }
      ' 2>/dev/null)
      [ -n "$protection" ] && echo "$protection" >> "$TMP_PROTECTIONS"
      continue
    fi

    ts=$(echo "$line" | jq -r '.ts // empty' 2>/dev/null)
    [[ "$ts" != "${PERIOD}"* ]] && continue
    pat=$(echo "$line" | jq -r '.pattern // empty' 2>/dev/null)
    [ -z "$pat" ] && continue
    fired=$(echo "$line" | jq -r '.fired // "false"' 2>/dev/null)
    echo "$pat" >> "$TMP_GATE_ALL"
    [ "$fired" = "true" ] && echo "$pat" >> "$TMP_GATE_FIRED"
  done < "$GATE_LOG"
fi

# --- Шаг 2: все incident-log файлы ---
while IFS= read -r logfile; do
  [ -f "$logfile" ] || continue

  # Формат A: JSON  "pattern": "P1_not_capturing"
  grep -o '"pattern"[[:space:]]*:[[:space:]]*"[^"]*"' "$logfile" 2>/dev/null \
    | sed 's/.*"pattern"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
    >> "$TMP_INCIDENTS" || true

  # Формат B: YAML  pattern: P5  (с отступом или без; может быть "P2, P5 (×3)")
  grep -E 'pattern:[[:space:]]*P[0-9]' "$logfile" 2>/dev/null \
    | grep -oE 'P[0-9]+[a-zA-Z_]*' \
    >> "$TMP_INCIDENTS" || true

done < <(find "$IWE_ROOT" -name "incident-log-${PERIOD}.md" -not -path "*/.git/*" 2>/dev/null)

# --- Шаг 3: подсчёт ---
# Функция: count pattern in file
count_pat() {
  local pat="$1" file="$2"
  [ -f "$file" ] || { echo "0"; return; }
  local n
  n=$(grep -c "^${pat}$" "$file" 2>/dev/null) || n=0
  echo "${n:-0}"
}

evidence_file_exists() {
  local path="$1"
  [ -n "$path" ] || return 1
  case "$path" in
    /*) [ -f "$path" ] ;;
    *)  [ -f "$IWE_ROOT/$path" ] ;;
  esac
}

# Sets four globals for one pattern: REQUIRES_PROTECTION, PROTECTION_STATE,
# GUARDRAIL_PATH, NEGATIVE_SELF_TEST_PATH.
load_protection_state() {
  local pat="$1" total="$2" record=""
  REQUIRES_PROTECTION=false
  PROTECTION_STATE="not_required"
  GUARDRAIL_PATH=""
  NEGATIVE_SELF_TEST_PATH=""

  [ "$total" -ge "$THRESHOLD" ] || return 0
  REQUIRES_PROTECTION=true
  PROTECTION_STATE="missing"

  record=$(jq -c --arg pattern "$pat" 'select(.pattern == $pattern)' \
    "$TMP_PROTECTIONS" 2>/dev/null | tail -1)
  [ -n "$record" ] || return 0

  GUARDRAIL_PATH=$(echo "$record" | jq -r '.guardrail_path // empty')
  NEGATIVE_SELF_TEST_PATH=$(echo "$record" | jq -r '.negative_self_test_path // empty')
  if evidence_file_exists "$GUARDRAIL_PATH" && evidence_file_exists "$NEGATIVE_SELF_TEST_PATH"; then
    PROTECTION_STATE="registered"
  else
    PROTECTION_STATE="incomplete"
  fi
}

# Собрать список всех уникальных паттернов
ALL_PATS=$(cat "$TMP_GATE_ALL" "$TMP_GATE_FIRED" "$TMP_INCIDENTS" 2>/dev/null \
  | sort -u)

if [ -z "$ALL_PATS" ]; then
  if [ "$OUTPUT_JSON" = "1" ]; then
    echo "{\"period\":\"$PERIOD\",\"patterns\":[],\"recommendations\":[]}"
  else
    echo "behaviour-report: нет данных за $PERIOD"
  fi
  exit 1
fi

# --- Шаг 4: сводка ---
INCIDENT_FILE_COUNT=$(find "$IWE_ROOT" -name "incident-log-${PERIOD}.md" \
  -not -path "*/.git/*" 2>/dev/null | wc -l | tr -d ' ')

if [ "$OUTPUT_JSON" = "1" ]; then
  # JSON output
  PATTERNS_ARR="["
  RECS_ARR="["
  first_p=1
  first_r=1

  while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    gate_total=$(count_pat "$pat" "$TMP_GATE_ALL")
    gate_fired=$(count_pat "$pat" "$TMP_GATE_FIRED")
    incidents=$(count_pat "$pat" "$TMP_INCIDENTS")
    total=$(( gate_fired + incidents ))
    load_protection_state "$pat" "$total"

    [ "$first_p" = "0" ] && PATTERNS_ARR+=","
    PATTERNS_ARR+=$(jq -cn \
      --arg pattern "$pat" \
      --argjson gate_total "$gate_total" \
      --argjson gate_fired "$gate_fired" \
      --argjson incidents "$incidents" \
      --argjson total "$total" \
      --argjson requires_protection "$REQUIRES_PROTECTION" \
      --arg protection_state "$PROTECTION_STATE" \
      --arg guardrail_path "$GUARDRAIL_PATH" \
      --arg negative_self_test_path "$NEGATIVE_SELF_TEST_PATH" \
      '{pattern:$pattern, gate_total:$gate_total, gate_fired:$gate_fired,
        incidents:$incidents, total:$total, requires_protection:$requires_protection,
        protection_state:$protection_state, guardrail_path:$guardrail_path,
        negative_self_test_path:$negative_self_test_path}')
    first_p=0

    # Рекомендации по качеству существующего гейта.
    if [ "$gate_total" -gt 0 ]; then
      fp=$(( gate_total - gate_fired ))
      fp_rate=$(( fp * 100 / gate_total ))
      if [ "$fp_rate" -gt 10 ]; then
        [ "$first_r" = "0" ] && RECS_ARR+=","
        RECS_ARR+=$(jq -cn --arg pattern "$pat" --argjson total "$total" \
          '{pattern:$pattern, action:"revert_gate", total:$total}')
        first_r=0
      fi
    fi

    # Второй подтверждённый сбой требует защиты и отдельного отрицательного теста.
    rec_code=""
    case "$PROTECTION_STATE" in
      missing)    rec_code="create_guardrail" ;;
      incomplete) rec_code="complete_guardrail_evidence" ;;
    esac
    if [ -n "$rec_code" ]; then
      [ "$first_r" = "0" ] && RECS_ARR+=","
      RECS_ARR+=$(jq -cn --arg pattern "$pat" --arg action "$rec_code" \
        --argjson total "$total" \
        '{pattern:$pattern, action:$action, total:$total}')
      first_r=0
    fi
  done <<< "$ALL_PATS"

  PATTERNS_ARR+="]"
  RECS_ARR+="]"
  echo "{\"period\":\"$PERIOD\",\"threshold\":$THRESHOLD,\"patterns\":${PATTERNS_ARR},\"recommendations\":${RECS_ARR}}"

else
  # Text output
  echo "=== Behaviour Report: ${PERIOD} (порог: ≥${THRESHOLD} → автоматическая защита) ==="
  echo ""
  printf "%-30s %10s %12s %11s  %s\n" "Паттерн" "gate/fired" "incidents" "итого" "Статус"
  printf "%-30s %10s %12s %11s  %s\n" "-------" "----------" "---------" "-----" "------"

  while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    gate_total=$(count_pat "$pat" "$TMP_GATE_ALL")
    gate_fired=$(count_pat "$pat" "$TMP_GATE_FIRED")
    incidents=$(count_pat "$pat" "$TMP_INCIDENTS")
    total=$(( gate_fired + incidents ))
    load_protection_state "$pat" "$total"

    # Статус
    status=""
    if [ "$gate_total" -gt 0 ]; then
      fp=$(( gate_total - gate_fired ))
      fp_rate=$(( fp * 100 / gate_total ))
      if [ "$fp_rate" -gt 10 ]; then
        status="⚠️  FP ${fp_rate}% → откатить гейт"
      fi
    fi
    if [ "$REQUIRES_PROTECTION" = "true" ]; then
      case "$PROTECTION_STATE" in
        registered) status="${status:+$status; }✅ защита + отрицательный тест зарегистрированы" ;;
        incomplete) status="${status:+$status; }🔴 неполные/устаревшие свидетельства защиты" ;;
        missing)    status="${status:+$status; }🔴 создать автоматическую защиту" ;;
      esac
    fi
    if [ -z "$status" ]; then
      status="📊 копим (${total}/${THRESHOLD})"
    fi

    printf "%-30s %10s %12s %11s  %s\n" \
      "$pat" "${gate_fired}/${gate_total}" "$incidents" "$total" "$status"
  done <<< "$ALL_PATS"

  echo ""
  echo "Источники: gate_log + ${INCIDENT_FILE_COUNT} incident-log файл(ов) в ~/IWE/"
  echo "Запустить: ~/.claude/lib/behaviour-report.sh [--period YYYY-MM] [--threshold N] [--json]"
fi

exit 0
