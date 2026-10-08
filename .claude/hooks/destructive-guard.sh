#!/usr/bin/env bash
# see DP.SC.198
# PreToolUse:Bash guard — blocks irreversible git/GitHub operations.
# Complements the global rm -rf blocker (which forces `trash`). Exit 2 = block.
set -euo pipefail

CMD=$(jq -r '.tool_input.command // empty' 2>/dev/null || true)
[ -z "$CMD" ] && exit 0

block() {
  echo "BLOCKED: $1" >&2
  exit 2
}

git_segment() {
  # Return only the shell segment containing `git <global-opts> <subcmd>`.
  # This prevents flags from neighbouring commands (`[ -f file ]`, `rm -f`)
  # from being attributed to `git push`.
  local subcmd="$1"
  SUBCMD="$subcmd" perl -ne '
    my $subcmd = quotemeta($ENV{"SUBCMD"});
    while (/(?:^|[;&|]\s*|\s+)(git(?:\s+(?:-C\s+\S+|--git-dir(?:=|\s+)\S+|--work-tree(?:=|\s+)\S+))*\s+$subcmd\b[^;&|]*)/g) {
      print "$1\n";
      exit 0;
    }
  ' <<< "$CMD"
}

is_git_subcmd() {
  [ -n "$(git_segment "$1")" ]
}

github_fork_create_segment() {
  # Match standard GitHub fork creation paths at the start of a shell segment
  # while allowing harmless text searches and read-only GitHub operations.
  perl -ne '
    for my $segment (split /(?:&&|\|\||[;&|\n])/) {
      $segment =~ s/^\s+//;
      $segment =~ s/^(?:(?:command|sudo)\s+)+//;
      $segment =~ s/^env(?:\s+[A-Za-z_][A-Za-z0-9_]*=\S+)*\s+//;
      $segment =~ s/^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)+//;

      if ($segment =~ /^((?:\S*\/)?gh\s+repo\s+fork\b.*)$/) {
        print "$1\n";
        exit 0;
      }

      my $fork_endpoint = qr{(?:https://api\.github\.com/|/)?repos/[^/\s"\x27?]+/[^/\s"\x27?]+/forks/?(?:[?\s"\x27#]|$)}i;
      my $explicit_get = $segment =~ /(?:^|\s)(?:-X(?:=|\s*)|--(?:method|request)(?:=|\s+))GET\b/i;
      my $explicit_post = $segment =~ /(?:^|\s)(?:-X(?:=|\s*)|--(?:method|request)(?:=|\s+))POST\b/i;
      my $gh_body = $segment =~ /(?:^|\s)(?:-[fF](?:\S+|\s)|--(?:field|raw-field|input)(?:=|\s|$))/;
      my $curl_body = $segment =~ /(?:^|\s)(?:-d(?:\S+|\s)|--(?:data(?:-ascii|-binary|-raw|-urlencode)?|json)(?:=|\s|$))/;

      if ($segment =~ /^(?:\S*\/)?gh\s+api\b/ && $segment =~ $fork_endpoint
          && !$explicit_get && ($explicit_post || $gh_body)) {
        print "$segment\n";
        exit 0;
      }
      if ($segment =~ /^(?:\S*\/)?curl\b/ && $segment =~ $fork_endpoint
          && !$explicit_get && ($explicit_post || $curl_body)) {
        print "$segment\n";
        exit 0;
      }
    }
  ' <<< "$CMD"
}

# Agent-created GitHub forks are forbidden. A repository already owned by the
# pilot does not need a fork; foreign repositories remain read-only by default.
if [ -n "$(github_fork_create_segment)" ]; then
  block "Создание GitHub fork агентом запрещено. Для чужого репозитория остановись и сообщи владельца пилоту."
fi

# git push --force / -f (allow the safe --force-with-lease)
PUSH_SEGMENT=$(git_segment push)
if [ -n "$PUSH_SEGMENT" ]; then
  PUSH_FORCE_SCAN=$(echo "$PUSH_SEGMENT" | sed -E 's/--force-with-lease(=[^[:space:]]*)?//g')
  if echo "$PUSH_FORCE_SCAN" | grep -qE -- '(^|[[:space:]])(--force([[:space:]]|=|$)|-[a-zA-Z]*f[a-zA-Z]*([[:space:]]|$))'; then
    block "git push --force запрещён. Используй --force-with-lease или согласуй с владельцем (CLAUDE.md §2)."
  fi
fi

# git reset --hard
RESET_SEGMENT=$(git_segment reset)
if [ -n "$RESET_SEGMENT" ] && echo "$RESET_SEGMENT" | grep -qE -- '(^|[[:space:]])--hard([[:space:]]|$)'; then
  block "git reset --hard запрещён (теряет незакоммиченное). Используй git stash."
fi

# git clean with delete flags (-f/-d/-x)
CLEAN_SEGMENT=$(git_segment clean)
if [ -n "$CLEAN_SEGMENT" ] && echo "$CLEAN_SEGMENT" | grep -qE -- '(^|[[:space:]])-[a-zA-Z]*[dfx]'; then
  block "git clean -fdx запрещён (удаляет неотслеживаемые файлы). Согласуй с владельцем."
fi

exit 0
