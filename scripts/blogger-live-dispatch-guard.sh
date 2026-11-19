#!/usr/bin/env bash
# Fail-closed secondary authorization control for Blogger write operations.
# Evaluated before costly dependencies and again immediately before publisher.
# No token handling, network access, repository writes or Blogger mutations.
set -euo pipefail

event="${GITHUB_EVENT_NAME:-}"
dry_run="${CDB_BLOGGER_DRY_RUN_INPUT:-true}"
count="${MAX_POSTS_PER_RUN:-}"
ready="${CDB_BLOGGER_OAUTH_READY:-}"
canary_approved="${CDB_BLOGGER_CANARY_APPROVED:-false}"

case "$count" in 1|2|3|4) ;; *)
  echo "::error title=Blogger dispatch blocked::Invalid bounded post count"
  exit 2
  ;; esac

if [ "$event" = "workflow_dispatch" ]; then
  if [ "$dry_run" = "true" ]; then
    echo "P0_BLOGGER_DISPATCH_AUTH=READ_ONLY_DRY_RUN"
    return 0 2>/dev/null || exit 0
  fi
  if [ "$dry_run" != "false" ]; then
    echo "::error title=Blogger dispatch blocked::Unexpected dry_run value"
    exit 2
  fi
  if [ "$count" = "1" ]; then
    if [ "$canary_approved" = "true" ]; then
      echo "P0_BLOGGER_DISPATCH_AUTH=EXPLICIT_ONE_POST_CANARY"
      return 0 2>/dev/null || exit 0
    fi
    echo "::error title=Blogger dispatch blocked::One-post live canary requires live_canary_approved=true"
    exit 2
  fi
  if [ "$ready" != "true" ]; then
    echo "::error title=Blogger dispatch blocked::Multi-post live dispatch requires BLOGGER_OAUTH_READY=true"
    exit 2
  fi
  echo "P0_BLOGGER_DISPATCH_AUTH=READY_MULTI_POST_BATCH"
  return 0 2>/dev/null || exit 0
fi

# A scheduled or push publication is permitted only after operator readiness.
# Workflow's job-level if: also implements this check; here it is enforced
# immediately before execution as defense in depth.
if [ "$event" = "schedule" ] || [ "$event" = "push" ]; then
  if [ "$ready" = "true" ]; then
    echo "P0_BLOGGER_DISPATCH_AUTH=READY_AUTOMATED_WRITE"
    return 0 2>/dev/null || exit 0
  fi
fi
echo "::error title=Blogger dispatch blocked::Unknown or unready write trigger"
exit 2
