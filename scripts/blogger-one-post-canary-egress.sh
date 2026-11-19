# P0-CANARY-SOCIAL-EGRESS: sourced by the Blogger workflow's bash step.
# Limit the side effects of an explicitly selected one-post manual live canary.
# This code does NOT authorize the Blogger post itself; publishing still
# requires operator approval, branch controls, and the existing quality gates.
#
# Do not execute this script as a subprocess: it must clear variables in the
# current shell before Python loads its Config from the environment.
if [ "${GITHUB_EVENT_NAME:-}" = "workflow_dispatch" ] &&
   [ "${CDB_BLOGGER_DRY_RUN_INPUT:-true}" = "false" ] &&
   [ "${MAX_POSTS_PER_RUN:-}" = "1" ]; then
  unset TWITTER_API_KEY TWITTER_API_SECRET
  unset TWITTER_ACCESS_TOKEN TWITTER_ACCESS_SECRET
  echo 'P0_ONE_POST_CANARY_X_AMPLIFICATION=DISABLED'
fi
