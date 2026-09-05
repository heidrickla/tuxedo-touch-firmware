#!/usr/bin/env bash
# Install a pre-push hook that runs ci/checks.sh. Use this when no Gitea
# Actions runner is registered, or as a faster local gate.
#
#   ci/install-hooks.sh
set -eu
cd "$(dirname "$0")/.."

mkdir -p .git/hooks
cat > .git/hooks/pre-push <<'EOS'
#!/usr/bin/env bash
# Regression checks. Skip with: git push --no-verify
exec bash "$(git rev-parse --show-toplevel)/ci/checks.sh"
EOS
chmod +x .git/hooks/pre-push
echo "installed .git/hooks/pre-push"
