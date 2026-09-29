#!/usr/bin/env bash
# Pushes this repo to your GitHub. Run from inside the threatmap/ folder.
#   ./push.sh <github-username> [repo-name] [public|private]
set -euo pipefail

USER="${1:?usage: ./push.sh <github-username> [repo-name] [public|private]}"
REPO="${2:-live-threat-map}"
VIS="${3:-private}"

git config user.name  >/dev/null 2>&1 || git config user.name  "$USER"
git config user.email >/dev/null 2>&1 || git config user.email "$USER@users.noreply.github.com"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  echo "==> Using GitHub CLI"
  gh repo create "$USER/$REPO" --"$VIS" --source=. --remote=origin --push
else
  echo "==> gh CLI not available. Create the repo first at:"
  echo "    https://github.com/new   (name: $REPO, $VIS, no README/.gitignore/licence)"
  read -rp "Press Enter once the empty repo exists… "
  git remote remove origin 2>/dev/null || true
  git remote add origin "https://github.com/$USER/$REPO.git"
  git branch -M main
  git push -u origin main
fi

echo
echo "==> Done: https://github.com/$USER/$REPO"
echo "==> Now deploy (GitHub Pages will NOT work - see DEPLOY.md):"
echo "      fly launch --copy-config --no-deploy && fly deploy"
