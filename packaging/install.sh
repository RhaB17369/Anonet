#!/usr/bin/env bash
# Builds anonet in release mode and installs it system-wide. Run from
# anywhere: ./packaging/install.sh
#
# Needs sudo for the actual install step (copying into /usr/local/bin and,
# optionally, /etc/systemd/system) — the build itself runs as your normal
# user, no privilege needed for that part.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Building anonet (release)..."
cargo build --release

echo "==> Installing binary to /usr/local/bin/anonet (sudo)..."
sudo install -Dm755 target/release/anonet /usr/local/bin/anonet

read -rp "Also install the systemd unit for headless/service use? [y/N] " reply
if [[ "$reply" =~ ^[Yy]$ ]]; then
    sudo install -Dm644 packaging/anonet.service /etc/systemd/system/anonet.service
    sudo systemctl daemon-reload
    echo "==> Unit installed. Enable and start with:"
    echo "      sudo systemctl enable --now anonet"
fi

echo "==> Done. Run 'anonet' for the dashboard, 'anonet --help' for all options."
