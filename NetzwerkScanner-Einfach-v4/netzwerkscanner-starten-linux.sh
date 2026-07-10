#!/usr/bin/env bash
set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/Get-NetworkDevices-Pro-v4-CrossPlatform.ps1"

if ! command -v pwsh >/dev/null 2>&1; then
  echo "Fehler: PowerShell 7 ist nicht installiert."
  echo "Ubuntu/Debian: sudo apt install powershell"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Der Scanner benoetigt Administratorrechte fuer ARP, DHCP-Leases und genaue Netzwerkerkennung."
  exec sudo pwsh -NoLogo -NoProfile -File "$SCRIPT" -SimpleMode
else
  exec pwsh -NoLogo -NoProfile -File "$SCRIPT" -SimpleMode
fi
