#!/usr/bin/env python3
"""Optional local audio only. Never approves or denies a permission request."""
import json
from pathlib import Path
import shutil
import subprocess
import sys


def notify(event, platform=None):
    platform = sys.platform if platform is None else platform
    permission = event.get("hook_event_name") == "PermissionRequest"
    if platform == "darwin":
        player = "/usr/bin/afplay"
        sound = Path("/System/Library/Sounds") / ("Ping.aiff" if permission else "Glass.aiff")
        if not Path(player).is_file():
            return
    elif platform.startswith("linux"):
        player = shutil.which("paplay")
        sound = Path("/usr/share/sounds/freedesktop/stereo") / (
            "dialog-warning.oga" if permission else "complete.oga")
        if player is None:
            return
    else:
        return
    if not sound.is_file():
        return
    try:
        subprocess.run([player, str(sound)], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        # Audio is advisory and must not prevent work when unavailable.
        pass


def main():
    try:
        event = json.load(sys.stdin)
    except (ValueError, TypeError):
        event = None
    if isinstance(event, dict):
        notify(event)
    print("{}")


if __name__ == "__main__":
    main()
