#!/usr/bin/env python3
"""Watchdog — keeps Claude Code agents from stalling.

On startup, shows a screen overlay for you to click-drag a selection box
around the terminal you want to monitor. Then watches that region for
visual changes using perceptual hashing. When the screen hasn't changed
for a configurable period, sends a screenshot to Claude to ask if the
agent is stuck, and if so, types a nudge message to keep it going.

Usage:
    python watchdog.py                    # defaults: 5 min stall, 30s poll
    python watchdog.py --stall 180        # 3 min stall threshold
    python watchdog.py --poll 15          # check every 15 seconds
    python watchdog.py --dry-run          # detect stalls but don't type

Requirements:
    pip install Pillow pyautogui pyperclip
    claude CLI (Claude Code) must be installed and authenticated
"""

import os
import sys
import time
import argparse
import tempfile
import tkinter as tk

try:
    from PIL import ImageGrab
except ImportError:
    print("pip install Pillow")
    sys.exit(1)

try:
    import pyautogui
except ImportError:
    print("pip install pyautogui")
    sys.exit(1)

import subprocess



# --- Region selector ---

def select_region():
    """Show a fullscreen overlay and let the user drag a rectangle.
    Returns (x1, y1, x2, y2) in screen coordinates."""

    coords = {}

    root = tk.Tk()
    root.attributes("-fullscreen", True)
    root.attributes("-alpha", 0.3)
    root.attributes("-topmost", True)
    root.configure(bg="black")
    root.title("Watchdog — drag to select region")

    canvas = tk.Canvas(root, cursor="cross", bg="black",
                       highlightthickness=0)
    canvas.pack(fill=tk.BOTH, expand=True)

    rect_id = None
    start_x = start_y = 0

    label = canvas.create_text(
        root.winfo_screenwidth() // 2,
        root.winfo_screenheight() // 2,
        text="Click and drag to select the terminal region to watch",
        fill="white", font=("Consolas", 24),
    )

    def on_press(event):
        nonlocal start_x, start_y, rect_id
        start_x, start_y = event.x, event.y
        canvas.delete(label)
        if rect_id:
            canvas.delete(rect_id)
        rect_id = canvas.create_rectangle(
            start_x, start_y, start_x, start_y,
            outline="lime", width=2,
        )

    def on_drag(event):
        nonlocal rect_id
        if rect_id:
            canvas.coords(rect_id, start_x, start_y, event.x, event.y)

    def on_release(event):
        x1 = min(start_x, event.x)
        y1 = min(start_y, event.y)
        x2 = max(start_x, event.x)
        y2 = max(start_y, event.y)

        if (x2 - x1) < 50 or (y2 - y1) < 50:
            canvas.create_text(
                root.winfo_screenwidth() // 2,
                root.winfo_screenheight() // 2,
                text="Too small -- try again",
                fill="red", font=("Consolas", 18),
            )
            return

        coords["bbox"] = (x1, y1, x2, y2)
        root.destroy()

    canvas.bind("<ButtonPress-1>", on_press)
    canvas.bind("<B1-Motion>", on_drag)
    canvas.bind("<ButtonRelease-1>", on_release)
    root.bind("<Escape>", lambda e: (coords.update({"bbox": None}),
                                     root.destroy()))

    root.mainloop()
    return coords.get("bbox")


# --- Screen capture ---

def capture_region(bbox):
    """Capture a screen region, return (pixel hash, image)."""
    import hashlib
    img = ImageGrab.grab(bbox=bbox)
    h = hashlib.md5(img.tobytes()).hexdigest()
    return h, img


# --- Claude analysis via claude -p ---

STALL_PROMPT = (
    "Read the image at {screenshot_path}. "
    "This is a screenshot of a Claude Code terminal. The screen has "
    "not changed for several minutes.\n\n"
    "Look at the BOTTOM of the screen -- the most recent output. "
    "Ignore everything above it. Focus ONLY on whether the agent's "
    "last message is waiting for the user to type something.\n\n"
    "Signs the agent is WAITING for input (needs a nudge):\n"
    "- The last line is a question or summary with no tool call after it\n"
    "- Text like 'want me to', 'should I', 'let me know', 'ready for'\n"
    "- A status report followed by silence\n"
    "- The cursor is on an empty input line (> prompt visible)\n\n"
    "Signs the agent is WORKING (leave it alone):\n"
    "- A tool call is in progress (spinner, 'Running...', progress bar)\n"
    "- Output is streaming\n"
    "- The word 'Churning', 'Crunching', or similar status indicator\n\n"
    "Reply ONLY with one of:\n"
    "- NUDGE: <short ASCII message to type>\n"
    "- WAIT\n\n"
    "Nothing else. No explanation. Just NUDGE or WAIT on the first line."
)


def ask_claude_about_stall(img, tmp_dir):
    """Save screenshot and ask claude -p if the agent is stuck."""
    screenshot_path = os.path.join(tmp_dir, "watchdog_stall.png")
    img.save(screenshot_path)

    prompt = STALL_PROMPT.format(screenshot_path=screenshot_path.replace("\\", "/"))

    result = subprocess.run(
        ["claude", "-p", "--model", "opus", prompt],
        capture_output=True, text=True, timeout=120,
        stdin=subprocess.DEVNULL,
    )

    if result.returncode != 0:
        raise RuntimeError(f"claude -p failed: {result.stderr.strip()}")

    return result.stdout.strip()


# --- Keyboard ---

def send_nudge(message):
    """Type a message into the active window."""
    time.sleep(0.5)
    try:
        import pyperclip
        pyperclip.copy(message)
        pyautogui.hotkey("ctrl", "v")
    except ImportError:
        pyautogui.typewrite(message, interval=0.015)
    time.sleep(0.2)
    pyautogui.press("enter")


# --- Main loop ---

def main():
    parser = argparse.ArgumentParser(
        description="Watchdog -- keeps Claude Code agents from stalling"
    )
    parser.add_argument(
        "--stall", type=int, default=300,
        help="Seconds of no change before intervening (default: 300)"
    )
    parser.add_argument(
        "--poll", type=int, default=30,
        help="Seconds between screen checks (default: 30)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Detect stalls and print verdict but don't type anything"
    )
    args = parser.parse_args()

    print("Select the terminal region to watch...")
    print("(Press Escape to cancel)")
    print()

    bbox = select_region()
    if bbox is None:
        print("Cancelled.")
        return

    x1, y1, x2, y2 = bbox
    print(f"Watching region: ({x1}, {y1}) to ({x2}, {y2})")
    print(f"  Size: {x2 - x1} x {y2 - y1} pixels")
    print(f"  Stall threshold: {args.stall}s")
    print(f"  Poll interval: {args.poll}s")
    print(f"  Comparison: exact pixel match (no tolerance)")
    print(f"  Mode: {'DRY RUN' if args.dry_run else 'LIVE'}")
    print()

    # Use a fixed location in the project dir — avoids WSL /tmp path issues
    tmp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".watchdog")
    os.makedirs(tmp_dir, exist_ok=True)
    last_phash = None
    stall_seconds = 0
    nudge_count = 0

    while True:
        try:
            current_phash, img = capture_region(bbox)
        except Exception as e:
            print(f"[error] capture failed: {e}")
            time.sleep(args.poll)
            continue

        if last_phash is None:
            last_phash = current_phash
            print(f"[init] First capture. Watching for changes...")
            time.sleep(args.poll)
            continue

        if current_phash == last_phash:
            # Screen is identical
            stall_seconds += args.poll

            remaining = args.stall - stall_seconds
            if remaining > 0 and stall_seconds % 60 < args.poll:
                print(f"[idle] {stall_seconds}s unchanged ({remaining}s until check)")

            if stall_seconds >= args.stall:
                print(f"[stall] {stall_seconds}s unchanged. Asking Claude...")

                try:
                    verdict = ask_claude_about_stall(img, tmp_dir)
                except Exception as e:
                    print(f"[api error] {e}")
                    stall_seconds = 0
                    time.sleep(args.poll)
                    continue

                print(f"[verdict] {verdict}")

                # Find NUDGE: anywhere in the response — Claude sometimes
                # explains before giving the verdict
                nudge_idx = verdict.upper().find("NUDGE:")
                if nudge_idx >= 0:
                    nudge_msg = verdict[nudge_idx + 6:].strip()
                    # Take only the first line (ignore trailing explanation)
                    nudge_msg = nudge_msg.split("\n")[0].strip().strip('"').strip("'")
                    # Strip non-ASCII to prevent garbled output on Windows
                    nudge_msg = nudge_msg.encode("ascii", errors="ignore").decode("ascii")
                    nudge_count += 1

                    if args.dry_run:
                        print(f"[dry run] Would type: {nudge_msg}")
                    else:
                        print(f"[nudge #{nudge_count}] Typing: {nudge_msg}")
                        send_nudge(nudge_msg)

                    stall_seconds = 0
                    last_phash = None
                    time.sleep(60)
                    continue
                else:
                    print(f"[wait] Agent appears blocked or working. Backing off.")
                    stall_seconds = 0
                    last_phash = None
                    time.sleep(args.stall // 2)
                    continue
        else:
            # Screen changed
            if stall_seconds > 0:
                print(f"[active] Screen changed after {stall_seconds}s idle.")
            stall_seconds = 0
            last_phash = current_phash

        time.sleep(args.poll)


if __name__ == "__main__":
    main()
