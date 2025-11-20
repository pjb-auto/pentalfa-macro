import ctypes
from ctypes import wintypes
import os
import platform
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import uuid
from typing import Any

import cv2
import numpy as np
import pyautogui

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

SCAN_INTERVAL = 5.0  # Seconds between scans
REGION_SCALE = 0.4  # Portion of the screen around the center to inspect
MATCH_THRESHOLD = 0.85  # Template matching score threshold
MAX_MISSES_BEFORE_EXPAND = 3  # Consecutive misses before scanning the whole screen

pyautogui.FAILSAFE = True

# Use the image file in the same directory as the script
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "afspelen.png")

# Load the button image
template = cv2.imread(TEMPLATE_PATH, cv2.IMREAD_UNCHANGED)
if template is None:
    raise FileNotFoundError(f"Template image not found at {TEMPLATE_PATH}")

if template.ndim == 2:
    template_gray = template
else:
    template_rgb = template[:, :, :3]
    if template.shape[2] == 4:
        alpha = template[:, :, 3].astype(np.float32) / 255.0
        background = np.full_like(template_rgb, 255, dtype=np.float32)
        blended = template_rgb.astype(np.float32) * alpha[..., None] + background * (1 - alpha[..., None])
        template_rgb = blended.astype(np.uint8)
    template_gray = cv2.cvtColor(template_rgb, cv2.COLOR_BGR2GRAY)

template_h, template_w = template_gray.shape[:2]
template_size = (template_w, template_h)


def _compute_region_for_point(center_x: int, center_y: int, scale: float, tmpl_size: tuple[int, int]):
    template_w, template_h = tmpl_size
    screen_w, screen_h = pyautogui.size()
    region_w = max(int(screen_w * scale), template_w)
    region_h = max(int(screen_h * scale), template_h)
    left = min(max(int(center_x - region_w // 2), 0), max(screen_w - region_w, 0))
    top = min(max(int(center_y - region_h // 2), 0), max(screen_h - region_h, 0))
    return left, top, region_w, region_h


def compute_scan_region(scale: float, tmpl_size: tuple[int, int], center: tuple[int, int] | None = None):
    if center is None:
        screen_w, screen_h = pyautogui.size()
        center = (screen_w // 2, screen_h // 2)
    return _compute_region_for_point(center[0], center[1], scale, tmpl_size)


SECURITY_BYPASS_ENV = "PENTALFA_ALLOW_UNSAFE"
VM_KEYWORDS = (
    "VIRTUAL",
    "VBOX",
    "VMWARE",
    "QEMU",
    "XEN",
    "HYPER-V",
    "PARALLELS",
    "KVM",
)
DEBUGGING_PROCESSES = (
    "ollydbg",
    "x64dbg",
    "ida64",
    "ida32",
    "ida.exe",
    "wireshark",
    "fiddler",
    "procmon",
    "processhacker",
    "immunitydebugger",
)
VM_MAC_PREFIXES = {
    "00:05:69",
    "00:0C:29",
    "00:1C:14",
    "00:50:56",
    "00:15:5D",
    "00:03:FF",
    "08:00:27",
}


class SecurityViolation(RuntimeError):
    """Raised when a security check fails."""


def _is_debugger_attached() -> bool:
    if sys.gettrace():
        return True
    if os.name != "nt":
        return False
    kernel32 = ctypes.windll.kernel32
    if kernel32.IsDebuggerPresent():
        return True
    check = wintypes.BOOL()
    if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(check)):
        if check.value:
            return True
    return False


def _has_debugging_tools_running() -> bool:
    if os.name != "nt":
        return False
    try:
        output = subprocess.check_output(["tasklist"], creationflags=CREATE_NO_WINDOW, text=True)
        output_lower = output.lower()
        return any(proc in output_lower for proc in DEBUGGING_PROCESSES)
    except Exception:
        return False


def _is_vm_environment() -> bool:
    uname_blob = " ".join(platform.uname()).upper()
    if any(keyword in uname_blob for keyword in VM_KEYWORDS):
        return True

    try:
        serial = subprocess.check_output(
            ["wmic", "bios", "get", "serialnumber"], creationflags=CREATE_NO_WINDOW, text=True
        )
        if any(keyword in serial.upper() for keyword in VM_KEYWORDS):
            return True
    except Exception:
        pass

    try:
        manufacturer = subprocess.check_output(
            ["wmic", "baseboard", "get", "manufacturer"], creationflags=CREATE_NO_WINDOW, text=True
        )
        if any(keyword in manufacturer.upper() for keyword in VM_KEYWORDS):
            return True
    except Exception:
        pass

    try:
        mac = uuid.getnode()
        if mac is not None:
            mac_bytes = mac.to_bytes(6, "big")
            prefix = ":".join(f"{b:02X}" for b in mac_bytes[:3])
            if prefix in VM_MAC_PREFIXES:
                return True
    except Exception:
        pass

    return False


def perform_security_checks() -> None:
    if os.environ.get(SECURITY_BYPASS_ENV) == "1":
        return

    reasons: list[str] = []
    if _is_debugger_attached():
        reasons.append("Debugger detected")
    if _has_debugging_tools_running():
        reasons.append("Debugging tools running")
    if _is_vm_environment():
        reasons.append("Virtualization environment detected")

    if reasons:
        reason_text = "; ".join(reasons)
        _report_security_failure(reason_text)
        raise SecurityViolation(reason_text)


def _report_security_failure(details: str) -> None:
    message = (
        "Security checks failed. This application cannot run in the current environment.\n\n"
        f"Reason: {details}"
    )
    print(message)
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(0, message, "Pentalfa Macro", 0x10)
        except Exception:
            pass

class AfspelenScanner:
    def __init__(self, template_gray_img: np.ndarray, tmpl_size: tuple[int, int], event_queue: queue.Queue[dict[str, Any]]):
        self.template_gray = template_gray_img
        self.template_w, self.template_h = tmpl_size
        self.template_size = tmpl_size
        self.event_queue = event_queue

        self.scan_region = compute_scan_region(REGION_SCALE, self.template_size)
        self.last_frame = None
        self.last_region = None
        self.button_visible = False
        self.miss_streak = 0
        self.click_count = 0

        self.running_event = threading.Event()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def shutdown(self) -> None:
        self.stop_event.set()
        self.running_event.set()
        self.thread.join()

    def _emit_status(self, message: str) -> None:
        print(message)
        self.event_queue.put({"type": "status", "text": message})

    def _emit_click_update(self) -> None:
        self.event_queue.put({"type": "click_count", "count": self.click_count})

    def _emit_region_status(self) -> None:
        left, top, width, height = self.scan_region
        self._emit_status(
            f"📍 Search region: left={left}, top={top}, width={width}, height={height}"
        )

    def _run(self) -> None:
        self._emit_status("🔍 Dashboard ready. Press ▶ Start to begin scanning.")
        self._emit_region_status()
        self._emit_click_update()

        while not self.stop_event.is_set():
            if not self.running_event.is_set():
                time.sleep(0.1)
                continue

            try:
                self._scan_once()
            except Exception as exc:  # pylint: disable=broad-except
                self._emit_status(f"❌ Scanner error: {exc}")
                self.running_event.clear()
                continue

            self._wait_interval()

    def _wait_interval(self) -> None:
        remaining = SCAN_INTERVAL
        while remaining > 0:
            if self.stop_event.is_set() or not self.running_event.is_set():
                break
            sleep_time = min(0.1, remaining)
            time.sleep(sleep_time)
            remaining -= sleep_time

    def _scan_once(self) -> None:
        current_region = None if self.miss_streak >= MAX_MISSES_BEFORE_EXPAND else self.scan_region

        if current_region is None:
            screenshot = pyautogui.screenshot()
            offset_x = 0
            offset_y = 0
        else:
            screenshot = pyautogui.screenshot(region=current_region)
            offset_x, offset_y, _, _ = current_region

        screenshot_np = np.array(screenshot)
        screenshot_gray = cv2.cvtColor(screenshot_np, cv2.COLOR_RGB2GRAY)

        if (
            self.last_frame is not None
            and self.last_region == current_region
            and np.array_equal(screenshot_gray, self.last_frame)
        ):
            return

        self.last_frame = screenshot_gray
        self.last_region = current_region

        result = cv2.matchTemplate(screenshot_gray, self.template_gray, cv2.TM_CCOEFF_NORMED)
        _, max_val, _, max_loc = cv2.minMaxLoc(result)

        if max_val >= MATCH_THRESHOLD:
            click_x = offset_x + max_loc[0] + self.template_w // 2
            click_y = offset_y + max_loc[1] + self.template_h // 2
            if not self.button_visible:
                self.click_count += 1
                self._emit_status(
                    f"✅ 'Afspelen' button detected (confidence {max_val:.2f}) at ({click_x}, {click_y}). "
                    "Clicking once."
                )
                pyautogui.click(click_x, click_y)
                self._emit_click_update()
            self.button_visible = True
            self.miss_streak = 0

            if current_region is None:
                self.scan_region = compute_scan_region(
                    REGION_SCALE,
                    self.template_size,
                    center=(click_x, click_y),
                )
                self._emit_region_status()
        else:
            if self.button_visible:
                self._emit_status("ℹ️ 'Afspelen' button no longer detected.")
            self.button_visible = False
            previous_miss_streak = self.miss_streak
            self.miss_streak += 1

            if self.miss_streak == MAX_MISSES_BEFORE_EXPAND and previous_miss_streak < MAX_MISSES_BEFORE_EXPAND:
                self._emit_status("🔄 Button not found; expanding search to the entire screen.")

    def reset_tracking_state(self) -> None:
        self.last_frame = None
        self.last_region = None
        self.button_visible = False
        self.miss_streak = 0

class Dashboard:
    LOG_POLL_INTERVAL_MS = 200

    def __init__(self, scanner: AfspelenScanner, event_queue: queue.Queue[dict[str, Any]]):
        self.scanner = scanner
        self.event_queue = event_queue

        self.root = tk.Tk()
        self.root.title("Pentalfa Macro")
        self.root.resizable(False, False)
        self.root.configure(bg="#000000")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.status_var = tk.StringVar(value="Paused")
        self.counter_var = tk.StringVar(value="000000")

        self._build_widgets()
        self._process_event_queue()

    def _build_widgets(self) -> None:
        main_frame = tk.Frame(self.root, padx=20, pady=20, bg="#000000")
        main_frame.pack(fill=tk.BOTH, expand=True)

        status_label = tk.Label(
            main_frame,
            textvariable=self.status_var,
            font=("Segoe UI", 12, "bold"),
            bg="#000000",
            fg="#0aff0a",
        )
        status_label.pack(anchor="center")

        counter_frame = tk.Frame(main_frame, bg="#000000", pady=20)
        counter_frame.pack(fill=tk.X)

        counter_title = tk.Label(
            counter_frame,
            text="Clicks",
            font=("Segoe UI", 12),
            bg="#000000",
            fg="#0aff0a",
        )
        counter_title.pack(anchor="center")

        counter_display = tk.Label(
            counter_frame,
            textvariable=self.counter_var,
            font=("Consolas", 44, "bold"),
            bg="#000000",
            fg="#39ff14",
        )
        counter_display.pack(anchor="center", pady=(8, 0))

        button_frame = tk.Frame(main_frame, bg="#000000", pady=10)
        button_frame.pack(fill=tk.X)

        self.start_button = tk.Button(
            button_frame,
            text="▶ Start",
            width=12,
            bg="#39ff14",
            fg="#000000",
            activebackground="#1aff0a",
            activeforeground="#000000",
            command=self._start_scanning,
            relief=tk.FLAT,
        )
        self.start_button.pack(side=tk.LEFT, padx=(0, 12))

        self.stop_button = tk.Button(
            button_frame,
            text="■ Stop",
            width=12,
            bg="#ff1744",
            fg="#000000",
            activebackground="#ff4561",
            activeforeground="#000000",
            state=tk.DISABLED,
            command=self._stop_scanning,
            relief=tk.FLAT,
        )
        self.stop_button.pack(side=tk.LEFT)

        info_label = tk.Label(
            main_frame,
            text="Fail-safe: move mouse to top-left corner to abort.",
            bg="#000000",
            fg="#0aff0a",
            font=("Segoe UI", 9),
        )
        info_label.pack(anchor="center", pady=(20, 0))

    def run(self) -> None:
        self.root.mainloop()

    def _process_event_queue(self) -> None:
        while not self.event_queue.empty():
            event = self.event_queue.get_nowait()
            event_type = event.get("type")
            if event_type == "status":
                text = event.get("text", "")
                self.status_var.set(text)
            elif event_type == "click_count":
                count = event.get("count", 0)
                self.counter_var.set(f"{count:06d}")
        self.root.after(self.LOG_POLL_INTERVAL_MS, self._process_event_queue)

    def _start_scanning(self) -> None:
        if self.scanner.running_event.is_set():
            return
        self.scanner.reset_tracking_state()
        self.scanner.running_event.set()
        self.status_var.set("Scanning...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def _stop_scanning(self) -> None:
        if not self.scanner.running_event.is_set():
            return
        self.scanner.running_event.clear()
        self.status_var.set("Paused")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def _on_close(self) -> None:
        self.scanner.shutdown()
        self.root.destroy()


def main() -> None:
    event_queue: queue.Queue[dict[str, Any]] = queue.Queue()
    scanner = AfspelenScanner(template_gray, template_size, event_queue)
    dashboard = Dashboard(scanner, event_queue)
    scanner.start()
    dashboard.run()


if __name__ == "__main__":
    try:
        perform_security_checks()
    except SecurityViolation:
        sys.exit(1)
    main()
