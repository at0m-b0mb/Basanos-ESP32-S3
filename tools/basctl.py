#!/usr/bin/env python3
"""Basanos console client.

    tools/basctl.py                       interactive
    tools/basctl.py list                  one command
    tools/basctl.py -f script.txt         a file of commands

Opening the port asserts DTR/RTS, which resets the ESP32 -- so anything sent
immediately after connecting lands while the board is still booting and is
lost. This client holds both lines low on open and then waits for the device
to announce itself before sending anything.
"""
import argparse
import sys
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial not installed: pip install pyserial")

PROMPT = "BAS>"


def find_port():
    """The board re-enumerates with a different number on every replug, so the
    port is discovered by Espressif's USB vendor id rather than hardcoded."""
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.vid == 0x303A:              # Espressif
                return p.device
        for p in list_ports.comports():
            if "usbmodem" in p.device and "Bluetooth" not in p.device:
                return p.device
    except Exception:
        pass
    import glob
    for d in sorted(glob.glob("/dev/cu.usbmodem*")):
        return d
    return None


def open_port(port):
    s = serial.Serial()
    s.port = port
    s.baudrate = 115200
    s.timeout = 0.2
    # Hold both low across the open so the board is not reset into the middle
    # of the session.
    s.dtr = False
    s.rts = False
    s.open()
    s.dtr = False
    s.rts = False
    return s


def drain(s, seconds, echo_log=False):
    """Read for `seconds`, returning device replies. Log lines are dropped
    unless asked for -- they are useful for diagnosis but noise otherwise."""
    end = time.time() + seconds
    buf = ""
    out = []
    while time.time() < end:
        d = s.read(4096)
        if d:
            buf += d.decode("utf-8", "replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                if PROMPT in line:
                    out.append(line[line.index(PROMPT) + len(PROMPT):].strip())
                elif echo_log:
                    out.append("  | " + line)
    return out


def wait_ready(s, timeout=25):
    """Wait for the device to finish booting.

    Nudges at most a few times, several seconds apart. The device queue is
    shallow and the main loop repaints the panel between commands, so spamming
    a probe just overflows it and gets "busy" back."""
    end = time.time() + timeout
    # It may already be booted and quiet, so listen before saying anything.
    for line in drain(s, 1.0):
        if line:
            return True
    while time.time() < end:
        s.write(b"status\n")
        s.flush()
        for line in drain(s, 3.0):
            if line:
                return True
    return False


def command(s, cmd, wait=2.0, echo_log=False):
    s.reset_input_buffer()
    s.write((cmd + "\n").encode())
    s.flush()
    # A run occupies the device for its whole duration, so the caller sets a
    # window long enough to cover it.
    return drain(s, wait, echo_log)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="*", help="command to send; omit for interactive")
    ap.add_argument("-p", "--port", default=None)
    ap.add_argument("-f", "--file", help="file of commands, one per line")
    ap.add_argument("-w", "--wait", type=float, default=2.0)
    ap.add_argument("-l", "--log", action="store_true", help="show device log lines too")
    a = ap.parse_args()

    port = a.port or find_port()
    if port is None:
        sys.exit("no ESP32 serial port found — is the board plugged in?")
    s = open_port(port)
    if not wait_ready(s):
        sys.exit("no response from the device — is it booted?")

    def run(line, wait):
        print(f"> {line}")
        for r in command(s, line, wait, a.log):
            print("  " + r)

    if a.file:
        for raw in open(a.file):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # A run needs a window that covers its duration plus the grace.
            w = a.wait
            if line.startswith("run"):
                parts = line.split()
                secs = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 10
                w = secs + 6
            run(line, w)
    elif a.cmd:
        run(" ".join(a.cmd), a.wait)
    else:
        print("connected. 'help' for commands, ctrl-d to quit.")
        try:
            while True:
                line = input("basanos> ").strip()
                if not line:
                    continue
                if line in ("quit", "exit"):
                    break
                w = a.wait
                if line.startswith("run"):
                    parts = line.split()
                    secs = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 10
                    w = secs + 6
                for r in command(s, line, w, a.log):
                    print("  " + r)
        except (EOFError, KeyboardInterrupt):
            print()

    s.close()


if __name__ == "__main__":
    main()
