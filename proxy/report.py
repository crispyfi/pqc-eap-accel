"""
report.py — per-auth output: a readable CLI summary block + a JSON record file.

Each completed authentication produces:
  * a human-readable block printed to stdout — the headline result at a glance,
    kept out of the logging stream so it isn't buried under per-packet log lines;
  * one JSON file under the configured output directory — a self-describing,
    machine-readable record per auth, ready to aggregate across a sweep.

Output is deliberately ASCII-only (no box-drawing or emoji): the proxy may run
on a minimised server with a C/POSIX locale where printing non-ASCII would raise
UnicodeEncodeError and take down the recv loop. Colour is added only on a TTY.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone


def _color(code: str, text: str) -> str:
    # Colourise only when stdout is an interactive terminal, so redirected
    # output / CI logs stay free of ANSI escape codes.
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def _human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


class Reporter:
    """Prints a readable summary and writes a JSON record for each finished auth."""

    def __init__(self, output_dir: str):
        self.output_dir = os.path.abspath(output_dir)
        self._seq = 0
        # Create the dir up front so the path logged at startup is real and a
        # bad/unwritable location fails fast here rather than mid-run.
        os.makedirs(self.output_dir, exist_ok=True)

    def report(self, summary: dict) -> str | None:
        """Write the JSON record and print the CLI block.

        Returns the JSON path (or None if the write failed). A write failure is
        reported in the block but never raised — losing one record must not kill
        the proxy mid-run.
        """
        path, error = None, None
        try:
            path = self._write_json(summary)
        except OSError as exc:
            error = str(exc)
        self._print_block(summary, path, error)
        return path

    def _write_json(self, summary: dict) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        self._seq += 1
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **summary,
        }
        fname = "{ts}-{seq:03d}-{mode}-{result}.json".format(
            ts=time.strftime("%Y%m%d-%H%M%S"),
            seq=self._seq,
            mode=summary.get("mode", "unknown"),
            result=summary.get("result", "unknown"),
        )
        path = os.path.join(self.output_dir, fname)
        with open(path, "w") as fh:
            json.dump(record, fh, indent=2)
            fh.write("\n")
        return path

    def _print_block(self, s: dict, json_path: str | None, error: str | None) -> None:
        result = (s.get("result") or "unknown").upper()
        accepted = s.get("result") == "accept"
        badge = _color("1;32", result) if accepted else _color("1;31", result)

        dur = s.get("duration_ms")
        dur_str = f"{dur:.0f} ms" if dur is not None else "-"
        rtts = s.get("upstream_round_trips", 0)
        up = s.get("supplicant_to_server", {})
        down = s.get("server_to_supplicant", {})
        saved = json_path if json_path else f"(write failed: {error})"

        rule = "=" * 68
        lines = [
            "",
            rule,
            f"  {badge}   mode={s.get('mode', '?')}   {dur_str}   |   "
            f"{rtts} upstream round-trip(s)",
            rule,
            f"  supplicant -> server   "
            f"{up.get('fragments_in', 0):>3} frag in    "
            f"{up.get('acks_generated', 0):>3} acks absorbed    "
            f"{_human_bytes(up.get('bytes', 0))}",
            f"  server -> supplicant   "
            f"{down.get('fragments_out', 0):>3} frag out   "
            f"{down.get('acks_generated', 0):>3} acks             "
            f"{_human_bytes(down.get('bytes', 0))}",
            f"  fragment sizes         down={s.get('downstream_fragment_size', '?')}  "
            f"up={s.get('upstream_fragment_size', '?')}",
            f"  session                {s.get('key', '?')}",
            f"  saved                  {saved}",
            rule,
            "",
        ]
        print("\n".join(lines))
