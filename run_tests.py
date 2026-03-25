#!/usr/bin/env python3
"""N4ughtyLLM Gate test runner.

Executes the full pytest suite with a verbose, human-readable display:
  - Per-test PASS / FAIL / SKIP / ERROR lines with timing
  - Per-module subtotals
  - Grand-total summary table
  - Full tracebacks for every failure printed at the end

Usage
-----
    python run_tests.py                  # run all tests
    python run_tests.py -k circuit       # pytest -k filter
    python run_tests.py test_v2_proxy    # run one module by name fragment
    python run_tests.py --no-color       # disable ANSI colours
    python run_tests.py --failfast       # stop on first failure
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_USE_COLOR = "--no-color" not in sys.argv and sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(t: str) -> str:   return _c("32", t)
def red(t: str) -> str:     return _c("31", t)
def yellow(t: str) -> str:  return _c("33", t)
def cyan(t: str) -> str:    return _c("36", t)
def bold(t: str) -> str:    return _c("1",  t)
def dim(t: str) -> str:     return _c("2",  t)
def blue(t: str) -> str:    return _c("34", t)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    node_id: str
    module: str
    name: str
    status: str          # "PASSED" | "FAILED" | "ERROR" | "SKIPPED" | "XFAIL" | "XPASS"
    duration_s: float = 0.0
    short_msg: str = ""  # inline failure reason from -v output


@dataclass
class ModuleStats:
    name: str
    passed: int = 0
    failed: int = 0
    error: int = 0
    skipped: int = 0
    xfail: int = 0
    xpass: int = 0
    results: list[TestResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pytest invocation
# ---------------------------------------------------------------------------

_STATUS_RE = re.compile(
    r"^(?P<node>.+?)\s+(?P<status>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)"
    r"(?:\s+\[\s*\d+%\])?"
    r"(?:\s+-\s+(?P<msg>.+))?$"
)
_DURATION_RE = re.compile(r"\((?P<sec>[\d.]+)s\)")
_SECTION_RE  = re.compile(r"^=+ (.+) =+$")
_FAILURE_SEP = re.compile(r"^_+ (.+) _+$")


def _module_from_node(node_id: str) -> str:
    """Extract the test file base name from a fully-qualified node id."""
    parts = node_id.split("::")
    path = Path(parts[0])
    return path.stem  # e.g. "test_circuit_breaker"


def _build_pytest_argv(extra_args: list[str]) -> list[str]:
    argv = [
        sys.executable, "-m", "pytest",
        "--tb=short",           # compact tracebacks in the failure section
        "-v",                   # verbose one-line-per-test output
        "--no-header",          # skip the platform/version banner
        "--durations=0",        # include all timings in the session summary
        "-rA",                  # show all test short summaries at the end
    ]
    if _USE_COLOR:
        argv.append("--color=yes")
    else:
        argv.append("--color=no")
    argv.extend(extra_args)
    return argv


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

def _parse_lines(
    lines: list[str],
) -> tuple[list[TestResult], list[str], str]:
    """Parse pytest -v output into structured results plus raw failure block."""
    results: list[TestResult] = []
    failure_lines: list[str] = []
    summary_line = ""
    in_failures = False

    for raw in lines:
        line = raw.rstrip()

        # Detect entry into the FAILURES / ERRORS section
        if _SECTION_RE.match(line):
            section = _SECTION_RE.match(line).group(1).lower()
            if "failure" in section or "error" in section:
                in_failures = True
            elif "short test summary" in section or "passed" in section or "failed" in section:
                in_failures = False
                if any(kw in section for kw in ("passed", "failed", "error", "warning")):
                    summary_line = line
            continue

        if in_failures:
            failure_lines.append(raw)
            continue

        m = _STATUS_RE.match(line)
        if not m:
            # Catch the final summary line that may not be in a section header
            if re.search(r"\d+ passed", line) or re.search(r"\d+ failed", line):
                summary_line = line
            continue

        node_id = m.group("node").strip()
        status  = m.group("status")
        msg     = (m.group("msg") or "").strip()

        # Duration can be embedded like "(0.12s)"
        dur = 0.0
        dm = _DURATION_RE.search(line)
        if dm:
            dur = float(dm.group("sec"))

        results.append(TestResult(
            node_id=node_id,
            module=_module_from_node(node_id),
            name=node_id.split("::")[-1],
            status=status,
            duration_s=dur,
            short_msg=msg,
        ))

    return results, failure_lines, summary_line


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_STATUS_DISPLAY = {
    "PASSED":  (green,  "PASS"),
    "FAILED":  (red,    "FAIL"),
    "ERROR":   (red,    "ERR "),
    "SKIPPED": (yellow, "SKIP"),
    "XFAIL":   (yellow, "XFAIL"),
    "XPASS":   (yellow, "XPASS"),
}

_MODULE_COL_W = 36
_NAME_COL_W   = 52


def _print_header() -> None:
    width = _MODULE_COL_W + _NAME_COL_W + 30
    print()
    print(bold("=" * width))
    print(bold("  N4ughtyLLM Gate — Test Suite"))
    print(bold("=" * width))
    print()


def _print_module_header(module: str) -> None:
    label = f"  {module}  "
    pad   = "-" * max(0, 76 - len(label))
    print(f"\n{cyan(label)}{dim(pad)}")


def _print_result(r: TestResult) -> None:
    colour_fn, label = _STATUS_DISPLAY.get(r.status, (dim, r.status))
    badge = colour_fn(f"[{label}]")

    name = r.name
    if len(name) > _NAME_COL_W:
        name = name[:_NAME_COL_W - 1] + "…"

    dur_str = f"{r.duration_s:5.2f}s" if r.duration_s > 0 else "      "

    extra = ""
    if r.status in ("FAILED", "ERROR") and r.short_msg:
        snippet = r.short_msg[:60]
        extra = f"  {dim(snippet)}"

    print(f"  {badge}  {name:<{_NAME_COL_W}}  {dim(dur_str)}{extra}")


def _print_module_stats(stats: ModuleStats) -> None:
    total = stats.passed + stats.failed + stats.error + stats.skipped
    parts: list[str] = []
    if stats.passed:  parts.append(green(f"{stats.passed} passed"))
    if stats.failed:  parts.append(red(f"{stats.failed} failed"))
    if stats.error:   parts.append(red(f"{stats.error} error"))
    if stats.skipped: parts.append(yellow(f"{stats.skipped} skipped"))
    summary = "  " + "  ".join(parts) + f"  {dim(f'({total} total)')}"
    print(summary)


def _print_failures(failure_lines: list[str]) -> None:
    if not failure_lines:
        return
    width = 76
    print()
    print(bold(red("=" * width)))
    print(bold(red("  FAILURE DETAILS")))
    print(bold(red("=" * width)))
    in_block = False
    for line in failure_lines:
        stripped = line.rstrip()
        if _FAILURE_SEP.match(stripped):
            m = _FAILURE_SEP.match(stripped)
            print(f"\n{bold(red('  ✗ ' + m.group(1)))}")
            in_block = True
        elif stripped.startswith("E ") or stripped.startswith("E\t"):
            print(red(f"    {stripped}"))
        elif stripped.startswith(">"):
            print(yellow(f"    {stripped}"))
        else:
            print(dim(f"    {stripped}"))


def _print_grand_summary(
    module_stats: dict[str, ModuleStats],
    total_duration: float,
    exit_code: int,
) -> None:
    width = 76
    print()
    print(bold("=" * width))
    print(bold("  SUMMARY"))
    print(bold("=" * width))

    # Per-module table
    col_m = 36
    col_p = 8
    col_f = 8
    col_e = 8
    col_s = 8

    header = (
        f"  {'Module':<{col_m}}"
        f"{'Passed':>{col_p}}"
        f"{'Failed':>{col_f}}"
        f"{'Error':>{col_e}}"
        f"{'Skip':>{col_s}}"
    )
    print(dim(header))
    print(dim("  " + "-" * (col_m + col_p + col_f + col_e + col_s)))

    g_pass = g_fail = g_err = g_skip = 0
    for mod_name in sorted(module_stats):
        s = module_stats[mod_name]
        g_pass += s.passed
        g_fail += s.failed
        g_err  += s.error
        g_skip += s.skipped

        fail_col = red(f"{s.failed:>{col_f}}") if s.failed else f"{'0':>{col_f}}"
        err_col  = red(f"{s.error:>{col_e}}")  if s.error  else f"{'0':>{col_e}}"
        pass_col = green(f"{s.passed:>{col_p}}") if s.passed else f"{'0':>{col_p}}"

        print(
            f"  {mod_name:<{col_m}}"
            f"{pass_col}"
            f"{fail_col}"
            f"{err_col}"
            f"{s.skipped:>{col_s}}"
        )

    print(dim("  " + "-" * (col_m + col_p + col_f + col_e + col_s)))
    g_total = g_pass + g_fail + g_err + g_skip
    total_pass_str = green(f"{g_pass:>{col_p}}")
    total_fail_str = red(f"{g_fail:>{col_f}}") if g_fail else f"{'0':>{col_f}}"
    total_err_str  = red(f"{g_err:>{col_e}}")  if g_err  else f"{'0':>{col_e}}"
    print(
        f"  {'TOTAL':<{col_m}}"
        f"{total_pass_str}"
        f"{total_fail_str}"
        f"{total_err_str}"
        f"{g_skip:>{col_s}}"
    )

    print()
    verdict = green("ALL TESTS PASSED") if exit_code == 0 else red("TESTS FAILED")
    print(f"  {bold(verdict)}   {dim(f'{g_total} tests in {total_duration:.2f}s')}")
    print(bold("=" * width))
    print()


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(extra_args: list[str]) -> int:
    argv = _build_pytest_argv(extra_args)

    _print_header()
    print(dim(f"  Command: {' '.join(argv[2:])}"))
    print()

    start = time.monotonic()

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    raw_lines: list[str] = []
    current_module: str | None = None
    module_stats: dict[str, ModuleStats] = {}

    # --- Stream output, printing results as they arrive ---
    assert proc.stdout is not None
    for raw_line in proc.stdout:
        raw_lines.append(raw_line)
        line = raw_line.rstrip()

        m = _STATUS_RE.match(line)
        if not m:
            continue

        node_id = m.group("node").strip()
        status  = m.group("status")
        msg     = (m.group("msg") or "").strip()
        mod     = _module_from_node(node_id)
        name    = node_id.split("::")[-1]

        dur = 0.0
        dm = _DURATION_RE.search(line)
        if dm:
            dur = float(dm.group("sec"))

        result = TestResult(
            node_id=node_id,
            module=mod,
            name=name,
            status=status,
            duration_s=dur,
            short_msg=msg,
        )

        # Module header when we switch modules
        if mod != current_module:
            if current_module and current_module in module_stats:
                _print_module_stats(module_stats[current_module])
            _print_module_header(mod)
            current_module = mod

        if mod not in module_stats:
            module_stats[mod] = ModuleStats(name=mod)

        s = module_stats[mod]
        if status == "PASSED":   s.passed  += 1
        elif status == "FAILED": s.failed  += 1
        elif status == "ERROR":  s.error   += 1
        elif status == "SKIPPED":s.skipped += 1
        elif status == "XFAIL": s.xfail   += 1
        elif status == "XPASS": s.xpass   += 1
        s.results.append(result)

        _print_result(result)

    # Print stats for the last module
    if current_module and current_module in module_stats:
        _print_module_stats(module_stats[current_module])

    proc.wait()
    total_duration = time.monotonic() - start

    # --- Re-parse full output for failure details ---
    _, failure_lines, _ = _parse_lines(raw_lines)
    _print_failures(failure_lines)

    # --- Grand summary ---
    _print_grand_summary(module_stats, total_duration, proc.returncode)

    return proc.returncode


def main() -> None:
    # Strip our own flags before passing the rest to pytest
    args = [a for a in sys.argv[1:] if a not in ("--no-color",)]
    sys.exit(run(args))


if __name__ == "__main__":
    main()
