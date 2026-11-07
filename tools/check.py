"""Run the release checks and generate the README badges from their exit status."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
BADGES = ROOT / "docs/badges"


def badge(name, label, value, color):
    left, right = (len(s) * 7 + 16 for s in (label, value))
    width = left + right
    title = escape(f"{label}: {value}")
    (BADGES / f"{name}.svg").write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="22" role="img" aria-label="{title}">\n'
        f'  <title>{title}</title><clipPath id="r"><rect width="{width}" height="22" rx="4"/></clipPath>\n'
        f'  <g clip-path="url(#r)"><rect width="{left}" height="22" fill="#314d49"/>'
        f'<rect x="{left}" width="{right}" height="22" fill="{color}"/></g>\n'
        f'  <g fill="white" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">'
        f'<text x="{left/2:g}" y="15">{escape(label)}</text>'
        f'<text x="{left+right/2:g}" y="15">{escape(value)}</text></g>\n</svg>\n', encoding="utf-8", newline="\n")


def main(coverage_only=False):
    os.chdir(ROOT)
    REPORTS.mkdir(exist_ok=True)
    BADGES.mkdir(parents=True, exist_ok=True)
    os.environ["COVERAGE_FILE"] = str(REPORTS / ".coverage")
    cov = [sys.executable, "-m", "coverage"]
    results = {}

    def check(name, command):
        print(f"\nRunning {name}", flush=True)
        try:
            results[name] = subprocess.run(command).returncode == 0
        except OSError as err:
            print(err, file=sys.stderr)
            results[name] = False
        return results[name]

    coverage_file = REPORTS / "coverage.json"
    coverage_file.unlink(missing_ok=True)
    (REPORTS / "coverage.xml").unlink(missing_ok=True)
    if check("Python unit tests", [*cov, "run", "--branch", "--source=sipdock", "-m",
                                   "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"]):
        subprocess.run([*cov, "json", "-o", str(coverage_file)], check=True)
        subprocess.run([*cov, "xml", "-o", str(REPORTS / "coverage.xml")], check=True)
        totals = json.loads(coverage_file.read_text())["totals"]
        lines = round(100 * totals["covered_lines"] / totals["num_statements"])
        badge("coverage", "Python line coverage", f"{lines}%", "#437467")
    else:
        badge("coverage", "Python line coverage", "unavailable", "#854b43")

    if coverage_only:
        return 0 if results["Python unit tests"] else 1

    if check("Production image", ["docker", "build", "-t", "sipdock:local", "."]):
        check("UDP calls and capacity", ["docker", "run", "--rm", "--network", "none", "--cap-add", "NET_ADMIN",
              "--sysctl", "net.ipv6.bindv6only=1", "--add-host", "proxy:127.0.0.1",
              "-v", f"{ROOT}/tests:/tests:ro", "--tmpfs", "/etc/sipdock",
              "--entrypoint", "python3", "sipdock:local", "/tests/calls.py", "--capacity-matrix"])
        check("Mutual TLS and dual-stack ingress", ["sh", "tests/security.sh"])

    passed = sum(results.values())
    success = passed == 4
    badge("tests", "release checks", f"{passed}/4 passed", "#437467" if success else "#854b43")
    (REPORTS / "checks.json").write_text(json.dumps(results, indent=2) + "\n")
    return 0 if success else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage-only", action="store_true",
                        help="run the Python tests and refresh the coverage badge")
    sys.exit(main(parser.parse_args().coverage_only))
