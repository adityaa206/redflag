"""
scanners/nmap_scan.py — the Nmap runner. The base of the evidence pipeline.

Produces the XML that analysis/parser.py turns into the finding set everything
else correlates into. Optionally attaches the Vulners NSE script, whose output
is parsed straight out of the same XML by scanners/vulners_parse.py — no extra
network call from RedFlag.

Two things make this module unlike every other scanner:

  1. It is the ONLY scanner that RAISES. run_nmap_scan throws FileNotFoundError
     when the binary is missing, because without Nmap there is no assessment —
     silence would be worse than an error.
  2. It is the loudest thing RedFlag does. Nmap sends packets directly to the
     target and will appear in its logs. Authorised targets only — see
     docs/legal/AUTHORIZED_USE.md.

Binary discovery is by ABSOLUTE WINDOWS PATH and does not consult PATH, so a
Homebrew or Linux install will not be found (see find_nmap below).

Callers must pass output_dir OUTSIDE the repository. Writing scan output inside
the worktree trips Reflex's dev file-watcher, which hot-reloads the backend
mid-scan and loses the findings.
"""
import os
import datetime
import nmap
from dotenv import load_dotenv
from config import NMAP_SCAN_ARGS, NMAP_FAST_ARGS

load_dotenv()

NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def find_nmap():
    """Return the Nmap binary path, or None if it is not in a known location.

    Probes NMAP_PATHS only — it does NOT consult PATH or use shutil.which, so a
    macOS/Linux install (/opt/homebrew/bin/nmap, /usr/local/bin/nmap) will not
    be found. Add your path to NMAP_PATHS above, or use RedFlag's upload-only
    mode, which needs no local Nmap at all.
    """
    for path in NMAP_PATHS:
        if os.path.exists(path):
            return path
    return None


def _vulners_script_args(nmap_path: str) -> str:
    """
    Return '--script vulners' arguments if the NSE script is installed.
    Includes API key if VULNERS_API_KEY is set. Returns '' if not installed.
    """
    scripts_dir = os.path.join(os.path.dirname(nmap_path), "scripts")
    if not os.path.exists(os.path.join(scripts_dir, "vulners.nse")):
        return ""
    key = os.getenv("VULNERS_API_KEY", "")
    args = " --script vulners --script-args vulners.mincvss=5.0"
    if key:
        args += f",api_key={key}"
    return args


def vulners_nse_available() -> bool:
    """Return True if vulners.nse is present in the Nmap scripts directory."""
    nmap_path = find_nmap()
    if not nmap_path:
        return False
    scripts_dir = os.path.join(os.path.dirname(nmap_path), "scripts")
    return os.path.exists(os.path.join(scripts_dir, "vulners.nse"))


def run_nmap_scan(target: str, output_dir: str = "data/results", fast_mode: bool = False) -> str:
    os.makedirs(output_dir, exist_ok=True)

    nmap_path = find_nmap()
    if not nmap_path:
        raise FileNotFoundError(
            "Could not find nmap.exe. Check whether Nmap is installed in Program Files."
        )

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace("\\", "_").replace(":", "_")
    output_file = os.path.join(output_dir, f"nmap_{safe_target}_{timestamp}.xml")

    scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))

    base_args = NMAP_FAST_ARGS if fast_mode else NMAP_SCAN_ARGS
    mode_label = "fast (top 200 ports)" if fast_mode else "full"
    print(f"[INFO] Using Nmap binary: {nmap_path}")
    print(f"[INFO] Starting Nmap scan on: {target}  [{mode_label}]")

    vulners_args = _vulners_script_args(nmap_path)
    if vulners_args:
        print("[INFO] Vulners NSE script detected — adding CVE lookup to scan.")
    else:
        print("[INFO] Vulners NSE script not found — skipping CVE lookup (see README to install).")

    scanner.scan(
        hosts=target,
        arguments=f"{base_args}{vulners_args}"
    )

    xml_output = scanner.get_nmap_last_output()

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(xml_output.decode("utf-8"))

    host_count = len(scanner.all_hosts())
    print(f"[INFO] Scan complete. Hosts found: {host_count}")
    print(f"[INFO] XML saved to: {output_file}")

    return output_file


if __name__ == "__main__":
    target = input("Enter target IP / host / subnet: ").strip()
    xml_path = run_nmap_scan(target)
    print(f"\nDone. File: {xml_path}")