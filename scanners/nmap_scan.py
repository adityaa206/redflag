import os
import datetime
import nmap
from dotenv import load_dotenv

load_dotenv()

NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def find_nmap():
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


def run_nmap_scan(target: str, output_dir: str = "data/results") -> str:
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

    print(f"[INFO] Using Nmap binary: {nmap_path}")
    print(f"[INFO] Starting Nmap scan on: {target}")
    print("[INFO] This may take 1-2 minutes...")

    vulners_args = _vulners_script_args(nmap_path)
    if vulners_args:
        print("[INFO] Vulners NSE script detected — adding CVE lookup to scan.")
    else:
        print("[INFO] Vulners NSE script not found — skipping CVE lookup (see README to install).")

    scanner.scan(
        hosts=target,
        arguments=f"-sV --open{vulners_args}"
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