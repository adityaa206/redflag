"""
brain_memory.py — RedFlag's persistent, self-improving attacker-brain memory.

"Learning by remembering", not "learning by retraining". No LLM, no GPU, no
training loop, no paid API — just a knowledge base on disk that ACCUMULATES
across every scan and gets sharper as the corpus grows.

Two operations drive the loop:

  • learn_from_scan(findings, plan, target)
        Fold this scan's techniques / CVEs / services / attack-paths into the
        knowledge base: bump prevalence weights, remember CISA-KEV status, and
        write linked Obsidian notes (Markdown + [[wikilinks]]) so the vault's
        graph view wires every CVE → technique → scan together.

  • recall(findings, plan)
        BEFORE learning, look up what the brain already knows and return
        prevalence-weighted insights ("this CVE has appeared in 3 prior scans",
        "this exact kill-chain has been seen before") so each analysis benefits
        from everything seen so far.

The store lives OUTSIDE the project tree (default ~/RedFlag-Brain) because it is
long-term memory — it must survive app restarts, and writing inside the Reflex
worktree would trip the dev file-watcher and hot-reload the app mid-scan (the
same reason nmap writes to a temp dir). Override with $REDFLAG_BRAIN_DIR.

The vault is a real Obsidian vault: point Obsidian at ~/RedFlag-Brain/vault and
open Graph View to literally see the brain grow.

Pure stdlib — no Reflex, no third-party deps — so any UI can consume it.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone


# ── helpers ───────────────────────────────────────────────────────────────────
def _v(x) -> str:
    return str(getattr(x, "value", x))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(s)).strip("-")
    return s or "item"


def _path_sig(plan) -> str:
    """Stable signature for a kill-chain: its ordered MITRE technique IDs."""
    tids = []
    for s in getattr(plan, "steps", []) or []:
        tid = getattr(s, "tid", "")
        if tid:
            tids.append(tid)
    return " → ".join(tids) if len(tids) >= 2 else ""


# CISA Known Exploited Vulnerabilities — free public feed, no key required.
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Repo-bundled seed brain. A fresh clone starts pre-loaded from this instead of
# empty (see _bootstrap_from_seed). Refresh it from your local brain with:
#   python -m analysis.brain_memory   (writes a sanitised snapshot here)
_SEED_PATH = os.path.join(os.path.dirname(__file__), "brain_seed", "brain.json")


# ── read-side containers (the UI flattens these into view-models) ─────────────
@dataclass
class BrainStats:
    scans: int
    techniques: int
    cves: int
    services: int
    paths: int
    kev_known: int
    last_seen: str
    vault_path: str


@dataclass
class BrainInsight:
    label: str
    sub: str
    weight: int
    kind: str   # "technique" | "cve" | "path" | "service"


class BrainMemory:
    """File-backed knowledge base. One JSON index + one Obsidian vault."""

    VERSION = 1

    def __init__(self, root: str | None = None):
        self.root = (root or os.environ.get("REDFLAG_BRAIN_DIR")
                     or os.path.join(os.path.expanduser("~"), "RedFlag-Brain"))
        self.index_path = os.path.join(self.root, "brain.json")
        self.vault = os.path.join(self.root, "vault")
        self.data = self._load()

    # ── persistence ──────────────────────────────────────────────────────────
    def _blank(self) -> dict:
        return {
            "version": self.VERSION, "scans": 0,
            "first_seen": "", "last_seen": "",
            "techniques": {}, "cves": {}, "services": {}, "ports": {},
            "targets": {}, "paths": {}, "tiers": {},
            "kev": {"cves": [], "count": 0, "updated": ""},
        }

    def _load(self) -> dict:
        # First run on a machine: seed from the repo-bundled brain so a fresh
        # clone starts pre-loaded with accumulated knowledge instead of empty.
        if not os.path.exists(self.index_path):
            self._bootstrap_from_seed()
        try:
            with open(self.index_path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            base = self._blank()
            if isinstance(d, dict):
                base.update(d)
            return base
        except Exception:
            return self._blank()

    def _bootstrap_from_seed(self) -> None:
        """Copy the repo-bundled seed into the local store (best-effort)."""
        try:
            if os.path.exists(_SEED_PATH):
                os.makedirs(self.root, exist_ok=True)
                shutil.copyfile(_SEED_PATH, self.index_path)
        except Exception:
            pass

    def export_seed(self, dest: str | None = None) -> str:
        """Snapshot this machine's brain into the repo seed, sanitised to share.

        Strips the `targets` map — the only place a scanned host/IP is named — so
        the shipped seed carries aggregate pattern knowledge (technique / CVE /
        service / path prevalence + KEV) without revealing who was scanned.
        """
        data = json.loads(json.dumps(self.data))   # deep copy
        data["targets"] = {}                        # drop who-was-scanned
        dest = dest or _SEED_PATH
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, dest)
        return dest

    def _save(self) -> None:
        try:
            os.makedirs(self.root, exist_ok=True)
            tmp = self.index_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.index_path)
        except Exception:
            pass

    # ── recall: read prior knowledge (call BEFORE learn) ─────────────────────
    def recall(self, findings: list, plan) -> tuple[str, list[BrainInsight]]:
        d = self.data
        cves = d.get("cves", {})
        paths = d.get("paths", {})
        prior_scans = int(d.get("scans", 0))

        items: list[BrainInsight] = []
        seen_cve = 0
        cur_cves = sorted({getattr(f, "cve_id", None)
                           for f in (findings or []) if getattr(f, "cve_id", None)})
        for cve in cur_cves:
            meta = cves.get(cve)
            cnt = int(meta.get("count", 0)) if meta else 0
            if cnt <= 0:
                continue
            seen_cve += 1
            sub = f"seen in {cnt} prior scan" + ("" if cnt == 1 else "s")
            if meta.get("kev"):
                sub += " · KEV"
            items.append(BrainInsight(cve, sub, cnt, "cve"))
        items.sort(key=lambda b: b.weight, reverse=True)
        items = items[:6]

        sig = _path_sig(plan)
        path_prior = int(paths.get(sig, 0)) if sig else 0

        if prior_scans == 0:
            summary = ("First scan on record — the brain is starting its memory. "
                       "Re-scan targets over time and it will recognise recurring CVEs, "
                       "services and attack paths automatically.")
        else:
            bits = [f"Cross-referenced against {prior_scans} prior scan"
                    + ("" if prior_scans == 1 else "s")]
            if seen_cve:
                bits.append(f"{seen_cve} CVE" + ("" if seen_cve == 1 else "s")
                            + " recognised from before")
            if path_prior:
                bits.append("this exact kill-chain has been seen before")
            summary = " · ".join(bits) + "."
        return summary, items

    # ── learn: fold this scan into the brain (call AFTER recall) ─────────────
    def learn_from_scan(self, findings: list, plan, target: str = "") -> None:
        d = self.data
        ts = _now()
        d["scans"] = int(d.get("scans", 0)) + 1
        if not d.get("first_seen"):
            d["first_seen"] = ts
        d["last_seen"] = ts

        kev_set = set(d.get("kev", {}).get("cves", []))

        for f in findings or []:
            svc = (getattr(f, "service", None) or "").lower()
            port = getattr(f, "port", None)
            cve = getattr(f, "cve_id", None)
            cvss = float(getattr(f, "cvss_score", 0) or 0)
            tier = _v(getattr(f, "deal_tier", "unscored"))
            es = _v(getattr(f, "exploit_status", "unknown"))
            inet = _v(getattr(f, "exposure", "unknown")) == "internet_facing"

            if svc:
                s = d["services"].setdefault(svc, {"count": 0, "inet": 0})
                s["count"] += 1
                if inet:
                    s["inet"] += 1
            if port:
                d["ports"].setdefault(str(port), {"count": 0})["count"] += 1
            if cve:
                c = d["cves"].setdefault(cve, {"count": 0, "cvss": 0.0,
                                               "kev": False, "services": []})
                c["count"] += 1
                c["cvss"] = max(float(c.get("cvss", 0)), cvss)
                if es == "active_exploitation" or cve in kev_set:
                    c["kev"] = True
                if svc and svc not in c["services"]:
                    c["services"].append(svc)
            d["tiers"][tier] = int(d["tiers"].get(tier, 0)) + 1

        for step in getattr(plan, "steps", []) or []:
            tid = getattr(step, "tid", "")
            if not tid:
                continue
            t = d["techniques"].setdefault(tid, {"count": 0, "name": ""})
            t["count"] += 1
            t["name"] = getattr(step, "technique", "") or t.get("name", "")

        sig = _path_sig(plan)
        if sig:
            d["paths"][sig] = int(d["paths"].get(sig, 0)) + 1

        if target:
            tg = d["targets"].setdefault(target, {"scans": 0, "last": ""})
            tg["scans"] += 1
            tg["last"] = ts

        self._save()
        self._write_vault(findings, plan, target, ts)

    # ── stats / insights (read, post-learn) ──────────────────────────────────
    def stats(self) -> BrainStats:
        d = self.data
        return BrainStats(
            scans=int(d.get("scans", 0)),
            techniques=len(d.get("techniques", {})),
            cves=len(d.get("cves", {})),
            services=len(d.get("services", {})),
            paths=len(d.get("paths", {})),
            kev_known=int(d.get("kev", {}).get("count", 0)),
            last_seen=d.get("last_seen", ""),
            vault_path=self.vault,
        )

    def top_techniques(self, limit: int = 6) -> list[BrainInsight]:
        d = self.data
        out: list[BrainInsight] = []
        for tid, m in sorted(d.get("techniques", {}).items(),
                             key=lambda kv: kv[1].get("count", 0), reverse=True)[:limit]:
            cnt = int(m.get("count", 0))
            name = m.get("name", "") or "technique"
            out.append(BrainInsight(tid, f"{name} · {cnt}×", cnt, "technique"))
        return out

    # ── optional: ingest the free CISA KEV feed (manual, best-effort) ────────
    def ingest_kev(self) -> tuple[bool, str, int]:
        import urllib.request
        try:
            req = urllib.request.Request(_KEV_URL, headers={"User-Agent": "RedFlag/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.load(resp)
            cves = sorted({v.get("cveID") for v in payload.get("vulnerabilities", [])
                           if v.get("cveID")})
        except Exception as e:
            return False, f"Couldn't reach the CISA KEV feed (offline?) — {e}", 0
        self.data["kev"] = {"cves": cves, "count": len(cves), "updated": _now()}
        kev_set = set(cves)
        for cve, meta in self.data.get("cves", {}).items():
            if cve in kev_set:
                meta["kev"] = True
        self._save()
        return True, f"Threat intel updated — {len(cves)} known-exploited CVEs in the brain.", len(cves)

    # ── Obsidian vault writer (best-effort; never raises to the caller) ──────
    def _write_vault(self, findings, plan, target, ts):
        try:
            scans_dir = os.path.join(self.vault, "Scans")
            tech_dir = os.path.join(self.vault, "Techniques")
            cve_dir = os.path.join(self.vault, "CVEs")
            for p in (scans_dir, tech_dir, cve_dir):
                os.makedirs(p, exist_ok=True)
            self._write_readme()

            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            tname = _slug(target or "target")
            cur_cves = sorted({getattr(f, "cve_id", None)
                               for f in (findings or []) if getattr(f, "cve_id", None)})
            cur_tids: list[str] = []
            for s in getattr(plan, "steps", []) or []:
                tid = getattr(s, "tid", "")
                if tid and tid not in cur_tids:
                    cur_tids.append(tid)

            lines = ["---", f"target: {target or 'target'}", f"scanned: {ts}",
                     f"findings: {len(findings or [])}", "---", "",
                     f"# Scan — {target or 'target'} ({stamp})", "",
                     f"- Findings: **{len(findings or [])}**", ""]
            if cur_tids:
                lines.append("## Techniques")
                lines += [f"- [[T-{t}]]" for t in cur_tids]
                lines.append("")
            if cur_cves:
                lines.append("## CVEs")
                lines += [f"- [[{c}]]" for c in cur_cves]
                lines.append("")
            if getattr(plan, "summary", ""):
                lines += ["## Attacker summary", plan.summary, ""]
            self._put(os.path.join(scans_dir, f"{tname}-{stamp}.md"), "\n".join(lines))

            for tid in cur_tids:
                m = self.data["techniques"].get(tid, {})
                self._put(
                    os.path.join(tech_dir, f"T-{tid}.md"),
                    f"# {tid} — {m.get('name', '')}\n\n"
                    f"- Seen in **{m.get('count', 0)}** scans\n"
                    f"- MITRE: https://attack.mitre.org/techniques/{tid.replace('.', '/')}/\n",
                )
            for cve in cur_cves:
                m = self.data["cves"].get(cve, {})
                kev = " · **CISA KEV**" if m.get("kev") else ""
                self._put(
                    os.path.join(cve_dir, f"{_slug(cve)}.md"),
                    f"# {cve}{kev}\n\n"
                    f"- Seen in **{m.get('count', 0)}** scans\n"
                    f"- Max CVSS: **{m.get('cvss', 0)}**\n"
                    f"- Services: {', '.join(m.get('services', [])) or '—'}\n",
                )
        except Exception:
            pass

    def _write_readme(self):
        path = os.path.join(self.vault, "README.md")
        if os.path.exists(path):
            return
        self._put(
            path,
            "# RedFlag Brain\n\n"
            "This is RedFlag's attacker-brain memory — an Obsidian vault that grows with "
            "every scan. Open this folder as a vault in Obsidian and use **Graph View** to "
            "see how scans, MITRE ATT&CK techniques and CVEs connect.\n\n"
            "Notes are written automatically. Anything you add becomes part of the brain's "
            "knowledge — there is no training step, the brain learns by remembering.\n",
        )

    @staticmethod
    def _put(path: str, text: str):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


if __name__ == "__main__":
    # Refresh the repo-bundled seed from THIS machine's accumulated brain, so a
    # fresh clone starts pre-loaded. Sanitised (target names stripped).
    #   python -m analysis.brain_memory
    _bm = BrainMemory()
    _out = _bm.export_seed()
    _s = _bm.stats()
    print(f"Brain seed written -> {_out}")
    print(f"  scans={_s.scans}  techniques={_s.techniques}  cves={_s.cves}  "
          f"services={_s.services}  paths={_s.paths}  kev={_s.kev_known}  (targets stripped)")
