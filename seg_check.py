"""Which leads sit behind a secure email gateway (SEG), and which ones should not be emailed at all?

SEGs (Proofpoint, Mimecast, Barracuda...) check SURBL and Spamhaus DBL and block mail from
listed domains, including the tracking domain in the links; Google and Microsoft mostly don't.
For every lead this reads the company domain's MX and SPF records over free public DNS
(Google, falling back to Cloudflare), names the gateway, flags addresses that bounce or
are likely spam traps, and says what to do with the lead. Read-only: nothing is changed in
SmartLead, and the only thing that leaves the machine is the company domain in a DNS query.

    python seg_check.py acme.com a@b.com   # quick check, prints the verdict
    python seg_check.py --csv leads.csv    # any CSV with an email column; writes leads_seg.csv
    python seg_check.py --smartlead        # live SmartLead campaigns (needs SMARTLEAD_API_KEY)
    add --refresh to ignore the 14-day DNS cache, --json for JSON on a quick check
SmartLead mode writes seg_leads.csv and seg_leads_<date>.xlsx (Summary, Campaigns, Leads).
"""
import csv, json, os, re, socket, sys, time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from pathlib import Path
import requests
from seg_providers import SEG, NATIVE, PARKED, SPF_HINTS, FREE_MAIL, DISPOSABLE, ROLE

HERE = Path(__file__).parent
CACHE = HERE / "seg_cache.json"
TTL = timedelta(days=14)
DOH = [("https://dns.google/resolve", {}), ("https://cloudflare-dns.com/dns-query", {"accept": "application/dns-json"})]
SMARTLEAD = "https://server.smartlead.ai/api/v1"
REMOVE = {"dead": "domain does not exist", "no_mx": "domain has no mail server", "null_mx": "domain refuses all mail",
          "parked": "parked or for-sale domain", "disposable": "disposable address"}


def doh(name, rtype):
    """(dns status, answers) from the first resolver that answers; None if all fail."""
    for url, headers in DOH:
        try:
            j = requests.get(url, params={"name": name, "type": rtype}, headers=headers, timeout=15).json()
            if j.get("Status") in (0, 3):  # NOERROR, NXDOMAIN
                return j["Status"], j.get("Answer", [])
        except (requests.RequestException, ValueError):
            pass
    return None


def lookup(domain):
    mx, txt = doh(domain, "MX"), doh(domain, "TXT")
    if mx is None:
        return None
    hosts = [a["data"].split()[-1].rstrip(".").lower()
             for a in sorted((a for a in mx[1] if a.get("type") == 15), key=lambda a: int(a["data"].split()[0]))]
    spf = next((t for t in (a["data"].replace('" "', "").strip('"') for a in (txt or (0, []))[1] if a.get("type") == 16)
                if t.lower().startswith("v=spf1")), "")
    return {"t": date.today().isoformat(), "nx": mx[0] == 3, "mx": hosts, "spf": spf}


def matches(host, patterns):
    return any(host == p or host.endswith("." + p) for p in patterns)


def first(hosts, table):
    return next((name for name, pats in table for h in hosts if matches(h, pats)), None)


def classify(r):
    """(category, provider, spf hint) for one domain's lookup result."""
    if r is None:
        return "lookup_failed", "", ""
    if r["nx"]:
        return "dead", "", ""
    hosts = r["mx"]
    if not hosts:
        return "no_mx", "", ""
    if all(h == "" for h in hosts):
        return "null_mx", "", ""
    if first(hosts, [("parked", PARKED)]):
        return "parked", "", ""
    includes = [i.rstrip(".").lower() for i in re.findall(r"(?:include:|redirect=)(\S+)", r["spf"], re.I)]
    hint = first(includes, SPF_HINTS) or ""
    if gw := first(hosts, SEG):
        return "seg", gw, hint
    if native := first(hosts, NATIVE):
        return ("possible_seg" if hint else "native"), native, hint
    return ("possible_seg" if hint else "unknown"), "", hint


def check_domains(domains, refresh=False):
    cache = {} if refresh or not CACHE.exists() else json.loads(CACHE.read_text(encoding="utf-8"))
    fresh = date.today() - TTL
    todo = [d for d in domains if d not in cache or date.fromisoformat(cache[d]["t"]) < fresh]
    if todo:
        print(f"DNS lookups for {len(todo)} domains ({len(domains) - len(todo)} cached)...", file=sys.stderr)
        with ThreadPoolExecutor(16) as ex:
            for d, r in zip(todo, ex.map(lookup, todo)):
                if r is not None:
                    cache[d] = r
        CACHE.write_text(json.dumps(cache), encoding="utf-8")
    return {d: cache.get(d) for d in domains}


def verdict(email, res, listed_senders=()):
    """Fill the SEG columns for one address. listed_senders: blocklisted sending/tracking domains on its campaign."""
    local, _, domain = email.lower().rpartition("@")
    r = res.get(domain)
    cat, provider, hint = classify(r)
    flags = [f for f, hit in (("role", local in ROLE), ("personal", domain in FREE_MAIL), ("disposable", domain in DISPOSABLE)) if hit]
    if "disposable" in flags:
        cat = "disposable"
    if "personal" in flags:
        cat, provider = "personal", "free mailbox"
    if cat in REMOVE:
        action = "REMOVE: " + REMOVE[cat]
    elif cat == "lookup_failed":
        action = "RECHECK: DNS lookup failed"
    elif cat in ("seg", "possible_seg") and listed_senders:
        action = f"AT RISK: {provider if cat == 'seg' else hint} gateway, campaign sends from listed {', '.join(listed_senders)}"
    elif cat in ("seg", "possible_seg"):
        action = "SEG: send only from a clean domain, plain text, no links or open tracking"
    elif "role" in flags:
        action = "REVIEW: role inbox, spam trap risk"
    elif cat == "personal":
        action = "REVIEW: personal address"
    elif provider == "Google Workspace":
        action = "OK: best sent from a Google mailbox"
    elif provider == "Microsoft 365":
        action = "OK: best sent from an Outlook mailbox"
    else:
        action = "OK"
    return {"domain": domain, "category": cat, "gateway": provider if cat == "seg" else (hint if cat == "possible_seg" else ""),
            "provider": provider, "spf_hint": hint, "flags": " ".join(flags),
            "mx": " ".join(((r or {}).get("mx") or [])[:2]), "action": action}


def quick(targets, refresh, as_json):
    clean = {}
    for t in targets:
        v = t.lower().split("<")[-1].strip(" >\"'").removeprefix("mailto:").split("://")[-1].split("/")[0].split(":")[0].removeprefix("www.")
        clean[v if "@" in v else "x@" + v] = t
    res = check_domains(sorted({e.rpartition("@")[2] for e in clean}), refresh)
    out = [{"input": t, **verdict(e, res)} for e, t in clean.items()]
    if as_json:
        print(json.dumps(out, indent=2)); return
    for v in out:
        name = v["gateway"] or v["provider"] or v["category"]
        print(f"{v['domain']}  ->  {name}  [{v['category']}]\n    {v['action']}\n    MX: {v['mx'] or '-'}"
              + (f"\n    SPF names {v['spf_hint']}" if v["spf_hint"] else ""))


def from_csv(path, refresh):
    path = Path(path)
    with path.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    col = next((c for c in rows[0] if "email" in c.lower()), None) or next(c for c in rows[0] if "@" in (rows[0][c] or ""))
    res = check_domains(sorted({r[col].lower().rpartition("@")[2] for r in rows if "@" in (r[col] or "")}), refresh)
    for r in rows:
        r.update(verdict(r[col].strip(), res) if "@" in (r[col] or "") else {"action": "REVIEW: no email"})
    out = path.with_name(path.stem + "_seg.csv")
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r))); w.writeheader(); w.writerows(rows)
    summarise(rows)
    print("\n->", out)


def sl(path, params=None):
    p = dict(params or {}); p["api_key"] = os.environ["SMARTLEAD_API_KEY"]
    for a in range(8):
        r = requests.get(SMARTLEAD + path, params=p, timeout=120)
        if r.status_code in (429, 500, 502, 503, 504) and a < 7:
            time.sleep(15 if r.status_code == 429 else 3 * (a + 1)); continue
        r.raise_for_status()
        return r.json() if r.content else {}


def resolve(name):
    try: return socket.gethostbyname(name)
    except OSError: return None


def listed(domain):
    """Blocklists a sending domain is on. Uses the system resolver: SURBL and Spamhaus refuse public ones."""
    s, d = resolve(domain + ".multi.surbl.org"), resolve(domain + ".dbl.spamhaus.org")
    if d and d.startswith("127.255.255."): d = None  # refused, not a listing
    return [n for n, hit in (("SURBL", s and s.startswith("127.0.0.") and s != "127.0.0.254"),
                             ("Spamhaus", d and d.startswith("127.0.1."))) if hit]


def senders(cid):
    """Sending and tracking domains on a campaign and its mailbox types."""
    accts = sl(f"/campaigns/{cid}/email-accounts") or []
    doms = {a["from_email"].lower().rpartition("@")[2] for a in accts}
    track = {(a.get("custom_tracking_domain") or "").lower().removeprefix("https://").removeprefix("http://").split("/")[0] for a in accts} - {""}
    return {"types": Counter(a.get("type") or "?" for a in accts), "domains": doms, "tracking": track}


def from_smartlead(refresh):
    try:
        from dotenv import load_dotenv; load_dotenv(HERE / ".env")
    except ImportError:
        pass
    if "SMARTLEAD_API_KEY" not in os.environ:
        sys.exit("Set SMARTLEAD_API_KEY (environment or a .env file next to this script).")
    if resolve("test.surbl.org.multi.surbl.org") != "127.0.0.254":
        sys.exit("SURBL test lookup failed: this resolver is refused by SURBL, so listings cannot be checked.")
    camps = [c for c in sl("/campaigns") if c["status"] == "ACTIVE"]
    leads, info = [], {}
    for c in camps:
        info[c["id"]] = senders(c["id"])
        for status in ("STARTED", "INPROGRESS"):
            off = 0
            while True:
                r = sl(f"/campaigns/{c['id']}/leads", {"offset": off, "limit": 100, "status": status})
                for x in r.get("data", []):
                    e = (x["lead"].get("email") or "").lower()
                    if "@" in e:
                        leads.append({"campaign_id": c["id"], "campaign": c["name"], "status": status, "email": e})
                off += 100
                if len(r.get("data", [])) < 100:
                    break
    if not leads:
        sys.exit("No leads left to email in active campaigns.")
    sending = sorted(set().union(*(i["domains"] | i["tracking"] for i in info.values())))
    print(f"{len(camps)} active campaigns, {len(leads)} leads still to be emailed, checking {len(sending)} sending/tracking domains", file=sys.stderr)
    with ThreadPoolExecutor(8) as ex:
        bad = {d: hits for d, hits in zip(sending, ex.map(listed, sending)) if hits}
    res = check_domains(sorted({l["email"].rpartition("@")[2] for l in leads}), refresh)
    for l in leads:
        i = info[l["campaign_id"]]
        l.update(verdict(l["email"], res, sorted(d for d in i["domains"] | i["tracking"] if d in bad)))
    with (HERE / "seg_leads.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(leads[0])); w.writeheader(); w.writerows(leads)
    camp_rows = []
    for c in camps:
        mine = [l for l in leads if l["campaign_id"] == c["id"]]
        i = info[c["id"]]
        camp_rows.append({"campaign": c["name"], "id": c["id"], "leads to email": len(mine),
                          "behind a gateway": sum(l["category"] in ("seg", "possible_seg") for l in mine),
                          "at risk": sum(l["action"].startswith("AT RISK") for l in mine),
                          "remove": sum(l["action"].startswith("REMOVE") for l in mine),
                          "mailboxes": " ".join(f"{k} {v}" for k, v in i["types"].items()),
                          "listed sending domains": " ".join(f"{d} ({'+'.join(bad[d])})" for d in sorted(i["domains"]) if d in bad),
                          "listed tracking domains": " ".join(f"{d} ({'+'.join(bad[d])})" for d in sorted(i["tracking"]) if d in bad)})
    camp_rows.sort(key=lambda r: (-r["at risk"], -r["behind a gateway"]))
    summarise(leads)
    print("\nCampaigns with the most gateway leads at risk (gateway lead + listed sending or tracking domain):")
    for r in camp_rows[:15]:
        print(f"  {r['at risk']:5} at risk, {r['behind a gateway']:5} behind a gateway, of {r['leads to email']:5}  {r['campaign']}")
    xlsx = HERE / f"seg_leads_{date.today().isoformat()}.xlsx"
    write_xlsx(xlsx, leads, camp_rows, bad)
    print("\n->", HERE / "seg_leads.csv", "\n->", xlsx)


def summarise(rows):
    rows = [r for r in rows if "category" in r]
    n = max(1, len(rows))
    seg = sum(r["category"] in ("seg", "possible_seg") for r in rows)
    print(f"\nBehind a gateway: {seg} of {len(rows)} ({100 * seg / n:.0f}%), of which "
          f"{sum(r['category'] == 'possible_seg' for r in rows)} found only through SPF")
    print("By gateway:", dict(Counter(r["gateway"] for r in rows if r["gateway"]).most_common()))
    print("Actions:", dict(Counter(r["action"].split(":")[0] for r in rows).most_common()))
    print("Remove reasons:", dict(Counter(r["action"][8:] for r in rows if r["action"].startswith("REMOVE")).most_common()))


def write_xlsx(path, leads, camp_rows, bad):
    from openpyxl import Workbook
    from openpyxl.styles import Font
    wb = Workbook()
    ws = wb.active; ws.title = "Summary"
    lines = [("SEG check", date.today().isoformat()), ("Leads still to email", len(leads)),
             ("Behind a gateway", sum(l["category"] in ("seg", "possible_seg") for l in leads)),
             ("At risk (gateway + listed sender)", sum(l["action"].startswith("AT RISK") for l in leads)),
             ("Remove (dead, no MX, parked, disposable)", sum(l["action"].startswith("REMOVE") for l in leads)),
             ("Role inboxes to review", sum("role" in l["flags"] for l in leads)), ("", ""),
             ("Gateway", "Leads")] + Counter(l["gateway"] for l in leads if l["gateway"]).most_common() + [("", ""),
             ("Listed sending / tracking domain", "Lists")] + sorted((d, "+".join(h)) for d, h in bad.items())
    for row in lines:
        ws.append(list(row))
    ws["A1"].font = Font(bold=True, size=14)
    ws.column_dimensions["A"].width = 45; ws.column_dimensions["B"].width = 18
    for title, rows in (("Campaigns", camp_rows), ("Leads", leads)):
        s = wb.create_sheet(title)
        s.append(list(rows[0])); [s.append(list(r.values())) for r in rows]
        for c in s[1]: c.font = Font(bold=True)
        s.freeze_panes = "A2"; s.auto_filter.ref = s.dimensions
        for col in s.columns:
            s.column_dimensions[col[0].column_letter].width = min(60, max(10, *(len(str(c.value or "")) for c in col[:200])))
    wb.save(path)


if __name__ == "__main__":
    args = sys.argv[1:]
    refresh = "--refresh" in args
    rest = [a for a in args if not a.startswith("--")]
    if "--csv" in args:
        from_csv(rest[0], refresh)
    elif "--smartlead" in args:
        from_smartlead(refresh)
    elif rest:
        quick(rest, refresh, "--json" in args)
    else:
        print(__doc__)
