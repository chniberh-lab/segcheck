# segcheck

Find out which of your cold email leads sit behind a secure email gateway (SEG), which ones will bounce, and which campaigns are sending to gateway-protected inboxes from blocklisted domains.

Free and read-only. It uses public DNS only (Google, with Cloudflare as a fallback), needs no paid API, and sends no mail.

## Why it matters

Gateways like Proofpoint, Mimecast and Barracuda check every inbound message against URI blocklists such as SURBL and Spamhaus DBL. That covers the sending domain and every link domain in the body, including your open-tracking domain. Google Workspace and Microsoft 365 mostly don't. So a sending domain can look healthy on Gmail and Outlook while every message to a gateway-protected lead is silently dropped.

## What it checks

For each lead's domain:

- **Gateway from MX records.** 27 gateways, matched on exact DNS labels so `notpphosted.com` never counts as Proofpoint.
- **Hidden gateways from SPF.** A domain whose mail lands at Microsoft or Google but whose SPF record names Mimecast, Proofpoint and so on is flagged `possible_seg`. MX-only tools miss these.
- **Undeliverable domains.** Dead (NXDOMAIN), no MX, null MX (RFC 7505), parked or for-sale.
- **Risky addresses.** Role inboxes (info@, sales@...), personal mailboxes, disposable domains.

In SmartLead mode it also checks every campaign's sending domains and tracking domains against SURBL and Spamhaus DBL, and marks a gateway lead **AT RISK** when its campaign sends from a listed domain.

Every lead gets one action:

| Action | Meaning |
|---|---|
| `REMOVE` | Dead, no mail server, refuses mail, parked or disposable |
| `AT RISK` | Behind a gateway, and the campaign sends from a listed domain |
| `SEG` | Behind a gateway; send from a clean domain, plain text, no links or open tracking |
| `REVIEW` | Role inbox or personal address |
| `OK` | Google or Microsoft without a gateway; match the sender type where you can |
| `RECHECK` | DNS lookup failed |

## Install

```bash
git clone https://github.com/chniberh-lab/segcheck
cd segcheck
pip install -r requirements.txt
```

Python 3.9 or newer.

## Use

Quick check of domains or addresses (messy pasted input is fine):

```bash
python seg_check.py salesforce.com "Jane <jane@bp.com>" https://www.example.com
```

```
salesforce.com  ->  Proofpoint  [seg]
    SEG: send only from a clean domain, plain text, no links or open tracking
    MX: mxa-00177002.gslb.pphosted.com mxb-00177002.gslb.pphosted.com
```

A lead list (any CSV with an email column). Writes `leads_seg.csv` with your columns plus the verdict:

```bash
python seg_check.py --csv leads.csv
```

Live SmartLead campaigns. Put `SMARTLEAD_API_KEY=...` in your environment or in a `.env` file next to the script:

```bash
python seg_check.py --smartlead
```

This reads every active campaign's leads that still have emails to receive, plus each campaign's mailboxes, and writes `seg_leads.csv` and an Excel workbook with Summary, Campaigns and Leads sheets. It changes nothing in SmartLead.

Options: `--refresh` ignores the 14-day DNS cache, `--json` prints JSON for a quick check.

The blocklist check runs through your system DNS resolver, because SURBL and Spamhaus refuse queries from public resolvers. The script tests this first and stops if your resolver is refused.

## Limits

- **API-based security tools are invisible.** Abnormal, Avanan, IRONSCALES, Material and similar tools connect to Microsoft 365 or Google by API and leave the MX records alone. The SPF hint catches some gateways in front of Microsoft, not these.
- **Spam traps can't be identified directly.** No free tool can say an address is a trap. This flags the patterns traps hide behind: dead and parked domains, role inboxes, disposable domains.
- **AT RISK is per campaign.** SmartLead rotates mailboxes, so a lead flagged at risk may still go out from a clean domain in that campaign.

## Add a gateway

Append a line to `seg_providers.py`:

```python
("Some Gateway", ["somegateway.com"]),
```

## Tests

```bash
python -m pytest
```

The tests use injected DNS data and need no network.

## License

MIT. Part of the provider list comes from [esgcheck](https://github.com/floris-maker/esgcheck) (MIT).
