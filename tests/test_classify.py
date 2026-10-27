"""Detection rules on injected DNS data; no network needed. Run with: python -m pytest"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from seg_check import classify, verdict


def r(mx, spf="", nx=False):
    return {"mx": mx, "spf": spf, "nx": nx}


def test_gateways():
    assert classify(r(["mx1.acme.com.pphosted.com"]))[:2] == ("seg", "Proofpoint")
    assert classify(r(["eu-smtp-inbound-1.mimecast.com", "acme-com.mail.protection.outlook.com"]))[:2] == ("seg", "Mimecast")


def test_label_boundary():
    assert classify(r(["mail.notpphosted.com"]))[0] == "unknown"


def test_spf_hint():
    m365 = ["acme-com.mail.protection.outlook.com"]
    assert classify(r(m365, "v=spf1 include:spf.protection.outlook.com include:eu._netblocks.mimecast.com -all")) == ("possible_seg", "Microsoft 365", "Mimecast")
    assert classify(r(m365, "v=spf1 include:notmimecast.com -all"))[0] == "native"
    assert classify(r(["mx.acme.com"], "v=spf1 include:spf.pphosted.com -all"))[0] == "possible_seg"


def test_undeliverable():
    assert classify(r([""]))[0] == "null_mx"
    assert classify(r([], nx=True))[0] == "dead"
    assert classify(r([]))[0] == "no_mx"
    assert classify(r(["mx.sedoparking.com"]))[0] == "parked"
    assert classify(None)[0] == "lookup_failed"


def test_actions():
    res = {"acme.com": r(["mx1.acme.com.pphosted.com"]), "gone.com": r([], nx=True), "shop.com": r(["aspmx.l.google.com"])}
    assert verdict("jo@acme.com", res)["action"].startswith("SEG")
    assert verdict("jo@acme.com", res, ["listed.com"])["action"].startswith("AT RISK")
    assert verdict("jo@gone.com", res)["action"].startswith("REMOVE")
    assert verdict("info@shop.com", res)["action"].startswith("REVIEW")
    assert verdict("jo@shop.com", res)["action"] == "OK: best sent from a Google mailbox"
