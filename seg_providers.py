"""Fingerprints used by seg_check.py. Add a provider by appending a line.

Patterns match on a DNS-label boundary: "pphosted.com" matches "mx1.acme.com.pphosted.com"
but not "notpphosted.com". Gateways are tried before native providers, so a domain whose MX
lists both (a gateway with a Microsoft fallback) is reported as the gateway.
The provider list builds on floris-maker/esgcheck (MIT), extended with gateways seen in real lead lists.
"""

SEG = [  # third-party secure email gateways: screen inbound mail and check SURBL/DBL
    ("Proofpoint", ["pphosted.com", "ppe-hosted.com", "gpphosted.com", "ppops.net"]),
    ("Mimecast", ["mimecast.com", "mimecast.co.za", "mimecast-offshore.com", "mimecast.com.au"]),
    ("Barracuda", ["barracudanetworks.com", "barracuda.com"]),
    ("Cisco Secure Email", ["iphmx.com"]),
    ("Sophos", ["sophos.com"]),
    ("Symantec / Broadcom", ["messagelabs.com"]),
    ("Forcepoint", ["mailcontrol.com"]),
    ("Trend Micro", ["trendmicro.com", "trendmicro.eu"]),
    ("Cloudflare Email Security", ["cf-emailsecurity.net", "mx.cloudflare.net", "mxrecord.io", "mxrecord.mx", "area1security.com"]),
    ("Trellix / FireEye", ["fireeyecloud.com"]),
    ("Perception Point", ["perceptionpoint.io"]),
    ("MailChannels", ["mailchannels.net"]),
    ("Mailprotector", ["mailprotector.com"]),
    ("Fortinet FortiMail", ["fortimail.com", "fortimailcloud.com"]),
    ("Hornetsecurity", ["antispameurope.com", "hornetsecurity.com"]),
    ("AppRiver / Zix", ["arsmtp.com", "zixmail.net"]),
    ("Retarus", ["retarus.com"]),
    ("N-able Mail Assure", ["antispamcloud.com", "spamexperts.com"]),
    ("SpamTitan", ["titanhq.com", "spamtitan.com"]),
    ("MailRoute", ["mroute.net"]),
    ("SpamHero", ["spamhero.com", "spamhero.net"]),
    ("Libraesva", ["libraesva.com"]),
    ("FuseMail / VIPRE", ["electric.net"]),
    ("MailGuard", ["mailguard.com.au"]),
    ("Trustwave", ["trustwave.com"]),
    ("SiteGround filter", ["mailspamprotection.com"]),
    ("GoSecure", ["gosecure.net"]),
]

NATIVE = [  # mailbox hosts with built-in filtering only
    ("Microsoft 365", ["protection.outlook.com", "mx.microsoft", "outlook.com", "protection.office365.us"]),
    ("Yahoo", ["yahoodns.net"]),
    ("Google Workspace", ["google.com", "googlemail.com"]),
    ("Zoho", ["zoho.com", "zoho.eu", "zohomail.com"]),
    ("Fastmail", ["messagingengine.com", "fastmail.com"]),
    ("Proton Mail", ["protonmail.ch"]),
    ("Rackspace", ["emailsrvr.com"]),
    ("GoDaddy", ["secureserver.net"]),
    ("OVH", ["ovh.net"]),
    ("IONOS", ["1and1.com", "kundenserver.de", "ionos.com"]),
    ("Namecheap", ["privateemail.com", "registrar-servers.com"]),
    ("Yandex", ["yandex.ru", "yandex.net"]),
]

PARKED = ["sedoparking.com", "parkingcrew.net", "bodis.com", "above.com", "parklogic.com", "dan.com", "afternic.com"]

# SPF include -> gateway. A Microsoft/Google MX with one of these in SPF usually means the
# gateway handles outbound and often inbound too via a connector the MX does not show.
SPF_HINTS = [
    ("Mimecast", ["mimecast.com"]),
    ("Proofpoint", ["pphosted.com", "ppe-hosted.com"]),
    ("Barracuda", ["barracudanetworks.com"]),
    ("Cisco Secure Email", ["iphmx.com"]),
    ("Symantec / Broadcom", ["messagelabs.com"]),
    ("Forcepoint", ["mailcontrol.com"]),
    ("Sophos", ["sophos.com"]),
    ("Trend Micro", ["trendmicro.com", "trendmicro.eu"]),
    ("Hornetsecurity", ["hornetsecurity.com", "antispameurope.com"]),
]

FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com",
             "yahoo.com", "yahoo.co.uk", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com",
             "gmx.com", "gmx.de", "web.de", "mail.com", "zoho.com", "yandex.com", "btinternet.com", "comcast.net"}

DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
              "yopmail.com", "trashmail.com", "getnada.com", "sharklasers.com", "dispostable.com", "maildrop.cc"}

# Role inboxes are shared, rarely opted in, and a classic home for spam traps.
ROLE = {"info", "sales", "admin", "contact", "hello", "office", "support", "help", "enquiries", "inquiries",
        "marketing", "hr", "jobs", "careers", "recruitment", "accounts", "billing", "finance", "team", "mail",
        "webmaster", "postmaster", "hostmaster", "abuse", "noreply", "no-reply", "privacy", "legal", "security",
        "press", "media", "reception", "general", "service", "customerservice", "feedback"}
