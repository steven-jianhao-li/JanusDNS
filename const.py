# DNS Record Types
DNS_TYPES = {
    1: {"name": "A", "description": "IPv4 address"},
    2: {"name": "NS", "description": "Authoritative name server"},
    5: {"name": "CNAME", "description": "Canonical name for an alias"},
    6: {"name": "SOA", "description": "Start of a zone of authority"},
    12: {"name": "PTR", "description": "Domain name pointer"},
    15: {"name": "MX", "description": "Mail exchange"},
    16: {"name": "TXT", "description": "Text strings"},
    28: {"name": "AAAA", "description": "IPv6 address"},
    33: {"name": "SRV", "description": "Service locator"},
    255: {"name": "ANY", "description": "All records"},
}
