import json
import os
from scapy.all import IP, UDP, DNS, Ether

RULES_FILE = "rules.json"
rules = []

def load_rules():
    """
    Loads rules from the JSON file into the global rules list.
    """
    global rules
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
            rules = json.load(f)
        print(f"[*] Loaded {len(rules)} rules from {RULES_FILE}")
    else:
        rules = []
        print(f"[!] Rules file not found ({RULES_FILE}). Starting with an empty rule set.")
    return rules

def save_rules():
    """
    Saves the current rules list to the JSON file.
    """
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=2)
    print(f"[*] Saved {len(rules)} rules to {RULES_FILE}")

def find_matching_rule(packet):
    """
    Iterates through the loaded rules and finds the first one that matches the packet.
    
    :param packet: The incoming Scapy packet.
    :return: The matching rule dictionary or None if no match is found.
    """
    for rule in rules:
        if not rule.get("is_enabled", False):
            continue

        if match_rule(packet, rule):
            return rule
    return None

def match_rule(packet, rule):
    """
    Checks if a single packet matches a given rule based on the detailed nested schema
    from the README.md. Follows the "layer-by-layer, field-by-field" validation principle.
    """
    condition = rule.get("trigger_condition", {})

    # Helper for safe field checking. Returns True if rule field is not set (ANY) or matches packet.
    def check(rule_value, packet_value):
        return rule_value is None or rule_value == packet_value

    # --- L2 Matching (Ethernet) ---
    l2_cond = condition.get('l2', {})
    if l2_cond:
        if not check(l2_cond.get('src_mac'), packet.getlayer(Ether).src): return False
        if not check(l2_cond.get('dst_mac'), packet.getlayer(Ether).dst): return False

    # --- L3 Matching (IP) ---
    l3_cond = condition.get('l3', {})
    if l3_cond:
        ip_layer = packet.getlayer(IP)
        if not check(l3_cond.get('src_ip'), ip_layer.src): return False
        if not check(l3_cond.get('dst_ip'), ip_layer.dst): return False
        if not check(l3_cond.get('ttl'), ip_layer.ttl): return False
        if not check(l3_cond.get('protocol'), ip_layer.proto): return False
        # Note: ip_version is implicitly checked by the presence of the IP layer.

    # --- L4 Matching (UDP) ---
    l4_cond = condition.get('l4', {})
    if l4_cond:
        udp_layer = packet.getlayer(UDP)
        if not check(l4_cond.get('src_port'), udp_layer.sport): return False
        if not check(l4_cond.get('dst_port'), udp_layer.dport): return False

    # --- L7 Matching (DNS) ---
    dns_cond = condition.get('dns', {})
    if not dns_cond: # DNS condition is mandatory for a DNS rule
        return False

    dns_layer = packet.getlayer(DNS)
    
    # Step 1: Mandatory fields (qname, qtype)
    packet_qname = dns_layer.qd.qname.decode().rstrip('.')
    if dns_cond.get('qname') != packet_qname: return False
    if dns_cond.get('qtype') != dns_layer.qd.qtype: return False

    # Step 2: Optional DNS header and count fields
    if not check(dns_cond.get('transaction_id'), dns_layer.id): return False
    
    # Counts
    if not check(dns_cond.get('qd_count'), dns_layer.qdcount): return False
    if not check(dns_cond.get('an_count'), dns_layer.ancount): return False
    if not check(dns_cond.get('ns_count'), dns_layer.nscount): return False
    if not check(dns_cond.get('ar_count'), dns_layer.arcount): return False

    # Flags
    flags_cond = dns_cond.get('flags', {})
    if flags_cond:
        if not check(flags_cond.get('qr'), dns_layer.qr): return False
        if not check(flags_cond.get('opcode'), dns_layer.opcode): return False
        if not check(flags_cond.get('aa'), dns_layer.aa): return False
        if not check(flags_cond.get('tc'), dns_layer.tc): return False
        if not check(flags_cond.get('rd'), dns_layer.rd): return False
        if not check(flags_cond.get('ra'), dns_layer.ra): return False
        if not check(flags_cond.get('ad'), dns_layer.ad): return False
        if not check(flags_cond.get('cd'), dns_layer.cd): return False
        if not check(flags_cond.get('rcode'), dns_layer.rcode): return False

    print(f"[*] Packet matched rule: {rule.get('name', rule.get('rule_id'))}")
    return True

# Initialize by loading rules on startup
load_rules()
