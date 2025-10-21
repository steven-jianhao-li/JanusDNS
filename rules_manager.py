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
    Checks if a single packet matches a given rule based on the new nested schema.
    """
    condition = rule.get("trigger_condition", {})
    
    # Helper for safe access
    def check(layer, field, packet_val):
        val = condition.get(layer, {}).get(field)
        return val is None or val == "" or val == packet_val

    # --- 核心修改：适配扁平化的 DNS 条件结构 ---
    # L7/DNS (Mandatory)
    # 直接从 condition 对象获取 dns_qname 和 dns_qtype
    packet_qname = packet[DNS].qd.qname.decode().rstrip('.')
    rule_qname = condition.get("dns_qname", "").rstrip('.') # 使用 dns_qname
    
    # 检查查询名称和类型是否匹配。
    if (packet_qname != rule_qname or
        packet[DNS].qd.qtype != condition.get("dns_qtype")): # 使用 dns_qtype
        return False

    # L2
    if not check('l2', 'src_mac', packet[Ether].src): return False
    if not check('l2', 'dst_mac', packet[Ether].dst): return False

    # L3
    if not check('l3', 'src_ip', packet[IP].src): return False
    if not check('l3', 'dst_ip', packet[IP].dst): return False
    if not check('l3', 'ttl', packet[IP].ttl): return False
    if not check('l3', 'protocol', packet[IP].proto): return False

    # L4
    if not check('l4', 'src_port', packet[UDP].sport): return False
    if not check('l4', 'dst_port', packet[UDP].dport): return False

    # L7/DNS Flags (Optional) - 注意：此部分逻辑仍依赖嵌套结构，如果需要请一并修改
    # 为了最小改动，我们暂时保持原样，因为它不是当前问题的核心
    dns_cond = condition.get('dns', {}) # 保留此行以兼容可能存在的dns.flags
    dns_flags_cond = dns_cond.get('flags', {})
    if dns_flags_cond:
        if 'rd' in dns_flags_cond and dns_flags_cond['rd'] != packet[DNS].rd: return False
        if 'opcode' in dns_flags_cond and dns_flags_cond['opcode'] != packet[DNS].opcode: return False
        # ... add other flag checks as needed
    
    print(f"[*] Packet matched rule: {rule.get('name', rule.get('rule_id'))}")
    return True

# Initialize by loading rules on startup
load_rules()
