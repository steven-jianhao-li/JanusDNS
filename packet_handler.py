import threading
# 从 scapy.all 导入 get_if_addr
from scapy.all import sniff, IP, UDP, DNS, Ether, get_if_addr # Ether 已经在这里，很好
from scapy.all import sendp, DNSQR, DNSRR
import socket
import rules_manager
import log_manager
# 核心改动：从 scapy.arch 导入 get_if_list，用于获取接口名称
from scapy.arch import get_if_list

# --- Globals ---
stop_sniffing = threading.Event()
active_interfaces = []

def get_active_interfaces():
    """
    Gets a list of active non-loopback interface names for Scapy to sniff on.
    此函数已被重构，以返回 Scapy 需要的接口名称，而不是 IP 地址。
    """
    global active_interfaces
    
    # 清空旧列表
    active_interfaces.clear()
    
    # 获取系统中所有接口的名称
    all_ifaces = get_if_list()
    # Scapy 的 show() 函数可以打印详细的接口信息，用于调试
    # from scapy.all import show_interfaces
    # show_interfaces()
    
    # 遍历所有接口，找到有效的、非环回的接口
    # 注意：在某些系统中，环回接口可能名称不同，如 'lo' 或 'Loopback'
    # 我们通过一个常见的名称列表来排除它们
    loopback_keywords = ['loopback', 'lo', 'dummy']
    
    for iface_name in all_ifaces:
        # 检查接口名称是否包含环回关键字
        is_loopback = any(keyword in iface_name.lower() for keyword in loopback_keywords)
        if not is_loopback:
            active_interfaces.append(iface_name)

    # 如果没有找到合适的接口（例如只剩下环回），则给出警告
    if not active_interfaces:
        print("[!] Warning: Could not find any active non-loopback interfaces. Sniffing might fail.")
        # 在某些情况下，可以让 Scapy 自动选择，但这可能不符合预期
        # return []
    
    print(f"[*] Active interfaces found for sniffing: {active_interfaces}")
    return active_interfaces

def process_packet(packet):
    """
    Callback function to process each sniffed packet.
    """
    print("[*] Packet captured, processing...")
    # Step 1: Filter by destination IP
    # --- 修复：使用 Scapy 从已激活的接口直接获取 IP 地址，替代不可靠的 hostname 解析 ---
    # 我们遍历 `active_interfaces` 列表，并使用 `get_if_addr` 获取每个接口的 IP
    active_ips = [get_if_addr(iface) for iface in active_interfaces]
    # 清理掉可能为空或环回地址的结果
    active_ips = [ip for ip in active_ips if ip and not ip.startswith("127.")]
    
    print(f"[*] Active IPs for filtering: {active_ips}")
    if not IP in packet or packet[IP].dst not in active_ips:
        return

    # Step 2: Check for valid DNS Query
    if not (packet.haslayer(DNS) and packet[DNS].qr == 0): # qr=0 means query
        return
        
    print(f"[*] DNS Query captured for: {packet[DNS].qd.qname.decode()}")
    
    matched_rule = rules_manager.find_matching_rule(packet)
    if matched_rule:
        print(f"[*] Rule '{matched_rule.get('name')}' matched. Generating response...")
        response_packet = generate_response(packet, matched_rule)
        if response_packet:
            sendp(response_packet, verbose=0)
            print(f"[*] Response sent for {packet[DNS].qd.qname.decode()}")
            # Log the event
            log_manager.log_triggered_rule(matched_rule, packet)
            log_manager.save_pcap_files(matched_rule, packet, response_packet)

def get_response_value(config, query_packet, auto_value=None):
    """Helper to resolve response values based on mode."""
    mode = config.get("mode")
    if mode == "custom":
        return config.get("value")
    if mode == "inherit":
        # This is a simplified mapping. A real implementation would need more context.
        # For now, we assume the frontend provides paths that can be resolved.
        # e.g., inherit path could be 'l2.src_mac'
        path = config.get("inherit_path", "").split('.') # Example, not in schema
        val = query_packet
        for key in path:
            val = val.getlayer(key) # Simplified
        return val
    if mode == "auto":
        return auto_value
    return config.get("value") # Fallback for simple structures

def generate_response(query_packet, rule):
    """
    Constructs a DNS response packet based on the new, detailed rule schema.
    """
    action = rule.get("response_action", {})

    # --- Resolve L2/L3/L4 values based on mode ---
    def resolve_val(path, query_val):
        # Helper to get nested config
        keys = path.split('.')
        config = action
        for key in keys:
            config = config.get(key, {})
        
        mode = config.get("mode")
        if mode == "custom":
            return config.get("value")
        if mode == "inherit":
            return query_val
        if mode == "auto":
            # 'auto' is tricky without more context (e.g. which interface to use)
            # We'll default to inheriting for now as it's the most common 'auto' case
            return query_val
        return query_val # Default to inherit

    # L2
    eth_src = resolve_val('l2.src_mac', query_packet[Ether].dst)
    eth_dst = resolve_val('l2.dst_mac', query_packet[Ether].src)
    # L3
    ip_src = resolve_val('l3.src_ip', query_packet[IP].dst)
    ip_dst = resolve_val('l3.dst_ip', query_packet[IP].src)
    # L4
    udp_sport = resolve_val('l4.src_port', query_packet[UDP].dport)
    udp_dport = resolve_val('l4.dst_port', query_packet[UDP].sport)

    # --- Build DNS Layer ---
    header = action.get('dns_header', {})
    flags = header.get('flags', {})
    
    # Build answers
    an = None
    answers_config = action.get('dns_answers', [])
    for answer_conf in answers_config:
        rr = DNSRR(
            rrname=query_packet[DNS].qd.qname, # Default to inheriting name
            type=answer_conf.get('type'),
            ttl=answer_conf.get('ttl'),
            rdata=answer_conf.get('rdata')
        )
        if an is None:
            an = rr
        else:
            an = an / rr
            
    response_dns = DNS(
        id=query_packet[DNS].id, # Always inherit transaction ID
        qd=query_packet[DNS].qd, # Always inherit question
        
        qr=flags.get('qr', 1),
        opcode=flags.get('opcode', 0),
        aa=flags.get('aa', 0),
        tc=flags.get('tc', 0),
        rd=flags.get('rd', query_packet[DNS].rd), # Inherit if not specified
        ra=flags.get('ra', 1),
        rcode=flags.get('rcode', 0),
        
        ancount=len(answers_config),
        an=an
    )

    # Construct the full packet
    response_packet = (
        Ether(src=eth_src, dst=eth_dst) /
        IP(src=ip_src, dst=ip_dst) /
        UDP(sport=udp_sport, dport=udp_dport) /
        response_dns
    )
    
    return response_packet

def start_sniffing():
    """
    Starts the packet sniffer in a separate thread.
    """
    global stop_sniffing
    if stop_sniffing.is_set():
        stop_sniffing.clear()
        
    # 调用重构后的函数获取接口名称列表
    if not get_active_interfaces():
        print("[!] No active interfaces found to sniff on. Aborting.")
        return
    
    print("[*] Starting packet sniffer...")
    # The sniff function will block, so it runs in a thread.
    # 核心改动：明确指定监听的网络接口。Scapy的`iface`参数可以接收一个接口列表。
    sniff(iface=active_interfaces, filter="udp port 53", prn=process_packet, store=False, stop_filter=lambda p: stop_sniffing.is_set())
    print("[*] Packet sniffer stopped.")


def stop_sniffing_handler():
    """
    Sets the event to stop the sniffer.
    """
    global stop_sniffing
    print("[*] Stopping packet sniffer...")
    stop_sniffing.set()

if __name__ == '__main__':
    # For direct testing of this module
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()
    try:
        input("Sniffing... Press Enter to stop.\n")
    finally:
        stop_sniffing_handler()
        sniffer_thread.join(timeout=5)
        print("[*] Sniffer thread joined.")
