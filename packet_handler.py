import threading
# 从 scapy.all 导入 get_if_addr
from scapy.all import sniff, IP, UDP, Ether, get_if_addr, get_if_hwaddr, sendp
# 核心修正：移除对不存在的类的导入，只导入通用的 DNSRR
from scapy.layers.dns import DNS, DNSQR, DNSRR
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

def get_response_value(config, query_value, auto_value=None):
    """
    Resolves a response field's value based on its configuration mode ('inherit', 'custom', 'auto').
    """
    mode = config.get("mode", "inherit")  # Default to inherit for safety
    if mode == "custom":
        return config.get("value")
    if mode == "auto":
        return auto_value
    # Default is "inherit"
    return query_value

def build_rr_section(section_config, query_packet):
    """
    Builds a Scapy DNS Resource Record section (an, ns, ar) from a configuration list.
    """
    section = None
    if not section_config:
        return None
        
    qname = query_packet[DNS].qd.qname

    for rr_conf in section_config:
        # Resolve RR name based on its mode
        rrname_conf = rr_conf.get("name", {})
        rrname = get_response_value(rrname_conf, qname, qname)

        # Handle special case for OPT record (EDNS0)
        if rr_conf.get("type") == 41:
            # Per Readme, UDP payload size is a key parameter. It's stored in 'rclass' for OPT.
            udp_payload_size = rr_conf.get("udp_payload_size", 1232)
            # 核心修正：使用通用的 DNSRR 手动构造 EDNS0 OPT 记录，以兼容旧版 Scapy
            rr = DNSRR(
                rrname='',  # OPT 记录的名称字段是根，即一个空字符串
                type=41,    # 记录类型为 OPT
                rclass=udp_payload_size, # rclass 字段用于存放 UDP 载荷大小
                ttl=0       # ttl 字段可用于扩展标志，0 是安全的默认值
            )
        else:  # Standard Resource Record
            rr = DNSRR(
                rrname=rrname,
                type=rr_conf.get("type"),
                ttl=rr_conf.get("ttl"),
                rdata=rr_conf.get("rdata")
            )

        # Chain the records together
        if section is None:
            section = rr
        else:
            section = section / rr
            
    return section

def get_flag_value(flags_conf, flag_name, default):
    """
    Safely gets a flag's integer value from the rule configuration, ensuring type safety.
    """
    flag_config = flags_conf.get(flag_name, {})
    # Ensure flag_config is a dictionary before proceeding
    if isinstance(flag_config, dict):
        value = flag_config.get('value')
        # Return the value only if it's an integer
        if isinstance(value, int):
            return value
    # If anything fails (not a dict, no 'value', or value is not int), return the default
    return default

def generate_response(query_packet, rule):
    """
    Constructs a DNS response packet based on the detailed rule schema from the README.md.
    """
    action = rule.get("response_action", {})
    if not action:
        return None

    # --- Resolve L2/L3/L4 values based on README logic ---
    iface = query_packet.sniffed_on
    my_mac = get_if_hwaddr(iface)
    my_ip = get_if_addr(iface)

    eth_src = get_response_value(action.get('l2', {}).get('src_mac', {}), query_packet[Ether].dst, my_mac)
    eth_dst = get_response_value(action.get('l2', {}).get('dst_mac', {}), query_packet[Ether].src)
    
    ip_src = get_response_value(action.get('l3', {}).get('src_ip', {}), query_packet[IP].dst, my_ip)
    ip_dst = get_response_value(action.get('l3', {}).get('dst_ip', {}), query_packet[IP].src)

    udp_sport = get_response_value(action.get('l4', {}).get('src_port', {}), query_packet[UDP].dport)
    udp_dport = get_response_value(action.get('l4', {}).get('dst_port', {}), query_packet[UDP].sport)

    # --- Build DNS Layer ---
    header_conf = action.get('dns_header', {})
    flags_conf = header_conf.get('flags', {})

    # Build all three RR sections
    dns_answers_conf = action.get('dns_answers', [])
    dns_authority_conf = action.get('dns_authority', [])
    dns_additional_conf = action.get('dns_additional', [])
    
    an_section = build_rr_section(dns_answers_conf, query_packet)
    ns_section = build_rr_section(dns_authority_conf, query_packet)
    ar_section = build_rr_section(dns_additional_conf, query_packet)

    # --- Resolve DNS Flags based on the new, detailed schema from Readme.md ---
    # Flags with simple 'value'
    qr_flag = get_flag_value(flags_conf, 'qr', 1)
    opcode_flag = get_flag_value(flags_conf, 'opcode', 0)
    aa_flag = get_flag_value(flags_conf, 'aa', 0)
    tc_flag = get_flag_value(flags_conf, 'tc', 0)
    ra_flag = get_flag_value(flags_conf, 'ra', 1)
    z_flag = get_flag_value(flags_conf, 'z', 0)
    rcode_flag = get_flag_value(flags_conf, 'rcode', 0)

    # Flags that support 'inherit' mode
    rd_flag = get_response_value(flags_conf.get('rd', {}), query_packet[DNS].rd)
    ad_flag = get_response_value(flags_conf.get('ad', {}), query_packet[DNS].ad)
    cd_flag = get_response_value(flags_conf.get('cd', {}), query_packet[DNS].cd)

    response_dns = DNS(
        # Per Readme, Transaction ID and Question must be inherited
        id=query_packet[DNS].id,
        qd=query_packet[DNS].qd,
        
        # Assign all resolved flags according to the new schema
        qr=qr_flag,
        opcode=opcode_flag,
        aa=aa_flag,
        tc=tc_flag,
        rd=rd_flag,
        ra=ra_flag,
        z=z_flag,
        ad=ad_flag,
        cd=cd_flag,
        rcode=rcode_flag,
        
        # Manually set counts to ensure correctness, overriding Scapy's auto-calculation
        ancount=len(dns_answers_conf),
        nscount=len(dns_authority_conf),
        arcount=len(dns_additional_conf),

        # Assign the built sections
        an=an_section,
        ns=ns_section,
        ar=ar_section
    )
    
    # --- Assemble and return the full packet ---
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
    # We use a loop with a timeout to make the sniffer responsive to the stop event.
    while not stop_sniffing.is_set():
        sniff(iface=active_interfaces, filter="udp port 53", prn=process_packet, store=False, timeout=1)
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
