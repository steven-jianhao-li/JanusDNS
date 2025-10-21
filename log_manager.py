import os
import datetime
from scapy.all import wrpcap, DNS

LOGS_DIR = "logs"
current_task_id = None
log_file_path = None

def start_new_log_session():
    """
    Starts a new logging session by creating a unique task directory and a single pcap file.
    """
    global current_task_id, log_file_path
    
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    current_task_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    task_dir = os.path.join(LOGS_DIR, current_task_id)
    os.makedirs(task_dir, exist_ok=True)
    
    log_file_path = os.path.join(task_dir, "task.log")
    pcap_file_path = os.path.join(task_dir, "capture.pcap")
    
    # Create an empty pcap file to append to later
    wrpcap(pcap_file_path, [])
    
    print(f"[*] New log session started. Task ID: {current_task_id}")
    return current_task_id

def log_triggered_rule(rule, query_packet):
    """
    Writes a log entry for a triggered rule.
    """
    if not log_file_path:
        return
        
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    qname = query_packet[DNS].qd.qname.decode().rstrip('.')
    rule_name = rule.get('name', rule.get('rule_id'))
    
    log_message = f"{timestamp} - Rule '{rule_name}' triggered by query for '{qname}'.\n"
    
    with open(log_file_path, 'a') as f:
        f.write(log_message)

def save_pcap_files(rule, query_packet, response_packet):
    """
    Appends the query and response packets to the single pcap file for the current session.
    """
    if not current_task_id:
        return
        
    task_dir = os.path.join(LOGS_DIR, current_task_id)
    pcap_filepath = os.path.join(task_dir, "capture.pcap")
    
    # Append both packets to the existing pcap file
    wrpcap(pcap_filepath, [query_packet, response_packet], append=True)
    
    print(f"[*] Appended query and response to {pcap_filepath}")

def get_log_sessions():
    """
    Lists all available log session directories.
    """
    if not os.path.exists(LOGS_DIR):
        return []
    return [d for d in os.listdir(LOGS_DIR) if os.path.isdir(os.path.join(LOGS_DIR, d))]

def get_log_details(task_id):
    """
    Gets the log entries and pcap files for a specific task_id.
    """
    task_dir = os.path.join(LOGS_DIR, task_id)
    if not os.path.isdir(task_dir):
        return None
    
    log_content = ""
    log_file = os.path.join(task_dir, "task.log")
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            log_content = f.read()
            
    pcap_files = [f for f in os.listdir(task_dir) if f.endswith(".pcap")]
    
    return {"log_content": log_content, "pcap_files": pcap_files}
