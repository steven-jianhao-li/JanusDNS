[Read the full development plan](DEVELOPMENT_PLAN.md)

# JanusDNS: The Two-Faced DNS Responder

<p align="center">
  <!-- You can create a Trendshift badge if you publish it there, or remove it -->
  <a href="https://github.com/steven-jianhao-li/JanusDNS" target="_blank" >
    <img src="https://img.shields.io/github/stars/steven-jianhao-li/JanusDNS?style=social" alt="JanusDNS GitHub Stars"/>
  </a>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg" alt="Python"></a>
  <a href="https://github.com/secdev/scapy"><img src="https://img.shields.io/badge/Scapy-2.5%2B-orange.svg" alt="Scapy"></a>
  <a href="https://flask.palletsprojects.com/"><img src="https://img.shields.io/badge/Flask-2.3%2B-green.svg" alt="Flask"></a>
  <a href="https://tailwindcss.com/"><img src="https://img.shields.io/badge/Tailwind_CSS-Styling-blueviolet.svg" alt="Tailwind CSS"></a>
</p>

> ⚠️ **License**: This project is licensed under the [MIT License](LICENSE). You are free to use, modify, and distribute it.

---

## 📖 Project Introduction

Named after the two-faced Roman god of gateways, **JanusDNS** is a powerful and highly configurable DNS responder that gives you complete control over the DNS conversation. It "looks backward" to analyze the fine-grained details of incoming DNS queries and "looks forward" to forge custom, multi-layered responses based on your rules.

This tool is designed for security researchers, penetration testers, and network developers who need to simulate, intercept, or manipulate DNS traffic with surgical precision. With an intuitive web interface built on Flask and a powerful packet processing engine using Scapy, JanusDNS turns complex network test cases into manageable, repeatable rules.

<details>
<summary>📂 View Project Structure</summary>

```plaintext
project/
├── app.py              # Flask Web Server & API Endpoints
├── packet_handler.py   # Core Scapy Packet Sniffing and Response Logic
├── rules_manager.py    # Rule Loading, Matching, and Saving
├── const.py            # DNS Constants (Types, Classes)
├── static/             # Frontend HTML/CSS/JavaScript Files
│   ├── index.html
│   └── css/
│       └── style.css
└── logs/               # Directory for Session Logs and PCAP Files
    └── <task_id>/
        ├── capture.pcap
        └── task.log
```
</details>

---

## ✨ Feature Highlights

*   🔬 **Granular Multi-Layer Rule Engine**: Define trigger conditions from the Ethernet layer (L2) up to the DNS application layer (L5). Match packets based on MAC/IP addresses, ports, TTLs, and detailed DNS header flags or record counts.
*   🎨 **Dynamic Response Crafting**: Forge custom DNS responses with ultimate flexibility. Control every field of the final packet, inherit values from the original query (e.g., Transaction ID, source port), or use environment-aware auto-completion (e.g., local MAC).
*   🖥️ **Intuitive Web Interface**: A clean, user-friendly UI to manage your rules (CRUD), start and stop the listener, and view detailed logs. No command-line expertise required for day-to-day use.
*   📡 **Live Sniffing & Logging**: The backend runs a dedicated sniffing thread that listens for DNS traffic on port 53, providing real-time feedback and logging for triggered events.
*   💾 **Session-Based PCAP Generation**: Each monitoring session generates a unique log and a `capture.pcap` file containing both the triggering query and the forged response, perfect for analysis in tools like Wireshark.
*   🔄 **Import/Export Rules**: Easily save and load complex rule sets as JSON files, allowing you to share configurations or switch between different testing scenarios quickly.

---

## 🚀 Quick Start

### Prerequisites

*   Python 3.8+
*   `pip`
*   Administrative/root privileges to run the packet sniffer.

### Local Development & Execution

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/your-username/JanusDNS.git
    cd JanusDNS
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You will need to create a `requirements.txt` file containing `scapy` and `flask`)*

3.  **Run the Application**:
    You need to run the application with root privileges for Scapy to access raw sockets.
    ```bash
    sudo python3 app.py
    ```

4.  **Access the Web UI**:
    Open your web browser and navigate to `http://127.0.0.1:5000`. From there, you can create rules and start the DNS listener.

*(Docker support is planned for a future release to simplify deployment.)*

---

## ⚙️ How It Works

The application operates in two main parts that run concurrently:

1.  **Flask Web Server (Main Thread)**:
    *   Serves the frontend HTML/CSS/JS.
    *   Provides a REST API for the frontend to manage rules (`/api/rules`), control the sniffer (`/api/control/start`, `/api/control/stop`), and view logs (`/api/logs`).

2.  **Scapy Sniffer (Background Thread)**:
    *   Started via the "Start Listening" button in the UI.
    *   Uses `scapy.sniff()` to capture UDP packets on port 53.
    *   For each captured packet, it passes it to the `rules_manager` for matching.
    *   If a rule matches, the `packet_handler` constructs and sends the custom response packet using `scapy.sendp()`.
    *   All relevant activities are logged to the current session's directory.

---

<details>
<summary>📋 View Rule JSON Schema</summary>

The core of JanusDNS is its rule engine, which uses a flexible JSON structure. This allows for precise control over both the trigger conditions and the response actions. Below is an overview of the schema.

```json
{
  "rule_id": "string",
  "name": "string",
  "is_enabled": "boolean",

  "trigger_condition": {
    "l2": { "src_mac": "string | null", "dst_mac": "string | null" },
    "l3": { "src_ip": "string | null", "dst_ip": "string | null", ... },
    "l4": { "src_port": "integer | null", "dst_port": "integer | null" },
    "dns": {
      "qname": "string",
      "qtype": "integer",
      "transaction_id": "integer | null",
      ...
    }
  },

  "response_action": {
    "l2": {
      "src_mac": { "mode": "'auto' | 'inherit' | 'custom'", "value": "string | null" },
      ...
    },
    "l3": { ... },
    "l4": { ... },
    "dns_header": {
      "transaction_id": { "mode": "'inherit'", ... },
      "flags": { "aa": { "value": "integer" }, ... }
    },
    "dns_answers": [
      {
        "name": { "mode": "'inherit' | 'custom'", "value": "string | null" },
        "type": "integer",
        "ttl": "integer",
        "rdata": "string"
      }
    ],
    "dns_authority": [],
    "dns_additional": []
  }
}
```

</details>