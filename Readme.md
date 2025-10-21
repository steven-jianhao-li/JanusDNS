## DNS 响应程序详细开发计划

本项目将采用 **Python** 语言，后端使用 **Scapy** (用于数据包处理) 和 **Flask** (用于提供 Web API 服务)，前端使用 **HTML/Tailwind CSS/JavaScript** (用于用户界面和API交互)。

-----

### 第一阶段：项目基础搭建与环境配置

| 步骤编号 | 任务描述 (面向小白的解释) | 技术栈/文件 |
| :--- | :--- | :--- |
| **1.1** | **安装必需的Python库。** (你需要安装专门用来处理网络数据包和搭建Web服务的工具。) | `pip install scapy flask` |
| **1.2** | **项目结构规划。** (将代码和文件分类存放，方便管理。) | `project/` (主目录) `├── app.py` (Flask 主程序) `├── packet_handler.py` (数据包监听与处理逻辑) `├── rules_manager.py` (规则的加载、保存和匹配) `├── const.py` (常量文件) `├── static/` (前端静态文件) `└── logs/` (日志和 pcap 存储) |
| **1.3** | **定义常量文件。** (把DNS请求类型等不变的信息存起来，方便查找和使用。) | `const.py` |
| | **内容要求：** 存储常见的DNS类型（Type）及其编号、名称和简要用途描述。例如：`TYPE_A = 1 (A Record - IPv4地址)`, `TYPE_AAAA = 28 (AAAA Record - IPv6地址)`, `TYPE_CNAME = 5 (CNAME Record - 别名)`。 |

-----

### 第二阶段：后端核心功能开发

#### 2.1. 核心数据包监听与筛选 (`packet_handler.py`)

| 步骤编号 | 任务描述 | 核心技术点 |
| :--- | :--- | :--- |
| **2.1.1** | **获取本机IP地址。** (程序需要知道自己的IP，才能判断收到的包是不是发给自己的。) | 使用 `socket` 库或 `scapy.interfaces` 自动获取本机所有活跃网卡的IP地址列表。 |
| **2.1.2** | **实现数据包监听功能。** (使用Scapy监听所有到达53端口的UDP数据包。) | 使用 Scapy 的 `sniff()` 函数，设置 `filter="udp port 53"`。将监听操作放在一个独立的线程中，以便 Flask Web 服务可以同时运行。 |
| **2.1.3** | **目标IP筛选 (Step 1)。** (初步筛选，只处理目标IP是本机IP的数据包。) | 在回调函数中，检查 `IP` 层的 `dst` 字段是否属于 2.1.1 获取的本机IP列表。如果不是，直接丢弃。 |
| **2.1.4** | **DNS请求有效性检查 (Step 2)。** (确认这是一个有效的DNS请求，而不是响应或损坏的包。) | 检查数据包是否包含 `DNS` 层，并且 `DNS` 层的 `qr` 字段（Query/Response Flag）为 `0` (表示这是一个 Query 请求)。 |

#### 2.2. 规则匹配逻辑 (`rules_manager.py`)

这是后端最复杂的部分，需要将传入的数据包（Query）与用户配置的所有规则进行逐一比对。

| 步骤编号 | 任务描述 | 逻辑实现细节 |
| :--- | :--- | :--- |
| **2.2.1** | **加载和存储规则。** (规则必须持久化，启动后能读取，修改后能保存。) | 实现 `load_rules()` 和 `save_rules()` 函数，从 JSON 文件中读取和写入规则数组。 |
| **2.2.2** | **规则匹配函数 (`match_rule(packet, rule)`)。** (核心比对函数，逐层进行匹配。) | 遍历用户配置的规则，对每一个规则的每个可选填字段进行比对：<br>1. **L7 (DNS) 必填字段匹配：** 检查数据包的 `DNS.qd.qname` (请求域名) 和 `DNS.qd.qtype` (请求类型) 是否与规则设置的必填值完全一致。**这是首要条件。**<br>2. **分层可选字段匹配：** 依次检查 L2/L3/L4/L7 的可选字段。如果规则中该字段为空（`""` 或 `None`），则跳过（代表不筛选）；如果不为空，则检查数据包中对应字段是否与规则配置的值完全一致。 |
| **2.2.3** | **匹配成功处理。** | 一旦找到第一个匹配成功的规则，立即停止比对，返回该规则对象及其编号。如果没有规则匹配，则不进行响应（默默丢弃）。 |

#### 2.3. 数据包生成与响应 (`packet_handler.py`)

匹配成功后，根据规则配置生成响应数据包（Response Packet）。

| 步骤编号 | 任务描述 | 响应数据包字段赋值逻辑 (面向小白的复杂参数解释) |
| :--- | :--- | :--- |
| **2.3.1** | **生成基础响应包 (L7)。** (构建DNS响应的骨架。) | **基础层：** 创建 `Ether / IP / UDP / DNS` 结构。设置 `DNS.qr=1` (是响应包)，`DNS.ra=1` (可以递归查询)。 |
| **2.3.2** | **填充 L7 (DNS) 继承字段。** (有些信息必须和请求包一模一样。) | 1. **Transaction ID (`id`)：** 必须选择 **`② 由触发条件的数据包实际参数决定`**，即继承自Query包的ID。客户端靠这个ID识别响应。 2. **Question Section (`qd`)：** 必须选择 **`② 由触发条件的数据包实际参数决定`**，即完全复制 Query 包的 Questions 部分。 |
| **2.3.3** | **填充 L7 (DNS) Answer 字段。** (这才是响应的核心内容。) | 1. **Answer Count (`ancount`)：** 选择 **`① 根据用户定义的Answer记录自动计算`**。 2. **Answer Records (`an`)：** 遍历规则中配置的 Answer 记录。对于每条记录，系统自动将其 Name/Type/Class 字段设置为与触发条件Query包的 Question 一致，**只使用用户在规则中配置的 RDATA (Resource Data，例如IP地址)**。 |
| **2.3.4** | **填充 L4 (UDP) 字段。** | 1. **源端口 (`sport`)：** **`① 由触发条件的数据包目的端口决定`** (通常是53)。 2. **目的端口 (`dport`)：** **`① 由触发条件的数据包源端口决定`** (发回给客户端的随机端口)。 |
| **2.3.5** | **填充 L3 (IP) 字段。** | 1. **源IP (`src`)：** **`② 由触发条件的数据包目的IP决定`** (即本机监听的IP)。 2. **目的IP (`dst`)：** **`① 由触发条件的数据包源IP决定`** (发回给客户端的IP)。 |
| **2.3.6** | **填充 L2 (Ethernet) 字段。** | 1. **源MAC (`src`)：** **`① 自动获取环境应有MAC`** (本机MAC)。 2. **目的MAC (`dst`)：** **`② 由触发条件的数据包源MAC决定`** (发回给客户端的MAC)。 |
| **2.3.7** | **发送响应数据包。** | 使用 Scapy 的 `sendp()` (带 L2/链路层) 或 `send()` (只带 L3/网络层) 函数将构造好的响应包发送出去。 |

#### 2.4. 日志与存储 (`log_manager.py`)

| 步骤编号 | 任务描述 | 存储细节要求 |
| :--- | :--- | :--- |
| **2.4.1** | **任务 ID 确定。** (每一次启动监听服务，都是一个新的“任务”。) | 启动时，根据当前时间生成一个唯一的任务 ID (例如 `YYYYMMDDHHMMSS`)。 |
| **2.4.2** | **创建任务文件夹。** | 在 `logs/` 目录下创建以该任务 ID 命名的子文件夹。 |
| **2.4.3** | **实时日志记录。** | 每当有规则被触发时，将触发信息 (时间、规则编号、匹配域名) 写入任务文件夹内的文本日志文件 (`task.log`)。 |
| **2.4.4** | **数据包 PCAP 存储。** (把原始数据包保存下来，方便后续分析。) | 在任务开始时，创建一个 `logs/<task_id>/capture.pcap` 文件。对于每一次触发，将**触发条件的数据包**和**响应的数据包**实时追加写入该 pcap 文件中，确保一个任务只生成一个 pcap 文件。 |

-----

### 第三阶段：前端页面开发 (Web UI)

前端目标：实现规则的 CRUD（创建、读取、更新、删除）、导入导出、以及日志查看和控制。

#### 3.1. UI 布局与控制

| 步骤编号 | 任务描述 | 交互细节 |
| :--- | :--- | :--- |
| **3.1.1** | **基础布局。** | 使用 Tailwind CSS 实现响应式布局。左侧为控制面板和规则列表，右侧为规则编辑区和日志查看区。 |
| **3.1.2** | **监听控制按钮。** | 放置“启动监听”和“终止监听”按钮。启动时，按钮变灰或禁用，并显示状态指示器（例如，一个闪烁的绿点）。 |
| **3.1.3** | **API 对接。** | 前端通过 Fetch/Axios 调用 Flask 提供的 API：`/api/rules` (规则管理), `/api/control/start`, `/api/control/stop`, `/api/logs` (日志)。 |

#### 3.2. 规则管理界面

| 步骤编号 | 任务描述 | 交互细节及 Wireshark-like 设计 |
| :--- | :--- | :--- |
| **3.2.1** | **必填项输入。** | 两个独立输入框：**请求域名** (默认 `baidu.com`) 和 **请求类型** (默认 `1`)。在请求类型输入框旁边放置一个圆圈问号图标，鼠标悬停时展示 `const.py` 中定义的 DNS 类型编号、名称和用途描述。 |
| **3.2.2** | **条件配置分层结构。** | 使用 4 个可折叠（加/减号控制展开/收起）的卡片/面板：**链路层 (L2)**、**网络层 (L3)**、**传输层 (L4)**、**应用层 (L7 - DNS)**。 |
| **3.2.3** | **分层摘要展示。** | 在每个折叠卡片的标题处，实时显示用户已配置的参数摘要。例如：`网络层 (L3)：源IP=192.168.1.1, 目的IP=ANY`。 |
| **3.2.4** | **L7 (DNS) 字段展开与自定义。** | 在 **应用层 (L7)** 卡片内部，对 `Query`, `Answer`, `Authority`, `Additional` 等字段也使用二级折叠标签，以模仿 Wireshark 的交互逻辑。<br>- **触发条件 (Query Packet):** `Query`, `Answer`, `Authority`, `Additional` 字段均可配置多条 RR 记录。`Query` 字段默认有一条记录，其余字段默认为空，用户可按需新增。<br>- **响应动作 (Response Packet):**<br>  - **`Query` 字段：** 默认有一条记录，且默认工作在 **`inherit mode`** (继承触发条件的 Query)。<br>  - **`Answer` / `Authority` 字段：** 默认为空。用户新增条目时，将创建一条默认 RR 记录，其 `QName` 默认继承自 Query 的 `QName`。<br>  - **`Additional` 字段：** 默认为空。用户新增条目时，可选择不同类型，如：<br>    - **EDNS0 (`<Root>`)**: 插入一条 OPT 记录 (Type 41)，用于扩展 DNS 功能，其参数（如 UDP Payload Size）可由用户自定义。默认值为：`Name: <Root>, Type: OPT (41), UDP payload size: 1232, EDNS0 version: 0, Data: COOKIE`。 <br>    - **DNSSEC (如 `DS`)**: 插入 DNS 安全扩展相关的记录。<br>    - **标准 RR**: 插入一条类似 Answer 的标准资源记录。 |
| **3.2.5** | **参数输入控件。** | 每个可选参数（如源MAC、目的IP）都使用文本框。如果留空，则在后端匹配时视为“不筛选 (ANY)”。 |
| **3.2.6** | **响应行为配置。** | 结构与条件配置类似，也是分层展示。对于每个字段，提供下拉选择框，对应 `2.3.4 - 2.3.6` 中定义的复杂选项：<br> - **① 自动获取环境应有XX** (如本机MAC/IP)<br> - **② 由触发条件的数据包实际参数决定** (如继承Query的Src MAC/Dst IP)<br> - **③ 自定义** (提供输入框手动输入) |
| **3.2.7** | **导入/导出功能。** | **导出：** 将当前所有规则打包成一个 JSON 文件，提供给用户下载。 **导入：** 接收用户上传的 JSON 文件，覆盖或追加到现有规则列表。 |

#### 3.3. 日志管理与分析界面

| 步骤编号 | 任务描述 | 交互细节 |
| :--- | :--- | :--- |
| **3.3.1** | **任务列表表格化。** | 以**表格形式**展示 `logs/` 目录下的所有任务。表格包含列：**任务ID (时间)** 和 **操作**。用户可以点击表头对任务进行**正序或逆序排序**。 |
| **3.3.2** | **查看任务详情。** | 在每行任务的操作列中，提供一个“**详情**”按钮。点击后，会按时间顺序展示该任务触发的所有数据包摘要。 |
| **3.3.3** | **下载 PCAP 文件。** | 在详情视图中，提供一个“**下载**”按钮，允许用户下载该任务对应的 `capture.pcap` 文件进行离线分析。 |
| **3.3.4** | **任务删除功能。** | 在每行任务的操作列中，提供一个“**删除**”按钮，用于删除该任务对应的整个文件夹及其内部所有日志和 pcap 文件。 |

-----

### 第四阶段：数据结构 (JSON Schema)

以下是规则 (Rule) 的 JSON 结构定义，用于前端与后端 API 交互以及文件导入导出。
```json
{
  "rule_id": "string",
  "name": "string", // 规则名称，用于前端列表展示
  "is_enabled": "boolean", // 规则是否启用 (true/false)
  "priority": "integer", // 规则匹配优先级 (数值越小，优先级越高，匹配成功即停止)
  
  "trigger_condition": { // 触发条件配置 (Query Packet 筛选)
    
    // ---------------- L2 链路层 (Ethernet) - 选填 ----------------
    "l2": {
      "src_mac": "string | null", // 源MAC地址 (e.g., "00:11:22:AA:BB:CC")
      "dst_mac": "string | null"  // 目的MAC地址 (通常是本机的MAC或广播/组播MAC)
    },
    
    // ---------------- L3 网络层 (IP/IPv6) - 选填 ----------------
    "l3": {
      "ip_version": "integer | null", // IP版本 (4 或 6)
      "src_ip": "string | null", // 源IP地址 (e.g., "192.168.1.1")
      "dst_ip": "string | null", // 目的IP地址 (通常是本机IP)
      "ttl": "integer | null", // Time To Live (TTL)
      "protocol": "integer | null" // 协议号 (UDP是17, TCP是6)
    },
    
    // ---------------- L4 传输层 (UDP) - 选填 ----------------
    "l4": {
      "src_port": "integer | null", // 源端口 (客户端随机端口)
      "dst_port": "integer | null"  // 目的端口 (DNS是53)
    },
    
    // ---------------- L7 应用层 (DNS) - 详细配置 ----------------
    "dns": {
      // 必填项 (核心匹配条件)
      "qname": "string", // 必填: 请求域名 (e.g., "baidu.com")
      "qtype": "integer", // 必填: 请求类型 (e.g., 1 for A, 28 for AAAA)
      
      // DNS 头部字段 (选填)
      "transaction_id": "integer | null", // 交易ID (Transaction ID)
      "flags": {
        "opcode": "integer | null", // 操作码 (Opcode: 0-标准查询)
        "qr": "integer | null",     // 问答标志 (Query/Response: 0-Query, 1-Response) (Query时应为0)
        "aa": "integer | null",     // 权威标志 (Authoritative Answer)
        "tc": "integer | null",     // 截断标志 (Truncated)
        "rd": "integer | null",     // 递归请求 (Recursion Desired)
        "ra": "integer | null",     // 递归可用 (Recursion Available)
        "ad": "integer | null",     // 验证数据 (Authentic Data)
        "cd": "integer | null",     // 检查禁用 (Checking Disabled)
        "rcode": "integer | null"   // 响应码 (Reply Code)
      },
      
      // DNS 计数字段 (选填)
      "qd_count": "integer | null", // Questions 数量
      "an_count": "integer | null", // Answers 数量 (Query时通常为0)
      "ns_count": "integer | null", // Authority RRs 数量
      "ar_count": "integer | null"  // Additional RRs 数量
    }
  },
  
  "response_action": { // 响应行为配置 (Response Packet 生成)
    
    // ---------------- L2 链路层 (Ethernet) - 响应生成配置 ----------------
    "l2": {
      "src_mac": {
        "mode": "string", // 选项: "auto" (自动获取本机MAC), "inherit" (继承Query包的Dst MAC), "custom"
        "value": "string | null", // 仅当mode为custom时有效 (e.g., "FF:FF:FF:00:00:01")
        "description": "源MAC地址：响应包的发送方MAC。选择 'auto' 确保响应能从本机正确发出。"
      },
      "dst_mac": {
        "mode": "string", // 选项: "inherit" (继承Query包的Src MAC), "custom"
        "value": "string | null",
        "description": "目的MAC地址：响应包的接收方MAC。选择 'inherit' 确保响应能回到正确的客户端。"
      }
    },
    
    // ---------------- L3 网络层 (IP) - 响应生成配置 ----------------
    "l3": {
      "src_ip": {
        "mode": "string", // 选项: "auto" (自动获取本机IP), "inherit" (继承Query包的Dst IP), "custom"
        "value": "string | null",
        "description": "源IP地址：响应包的发送方IP。**推荐 'inherit'** (即本机监听的IP) 或 'auto'。"
      },
      "dst_ip": {
        "mode": "string", // 选项: "inherit" (继承Query包的Src IP), "custom"
        "value": "string | null",
        "description": "目的IP地址：响应包的接收方IP。**必须选择 'inherit'**，将响应发回给客户端。"
      }
    },
    
    // ---------------- L4 传输层 (UDP) - 响应生成配置 ----------------
    "l4": {
      "src_port": {
        "mode": "string", // 选项: "inherit" (继承Query包的Dst Port), "custom"
        "value": "integer | null",
        "description": "源端口：响应包的发送方端口。**推荐 'inherit'** (通常是53)。"
      },
      "dst_port": {
        "mode": "string", // 选项: "inherit" (继承Query包的Src Port), "custom"
        "value": "integer | null",
        "description": "目的端口：响应包的接收方端口。**必须选择 'inherit'** (发回给客户端的随机端口)。"
      }
    },
    
    // ---------------- L7 应用层 (DNS) - 核心响应内容 ----------------
    "dns_header": {
      // 必须继承的字段
      "transaction_id": {
        "mode": "string", // 选项: "inherit"
        "description": "交易ID：**必须继承** Query包的ID，用于客户端匹配请求与响应。"
      },
      "questions": {
        "mode": "string", // 选项: "inherit"
        "description": "Questions部分：**必须继承** Query包的Questions部分，保持响应的完整性。"
      },
      
      // 响应标志位配置 (需要手动设置的)
      "flags": { 
        "qr": "integer", // 问答标志: 必须是 1 (Response)
        "opcode": "integer", // 操作码: 必须是 0 (Standard Query)
        "aa": "integer", // 权威标志: 0 或 1 (是否是权威服务器)
        "tc": "integer", // 截断标志: 0 或 1 
        "rd": "integer", // 递归请求: 0 或 1 (通常继承Query的RD)
        "ra": "integer", // 递归可用: 0 或 1 
        "ad": "integer", // 验证数据: 0 或 1
        "cd": "integer", // 检查禁用: 0 或 1
        "rcode": "integer" // 响应码: 0 (No Error) 或 其它错误码 (如 3-NXDOMAIN)
      }
    },
    
    "dns_answers": [ // 响应记录列表 (Answer Section)
      {
        "type": "integer", // 记录类型 (e.g., 1-A, 5-CNAME)
        "ttl": "integer", // 缓存时间 (Time To Live, 秒)
        "rdata": "string", // 资源数据 (例如：A记录的IP地址 "1.2.3.4")
        "name": {
           "mode": "string", // 选项: "inherit" (继承Query的QNAME), "custom"
           "value": "string | null",
           "description": "记录所属域名：**推荐 'inherit'** (即 Query 的请求域名)"
        }
      }
    ],
    
    "dns_authority": "array", // 权威名称服务器 (NS) 记录列表 (结构同上 dns_answers)
    "dns_additional": "array" // 附加信息 (Additional) 记录列表 (结构同上 dns_answers)
  }
}

```
