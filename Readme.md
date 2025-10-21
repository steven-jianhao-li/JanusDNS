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
| **2.2.2** | **规则匹配函数 (`match_rule(packet, rule)`)。** (核心比对函数，逐层将收到的DNS请求包与规则进行精确比对。) | 该函数的目标是判断一个传入的DNS请求 `packet` 是否完全满足某条 `rule` 中定义的所有“触发条件 (`trigger_condition`)”。匹配过程遵循“**逐层筛选，逐字段验证**”的原则：<br><br>1. **分层可选字段匹配 (L2/L3/L4)：** 依次从链路层 (L2) 到传输层 (L4) 进行检查。对于规则中配置的任何一个字段（如 `src_mac`, `dst_ip`, `src_port`），如果该字段有具体值，则必须与数据包中对应字段的值完全一致。如果规则中该字段未配置（为 `null`），则代表“任意值 (ANY)”，跳过该字段的检查。只要有任何一个配置了的字段不匹配，则该规则立即匹配失败，函数停止并返回 `False`。<br><br>2. **应用层 DNS 核心匹配 (L7)：** 只有通过了 L2-L4 的所有检查后，才会进入最关键的 DNS 层匹配。该层匹配分为两步：<br>   - **必填项匹配：** 首先，必须检查数据包的 **请求域名 (`DNS.qd.qname`)** 和 **请求类型 (`DNS.qd.qtype`)** 是否与规则中定义的 `qname` 和 `qtype` 完全一致。这是最基础的匹配前提，如果不满足，则规则立即匹配失败。<br>   - **DNS 头部及计数器匹配：** 接下来，将根据规则中 `dns` 对象的其他可选字段，对数据包进行更精细的校验。以您提供的 `baidu.com` A记录请求包为例：<br>     - **数据包样例：**<br>       `Transaction ID: 0x9f24`<br>       `Flags: 0x0120 (rd)`<br>       `Questions: 1`<br>       `Additional RRs: 1`<br>       `Queries: baidu.com (type A)`<br><br>     - **匹配逻辑演示：**<br>       - 如果规则要求 `trigger_condition.dns.transaction_id` 为 `0x9f24`，则数据包匹配成功。<br>       - 如果规则要求 `trigger_condition.dns.flags.rd` 为 `1` (Recursion Desired)，则数据包的 Flags 字段中的 `rd` 位为1，匹配成功。<br>       - 如果规则要求 `trigger_condition.dns.qd_count` 为 `1` 且 `ar_count` 为 `1`，则数据包的 Questions 和 Additional RRs 计数均为1，匹配成功。<br>       - 如果规则要求 `an_count` 为 `0`，而数据包的 Answer RRs 计数也为0，匹配成功。<br>       - 同样，如果规则中这些值为 `null`，则不进行检查。<br><br>只有当 L2 到 L7 的所有已配置字段全部通过验证时，`match_rule` 函数才最终返回 `True`，表示该数据包成功匹配此条规则。 |
| **2.2.3** | **匹配成功处理。** | 一旦找到第一个匹配成功的规则，立即停止比对，返回该规则对象及其编号。如果没有规则匹配，则不进行响应（默默丢弃）。 |

#### 2.3. 数据包生成与响应 (`packet_handler.py`)

匹配成功后，根据规则配置生成响应数据包（Response Packet）。

| 步骤编号 | 任务描述 | 响应数据包字段赋值逻辑 (面向小白的复杂参数解释) |
| :--- | :--- | :--- |
| **2.3.1** | **构建DNS响应骨架 (Header & Counts)。** (这是响应包的第一部分，包含了“我是谁、我来干嘛、我带了多少信息”等元数据。) | 根据规则 `response_action` 中的 `dns_header` 进行配置：<br><br>1. **Transaction ID (`id`)**: **必须**继承自触发请求包的ID，这是客户端用来匹配问答的唯一凭证。<br><br>2. **Flags (标志位)**: 这是一个16位的字段，每一位都有特殊含义，共同决定了响应包的性质。<br>   - **`qr` (Query/Response)**: 必须设为 `1`，表明这是一个响应包。<br>   - **`opcode` (操作码)**: 通常设为 `0`，表示一个标准的查询响应。<br>   - **`aa` (Authoritative)**: 设为 `1` 表示你是这个域名的权威服务器，否则为 `0`。<br>   - **`tc` (Truncated)**: 设为 `1` 表示响应太长被截断了，通常为 `0`。<br>   - **`rd` (Recursion Desired)**: 通常继承自请求包的 `rd` 标志位。<br>   - **`ra` (Recursion Available)**: 设为 `1` 表示你的服务器支持递归查询，否则为 `0`。<br>   - **`rcode` (Reply Code)**: 响应状态码。`0` 代表**No Error**，`3` 代表**NXDOMAIN** (域名不存在) 等。<br><br>3. **Counts (计数器)**: 这四个字段的值 **由程序自动计算**，无需用户手动填写。<br>   - **Questions (`qdcount`)**: 等于 `Questions` 字段里的记录数 (通常为1)。<br>   - **Answer RRs (`ancount`)**: 等于 `Answers` 字段里的记录数。<br>   - **Authority RRs (`nscount`)**: 等于 `Authority` 字段里的记录数。<br>   - **Additional RRs (`arcount`)**: 等于 `Additional` 字段里的记录数。 |
| **2.3.2** | **填充查询部分 (Question Section)。** (告诉客户端：“我正在回答你关于‘这个域名’的‘这种类型’的查询”。) | **必须**完整地从触发它的请求包中复制整个 Question 部分 (`DNS.qd`)。这部分包含了客户端原始查询的 **Name (域名)**、**Type (类型)** 和 **Class (类别)**，是响应必须严格遵守的上下文。 |
| **2.3.3** | **填充应答部分 (Answer Section)。** (这是响应的核心，包含了用户请求的具体数据，比如IP地址。) | 遍历规则中 `response_action.dns_answers` 定义的每一条资源记录 (RR)，并构造成Scapy的 `DNSRR` 对象。一条标准的 Answer RR 包含：<br><br>- **Name**: 记录所属的域名，通常继承自 Question 的域名。<br>- **Type**: 记录的类型 (如 A, AAAA, CNAME)。<br>- **Class**: 类别，通常是 `IN` (Internet)。<br>- **TTL**: 客户端可以缓存这条记录多久（秒）。<br>- **Data length**: RDATA 的长度，由Scapy自动计算。<br>- **RDATA**: 真正的资源数据，例如：A记录的IPv4地址 (`47.237.105.36`)，或CNAME记录的别名域名。 |
| **2.3.4** | **填充权威部分 (Authority Section)。** (用于告知客户端，哪个域名服务器对该域具有最终解释权。) | 结构与 Answer Section 完全相同。通常用于存放 NS (Name Server) 类型的记录。在本次响应不直接提供答案，而是想将客户端引导至正确的权威服务器时，此部分会非常有用。如果规则中未定义，则此部分为空。|
| **2.3.5** | **填充附加部分 (Additional Section)。** (提供一些额外信息，以帮助客户端更好地理解响应，或减少后续查询。) | 结构与 Answer Section 类似，但可以包含一些特殊的记录类型：<br><br>- **标准 RR**: 例如，如果在 Authority 部分提供了NS服务器的域名，此部分可以提供那些NS服务器的IP地址（A或AAAA记录），避免客户端需要再次查询。<br>- **OPT Record (`<Root>`)**: 这是 **EDNS0** 的实现，用于扩展DNS协议功能。它不是一个真正的记录，而是一种“伪记录”。它可以用来：<br>  - `UDP payload size`: 告知客户端你能接收多大的UDP包。<br>  - `COOKIE`: 用于验证客户端和服务器，防止IP欺骗等攻击。<br>  - `DO bit`: 表明你是否处理 DNSSEC 安全记录。 |
| **2.3.6** | **填充 L4 (UDP) 字段。** | 1. **源端口 (`sport`)**: **`① 由触发条件的数据包目的端口决定`** (通常是53，响应从53端口发出)。 2. **目的端口 (`dport`)**: **`② 由触发条件的数据包源端口决定`** (发回给客户端发起请求的那个随机端口)。 |
| **2.3.7** | **填充 L3 (IP) 字段。** | 1. **源IP (`src`)**: **`② 由触发条件的数据包目的IP决定`** (即本机监听的IP)。 2. **目的IP (`dst`)**: **`① 由触发条件的数据包源IP决定`** (发回给客户端的IP)。 |
| **2.3.8** | **填充 L2 (Ethernet) 字段。** | 1. **源MAC (`src`)**: **`① 自动获取环境应有MAC`** (本机网卡的MAC地址)。 2. **目的MAC (`dst`)**: **`② 由触发条件的数据包源MAC决定`** (发回给客户端的MAC地址)。 |
| **2.3.9** | **发送响应数据包。** | 使用 Scapy 的 `sendp()` 函数 (工作在L2/链路层) 将完整构造好的响应数据包从正确的网络接口发送出去。 |

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
  "name": "string",
  "is_enabled": "boolean",
  "priority": "integer",

  "trigger_condition": {
    "l2": {
      "src_mac": "string | null",
      "dst_mac": "string | null"
    },
  
    "l3": {
      "ip_version": "integer | null",
      "src_ip": "string | null",
      "dst_ip": "string | null",
      "ttl": "integer | null",
      "protocol": "integer | null"
    },
  
    "l4": {
      "src_port": "integer | null",
      "dst_port": "integer | null"
    },
  
    "dns": {
      "qname": "string",
      "qtype": "integer",
    
      "transaction_id": "integer | null",
      "flags": {
        "opcode": "integer | null",
        "qr": "integer | null",
        "aa": "integer | null",
        "tc": "integer | null",
        "rd": "integer | null",
        "ra": "integer | null",
        "ad": "integer | null",
        "cd": "integer | null",
        "rcode": "integer | null"
      },
    
      "qd_count": "integer | null",
      "an_count": "integer | null",
      "ns_count": "integer | null",
      "ar_count": "integer | null"
    }
  },

  "response_action": {
    "l2": {
      "src_mac": {
        "mode": "string",
        "value": "string | null",
        "default": "auto",
        "description": "源MAC地址：响应包的发送方MAC。'auto' (自动获取本机MAC), 'inherit' (继承Query包的Dst MAC), 'custom' (自定义)。"
      },
      "dst_mac": {
        "mode": "string",
        "value": "string | null",
        "default": "inherit",
        "description": "目的MAC地址：响应包的接收方MAC。'inherit' (继承Query包的Src MAC), 'custom'。推荐 'inherit'。"
      }
    },
  
    "l3": {
      "src_ip": {
        "mode": "string",
        "value": "string | null",
        "default": "inherit",
        "description": "源IP地址：响应包的发送方IP。'auto' (自动获取本机IP), 'inherit' (继承Query包的Dst IP), 'custom'。推荐 'inherit'。"
      },
      "dst_ip": {
        "mode": "string",
        "value": "string | null",
        "default": "inherit",
        "description": "目的IP地址：响应包的接收方IP。'inherit' (继承Query包的Src IP), 'custom'。必须 'inherit'。"
      }
    },
  
    "l4": {
      "src_port": {
        "mode": "string",
        "value": "integer | null",
        "default": "inherit",
        "description": "源端口：响应包的发送方端口。'inherit' (继承Query包的Dst Port), 'custom'。推荐 'inherit' (通常是53)。"
      },
      "dst_port": {
        "mode": "string",
        "value": "integer | null",
        "default": "inherit",
        "description": "目的端口：响应包的接收方端口。'inherit' (继承Query包的Src Port), 'custom'。必须 'inherit'。"
      }
    },
  
    "dns_header": {
      "transaction_id": {
        "mode": "string",
        "default": "inherit",
        "description": "交易ID：必须继承Query包的ID，用于客户端匹配请求与响应。"
      },
      "questions": {
        "mode": "string",
        "default": "inherit",
        "description": "Questions部分：必须继承Query包的Questions部分，以告知客户端这是对哪个问题的回答。"
      },
    
      "flags": { 
        "qr": { "value": "integer", "default": 1, "description": "问答标志: 必须是 1 (Response)。" },
        "opcode": { "value": "integer", "default": 0, "description": "操作码: 必须是 0 (Standard Query)。" },
        "aa": { "value": "integer", "default": 1, "description": "权威标志: 1 (是权威服务器), 0 (非权威)。" },
        "tc": { "value": "integer", "default": 0, "description": "截断标志: 通常为 0。" },
        "rd": { "mode": "string", "value": "integer | null", "default": "inherit", "description": "递归请求: 'inherit' (继承Query包的rd位), 'custom' (自定义为0或1)。" },
        "ra": { "value": "integer", "default": 1, "description": "递归可用: 1 (服务器可用递归), 0 (不可用)。" },
        "ad": { "mode": "string", "value": "integer | null", "default": "inherit", "description": "验证数据(DNSSEC): 'inherit', 'custom'。" },
        "cd": { "mode": "string", "value": "integer | null", "default": "inherit", "description": "检查禁用(DNSSEC): 'inherit', 'custom'。" },
        "rcode": { "value": "integer", "default": 0, "description": "响应码: 0 (No Error), 3 (NXDOMAIN), etc." }
      }
    },
  
    "dns_answers": [
      {
        "name": {
           "mode": "string",
           "value": "string | null",
           "default": "inherit",
           "description": "记录所属域名: 'inherit' (继承Query的QNAME), 'custom'。推荐 'inherit'。"
        },
        "type": "integer",
        "ttl": "integer",
        "rdata": "string",
        "default": {
          "ttl": 3600
        }
      }
    ],
  
    "dns_authority": [],
    "dns_additional": []
  }
}
```

## 补充信息
#### 标准请求数据包结构
Domain Name System (query)
    Transaction ID: 0x3469
    Flags: 0x0120 Standard query
        0... .... .... .... = Response: Message is a query
        .000 0... .... .... = Opcode: Standard query (0)
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..1. .... = AD bit: Set
        .... .... ...0 .... = Non-authenticated data: Unacceptable
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 1
    Queries
        victim1.ns4.48232025.xyz: type A, class IN
            Name: victim1.ns4.48232025.xyz
            [Name Length: 24]
            [Label Count: 4]
            Type: A (1) (Host Address)
            Class: IN (0x0001)
    Additional records
        <Root>: type OPT
            Name: <Root>
            Type: OPT (41) 
            UDP payload size: 1232
            Higher bits in extended RCODE: 0x00
            EDNS0 version: 0
            Z: 0x0000
                0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
                .000 0000 0000 0000 = Reserved: 0x0000
            Data length: 12
            Option: COOKIE
                Option Code: COOKIE (10)
                Option Length: 8
                Option Data: 34fc480c4135f228
                Client Cookie: 34fc480c4135f228
                Server Cookie: <MISSING>
    [Response In: 24]

#### 标准响应数据包结构
Domain Name System (response)
    Transaction ID: 0x3469
    Flags: 0x8180 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .0.. .... .... = Authoritative: Server is not an authority for domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    Questions: 1
    Answer RRs: 1
    Authority RRs: 0
    Additional RRs: 1
    Queries
        victim1.ns4.48232025.xyz: type A, class IN
            Name: victim1.ns4.48232025.xyz
            [Name Length: 24]
            [Label Count: 4]
            Type: A (1) (Host Address)
            Class: IN (0x0001)
    Answers
        victim1.ns4.48232025.xyz: type A, class IN, addr 47.237.105.36
            Name: victim1.ns4.48232025.xyz
            Type: A (1) (Host Address)
            Class: IN (0x0001)
            Time to live: 3600 (1 hour)
            Data length: 4
            Address: 47.237.105.36
    Additional records
        <Root>: type OPT
            Name: <Root>
            Type: OPT (41) 
            UDP payload size: 1232
            Higher bits in extended RCODE: 0x00
            EDNS0 version: 0
            Z: 0x0000
                0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
                .000 0000 0000 0000 = Reserved: 0x0000
            Data length: 28
            Option: COOKIE
                Option Code: COOKIE (10)
                Option Length: 24
                Option Data: 34fc480c4135f2280100000068f60d971a5aad220a4b6944
                Client Cookie: 34fc480c4135f228
                Server Cookie: 0100000068f60d971a5aad220a4b6944
    [Request In: 5]
    [Time: 0.045155000 seconds]
