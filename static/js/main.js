document.addEventListener('DOMContentLoaded', () => {
    // --- Global State ---
    let currentRules = [];
    let selectedRuleId = null;

    // --- DOM Elements ---
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const rulesListContainer = document.getElementById('rules-list-container');
    const newRuleBtn = document.getElementById('new-rule-btn');
    const saveRuleBtn = document.getElementById('save-rule-btn');
    const deleteRuleBtn = document.getElementById('delete-rule-btn');
    const addAnswerBtn = document.getElementById('add-answer-btn');
    const dnsAnswersContainer = document.getElementById('dns-answers-container');
    
    const ruleEditor = document.getElementById('rule-editor');
    const logsViewer = document.getElementById('logs-viewer');
    const logTasksList = document.getElementById('log-tasks-list');
    const tabEditor = document.getElementById('tab-editor');
    const tabLogs = document.getElementById('tab-logs');

    // --- API Functions ---
    const api = {
        get: (url) => fetch(url).then(res => res.json()),
        post: (url, data) => fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).then(res => res.json()),
        put: (url, data) => fetch(url, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).then(res => res.json()),
        delete: (url) => fetch(url, { method: 'DELETE' }).then(res => res.json())
    };

    // --- UI Update Functions ---
    function updateStatus(isRunning) {
        if (isRunning) {
            statusIndicator.classList.remove('bg-red-500');
            statusIndicator.classList.add('bg-green-500');
            statusText.textContent = 'Running';
            startBtn.disabled = true;
            stopBtn.disabled = false;
        } else {
            statusIndicator.classList.remove('bg-green-500');
            statusIndicator.classList.add('bg-red-500');
            statusText.textContent = 'Stopped';
            startBtn.disabled = false;
            stopBtn.disabled = true;
        }
    }

    function renderRulesList() {
        rulesListContainer.innerHTML = '';
        currentRules.forEach(rule => {
            const ruleEl = document.createElement('div');
            ruleEl.className = `rule-item p-2 rounded cursor-pointer hover:bg-gray-600 flex justify-between items-center ${rule.rule_id === selectedRuleId ? 'bg-blue-800' : ''}`;
            ruleEl.dataset.ruleId = rule.rule_id;
            
            const nameSpan = document.createElement('span');
            nameSpan.className = 'rule-name-display';
            nameSpan.textContent = rule.name || 'Untitled Rule';
            
            const enabledCheckbox = document.createElement('input');
            enabledCheckbox.type = 'checkbox';
            enabledCheckbox.checked = rule.is_enabled;
            enabledCheckbox.className = 'rule-enabled-toggle pointer-events-none';

            ruleEl.appendChild(nameSpan);
            ruleEl.appendChild(enabledCheckbox);
            rulesListContainer.appendChild(ruleEl);
        });
    }

    function clearEditor() {
        document.getElementById('rule-id').value = '';
        document.getElementById('rule-name').value = '';
        document.getElementById('rule-enabled').checked = true;
        
        ruleEditor.querySelectorAll('input[data-path], select[data-path]').forEach(el => {
            if (el.tagName === 'SELECT') {
                el.selectedIndex = 0;
            } else {
                el.value = '';
            }
        });
        
        dnsAnswersContainer.innerHTML = '';
    }

    function displayRuleInEditor(rule) {
        clearEditor();
        if (!rule) return;

        document.getElementById('rule-id').value = rule.rule_id;
        document.getElementById('rule-name').value = rule.name;
        document.getElementById('rule-enabled').checked = rule.is_enabled;

        // Helper to get nested property
        const getProp = (obj, path) => path.split('.').reduce((o, k) => (o && o[k] !== undefined) ? o[k] : undefined, obj);

        // Populate all fields based on data-path
        ruleEditor.querySelectorAll('input[data-path], select[data-path]').forEach(el => {
            const path = el.dataset.path;
            const value = getProp(rule, path);

            if (value !== undefined && value !== null) {
                el.value = value;
            }
        });

        // Populate DNS answers
        const answers = getProp(rule, 'response_action.dns_answers') || [];
        answers.forEach(answer => addAnswerRow(answer));
    }
    
    function addAnswerRow(answer = {}) {
        const answerDiv = document.createElement('div');
        answerDiv.className = 'dns-answer-row grid grid-cols-10 gap-2 items-center';
        answerDiv.innerHTML = `
            <input type="number" data-key="type" class="col-span-2 w-full bg-gray-600 rounded p-1 text-sm" placeholder="Type" value="${answer.type || ''}">
            <input type="number" data-key="ttl" class="col-span-2 w-full bg-gray-600 rounded p-1 text-sm" placeholder="TTL" value="${answer.ttl || ''}">
            <input type="text" data-key="rdata" class="col-span-5 w-full bg-gray-600 rounded p-1 text-sm" placeholder="RDATA (e.g., IP address)" value="${answer.rdata || ''}">
            <button class="remove-answer-btn bg-red-600 hover:bg-red-700 text-white font-bold py-1 px-2 rounded text-xs">X</button>
        `;
        dnsAnswersContainer.appendChild(answerDiv);
    }

    // --- Event Handlers ---
    async function fetchAndRenderRules() {
        try {
            currentRules = await api.get('/api/rules');
            renderRulesList();
            const selectedRule = currentRules.find(r => r.rule_id === selectedRuleId);
            displayRuleInEditor(selectedRule);
        } catch (error) {
            console.error("Failed to fetch rules:", error);
            alert("Error: Could not fetch rules from the server.");
        }
    }

    startBtn.addEventListener('click', async () => {
        try {
            const result = await api.post('/api/control/start');
            updateStatus(true);
            alert(result.message || 'Sniffer started successfully.');
        } catch (error) {
            console.error("Failed to start sniffer:", error);
            alert(`Error starting sniffer: ${error.message}`);
        }
    });

    stopBtn.addEventListener('click', async () => {
        try {
            const result = await api.post('/api/control/stop');
            updateStatus(false);
            alert(result.message || 'Sniffer stopped successfully.');
        } catch (error) {
            console.error("Failed to stop sniffer:", error);
            alert(`Error stopping sniffer: ${error.message}`);
        }
    });

    rulesListContainer.addEventListener('click', (e) => {
        const ruleItem = e.target.closest('.rule-item');
        if (ruleItem) {
            selectedRuleId = ruleItem.dataset.ruleId;
            fetchAndRenderRules();
        }
    });

    newRuleBtn.addEventListener('click', () => {
        selectedRuleId = null;
        renderRulesList();
        clearEditor();
    });

    saveRuleBtn.addEventListener('click', async () => {
        const ruleData = {
            rule_id: document.getElementById('rule-id').value || null,
            name: document.getElementById('rule-name').value,
            is_enabled: document.getElementById('rule-enabled').checked,
            priority: 1 // Default priority
        };

        // Helper to set nested property
        const setProp = (obj, path, value) => {
            const keys = path.split('.');
            let current = obj;
            for (let i = 0; i < keys.length - 1; i++) {
                current = current[keys[i]] = current[keys[i]] || {};
            }
            if (value !== '' && value !== null) {
                const key = keys[keys.length - 1];
                const el = document.querySelector(`[data-path="${path}"]`);
                current[key] = (el && el.type === 'number') ? parseInt(value, 10) : value;
            }
        };

        // Gather all data from data-path elements
        ruleEditor.querySelectorAll('input[data-path], select[data-path]').forEach(el => {
            setProp(ruleData, el.dataset.path, el.value);
        });

        // Gather DNS answers
        const answers = [];
        dnsAnswersContainer.querySelectorAll('.dns-answer-row').forEach(row => {
            const answer = {};
            row.querySelectorAll('input[data-key]').forEach(input => {
                if (input.value) {
                    answer[input.dataset.key] = input.type === 'number' ? parseInt(input.value, 10) : input.value;
                }
            });
            if (answer.type && answer.ttl && answer.rdata) {
                answers.push(answer);
            }
        });
        setProp(ruleData, 'response_action.dns_answers', answers);

        try {
            if (selectedRuleId) {
                await api.put(`/api/rules/${selectedRuleId}`, ruleData);
            } else {
                const newRule = await api.post('/api/rules', ruleData);
                selectedRuleId = newRule.rule_id;
            }
            alert('Rule saved!');
            fetchAndRenderRules();
        } catch (error) {
            console.error("Failed to save rule:", error);
            alert(`Error saving rule: ${error.message}`);
        }
    });
    
    deleteRuleBtn.addEventListener('click', async () => {
        if (!selectedRuleId) {
            alert("No rule selected to delete.");
            return;
        }
        if (confirm("Are you sure you want to delete this rule?")) {
            try {
                await api.delete(`/api/rules/${selectedRuleId}`);
                selectedRuleId = null;
                alert('Rule deleted!');
                fetchAndRenderRules();
            } catch (error) {
                console.error("Failed to delete rule:", error);
                alert(`Error deleting rule: ${error.message}`);
            }
        }
    });
    
    addAnswerBtn.addEventListener('click', () => addAnswerRow());
    dnsAnswersContainer.addEventListener('click', (e) => {
        if (e.target.classList.contains('remove-answer-btn')) {
            e.target.closest('.dns-answer-row').remove();
        }
    });

    // --- Tab Logic ---
    tabEditor.addEventListener('click', () => {
        ruleEditor.classList.remove('hidden');
        logsViewer.classList.add('hidden');
        tabEditor.classList.add('border-blue-500', 'text-white');
        tabEditor.classList.remove('text-gray-400');
        tabLogs.classList.remove('border-blue-500', 'text-white');
        tabLogs.classList.add('text-gray-400');
    });

    async function fetchAndRenderLogs() {
        try {
            const sessions = await api.get('/api/logs');
            logTasksList.innerHTML = '<ul>';
            sessions.forEach(sessionId => {
                logTasksList.innerHTML += `<li class="p-2 hover:bg-gray-700 cursor-pointer" data-task-id="${sessionId}">${sessionId}</li>`;
            });
            logTasksList.innerHTML += '</ul>';
        } catch (error) {
            console.error("Failed to fetch logs:", error);
            logTasksList.innerHTML = '<p class="text-red-400">Failed to load log sessions.</p>';
        }
    }

    logTasksList.addEventListener('click', async (e) => {
        const taskId = e.target.dataset.taskId;
        if (taskId) {
            try {
                const details = await api.get(`/api/logs/${taskId}`);
                alert(`Logs for ${taskId}:\n\n${details.log_content}\n\nPcaps: ${details.pcap_files.join(', ')}`);
            } catch (error) {
                alert(`Failed to load details for task ${taskId}`);
            }
        }
    });

    tabLogs.addEventListener('click', () => {
        logsViewer.classList.remove('hidden');
        ruleEditor.classList.add('hidden');
        tabLogs.classList.add('border-blue-500', 'text-white');
        tabLogs.classList.remove('text-gray-400');
        tabEditor.classList.remove('border-blue-500', 'text-white');
        tabEditor.classList.add('text-gray-400');
        fetchAndRenderLogs();
    });

    // --- Initial Load ---
    updateStatus(false);
    fetchAndRenderRules();
});
