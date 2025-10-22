document.addEventListener('DOMContentLoaded', () => {
    // --- Global State ---
    let currentRules = [];
    let selectedRuleId = null;
    let logSessions = [];
    let logSort = { column: 'id', order: 'desc' };
    let logsPerPage = 10;
    let currentPage = 1;
    let totalLogPages = 1;
    let totalLogCount = 0;

    // --- i18n State ---
    let currentLang = 'en';
    let translations = {};

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
    const addAuthorityBtn = document.getElementById('add-authority-btn');
    const dnsAuthorityContainer = document.getElementById('dns-authority-container');
    const addAdditionalBtn = document.getElementById('add-additional-btn');
    const dnsAdditionalContainer = document.getElementById('dns-additional-container');
    
    const ruleEditor = document.getElementById('rule-editor');
    const logsViewer = document.getElementById('logs-viewer');
    const tabEditor = document.getElementById('tab-editor');
    const tabLogs = document.getElementById('tab-logs');
    const ruleNameSection = document.getElementById('rule-name-section');

    // Log-specific DOM elements
    const logTableBody = document.getElementById('log-tasks-table-body');
    const logTableHeader = document.querySelector('#logs-viewer thead');
    const modal = document.getElementById('log-details-modal');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    const modalTaskId = document.getElementById('modal-task-id');
    const modalLogContent = document.getElementById('modal-log-content');
    const modalDownloadLink = document.getElementById('modal-download-pcap');
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toast-message');
    const logsPerPageSelect = document.getElementById('logs-per-page');
    const logPageJumpInput = document.getElementById('log-page-jump');
    const logPageJumpBtn = document.getElementById('log-page-jump-btn');
    const logPagination = document.getElementById('log-pagination');
    const langEnBtn = document.getElementById('lang-en');
    const langZhBtn = document.getElementById('lang-zh');

    // --- i18n Functions ---
    async function setLanguage(lang) {
        try {
            const response = await fetch(`/static/lang/${lang}.json`);
            translations = await response.json();
            currentLang = lang;
            localStorage.setItem('preferredLanguage', lang);
            updateContent();
            
            // Update language switcher style
            if (lang === 'en') {
                langEnBtn.classList.add('bg-gray-600');
                langEnBtn.classList.remove('bg-gray-800');
                langZhBtn.classList.add('bg-gray-800');
                langZhBtn.classList.remove('bg-gray-600');
            } else {
                langZhBtn.classList.add('bg-gray-600');
                langZhBtn.classList.remove('bg-gray-800');
                langEnBtn.classList.add('bg-gray-800');
                langEnBtn.classList.remove('bg-gray-600');
            }

        } catch (error) {
            console.error(`Could not load language file for ${lang}:`, error);
        }
    }

    function updateContent() {
        document.querySelectorAll('[data-i18n-key]').forEach(el => {
            const key = el.dataset.i18nKey;
            if (translations[key]) {
                // Handle specific cases like status text which might need dynamic parts
                if (key === 'statusRunning' && statusText.textContent === 'Running') {
                    el.textContent = translations[key];
                } else if (key === 'statusStopped' && statusText.textContent === 'Stopped') {
                    el.textContent = translations[key];
                } else if (!['statusRunning', 'statusStopped'].includes(key)) {
                    el.textContent = translations[key];
                }
            }
        });
        document.querySelectorAll('[data-i18n-placeholder-key]').forEach(el => {
            const key = el.dataset.i18nPlaceholderKey;
            if (translations[key]) {
                el.placeholder = translations[key];
            }
        });
        // Re-render dynamic content that needs translation
        renderRulesList();
        fetchAndRenderLogs();
    }


    // --- UI Functions ---
    function showToast(message, isError = false) {
        toastMessage.textContent = message;
        toast.classList.remove('bg-blue-500', 'bg-red-500', 'translate-x-full');
        
        if (isError) {
            toast.classList.add('bg-red-500');
        } else {
            toast.classList.add('bg-blue-500');
        }

        // Show the toast
        toast.classList.remove('translate-x-full');
        toast.style.transform = 'translateX(0)';

        // Hide it after 3 seconds
        setTimeout(() => {
            toast.style.transform = 'translateX(120%)';
        }, 3000);
    }

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
            nameSpan.textContent = rule.name || (translations.untitledRule || 'Untitled Rule');
            
            const enabledCheckbox = document.createElement('input');
            enabledCheckbox.type = 'checkbox';
            enabledCheckbox.checked = rule.is_enabled;
            enabledCheckbox.className = 'rule-enabled-toggle'; // Allow pointer events
            enabledCheckbox.dataset.ruleId = rule.rule_id; // Add rule-id for direct access

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
        dnsAuthorityContainer.innerHTML = '';
        dnsAdditionalContainer.innerHTML = '';
    }

    function displayRuleInEditor(rule) {
        clearEditor();
        if (!rule) return;

        document.getElementById('rule-id').value = rule.rule_id;
        document.getElementById('rule-name').value = rule.name;
        document.getElementById('rule-enabled').checked = rule.is_enabled;

        const getProp = (obj, path) => path.split('.').reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);

        // Universal populator for all fields with a data-path
        ruleEditor.querySelectorAll('[data-path]').forEach(el => {
            const path = el.dataset.path;
            const value = getProp(rule, path);

            if (el.tagName === 'SELECT') {
                // Handle mode selects
                if (path.endsWith('.mode')) {
                    const config = getProp(rule, path.replace('.mode', ''));
                    el.value = config?.mode || el.options.value; // Default to first option
                    
                    const valueEl = ruleEditor.querySelector(`[data-path="${path.replace('.mode', '.value')}"]`);
                    if (valueEl) {
                        valueEl.value = config?.value ?? '';
                        valueEl.disabled = (config?.mode || 'inherit') !== 'custom';
                    }
                }
            } else if (el.type === 'checkbox') {
                el.checked = !!value;
            } else {
                 // Handle all other inputs, including nested values like flags
                if (value !== null) {
                    el.value = value;
                }
            }
        });

        // Populate RR sections
        const answers = getProp(rule, 'response_action.dns_answers') || [];
        answers.forEach(rr => addRRRow(dnsAnswersContainer, rr));
        
        const authorities = getProp(rule, 'response_action.dns_authority') || [];
        authorities.forEach(rr => addRRRow(dnsAuthorityContainer, rr));

        const additionals = getProp(rule, 'response_action.dns_additional') || [];
        additionals.forEach(rr => addRRRow(dnsAdditionalContainer, rr));
    }
    
    function addRRRow(container, rr = {}) {
        const rrDiv = document.createElement('div');
        rrDiv.className = 'rr-row grid grid-cols-12 gap-2 items-end mb-2'; // Use items-end to align labels nicely
        
        const nameMode = rr.name?.mode || 'inherit';
        const nameValue = rr.name?.value || '';
        const type = rr.type || '';
        const isOpt = type === 41;

        rrDiv.innerHTML = `
            <div class="col-span-2">
                <label class="text-xs text-gray-400">Name Mode</label>
                <select data-key="name.mode" class="w-full bg-gray-600 rounded p-1 text-sm mt-1">
                    <option value="inherit" ${nameMode === 'inherit' ? 'selected' : ''}>Inherit</option>
                    <option value="custom" ${nameMode === 'custom' ? 'selected' : ''}>Custom</option>
                </select>
            </div>
            <div class="col-span-3">
                <label class="text-xs text-gray-400">Name Value</label>
                <input type="text" data-key="name.value" class="w-full bg-gray-600 rounded p-1 text-sm mt-1" placeholder="e.g., ns1.example.com" value="${nameValue}" ${nameMode !== 'custom' ? 'disabled' : ''}>
            </div>
            <div class="col-span-1">
                <label class="text-xs text-gray-400" data-i18n-key="rrTypeLabel">Type</label><i class="fas fa-info-circle text-gray-400 ml-1 cursor-pointer" data-tooltip-type="list" data-tooltip-key="DnsType"></i>
                <input type="number" data-key="type" class="w-full bg-gray-600 rounded p-1 text-sm mt-1" placeholder="1" value="${type}">
            </div>
            <div class="col-span-1">
                <label class="text-xs text-gray-400">TTL</label>
                <input type="number" data-key="ttl" class="w-full bg-gray-600 rounded p-1 text-sm mt-1" placeholder="3600" value="${rr.ttl || ''}" ${isOpt ? 'disabled' : ''}>
            </div>
            <div class="col-span-4">
                <label class="text-xs text-gray-400">RDATA</label>
                <input type="text" data-key="rdata" class="w-full bg-gray-600 rounded p-1 text-sm mt-1" placeholder="e.g., 1.2.3.4" value="${rr.rdata || ''}" ${isOpt ? 'disabled' : ''}>
            </div>
            <button class="remove-rr-btn bg-red-600 hover:bg-red-700 text-white font-bold py-1 px-2 rounded text-xs self-center">X</button>
        `;
        container.appendChild(rrDiv);

        // Add event listener for the new row's select
        rrDiv.querySelector('select[data-key="name.mode"]').addEventListener('change', (e) => {
            const valueInput = e.target.nextElementSibling;
            valueInput.disabled = e.target.value !== 'custom';
        });
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
            showToast("Error: Could not fetch rules from the server.", true);
        }
    }

    startBtn.addEventListener('click', async () => {
        try {
            const result = await api.post('/api/control/start');
            updateStatus(true);
            showToast(result.message || 'Sniffer started successfully.');
        } catch (error) {
            console.error("Failed to start sniffer:", error);
            showToast(`Error starting sniffer: ${error.message}`, true);
        }
    });

    stopBtn.addEventListener('click', async () => {
        try {
            const result = await api.post('/api/control/stop');
            updateStatus(false);
            showToast(result.message || 'Sniffer stopped successfully.');
        } catch (error) {
            console.error("Failed to stop sniffer:", error);
            showToast(`Error stopping sniffer: ${error.message}`, true);
        }
    });

    rulesListContainer.addEventListener('click', async (e) => {
        const ruleItem = e.target.closest('.rule-item');
        
        // Handle clicks on the checkbox for enabling/disabling rules
        if (e.target.classList.contains('rule-enabled-toggle')) {
            const checkbox = e.target;
            const ruleId = checkbox.dataset.ruleId;
            const rule = currentRules.find(r => r.rule_id === ruleId);
            if (rule) {
                rule.is_enabled = checkbox.checked;
                try {
                    await api.put(`/api/rules/${ruleId}`, rule);
                    showToast(`Rule '${rule.name}' ${rule.is_enabled ? 'enabled' : 'disabled'}.`);
                    // If the sniffer is running, restart it to apply the change
                    if (statusText.textContent === 'Running') {
                        await api.post('/api/control/stop');
                        await api.post('/api/control/start');
                        showToast('Sniffer restarted to apply rule changes.');
                    }
                } catch (error) {
                    console.error("Failed to update rule state:", error);
                    showToast(`Error updating rule: ${error.message}`, true);
                    // Revert checkbox on failure
                    checkbox.checked = !checkbox.checked;
                }
            }
            return; // Stop further processing to prevent selecting the rule
        }

        // Handle clicks on the rule item itself to select it
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
        const isSnifferRunning = statusText.textContent === 'Running';
        const ruleData = {
            rule_id: document.getElementById('rule-id').value || null,
            name: document.getElementById('rule-name').value,
            is_enabled: document.getElementById('rule-enabled').checked,
            priority: 1, // Default priority
        };

        const setProp = (obj, path, value) => {
            // Only set the property if the value is not an empty string
            if (value === '' || value === null || value === undefined) return;
            
            const keys = path.split('.');
            let current = obj;
            for (let i = 0; i < keys.length - 1; i++) {
                current = current[keys[i]] = current[keys[i]] || {};
            }
            const finalKey = keys[keys.length - 1];
            const isNumber = !isNaN(parseFloat(value)) && isFinite(value);
            current[finalKey] = isNumber ? parseFloat(value) : value;
        };

        // Universal collector for all fields with a data-path
        ruleEditor.querySelectorAll('[data-path]').forEach(el => {
            const path = el.dataset.path;
            let value = el.type === 'checkbox' ? el.checked : el.value;
            
            // Skip mode fields, they are handled by their corresponding value fields
            if (path.endsWith('.mode')) return;

            // Handle complex objects (like flags or l2/l3/l4 settings)
            if (path.endsWith('.value')) {
                const basePath = path.substring(0, path.lastIndexOf('.value'));
                const modeEl = ruleEditor.querySelector(`[data-path="${basePath}.mode"]`);
                if (modeEl) { // This is a complex object with mode/value
                    const mode = modeEl.value;
                    const obj = { mode };
                    if (mode === 'custom' && value !== '') {
                        const isNumber = el.type === 'number';
                        obj.value = isNumber ? parseInt(value, 10) : value;
                    }
                    // Use a different setter to place the whole object
                    const keys = basePath.split('.');
                    let current = ruleData;
                    for (let i = 0; i < keys.length - 1; i++) {
                        current = current[keys[i]] = current[keys[i]] || {};
                    }
                    current[keys[keys.length - 1]] = obj;

                } else { // This is a simple value-only object (e.g., simple response flags)
                     if (value !== '') {
                        const obj = { value: el.type === 'number' ? parseInt(value, 10) : value };
                        // FIX: Use basePath for keys to set the object at the correct level (e.g., at 'qr'), not at 'qr.value'
                        const keys = basePath.split('.');
                        let current = ruleData;
                        for (let i = 0; i < keys.length - 1; i++) {
                            current = current[keys[i]] = current[keys[i]] || {};
                        }
                        current[keys[keys.length - 1]] = obj;
                     }
                }
            } else {
                // Handle simple path values
                setProp(ruleData, path, value);
            }
        });

        // Collect RR sections
        const collectRRSection = (container) => {
            const rrs = [];
            container.querySelectorAll('.rr-row').forEach(row => {
                const rr = {};
                // Custom collector for nested RR structure
                const nameMode = row.querySelector('[data-key="name.mode"]').value;
                const nameValue = row.querySelector('[data-key="name.value"]').value;
                rr.name = { mode: nameMode };
                if (nameMode === 'custom' && nameValue) {
                    rr.name.value = nameValue;
                }
                
                const type = row.querySelector('[data-key="type"]').value;
                if (type) rr.type = parseInt(type, 10);

                const ttl = row.querySelector('[data-key="ttl"]').value;
                if (ttl) rr.ttl = parseInt(ttl, 10);

                const rdata = row.querySelector('[data-key="rdata"]').value;
                if (rdata) rr.rdata = rdata;

                if (rr.type) { // Type is mandatory for an RR
                    rrs.push(rr);
                }
            });
            return rrs;
        };
        
        const responseAction = ruleData.response_action || {};
        responseAction.dns_answers = collectRRSection(dnsAnswersContainer);
        responseAction.dns_authority = collectRRSection(dnsAuthorityContainer);
        responseAction.dns_additional = collectRRSection(dnsAdditionalContainer);
        ruleData.response_action = responseAction;

        try {
            if (selectedRuleId) {
                await api.put(`/api/rules/${selectedRuleId}`, ruleData);
            } else {
                const newRule = await api.post('/api/rules', ruleData);
                selectedRuleId = newRule.rule_id;
            }
            showToast('Rule saved!');
            await fetchAndRenderRules(); // Use await to ensure rules are fresh

            // If the sniffer was running, restart it to apply changes
            if (isSnifferRunning) {
                showToast('Restarting sniffer to apply changes...');
                await api.post('/api/control/stop');
                const result = await api.post('/api/control/start');
                updateStatus(true);
                showToast(result.message || 'Sniffer restarted successfully.');
            }

        } catch (error) {
            console.error("Failed to save rule:", error);
            showToast(`Error saving rule: ${error.message}`, true);
        }
    });
    
    deleteRuleBtn.addEventListener('click', async () => {
        if (!selectedRuleId) {
            showToast("No rule selected to delete.", true);
            return;
        }
        if (confirm("Are you sure you want to delete this rule?")) {
            try {
                await api.delete(`/api/rules/${selectedRuleId}`);
                selectedRuleId = null;
                showToast('Rule deleted!');
                fetchAndRenderRules();
            } catch (error) {
                console.error("Failed to delete rule:", error);
                showToast(`Error deleting rule: ${error.message}`, true);
            }
        }
    });
    
    addAnswerBtn.addEventListener('click', () => addRRRow(dnsAnswersContainer));
    addAuthorityBtn.addEventListener('click', () => addRRRow(dnsAuthorityContainer));
    addAdditionalBtn.addEventListener('click', () => addRRRow(dnsAdditionalContainer));

    const handleRemoveRR = (e) => {
        if (e.target.classList.contains('remove-rr-btn')) {
            e.target.closest('.rr-row').remove();
        }
    };
    dnsAnswersContainer.addEventListener('click', handleRemoveRR);
    dnsAuthorityContainer.addEventListener('click', handleRemoveRR);
    dnsAdditionalContainer.addEventListener('click', handleRemoveRR);

    // --- Tooltip Logic ---
    function showTooltip(element) {
        const type = element.dataset.tooltipType;
        const key = element.dataset.tooltipKey;
        
        const tooltip = document.createElement('div');
        tooltip.className = 'absolute z-10 w-auto max-w-xs p-2 my-2 text-sm text-white bg-gray-800 rounded-lg shadow-lg';
        tooltip.id = 'dynamic-tooltip';

        let content = '';
        if (type === 'list') {
            content = `<h3 class="font-bold">${translations[`tooltip${key}Title`]}</h3><ul class="list-disc list-inside">`;
            for (let i = 1; i <= 50; i++) { // Check for up to 50 types
                const transKey = `tooltip${key}${i}`;
                if (translations[transKey]) {
                    content += `<li>${translations[transKey]}</li>`;
                }
            }
            content += '</ul>';
        } else { // 'text'
            content = translations[`tooltip${key}`] || 'No information available.';
        }
        
        tooltip.innerHTML = content;
        document.body.appendChild(tooltip);

        const rect = element.getBoundingClientRect();
        tooltip.style.left = `${rect.left + window.scrollX}px`;
        tooltip.style.top = `${rect.bottom + window.scrollY + 5}px`;
    }

    function hideTooltip() {
        const tooltip = document.getElementById('dynamic-tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }

    document.body.addEventListener('mouseover', (e) => {
        if (e.target.matches('[data-tooltip-key]')) {
            showTooltip(e.target);
        }
    });

    document.body.addEventListener('mouseout', (e) => {
        if (e.target.matches('[data-tooltip-key]')) {
            hideTooltip();
        }
    });

    ruleEditor.addEventListener('change', (e) => {
        if (e.target.matches('select[data-path$=".mode"]')) {
            const valueInput = e.target.parentElement.querySelector('input[data-path$=".value"]');
            if (valueInput) {
                valueInput.disabled = e.target.value !== 'custom';
            }
        }
    });

    // --- Tab Logic ---
    tabEditor.addEventListener('click', () => {
        ruleEditor.classList.remove('hidden');
        logsViewer.classList.add('hidden');
        ruleNameSection.classList.remove('hidden');
        ruleNameSection.classList.add('flex');
        tabEditor.classList.add('border-blue-500', 'text-white');
        tabEditor.classList.remove('text-gray-400');
        tabLogs.classList.remove('border-blue-500', 'text-white');
        tabLogs.classList.add('text-gray-400');
    });

    tabLogs.addEventListener('click', () => {
        logsViewer.classList.remove('hidden');
        logsViewer.classList.add('flex');
        ruleEditor.classList.add('hidden');
        ruleNameSection.classList.add('hidden');
        ruleNameSection.classList.remove('flex');
        
        tabLogs.classList.add('border-blue-500', 'text-white');
        tabLogs.classList.remove('text-gray-400');
        
        tabEditor.classList.remove('border-blue-500', 'text-white');
        tabEditor.classList.add('text-gray-400');
        
        fetchAndRenderLogs();
    });

    // --- Log Viewer Logic ---
    function formatTaskId(taskId) {
        const year = taskId.substring(0, 4);
        const month = taskId.substring(4, 6);
        const day = taskId.substring(6, 8);
        const hour = taskId.substring(8, 10);
        const minute = taskId.substring(10, 12);
        const second = taskId.substring(12, 14);
        return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
    }

    function renderLogs(sessions) {
        logTableBody.innerHTML = '';

        if (!sessions || sessions.length === 0) {
            const noLogsMessage = translations.noLogsMessage || 'No log sessions found.';
            logTableBody.innerHTML = `<tr><td colspan="2" class="text-center py-4">${noLogsMessage}</td></tr>`;
            return;
        }

        sessions.forEach(sessionId => {
            const row = document.createElement('tr');
            row.className = 'bg-gray-800 border-b border-gray-700 hover:bg-gray-600';
            row.innerHTML = `
                <td class="px-6 py-4 font-medium whitespace-nowrap">${formatTaskId(sessionId)}</td>
                <td class="px-6 py-4">
                    <button class="view-log-details-btn bg-blue-600 hover:bg-blue-700 text-white text-xs py-1 px-2 rounded" data-task-id="${sessionId}">${translations.logDetailsBtn || 'Details'}</button>
                    <button class="delete-log-btn bg-red-600 hover:bg-red-700 text-white text-xs py-1 px-2 rounded ml-2" data-task-id="${sessionId}">${translations.logDeleteBtn || 'Delete'}</button>
                </td>
            `;
            logTableBody.appendChild(row);
        });
    }

    function renderPagination() {
        logPagination.innerHTML = '';
        if (totalLogCount === 0) return;

        const startItem = (currentPage - 1) * logsPerPage + 1;
        const endItem = Math.min(startItem + logsPerPage - 1, totalLogCount);

        const text = `
            <span class="text-gray-400">
                ${translations.paginationShowing || 'Showing'} ${startItem} ${translations.paginationTo || 'to'} ${endItem} ${translations.paginationOf || 'of'} ${totalLogCount} ${translations.paginationResults || 'Results'}
            </span>
        `;

        const buttons = `
            <div class="flex items-center">
                <button id="prev-page-btn" class="px-3 py-1 bg-gray-700 rounded-l-md hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed" ${currentPage === 1 ? 'disabled' : ''}>
                    <i class="fas fa-chevron-left"></i> <span class="ml-1">${translations.paginationPrev || 'Previous'}</span>
                </button>
                <button id="next-page-btn" class="px-3 py-1 bg-gray-700 rounded-r-md hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed" ${currentPage === totalLogPages ? 'disabled' : ''}>
                    <span class="mr-1">${translations.paginationNext || 'Next'}</span> <i class="fas fa-chevron-right"></i>
                </button>
            </div>
        `;
        
        logPagination.innerHTML = text + buttons;
    }

    async function fetchAndRenderLogs() {
        try {
            const params = new URLSearchParams({
                page: currentPage,
                limit: logsPerPage,
                sort: logSort.column,
                order: logSort.order
            });
            const data = await api.get(`/api/logs?${params.toString()}`);
            
            logSessions = data.sessions;
            totalLogPages = data.pages;
            currentPage = data.page;
            totalLogCount = data.total;

            renderLogs(logSessions);
            renderPagination();
            logPageJumpInput.value = currentPage;
            logPageJumpInput.max = totalLogPages;

        } catch (error) {
            console.error("Failed to fetch logs:", error);
            logTableBody.innerHTML = '<tr><td colspan="2" class="text-center text-red-400 p-4">Failed to load log sessions.</td></tr>';
        }
    }

    logTableHeader.addEventListener('click', (e) => {
        const th = e.target.closest('th');
        if (th && th.dataset.sort) {
            const column = th.dataset.sort;
            if (logSort.column === column) {
                logSort.order = logSort.order === 'asc' ? 'desc' : 'asc';
            } else {
                logSort.column = column;
                logSort.order = 'desc';
            }
            // Update indicator
            document.querySelectorAll('.sort-indicator').forEach(el => el.textContent = '');
            th.querySelector('.sort-indicator').textContent = logSort.order === 'asc' ? ' ▲' : ' ▼';
            fetchAndRenderLogs();
        }
    });

    logTableBody.addEventListener('click', async (e) => {
        const taskId = e.target.dataset.taskId;
        if (!taskId) return;

        if (e.target.classList.contains('view-log-details-btn')) {
            try {
                const details = await api.get(`/api/logs/${taskId}`);
                modalTaskId.textContent = formatTaskId(taskId);
                modalLogContent.textContent = details.log_content || 'No log entries found.';
                // Assuming only one pcap file named 'capture.pcap'
                modalDownloadLink.href = `/api/logs/${taskId}/download/capture.pcap`;
                modal.classList.remove('hidden');
                modal.classList.add('flex');
            } catch (error) {
                alert(`Failed to load details for task ${taskId}`);
            }
        }

        if (e.target.classList.contains('delete-log-btn')) {
            if (confirm(`Are you sure you want to delete the log session ${formatTaskId(taskId)}?`)) {
                try {
                    await api.delete(`/api/logs/${taskId}`);
                    alert('Log session deleted.');
                    fetchAndRenderLogs();
                } catch (error) {
                    alert(`Failed to delete log session ${taskId}`);
                }
            }
        }
    });

    modalCloseBtn.addEventListener('click', () => {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    });

    logPagination.addEventListener('click', (e) => {
        const prevBtn = e.target.closest('#prev-page-btn');
        const nextBtn = e.target.closest('#next-page-btn');

        if (prevBtn && !prevBtn.disabled) {
            currentPage--;
            fetchAndRenderLogs();
        } else if (nextBtn && !nextBtn.disabled) {
            currentPage++;
            fetchAndRenderLogs();
        }
    });

    logsPerPageSelect.addEventListener('change', (e) => {
        logsPerPage = parseInt(e.target.value, 10);
        currentPage = 1; // Reset to first page
        fetchAndRenderLogs();
    });

    logPageJumpBtn.addEventListener('click', () => {
        const page = parseInt(logPageJumpInput.value, 10);
        if (page > 0 && page <= totalLogPages) {
            currentPage = page;
            fetchAndRenderLogs();
        } else {
            showToast(`Please enter a valid page number between 1 and ${totalLogPages}.`, true);
        }
    });

    langEnBtn.addEventListener('click', () => setLanguage('en'));
    langZhBtn.addEventListener('click', () => setLanguage('zh'));

    // --- Initial Load ---
    async function initializeApp() {
        const preferredLanguage = localStorage.getItem('preferredLanguage') || 'en';
        await setLanguage(preferredLanguage);
        updateStatus(false);
        fetchAndRenderRules();
    }

    initializeApp();
});
