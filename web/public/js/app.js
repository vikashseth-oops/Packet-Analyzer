// ============================================================================
// PACKET ANALYZER & DPI ENGINE - FRONTEND CONTROLLER (TEAL & LIME THEME)
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Chart instances
  let appChartInstance = null;
  let threadChartInstance = null;

  // State
  let currentRules = { ips: [], apps: [], domains: [], ports: [] };
  let currentFlows = [];

  // DOM Elements
  const clockDisplay = document.getElementById('clock-display');
  const engineStatusText = document.getElementById('engine-status-text');
  const pcapInput = document.getElementById('pcap-input');
  const chosenFileName = document.getElementById('chosen-file-name');
  const uploadForm = document.getElementById('upload-form');
  const runSampleBtn = document.getElementById('run-sample-btn');
  const downloadOutputBtn = document.getElementById('download-output-btn');
  
  const valTotalPackets = document.getElementById('val-total-packets');
  const valTcpUdp = document.getElementById('val-tcp-udp');
  const valTotalBytes = document.getElementById('val-total-bytes');
  const valThroughput = document.getElementById('val-throughput');
  const valActiveFlows = document.getElementById('val-active-flows');
  const valClassifiedFlows = document.getElementById('val-classified-flows');
  const valDroppedPackets = document.getElementById('val-dropped-packets');
  const valDropRate = document.getElementById('val-drop-rate');
  
  const ruleTypeSelect = document.getElementById('rule-type-select');
  const ruleValueInput = document.getElementById('rule-value-input');
  const addRuleBtn = document.getElementById('add-rule-btn');
  const ruleTagsContainer = document.getElementById('rule-tags-container');
  const activeRulesCount = document.getElementById('active-rules-count');
  
  const flowSearchInput = document.getElementById('flow-search-input');
  const flowTableBody = document.getElementById('flow-table-body');
  const consoleOutput = document.getElementById('console-output');
  const clearConsoleBtn = document.getElementById('clear-console-btn');

  // 1. Clock Update
  function updateClock() {
    const now = new Date();
    clockDisplay.textContent = now.toTimeString().split(' ')[0];
  }
  setInterval(updateClock, 1000);
  updateClock();

  // 2. Initialize Chart.js with Greenish Teal & Lime Palette
  function initCharts() {
    // App Doughnut Chart
    const ctxApp = document.getElementById('appChart').getContext('2d');
    appChartInstance = new Chart(ctxApp, {
      type: 'doughnut',
      data: {
        labels: ['Unknown', 'HTTP', 'HTTPS', 'DNS'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: [
            '#475569', '#0d9488', '#84cc16', '#2dd4bf',
            '#a3e635', '#f43f5e', '#f59e0b', '#06b6d4',
            '#10b981', '#6366f1'
          ],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#cbd5e1', font: { family: 'Inter', size: 12 } }
          }
        }
      }
    });

    // Thread Bar Chart (Teal & Lime gradient bars)
    const ctxThread = document.getElementById('threadChart').getContext('2d');
    threadChartInstance = new Chart(ctxThread, {
      type: 'bar',
      data: {
        labels: ['FP0', 'FP1', 'FP2', 'FP3'],
        datasets: [{
          label: 'Packets Processed',
          data: [0, 0, 0, 0],
          backgroundColor: ['#0d9488', '#84cc16', '#2dd4bf', '#a3e635'],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: { color: '#94a3b8' },
            grid: { color: 'rgba(255, 255, 255, 0.05)' }
          },
          x: {
            ticks: { color: '#94a3b8' },
            grid: { display: false }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }

  initCharts();

  // 3. Console Logger
  function logConsole(msg, type = 'info') {
    const time = new Date().toTimeString().split(' ')[0];
    const div = document.createElement('div');
    div.className = `term-line ${type}`;
    div.textContent = `[${time}] ${msg}`;
    consoleOutput.appendChild(div);
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
  }

  clearConsoleBtn.addEventListener('click', () => {
    consoleOutput.innerHTML = '';
    logConsole('Console log cleared.', 'info');
  });

  // 4. File input display
  pcapInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      chosenFileName.textContent = `File chosen: ${e.target.files[0].name}`;
      logConsole(`Selected file: ${e.target.files[0].name}`, 'info');
    } else {
      chosenFileName.textContent = 'Or run test demo capture file below';
    }
  });

  // 5. Fetch Rules & Engine Status
  async function fetchStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      if (data.status === 'online') {
        engineStatusText.textContent = data.engineAvailable ? 'Engine Online' : 'Engine Build Missing';
        logConsole('PacketScope DPI Backend online. C++ Engine ready.', 'success');
      }
    } catch (err) {
      engineStatusText.textContent = 'Backend Offline';
      logConsole('Failed to connect to backend server.', 'error');
    }
  }

  async function fetchRules() {
    try {
      const res = await fetch('/api/rules');
      const data = await res.json();
      currentRules = data;
      renderRules();
    } catch (err) {
      logConsole('Error fetching rules.', 'error');
    }
  }

  // 6. Render Rules in UI
  function renderRules() {
    ruleTagsContainer.innerHTML = '';
    let totalCount = 0;

    const addTag = (type, val) => {
      totalCount++;
      const tag = document.createElement('div');
      tag.className = 'active-chip';
      tag.innerHTML = `
        <span class="chip-type">${type}</span>
        <span>${val}</span>
        <i class="fa-solid fa-xmark chip-remove" data-type="${type}" data-val="${val}"></i>
      `;
      ruleTagsContainer.appendChild(tag);
    };

    currentRules.ips.forEach(v => addTag('ip', v));
    currentRules.apps.forEach(v => addTag('app', v));
    currentRules.domains.forEach(v => addTag('domain', v));
    currentRules.ports.forEach(v => addTag('port', v));

    activeRulesCount.textContent = `${totalCount} Rule${totalCount !== 1 ? 's' : ''} Active`;

    // Highlight active app chips
    document.querySelectorAll('.app-chip').forEach(chip => {
      const appName = chip.dataset.app;
      if (currentRules.apps.includes(appName)) {
        chip.classList.add('blocked');
      } else {
        chip.classList.remove('blocked');
      }
    });
  }

  // 7. Add Rule
  async function addRule(type, value) {
    if (!value) return;
    try {
      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, value })
      });
      const data = await res.json();
      if (data.success) {
        currentRules = data.activeRules;
        renderRules();
        logConsole(`Added filter rule: [${type.toUpperCase()}] ${value}`, 'warn');
      }
    } catch (err) {
      logConsole('Failed to add rule', 'error');
    }
  }

  // 8. Remove Rule
  async function removeRule(type, value) {
    try {
      const res = await fetch('/api/rules', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, value })
      });
      const data = await res.json();
      if (data.success) {
        currentRules = data.activeRules;
        renderRules();
        logConsole(`Removed filter rule: [${type.toUpperCase()}] ${value}`, 'info');
      }
    } catch (err) {
      logConsole('Failed to remove rule', 'error');
    }
  }

  // Form custom rule submit
  addRuleBtn.addEventListener('click', () => {
    const type = ruleTypeSelect.value;
    const value = ruleValueInput.value.trim();
    if (value) {
      addRule(type, value);
      ruleValueInput.value = '';
    }
  });

  // Remove tag click event delegation
  ruleTagsContainer.addEventListener('click', (e) => {
    if (e.target.classList.contains('chip-remove')) {
      const type = e.target.dataset.type;
      const val = e.target.dataset.val;
      removeRule(type, val);
    }
  });

  // Quick app toggle click
  document.querySelectorAll('.app-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const appName = chip.dataset.app;
      if (currentRules.apps.includes(appName)) {
        removeRule('app', appName);
      } else {
        addRule('app', appName);
      }
    });
  });

  // 9. Run Analysis (Upload or Demo)
  async function runAnalysis(fileObj = null) {
    logConsole('Executing DPI Engine analysis...', 'info');
    downloadOutputBtn.classList.add('disabled');
    downloadOutputBtn.removeAttribute('href');

    const formData = new FormData();
    if (fileObj) {
      formData.append('pcapFile', fileObj);
    }

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        body: fileObj ? formData : null
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        logConsole(`Analysis failed: ${data.error || 'Unknown error'}`, 'error');
        if (data.details) logConsole(data.details, 'error');
        return;
      }

      logConsole(`Analysis complete for ${data.results.inputFileName}`, 'success');
      
      // Update download link
      if (data.results.downloadUrl) {
        downloadOutputBtn.href = data.results.downloadUrl;
        downloadOutputBtn.classList.remove('disabled');
      }

      // Update UI components
      updateUIResults(data.results);

    } catch (err) {
      logConsole(`Exception during analysis: ${err.message}`, 'error');
    }
  }

  // Upload Form Submit
  uploadForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (pcapInput.files.length > 0) {
      runAnalysis(pcapInput.files[0]);
    } else {
      logConsole('Please select a .pcap file or click "Run Demo Capture"', 'warn');
    }
  });

  // Run Sample Button
  runSampleBtn.addEventListener('click', () => {
    runAnalysis(null);
  });

  // 10. Update Dashboard Metrics & Charts
  function updateUIResults(results) {
    // Metrics
    valTotalPackets.textContent = results.totalPackets.toLocaleString();
    valTcpUdp.textContent = `${results.tcpPackets} TCP / ${results.udpPackets} UDP`;
    
    valTotalBytes.textContent = formatBytes(results.totalBytes);
    valThroughput.textContent = `${(results.totalBytes / 1024).toFixed(1)} KB volume`;
    
    valActiveFlows.textContent = results.activeConnections || results.flows.length || 0;
    valClassifiedFlows.textContent = `${results.apps.length} classified types`;
    
    valDroppedPackets.textContent = results.dropped.toLocaleString();
    valDropRate.textContent = `Drop Rate: ${results.dropRate}`;

    // App Chart
    if (results.apps && results.apps.length > 0) {
      const labels = results.apps.map(a => a.name);
      const data = results.apps.map(a => a.count);
      appChartInstance.data.labels = labels;
      appChartInstance.data.datasets[0].data = data;
      appChartInstance.update();
    }

    // Thread Chart
    if (results.threadStats && results.threadStats.length > 0) {
      const labels = results.threadStats.map(t => t.thread);
      const data = results.threadStats.map(t => t.packets);
      threadChartInstance.data.labels = labels;
      threadChartInstance.data.datasets[0].data = data;
      threadChartInstance.update();
    }

    // Blocked logs
    if (results.blockedEvents && results.blockedEvents.length > 0) {
      results.blockedEvents.forEach(evt => logConsole(evt, 'warn'));
    }

    // Flow Table
    currentFlows = results.flows || [];
    renderFlowTable(currentFlows);
  }

  // Helper byte format
  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // 11. Render Flow Table
  function renderFlowTable(flows) {
    flowTableBody.innerHTML = '';

    if (!flows || flows.length === 0) {
      flowTableBody.innerHTML = '<tr><td colspan="7" class="empty-state">No flows matching filter query.</td></tr>';
      return;
    }

    flows.forEach((f, idx) => {
      const tr = document.createElement('tr');
      
      let isBlocked = false;
      if (currentRules.ips.some(ip => f.src.includes(ip))) isBlocked = true;
      if (currentRules.ports.some(p => f.dst.endsWith(':' + p))) isBlocked = true;

      const actionBadge = isBlocked 
        ? '<span class="action-badge badge-drop">DROPPED</span>'
        : '<span class="action-badge badge-fwd">FORWARDED</span>';

      tr.innerHTML = `
        <td>${idx + 1}</td>
        <td>${f.time || 'N/A'}</td>
        <td style="color: var(--teal-bright);">${f.src}</td>
        <td style="color: var(--lime-light);">${f.dst}</td>
        <td><span class="pill-tag teal-tag">${f.protocol}</span></td>
        <td>${f.payloadLen} B</td>
        <td>${actionBadge}</td>
      `;
      flowTableBody.appendChild(tr);
    });
  }

  // Search filter flow table
  flowSearchInput.addEventListener('input', (e) => {
    const term = e.target.value.toLowerCase();
    const filtered = currentFlows.filter(f => 
      f.src.toLowerCase().includes(term) ||
      f.dst.toLowerCase().includes(term) ||
      f.protocol.toLowerCase().includes(term)
    );
    renderFlowTable(filtered);
  });

  // Initial Load
  fetchStatus();
  fetchRules();
});
