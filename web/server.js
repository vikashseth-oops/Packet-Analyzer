const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { exec, spawn } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure multer for PCAP file uploads
const uploadsDir = path.join(__dirname, 'uploads');
const outputsDir = path.join(__dirname, 'outputs');

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(outputsDir)) fs.mkdirSync(outputsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'input-' + uniqueSuffix + '.pcap');
  }
});
const upload = multer({ storage });

// In-memory rules state
let activeRules = {
  ips: ['192.168.1.50'],
  apps: ['YouTube'],
  domains: ['*.tiktok.com'],
  ports: []
};

// Root endpoint
app.get('/api/status', (req, me) => {
  const enginePath = path.join(__dirname, '..', 'dpi_engine.exe');
  const engineExists = fs.existsSync(enginePath);
  me.json({
    status: 'online',
    engineAvailable: engineExists,
    activeRulesCount: activeRules.ips.length + activeRules.apps.length + activeRules.domains.length + activeRules.ports.length,
    defaultSampleAvailable: fs.existsSync(path.join(__dirname, '..', 'test_dpi.pcap'))
  });
});

// GET active rules
app.get('/api/rules', (req, res) => {
  res.json(activeRules);
});

// POST add block rule
app.post('/api/rules', (req, res) => {
  const { type, value } = req.body;
  if (!type || !value) {
    return res.status(400).json({ error: 'Missing type or value' });
  }

  const cleanValue = value.trim();
  if (type === 'ip' && !activeRules.ips.includes(cleanValue)) {
    activeRules.ips.push(cleanValue);
  } else if (type === 'app' && !activeRules.apps.includes(cleanValue)) {
    activeRules.apps.push(cleanValue);
  } else if (type === 'domain' && !activeRules.domains.includes(cleanValue)) {
    activeRules.domains.push(cleanValue);
  } else if (type === 'port') {
    const portNum = parseInt(cleanValue, 10);
    if (!isNaN(portNum) && !activeRules.ports.includes(portNum)) {
      activeRules.ports.push(portNum);
    }
  }

  res.json({ success: true, activeRules });
});

// DELETE remove block rule
app.delete('/api/rules', (req, res) => {
  const { type, value } = req.body;
  if (!type || !value) {
    return res.status(400).json({ error: 'Missing type or value' });
  }

  const cleanValue = value.toString().trim();
  if (type === 'ip') {
    activeRules.ips = activeRules.ips.filter(v => v !== cleanValue);
  } else if (type === 'app') {
    activeRules.apps = activeRules.apps.filter(v => v !== cleanValue);
  } else if (type === 'domain') {
    activeRules.domains = activeRules.domains.filter(v => v !== cleanValue);
  } else if (type === 'port') {
    activeRules.ports = activeRules.ports.filter(v => v.toString() !== cleanValue);
  }

  res.json({ success: true, activeRules });
});

// Helper to build rule arguments for dpi_engine.exe
function buildEngineArgs() {
  const args = [];
  activeRules.ips.forEach(ip => {
    args.push('--block-ip', ip);
  });
  activeRules.apps.forEach(app => {
    args.push('--block-app', app);
  });
  activeRules.domains.forEach(dom => {
    args.push('--block-domain', dom);
  });
  return args;
}

// POST analyze PCAP (either uploaded file or default test_dpi.pcap)
app.post('/api/analyze', upload.single('pcapFile'), async (req, res) => {
  try {
    const projectRoot = path.join(__dirname, '..');
    const dpiEngineExe = path.join(projectRoot, 'dpi_engine.exe');
    const packetAnalyzerExe = path.join(projectRoot, 'packet_analyzer.exe');

    if (!fs.existsSync(dpiEngineExe)) {
      return res.status(500).json({ error: 'dpi_engine.exe executable not found. Please compile the C++ project first.' });
    }

    let inputPath;
    let isUpload = false;

    if (req.file) {
      inputPath = req.file.path;
      isUpload = true;
    } else {
      inputPath = path.join(projectRoot, 'test_dpi.pcap');
      if (!fs.existsSync(inputPath)) {
        return res.status(404).json({ error: 'Default test_dpi.pcap file not found' });
      }
    }

    const outputFilename = `filtered-${Date.now()}.pcap`;
    const outputPath = path.join(outputsDir, outputFilename);

    const ruleArgs = buildEngineArgs();
    const cmdArgs = [inputPath, outputPath, ...ruleArgs];

    console.log(`[Server] Executing: ${dpiEngineExe} ${cmdArgs.join(' ')}`);

    exec(`"${dpiEngineExe}" "${inputPath}" "${outputPath}" ${ruleArgs.map(a => `"${a}"`).join(' ')}`, { cwd: projectRoot }, (error, stdout, stderr) => {
      if (error) {
        console.error(`[Server] DPI Engine error:`, stderr || error.message);
        return res.status(500).json({ error: 'Failed to run DPI engine', details: stderr || error.message });
      }

      // Parse output metrics from dpi_engine.exe stdout
      const parsedResults = parseDPIOutput(stdout);
      parsedResults.downloadUrl = `/api/download/${outputFilename}`;
      parsedResults.inputFileName = isUpload ? req.file.originalname : 'test_dpi.pcap';

      // Optionally run packet_analyzer.exe to extract individual flow details
      exec(`"${packetAnalyzerExe}" "${inputPath}"`, { cwd: projectRoot }, (paErr, paStdout) => {
        let flows = [];
        if (!paErr && paStdout) {
          flows = parsePacketAnalyzerOutput(paStdout);
        }
        parsedResults.flows = flows;
        parsedResults.rawOutput = stdout;

        res.json({ success: true, results: parsedResults });
      });
    });

  } catch (err) {
    console.error(`[Server] Exception during analysis:`, err);
    res.status(500).json({ error: 'Internal server error during analysis', details: err.message });
  }
});

// GET download output PCAP
app.get('/api/download/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(outputsDir, filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Requested output PCAP file not found' });
  }

  res.download(filePath, filename);
});

// Helper parser function to parse stdout report from dpi_engine.exe
function parseDPIOutput(stdout) {
  const results = {
    totalPackets: 0,
    totalBytes: 0,
    tcpPackets: 0,
    udpPackets: 0,
    forwarded: 0,
    dropped: 0,
    dropRate: '0%',
    lbReceived: 0,
    lbDispatched: 0,
    fpProcessed: 0,
    activeConnections: 0,
    threadStats: [],
    apps: [],
    blockedEvents: []
  };

  const lines = stdout.split('\n');

  lines.forEach(line => {
    if (line.includes('Total Packets:')) {
      const match = line.match(/\:\s*(\d+)/);
      if (match) results.totalPackets = parseInt(match[1], 10);
    } else if (line.includes('Total Bytes:')) {
      const match = line.match(/\:\s*(\d+)/);
      if (match) results.totalBytes = parseInt(match[1], 10);
    } else if (line.includes('TCP Packets:')) {
      const match = line.match(/\:\s*(\d+)/);
      if (match) results.tcpPackets = parseInt(match[1], 10);
    } else if (line.includes('UDP Packets:')) {
      const match = line.match(/\:\s*(\d+)/);
      if (match) results.udpPackets = parseInt(match[1], 10);
    } else if (line.includes('Forwarded:')) {
      const match = line.match(/\:\s*(\d+)/);
      if (match && results.forwarded === 0) results.forwarded = parseInt(match[1], 10);
    } else if (line.includes('Dropped/Blocked:') || line.includes('Dropped:')) {
      const match = line.match(/\:\s*(\d+)/);
      if (match && results.dropped === 0) results.dropped = parseInt(match[1], 10);
    } else if (line.includes('Drop Rate:')) {
      const match = line.match(/\:\s*([\d\.\%]+)/);
      if (match) results.dropRate = match[1];
    } else if (line.includes('Active Connections:')) {
      const match = line.match(/\:\s*(\d+)/);
      if (match) results.activeConnections = parseInt(match[1], 10);
    } else if (line.includes('[FP') && line.includes('Stopped (processed')) {
      const match = line.match(/\[FP(\d+)\]\s+Stopped\s+\(processed\s+(\d+)\s+packets\)/);
      if (match) {
        results.threadStats.push({
          thread: `FP${match[1]}`,
          packets: parseInt(match[2], 10)
        });
      }
    } else if (line.includes('[FP') && line.includes('BLOCKED packet:')) {
      results.blockedEvents.push(line.trim());
    }
  });

  // Parse application breakdown table
  let inAppSection = false;
  lines.forEach(line => {
    if (line.includes('APPLICATION BREAKDOWN') || line.includes('APPLICATION DISTRIBUTION')) {
      inAppSection = true;
      return;
    }
    if (inAppSection && line.includes('╚════')) {
      inAppSection = false;
      return;
    }
    if (inAppSection && line.includes('║')) {
      // Line format: ║ Unknown              21  48.8% #########              ║
      const parts = line.replace(/║/g, '').trim().split(/\s+/);
      if (parts.length >= 3) {
        const name = parts[0];
        const count = parseInt(parts[1], 10);
        const pct = parts[2];
        if (!isNaN(count) && name !== 'APPLICATION' && name !== 'BREAKDOWN') {
          results.apps.push({ name, count, pct });
        }
      }
    }
  });

  return results;
}

// Helper parser to parse packet_analyzer output into structured flow items
function parsePacketAnalyzerOutput(paStdout) {
  const flows = [];
  const blocks = paStdout.split('========== Packet #');

  blocks.forEach((block, idx) => {
    if (idx === 0) return;

    const lines = block.split('\n');
    const flow = { id: idx, time: '', src: '', dst: '', protocol: 'IPv4', payloadLen: 0, sni: '' };

    lines.forEach(l => {
      if (l.startsWith('Time:')) flow.time = l.replace('Time:', '').trim();
      else if (l.includes('Source IP:')) flow.src = l.replace('Source IP:', '').trim();
      else if (l.includes('Destination IP:')) flow.dst = l.replace('Destination IP:', '').trim();
      else if (l.includes('Source Port:')) flow.srcPort = l.replace('Source Port:', '').trim();
      else if (l.includes('Destination Port:')) flow.dstPort = l.replace('Destination Port:', '').trim();
      else if (l.includes('Protocol:')) flow.protocol = l.replace('Protocol:', '').trim();
      else if (l.includes('Length:') && l.includes('bytes')) {
        const m = l.match(/Length:\s*(\d+)/);
        if (m) flow.payloadLen = parseInt(m[1], 10);
      }
    });

    if (flow.srcPort) flow.src += `:${flow.srcPort}`;
    if (flow.dstPort) flow.dst += `:${flow.dstPort}`;

    if (flow.src || flow.dst) {
      flows.push(flow);
    }
  });

  return flows.slice(0, 100); // return top 100 flows for visual presentation
}

app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════════════════════════╗`);
  console.log(`║     Packet Analyzer Web Dashboard is running!                ║`);
  console.log(`║     URL: http://localhost:${PORT}                              ║`);
  console.log(`╚══════════════════════════════════════════════════════════════╝\n`);
});
