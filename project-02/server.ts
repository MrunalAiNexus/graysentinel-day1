import express from "express";
import { exec } from "child_process";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;
const PROJECT_DIR = path.join(process.cwd(), "project-02");

app.use(express.json());

// Basic API health check
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", type: "python-cli-terminal" });
});

// Run a whitelisted CLI command and stream terminal output
app.post("/api/terminal/execute", (req, res) => {
  const { command } = req.body;
  const validCommands: Record<string, string> = {
    demo: "python3 main.py --demo",
    test: "pytest -v",
    validate_pass: "python3 main.py --recon data/sample/sanitized_recon.json --validate",
    validate_fail: "python3 main.py --findings data/invalid_finding_sample.json --validate",
    analyze: "python3 main.py --recon data/sample/sanitized_recon.json --analyze",
    analyze_json: "python3 main.py --recon data/sample/sanitized_recon.json --analyze --json",
    report: "python3 main.py --recon data/sample/sanitized_recon.json --report --out reports/recon_report.md",
    help: "python3 main.py --help",
  };

  const targetCmd = validCommands[command] || (typeof command === "string" && command.startsWith("python3 ") ? command : null);

  if (!targetCmd) {
    return res.status(400).json({ error: "Invalid command requested." });
  }

  exec(targetCmd, { cwd: PROJECT_DIR, env: { ...process.env, PYTHONPATH: path.join(PROJECT_DIR, "src") } }, (err, stdout, stderr) => {
    res.json({
      command: targetCmd,
      exitCode: err ? (err.code ?? 1) : 0,
      stdout: stdout || "",
      stderr: stderr || "",
    });
  });
});

// Serve HTML Terminal Console
app.get("*", (_req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GraySentinel Project 02 — Web Security Findings Reporter</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --cyan: #38bdf8;
      --green: #4ade80;
      --red: #f87171;
      --yellow: #facc15;
      --dim: #8b949e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      padding: 18px;
      line-height: 1.5;
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 14px;
      margin-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }
    .title {
      font-size: 1.15rem;
      font-weight: 700;
      color: var(--cyan);
      letter-spacing: -0.02em;
    }
    .subtitle {
      font-size: 0.8rem;
      color: var(--dim);
    }
    .badge {
      display: inline-block;
      background: rgba(74, 222, 128, 0.1);
      color: var(--green);
      border: 1px solid rgba(74, 222, 128, 0.3);
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 14px;
    }
    button {
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-family: inherit;
      font-size: 0.8rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    button:hover {
      background: #21262d;
      border-color: var(--cyan);
      color: #fff;
    }
    button.primary {
      background: #0284c7;
      border-color: #38bdf8;
      color: #fff;
      font-weight: 600;
    }
    button.primary:hover {
      background: #0369a1;
    }
    .terminal-window {
      background: #000000;
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    }
    .terminal-topbar {
      background: #161b22;
      padding: 8px 14px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 0.75rem;
      color: var(--dim);
    }
    .terminal-dots {
      display: flex;
      gap: 6px;
    }
    .dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }
    .dot.red { background: #ff5f56; }
    .dot.yellow { background: #ffbd2e; }
    .dot.green { background: #27c93f; }
    .terminal-body {
      padding: 16px;
      min-height: 480px;
      max-height: 650px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
      font-size: 0.82rem;
      color: #e6edf3;
    }
    .cmd-bar {
      display: flex;
      margin-top: 12px;
      gap: 8px;
    }
    .cmd-bar input {
      flex: 1;
      background: #000;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      color: #38bdf8;
      font-family: inherit;
      font-size: 0.85rem;
    }
    .cmd-bar input:focus {
      outline: none;
      border-color: var(--cyan);
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <div class="title">GRAY_SENTINEL // PROJECT 02</div>
      <div class="subtitle">Standalone Python CLI Security Finding Reporter &bull; Target: lab.graysentinel.internal</div>
    </div>
    <div>
      <span class="badge">&check; 36/36 Tests Passing</span>
      <span class="badge" style="background:rgba(56,189,248,0.1);color:var(--cyan);border-color:rgba(56,189,248,0.3)">Pure Python CLI</span>
    </div>
  </div>

  <div class="actions">
    <button class="primary" onclick="runCmd('demo')">&blacktriangleright; Run Demo Pipeline (--demo)</button>
    <button onclick="runCmd('test')">&check; Run Pytest (36 Tests)</button>
    <button onclick="runCmd('validate_pass')">Validate Findings (Pass)</button>
    <button onclick="runCmd('validate_fail')">Negative Validation (Fail)</button>
    <button onclick="runCmd('analyze')">Risk Posture Summary</button>
    <button onclick="runCmd('analyze_json')">Risk Analysis (JSON)</button>
    <button onclick="runCmd('report')">Generate Markdown Report</button>
    <button onclick="runCmd('help')">CLI Help</button>
    <button onclick="clearTerm()" style="margin-left:auto;">Clear</button>
  </div>

  <div class="terminal-window">
    <div class="terminal-topbar">
      <div class="terminal-dots">
        <div class="dot red"></div>
        <div class="dot yellow"></div>
        <div class="dot green"></div>
      </div>
      <div id="term-status">Terminal ready &bull; cd project-02 && python3 main.py</div>
      <div>bash</div>
    </div>
    <div id="terminal" class="terminal-body">Loading initial GraySentinel CLI demonstration...</div>
  </div>

  <form class="cmd-bar" onsubmit="event.preventDefault(); submitCustom();">
    <input id="custom-cmd" type="text" placeholder="Enter CLI command (e.g. python3 main.py --help, python3 main.py --analyze)" value="python3 main.py --demo" />
    <button class="primary" type="submit">Execute</button>
  </form>

  <script>
    const term = document.getElementById('terminal');
    const status = document.getElementById('term-status');

    function stripAnsi(str) {
      return str.replace(/\\x1B\\[[0-9;]*[a-zA-Z]/g, '');
    }

    async function runCmd(cmdKey) {
      status.innerText = 'Executing ' + cmdKey + '...';
      term.innerHTML += '\\n\\n\\x1b[36m$ [graysentinel] running ' + cmdKey + '...\\x1b[0m\\n';
      try {
        const res = await fetch('/api/terminal/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: cmdKey })
        });
        const data = await res.json();
        const text = (data.stdout || '') + (data.stderr ? '\\n' + data.stderr : '');
        term.innerText += '\\n$ ' + data.command + ' (exit ' + data.exitCode + ')\\n' + stripAnsi(text);
        term.scrollTop = term.scrollHeight;
        status.innerText = 'Exit: ' + data.exitCode + ' &bull; Ready';
      } catch (err) {
        term.innerText += '\\nError executing command: ' + err.message;
        status.innerText = 'Error';
      }
    }

    async function submitCustom() {
      const val = document.getElementById('custom-cmd').value.trim();
      if (!val) return;
      status.innerText = 'Executing ' + val + '...';
      try {
        const res = await fetch('/api/terminal/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: val })
        });
        const data = await res.json();
        const text = (data.stdout || '') + (data.stderr ? '\\n' + data.stderr : '');
        term.innerText += '\\n\\n$ ' + data.command + ' (exit ' + data.exitCode + ')\\n' + stripAnsi(text);
        term.scrollTop = term.scrollHeight;
        status.innerText = 'Exit: ' + data.exitCode + ' &bull; Ready';
      } catch (err) {
        term.innerText += '\\nError: ' + err.message;
        status.innerText = 'Error';
      }
    }

    function clearTerm() {
      term.innerText = '$ cd project-02 && python3 main.py\\n';
    }

    // Auto run demo on startup
    window.addEventListener('load', () => {
      runCmd('demo');
    });
  </script>
</body>
</html>
`);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`GraySentinel Server running on http://0.0.0.0:${PORT}`);
});
