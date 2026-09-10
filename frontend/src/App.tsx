import { type ChangeEvent, useState } from "react";

type Finding = {
  rule_id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  line: number;
  code: string;
  explanation: string;
  recommendation: string;
  source_tool: string;
  source_tools: string[];
};

type AnalysisResult = {
  filename: string;
  language: Language;
  pipeline: `${Language}-security`;
  finding_count: number;
  findings: Finding[];
  tool_runs: ToolRun[];
};

type ToolRun = {
  tool: string;
  status: "completed" | "unavailable" | "skipped" | "error";
  finding_count: number;
  message: string;
};

type SeverityFilter = "all" | Finding["severity"];
type Language = "solidity" | "vyper" | "rust" | "move";

const sampleContract = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
  mapping(address => uint256) public balances;

  function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
  }

  function adminAction() external {
    require(tx.origin == msg.sender);
  }
}`;

function App() {
  const [source, setSource] = useState("");
  const [filename, setFilename] = useState("Contract.sol");
  const [language, setLanguage] = useState<Language>("solidity");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");

  async function loadContractFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    const extension = file.name.split(".").pop()?.toLowerCase();
    if (extension === "vy" || extension === "vyper") setLanguage("vyper");
    if (extension === "rs") setLanguage("rust");
    if (extension === "move") setLanguage("move");
    if (extension === "sol") setLanguage("solidity");
    setSource(await file.text());
    setResult(null);
    setError("");
  }

  async function analyzeContract() {
    setLoading(true);
    setResult(null);
    setError("");
    try {
      const response = await fetch("http://127.0.0.1:8000/api/v1/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          filename,
          language,
          source,
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : JSON.stringify(data.detail ?? data),
        );
      }
      setResult(data);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unknown analysis error",
      );
    } finally {
      setLoading(false);
    }
  }

  function loadSample() {
    setFilename("VulnerableVault.sol");
    setLanguage("solidity");
    setSource(sampleContract);
    setResult(null);
    setError("");
  }

  const visibleFindings = result?.findings.filter((finding) =>
    severityFilter === "all" || finding.severity === severityFilter,
  ) ?? [];

  return (
    <main>
      <header className="app-header">
        <div>
          <p className="brand-kicker">SecureXAI / audit workspace</p>
          <h1>Contract security, made legible.</h1>
          <p className="header-copy">
            Run independent analyzers, compare their evidence, and triage risk before deployment.
          </p>
        </div>
        <div className="header-meta">
          <span className="live-dot" />
          Local analysis
        </div>
      </header>

      <section className="editor-panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Source</p>
            <h2>Inspect a contract</h2>
          </div>
          <button className="ghost-button" onClick={loadSample} type="button">
            Load vulnerable sample
          </button>
        </div>

        <div className="editor-toolbar">
          <span className="filename">{filename}</span>
          <div className="language-row">
            <label htmlFor="language">Language</label>
            <select
              id="language"
              value={language}
              onChange={(event) => setLanguage(event.target.value as Language)}
            >
              <option value="solidity">Solidity</option>
              <option value="vyper">Vyper</option>
              <option value="rust">Rust</option>
              <option value="move">Move</option>
            </select>
          </div>
        </div>

        <textarea
          value={source}
          onChange={(event) => setSource(event.target.value)}
          placeholder="Paste source code or load a file to begin analysis"
          rows={18}
        />

        <div className="input-actions">
          <label className="file-picker">
            <span>Choose source file</span>
            <input type="file" accept=".sol,.vy,.vyper,.rs,.move,text/plain" onChange={loadContractFile} />
          </label>
          <button
            className="analyze-button"
            onClick={analyzeContract}
            disabled={loading || !source.trim()}
            type="button"
          >
            {loading ? "Analyzing..." : "Analyze contract"}
          </button>
        </div>
      </section>

      {error && <p className="error-banner">{error}</p>}

      {result && (
        <section className="results-section">
          <div className="results-heading">
            <div>
              <p className="eyebrow">Analysis complete</p>
              <h2>{result.filename}</h2>
              <p className="pipeline-label">Pipeline: {result.pipeline}</p>
            </div>
            <label>
              Filter severity
              <select
                value={severityFilter}
                onChange={(event) =>
                  setSeverityFilter(event.target.value as SeverityFilter)
                }
              >
                <option value="all">All findings</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
          </div>

          <div className="summary-grid">
            {(["critical", "high", "medium", "low"] as const).map((severity) => (
              <div className={`summary-tile severity-${severity}`} key={severity}>
                <span>{severity}</span>
                <strong>
                  {result.findings.filter((finding) => finding.severity === severity).length}
                </strong>
              </div>
            ))}
          </div>

          <div className="tool-status">
            {result.tool_runs.map((toolRun) => (
              <span className={`tool-chip tool-${toolRun.status}`} key={toolRun.tool}>
                {toolRun.tool} <b>{toolRun.status}</b> · {toolRun.finding_count}
              </span>
            ))}
          </div>

          <p className="result-count">
            Showing {visibleFindings.length} of {result.finding_count} findings
          </p>

          <div className="findings-list">
          {visibleFindings.map((finding) => (
            <article key={`${finding.rule_id}-${finding.line}`}>
              <div className="finding-header">
                <h3>{finding.title}</h3>
                <span className={`severity-badge severity-${finding.severity}`}>
                  {finding.severity}
                </span>
              </div>

              <p>
                Line {finding.line} | Confidence {Math.round(finding.confidence * 100)}%
              </p>

              <p>Detected by: {finding.source_tools.join(", ")}</p>

              <code>{finding.code}</code>

              <p>{finding.explanation}</p>

              <strong>Recommendation:</strong>
              <p>{finding.recommendation}</p>
            </article>
          ))}
          {!visibleFindings.length && (
            <div className="empty-results">
              <strong>No findings in this view.</strong>
              <span>Try another severity filter or analyze a different source file.</span>
            </div>
          )}
          </div>
        </section>
      )}
    </main>
  );
}

export default App;