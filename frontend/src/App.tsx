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

type Remediation = {
  provider: string;
  summary: string;
  patch_guidance: string;
  patch?: string;
  validation_steps: string[];
  auto_apply: boolean;
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
  const [remediations, setRemediations] = useState<Record<string, Remediation>>({});
  const [remediationLoading, setRemediationLoading] = useState("");

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

  async function getRemediation(finding: Finding) {
    const key = `${finding.rule_id}-${finding.line}`;
    setRemediationLoading(key);
    try {
      const response = await fetch("http://127.0.0.1:8000/api/v1/remediate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...finding, source }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Remediation failed");
      setRemediations((current) => ({ ...current, [key]: data }));
    } catch (error) {
      setError(error instanceof Error ? error.message : "Remediation failed");
    } finally {
      setRemediationLoading("");
    }
  }

  function loadSample() {
    setFilename("VulnerableVault.sol");
    setLanguage("solidity");
    setSource(sampleContract);
    setResult(null);
    setError("");
  }

  function downloadReport(format: "json" | "html") {
    if (!result) return;
    const escapeHtml = (value: string) =>
      value.replace(/[&<>"']/g, (character) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character] ?? character);
    const report = format === "json"
      ? JSON.stringify(result, null, 2)
      : `<!doctype html>
<html><head><meta charset="utf-8"><title>SecureXAI report - ${escapeHtml(result.filename)}</title>
<style>body{font:16px Arial,sans-serif;max-width:900px;margin:40px auto;color:#17202b}article{border:1px solid #dce3e1;border-radius:8px;padding:18px;margin:14px 0}pre{background:#eef3f1;padding:12px;overflow:auto}.critical{color:#c94b45}.high{color:#b56f1d}</style>
</head><body><h1>SecureXAI analysis report</h1><p><b>File:</b> ${escapeHtml(result.filename)} | <b>Pipeline:</b> ${escapeHtml(result.pipeline)}</p>
<h2>Findings: ${result.finding_count}</h2>${result.findings.map((finding) => `<article><h3 class="${finding.severity}">${escapeHtml(finding.title)}</h3><p><b>Severity:</b> ${finding.severity} | <b>Line:</b> ${finding.line} | <b>Confidence:</b> ${Math.round(finding.confidence * 100)}%</p><p><b>Detected by:</b> ${escapeHtml(finding.source_tools.join(", "))}</p><pre>${escapeHtml(finding.code)}</pre><p>${escapeHtml(finding.explanation)}</p><p><b>Recommendation:</b> ${escapeHtml(finding.recommendation)}</p></article>`).join("")}</body></html>`;
    const blob = new Blob([report], { type: format === "json" ? "application/json" : "text/html" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${result.filename.replace(/\.[^.]+$/, "")}-securexai.${format}`;
    link.click();
    URL.revokeObjectURL(link.href);
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
            <div className="results-actions">
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
              <div className="export-actions">
                <button type="button" className="ghost-button" onClick={() => downloadReport("json")}>JSON</button>
                <button type="button" className="ghost-button" onClick={() => downloadReport("html")}>HTML</button>
              </div>
            </div>
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

          <div className="benchmark-panel">
            <div>
              <p className="eyebrow">Benchmark snapshot</p>
              <h3>Analyzer comparison</h3>
            </div>
            <div className="benchmark-grid">
              {result.tool_runs.map((toolRun) => {
                const normalizedCount = result.findings.filter((finding) =>
                  finding.source_tools.includes(toolRun.tool),
                ).length;
                return (
                  <div className="benchmark-item" key={toolRun.tool}>
                    <span>{toolRun.tool}</span>
                    <strong>{normalizedCount}</strong>
                    <small>{toolRun.finding_count} raw · {toolRun.status}</small>
                  </div>
                );
              })}
              <div className="benchmark-item">
                <span>Cross-tool overlap</span>
                <strong>{result.findings.filter((finding) => finding.source_tools.length > 1).length}</strong>
                <small>normalized findings</small>
              </div>
            </div>
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

              <button
                type="button"
                className="remediation-button"
                onClick={() => getRemediation(finding)}
                disabled={remediationLoading === `${finding.rule_id}-${finding.line}`}
              >
                {remediationLoading === `${finding.rule_id}-${finding.line}`
                  ? "Preparing guidance..."
                  : "Prepare remediation guidance"}
              </button>

              {remediations[`${finding.rule_id}-${finding.line}`] && (
                <div className="remediation-panel">
                  <p className="eyebrow">{remediations[`${finding.rule_id}-${finding.line}`].provider}</p>
                  <strong>{remediations[`${finding.rule_id}-${finding.line}`].summary}</strong>
                  <p>{remediations[`${finding.rule_id}-${finding.line}`].patch_guidance}</p>
                  {remediations[`${finding.rule_id}-${finding.line}`].patch && (
                    <pre className="patch-preview">{remediations[`${finding.rule_id}-${finding.line}`].patch}</pre>
                  )}
                  <ul>
                    {remediations[`${finding.rule_id}-${finding.line}`].validation_steps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}
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