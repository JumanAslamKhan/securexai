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

  return (
    <main>
      <h1>SecureXAI Contract Analyzer</h1>

      <textarea
        value={source}
        onChange={(event) => setSource(event.target.value)}
        placeholder="Paste Solidity code here"
        rows={16}
        cols={80}
      />

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

      <div className="input-actions">
        <label className="file-picker">
          <span>Choose Solidity file</span>
          <input type="file" accept=".sol,text/plain" onChange={loadContractFile} />
        </label>
        <span className="filename">{filename}</span>
      </div>

      <br />

      <button
        onClick={analyzeContract}
        disabled={loading || !source.trim()}
      >
        {loading ? "Analyzing..." : "Analyze Contract"}
      </button>

      {error && <p>{error}</p>}

      {result && (
        <section>
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

          <p className="tool-status">
            {result.tool_runs.map((toolRun) =>
              `${toolRun.tool}: ${toolRun.status} (${toolRun.finding_count})`,
            ).join(" | ")}
          </p>

          <p className="result-count">
            Showing {result.findings.filter((finding) =>
              severityFilter === "all" || finding.severity === severityFilter,
            ).length} of {result.finding_count} findings
          </p>

          <div className="findings-list">
          {result.findings
            .filter((finding) =>
              severityFilter === "all" || finding.severity === severityFilter,
            )
            .map((finding) => (
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
          </div>
        </section>
      )}
    </main>
  );
}

export default App;