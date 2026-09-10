import { useState } from "react";

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
};

type AnalysisResult = {
  filename: string;
  finding_count: number;
  findings: Finding[];
  tool_runs: ToolRun[];
};

type ToolRun = {
  tool: string;
  status: "completed" | "unavailable" | "error";
  finding_count: number;
  message: string;
};

function App() {
  const [source, setSource] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

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
          filename: "Contract.sol",
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
          <h2>
            Findings: {result.finding_count}
          </h2>

          <p>
            {result.tool_runs.map((toolRun) =>
              `${toolRun.tool}: ${toolRun.status} (${toolRun.finding_count})`,
            ).join(" | ")}
          </p>

          {result.findings.map((finding) => (
            <article key={`${finding.rule_id}-${finding.line}`}>
              <h3>{finding.title}</h3>

              <p>
                Severity: {finding.severity} | Line: {finding.line}
              </p>

              <code>{finding.code}</code>

              <p>{finding.explanation}</p>

              <strong>Recommendation:</strong>
              <p>{finding.recommendation}</p>
            </article>
          ))}
        </section>
      )}
    </main>
  );
}

export default App;