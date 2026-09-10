import { useState } from "react";

function App() {
  const [source, setSource] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);

  async function analyzeContract() {
    setLoading(true);
    setResult("");

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
      setResult(JSON.stringify(data, null, 2));
    } catch (error) {
      setResult(
        error instanceof Error
          ? `Analysis failed: ${error.message}`
          : "Analysis failed: unknown error",
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

      <button onClick={analyzeContract} disabled={loading || !source.trim()}>
        {loading ? "Analyzing..." : "Analyze Contract"}
      </button>

      <pre>{result}</pre>
    </main>
  );
}

export default App;