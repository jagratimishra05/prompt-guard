import { useEffect, useState } from "react";
import { getHealth, protectedGenerate, scanText } from "./api";

const detectorLabels = {
  rules: "Rules",
  ml: "ML",
  contextual: "Contextual",
};

function mockDetectorReason(detectors) {
  return Object.values(detectors || {}).some((result) =>
    /mock|temporary/i.test(result?.reason || ""),
  );
}

function DecisionBadge({ decision }) {
  return (
    <span className={`decision decision-${String(decision).toLowerCase()}`}>
      {decision}
    </span>
  );
}

function DetectorResult({ name, result }) {
  return (
    <article className="detector-card">
      <h3>{detectorLabels[name] || name}</h3>
      <dl>
        <div>
          <dt>Status</dt>
          <dd>{result?.status || "unknown"}</dd>
        </div>
        <div>
          <dt>Prediction</dt>
          <dd>{result?.prediction || "none"}</dd>
        </div>
        {name === "rules" && (
          <div>
            <dt>Evidence</dt>
            <dd>{result?.evidence?.length ? result.evidence.join(", ") : "none"}</dd>
          </div>
        )}
        {name === "ml" && (
          <div>
            <dt>Malicious probability</dt>
            <dd>
              {result?.malicious_probability == null
                ? "unavailable"
                : result.malicious_probability.toFixed(2)}
            </dd>
          </div>
        )}
        {result?.reason && (
          <div>
            <dt>Reason</dt>
            <dd>{result.reason}</dd>
          </div>
        )}
      </dl>
    </article>
  );
}

function Assessment({ assessment }) {
  if (!assessment) return null;
  const isMock = mockDetectorReason(assessment.detectors);

  return (
    <section className="panel result-panel" aria-live="polite">
      <div className="result-heading">
        <h2>Security assessment</h2>
        <DecisionBadge decision={assessment.decision} />
      </div>
      {isMock && (
        <p className="warning" role="note">
          Temporary mock assessment. This result is not from a real detector.
        </p>
      )}
      <div className="metric">
        <span>Risk score</span>
        <strong>{assessment.risk_score}/100</strong>
      </div>
      <p>{assessment.reason}</p>
      <div className="detector-grid">
        {Object.entries(assessment.detectors || {}).map(([name, result]) => (
          <DetectorResult key={name} name={name} result={result} />
        ))}
      </div>
    </section>
  );
}

function App() {
  const [health, setHealth] = useState(null);
  const [text, setText] = useState("");
  const [task, setTask] = useState("");
  const [assessment, setAssessment] = useState(null);
  const [generated, setGenerated] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState("");

  const refreshHealth = async () => {
    try {
      setHealth(await getHealth());
    } catch {
      setHealth(null);
    }
  };

  useEffect(() => {
    refreshHealth();
  }, []);

  const runScan = async (event) => {
    event.preventDefault();
    setError("");
    if (!text.trim()) {
      setError("Enter text to scan.");
      return;
    }
    if (text.length > 10000) {
      setError("Text must be 10,000 characters or fewer.");
      return;
    }
    setLoading("scan");
    setAssessment(null);
    setGenerated(null);
    try {
      setAssessment(await scanText(text));
    } catch (scanError) {
      setError(scanError.message);
    } finally {
      setLoading("");
    }
  };

  const runProtectedGeneration = async (event) => {
    event.preventDefault();
    setError("");
    setGenerated(null);
    if (!text.trim() || !task.trim()) {
      setError("Enter both text and a generation task.");
      return;
    }
    if (text.length > 10000 || task.length > 2000) {
      setError("Check the text and task length limits.");
      return;
    }
    setLoading("generate");
    try {
      const result = await protectedGenerate(text, task);
      setAssessment(result);
      if (result.decision === "ALLOW" && result.generated_response) {
        setGenerated(result.generated_response);
      }
    } catch (generateError) {
      setError(generateError.message);
    } finally {
      setLoading("");
    }
  };

  return (
    <main>
      <header className="topbar">
        <div>
          <p className="eyebrow">Security prototype</p>
          <h1>PromptGuard Dashboard</h1>
        </div>
        <button className="health-button" type="button" onClick={refreshHealth}>
          <span className={`health-dot ${health ? "online" : "offline"}`} />
          {health ? "Backend online" : "Backend unavailable"}
        </button>
      </header>

      <div className="workspace">
        <section className="panel input-panel">
          <h2>Untrusted content</h2>
          <form onSubmit={runProtectedGeneration}>
            <label htmlFor="text">Text</label>
            <textarea
              id="text"
              value={text}
              maxLength={10000}
              onChange={(event) => setText(event.target.value)}
              placeholder="Paste webpage, document, email, or tool output..."
            />
            <div className="character-count">{text.length}/10,000</div>

            <label htmlFor="task">Protected-generation task</label>
            <input
              id="task"
              value={task}
              maxLength={2000}
              onChange={(event) => setTask(event.target.value)}
              placeholder="Summarize this content"
            />
            <div className="character-count">{task.length}/2,000</div>

            {error && <p className="error" role="alert">{error}</p>}
            <div className="actions">
              <button type="button" onClick={runScan} disabled={Boolean(loading)}>
                {loading === "scan" ? "Scanning..." : "Scan content"}
              </button>
              <button className="primary" type="submit" disabled={Boolean(loading)}>
                {loading === "generate" ? "Generating..." : "Protected generate"}
              </button>
            </div>
          </form>
        </section>

        <Assessment assessment={assessment} />

        {generated && (
          <section className="panel generated-panel">
            <h2>Target provider response</h2>
            {generated.is_mock || generated.is_synthetic ? (
              <p className="warning" role="note">
                Synthetic mock output. No real target LLM response was generated.
              </p>
            ) : null}
            <p>{generated.text}</p>
          </section>
        )}
      </div>
    </main>
  );
}

export default App;
