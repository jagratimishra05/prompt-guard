import { useEffect, useMemo, useState } from "react";
import { getHealth, protectedGenerate, scanText } from "./api";

const navItems = [
  ["overview", "Overview", "grid"],
  ["scanner", "Security Scanner", "scan"],
  ["generate", "Protected Generation", "shield"],
  ["history", "Scan History", "clock"],
  ["analytics", "Analytics", "chart"],
  ["settings", "Settings", "settings"],
];

const iconPaths = {
  grid: "M3 3h7v7H3V3Zm11 0h7v7h-7V3ZM3 14h7v7H3v-7Zm11 0h7v7h-7v-7Z",
  scan: "M4 4h4M4 4v4m12-4h4v4M4 16v4h4m12-4v4h-4M7 12h10M12 7v10",
  shield: "M12 2l7 3v5c0 4.9-2.9 8.9-7 10-4.1-1.1-7-5.1-7-10V5l7-3Z",
  clock: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Zm0-16v6l4 2",
  chart: "M4 20V10m5 10V4m6 16v-7m5 7V7",
  settings: "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z",
  menu: "M4 6h16M4 12h16M4 18h16",
  logout: "M10 5H4v14h6M14 8l4 4-4 4m4-4H9",
  arrow: "M5 12h14m-5-5 5 5-5 5",
};

function Icon({ name, size = 20 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={iconPaths[name]} />
    </svg>
  );
}

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
  const labels = { rules: "Rules", ml: "ML model", contextual: "Contextual" };
  return (
    <article className="detector-card">
      <div className="detector-card-header">
        <h3>{labels[name] || name}</h3>
        <span className={`status status-${result?.status || "unknown"}`}>
          {result?.status || "unknown"}
        </span>
      </div>
      <dl>
        <div>
          <dt>Prediction</dt>
          <dd>{result?.prediction || "Unavailable"}</dd>
        </div>
        {name === "rules" && (
          <div>
            <dt>Evidence</dt>
            <dd>{result?.evidence?.length ? result.evidence.join(", ") : "None matched"}</dd>
          </div>
        )}
        {name === "ml" && (
          <div>
            <dt>Malicious probability</dt>
            <dd>
              {result?.malicious_probability == null
                ? "Unavailable"
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
        {result?.error && (
          <div>
            <dt>Error</dt>
            <dd>{result.error}</dd>
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
      <div className="card-heading">
        <h2>Security assessment</h2>
        <DecisionBadge decision={assessment.decision} />
      </div>
      {isMock && (
        <p className="warning" role="note">
          Temporary mock assessment. This result is not from a real detector.
        </p>
      )}
      <div className="risk-summary">
        <span>Risk score</span>
        <strong>{assessment.risk_score}/100</strong>
      </div>
      <div className="risk-track" aria-label={`Risk score ${assessment.risk_score} out of 100`}>
        <span style={{ width: `${assessment.risk_score}%` }} />
      </div>
      <p className="assessment-reason">{assessment.reason}</p>
      <div className="detector-grid">
        {Object.entries(assessment.detectors || {}).map(([name, result]) => (
          <DetectorResult key={name} name={name} result={result} />
        ))}
      </div>
    </section>
  );
}

const STORAGE_KEY = "promptguard-session-history";

function loadHistory() {
  try {
    return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

function PageHeader({ eyebrow, title, description, action }) {
  return (
    <div className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  );
}

function StatCard({ label, value, tone, detail }) {
  return (
    <article className="stat-card">
      <div className={`stat-marker ${tone}`} />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        {detail && <small>{detail}</small>}
      </div>
    </article>
  );
}

function Overview({ health, history, onNavigate }) {
  const counts = ["ALLOW", "REVIEW", "BLOCK"].reduce((result, decision) => {
    result[decision] = history.filter((item) => item.decision === decision).length;
    return result;
  }, {});
  const latest = history.length ? history[history.length - 1] : null;
  const detectorStatuses = Object.values(latest?.assessment?.detectors || {});
  const detectorIntegrationAvailable = Boolean(detectorStatuses.length);
  const detectorFailures = detectorStatuses.filter((result) => result.status === "failed").length;

  return (
    <>
      <PageHeader
        eyebrow="Security operations"
        title="Overview"
        description="A session view of PromptGuard security activity."
      />
      <div className="stat-grid">
        <StatCard label="Total scans" value={history.length} tone="blue" detail="This browser session" />
        <StatCard label="Allowed" value={counts.ALLOW} tone="green" detail="ALLOW decisions" />
        <StatCard label="Review" value={counts.REVIEW} tone="amber" detail="REVIEW decisions" />
        <StatCard label="Blocked" value={counts.BLOCK} tone="red" detail="BLOCK decisions" />
      </div>
      <div className="overview-grid">
        <section className="card">
          <div className="card-heading">
            <div>
              <p className="section-kicker">System status</p>
              <h2>Backend connection</h2>
            </div>
            <span className={`health-pill ${health ? "healthy" : "unhealthy"}`}>
              {health ? "Connected" : "Unavailable"}
            </span>
          </div>
          <div className="connection-row">
            <span className={`connection-orb ${health ? "healthy" : "unhealthy"}`} />
            <div>
              <strong>{health?.service || "PromptGuard API"}</strong>
              <p>{health ? "The API responded successfully." : "The backend is not reachable."}</p>
            </div>
            <div className="integration-status">
              <span>Detector integration</span>
              <strong>
                {!health
                  ? "Unavailable"
                  : !detectorIntegrationAvailable
                    ? "Not assessed"
                    : detectorFailures
                      ? `${detectorFailures} detector${detectorFailures === 1 ? "" : "s"} failed`
                      : "Available"}
              </strong>
            </div>
          </div>
        </section>
        <section className="card recent-card">
          <div className="card-heading">
            <div>
              <p className="section-kicker">Session activity</p>
              <h2>Recent scans</h2>
            </div>
            <button className="text-button" onClick={() => onNavigate("history")}>View all <Icon name="arrow" size={16} /></button>
          </div>
          {history.length ? (
            <div className="activity-list">
              {[...history].slice(-4).reverse().map((item) => (
                <button key={item.id} className="activity-row" onClick={() => onNavigate("history")}>
                  <DecisionBadge decision={item.decision} />
                  <span>{item.preview}</span>
                  <strong>{item.risk_score}</strong>
                  <small>{new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</small>
                </button>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <Icon name="scan" size={28} />
              <p>No scans in this session yet.</p>
              <button className="primary-button" onClick={() => onNavigate("scanner")}>Run first scan</button>
            </div>
          )}
        </section>
      </div>
    </>
  );
}

function ContentWorkbench({ mode, assessment, setAssessment, onRecord }) {
  const [health, setHealth] = useState(null);
  const [text, setText] = useState("");
  const [task, setTask] = useState("");
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
        const result = await scanText(text);
        setAssessment(result);
        onRecord(result, text);
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
      const isMockAssessment = mockDetectorReason(result.detectors);
      if (result.decision === "ALLOW" && !isMockAssessment && result.generated_response) {
        setGenerated(result.generated_response);
      }
      onRecord(result, text);
    } catch (generateError) {
      setError(generateError.message);
    } finally {
      setLoading("");
    }
  };

  return (
    <>
      <PageHeader
        eyebrow={mode === "generate" ? "Policy enforcement" : "Content analysis"}
        title={mode === "generate" ? "Protected Generation" : "Security Scanner"}
        description={
          mode === "generate"
            ? "Assess untrusted content before any target-model request is authorized."
            : "Submit external content for structured prompt-injection risk assessment."
        }
      />
      <div className="workbench">
        <section className="card composer-card">
          <div className="card-heading">
            <div>
              <p className="section-kicker">Input</p>
              <h2>{mode === "generate" ? "Content and task" : "Untrusted content"}</h2>
            </div>
            <span className="input-limit">{text.length.toLocaleString()} / 10,000</span>
          </div>
          <form onSubmit={mode === "generate" ? runProtectedGeneration : runScan}>
            <label htmlFor="content-text">Text to analyze</label>
            <textarea
              id="content-text"
              value={text}
              maxLength={10000}
              onChange={(event) => setText(event.target.value)}
              placeholder="Paste webpage content, email text, retrieved documents, or tool output..."
            />
            {mode === "generate" && (
              <>
                <label htmlFor="generation-task">Generation task</label>
                <input
                  id="generation-task"
                  value={task}
                  maxLength={2000}
                  onChange={(event) => setTask(event.target.value)}
                  placeholder="Summarize the supplied content"
                />
                <span className="task-limit">{task.length.toLocaleString()} / 2,000 characters</span>
              </>
            )}
            {error && <p className="error" role="alert">{error}</p>}
            <div className="form-actions">
              <button
                className="secondary-button"
                type="button"
                onClick={() => { setText(""); setTask(""); setAssessment(null); setGenerated(null); setError(""); }}
              >
                Clear
              </button>
              <button
                className="text-button reset-button"
                type="button"
                disabled={Boolean(loading)}
                onClick={() => {
                  setText("");
                  setTask("");
                  setAssessment(null);
                  setGenerated(null);
                  setError("");
                }}
              >
                Reset
              </button>
              {mode === "generate" ? (
                <button className="primary-button" type="submit" disabled={Boolean(loading)}>
                  {loading === "generate" ? <><span className="spinner" /> Checking and generating</> : <><Icon name="shield" /> Protected generate</>}
                </button>
              ) : (
                <button className="primary-button" type="button" onClick={runScan} disabled={Boolean(loading)}>
                  {loading === "scan" ? <><span className="spinner" /> Running scan</> : <><Icon name="scan" /> Run security scan</>}
                </button>
              )}
            </div>
          </form>
        </section>
        <div className="result-column">
          <Assessment assessment={assessment} />
          {generated && (
            <section className="card generated-card">
              <div className="card-heading">
                <div>
                  <p className="section-kicker">Target output</p>
                  <h2>Generated response</h2>
                </div>
                {(generated.is_mock || generated.is_synthetic) && (
                  <span className="mock-badge">Synthetic mock</span>
                )}
              </div>
              {(generated.is_mock || generated.is_synthetic) && (
                <p className="warning" role="note">Synthetic mock output. No real target LLM response was generated.</p>
              )}
              <p className="generated-text">{generated.text}</p>
            </section>
          )}
        </div>
      </div>
    </>
  );
}

function History({ history, onInspect }) {
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState("ALL");
  const visibleHistory = [...history]
    .reverse()
    .filter((item) => filter === "ALL" || item.decision === filter);
  return (
    <>
      <PageHeader eyebrow="Session data" title="Scan History" description="Scans performed in this browser session only. No persistent backend history is claimed." />
      <section className="card history-card">
        <div className="history-filter" aria-label="Filter scan history">
          {["ALL", "ALLOW", "REVIEW", "BLOCK"].map((decision) => (
            <button
              key={decision}
              type="button"
              className={filter === decision ? "active" : ""}
              aria-pressed={filter === decision}
              onClick={() => setFilter(decision)}
            >
              {decision === "ALL" ? "All scans" : decision}
            </button>
          ))}
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Content</th><th>Decision</th><th>Risk</th><th /></tr></thead>
            <tbody>
              {visibleHistory.map((item) => (
                <tr key={item.id}>
                  <td>{new Date(item.timestamp).toLocaleString()}</td>
                  <td>{item.preview}</td>
                  <td><DecisionBadge decision={item.decision} /></td>
                  <td><strong>{item.risk_score}</strong></td>
                  <td><button className="icon-button" aria-label="Inspect scan" onClick={() => { setSelected(item); onInspect(item.assessment); }}>Inspect</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!visibleHistory.length && (
            <div className="empty-state">
              <Icon name="clock" size={28} />
              <p>{history.length ? `No ${filter} scans in this session.` : "No session scans yet."}</p>
            </div>
          )}
        </div>
      </section>
      {selected && <Assessment assessment={selected.assessment} />}
    </>
  );
}

function DistributionChart({ history, activeDecision, onSelectDecision }) {
  const counts = ["ALLOW", "REVIEW", "BLOCK"].map((decision) => ({
    decision,
    count: history.filter((item) => item.decision === decision).length,
  }));
  const total = history.length || 1;
  return (
    <div className="distribution-chart">
      {counts.map(({ decision, count }) => (
        <button
          className={`distribution-row ${activeDecision === decision ? "active" : ""}`}
          key={decision}
          type="button"
          aria-pressed={activeDecision === decision}
          onClick={() => onSelectDecision(activeDecision === decision ? null : decision)}
        >
          <span>{decision}</span>
          <div><i className={`bar-${decision.toLowerCase()}`} style={{ width: `${(count / total) * 100}%` }} /></div>
          <strong>{count}</strong>
        </button>
      ))}
    </div>
  );
}

function Analytics({ history }) {
  const [activeDecision, setActiveDecision] = useState(null);
  const [activeRiskBand, setActiveRiskBand] = useState(null);
  const buckets = [
    { label: "0–29", min: 0, max: 29 },
    { label: "30–69", min: 30, max: 69 },
    { label: "70–100", min: 70, max: 100 },
  ].map((bucket) => ({
    ...bucket,
    count: history.filter((item) => item.risk_score >= bucket.min && item.risk_score <= bucket.max).length,
  }));
  const activityMax = Math.max(...history.length ? buckets.map((bucket) => bucket.count) : [1], 1);

  return (
    <>
      <PageHeader eyebrow="Session analytics" title="Analytics" description="Charts reflect scans performed during the current browser session only." />
      {!history.length && <div className="notice"><strong>Session data is unavailable.</strong><span>Run security scans to populate these charts.</span></div>}
      <div className="analytics-grid">
        <section className="card chart-card">
          <p className="section-kicker">Decision distribution</p>
          <h2>Security outcomes</h2>
          <DistributionChart
            history={history}
            activeDecision={activeDecision}
            onSelectDecision={setActiveDecision}
          />
          {activeDecision && (
            <p className="chart-selection">
              Showing {history.filter((item) => item.decision === activeDecision).length} {activeDecision} scans.
            </p>
          )}
        </section>
        <section className="card chart-card">
          <p className="section-kicker">Risk score distribution</p>
          <h2>Session risk bands</h2>
          <div className="risk-bars">
            {buckets.map((bucket) => (
              <button
                key={bucket.label}
                type="button"
                className={activeRiskBand === bucket.label ? "active" : ""}
                aria-pressed={activeRiskBand === bucket.label}
                onClick={() => setActiveRiskBand(activeRiskBand === bucket.label ? null : bucket.label)}
              >
                <span>{bucket.label}</span>
                <div><i style={{ height: `${history.length ? Math.max((bucket.count / activityMax) * 100, 4) : 4}%` }} /></div>
                <strong>{bucket.count}</strong>
              </button>
            ))}
          </div>
          {activeRiskBand && (
            <p className="chart-selection">
              Showing {buckets.find((bucket) => bucket.label === activeRiskBand)?.count || 0} scans in the {activeRiskBand} risk band.
            </p>
          )}
        </section>
      </div>
      <section className="card chart-card activity-chart">
        <p className="section-kicker">Session activity</p>
        <h2>Scans over time</h2>
        {history.length ? (
          <div className="timeline-bars">
            {history.map((item, index) => (
              <div key={item.id} title={`${item.decision}: ${item.risk_score}`}>
                <i className={`bar-${item.decision.toLowerCase()}`} style={{ height: `${Math.max(item.risk_score, 8)}%` }} />
                <span>{index + 1}</span>
              </div>
            ))}
          </div>
        ) : <div className="empty-chart">No session activity</div>}
      </section>
    </>
  );
}

function Settings({ health, apiBase, history }) {
  const [compact, setCompact] = useState(() => localStorage.getItem("promptguard-compact") === "true");
  const toggleCompact = () => {
    const next = !compact;
    setCompact(next);
    localStorage.setItem("promptguard-compact", String(next));
    document.documentElement.classList.toggle("compact", next);
  };
  const latest = history[history.length - 1];
  const detectorResults = Object.values(latest?.assessment?.detectors || {});
  const targetResponses = history
    .map((item) => item.assessment?.generated_response)
    .filter(Boolean);
  const latestTargetResponse = targetResponses[targetResponses.length - 1];
  return (
    <>
      <PageHeader eyebrow="Configuration" title="Settings" description="Interface and local API connection preferences." />
      <div className="settings-grid">
        <section className="card">
          <p className="section-kicker">Connectivity</p>
          <h2>Backend API</h2>
          <dl className="settings-list">
            <div><dt>Status</dt><dd><span className={`health-pill ${health ? "healthy" : "unhealthy"}`}>{health ? "Connected" : "Unavailable"}</span></dd></div>
            <div><dt>API base</dt><dd>{apiBase || "Vite proxy / same origin"}</dd></div>
            <div><dt>Service</dt><dd>{health?.service || "Not detected"}</dd></div>
            <div><dt>Latest assessment</dt><dd>{latest ? `${latest.decision} · risk ${latest.risk_score}` : "No scan completed"}</dd></div>
            <div>
              <dt>Detectors</dt>
              <dd>{detectorResults.length ? detectorResults.map((result) => result.status).join(", ") : "Not assessed"}</dd>
            </div>
            <div>
              <dt>Target provider</dt>
              <dd>{latestTargetResponse ? (latestTargetResponse.is_mock || latestTargetResponse.is_synthetic ? "Synthetic mock" : "Configured provider") : "Not used yet"}</dd>
            </div>
          </dl>
        </section>
        <section className="card">
          <p className="section-kicker">Interface</p>
          <h2>Preferences</h2>
          <div className="setting-toggle">
            <div><strong>Compact spacing</strong><p>Reduce spacing between dashboard cards.</p></div>
            <button type="button" role="switch" aria-checked={compact} className={`switch ${compact ? "on" : ""}`} onClick={toggleCompact}><span /></button>
          </div>
          <p className="settings-note">API keys and credentials are never displayed in this dashboard.</p>
        </section>
      </div>
    </>
  );
}

function App() {
  const [activePage, setActivePage] = useState("overview");
  const [health, setHealth] = useState(null);
  const [history, setHistory] = useState(loadHistory);
  const [assessment, setAssessment] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const refreshHealth = async () => {
    try { setHealth(await getHealth()); } catch { setHealth(null); }
  };

  useEffect(() => { refreshHealth(); }, []);
  useEffect(() => {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  }, [history]);
  useEffect(() => {
    document.documentElement.classList.toggle(
      "compact",
      localStorage.getItem("promptguard-compact") === "true",
    );
  }, []);

  const recordScan = (result, text) => {
    const item = {
      id: `${Date.now()}-${history.length}`,
      timestamp: new Date().toISOString(),
      decision: result.decision,
      risk_score: result.risk_score,
      preview: text.length > 72 ? `${text.slice(0, 72)}...` : text,
      assessment: result,
    };
    setHistory((current) => [...current, item]);
  };

  const navigate = (page) => {
    setActivePage(page);
    setSidebarOpen(false);
  };

  const page = {
    overview: <Overview health={health} history={history} onNavigate={navigate} />,
    scanner: <ContentWorkbench mode="scanner" assessment={assessment} setAssessment={setAssessment} onRecord={recordScan} />,
    generate: <ContentWorkbench mode="generate" assessment={assessment} setAssessment={setAssessment} onRecord={recordScan} />,
    history: <History history={history} />,
    analytics: <Analytics history={history} />,
    settings: <Settings health={health} apiBase={import.meta.env.VITE_API_BASE_URL || ""} history={history} />,
  }[activePage];

  return (
    <div className="app-shell">
      <aside className={`sidebar ${sidebarOpen ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Icon name="shield" size={24} /></div>
          <div><strong>PromptGuard</strong><span>Security Platform</span></div>
        </div>
        <nav aria-label="Primary navigation">
          {navItems.map(([id, label, icon]) => (
            <button key={id} className={activePage === id ? "active" : ""} onClick={() => navigate(id)}>
              <Icon name={icon} /><span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-status">
          <span className={`health-dot ${health ? "online" : "offline"}`} />
          <div><strong>{health ? "API connected" : "API unavailable"}</strong><small>Backend status</small></div>
        </div>
      </aside>
      {sidebarOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
      <main className="main-content">
        <div className="mobile-header">
          <button className="icon-button" aria-label="Open navigation" onClick={() => setSidebarOpen(true)}><Icon name="menu" /></button>
          <strong>PromptGuard</strong>
          <span className={`health-dot ${health ? "online" : "offline"}`} />
        </div>
        {page}
      </main>
    </div>
  );
}

export default App;
