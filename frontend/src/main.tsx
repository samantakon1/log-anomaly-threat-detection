import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  BarChart3,
  CloudDownload,
  Gauge,
  ListFilter,
  PlayCircle,
  Radar,
  Terminal,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8012";

type ThreatLevel = "critical" | "high" | "medium" | "low";

type Overview = {
  model_version: string;
  total_windows: number;
  high_anomaly_score_windows: number;
  security_relevant_windows: number;
  high_or_critical_windows: number;
  avg_anomaly_score: number;
  avg_threat_score: number;
  first_window: string | null;
  last_window: string | null;
  threat_level_counts: Record<ThreatLevel, number>;
};

type Alert = {
  window_start: string;
  ip_hash: string;
  model_version: string;
  threat_score: number;
  threat_level: ThreatLevel;
  is_security_relevant: boolean;
  reasons: string[];
  anomaly_score: number;
  anomaly_rank: number;
  request_count: number;
  suspicious_path_count: number;
  error_count: number;
  error_rate: number;
  unique_endpoint_count: number;
  static_asset_count: number;
  off_hours: boolean;
  module_id: string | null;
  endpoint_template: string | null;
  endpoint_group: string | null;
  status_family: string | null;
};

type TimelinePoint = {
  bucket: string;
  total_windows: number;
  security_relevant_windows: number;
  high_or_critical_windows: number;
  max_threat_score: number;
  max_anomaly_score: number;
};

type Metric = {
  ranking_method: string;
  metric_name: string;
  k_value: number;
  metric_value: number;
};

type Scenario = {
  scenario_name: string;
  is_attack_like: boolean;
  rows: number;
  avg_anomaly_score: number;
  avg_threat_score: number;
  security_relevant_rows: number;
};

type Evaluation = {
  evaluation_id: string | null;
  metrics: Metric[];
  scenarios: Scenario[];
};

type Incident = {
  model_version: string;
  date: string;
  interpretation: string;
  windows: Alert[];
};

type DashboardData = {
  overview: Overview;
  alerts: Alert[];
  timeline: TimelinePoint[];
  evaluation: Evaluation;
  incident: Incident;
};

type DemoStatus = "idle" | "running" | "completed" | "failed";

type DemoRun = {
  run_id: string | null;
  action: "get_process_latest" | "analyse_latest" | null;
  status: DemoStatus;
  started_at: string | null;
  finished_at: string | null;
  lines: string[];
  error: string | null;
};

type Tab = "overview" | "alerts" | "case-review" | "evaluation" | "demo";
type SortDirection = "asc" | "desc";

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatDecimal(value: number, digits = 3): string {
  return value.toFixed(digits);
}

function formatDateTime(value: string | null): string {
  if (!value) return "n/a";
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function postJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { method: "POST" });
  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function useDashboardData() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  function reload() {
    let active = true;
    setLoading(true);
    Promise.all([
      getJson<Overview>("/api/overview"),
      getJson<Alert[]>("/api/alerts?limit=50"),
      getJson<TimelinePoint[]>("/api/timeline"),
      getJson<Evaluation>("/api/evaluation"),
      getJson<Incident>("/api/incident"),
    ])
      .then(([overview, alerts, timeline, evaluation, incident]) => {
        if (active) {
          setData({ overview, alerts, timeline, evaluation, incident });
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (active) setError(err instanceof Error ? err.message : "Failed to load dashboard data");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }

  useEffect(() => {
    return reload();
  }, []);

  return { data, error, loading, reload };
}

function StatCard({
  label,
  value,
  detail,
  icon,
}: {
  label: string;
  value: string;
  detail: string;
  icon: React.ReactNode;
}) {
  return (
    <section className="stat-card">
      <div className="stat-icon">{icon}</div>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{detail}</span>
      </div>
    </section>
  );
}

function LevelBadge({ level }: { level: ThreatLevel }) {
  return <span className={`level-badge ${level}`}>{level}</span>;
}

function OverviewPanel({ overview, timeline }: { overview: Overview; timeline: TimelinePoint[] }) {
  const maxTimelineThreat = Math.max(...timeline.map((item) => item.max_threat_score), 1);

  return (
    <div className="panel-grid">
      <div className="stats-grid">
        <StatCard
          label="Feature windows"
          value={formatNumber(overview.total_windows)}
          detail={`Latest window ${formatDateTime(overview.last_window)}`}
          icon={<Activity size={22} />}
        />
        <StatCard
          label="Security-relevant"
          value={formatNumber(overview.security_relevant_windows)}
          detail="Windows retained for analyst review"
          icon={<ShieldAlert size={22} />}
        />
        <StatCard
          label="High or critical"
          value={formatNumber(overview.high_or_critical_windows)}
          detail="Highest-priority review set"
          icon={<AlertTriangle size={22} />}
        />
        <StatCard
          label="Average threat score"
          value={formatDecimal(overview.avg_threat_score, 2)}
          detail={`Model ${overview.model_version}`}
          icon={<Gauge size={22} />}
        />
      </div>

      <section className="chart-section">
        <div className="section-heading">
          <div>
            <h2>Threat Level Distribution</h2>
            <p>Second-stage scoring output by severity level.</p>
          </div>
        </div>
        <div className="level-bars">
          {(Object.keys(overview.threat_level_counts) as ThreatLevel[]).map((level) => {
            const count = overview.threat_level_counts[level];
            const percent = overview.total_windows ? (count / overview.total_windows) * 100 : 0;
            return (
              <div className="level-row" key={level}>
                <LevelBadge level={level} />
                <div className="bar-track">
                  <div className={`bar-fill ${level}`} style={{ width: `${Math.max(percent, count ? 1 : 0)}%` }} />
                </div>
                <strong>{formatNumber(count)}</strong>
              </div>
            );
          })}
        </div>
      </section>

      <section className="chart-section">
        <div className="section-heading">
          <div>
            <h2>Hourly Threat Timeline</h2>
            <p>Maximum score and prioritized windows by hour.</p>
          </div>
        </div>
        <div className="timeline-list">
          {timeline.map((point) => (
            <div className="timeline-row" key={point.bucket}>
              <div className="timeline-time">
                <strong>{formatDateTime(point.bucket)}</strong>
                <span>{formatNumber(point.total_windows)} windows</span>
              </div>
              <div className="timeline-score">
                <div className="score-track">
                  <div
                    className="score-fill"
                    style={{ width: `${Math.max((point.max_threat_score / maxTimelineThreat) * 100, 2)}%` }}
                  />
                </div>
                <span>Max threat {formatDecimal(point.max_threat_score, 2)}</span>
              </div>
              <div className="timeline-counts">
                <span>{formatNumber(point.security_relevant_windows)} relevant</span>
                <strong>{formatNumber(point.high_or_critical_windows)} high/critical</strong>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function AlertsPanel({ alerts }: { alerts: Alert[] }) {
  const [level, setLevel] = useState<ThreatLevel | "all">("all");
  const [windowSort, setWindowSort] = useState<SortDirection>("desc");
  const filtered = useMemo(() => {
    return [...alerts]
      .filter((alert) => level === "all" || alert.threat_level === level)
      .sort((left, right) => {
        const leftTime = new Date(left.window_start).getTime();
        const rightTime = new Date(right.window_start).getTime();
        return windowSort === "asc" ? leftTime - rightTime : rightTime - leftTime;
      });
  }, [alerts, level, windowSort]);

  function toggleWindowSort() {
    setWindowSort((current) => (current === "asc" ? "desc" : "asc"));
  }

  return (
    <section className="table-section">
      <div className="section-heading">
        <div>
          <h2>Alert Review</h2>
          <p>Top anonymized threat-scored windows with reason codes.</p>
        </div>
        <div className="toolbar">
          <ListFilter size={18} />
          <select value={level} onChange={(event) => setLevel(event.target.value as ThreatLevel | "all")}>
            <option value="all">All levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>
                <button className="sort-header" type="button" onClick={toggleWindowSort}>
                  Window
                  {windowSort === "asc" ? <ArrowUp size={14} /> : <ArrowDown size={14} />}
                </button>
              </th>
              <th>Level</th>
              <th>Threat</th>
              <th>Anomaly</th>
              <th>IP hash</th>
              <th>Requests</th>
              <th>Suspicious</th>
              <th>Error rate</th>
              <th>Endpoint</th>
              <th>Reasons</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((alert) => (
              <tr key={`${alert.window_start}-${alert.ip_hash}-${alert.threat_score}`}>
                <td>{formatDateTime(alert.window_start)}</td>
                <td><LevelBadge level={alert.threat_level} /></td>
                <td>{formatDecimal(alert.threat_score, 2)}</td>
                <td>{formatDecimal(alert.anomaly_score, 4)}</td>
                <td><code>{alert.ip_hash}</code></td>
                <td>{formatNumber(alert.request_count)}</td>
                <td>{formatNumber(alert.suspicious_path_count)}</td>
                <td>{formatDecimal(alert.error_rate, 3)}</td>
                <td>{alert.endpoint_template ?? alert.endpoint_group ?? "n/a"}</td>
                <td className="reason-cell">{alert.reasons.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function CaseReviewPanel({ incident }: { incident: Incident }) {
  const topWindow = incident.windows[0];

  return (
    <div className="panel-grid">
      <section className="incident-summary">
        <div>
          <Radar size={26} />
          <h2>Case Review</h2>
        </div>
        <p>{incident.interpretation}</p>
        {topWindow && (
          <div className="incident-metrics">
            <span>{formatDateTime(topWindow.window_start)}</span>
            <strong>{formatDecimal(topWindow.threat_score, 2)}</strong>
            <LevelBadge level={topWindow.threat_level} />
          </div>
        )}
      </section>
      <AlertsPanel alerts={incident.windows} />
    </div>
  );
}

function EvaluationPanel({ evaluation }: { evaluation: Evaluation }) {
  const classification = evaluation.metrics.filter((metric) => metric.k_value === 0);

  return (
    <div className="panel-grid">
      <section className="chart-section">
        <div className="section-heading">
          <div>
            <h2>Synthetic Evaluation</h2>
            <p>{evaluation.evaluation_id ?? "No evaluation available"}</p>
          </div>
          <BarChart3 size={22} />
        </div>
        <div className="metric-grid">
          {classification.map((metric) => (
            <div className="metric-tile" key={`${metric.ranking_method}-${metric.metric_name}`}>
              <span>{metric.ranking_method.replaceAll("_", " ")}</span>
              <strong>{formatDecimal(metric.metric_value, 4)}</strong>
              <p>{metric.metric_name.replaceAll("_", " ")}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="table-section">
        <div className="section-heading">
          <div>
            <h2>Scenario Results</h2>
            <p>Controlled attack-like and benign anomaly scenarios.</p>
          </div>
        </div>
        <div className="table-wrap compact">
          <table>
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Type</th>
                <th>Rows</th>
                <th>Avg anomaly</th>
                <th>Avg threat</th>
                <th>Relevant</th>
              </tr>
            </thead>
            <tbody>
              {evaluation.scenarios.map((scenario) => (
                <tr key={scenario.scenario_name}>
                  <td>{scenario.scenario_name.replaceAll("_", " ")}</td>
                  <td>{scenario.is_attack_like ? "Attack-like" : "Benign anomaly"}</td>
                  <td>{scenario.rows}</td>
                  <td>{formatDecimal(scenario.avg_anomaly_score, 4)}</td>
                  <td>{formatDecimal(scenario.avg_threat_score, 2)}</td>
                  <td>{scenario.security_relevant_rows}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function DemoPanel({ onAnalysisCompleted }: { onAnalysisCompleted: () => void }) {
  const [run, setRun] = useState<DemoRun>({
    run_id: null,
    action: null,
    status: "idle",
    started_at: null,
    finished_at: null,
    lines: [],
    error: null,
  });
  const [startError, setStartError] = useState<string | null>(null);
  const isRunning = run.status === "running";

  async function startRun(action: "get_process_latest" | "analyse_latest") {
    setStartError(null);
    setRun({
      run_id: null,
      action,
      status: "running",
      started_at: new Date().toISOString(),
      finished_at: null,
      lines: [],
      error: null,
    });
    try {
      const path = action === "get_process_latest" ? "/api/demo/get-process-latest" : "/api/demo/analyse-latest";
      setRun(await postJson<DemoRun>(path));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to start demo run";
      setStartError(message);
      setRun((current) => ({ ...current, status: "failed", error: message, lines: [`[local] ERROR: ${message}`] }));
    }
  }

  useEffect(() => {
    if (!isRunning) return undefined;
    let active = true;
    const interval = window.setInterval(() => {
      getJson<DemoRun>("/api/demo/status")
        .then((nextRun) => {
          if (!active) return;
          setRun(nextRun);
          if (nextRun.status === "completed" && nextRun.action === "analyse_latest") {
            onAnalysisCompleted();
          }
        })
        .catch((err: unknown) => {
          if (!active) return;
          const message = err instanceof Error ? err.message : "Failed to read demo status";
          setRun((current) => ({ ...current, status: "failed", error: message, lines: [...current.lines, `[local] ERROR: ${message}`] }));
        });
    }, 1000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [isRunning, onAnalysisCompleted]);

  return (
    <div className="panel-grid">
      <section className="demo-controls">
        <div className="section-heading">
          <div>
            <h2>Live Demo Controls</h2>
            <p>Fetch, anonymize, process, and analyze the latest App Engine logs from a controlled dashboard workflow.</p>
          </div>
          <Terminal size={22} />
        </div>
        <div className="demo-button-row">
          <button className="primary-action" disabled={isRunning} onClick={() => startRun("get_process_latest")}>
            <CloudDownload size={18} />
            Get & Process Latest Logs
          </button>
          <button className="secondary-action" disabled={isRunning} onClick={() => startRun("analyse_latest")}>
            <PlayCircle size={18} />
            Analyse Latest Logs
          </button>
        </div>
        <div className={`demo-status ${run.status}`}>
          <strong>{run.status}</strong>
          <span>{run.action ? run.action.replaceAll("_", " ") : "No run started"}</span>
        </div>
        {startError && <p className="demo-error">{startError}</p>}
      </section>

      <section className="terminal-section" aria-label="Demo run terminal">
        <div className="terminal-header">
          <span>Demo terminal</span>
          <code>{run.run_id ?? "idle"}</code>
        </div>
        <div className="terminal-output">
          {run.lines.length === 0 ? (
            <p className="terminal-muted">Terminal output will appear here after a demo action starts.</p>
          ) : (
            run.lines.map((line, index) => (
              <p className={line.includes("ERROR") ? "terminal-error" : ""} key={`${line}-${index}`}>
                {line}
              </p>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

function App() {
  const { data, error, loading, reload } = useDashboardData();
  const [tab, setTab] = useState<Tab>("overview");

  if (loading) {
    return <main className="loading">Loading dashboard outputs...</main>;
  }

  if (error || !data) {
    return (
      <main className="loading error">
        <ShieldAlert size={28} />
        <span>{error ?? "No dashboard data available"}</span>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <span className="eyebrow">MSc thesis prototype</span>
          <h1>Log Anomaly Threat Detection Dashboard</h1>
          <p>Analyst view over anonymized anomaly scores, threat scores, case-review windows, and synthetic evaluation results.</p>
        </div>
        <div className="status-pill">
          <ShieldCheck size={18} />
          Processed data only
        </div>
      </header>

      <nav className="tabs" aria-label="Dashboard sections">
        {[
          ["overview", Activity, "Overview"],
          ["alerts", ShieldAlert, "Alerts"],
          ["case-review", Radar, "Case Review"],
          ["evaluation", BarChart3, "Evaluation"],
          ["demo", Terminal, "Demo"],
        ].map(([value, Icon, label]) => {
          const TypedIcon = Icon as typeof Activity;
          return (
            <button key={value as string} className={tab === value ? "active" : ""} onClick={() => setTab(value as Tab)}>
              <TypedIcon size={18} />
              {label as string}
            </button>
          );
        })}
      </nav>

      {tab === "overview" && <OverviewPanel overview={data.overview} timeline={data.timeline} />}
      {tab === "alerts" && <AlertsPanel alerts={data.alerts} />}
      {tab === "case-review" && <CaseReviewPanel incident={data.incident} />}
      {tab === "evaluation" && <EvaluationPanel evaluation={data.evaluation} />}
      {tab === "demo" && <DemoPanel onAnalysisCompleted={reload} />}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
