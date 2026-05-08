import { useEffect, useMemo, useState } from "react";

import { apiGet, apiPatch, apiPost, fetchDashboardData } from "../api/client.js";
import { useRealtimeAlerts } from "../hooks/useRealtimeAlerts.js";

const sections = [
  { key: "assets", title: "Assets", empty: "No assets found." },
  { key: "events", title: "Security Events", empty: "No events found." },
];

const formTabs = [
  { key: "asset", label: "Asset" },
  { key: "event", label: "Event" },
  { key: "alert", label: "Alert" },
  { key: "incident", label: "Incident" },
];

const initialForms = {
  asset: {
    hostname: "",
    ip_address: "",
    operating_system: "",
    role: "",
    status: "active",
  },
  event: {
    event_type: "",
    source: "dashboard",
    source_ip: "",
    destination_ip: "",
    username: "",
    raw_message: "",
    severity: "medium",
  },
  alert: {
    title: "",
    description: "",
    severity: "medium",
    status: "new",
    event_id: "",
  },
  incident: {
    title: "",
    description: "",
    severity: "high",
    status: "open",
    alert_id: "",
  },
};

const alertStatuses = ["new", "investigating", "resolved", "false_positive"];
const alertActions = [
  { label: "Mark Investigating", status: "investigating" },
  { label: "Mark Resolved", status: "resolved" },
  { label: "Mark False Positive", status: "false_positive" },
];

const incidentStatuses = ["open", "investigating", "contained", "resolved"];
const incidentActions = [
  { label: "Mark Investigating", status: "investigating" },
  { label: "Mark Contained", status: "contained" },
  { label: "Mark Resolved", status: "resolved" },
];

const resourcePaths = {
  assets: "/api/assets/",
  events: "/api/events/",
  alerts: "/api/alerts/",
  incidents: "/api/incidents/",
  activity: "/api/activity/recent",
};

const nodeColors = {
  source_ip: "#38bdf8",
  asset: "#a5b4fc",
  event: "#facc15",
  alert: "#fb7185",
  incident: "#f97316",
  threat_intel: "#c084fc",
};

function cleanOptionalNumber(value) {
  return value === "" ? null : Number(value);
}

function getPrimaryText(sectionKey, item) {
  if (sectionKey === "assets") return item.hostname;
  if (sectionKey === "events") return item.event_type;
  return item.title;
}

function getSecondaryText(sectionKey, item) {
  if (sectionKey === "assets") {
    return [item.ip_address, item.operating_system, item.role, item.status].filter(Boolean).join(" | ");
  }

  if (sectionKey === "events") {
    return [item.source, item.source_ip, item.destination_ip, item.username, item.raw_message]
      .filter(Boolean)
      .join(" | ");
  }

  return [item.status, item.source ?? item.summary ?? item.description].filter(Boolean).join(" | ");
}

function formatDateTime(value) {
  if (!value) return "No timestamp";

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function countryFlag(country) {
  if (!country) return "N/A";

  const countryCodes = {
    Internal: "INT",
    Reserved: "RSV",
    Unknown: "UNK",
    "United States": "US",
    "United Kingdom": "GB",
    Germany: "DE",
    France: "FR",
    Netherlands: "NL",
    Canada: "CA",
    Australia: "AU",
    Japan: "JP",
    Singapore: "SG",
    "South Africa": "ZA",
  };
  const code = countryCodes[country] ?? country;

  if (!/^[A-Z]{2}$/.test(code)) return code;

  return String.fromCodePoint(...[...code].map((character) => 127397 + character.charCodeAt(0)));
}

function threatLevel(score, knownMalicious = false) {
  if (knownMalicious || score >= 70) return "critical";
  if (score >= 40) return "elevated";
  if (score > 0) return "observed";
  return "unknown";
}

function StatusBadge({ status, allowedStatuses }) {
  const normalizedStatus = status ?? "unknown";
  const badgeClass = allowedStatuses.includes(normalizedStatus)
    ? `status-${normalizedStatus}`
    : "status-unknown";

  return <span className={`status-badge ${badgeClass}`}>{normalizedStatus}</span>;
}

function RealtimeBadge({ status }) {
  const labels = {
    connected: "Live connected",
    reconnecting: "Reconnecting",
    offline: "Offline",
  };

  return <span className={`live-badge live-${status}`}>{labels[status] ?? "Offline"}</span>;
}

function ThreatBadges({ item }) {
  const score = item.threat_score ?? item.risk_score;
  const country = item.geo_country ?? item.country;
  const knownMalicious = item.known_malicious ?? score >= 70;

  if (!score && !country && !item.enrichment_status) return null;

  return (
    <div className="threat-badge-row">
      <span className={`threat-badge threat-${threatLevel(score ?? 0, knownMalicious)}`}>
        Threat {score ?? "n/a"}
      </span>
      {knownMalicious && <span className="threat-badge threat-critical">Malicious IP</span>}
      {country && <span className="threat-badge">{countryFlag(country)} {country}</span>}
      {item.isp && <span className="threat-badge">{item.isp}</span>}
      {item.enrichment_status && <span className="threat-badge">{item.enrichment_status}</span>}
    </div>
  );
}

function buildGraphPath(filters) {
  const params = new URLSearchParams();
  const sourceIp = filters.source_ip.trim();
  const severity = filters.severity.trim();
  const limit = Number.parseInt(filters.limit, 10);

  if (sourceIp) params.set("source_ip", sourceIp);
  if (severity) params.set("severity", severity);
  if (Number.isInteger(limit) && limit >= 1 && limit <= 500) {
    params.set("limit", String(limit));
  }

  const query = params.toString();
  return `/api/graph/investigation${query ? `?${query}` : ""}`;
}

function layoutGraph(nodes) {
  const centerX = 520;
  const centerY = 260;
  const radius = Math.max(150, Math.min(240, nodes.length * 18));

  return nodes.map((node, index) => {
    if (node.type === "source_ip") {
      return { ...node, x: centerX, y: centerY };
    }

    const angle = (Math.PI * 2 * index) / Math.max(nodes.length, 1) - Math.PI / 2;
    const typeOffset = Object.keys(nodeColors).indexOf(node.type) * 18;
    return {
      ...node,
      x: centerX + Math.cos(angle) * (radius + typeOffset),
      y: centerY + Math.sin(angle) * (radius - typeOffset / 2),
    };
  });
}

function Field({ label, name, value, onChange, required = false, type = "text" }) {
  return (
    <label>
      <span>{label}</span>
      <input
        name={name}
        type={type}
        value={value}
        required={required}
        onChange={(event) => onChange(name, event.target.value)}
      />
    </label>
  );
}

function SelectField({ label, name, value, onChange, options }) {
  return (
    <label>
      <span>{label}</span>
      <select name={name} value={value} onChange={(event) => onChange(name, event.target.value)}>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function TextAreaField({ label, name, value, onChange, required = false }) {
  return (
    <label className="wide-field">
      <span>{label}</span>
      <textarea
        name={name}
        value={value}
        required={required}
        rows={3}
        onChange={(event) => onChange(name, event.target.value)}
      />
    </label>
  );
}

function DataSection({ section, items }) {
  return (
    <section className="data-section">
      <div className="section-heading">
        <h2>{section.title}</h2>
        <span>{items.length}</span>
      </div>

      {items.length === 0 ? (
        <p className="empty-state">{section.empty}</p>
      ) : (
        <ul className="data-list">
          {items.slice(0, 5).map((item) => (
            <li key={`${section.key}-${item.id}`}>
              <div>
                <strong>{getPrimaryText(section.key, item) ?? "Untitled"}</strong>
                <p>{getSecondaryText(section.key, item) || "No additional context"}</p>
                <ThreatBadges item={item} />
              </div>
              <span className="severity">{item.severity ?? "info"}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function CreateRecordPanel({
  activeForm,
  forms,
  submitState,
  submitMessage,
  submitError,
  onTabChange,
  onFieldChange,
  onSubmit,
}) {
  const form = forms[activeForm];

  return (
    <section className="create-panel">
      <div className="section-heading">
        <h2>Create SOC Record</h2>
        <span>{activeForm}</span>
      </div>

      <div className="tab-row" role="tablist" aria-label="Create SOC record type">
        {formTabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            className={activeForm === tab.key ? "active-tab" : ""}
            onClick={() => onTabChange(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <form className="record-form" onSubmit={onSubmit}>
        {activeForm === "asset" && (
          <>
            <Field label="Hostname" name="hostname" value={form.hostname} required onChange={onFieldChange} />
            <Field label="IP address" name="ip_address" value={form.ip_address} onChange={onFieldChange} />
            <Field
              label="Operating system"
              name="operating_system"
              value={form.operating_system}
              onChange={onFieldChange}
            />
            <Field label="Role" name="role" value={form.role} onChange={onFieldChange} />
            <SelectField
              label="Status"
              name="status"
              value={form.status}
              onChange={onFieldChange}
              options={["active", "monitored", "isolated", "retired"]}
            />
          </>
        )}

        {activeForm === "event" && (
          <>
            <Field label="Event type" name="event_type" value={form.event_type} required onChange={onFieldChange} />
            <Field label="Source" name="source" value={form.source} required onChange={onFieldChange} />
            <Field label="Source IP" name="source_ip" value={form.source_ip} onChange={onFieldChange} />
            <Field
              label="Destination IP"
              name="destination_ip"
              value={form.destination_ip}
              onChange={onFieldChange}
            />
            <Field label="Username" name="username" value={form.username} onChange={onFieldChange} />
            <SelectField
              label="Severity"
              name="severity"
              value={form.severity}
              onChange={onFieldChange}
              options={["low", "medium", "high", "critical"]}
            />
            <TextAreaField
              label="Raw message"
              name="raw_message"
              value={form.raw_message}
              onChange={onFieldChange}
            />
          </>
        )}

        {activeForm === "alert" && (
          <>
            <Field label="Title" name="title" value={form.title} required onChange={onFieldChange} />
            <SelectField
              label="Severity"
              name="severity"
              value={form.severity}
              onChange={onFieldChange}
              options={["low", "medium", "high", "critical"]}
            />
            <SelectField
              label="Status"
              name="status"
              value={form.status}
              onChange={onFieldChange}
              options={alertStatuses}
            />
            <Field label="Event ID" name="event_id" value={form.event_id} type="number" onChange={onFieldChange} />
            <TextAreaField
              label="Description"
              name="description"
              value={form.description}
              onChange={onFieldChange}
            />
          </>
        )}

        {activeForm === "incident" && (
          <>
            <Field label="Title" name="title" value={form.title} required onChange={onFieldChange} />
            <SelectField
              label="Severity"
              name="severity"
              value={form.severity}
              onChange={onFieldChange}
              options={["low", "medium", "high", "critical"]}
            />
            <SelectField
              label="Status"
              name="status"
              value={form.status}
              onChange={onFieldChange}
              options={incidentStatuses}
            />
            <Field label="Alert ID" name="alert_id" value={form.alert_id} type="number" onChange={onFieldChange} />
            <TextAreaField
              label="Description"
              name="description"
              value={form.description}
              onChange={onFieldChange}
            />
          </>
        )}

        <div className="form-footer">
          <button type="submit" disabled={submitState === "submitting"}>
            {submitState === "submitting" ? "Creating..." : `Create ${activeForm}`}
          </button>
          {submitMessage && <span className="success-message">{submitMessage}</span>}
          {submitError && <span className="form-error">{submitError}</span>}
        </div>
      </form>
    </section>
  );
}

function DetectionPanel({ detectionState, detectionResult, detectionError, onRun }) {
  return (
    <section className="detection-panel">
      <div>
        <h2>Detection Engine</h2>
        <p>Run deterministic SOC rules against recent security events before AI enrichment.</p>
      </div>
      <button type="button" disabled={detectionState === "running"} onClick={onRun}>
        {detectionState === "running" ? "Running..." : "Run Detection Engine"}
      </button>
      {detectionResult && (
        <div className="detection-result">
          <span>Rules checked: {detectionResult.rules_checked}</span>
          <span>Matches found: {detectionResult.matches_found}</span>
          <span>Alerts created: {detectionResult.alerts_created}</span>
        </div>
      )}
      {detectionError && <span className="form-error">{detectionError}</span>}
    </section>
  );
}

function ThreatIntelPanel({ threatState, threatResult, threatError, onRun }) {
  return (
    <section className="threat-panel">
      <div>
        <h2>Threat Intelligence</h2>
        <p>Enrich source IPs with AbuseIPDB, VirusTotal, GeoIP, and Shodan-ready provider context.</p>
      </div>
      <button type="button" disabled={threatState === "running"} onClick={onRun}>
        {threatState === "running" ? "Enriching..." : "Run Threat Enrichment"}
      </button>
      {threatResult && (
        <div className="detection-result">
          <span>Source IPs: {threatResult.source_ips_checked}</span>
          <span>Events enriched: {threatResult.events_enriched}</span>
          <span>Alerts enriched: {threatResult.alerts_enriched}</span>
          <span>Providers: {threatResult.providers?.join(", ")}</span>
        </div>
      )}
      {threatError && <span className="form-error">{threatError}</span>}
    </section>
  );
}

function GraphInvestigationPanel({
  graphData,
  graphStatus,
  graphError,
  graphFilters,
  selectedNode,
  zoom,
  onFilterChange,
  onRefresh,
  onNodeSelect,
  onZoomChange,
}) {
  const nodes = layoutGraph(graphData?.nodes ?? []);
  const nodeById = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const edges = graphData?.edges ?? [];

  return (
    <section className="graph-panel">
      <div className="section-heading">
        <div>
          <h2>Graph Investigation</h2>
          <p>Map source IPs, events, alerts, incidents, assets, and threat intel into a visual case graph.</p>
        </div>
        <button type="button" disabled={graphStatus === "loading"} onClick={onRefresh}>
          {graphStatus === "loading" ? "Refreshing..." : "Refresh Graph"}
        </button>
      </div>

      <div className="graph-controls">
        <label>
          <span>Source IP</span>
          <input
            value={graphFilters.source_ip}
            onChange={(event) => onFilterChange("source_ip", event.target.value)}
            placeholder="Any source IP"
          />
        </label>
        <label>
          <span>Severity</span>
          <select value={graphFilters.severity} onChange={(event) => onFilterChange("severity", event.target.value)}>
            <option value="">Any severity</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </label>
        <label>
          <span>Limit</span>
          <input
            type="number"
            min="1"
            max="500"
            value={graphFilters.limit}
            onChange={(event) => onFilterChange("limit", event.target.value)}
          />
        </label>
        <label>
          <span>Zoom</span>
          <input
            type="range"
            min="70"
            max="140"
            value={zoom}
            onChange={(event) => onZoomChange(Number(event.target.value))}
          />
        </label>
      </div>

      {graphError && <span className="form-error">{graphError}</span>}

      {graphData && (
        <div className="graph-summary">
          <span>{graphData.summary.nodes} nodes</span>
          <span>{graphData.summary.edges} edges</span>
          <span>{graphData.summary.high_risk_nodes} high risk</span>
        </div>
      )}

      {graphStatus === "loading" && <div className="state-panel">Loading investigation graph...</div>}

      {graphStatus !== "loading" && nodes.length === 0 && (
        <p className="empty-state">No graph relationships found. Run detection, enrichment, or correlation first.</p>
      )}

      {nodes.length > 0 && (
        <div className="graph-workspace">
          <svg className="graph-canvas" viewBox="0 0 1040 560" style={{ transform: `scale(${zoom / 100})` }}>
            {edges.map((edge) => {
              const source = nodeById[edge.source];
              const target = nodeById[edge.target];
              if (!source || !target) return null;
              const midX = (source.x + target.x) / 2;
              const midY = (source.y + target.y) / 2;

              return (
                <g key={edge.id}>
                  <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} className="graph-edge" />
                  <text x={midX} y={midY} className="graph-edge-label">
                    {edge.relationship}
                  </text>
                </g>
              );
            })}

            {nodes.map((node) => {
              const highRisk = node.risk_score >= 70 || ["high", "critical"].includes(node.severity);
              return (
                <g
                  key={node.id}
                  className={`graph-node ${highRisk ? "graph-node-high" : ""}`}
                  onClick={() => onNodeSelect(node)}
                >
                  <circle cx={node.x} cy={node.y} r={highRisk ? 24 : 19} fill={nodeColors[node.type] ?? "#94a3b8"} />
                  <text x={node.x} y={node.y + 38} className="graph-node-label">
                    {node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          <aside className="graph-detail">
            {selectedNode ? (
              <>
                <span className="threat-badge">{selectedNode.type}</span>
                <h3>{selectedNode.label}</h3>
                <p>{selectedNode.id}</p>
                <div className="activity-meta">
                  <span>Risk {selectedNode.risk_score}</span>
                  <span>{selectedNode.severity}</span>
                </div>
                <dl>
                  {Object.entries(selectedNode.metadata ?? {}).map(([key, value]) => (
                    <div key={key}>
                      <dt>{key}</dt>
                      <dd>{String(value)}</dd>
                    </div>
                  ))}
                </dl>
              </>
            ) : (
              <p>Select a node to inspect metadata.</p>
            )}
          </aside>
        </div>
      )}
    </section>
  );
}

function CorrelationPanel({ correlationState, correlationResult, correlationError, onRun }) {
  const chains = correlationResult?.chains ?? [];

  return (
    <section className="correlation-panel">
      <div className="section-heading">
        <div>
          <h2>Attack Chains</h2>
          <p>Correlate events, alerts, assets, and incidents into source-IP attack paths.</p>
        </div>
        <button type="button" disabled={correlationState === "running"} onClick={onRun}>
          {correlationState === "running" ? "Correlating..." : "Run Correlation Engine"}
        </button>
      </div>

      {correlationResult && (
        <div className="detection-result">
          <span>Chains: {correlationResult.chains_found}</span>
          <span>Source IPs: {correlationResult.source_ips_checked}</span>
        </div>
      )}

      {correlationError && <span className="form-error">{correlationError}</span>}

      {correlationResult && chains.length === 0 && (
        <p className="empty-state">No attack-chain candidates found yet.</p>
      )}

      {chains.length > 0 && (
        <ul className="data-list chain-list">
          {chains.slice(0, 6).map((chain) => (
            <li key={`chain-${chain.source_ip}`} className="chain-item">
              <div className="record-body">
                <div className="record-title-row">
                  <strong>{chain.source_ip}</strong>
                  <span className={`threat-badge threat-${threatLevel(chain.risk_score)}`}>
                    Risk {chain.risk_score}
                  </span>
                </div>
                <p>{chain.recommended_action}</p>
                <div className="activity-meta">
                  <span>{chain.attack_stage}</span>
                  <span>{chain.related_events.length} events</span>
                  <span>{chain.related_alerts.length} alerts</span>
                  <span>{chain.affected_assets.length || 0} assets</span>
                </div>
                {chain.affected_assets.length > 0 && (
                  <p className="chain-assets">{chain.affected_assets.join(" | ")}</p>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function AlertSection({ alerts, onStatusChange, updatingKey }) {
  return (
    <section className="data-section workflow-section">
      <div className="section-heading">
        <h2>Alerts</h2>
        <span>{alerts.length}</span>
      </div>

      {alerts.length === 0 ? (
        <p className="empty-state">No alerts found.</p>
      ) : (
        <ul className="data-list">
          {alerts.slice(0, 5).map((alert) => (
            <li key={`alert-${alert.id}`} className="workflow-item">
              <div className="record-body">
                <div className="record-title-row">
                  <strong>{alert.title ?? "Untitled alert"}</strong>
                  <StatusBadge status={alert.status} allowedStatuses={alertStatuses} />
                </div>
                <p>{[alert.source, alert.description].filter(Boolean).join(" | ") || "No alert context"}</p>
                <ThreatBadges item={alert} />
                <div className="action-row">
                  {alertActions.map((action) => (
                    <button
                      key={`${alert.id}-${action.status}`}
                      type="button"
                      disabled={alert.status === action.status || updatingKey === `alert-${alert.id}`}
                      onClick={() => onStatusChange(alert.id, action.status)}
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
              </div>
              <span className="severity">{alert.severity ?? "info"}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function IncidentSection({ incidents, onStatusChange, updatingKey }) {
  return (
    <section className="data-section workflow-section">
      <div className="section-heading">
        <h2>Incidents</h2>
        <span>{incidents.length}</span>
      </div>

      {incidents.length === 0 ? (
        <p className="empty-state">No incidents found.</p>
      ) : (
        <ul className="data-list">
          {incidents.slice(0, 5).map((incident) => (
            <li key={`incident-${incident.id}`} className="workflow-item">
              <div className="record-body">
                <div className="record-title-row">
                  <strong>{incident.title ?? "Untitled incident"}</strong>
                  <StatusBadge status={incident.status} allowedStatuses={incidentStatuses} />
                </div>
                <p>{incident.description || incident.summary || "No incident summary"}</p>
                <div className="action-row">
                  {incidentActions.map((action) => (
                    <button
                      key={`${incident.id}-${action.status}`}
                      type="button"
                      disabled={incident.status === action.status || updatingKey === `incident-${incident.id}`}
                      onClick={() => onStatusChange(incident.id, action.status)}
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
              </div>
              <span className="severity">{incident.severity ?? "info"}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ActivitySection({ activity }) {
  return (
    <section className="data-section activity-section">
      <div className="section-heading">
        <h2>Activity Timeline</h2>
        <span>{activity.length}</span>
      </div>

      {activity.length === 0 ? (
        <p className="empty-state">No activity records found.</p>
      ) : (
        <ul className="data-list">
          {activity.slice(0, 8).map((item) => (
            <li key={`activity-${item.id}`} className="activity-item">
              <div className="record-body">
                <div className="record-title-row">
                  <strong>{item.action}</strong>
                  <span className="activity-time">{formatDateTime(item.created_at)}</span>
                </div>
                <p>{item.message}</p>
                <div className="activity-meta">
                  <span>{item.entity_type}</span>
                  <span>#{item.entity_id ?? "n/a"}</span>
                  <span>{item.severity ?? "info"}</span>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default function Dashboard() {
  const [data, setData] = useState({
    assets: [],
    events: [],
    alerts: [],
    incidents: [],
    activity: [],
  });
  const [status, setStatus] = useState("loading");
  const [error, setError] = useState("");
  const [updatingKey, setUpdatingKey] = useState("");
  const [activeForm, setActiveForm] = useState("asset");
  const [forms, setForms] = useState(initialForms);
  const [submitState, setSubmitState] = useState("idle");
  const [submitMessage, setSubmitMessage] = useState("");
  const [submitError, setSubmitError] = useState("");
  const [detectionState, setDetectionState] = useState("idle");
  const [detectionResult, setDetectionResult] = useState(null);
  const [detectionError, setDetectionError] = useState("");
  const [threatState, setThreatState] = useState("idle");
  const [threatResult, setThreatResult] = useState(null);
  const [threatError, setThreatError] = useState("");
  const [correlationState, setCorrelationState] = useState("idle");
  const [correlationResult, setCorrelationResult] = useState(null);
  const [correlationError, setCorrelationError] = useState("");
  const [graphData, setGraphData] = useState(null);
  const [graphStatus, setGraphStatus] = useState("idle");
  const [graphError, setGraphError] = useState("");
  const [graphFilters, setGraphFilters] = useState({ source_ip: "", severity: "", limit: "150" });
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);
  const [graphZoom, setGraphZoom] = useState(100);
  const [liveNotice, setLiveNotice] = useState("");

  const realtimeStatus = useRealtimeAlerts({ onMessage: handleRealtimeMessage });

  useEffect(() => {
    let isMounted = true;

    async function loadDashboard() {
      try {
        setStatus("loading");
        const nextData = await fetchDashboardData();

        if (isMounted) {
          setData(nextData);
          setStatus("ready");
        }
      } catch (requestError) {
        if (isMounted) {
          setError(requestError.message);
          setStatus("error");
        }
      }
    }

    loadDashboard();
    loadGraph();

    return () => {
      isMounted = false;
    };
  }, []);

  const totalRecords = useMemo(
    () => Object.values(data).reduce((total, items) => total + items.length, 0),
    [data],
  );

  function handleFieldChange(name, value) {
    setForms((currentForms) => ({
      ...currentForms,
      [activeForm]: {
        ...currentForms[activeForm],
        [name]: value,
      },
    }));
  }

  async function refreshSlices(keys) {
    const responses = await Promise.all(keys.map((key) => apiGet(resourcePaths[key])));

    setData((currentData) =>
      keys.reduce(
        (nextData, key, index) => ({
          ...nextData,
          [key]: responses[index],
        }),
        currentData,
      ),
    );
  }

  async function handleRealtimeMessage(message) {
    if (message.type === "connected") return;

    if (message.type === "correlation_completed") {
      setCorrelationResult({
        chains: message.chains,
        chains_found: message.chains_found,
        source_ips_checked: message.source_ips_checked,
      });
    }

    if (["graph_updated", "correlation_completed", "threat_intel_enrichment", "alert_created"].includes(message.type)) {
      await loadGraph();
    }

    setLiveNotice("Live update received");
    await refreshSlices(["alerts", "incidents", "activity"]);
  }

  async function loadGraph() {
    try {
      setGraphStatus("loading");
      setGraphError("");
      const result = await apiGet(buildGraphPath(graphFilters));
      setGraphData(result);
      setSelectedGraphNode((currentNode) =>
        currentNode ? result.nodes.find((node) => node.id === currentNode.id) ?? null : null,
      );
      setGraphStatus("ready");
    } catch (requestError) {
      setGraphError(requestError.message);
      setGraphStatus("error");
    }
  }

  function handleGraphFilterChange(name, value) {
    setGraphFilters((currentFilters) => ({
      ...currentFilters,
      [name]: value,
    }));
  }

  function buildPayload() {
    const form = forms[activeForm];

    if (activeForm === "asset") {
      return {
        hostname: form.hostname.trim(),
        ip_address: form.ip_address.trim() || null,
        operating_system: form.operating_system.trim() || null,
        role: form.role.trim() || null,
        status: form.status,
      };
    }

    if (activeForm === "event") {
      return {
        event_type: form.event_type.trim(),
        source: form.source.trim() || "dashboard",
        source_ip: form.source_ip.trim() || null,
        destination_ip: form.destination_ip.trim() || null,
        username: form.username.trim() || null,
        raw_message: form.raw_message.trim() || null,
        summary: form.raw_message.trim() || null,
        severity: form.severity,
      };
    }

    if (activeForm === "alert") {
      return {
        title: form.title.trim(),
        description: form.description.trim() || null,
        severity: form.severity,
        status: form.status,
        event_id: cleanOptionalNumber(form.event_id),
      };
    }

    return {
      title: form.title.trim(),
      description: form.description.trim() || null,
      summary: form.description.trim() || null,
      severity: form.severity,
      status: form.status,
      alert_id: cleanOptionalNumber(form.alert_id),
    };
  }

  function validateForm() {
    const form = forms[activeForm];

    if (activeForm === "asset" && !form.hostname.trim()) return "Hostname is required.";
    if (activeForm === "event" && !form.event_type.trim()) return "Event type is required.";
    if (activeForm === "event" && !form.source.trim()) return "Source is required.";
    if (activeForm === "alert" && !form.title.trim()) return "Alert title is required.";
    if (activeForm === "incident" && !form.title.trim()) return "Incident title is required.";

    return "";
  }

  async function handleCreateRecord(event) {
    event.preventDefault();
    const validationError = validateForm();

    if (validationError) {
      setSubmitError(validationError);
      setSubmitMessage("");
      return;
    }

    const createConfig = {
      asset: { path: "/api/assets/", refresh: ["assets", "activity"] },
      event: { path: "/api/events/", refresh: ["events", "activity"] },
      alert: { path: "/api/alerts/", refresh: ["alerts", "activity"] },
      incident: { path: "/api/incidents/", refresh: ["incidents", "activity"] },
    }[activeForm];

    try {
      setSubmitState("submitting");
      setSubmitError("");
      setSubmitMessage("");
      await apiPost(createConfig.path, buildPayload());
      await refreshSlices(createConfig.refresh);
      setForms((currentForms) => ({ ...currentForms, [activeForm]: initialForms[activeForm] }));
      setSubmitMessage(`${activeForm} created successfully.`);
    } catch (requestError) {
      setSubmitError(requestError.message);
    } finally {
      setSubmitState("idle");
    }
  }

  async function handleAlertStatusChange(alertId, nextStatus) {
    try {
      setUpdatingKey(`alert-${alertId}`);
      await apiPatch(`/api/alerts/${alertId}/status`, { status: nextStatus });
      await refreshSlices(["alerts", "activity"]);
    } catch (requestError) {
      setError(requestError.message);
      setStatus("error");
    } finally {
      setUpdatingKey("");
    }
  }

  async function handleIncidentStatusChange(incidentId, nextStatus) {
    try {
      setUpdatingKey(`incident-${incidentId}`);
      await apiPatch(`/api/incidents/${incidentId}/status`, { status: nextStatus });
      await refreshSlices(["incidents", "activity"]);
    } catch (requestError) {
      setError(requestError.message);
      setStatus("error");
    } finally {
      setUpdatingKey("");
    }
  }

  async function handleRunDetectionEngine() {
    try {
      setDetectionState("running");
      setDetectionError("");
      const result = await apiPost("/api/detections/run", {});
      setDetectionResult(result);
      await refreshSlices(["alerts", "activity"]);
    } catch (requestError) {
      setDetectionError(requestError.message);
    } finally {
      setDetectionState("idle");
    }
  }

  async function handleRunThreatIntel() {
    try {
      setThreatState("running");
      setThreatError("");
      const result = await apiPost("/api/threat-intel/enrich", {});
      setThreatResult(result);
      await refreshSlices(["events", "alerts", "activity"]);
    } catch (requestError) {
      setThreatError(requestError.message);
    } finally {
      setThreatState("idle");
    }
  }

  async function handleRunCorrelationEngine() {
    try {
      setCorrelationState("running");
      setCorrelationError("");
      const result = await apiPost("/api/correlation/run", {});
      setCorrelationResult(result);
      await refreshSlices(["activity"]);
    } catch (requestError) {
      setCorrelationError(requestError.message);
    } finally {
      setCorrelationState("idle");
    }
  }

  return (
    <main className="app-shell">
      <section className="page-header">
        <p>HexSOC AI</p>
        <h1>SOC Command Dashboard</h1>
        <div className="status-line">
          <span>Live backend: {import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:9000"}</span>
          <RealtimeBadge status={realtimeStatus} />
        </div>
        {liveNotice && <div className="live-toast">{liveNotice}</div>}
      </section>

      {status === "loading" && <div className="state-panel">Loading live SOC data...</div>}

      {status === "error" && (
        <div className="state-panel error-panel">
          <strong>Unable to load dashboard data.</strong>
          <p>{error}</p>
        </div>
      )}

      {status === "ready" && (
        <CreateRecordPanel
          activeForm={activeForm}
          forms={forms}
          submitState={submitState}
          submitMessage={submitMessage}
          submitError={submitError}
          onTabChange={(nextForm) => {
            setActiveForm(nextForm);
            setSubmitMessage("");
            setSubmitError("");
          }}
          onFieldChange={handleFieldChange}
          onSubmit={handleCreateRecord}
        />
      )}

      {status === "ready" && (
        <DetectionPanel
          detectionState={detectionState}
          detectionResult={detectionResult}
          detectionError={detectionError}
          onRun={handleRunDetectionEngine}
        />
      )}

      {status === "ready" && (
        <ThreatIntelPanel
          threatState={threatState}
          threatResult={threatResult}
          threatError={threatError}
          onRun={handleRunThreatIntel}
        />
      )}

      {status === "ready" && (
        <CorrelationPanel
          correlationState={correlationState}
          correlationResult={correlationResult}
          correlationError={correlationError}
          onRun={handleRunCorrelationEngine}
        />
      )}

      {status === "ready" && (
        <GraphInvestigationPanel
          graphData={graphData}
          graphStatus={graphStatus}
          graphError={graphError}
          graphFilters={graphFilters}
          selectedNode={selectedGraphNode}
          zoom={graphZoom}
          onFilterChange={handleGraphFilterChange}
          onRefresh={loadGraph}
          onNodeSelect={setSelectedGraphNode}
          onZoomChange={setGraphZoom}
        />
      )}

      {status === "ready" && totalRecords === 0 && (
        <div className="state-panel">
          Production database is connected. Create a SOC record or load demo data.
        </div>
      )}

      {status === "ready" && (
        <div className="dashboard-grid">
          {sections.map((section) => (
            <DataSection key={section.key} section={section} items={data[section.key]} />
          ))}
          <AlertSection
            alerts={data.alerts}
            onStatusChange={handleAlertStatusChange}
            updatingKey={updatingKey}
          />
          <IncidentSection
            incidents={data.incidents}
            onStatusChange={handleIncidentStatusChange}
            updatingKey={updatingKey}
          />
          <ActivitySection activity={data.activity} />
        </div>
      )}
    </main>
  );
}
