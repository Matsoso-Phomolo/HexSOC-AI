import { useEffect, useMemo, useRef, useState } from "react";

import {
  API_BASE_URL,
  apiGet,
  apiPatch,
  apiPost,
  clearStoredToken,
  fetchDashboardData,
  getAttackChains,
  getAttackChainTimeline,
  getCampaigns,
  getThreatIntelRelationshipSummary,
  getThreatIntelSyncStatus,
  getStoredToken,
  graphEnrichIOC,
  login,
  register,
  rebuildAttackChains,
  correlateIndicators,
  searchThreatIntel,
  setStoredToken,
} from "../api/client.js";
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
  destination_ip: "#67e8f9",
  asset: "#a5b4fc",
  user: "#86efac",
  process: "#fbbf24",
  event: "#facc15",
  event_cluster: "#facc15",
  alert: "#fb7185",
  alert_cluster: "#fb7185",
  cluster_member: "#64748b",
  incident: "#f97316",
  threat_intel: "#c084fc",
  mitre_technique: "#c084fc",
};

const sampleIngestionLogs = {
  logs: [
    {
      timestamp: "2026-05-08T10:00:00Z",
      event_type: "failed_login",
      source: "windows_event_log",
      source_ip: "203.0.113.45",
      destination_ip: "10.0.0.10",
      username: "svc_backup",
      hostname: "prod-web-01",
      severity: "medium",
      raw_message: "Failed login attempt for svc_backup from external source.",
    },
    {
      timestamp: "2026-05-08T10:01:00Z",
      event_type: "failed_login",
      source: "windows_event_log",
      source_ip: "203.0.113.45",
      destination_ip: "10.0.0.10",
      username: "svc_backup",
      hostname: "prod-web-01",
      severity: "medium",
      raw_message: "Repeated failed login attempt for svc_backup.",
    },
    {
      timestamp: "2026-05-08T10:02:00Z",
      event_type: "failed_login",
      source: "windows_event_log",
      source_ip: "203.0.113.45",
      destination_ip: "10.0.0.10",
      username: "svc_backup",
      hostname: "prod-web-01",
      severity: "medium",
      raw_message: "Repeated failed login attempt for svc_backup.",
    },
    {
      timestamp: "2026-05-08T10:03:00Z",
      event_type: "failed_login",
      source: "windows_event_log",
      source_ip: "203.0.113.45",
      destination_ip: "10.0.0.10",
      username: "svc_backup",
      hostname: "prod-web-01",
      severity: "high",
      raw_message: "Repeated failed login attempt for svc_backup.",
    },
    {
      timestamp: "2026-05-08T10:04:00Z",
      event_type: "failed_login",
      source: "windows_event_log",
      source_ip: "203.0.113.45",
      destination_ip: "10.0.0.10",
      username: "svc_backup",
      hostname: "prod-web-01",
      severity: "high",
      raw_message: "Fifth failed login attempt for svc_backup.",
    },
    {
      timestamp: "2026-05-08T10:11:00Z",
      event_type: "malware_indicator",
      source: "edr",
      source_ip: "10.0.22.47",
      destination_ip: "10.0.22.47",
      username: "jane.finance",
      hostname: "finance-laptop-07",
      severity: "critical",
      raw_message: "Trojan loader behavior detected with ransomware staging indicators.",
    },
  ],
};

const sampleWindowsSysmonEvents = {
  events: [
    {
      ProviderName: "Microsoft-Windows-Sysmon",
      EventID: 1,
      UtcTime: "2026-05-08T11:00:00Z",
      Computer: "finance-laptop-07",
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      CommandLine: "powershell.exe -NoP -EncodedCommand SQBFAFgA",
      User: "CORP\\jane.finance",
      Message: "Process Create: PowerShell encoded command observed.",
    },
    {
      ProviderName: "Microsoft-Windows-Security-Auditing",
      EventID: 4625,
      TimeCreated: "2026-05-08T11:03:00Z",
      Computer: "prod-web-01",
      IpAddress: "203.0.113.45",
      TargetUserName: "svc_backup",
      TargetDomainName: "CORP",
      Message: "An account failed to log on.",
    },
    {
      ProviderName: "Microsoft-Windows-Sysmon",
      EventID: 10,
      UtcTime: "2026-05-08T11:10:00Z",
      Computer: "finance-laptop-07",
      SourceImage: "C:\\Tools\\procdump.exe",
      TargetImage: "C:\\Windows\\System32\\lsass.exe",
      CommandLine: "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp",
      User: "CORP\\jane.finance",
      Message: "Process accessed LSASS memory.",
    },
    {
      ProviderName: "Microsoft-Windows-Sysmon",
      EventID: 22,
      UtcTime: "2026-05-08T11:12:00Z",
      Computer: "finance-laptop-07",
      SourceIp: "10.0.22.47",
      QueryName: "a92js8d7f6s5d4f3g2h1.example",
      Message: "DNS query for unusual generated-looking domain.",
    },
  ],
};

const initialCollectorForm = {
  name: "",
  description: "",
  collector_type: "sysmon",
  source_label: "",
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

function formatRelativeAge(value) {
  if (!value) return "No heartbeat";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
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

function MitreBadges({ item }) {
  const techniqueId = item.mitre_technique_id;
  const technique = item.mitre_technique;
  const tactic = item.mitre_tactic;
  const confidence = item.mitre_confidence ?? item.confidence_score;

  if (!techniqueId && !technique && !tactic) return null;

  return (
    <div className="mitre-badge-row">
      {techniqueId && <span className="mitre-badge">{techniqueId}</span>}
      {technique && <span className="mitre-badge">{technique}</span>}
      {tactic && <span className="mitre-badge">{tactic}</span>}
      {confidence && <span className="mitre-badge">Confidence {confidence}</span>}
    </div>
  );
}

function buildGraphPath(filters) {
  const params = new URLSearchParams();
  const sourceIp = (filters.source_ip ?? "").trim();
  const severity = (filters.severity ?? "").trim();
  const nodeType = (filters.node_type ?? "").trim();
  const mitreTactic = (filters.mitre_tactic ?? "").trim();
  const hostname = (filters.hostname ?? "").trim();
  const timeWindow = (filters.time_window ?? "").trim();
  const limit = Number.parseInt(filters.limit, 10);

  if (sourceIp) params.set("source_ip", sourceIp);
  if (severity) params.set("severity", severity);
  if (nodeType) params.set("node_type", nodeType);
  if (mitreTactic) params.set("mitre_tactic", mitreTactic);
  if (hostname) params.set("hostname", hostname);
  if (timeWindow) params.set("time_window", timeWindow);
  if (filters.cluster_mode === false) params.set("aggregate", "false");
  if (Number.isInteger(limit) && limit >= 1 && limit <= 500) {
    params.set("limit", String(limit));
  }

  const query = params.toString();
  return `/api/graph/investigation${query ? `?${query}` : ""}`;
}

function layoutGraph(nodes, physicsEnabled = false) {
  const centerX = 520;
  const centerY = 260;
  const typeLayout = {
    source_ip: { radius: 55, yScale: 0.55, xOffset: 0 },
    asset: { radius: 155, yScale: 0.6, xOffset: 0 },
    user: { radius: 210, yScale: 0.55, xOffset: -70 },
    process: { radius: 235, yScale: 0.55, xOffset: -40 },
    destination_ip: { radius: 245, yScale: 0.55, xOffset: 60 },
    event_cluster: { radius: 295, yScale: 0.58, xOffset: -80 },
    alert_cluster: { radius: 335, yScale: 0.58, xOffset: 0 },
    event: { radius: 360, yScale: 0.58, xOffset: -90 },
    alert: { radius: 370, yScale: 0.58, xOffset: 20 },
    cluster_member: { radius: 390, yScale: 0.58, xOffset: -20 },
    incident: { radius: 405, yScale: 0.52, xOffset: 70 },
    mitre_technique: { radius: 0, yScale: 1, xOffset: 390 },
  };
  const grouped = nodes.reduce((groups, node) => {
    const key = node.type ?? "unknown";
    groups[key] = groups[key] ?? [];
    groups[key].push(node);
    return groups;
  }, {});

  return nodes.map((node, index) => {
    const siblings = grouped[node.type] ?? nodes;
    const siblingIndex = siblings.findIndex((item) => item.id === node.id);
    const layout = typeLayout[node.type] ?? { radius: 260, yScale: 0.58, xOffset: 0 };
    const radius = layout.radius;
    const angle = (Math.PI * 2 * Math.max(siblingIndex, 0)) / Math.max(siblings.length, 1) - Math.PI / 2;
    const collisionOffset = physicsEnabled ? (index % 7) * 13 : (index % 4) * 8;
    const mitreY = 90 + (siblingIndex * 74) % 380;

    return {
      ...node,
      x: node.type === "mitre_technique" ? centerX + layout.xOffset : centerX + layout.xOffset + Math.cos(angle) * (radius + collisionOffset),
      y: node.type === "mitre_technique" ? mitreY : centerY + Math.sin(angle) * (radius * layout.yScale + collisionOffset),
    };
  });
}

function graphNeighbors(nodeId, edges) {
  const related = new Set([nodeId]);
  edges.forEach((edge) => {
    if (edge.source === nodeId) related.add(edge.target);
    if (edge.target === nodeId) related.add(edge.source);
  });
  return related;
}

function shouldShowGraphLabel(node, selectedNode, hoveredNodeId, zoom, showAllLabels) {
  if (showAllLabels) return true;
  if (selectedNode?.id === node.id) return true;
  if (hoveredNodeId === node.id) return true;
  if (node.severity === "critical") return true;
  if (zoom >= 135 && !["event", "alert", "cluster_member"].includes(node.type)) return true;
  return false;
}

function graphNodeRadius(node) {
  const count = Number(node.metadata?.count ?? 0);
  const clusterBoost = count > 0 ? Math.min(12, Math.log2(count + 1) * 4) : 0;
  const riskBoost = node.risk_score >= 70 || ["high", "critical"].includes(node.severity) ? 5 : 0;
  const base = ["event_cluster", "alert_cluster"].includes(node.type) ? 20 : 17;
  return base + clusterBoost + riskBoost;
}

function deduplicateGraphNodes(nodes) {
  return Array.from(new Map(nodes.map((node) => [node.id, node])).values());
}

function expandGraphClusters(nodes, edges, expandedClusterIds) {
  const expandedNodes = [...nodes];
  const expandedEdges = [...edges];

  nodes.forEach((node) => {
    if (!expandedClusterIds.includes(node.id)) return;
    const eventIds = node.metadata?.sample_event_ids ?? [];
    const alertIds = node.metadata?.sample_alert_ids ?? [];
    eventIds.slice(0, 8).forEach((eventId) => {
      const childId = `${node.id}:event:${eventId}`;
      expandedNodes.push({
        id: childId,
        label: `Event ${eventId}`,
        type: "cluster_member",
        severity: node.severity,
        risk_score: Math.max(0, Number(node.risk_score ?? 0) - 10),
        metadata: { id: eventId, parent_cluster: node.id, member_type: "event" },
      });
      expandedEdges.push({ id: `edge:${node.id}-${childId}`, source: node.id, target: childId, relationship: "contains" });
    });
    alertIds.slice(0, 8).forEach((alertId) => {
      const childId = `${node.id}:alert:${alertId}`;
      expandedNodes.push({
        id: childId,
        label: `Alert ${alertId}`,
        type: "cluster_member",
        severity: node.severity,
        risk_score: Math.max(0, Number(node.risk_score ?? 0) - 5),
        metadata: { id: alertId, parent_cluster: node.id, member_type: "alert" },
      });
      expandedEdges.push({ id: `edge:${node.id}-${childId}`, source: node.id, target: childId, relationship: "contains" });
    });
  });

  return { nodes: deduplicateGraphNodes(expandedNodes), edges: expandedEdges };
}

function normalizeGraphEdges(edges, nodes, edgeVisibility) {
  const nodeById = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const threshold = Number(edgeVisibility ?? 0);
  return edges.filter((edge) => {
    const source = nodeById[edge.source];
    const target = nodeById[edge.target];
    if (!source || !target) return false;
    if (threshold <= 0) return true;
    return Math.max(Number(source.risk_score ?? 0), Number(target.risk_score ?? 0)) >= threshold;
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

function PasswordField({ value, onChange }) {
  const [isVisible, setIsVisible] = useState(false);

  return (
    <label>
      <span>Password</span>
      <div className="password-field">
        <input
          name="password"
          type={isVisible ? "text" : "password"}
          value={value}
          required
          onChange={(event) => onChange("password", event.target.value)}
        />
        <button
          type="button"
          aria-label={isVisible ? "Hide password" : "Show password"}
          title={isVisible ? "Hide password" : "Show password"}
          onClick={() => setIsVisible((current) => !current)}
        >
          <svg aria-hidden="true" viewBox="0 0 24 24">
            {isVisible ? (
              <>
                <path d="M3 3l18 18" />
                <path d="M10.58 10.58A2 2 0 0 0 12 14a2 2 0 0 0 1.42-.58" />
                <path d="M9.88 5.09A9.77 9.77 0 0 1 12 4c5 0 9 5 9 8a9.58 9.58 0 0 1-2.19 3.84" />
                <path d="M6.61 6.61C4.4 8.14 3 10.42 3 12c0 3 4 8 9 8a9.77 9.77 0 0 0 3.39-.61" />
              </>
            ) : (
              <>
                <path d="M2.5 12s3.5-7 9.5-7 9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7z" />
                <circle cx="12" cy="12" r="3" />
              </>
            )}
          </svg>
        </button>
      </div>
    </label>
  );
}

function AuthScreen({ authMode, authForm, authError, authState, onModeChange, onFieldChange, onSubmit }) {
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <p>HexSOC AI</p>
        <h1>HexSOC AI Secure Access</h1>
        <p className="auth-subtitle">Sign in to the Security Operations Command Center.</p>
        <form className="record-form" onSubmit={onSubmit}>
          {authMode === "register" && (
            <>
              <Field label="Full name" name="full_name" value={authForm.full_name} required onChange={onFieldChange} />
              <Field label="Email" name="email" value={authForm.email} required onChange={onFieldChange} />
            </>
          )}
          <Field label="Username or email" name="username" value={authForm.username} required onChange={onFieldChange} />
          {authMode === "register" && (
            <SelectField
              label="Role"
              name="role"
              value={authForm.role}
              onChange={onFieldChange}
              options={["analyst", "viewer", "admin"]}
            />
          )}
          <PasswordField value={authForm.password} onChange={onFieldChange} />
          <div className="form-footer">
            <button type="submit" disabled={authState === "loading"}>
              {authState === "loading" ? "Please wait..." : authMode === "login" ? "Sign in" : "Create account"}
            </button>
            <button type="button" onClick={() => onModeChange(authMode === "login" ? "register" : "login")}>
              {authMode === "login" ? "Request / Create account" : "Back to sign in"}
            </button>
            {authError && <span className="form-error">{authError}</span>}
          </div>
        </form>
      </section>
    </main>
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
                <MitreBadges item={item} />
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
  canOperate,
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
          <button type="submit" disabled={!canOperate || submitState === "submitting"}>
            {submitState === "submitting" ? "Creating..." : `Create ${activeForm}`}
          </button>
          {submitMessage && <span className="success-message">{submitMessage}</span>}
          {submitError && <span className="form-error">{submitError}</span>}
        </div>
      </form>
    </section>
  );
}

function DetectionPanel({ detectionState, detectionResult, detectionError, onRun, canOperate }) {
  return (
    <section className="detection-panel">
      <div>
        <h2>Detection Engine</h2>
        <p>Run deterministic SOC rules against recent security events before AI enrichment.</p>
      </div>
      <button type="button" disabled={!canOperate || detectionState === "running"} onClick={onRun}>
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

function LogIngestionPanel({
  mode,
  value,
  autoDetect,
  state,
  result,
  error,
  onModeChange,
  onChange,
  onAutoDetectChange,
  onLoadSample,
  onLoadWindowsSample,
  onIngest,
  canOperate,
}) {
  return (
    <section className="ingestion-panel">
      <div className="section-heading">
        <div>
          <h2>Log Ingestion Pipeline</h2>
          <p>Paste normalized JSON telemetry from Sysmon, EDR, DNS, firewall, or collector pipelines.</p>
        </div>
        <div className="ingestion-header-actions">
          <button type="button" onClick={onLoadSample}>
            Load Normalized Sample
          </button>
          <button type="button" onClick={onLoadWindowsSample}>
            Load Windows/Sysmon Sample
          </button>
        </div>
      </div>

      <div className="ingestion-mode-row">
        <label>
          <span>Ingestion mode</span>
          <select value={mode} onChange={(event) => onModeChange(event.target.value)}>
            <option value="normalized">Normalized JSON</option>
            <option value="windows">Windows/Sysmon JSON</option>
          </select>
        </label>
      </div>

      <label className="ingestion-textarea">
        <span>{mode === "windows" ? "Windows/Sysmon JSON events" : "Normalized JSON logs"}</span>
        <textarea
          value={value}
          rows={10}
          placeholder='{"logs":[{"event_type":"failed_login","source":"windows_event_log","severity":"high"}]}'
          onChange={(event) => onChange(event.target.value)}
        />
      </label>

      <div className="ingestion-actions">
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={autoDetect}
            disabled={!canOperate || state === "running"}
            onChange={(event) => onAutoDetectChange(event.target.checked)}
          />
          <span>Run detection after ingest</span>
        </label>
        <button type="button" disabled={!canOperate || state === "running"} onClick={onIngest}>
          {state === "running" ? "Ingesting..." : "Ingest Logs"}
        </button>
      </div>

      {!canOperate && <p className="empty-state">Viewer role is read-only. Admin or analyst access is required to ingest logs.</p>}
      {error && <span className="form-error">{error}</span>}

      {result && (
        <div className="detection-result">
          <span>Received: {result.received}</span>
          {mode === "windows" && <span>Parsed: {result.received - (result.validation_errors?.length ?? 0)}</span>}
          <span>Ingested: {result.ingested}</span>
          <span>Skipped: {result.skipped}</span>
          <span>Assets created: {result.assets_created}</span>
          <span>Detections: {result.detections_run ? "run" : "not run"}</span>
          <span>Alerts: {result.detection_summary?.alerts_created ?? 0}</span>
        </div>
      )}

      {result?.validation_errors?.length > 0 && (
        <ul className="ingestion-errors">
          {result.validation_errors.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ThreatIntelPanel({ threatState, threatResult, threatError, onRun, canOperate }) {
  return (
    <section className="threat-panel">
      <div>
        <h2>Threat Intelligence</h2>
        <p>Enrich source IPs with AbuseIPDB, VirusTotal, GeoIP, and Shodan-ready provider context.</p>
      </div>
      <button type="button" disabled={!canOperate || threatState === "running"} onClick={onRun}>
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

function IOCInvestigationPanel({
  syncStatus,
  relationshipSummary,
  state,
  error,
  searchQuery,
  searchResult,
  searchState,
  correlationInput,
  correlationResult,
  correlationState,
  graphForm,
  graphResult,
  graphState,
  onSearchQueryChange,
  onCorrelationInputChange,
  onGraphFormChange,
  onSearch,
  onCorrelate,
  onGraphEnrich,
  onRefresh,
  canOperate,
}) {
  const activeIocs = syncStatus?.active_iocs ?? 0;
  const highSeverityIocs = (searchResult?.indicators ?? []).filter((ioc) => ["high", "critical"].includes(ioc.severity)).length;
  const recentMatches = relationshipSummary?.recent_relationships ?? [];
  const topRelationship = relationshipSummary?.by_entity_type?.[0];

  return (
    <section className="ioc-panel">
      <div className="section-heading">
        <div>
          <h2>IOC Intelligence</h2>
          <p>Search, correlate, and preview threat intelligence relationships without expanding the full graph.</p>
        </div>
        <button type="button" disabled={state === "loading"} onClick={onRefresh}>
          {state === "loading" ? "Refreshing..." : "Refresh IOC Intel"}
        </button>
      </div>

      {error && <span className="form-error">{error}</span>}

      <div className="ioc-summary-grid">
        <div><span>Active IOCs</span><strong>{activeIocs}</strong></div>
        <div><span>High severity in results</span><strong>{highSeverityIocs}</strong></div>
        <div><span>Relationships</span><strong>{relationshipSummary?.total_relationships ?? 0}</strong></div>
        <div><span>Top relation</span><strong>{topRelationship ? `${topRelationship.entity_type} (${topRelationship.count})` : "none"}</strong></div>
      </div>

      <div className="ioc-workspace">
        <form className="ioc-card" onSubmit={onSearch}>
          <h3>IOC Search</h3>
          <input value={searchQuery} onChange={(event) => onSearchQueryChange(event.target.value)} placeholder="IP, domain, URL, hash, email, CVE" />
          <button type="submit" disabled={searchState === "loading"}>{searchState === "loading" ? "Searching..." : "Search IOC"}</button>
          {searchResult?.indicators?.length ? (
            <ul className="ioc-list">
              {searchResult.indicators.slice(0, 5).map((ioc) => (
                <li key={ioc.id}>
                  <strong>{ioc.ioc_type}: {ioc.normalized_value}</strong>
                  <p>{ioc.severity} | confidence {ioc.confidence_score} | sources {ioc.source_count ?? 1}</p>
                  <div className="threat-badge-row">
                    {(ioc.tags ?? []).slice(0, 4).map((tag) => <span key={`${ioc.id}-${tag}`} className="threat-badge">{tag}</span>)}
                    <span className="threat-badge">{ioc.is_active ? "active" : "expired"}</span>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty-state">No IOC search results yet.</p>
          )}
        </form>

        <form className="ioc-card" onSubmit={onCorrelate}>
          <h3>Correlation Test</h3>
          <textarea value={correlationInput} rows={4} onChange={(event) => onCorrelationInputChange(event.target.value)} placeholder="One indicator per line" />
          <button type="submit" disabled={!canOperate || correlationState === "loading"}>{correlationState === "loading" ? "Correlating..." : "Correlate Indicators"}</button>
          {correlationResult ? (
            <div className="ioc-result">
              <span>Matched IOCs: {correlationResult.matches_found}</span>
              <span>Risk amplification: {correlationResult.risk_amplification}</span>
              <span>Inputs checked: {correlationResult.inputs_checked}</span>
            </div>
          ) : (
            <p className="empty-state">Run a bounded IOC correlation test.</p>
          )}
        </form>

        <form className="ioc-card" onSubmit={onGraphEnrich}>
          <h3>Graph Enrichment Preview</h3>
          <div className="ioc-inline-fields">
            <select value={graphForm.entity_type} onChange={(event) => onGraphFormChange("entity_type", event.target.value)}>
              <option value="alert">alert</option>
              <option value="event">event</option>
              <option value="asset">asset</option>
              <option value="incident">incident</option>
            </select>
            <input value={graphForm.entity_id} onChange={(event) => onGraphFormChange("entity_id", event.target.value)} placeholder="Entity ID" />
          </div>
          <textarea value={graphForm.indicators} rows={4} onChange={(event) => onGraphFormChange("indicators", event.target.value)} placeholder="Indicators, one per line" />
          <button type="submit" disabled={!canOperate || graphState === "loading"}>{graphState === "loading" ? "Building..." : "Preview Graph Enrichment"}</button>
          {graphResult ? (
            <div className="ioc-result">
              <span>Entity: {graphResult.entity_node?.id}</span>
              <span>IOC nodes: {graphResult.ioc_nodes?.length ?? 0}</span>
              <span>Relationships: {graphResult.relationships?.length ?? 0}</span>
              <span>Max weight: {graphResult.summary?.max_weight ?? 0}</span>
              <span>Risk amplification: {graphResult.summary?.risk_amplification ?? 0}</span>
            </div>
          ) : (
            <p className="empty-state">Preview weighted IOC relationships for one entity.</p>
          )}
        </form>
      </div>

      <div className="ioc-relationship-strip">
        <strong>Relationship Summary</strong>
        <span>Top IOC types: {relationshipSummary?.top_ioc_types?.length ? relationshipSummary.top_ioc_types.map((item) => `${item.ioc_type} (${item.count})`).join(", ") : "none"}</span>
        <span>Highest weighted: {relationshipSummary?.highest_weighted_relationships?.length ? relationshipSummary.highest_weighted_relationships.slice(0, 3).map((item) => `${item.ioc_type}:${item.ioc_value} w${item.weight}`).join(", ") : "none"}</span>
        <span>Recent activity: {recentMatches.length} links</span>
      </div>
    </section>
  );
}

function MitreCoveragePanel({ coverage, state, error, onRun, onRefresh, canOperate }) {
  return (
    <section className="mitre-panel">
      <div className="section-heading">
        <div>
          <h2>MITRE ATT&CK Coverage</h2>
          <p>Map normalized telemetry and detections to ATT&CK tactics and techniques.</p>
        </div>
        <div className="ingestion-header-actions">
          <button type="button" disabled={state === "running"} onClick={onRefresh}>
            Refresh Coverage
          </button>
          <button type="button" disabled={!canOperate || state === "running"} onClick={onRun}>
            {state === "running" ? "Mapping..." : "Run MITRE Mapping"}
          </button>
        </div>
      </div>

      {error && <span className="form-error">{error}</span>}
      {coverage && (
        <>
          <div className="report-summary-grid">
            <div className="report-summary-card">
              <span>Mapped events</span>
              <strong>{coverage.mapped_events} / {coverage.total_events}</strong>
            </div>
            <div className="report-summary-card">
              <span>Mapped alerts</span>
              <strong>{coverage.mapped_alerts} / {coverage.total_alerts}</strong>
            </div>
            <div className="report-summary-card report-wide-card">
              <span>Top techniques</span>
              <strong>{coverage.top_techniques?.map((item) => `${item.name} (${item.count})`).join(", ") || "None yet"}</strong>
            </div>
            <div className="report-summary-card report-wide-card">
              <span>Top tactics</span>
              <strong>{coverage.top_tactics?.map((item) => `${item.name} (${item.count})`).join(", ") || "None yet"}</strong>
            </div>
          </div>
        </>
      )}
    </section>
  );
}

function GraphInvestigationPanel({
  graphData,
  graphStatus,
  graphError,
  graphFilters,
  graphControls,
  selectedNode,
  hoveredNodeId,
  expandedClusterIds,
  zoom,
  onFilterChange,
  onControlChange,
  onRefresh,
  onNodeSelect,
  onNodeHover,
  onToggleCluster,
  onAnalyzeNode,
  onZoomChange,
  canOperate,
}) {
  const expandedGraph = expandGraphClusters(deduplicateGraphNodes(graphData?.nodes ?? []), graphData?.edges ?? [], expandedClusterIds);
  const edges = normalizeGraphEdges(expandedGraph.edges, expandedGraph.nodes, graphControls.edgeVisibility);
  const nodes = layoutGraph(expandedGraph.nodes, graphControls.physicsEnabled);
  const renderNodes = [...nodes].sort((left, right) => {
    const rank = (node) => {
      if (selectedNode?.id === node.id) return 4;
      if (["event_cluster", "alert_cluster"].includes(node.type)) return 3;
      if (node.type === "cluster_member") return 2;
      return 1;
    };
    return rank(left) - rank(right);
  });
  const nodeById = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const summary = graphData?.summary ?? {};
  const focusedNodeIds = selectedNode ? graphNeighbors(selectedNode.id, edges) : null;
  const topSources = summary.top_source_ips ?? [];
  const topTechniques = summary.top_techniques ?? [];
  const connectedAssets = summary.most_connected_assets ?? [];

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
          <span>Node type</span>
          <select value={graphFilters.node_type} onChange={(event) => onFilterChange("node_type", event.target.value)}>
            <option value="">Any node type</option>
            <option value="asset">asset</option>
            <option value="user">user</option>
            <option value="source_ip">source_ip</option>
            <option value="destination_ip">destination_ip</option>
            <option value="process">process</option>
            <option value="event_cluster">event_cluster</option>
            <option value="alert_cluster">alert_cluster</option>
            <option value="incident">incident</option>
            <option value="mitre_technique">mitre_technique</option>
          </select>
        </label>
        <label>
          <span>MITRE tactic</span>
          <input
            value={graphFilters.mitre_tactic}
            onChange={(event) => onFilterChange("mitre_tactic", event.target.value)}
            placeholder="Any tactic"
          />
        </label>
        <label>
          <span>Hostname</span>
          <input
            value={graphFilters.hostname}
            onChange={(event) => onFilterChange("hostname", event.target.value)}
            placeholder="Any host"
          />
        </label>
        <label>
          <span>Time window</span>
          <select value={graphFilters.time_window} onChange={(event) => onFilterChange("time_window", event.target.value)}>
            <option value="">All recent data</option>
            <option value="1h">Last 1 hour</option>
            <option value="6h">Last 6 hours</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
        </label>
        <label>
          <span>Max nodes</span>
          <input
            type="number"
            min="1"
            max="150"
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
        <label className="graph-toggle-control">
          <span>Labels</span>
          <button type="button" onClick={() => onControlChange("showLabels", !graphControls.showLabels)}>
            {graphControls.showLabels ? "Labels on" : "Labels off"}
          </button>
        </label>
        <label className="graph-toggle-control">
          <span>Physics</span>
          <button type="button" onClick={() => onControlChange("physicsEnabled", !graphControls.physicsEnabled)}>
            {graphControls.physicsEnabled ? "Physics on" : "Physics off"}
          </button>
        </label>
        <label className="graph-toggle-control">
          <span>Cluster mode</span>
          <button type="button" onClick={() => onFilterChange("cluster_mode", graphFilters.cluster_mode === false)}>
            {graphFilters.cluster_mode === false ? "Raw mode" : "Clustered"}
          </button>
        </label>
        <label>
          <span>Edge visibility</span>
          <input
            type="range"
            min="0"
            max="90"
            value={graphControls.edgeVisibility}
            onChange={(event) => onControlChange("edgeVisibility", Number(event.target.value))}
          />
        </label>
      </div>

      {graphError && <span className="form-error">{graphError}</span>}

      {graphData && (
        <div className="graph-intelligence">
          <div className="graph-summary">
            <span>{summary.nodes ?? 0} nodes</span>
            <span>{edges.length} visible edges</span>
            <span>{summary.edges ?? 0} server edges</span>
            <span>{summary.high_risk_nodes ?? 0} high risk</span>
            <span>{summary.high_risk_clusters ?? 0} high-risk clusters</span>
            <span>{summary.aggregation ?? "raw"} view</span>
          </div>
          <div className="graph-insights">
            <div>
              <strong>Top source IPs</strong>
              <p>{topSources.length ? topSources.map((item) => `${item.label} (${item.count})`).join(", ") : "No source IP concentration yet"}</p>
            </div>
            <div>
              <strong>Top techniques</strong>
              <p>{topTechniques.length ? topTechniques.map((item) => `${item.label} (${item.count})`).join(", ") : "No MITRE techniques mapped yet"}</p>
            </div>
            <div>
              <strong>Most connected assets</strong>
              <p>{connectedAssets.length ? connectedAssets.map((item) => `${item.label} (${item.count})`).join(", ") : "No asset relationships yet"}</p>
            </div>
          </div>
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
              const focused = !focusedNodeIds || (focusedNodeIds.has(edge.source) && focusedNodeIds.has(edge.target));
              const showEdgeLabel = focusedNodeIds ? focused : zoom >= 135;

              return (
                <g key={edge.id}>
                  <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} className={`graph-edge ${focused ? "" : "graph-dim"}`} />
                  {showEdgeLabel && (
                    <text x={midX} y={midY} className={`graph-edge-label ${focused ? "" : "graph-dim"}`}>
                      {edge.relationship}
                    </text>
                  )}
                </g>
              );
            })}

            {renderNodes.map((node) => {
              const highRisk = node.risk_score >= 70 || ["high", "critical"].includes(node.severity);
              const focused = !focusedNodeIds || focusedNodeIds.has(node.id);
              const nodeRadius = graphNodeRadius(node);
              const isCluster = ["event_cluster", "alert_cluster"].includes(node.type);
              const count = node.metadata?.count;
              return (
                <g
                  key={node.id}
                  className={`graph-node ${highRisk ? "graph-node-high" : ""} ${focused ? "" : "graph-dim"} ${
                    selectedNode?.id === node.id ? "graph-node-selected" : ""
                  } ${isCluster ? "graph-node-cluster" : ""}`}
                  onClick={() => {
                    onNodeSelect(node);
                    if (isCluster) onToggleCluster(node.id);
                  }}
                  onMouseEnter={() => onNodeHover(node.id)}
                  onMouseLeave={() => onNodeHover("")}
                >
                  <circle cx={node.x} cy={node.y} r={nodeRadius} fill={nodeColors[node.type] ?? "#94a3b8"} />
                  {count && (
                    <text x={node.x} y={node.y + 4} className="graph-node-count">
                      {count}
                    </text>
                  )}
                  {shouldShowGraphLabel(node, selectedNode, hoveredNodeId, zoom, graphControls.showLabels) && (
                    <text x={node.x} y={node.y + nodeRadius + 18} className="graph-node-label">
                      {node.label}
                    </text>
                  )}
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
                <p className="graph-focus-note">Focus mode highlights directly related graph entities.</p>
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
                {["alert", "incident"].includes(selectedNode.type) && (
                  <div className="graph-detail-actions">
                    <button type="button" disabled={!canOperate} onClick={() => onAnalyzeNode(selectedNode)}>
                      Analyze {selectedNode.type}
                    </button>
                  </div>
                )}
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

function CopilotPanel({
  alerts,
  incidents,
  chains,
  selectedNode,
  copilotMode,
  copilotTargetId,
  copilotState,
  copilotResult,
  copilotError,
  onModeChange,
  onTargetChange,
  onAnalyze,
  canOperate,
}) {
  const chainOptions = chains ?? [];

  return (
    <section className="copilot-panel">
      <div className="section-heading">
        <div>
          <h2>AI Analyst Copilot</h2>
          <p>Deterministic SOC analyst reasoning for alerts, incidents, and attack chains.</p>
        </div>
        <span className="ai-badge">AI-ready</span>
      </div>

      <div className="copilot-controls">
        <label>
          <span>Analysis type</span>
          <select value={copilotMode} onChange={(event) => onModeChange(event.target.value)}>
            <option value="alert">Alert</option>
            <option value="incident">Incident</option>
            <option value="chain">Attack chain</option>
          </select>
        </label>

        {copilotMode === "alert" && (
          <label>
            <span>Alert</span>
            <select value={copilotTargetId} onChange={(event) => onTargetChange(event.target.value)}>
              <option value="">Select alert</option>
              {alerts.map((alert) => (
                <option key={alert.id} value={alert.id}>
                  #{alert.id} {alert.title}
                </option>
              ))}
            </select>
          </label>
        )}

        {copilotMode === "incident" && (
          <label>
            <span>Incident</span>
            <select value={copilotTargetId} onChange={(event) => onTargetChange(event.target.value)}>
              <option value="">Select incident</option>
              {incidents.map((incident) => (
                <option key={incident.id} value={incident.id}>
                  #{incident.id} {incident.title}
                </option>
              ))}
            </select>
          </label>
        )}

        {copilotMode === "chain" && (
          <label>
            <span>Attack chain</span>
            <select value={copilotTargetId} onChange={(event) => onTargetChange(event.target.value)}>
              <option value="">Top chain</option>
              {chainOptions.map((chain) => (
                <option key={chain.source_ip} value={chain.source_ip}>
                  {chain.source_ip} | Risk {chain.risk_score}
                </option>
              ))}
            </select>
          </label>
        )}

        <button type="button" disabled={!canOperate || copilotState === "loading"} onClick={onAnalyze}>
          {copilotState === "loading" ? "Analyzing..." : "Run AI Analysis"}
        </button>
      </div>

      {selectedNode && ["alert", "incident"].includes(selectedNode.type) && (
        <p className="copilot-context">Graph selection: {selectedNode.id}</p>
      )}

      {copilotError && <span className="form-error">{copilotError}</span>}

      {copilotResult && (
        <article className="copilot-card">
          <div className="copilot-card-header">
            <span className="ai-badge">Analyst summary</span>
            <span className={`confidence-badge threat-${threatLevel(copilotResult.confidence)}`}>
              {copilotResult.confidence}% confidence
            </span>
          </div>
          <div className="confidence-track">
            <span style={{ width: `${copilotResult.confidence}%` }} />
          </div>

          <section>
            <h3>Summary</h3>
            <p>{copilotResult.summary}</p>
          </section>
          <section>
            <h3>Risk Assessment</h3>
            <p>{copilotResult.risk_assessment}</p>
          </section>
          <section>
            <h3>MITRE Explanation</h3>
            <p>{copilotResult.mitre_explanation}</p>
          </section>
          <section>
            <h3>Recommended Response</h3>
            <ul className="recommendation-list">
              {copilotResult.recommended_actions.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ul>
          </section>
          <section>
            <h3>Investigation Notes</h3>
            <p className="analyst-note">{copilotResult.investigation_notes}</p>
          </section>
        </article>
      )}
    </section>
  );
}

function CaseManagementPanel({
  incidents,
  selectedCaseId,
  caseDetails,
  activeTab,
  caseForm,
  noteForm,
  evidenceForm,
  notes,
  evidence,
  report,
  copilot,
  state,
  error,
  onSelectCase,
  onTabChange,
  onCaseFieldChange,
  onNoteFieldChange,
  onEvidenceFieldChange,
  onUpdateCase,
  onAddNote,
  onAddEvidence,
  onGenerateReport,
  onDownloadJson,
  onOpenHtml,
  onGenerateCopilot,
  canOperate,
}) {
  return (
    <section className="case-panel">
      <div className="section-heading">
        <div>
          <h2>Case Management</h2>
          <p>Manage incident assignment, notes, evidence, and SOC report output.</p>
        </div>
        <span>{incidents.length} cases</span>
      </div>

      {incidents.length === 0 ? (
        <p className="empty-state">No cases available. Create an incident to start case management.</p>
      ) : (
        <>
          <div className="case-layout">
            <aside className="case-list">
              {incidents.map((incident) => (
                <button
                  key={incident.id}
                  type="button"
                  className={String(incident.id) === String(selectedCaseId) ? "active-case" : ""}
                  onClick={() => onSelectCase(String(incident.id))}
                >
                  <strong>{incident.title}</strong>
                  <span>{incident.severity} | {incident.case_status || incident.status}</span>
                </button>
              ))}
            </aside>

            <div className="case-workspace">
              <div className="tab-row" role="tablist" aria-label="Case sections">
                {["overview", "notes", "evidence", "report"].map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    className={activeTab === tab ? "active-tab" : ""}
                    onClick={() => onTabChange(tab)}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {error && <span className="form-error">{error}</span>}
              {state === "loading" && <div className="state-panel">Loading case...</div>}

              {caseDetails && activeTab === "overview" && (
                <div className="case-card">
                  <div className="record-title-row">
                    <div>
                      <h3>{caseDetails.title}</h3>
                      <p>{caseDetails.description || caseDetails.summary || "No case summary yet."}</p>
                    </div>
                    <StatusBadge status={caseDetails.status} allowedStatuses={incidentStatuses} />
                  </div>

                  <div className="case-form-grid">
                    <Field label="Assigned analyst" name="assigned_to" value={caseForm.assigned_to} onChange={onCaseFieldChange} />
                    <SelectField
                      label="Priority"
                      name="priority"
                      value={caseForm.priority}
                      onChange={onCaseFieldChange}
                      options={["", "low", "medium", "high", "critical"]}
                    />
                    <SelectField
                      label="Case status"
                      name="case_status"
                      value={caseForm.case_status}
                      onChange={onCaseFieldChange}
                      options={["", "open", "investigating", "contained", "resolved", "closed"]}
                    />
                    <SelectField
                      label="Escalation"
                      name="escalation_level"
                      value={caseForm.escalation_level}
                      onChange={onCaseFieldChange}
                      options={["", "tier1", "tier2", "tier3", "incident_commander"]}
                    />
                    <TextAreaField
                      label="Resolution summary"
                      name="resolution_summary"
                      value={caseForm.resolution_summary}
                      onChange={onCaseFieldChange}
                    />
                  </div>

                  <div className="action-row">
                    <button type="button" disabled={!canOperate || state === "saving"} onClick={onUpdateCase}>
                      {state === "saving" ? "Updating..." : "Update Case"}
                    </button>
                    <button type="button" disabled={!canOperate || state === "saving"} onClick={onGenerateCopilot}>
                      Generate Copilot Guidance
                    </button>
                  </div>

                  {copilot && (
                    <div className="analyst-note">
                      <strong>Copilot guidance</strong>
                      <p>{copilot.summary}</p>
                      <p>{copilot.risk_assessment}</p>
                    </div>
                  )}
                </div>
              )}

              {activeTab === "notes" && (
                <div className="case-card">
                  <div className="case-form-grid">
                    <Field label="Author" name="author" value={noteForm.author} onChange={onNoteFieldChange} />
                    <SelectField
                      label="Note type"
                      name="note_type"
                      value={noteForm.note_type}
                      onChange={onNoteFieldChange}
                      options={["investigation", "containment", "escalation", "evidence", "resolution"]}
                    />
                    <TextAreaField label="Note" name="content" value={noteForm.content} required onChange={onNoteFieldChange} />
                  </div>
                  <button type="button" disabled={!canOperate || state === "saving"} onClick={onAddNote}>
                    Add Note
                  </button>
                  {notes.length === 0 ? (
                    <p className="empty-state">No analyst notes yet.</p>
                  ) : (
                    <ul className="case-feed">
                      {notes.map((note) => (
                        <li key={note.id}>
                          <strong>{note.note_type} | {note.author}</strong>
                          <p>{note.content}</p>
                          <span>{formatDateTime(note.created_at)}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {activeTab === "evidence" && (
                <div className="case-card">
                  <div className="case-form-grid">
                    <SelectField
                      label="Evidence type"
                      name="evidence_type"
                      value={evidenceForm.evidence_type}
                      onChange={onEvidenceFieldChange}
                      options={["related_alert", "related_event", "threat_intel", "graph_node", "analyst_upload_placeholder"]}
                    />
                    <Field label="Title" name="title" value={evidenceForm.title} required onChange={onEvidenceFieldChange} />
                    <Field label="Source" name="source" value={evidenceForm.source} onChange={onEvidenceFieldChange} />
                    <Field label="Reference ID" name="reference_id" value={evidenceForm.reference_id} onChange={onEvidenceFieldChange} />
                    <TextAreaField
                      label="Description"
                      name="description"
                      value={evidenceForm.description}
                      onChange={onEvidenceFieldChange}
                    />
                  </div>
                  <button type="button" disabled={!canOperate || state === "saving"} onClick={onAddEvidence}>
                    Add Evidence
                  </button>
                  {evidence.length === 0 ? (
                    <p className="empty-state">No evidence records yet.</p>
                  ) : (
                    <ul className="case-feed">
                      {evidence.map((item) => (
                        <li key={item.id}>
                          <strong>{item.evidence_type} | {item.title}</strong>
                          <p>{item.description || "No description"}</p>
                          <span>{[item.source, item.reference_id].filter(Boolean).join(" | ") || "No source"}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {activeTab === "report" && (
                <div className="case-card">
                  <div className="report-actions">
                    <button type="button" disabled={!canOperate || state === "saving"} onClick={onGenerateReport}>
                      Generate Report
                    </button>
                    <button type="button" disabled={!canOperate || state === "saving" || !caseDetails} onClick={onDownloadJson}>
                      Download JSON
                    </button>
                    <button type="button" disabled={!canOperate || !caseDetails} onClick={onOpenHtml}>
                      Open Printable HTML
                    </button>
                  </div>
                  {report ? (
                    <div className="report-summary-grid">
                      <div className="report-summary-card">
                        <span>Summary</span>
                        <strong>{report.incident_summary?.title}</strong>
                        <p>{report.status} | {report.severity} | {report.priority || "unset priority"}</p>
                      </div>
                      <div className="report-summary-card">
                        <span>Analyst Notes</span>
                        <strong>{report.analyst_notes?.length ?? 0}</strong>
                      </div>
                      <div className="report-summary-card">
                        <span>Evidence</span>
                        <strong>{report.evidence?.length ?? 0}</strong>
                      </div>
                      <div className="report-summary-card">
                        <span>Generated</span>
                        <strong>{formatDateTime(report.generated_at)}</strong>
                      </div>
                      <div className="report-summary-card report-wide-card">
                        <span>Recommended Actions</span>
                        <ul className="recommendation-list">
                          {(report.recommended_actions ?? []).map((action) => (
                            <li key={action}>{action}</li>
                          ))}
                        </ul>
                      </div>
                      <details className="raw-report-details">
                        <summary>Raw JSON</summary>
                        <pre className="report-preview">{JSON.stringify(report, null, 2)}</pre>
                      </details>
                    </div>
                  ) : (
                    <p className="empty-state">Generate a report to preview structured case output.</p>
                  )}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </section>
  );
}

function AdminUserManagementPanel({
  users,
  selectedUserId,
  userDetail,
  adminForm,
  adminRole,
  state,
  error,
  currentUser,
  onSelectUser,
  onFormChange,
  onRoleChange,
  onUpdateUser,
  onChangeRole,
  onActivate,
  onDeactivate,
  onRefresh,
}) {
  const selectedUser = userDetail ?? users.find((user) => String(user.id) === String(selectedUserId));

  return (
    <section className="admin-panel">
      <div className="section-heading">
        <div>
          <h2>Admin User Management</h2>
          <p>Manage analyst access, roles, account status, and recent login activity.</p>
        </div>
        <button type="button" disabled={state === "loading"} onClick={onRefresh}>
          {state === "loading" ? "Refreshing..." : "Refresh Users"}
        </button>
      </div>

      {error && <span className="form-error">{error}</span>}

      <div className="admin-layout">
        <div className="admin-user-list">
          {users.length === 0 ? (
            <p className="empty-state">No users found.</p>
          ) : (
            users.map((user) => (
              <button
                key={user.id}
                type="button"
                className={String(selectedUserId) === String(user.id) ? "active-user" : ""}
                onClick={() => onSelectUser(String(user.id))}
              >
                <strong>{user.full_name}</strong>
                <span>{user.username}</span>
                <div className="admin-badge-row">
                  <span className={`role-pill role-${user.role}`}>{user.role}</span>
                  <span className={`account-pill ${user.is_active ? "account-active" : "account-inactive"}`}>
                    {user.is_active ? "active" : "inactive"}
                  </span>
                </div>
              </button>
            ))
          )}
        </div>

        <div className="admin-detail-card">
          {!selectedUser ? (
            <p className="empty-state">Select a SOC user to manage.</p>
          ) : (
            <>
              <div className="record-title-row">
                <div>
                  <h3>{selectedUser.full_name}</h3>
                  <p>{selectedUser.email}</p>
                </div>
                <div className="admin-badge-row">
                  <span className={`role-pill role-${selectedUser.role}`}>{selectedUser.role}</span>
                  <span className={`account-pill ${selectedUser.is_active ? "account-active" : "account-inactive"}`}>
                    {selectedUser.is_active ? "active" : "inactive"}
                  </span>
                </div>
              </div>

              <div className="admin-meta-grid">
                <div>
                  <span>Username</span>
                  <strong>{selectedUser.username}</strong>
                </div>
                <div>
                  <span>Last login</span>
                  <strong>{formatDateTime(selectedUser.last_login_at)}</strong>
                </div>
                <div>
                  <span>Updated</span>
                  <strong>{formatDateTime(selectedUser.updated_at)}</strong>
                </div>
                <div>
                  <span>Disabled reason</span>
                  <strong>{selectedUser.disabled_reason ?? "n/a"}</strong>
                </div>
              </div>

              <div className="case-form-grid">
                <Field label="Full name" name="full_name" value={adminForm.full_name} onChange={onFormChange} />
                <Field label="Email" name="email" value={adminForm.email} onChange={onFormChange} />
                <label>
                  <span>Role</span>
                  <select value={adminRole} onChange={(event) => onRoleChange(event.target.value)}>
                    <option value="admin">admin</option>
                    <option value="analyst">analyst</option>
                    <option value="viewer">viewer</option>
                  </select>
                </label>
              </div>

              <div className="action-row">
                <button type="button" disabled={state === "saving"} onClick={onUpdateUser}>
                  Update Profile
                </button>
                <button type="button" disabled={state === "saving"} onClick={onChangeRole}>
                  Change Role
                </button>
                {selectedUser.is_active ? (
                  <button
                    type="button"
                    disabled={state === "saving" || selectedUser.id === currentUser.id}
                    onClick={onDeactivate}
                  >
                    Deactivate
                  </button>
                ) : (
                  <button type="button" disabled={state === "saving"} onClick={onActivate}>
                    Activate
                  </button>
                )}
              </div>

              <h3 className="admin-subheading">Login Audit Preview</h3>
              {userDetail?.login_audits?.length ? (
                <ul className="case-feed">
                  {userDetail.login_audits.map((audit) => (
                    <li key={`audit-${audit.id}`}>
                      <strong>{audit.success ? "Successful login" : "Failed login"}</strong>
                      <p>{audit.reason ?? "No reason"} | {audit.ip_address ?? "unknown IP"}</p>
                      <span>{formatDateTime(audit.created_at)}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="empty-state">No login audit records yet.</p>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function CollectorManagementPanel({
  collectors,
  healthSummary,
  form,
  state,
  error,
  oneTimeKey,
  onFieldChange,
  onCreate,
  onRotate,
  onRevoke,
  onRefresh,
  onCopyKey,
  onDismissKey,
  keyCopied,
  updatedCollectorIds,
  canCreate,
  canAdmin,
}) {
  const hasUnhealthyCollectors = (healthSummary?.stale ?? 0) > 0 || (healthSummary?.offline ?? 0) > 0;

  return (
    <section className="collector-panel">
      <div className="section-heading">
        <div>
          <h2>Live Collectors</h2>
          <p>Monitor live agent health and issue API keys for telemetry collectors.</p>
        </div>
        <button type="button" disabled={state === "loading"} onClick={onRefresh}>
          {state === "loading" ? "Refreshing..." : "Refresh Health"}
        </button>
      </div>

      <div className="collector-health-summary">
        <div><span>Online</span><strong>{healthSummary?.online ?? 0}</strong></div>
        <div><span>Stale</span><strong>{healthSummary?.stale ?? 0}</strong></div>
        <div><span>Offline</span><strong>{healthSummary?.offline ?? 0}</strong></div>
        <div><span>Revoked</span><strong>{healthSummary?.revoked ?? 0}</strong></div>
      </div>

      {hasUnhealthyCollectors && (
        <div className="collector-warning">Some collectors are not reporting telemetry.</div>
      )}

      {oneTimeKey && (
        <div className="collector-key-box">
          <div className="collector-key-header">
            <strong>Store this key now. It will not be shown again.</strong>
            <button type="button" className="collector-key-close" aria-label="Dismiss collector key" onClick={onDismissKey}>
              X
            </button>
          </div>
          <code>{oneTimeKey}</code>
          {keyCopied && <span className="collector-key-copied">Copied. Store it securely.</span>}
          <div className="collector-key-actions">
            <button type="button" onClick={onCopyKey}>Copy key</button>
            <button type="button" onClick={onDismissKey}>Done</button>
          </div>
        </div>
      )}

      <form className="record-form" onSubmit={onCreate}>
        <Field label="Name" name="name" value={form.name} required onChange={onFieldChange} />
        <Field label="Source label" name="source_label" value={form.source_label} onChange={onFieldChange} />
        <SelectField
          label="Collector type"
          name="collector_type"
          value={form.collector_type}
          onChange={onFieldChange}
          options={["sysmon", "windows_event", "linux_auth", "firewall", "zeek", "suricata", "custom_json"]}
        />
        <TextAreaField label="Description" name="description" value={form.description} onChange={onFieldChange} />
        <div className="form-footer">
          <button type="submit" disabled={!canCreate || state === "saving"}>
            {state === "saving" ? "Saving..." : "Create Collector"}
          </button>
          {error && <span className="form-error">{error}</span>}
        </div>
      </form>

      {collectors.length === 0 ? (
        <p className="empty-state">No collectors configured yet.</p>
      ) : (
        <ul className="collector-list">
          {collectors.map((collector) => (
            <li
              key={`collector-${collector.id}`}
              className={updatedCollectorIds.includes(collector.id) ? "collector-live-updated" : ""}
            >
              <div>
                <div className="record-title-row">
                  <strong>{collector.name}</strong>
                  <span className={`collector-health-pill collector-health-${collector.health_status ?? "offline"}`}>
                    {collector.health_status ?? "offline"}
                  </span>
                </div>
                <p>{collector.description || "No description"}</p>
                <div className="activity-meta">
                  <span>{collector.collector_type}</span>
                  <span>prefix {collector.key_prefix}</span>
                  <span>heartbeat {formatRelativeAge(collector.last_heartbeat_at)}</span>
                  <span>count {collector.heartbeat_count ?? 0}</span>
                  <span>source {collector.source_label || collector.name}</span>
                </div>
                <div className="collector-health-grid">
                  <span>Agent <strong>{collector.agent_version || "unknown"}</strong></span>
                  <span>Host <strong>{collector.host_name || "unknown"}</strong></span>
                  <span>OS <strong>{[collector.os_name, collector.os_version].filter(Boolean).join(" ") || "unknown"}</strong></span>
                  <span>Last events <strong>{collector.last_event_count ?? 0}</strong></span>
                  <span>Last heartbeat <strong>{formatDateTime(collector.last_heartbeat_at)}</strong></span>
                  <span>Last seen <strong>{formatDateTime(collector.last_seen_at)}</strong></span>
                </div>
                {collector.last_error && <p className="collector-error">Last error: {collector.last_error}</p>}
              </div>
              <div className="action-row">
                <button type="button" disabled={!canAdmin || state === "saving"} onClick={() => onRotate(collector.id)}>
                  Rotate Key
                </button>
                <button
                  type="button"
                  disabled={!canAdmin || state === "saving" || Boolean(collector.revoked_at)}
                  onClick={() => onRevoke(collector.id)}
                >
                  Revoke
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function CorrelationPanel({ correlationState, correlationResult, correlationError, onRun, canOperate }) {
  const chains = correlationResult?.chains ?? [];

  return (
    <section className="correlation-panel">
      <div className="section-heading">
        <div>
          <h2>Attack Chains</h2>
          <p>Correlate events, alerts, assets, and incidents into source-IP attack paths.</p>
        </div>
        <button type="button" disabled={!canOperate || correlationState === "running"} onClick={onRun}>
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

function AttackChainIntelligencePanel({
  chains,
  campaigns,
  selectedChainId,
  timeline,
  state,
  timelineState,
  error,
  rebuildResult,
  onRebuild,
  onSelectChain,
  canOperate,
}) {
  const chainList = chains?.chains ?? [];
  const campaignList = campaigns?.campaigns ?? [];
  const highestRiskChain = chainList[0];
  const criticalHighCount = chainList.filter((chain) => ["critical", "high"].includes(chain.classification)).length;

  return (
    <section className="attack-chain-panel">
      <div className="section-heading">
        <div>
          <h2>Attack Chain Intelligence</h2>
          <p>Risk-ranked multi-stage intrusion candidates built from telemetry, alerts, MITRE, IOC links, and assets.</p>
        </div>
        <button type="button" disabled={!canOperate || state === "rebuilding"} onClick={onRebuild}>
          {state === "rebuilding" ? "Rebuilding..." : "Rebuild Attack Chains"}
        </button>
      </div>

      {error && <span className="form-error">{error}</span>}

      <div className="attack-chain-summary">
        <div>
          <span>Total chains</span>
          <strong>{chainList.length}</strong>
        </div>
        <div>
          <span>Critical / high</span>
          <strong>{criticalHighCount}</strong>
        </div>
        <div>
          <span>Campaigns</span>
          <strong>{campaignList.length}</strong>
        </div>
        <div>
          <span>Highest risk</span>
          <strong>{highestRiskChain ? highestRiskChain.risk_score : 0}</strong>
        </div>
      </div>

      {rebuildResult && (
        <div className="detection-result">
          <span>Last rebuild: {rebuildResult.chains_found ?? 0} chains</span>
          <span>Highest risk: {rebuildResult.highest_risk_score ?? 0}</span>
          <span>Critical: {rebuildResult.critical_chains ?? 0}</span>
        </div>
      )}

      {state === "loading" && <p className="empty-state">Loading attack-chain intelligence...</p>}
      {state !== "loading" && chainList.length === 0 && (
        <p className="empty-state">No attack-chain candidates yet. Run detection, MITRE mapping, or rebuild chains after ingesting telemetry.</p>
      )}

      {chainList.length > 0 && (
        <div className="attack-chain-layout">
          <ul className="attack-chain-list">
            {chainList.slice(0, 20).map((chain) => (
              <li key={chain.chain_id}>
                <button
                  type="button"
                  className={selectedChainId === chain.chain_id ? "active-chain" : ""}
                  onClick={() => onSelectChain(chain.chain_id)}
                >
                  <div className="record-title-row">
                    <strong>{chain.title ?? chain.chain_id}</strong>
                    <span className={`threat-badge threat-${threatLevel(chain.risk_score)}`}>
                      {chain.classification} {chain.risk_score}
                    </span>
                  </div>
                  <p>{chain.primary_source_ip || chain.primary_group || "No primary entity"}</p>
                  <div className="activity-meta">
                    <span>Confidence {chain.confidence}</span>
                    <span>{chain.related_events?.count ?? 0} events</span>
                    <span>{chain.related_alerts?.count ?? 0} alerts</span>
                    <span>{chain.timeline?.first_seen ? formatDateTime(chain.timeline.first_seen) : "No first seen"}</span>
                  </div>
                  <div className="mitre-badge-row">
                    {(chain.stages ?? []).slice(0, 5).map((stage) => (
                      <span key={`${chain.chain_id}-${stage}`} className="mitre-badge">{stage}</span>
                    ))}
                  </div>
                </button>
              </li>
            ))}
          </ul>

          <div className="attack-chain-detail">
            <h3>Timeline Preview</h3>
            {!selectedChainId && <p className="empty-state">Select a chain to inspect ordered timeline context.</p>}
            {timelineState === "loading" && <p className="empty-state">Loading timeline...</p>}
            {selectedChainId && timelineState !== "loading" && (timeline?.steps ?? []).length === 0 && (
              <p className="empty-state">No timeline steps returned for this chain.</p>
            )}
            {(timeline?.steps ?? []).length > 0 && (
              <ol className="attack-timeline-list">
                {timeline.steps.slice(0, 25).map((step) => (
                  <li key={step.step_id}>
                    <div className="record-title-row">
                      <strong>{step.event_type || step.title}</strong>
                      <span className="severity">{step.severity}</span>
                    </div>
                    <p>{formatDateTime(step.timestamp)} | {step.attack_stage}</p>
                    <div className="activity-meta">
                      {step.mitre_technique_id && <span>{step.mitre_technique_id}</span>}
                      {step.mitre_tactic && <span>{step.mitre_tactic}</span>}
                      {step.hostname && <span>{step.hostname}</span>}
                      {step.username && <span>{step.username}</span>}
                      {step.source_ip && <span>{step.source_ip}</span>}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      )}

      <div className="campaign-summary">
        <h3>Campaign Clusters</h3>
        {campaignList.length === 0 ? (
          <p className="empty-state">No campaign clusters available yet.</p>
        ) : (
          <ul className="data-list chain-list">
            {campaignList.slice(0, 6).map((campaign) => (
              <li key={campaign.campaign_id} className="chain-item">
                <div className="record-title-row">
                  <strong>{campaign.title}</strong>
                  <span className={`threat-badge threat-${threatLevel(campaign.max_risk_score)}`}>
                    {campaign.classification}
                  </span>
                </div>
                <p>{campaign.summary}</p>
                <div className="activity-meta">
                  <span>{campaign.chain_count} chains</span>
                  <span>Risk {campaign.max_risk_score}</span>
                  {(campaign.source_ips ?? []).slice(0, 2).map((ip) => <span key={`${campaign.campaign_id}-${ip}`}>{ip}</span>)}
                  {(campaign.mitre_techniques ?? []).slice(0, 2).map((technique) => (
                    <span key={`${campaign.campaign_id}-${technique}`}>{technique}</span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function AlertSection({ alerts, onStatusChange, updatingKey, canOperate }) {
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
                <MitreBadges item={alert} />
                <div className="action-row">
                  {alertActions.map((action) => (
                    <button
                      key={`${alert.id}-${action.status}`}
                      type="button"
                      disabled={!canOperate || alert.status === action.status || updatingKey === `alert-${alert.id}`}
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

function IncidentSection({ incidents, onStatusChange, updatingKey, canOperate }) {
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
                      disabled={!canOperate || incident.status === action.status || updatingKey === `incident-${incident.id}`}
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
  const [currentUser, setCurrentUser] = useState(null);
  const [authMode, setAuthMode] = useState("login");
  const [authState, setAuthState] = useState("checking");
  const [authError, setAuthError] = useState("");
  const [authForm, setAuthForm] = useState({
    full_name: "",
    email: "",
    username: "",
    password: "",
    role: "analyst",
  });
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
  const [ingestionText, setIngestionText] = useState(JSON.stringify(sampleIngestionLogs, null, 2));
  const [ingestionMode, setIngestionMode] = useState("normalized");
  const [ingestionAutoDetect, setIngestionAutoDetect] = useState(true);
  const [ingestionState, setIngestionState] = useState("idle");
  const [ingestionResult, setIngestionResult] = useState(null);
  const [ingestionError, setIngestionError] = useState("");
  const [threatState, setThreatState] = useState("idle");
  const [threatResult, setThreatResult] = useState(null);
  const [threatError, setThreatError] = useState("");
  const [iocSyncStatus, setIocSyncStatus] = useState(null);
  const [iocRelationshipSummary, setIocRelationshipSummary] = useState(null);
  const [iocPanelState, setIocPanelState] = useState("idle");
  const [iocPanelError, setIocPanelError] = useState("");
  const [iocSearchQuery, setIocSearchQuery] = useState("");
  const [iocSearchResult, setIocSearchResult] = useState(null);
  const [iocSearchState, setIocSearchState] = useState("idle");
  const [iocCorrelationInput, setIocCorrelationInput] = useState("");
  const [iocCorrelationResult, setIocCorrelationResult] = useState(null);
  const [iocCorrelationState, setIocCorrelationState] = useState("idle");
  const [iocGraphForm, setIocGraphForm] = useState({ entity_type: "alert", entity_id: "", indicators: "" });
  const [iocGraphResult, setIocGraphResult] = useState(null);
  const [iocGraphState, setIocGraphState] = useState("idle");
  const [mitreCoverage, setMitreCoverage] = useState(null);
  const [mitreState, setMitreState] = useState("idle");
  const [mitreError, setMitreError] = useState("");
  const [correlationState, setCorrelationState] = useState("idle");
  const [correlationResult, setCorrelationResult] = useState(null);
  const [correlationError, setCorrelationError] = useState("");
  const [attackChains, setAttackChains] = useState({ total: 0, chains: [] });
  const [campaigns, setCampaigns] = useState({ total: 0, campaigns: [] });
  const [attackChainState, setAttackChainState] = useState("idle");
  const [attackChainError, setAttackChainError] = useState("");
  const [attackChainRebuildResult, setAttackChainRebuildResult] = useState(null);
  const [selectedAttackChainId, setSelectedAttackChainId] = useState("");
  const [attackChainTimeline, setAttackChainTimeline] = useState(null);
  const [attackChainTimelineState, setAttackChainTimelineState] = useState("idle");
  const [graphData, setGraphData] = useState(null);
  const [graphStatus, setGraphStatus] = useState("idle");
  const [graphError, setGraphError] = useState("");
  const [graphFilters, setGraphFilters] = useState({
    source_ip: "",
    severity: "",
    node_type: "",
    mitre_tactic: "",
    hostname: "",
    time_window: "",
    limit: "150",
    cluster_mode: true,
  });
  const [graphControls, setGraphControls] = useState({
    showLabels: false,
    physicsEnabled: false,
    edgeVisibility: 0,
  });
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);
  const [hoveredGraphNodeId, setHoveredGraphNodeId] = useState("");
  const [expandedGraphClusters, setExpandedGraphClusters] = useState([]);
  const [graphZoom, setGraphZoom] = useState(100);
  const [copilotMode, setCopilotMode] = useState("alert");
  const [copilotTargetId, setCopilotTargetId] = useState("");
  const [copilotState, setCopilotState] = useState("idle");
  const [copilotResult, setCopilotResult] = useState(null);
  const [copilotError, setCopilotError] = useState("");
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [activeCaseTab, setActiveCaseTab] = useState("overview");
  const [caseDetails, setCaseDetails] = useState(null);
  const [caseNotes, setCaseNotes] = useState([]);
  const [caseEvidence, setCaseEvidence] = useState([]);
  const [caseReport, setCaseReport] = useState(null);
  const [caseCopilot, setCaseCopilot] = useState(null);
  const [caseState, setCaseState] = useState("idle");
  const [caseError, setCaseError] = useState("");
  const [caseForm, setCaseForm] = useState({
    assigned_to: "",
    priority: "",
    case_status: "",
    escalation_level: "",
    resolution_summary: "",
  });
  const [noteForm, setNoteForm] = useState({ author: "analyst", note_type: "investigation", content: "" });
  const [evidenceForm, setEvidenceForm] = useState({
    evidence_type: "related_alert",
    title: "",
    description: "",
    source: "",
    reference_id: "",
  });
  const [adminUsers, setAdminUsers] = useState([]);
  const [selectedAdminUserId, setSelectedAdminUserId] = useState("");
  const [adminUserDetail, setAdminUserDetail] = useState(null);
  const [adminState, setAdminState] = useState("idle");
  const [adminError, setAdminError] = useState("");
  const [adminForm, setAdminForm] = useState({ full_name: "", email: "" });
  const [adminRole, setAdminRole] = useState("analyst");
  const [collectors, setCollectors] = useState([]);
  const [collectorHealthSummary, setCollectorHealthSummary] = useState({
    total_collectors: 0,
    online: 0,
    stale: 0,
    offline: 0,
    revoked: 0,
  });
  const [collectorForm, setCollectorForm] = useState(initialCollectorForm);
  const [collectorState, setCollectorState] = useState("idle");
  const [collectorError, setCollectorError] = useState("");
  const [collectorOneTimeKey, setCollectorOneTimeKey] = useState("");
  const [collectorKeyCopied, setCollectorKeyCopied] = useState(false);
  const [liveNotice, setLiveNotice] = useState("");
  const [lastLiveSync, setLastLiveSync] = useState("");
  const [updatedCollectorIds, setUpdatedCollectorIds] = useState([]);
  const realtimeRefreshTimerRef = useRef(null);
  const pendingRealtimeRefreshRef = useRef({
    slices: new Set(),
    collectors: false,
    graph: false,
    mitre: false,
    ioc: false,
    attackChains: false,
    adminUsers: false,
    caseId: null,
  });

  const realtimeStatus = useRealtimeAlerts({ onMessage: handleRealtimeMessage });
  const canOperate = currentUser?.role === "admin" || currentUser?.role === "analyst";
  const isAdmin = currentUser?.role === "admin";

  useEffect(() => {
    async function loadSession() {
      if (!getStoredToken()) {
        setAuthState("anonymous");
        return;
      }
      try {
        const user = await apiGet("/api/auth/me");
        setCurrentUser(user);
        setAuthState("authenticated");
      } catch {
        setAuthState("anonymous");
      }
    }

    loadSession();

    function handleExpired() {
      setCurrentUser(null);
      setAuthState("anonymous");
    }

    window.addEventListener("hexsoc-auth-expired", handleExpired);
    return () => window.removeEventListener("hexsoc-auth-expired", handleExpired);
  }, []);

  useEffect(() => {
    if (!currentUser) return;
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
    loadMitreCoverage();
    loadIOCIntelligence();
    loadAttackChainIntelligence();

    return () => {
      isMounted = false;
    };
  }, [currentUser]);

  useEffect(() => {
    if (!selectedCaseId && data.incidents.length > 0) {
      setSelectedCaseId(String(data.incidents[0].id));
    }
  }, [data.incidents, selectedCaseId]);

  useEffect(() => {
    if (!selectedAttackChainId && attackChains.chains.length > 0) {
      setSelectedAttackChainId(attackChains.chains[0].chain_id);
    }
  }, [attackChains.chains, selectedAttackChainId]);

  useEffect(() => {
    if (selectedCaseId) {
      loadCase(selectedCaseId);
    }
  }, [selectedCaseId]);

  useEffect(() => {
    if (selectedAttackChainId) {
      loadAttackChainTimeline(selectedAttackChainId);
    } else {
      setAttackChainTimeline(null);
    }
  }, [selectedAttackChainId]);

  useEffect(() => {
    if (currentUser) {
      loadCollectors();
    }
    if (isAdmin) {
      loadAdminUsers();
    } else {
      setAdminUsers([]);
      setSelectedAdminUserId("");
      setAdminUserDetail(null);
    }
    if (!currentUser) {
      setCollectors([]);
      setCollectorHealthSummary({ total_collectors: 0, online: 0, stale: 0, offline: 0, revoked: 0 });
    }
  }, [currentUser?.id, isAdmin]);

  useEffect(() => {
    if (currentUser) {
      const timer = window.setTimeout(() => loadGraph(), 350);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [currentUser?.id, graphFilters]);

  useEffect(() => {
    return () => window.clearTimeout(realtimeRefreshTimerRef.current);
  }, []);

  useEffect(() => {
    if (isAdmin && selectedAdminUserId) {
      loadAdminUserDetail(selectedAdminUserId);
    }
  }, [isAdmin, selectedAdminUserId]);

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

  async function loadAdminUsers() {
    if (!isAdmin) return;
    try {
      setAdminState("loading");
      setAdminError("");
      const users = await apiGet("/api/users/");
      setAdminUsers(users);
      if (!selectedAdminUserId && users.length > 0) {
        setSelectedAdminUserId(String(users[0].id));
      }
      setAdminState("ready");
    } catch (requestError) {
      setAdminError(requestError.message);
      setAdminState("error");
    }
  }

  async function loadAdminUserDetail(userId) {
    if (!isAdmin || !userId) return;
    try {
      setAdminState("loading");
      setAdminError("");
      const detail = await apiGet(`/api/users/${userId}`);
      setAdminUserDetail(detail);
      setAdminForm({ full_name: detail.full_name ?? "", email: detail.email ?? "" });
      setAdminRole(detail.role ?? "analyst");
      setAdminState("ready");
    } catch (requestError) {
      setAdminError(requestError.message);
      setAdminState("error");
    }
  }

  async function refreshAdminUsers(userId = selectedAdminUserId) {
    if (!isAdmin) return;
    const users = await apiGet("/api/users/");
    setAdminUsers(users);
    if (userId) {
      const detail = await apiGet(`/api/users/${userId}`);
      setAdminUserDetail(detail);
      setAdminForm({ full_name: detail.full_name ?? "", email: detail.email ?? "" });
      setAdminRole(detail.role ?? "analyst");
    }
  }

  async function loadCollectors() {
    if (!currentUser) return;
    try {
      setCollectorState("loading");
      setCollectorError("");
      const result = await apiGet("/api/collectors/health");
      setCollectors(result.collectors ?? []);
      setCollectorHealthSummary({
        total_collectors: result.total_collectors ?? 0,
        online: result.online ?? 0,
        stale: result.stale ?? 0,
        offline: result.offline ?? 0,
        revoked: result.revoked ?? 0,
      });
      setCollectorState("ready");
    } catch (requestError) {
      setCollectorError(requestError.message);
      setCollectorState("error");
    }
  }

  async function loadIOCIntelligence() {
    if (!currentUser) return;
    try {
      setIocPanelState("loading");
      setIocPanelError("");
      const [syncStatus, relationshipSummary] = await Promise.all([
        getThreatIntelSyncStatus(),
        getThreatIntelRelationshipSummary(),
      ]);
      setIocSyncStatus(syncStatus);
      setIocRelationshipSummary(relationshipSummary);
      setIocPanelState("ready");
    } catch (requestError) {
      setIocPanelError(requestError.message);
      setIocPanelState("error");
    }
  }

  function scheduleRealtimeRefresh(options = {}) {
    const pending = pendingRealtimeRefreshRef.current;
    (options.slices ?? []).forEach((key) => pending.slices.add(key));
    pending.collectors = pending.collectors || Boolean(options.collectors);
    pending.graph = pending.graph || Boolean(options.graph);
    pending.mitre = pending.mitre || Boolean(options.mitre);
    pending.ioc = pending.ioc || Boolean(options.ioc);
    pending.attackChains = pending.attackChains || Boolean(options.attackChains);
    pending.adminUsers = pending.adminUsers || Boolean(options.adminUsers);
    pending.caseId = options.caseId ?? pending.caseId;

    window.clearTimeout(realtimeRefreshTimerRef.current);
    realtimeRefreshTimerRef.current = window.setTimeout(async () => {
      const refresh = pendingRealtimeRefreshRef.current;
      pendingRealtimeRefreshRef.current = {
        slices: new Set(),
        collectors: false,
        graph: false,
        mitre: false,
        ioc: false,
        attackChains: false,
        adminUsers: false,
        caseId: null,
      };

      const tasks = [];
      const sliceKeys = Array.from(refresh.slices);
      if (sliceKeys.length) tasks.push(refreshSlices(sliceKeys));
      if (refresh.collectors) tasks.push(loadCollectors());
      if (refresh.graph) tasks.push(loadGraph());
      if (refresh.mitre) tasks.push(loadMitreCoverage());
      if (refresh.ioc) tasks.push(loadIOCIntelligence());
      if (refresh.attackChains) tasks.push(loadAttackChainIntelligence());
      if (refresh.adminUsers) tasks.push(refreshAdminUsers(selectedAdminUserId));
      if (refresh.caseId) tasks.push(loadCase(refresh.caseId));
      await Promise.all(tasks);
      setLastLiveSync(new Date().toLocaleTimeString());
    }, 700);
  }

  function handleRealtimeMessage(message) {
    if (message.type === "connected") return;

    if (message.type === "correlation_completed") {
      setCorrelationResult({
        chains: message.chains,
        chains_found: message.chains_found,
        source_ips_checked: message.source_ips_checked,
      });
    }

    if (message.type === "attack_chains_rebuilt") {
      scheduleRealtimeRefresh({ attackChains: true, slices: ["activity"] });
    }

    const collectorId = message.collector?.id ?? message.collector_id;
    if (collectorId) {
      setUpdatedCollectorIds((ids) => Array.from(new Set([collectorId, ...ids])).slice(0, 8));
      window.setTimeout(() => {
        setUpdatedCollectorIds((ids) => ids.filter((id) => id !== collectorId));
      }, 4000);
    }

    if (["collector_heartbeat", "collector_health_changed"].includes(message.type)) {
      scheduleRealtimeRefresh({ collectors: true });
    }

    if (["collector_created", "collector_updated", "collector_revoked"].includes(message.type)) {
      scheduleRealtimeRefresh({ collectors: true, slices: ["activity"] });
    }

    if (["collector_ingestion_completed", "event_ingested", "bulk_ingestion_completed", "windows_event_ingested", "bulk_windows_ingestion_completed"].includes(message.type)) {
      scheduleRealtimeRefresh({ collectors: true, slices: ["events", "assets", "alerts", "activity"], graph: true, mitre: true });
    }

    if (["alert_created", "alert_updated", "alert_status_changed"].includes(message.type)) {
      scheduleRealtimeRefresh({ slices: ["alerts", "activity"], graph: true });
    }

    if (message.type === "activity_created") {
      scheduleRealtimeRefresh({ slices: ["activity"] });
    }

    if (message.type === "mitre_mapping_completed") {
      scheduleRealtimeRefresh({ slices: ["events", "alerts", "activity"], graph: true, mitre: true });
    }

    if (["graph_updated", "correlation_completed", "threat_intel_enrichment", "threat_ioc_graph_enriched", "threat_ioc_correlated"].includes(message.type)) {
      scheduleRealtimeRefresh({ graph: true, ioc: true });
    }

    if (["case_updated", "case_note_added", "case_evidence_added", "case_report_generated", "case_report_exported", "incident_updated"].includes(message.type)) {
      scheduleRealtimeRefresh({
        slices: ["incidents", "activity"],
        caseId: selectedCaseId && Number(selectedCaseId) === message.incident_id ? selectedCaseId : null,
      });
    }

    if (["user_updated", "user_role_changed", "user_deactivated", "user_activated"].includes(message.type)) {
      scheduleRealtimeRefresh({ adminUsers: true, slices: ["activity"] });
    }

    if (message.type === "dashboard_metrics_updated") {
      scheduleRealtimeRefresh({ collectors: true, slices: ["assets", "events", "alerts", "incidents"] });
    }

    setLiveNotice("Live update received");
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

  async function loadAttackChainIntelligence() {
    if (!currentUser) return;
    try {
      setAttackChainState((currentState) => (currentState === "rebuilding" ? currentState : "loading"));
      setAttackChainError("");
      const [chainResult, campaignResult] = await Promise.all([getAttackChains(20), getCampaigns(20)]);
      setAttackChains(chainResult);
      setCampaigns(campaignResult);
      setSelectedAttackChainId((currentId) => {
        if (currentId && (chainResult.chains ?? []).some((chain) => chain.chain_id === currentId)) {
          return currentId;
        }
        return chainResult.chains?.[0]?.chain_id ?? "";
      });
      setAttackChainState("ready");
    } catch (requestError) {
      setAttackChainError(requestError.message);
      setAttackChainState("error");
    }
  }

  async function loadAttackChainTimeline(chainId) {
    if (!chainId) return;
    try {
      setAttackChainTimelineState("loading");
      const result = await getAttackChainTimeline(chainId);
      setAttackChainTimeline(result);
      setAttackChainTimelineState("ready");
    } catch (requestError) {
      setAttackChainError(requestError.message);
      setAttackChainTimelineState("error");
    }
  }

  function parseIndicatorLines(value) {
    return value
      .split(/\r?\n|,/)
      .map((item) => item.trim())
      .filter(Boolean)
      .slice(0, 100);
  }

  async function handleIOCSearch(event) {
    event.preventDefault();
    const query = iocSearchQuery.trim();
    if (!query) return;
    try {
      setIocSearchState("loading");
      setIocPanelError("");
      const result = await searchThreatIntel(query);
      setIocSearchResult(result);
      setIocSearchState("ready");
    } catch (requestError) {
      setIocPanelError(requestError.message);
      setIocSearchState("error");
    }
  }

  async function handleIOCCorrelate(event) {
    event.preventDefault();
    const indicators = parseIndicatorLines(iocCorrelationInput);
    if (!indicators.length) return;
    try {
      setIocCorrelationState("loading");
      setIocPanelError("");
      const result = await correlateIndicators(indicators);
      setIocCorrelationResult(result);
      await loadIOCIntelligence();
      setIocCorrelationState("ready");
    } catch (requestError) {
      setIocPanelError(requestError.message);
      setIocCorrelationState("error");
    }
  }

  function handleIOCGraphFormChange(name, value) {
    setIocGraphForm((currentForm) => ({ ...currentForm, [name]: value }));
  }

  async function handleIOCGraphEnrich(event) {
    event.preventDefault();
    const entityId = Number(iocGraphForm.entity_id);
    const indicators = parseIndicatorLines(iocGraphForm.indicators);
    if (!entityId || !indicators.length) return;
    try {
      setIocGraphState("loading");
      setIocPanelError("");
      const result = await graphEnrichIOC({
        entity_type: iocGraphForm.entity_type,
        entity_id: entityId,
        indicators,
      });
      setIocGraphResult(result);
      await Promise.all([loadIOCIntelligence(), loadGraph()]);
      setIocGraphState("ready");
    } catch (requestError) {
      setIocPanelError(requestError.message);
      setIocGraphState("error");
    }
  }

  async function loadMitreCoverage() {
    try {
      setMitreError("");
      const coverage = await apiGet("/api/mitre/coverage");
      setMitreCoverage(coverage);
    } catch (requestError) {
      setMitreError(requestError.message);
    }
  }

  function handleGraphFilterChange(name, value) {
    setGraphFilters((currentFilters) => ({
      ...currentFilters,
      [name]: value,
    }));
    if (name === "cluster_mode") {
      setExpandedGraphClusters([]);
      setSelectedGraphNode(null);
    }
  }

  function handleGraphControlChange(name, value) {
    setGraphControls((currentControls) => ({
      ...currentControls,
      [name]: value,
    }));
  }

  function handleToggleGraphCluster(clusterId) {
    setExpandedGraphClusters((currentClusters) =>
      currentClusters.includes(clusterId)
        ? currentClusters.filter((id) => id !== clusterId)
        : [...currentClusters, clusterId],
    );
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

  async function handleIngestLogs() {
    try {
      setIngestionState("running");
      setIngestionError("");
      setIngestionResult(null);
      const parsed = JSON.parse(ingestionText);
      const payload = Array.isArray(parsed) ? { logs: parsed } : parsed;

      if (!Array.isArray(payload.logs)) {
        throw new Error("JSON must be an array of logs or an object with a logs array.");
      }

      const path =
        ingestionMode === "windows"
          ? `/api/ingestion/windows-events/bulk?auto_detect=${ingestionAutoDetect ? "true" : "false"}`
          : `/api/ingestion/events/bulk?auto_detect=${ingestionAutoDetect ? "true" : "false"}`;
      const result = await apiPost(path, payload);
      setIngestionResult(result);
      await refreshSlices(["events", "assets", "alerts", "activity"]);
      await loadGraph();
    } catch (requestError) {
      setIngestionError(requestError.message);
    } finally {
      setIngestionState("idle");
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

  async function handleRunMitreMapping() {
    try {
      setMitreState("running");
      setMitreError("");
      await apiPost("/api/mitre/map-events", {});
      await apiPost("/api/mitre/map-alerts", {});
      await Promise.all([refreshSlices(["events", "alerts", "activity"]), loadGraph(), loadMitreCoverage()]);
    } catch (requestError) {
      setMitreError(requestError.message);
    } finally {
      setMitreState("idle");
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

  async function handleRebuildAttackChains() {
    try {
      setAttackChainState("rebuilding");
      setAttackChainError("");
      const result = await rebuildAttackChains(50);
      setAttackChainRebuildResult(result);
      setAttackChains({ total: result.chains?.length ?? 0, limit: 50, chains: result.chains ?? [] });
      const campaignResult = await getCampaigns(20);
      setCampaigns(campaignResult);
      setSelectedAttackChainId(result.chains?.[0]?.chain_id ?? "");
      await refreshSlices(["activity"]);
      setAttackChainState("ready");
    } catch (requestError) {
      setAttackChainError(requestError.message);
      setAttackChainState("error");
    }
  }

  function handleAnalyzeGraphNode(node) {
    if (node.type === "alert") {
      setCopilotMode("alert");
      setCopilotTargetId(String(node.metadata?.id ?? node.id.replace("alert:", "")));
    }
    if (node.type === "incident") {
      setCopilotMode("incident");
      setCopilotTargetId(String(node.metadata?.id ?? node.id.replace("incident:", "")));
    }
  }

  async function handleRunCopilotAnalysis() {
    try {
      setCopilotState("loading");
      setCopilotError("");
      let result;

      if (copilotMode === "alert") {
        if (!copilotTargetId) throw new Error("Select an alert to analyze.");
        result = await apiGet(`/api/copilot/alert/${copilotTargetId}`);
      } else if (copilotMode === "incident") {
        if (!copilotTargetId) throw new Error("Select an incident to analyze.");
        result = await apiGet(`/api/copilot/incident/${copilotTargetId}`);
      } else {
        const selectedChain =
          (correlationResult?.chains ?? []).find((chain) => chain.source_ip === copilotTargetId) ??
          correlationResult?.chains?.[0];
        if (!selectedChain) throw new Error("Run correlation before analyzing an attack chain.");
        result = await apiPost("/api/copilot/attack-chain-summary", selectedChain);
      }

      setCopilotResult(result);
      await refreshSlices(["activity"]);
    } catch (requestError) {
      setCopilotError(requestError.message);
    } finally {
      setCopilotState("idle");
    }
  }

  async function loadCase(incidentId) {
    try {
      setCaseState("loading");
      setCaseError("");
      const [details, notes, evidenceItems] = await Promise.all([
        apiGet(`/api/cases/${incidentId}`),
        apiGet(`/api/cases/${incidentId}/notes`),
        apiGet(`/api/cases/${incidentId}/evidence`),
      ]);
      setCaseDetails(details);
      setCaseNotes(notes);
      setCaseEvidence(evidenceItems);
      setCaseForm({
        assigned_to: details.assigned_to ?? "",
        priority: details.priority ?? "",
        case_status: details.case_status ?? "",
        escalation_level: details.escalation_level ?? "",
        resolution_summary: details.resolution_summary ?? "",
      });
      setCaseState("ready");
    } catch (requestError) {
      setCaseError(requestError.message);
      setCaseState("error");
    }
  }

  function handleCaseFieldChange(name, value) {
    setCaseForm((currentForm) => ({ ...currentForm, [name]: value }));
  }

  function handleNoteFieldChange(name, value) {
    setNoteForm((currentForm) => ({ ...currentForm, [name]: value }));
  }

  function handleEvidenceFieldChange(name, value) {
    setEvidenceForm((currentForm) => ({ ...currentForm, [name]: value }));
  }

  async function handleUpdateCase() {
    if (!selectedCaseId) return;
    try {
      setCaseState("saving");
      setCaseError("");
      const payload = Object.fromEntries(
        Object.entries(caseForm).map(([key, value]) => [key, value.trim() || null]),
      );
      await apiPatch(`/api/cases/${selectedCaseId}`, payload);
      await Promise.all([loadCase(selectedCaseId), refreshSlices(["incidents", "activity"])]);
    } catch (requestError) {
      setCaseError(requestError.message);
      setCaseState("error");
    }
  }

  async function handleAddCaseNote() {
    if (!selectedCaseId) return;
    if (!noteForm.content.trim()) {
      setCaseError("Note content is required.");
      return;
    }
    try {
      setCaseState("saving");
      setCaseError("");
      await apiPost(`/api/cases/${selectedCaseId}/notes`, {
        ...noteForm,
        content: noteForm.content.trim(),
      });
      setNoteForm({ author: noteForm.author, note_type: "investigation", content: "" });
      await Promise.all([loadCase(selectedCaseId), refreshSlices(["activity"])]);
    } catch (requestError) {
      setCaseError(requestError.message);
      setCaseState("error");
    }
  }

  async function handleAddCaseEvidence() {
    if (!selectedCaseId) return;
    if (!evidenceForm.title.trim()) {
      setCaseError("Evidence title is required.");
      return;
    }
    try {
      setCaseState("saving");
      setCaseError("");
      await apiPost(`/api/cases/${selectedCaseId}/evidence`, {
        ...evidenceForm,
        title: evidenceForm.title.trim(),
        description: evidenceForm.description.trim() || null,
        source: evidenceForm.source.trim() || null,
        reference_id: evidenceForm.reference_id.trim() || null,
      });
      setEvidenceForm({
        evidence_type: "related_alert",
        title: "",
        description: "",
        source: "",
        reference_id: "",
      });
      await Promise.all([loadCase(selectedCaseId), refreshSlices(["activity"])]);
    } catch (requestError) {
      setCaseError(requestError.message);
      setCaseState("error");
    }
  }

  async function handleGenerateCaseReport() {
    if (!selectedCaseId) return;
    try {
      setCaseState("saving");
      setCaseError("");
      const report = await apiGet(`/api/cases/${selectedCaseId}/report`);
      setCaseReport(report);
      await refreshSlices(["activity"]);
      setCaseState("ready");
    } catch (requestError) {
      setCaseError(requestError.message);
      setCaseState("error");
    }
  }

  async function handleDownloadCaseJson() {
    if (!selectedCaseId) return;
    try {
      setCaseState("saving");
      setCaseError("");
      const token = getStoredToken();
      const response = await fetch(`${API_BASE_URL}/api/cases/${selectedCaseId}/report/json`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        throw new Error(`Report download failed: ${response.status}`);
      }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `hexsoc-case-${selectedCaseId}-report.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      await refreshSlices(["activity"]);
      setCaseState("ready");
    } catch (requestError) {
      setCaseError(requestError.message);
      setCaseState("error");
    }
  }

  function handleOpenCaseHtml() {
    if (!selectedCaseId) return;
    const token = getStoredToken();
    const query = token ? `?token=${encodeURIComponent(token)}` : "";
    window.open(`${API_BASE_URL}/api/cases/${selectedCaseId}/report/html${query}`, "_blank", "noopener,noreferrer");
  }

  async function handleGenerateCaseCopilot() {
    if (!selectedCaseId) return;
    try {
      setCaseState("saving");
      setCaseError("");
      const result = await apiGet(`/api/copilot/incident/${selectedCaseId}`);
      setCaseCopilot(result);
      await refreshSlices(["activity"]);
      setCaseState("ready");
    } catch (requestError) {
      setCaseError(requestError.message);
      setCaseState("error");
    }
  }

  function handleAdminFormChange(name, value) {
    setAdminForm((currentForm) => ({ ...currentForm, [name]: value }));
  }

  async function handleAdminUpdateUser() {
    if (!selectedAdminUserId) return;
    try {
      setAdminState("saving");
      setAdminError("");
      await apiPatch(`/api/users/${selectedAdminUserId}`, {
        full_name: adminForm.full_name.trim(),
        email: adminForm.email.trim(),
      });
      await Promise.all([refreshAdminUsers(selectedAdminUserId), refreshSlices(["activity"])]);
      setAdminState("ready");
    } catch (requestError) {
      setAdminError(requestError.message);
      setAdminState("error");
    }
  }

  async function handleAdminChangeRole() {
    if (!selectedAdminUserId) return;
    try {
      setAdminState("saving");
      setAdminError("");
      await apiPost(`/api/users/${selectedAdminUserId}/role`, { role: adminRole });
      await Promise.all([refreshAdminUsers(selectedAdminUserId), refreshSlices(["activity"])]);
      setAdminState("ready");
    } catch (requestError) {
      setAdminError(requestError.message);
      setAdminState("error");
    }
  }

  async function handleAdminActivateUser() {
    if (!selectedAdminUserId) return;
    try {
      setAdminState("saving");
      setAdminError("");
      await apiPost(`/api/users/${selectedAdminUserId}/activate`, {});
      await Promise.all([refreshAdminUsers(selectedAdminUserId), refreshSlices(["activity"])]);
      setAdminState("ready");
    } catch (requestError) {
      setAdminError(requestError.message);
      setAdminState("error");
    }
  }

  async function handleAdminDeactivateUser() {
    if (!selectedAdminUserId) return;
    try {
      setAdminState("saving");
      setAdminError("");
      await apiPost(`/api/users/${selectedAdminUserId}/deactivate`, {
        disabled_reason: "Disabled by admin from HexSOC dashboard",
      });
      await Promise.all([refreshAdminUsers(selectedAdminUserId), refreshSlices(["activity"])]);
      setAdminState("ready");
    } catch (requestError) {
      setAdminError(requestError.message);
      setAdminState("error");
    }
  }

  function handleCollectorFieldChange(name, value) {
    setCollectorForm((currentForm) => ({ ...currentForm, [name]: value }));
  }

  async function handleCreateCollector(event) {
    event.preventDefault();
    if (!collectorForm.name.trim()) {
      setCollectorError("Collector name is required.");
      return;
    }
    try {
      setCollectorState("saving");
      setCollectorError("");
      const response = await apiPost("/api/collectors/", {
        ...collectorForm,
        name: collectorForm.name.trim(),
        description: collectorForm.description.trim() || null,
        source_label: collectorForm.source_label.trim() || null,
      });
      setCollectorOneTimeKey(response.api_key);
      setCollectorKeyCopied(false);
      setCollectorForm(initialCollectorForm);
      await Promise.all([loadCollectors(), refreshSlices(["activity"])]);
      setCollectorState("ready");
    } catch (requestError) {
      setCollectorError(requestError.message);
      setCollectorState("error");
    }
  }

  async function handleRotateCollector(collectorId) {
    try {
      setCollectorState("saving");
      setCollectorError("");
      const response = await apiPost(`/api/collectors/${collectorId}/rotate`, {});
      setCollectorOneTimeKey(response.api_key);
      setCollectorKeyCopied(false);
      await Promise.all([loadCollectors(), refreshSlices(["activity"])]);
      setCollectorState("ready");
    } catch (requestError) {
      setCollectorError(requestError.message);
      setCollectorState("error");
    }
  }

  async function handleRevokeCollector(collectorId) {
    try {
      setCollectorState("saving");
      setCollectorError("");
      await apiPost(`/api/collectors/${collectorId}/revoke`, {});
      await Promise.all([loadCollectors(), refreshSlices(["activity"])]);
      setCollectorState("ready");
    } catch (requestError) {
      setCollectorError(requestError.message);
      setCollectorState("error");
    }
  }

  async function handleCopyCollectorKey() {
    if (!collectorOneTimeKey) return;
    await navigator.clipboard.writeText(collectorOneTimeKey);
    setCollectorKeyCopied(true);
  }

  function handleDismissCollectorKey() {
    setCollectorOneTimeKey("");
    setCollectorKeyCopied(false);
  }

  function handleAuthFieldChange(name, value) {
    setAuthForm((currentForm) => ({ ...currentForm, [name]: value }));
  }

  async function handleAuthSubmit(event) {
    event.preventDefault();
    try {
      setAuthState("loading");
      setAuthError("");
      if (authMode === "register") {
        await register(authForm);
      }
      const response = await login({ username: authForm.username, password: authForm.password });
      setStoredToken(response.access_token);
      setCurrentUser(response.user);
      setAuthState("authenticated");
      setAuthForm((currentForm) => ({ ...currentForm, password: "" }));
    } catch (requestError) {
      setAuthError(requestError.message);
      setAuthState("anonymous");
    }
  }

  function handleLogout() {
    clearStoredToken();
    setCurrentUser(null);
    setAuthState("anonymous");
    setData({ assets: [], events: [], alerts: [], incidents: [], activity: [] });
  }

  if (authState === "checking" || authState === "loading") {
    return <div className="state-panel">Checking analyst session...</div>;
  }

  if (!currentUser) {
    return (
      <AuthScreen
        authMode={authMode}
        authForm={authForm}
        authError={authError}
        authState={authState}
        onModeChange={(mode) => {
          setAuthMode(mode);
          setAuthError("");
        }}
        onFieldChange={handleAuthFieldChange}
        onSubmit={handleAuthSubmit}
      />
    );
  }

  return (
    <main className="app-shell">
      <section className="page-header">
        <p>HexSOC AI</p>
        <h1>SOC Command Dashboard</h1>
        <div className="status-line">
          <span>Live backend: {import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:9000"}</span>
          <RealtimeBadge status={realtimeStatus} />
          <span className="role-badge">{currentUser.full_name} | {currentUser.role}</span>
          <button type="button" className="logout-button" onClick={handleLogout}>Logout</button>
        </div>
        {liveNotice && (
          <div className="live-toast">
            {liveNotice}
            {lastLiveSync && <span>Last live sync: {lastLiveSync}</span>}
          </div>
        )}
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
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <DetectionPanel
          detectionState={detectionState}
          detectionResult={detectionResult}
          detectionError={detectionError}
          onRun={handleRunDetectionEngine}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <LogIngestionPanel
          mode={ingestionMode}
          value={ingestionText}
          autoDetect={ingestionAutoDetect}
          state={ingestionState}
          result={ingestionResult}
          error={ingestionError}
          onModeChange={(mode) => {
            setIngestionMode(mode);
            setIngestionText(JSON.stringify(mode === "windows" ? sampleWindowsSysmonEvents : sampleIngestionLogs, null, 2));
            setIngestionError("");
          }}
          onChange={setIngestionText}
          onAutoDetectChange={setIngestionAutoDetect}
          onLoadSample={() => {
            setIngestionMode("normalized");
            setIngestionText(JSON.stringify(sampleIngestionLogs, null, 2));
            setIngestionError("");
          }}
          onLoadWindowsSample={() => {
            setIngestionMode("windows");
            setIngestionText(JSON.stringify(sampleWindowsSysmonEvents, null, 2));
            setIngestionError("");
          }}
          onIngest={handleIngestLogs}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <ThreatIntelPanel
          threatState={threatState}
          threatResult={threatResult}
          threatError={threatError}
          onRun={handleRunThreatIntel}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <IOCInvestigationPanel
          syncStatus={iocSyncStatus}
          relationshipSummary={iocRelationshipSummary}
          state={iocPanelState}
          error={iocPanelError}
          searchQuery={iocSearchQuery}
          searchResult={iocSearchResult}
          searchState={iocSearchState}
          correlationInput={iocCorrelationInput}
          correlationResult={iocCorrelationResult}
          correlationState={iocCorrelationState}
          graphForm={iocGraphForm}
          graphResult={iocGraphResult}
          graphState={iocGraphState}
          onSearchQueryChange={setIocSearchQuery}
          onCorrelationInputChange={setIocCorrelationInput}
          onGraphFormChange={handleIOCGraphFormChange}
          onSearch={handleIOCSearch}
          onCorrelate={handleIOCCorrelate}
          onGraphEnrich={handleIOCGraphEnrich}
          onRefresh={loadIOCIntelligence}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <MitreCoveragePanel
          coverage={mitreCoverage}
          state={mitreState}
          error={mitreError}
          onRun={handleRunMitreMapping}
          onRefresh={loadMitreCoverage}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <CorrelationPanel
          correlationState={correlationState}
          correlationResult={correlationResult}
          correlationError={correlationError}
          onRun={handleRunCorrelationEngine}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <AttackChainIntelligencePanel
          chains={attackChains}
          campaigns={campaigns}
          selectedChainId={selectedAttackChainId}
          timeline={attackChainTimeline}
          state={attackChainState}
          timelineState={attackChainTimelineState}
          error={attackChainError}
          rebuildResult={attackChainRebuildResult}
          onRebuild={handleRebuildAttackChains}
          onSelectChain={setSelectedAttackChainId}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <GraphInvestigationPanel
          graphData={graphData}
          graphStatus={graphStatus}
          graphError={graphError}
          graphFilters={graphFilters}
          graphControls={graphControls}
          selectedNode={selectedGraphNode}
          hoveredNodeId={hoveredGraphNodeId}
          expandedClusterIds={expandedGraphClusters}
          zoom={graphZoom}
          onFilterChange={handleGraphFilterChange}
          onControlChange={handleGraphControlChange}
          onRefresh={loadGraph}
          onNodeSelect={setSelectedGraphNode}
          onNodeHover={setHoveredGraphNodeId}
          onToggleCluster={handleToggleGraphCluster}
          onAnalyzeNode={handleAnalyzeGraphNode}
          onZoomChange={setGraphZoom}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <CopilotPanel
          alerts={data.alerts}
          incidents={data.incidents}
          chains={correlationResult?.chains ?? []}
          selectedNode={selectedGraphNode}
          copilotMode={copilotMode}
          copilotTargetId={copilotTargetId}
          copilotState={copilotState}
          copilotResult={copilotResult}
          copilotError={copilotError}
          onModeChange={(mode) => {
            setCopilotMode(mode);
            setCopilotTargetId("");
            setCopilotError("");
          }}
          onTargetChange={setCopilotTargetId}
          onAnalyze={handleRunCopilotAnalysis}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && (
        <CaseManagementPanel
          incidents={data.incidents}
          selectedCaseId={selectedCaseId}
          caseDetails={caseDetails}
          activeTab={activeCaseTab}
          caseForm={caseForm}
          noteForm={noteForm}
          evidenceForm={evidenceForm}
          notes={caseNotes}
          evidence={caseEvidence}
          report={caseReport}
          copilot={caseCopilot}
          state={caseState}
          error={caseError}
          onSelectCase={(incidentId) => {
            setSelectedCaseId(incidentId);
            setCaseReport(null);
            setCaseCopilot(null);
          }}
          onTabChange={setActiveCaseTab}
          onCaseFieldChange={handleCaseFieldChange}
          onNoteFieldChange={handleNoteFieldChange}
          onEvidenceFieldChange={handleEvidenceFieldChange}
          onUpdateCase={handleUpdateCase}
          onAddNote={handleAddCaseNote}
          onAddEvidence={handleAddCaseEvidence}
          onGenerateReport={handleGenerateCaseReport}
          onDownloadJson={handleDownloadCaseJson}
          onOpenHtml={handleOpenCaseHtml}
          onGenerateCopilot={handleGenerateCaseCopilot}
          canOperate={canOperate}
        />
      )}

      {status === "ready" && isAdmin && (
        <AdminUserManagementPanel
          users={adminUsers}
          selectedUserId={selectedAdminUserId}
          userDetail={adminUserDetail}
          adminForm={adminForm}
          adminRole={adminRole}
          state={adminState}
          error={adminError}
          currentUser={currentUser}
          onSelectUser={(userId) => {
            setSelectedAdminUserId(userId);
            setAdminUserDetail(null);
          }}
          onFormChange={handleAdminFormChange}
          onRoleChange={setAdminRole}
          onUpdateUser={handleAdminUpdateUser}
          onChangeRole={handleAdminChangeRole}
          onActivate={handleAdminActivateUser}
          onDeactivate={handleAdminDeactivateUser}
          onRefresh={loadAdminUsers}
        />
      )}

      {status === "ready" && currentUser && (
        <CollectorManagementPanel
          collectors={collectors}
          healthSummary={collectorHealthSummary}
          form={collectorForm}
          state={collectorState}
          error={collectorError}
          oneTimeKey={collectorOneTimeKey}
          keyCopied={collectorKeyCopied}
          updatedCollectorIds={updatedCollectorIds}
          onFieldChange={handleCollectorFieldChange}
          onCreate={handleCreateCollector}
          onRotate={handleRotateCollector}
          onRevoke={handleRevokeCollector}
          onRefresh={loadCollectors}
          onCopyKey={handleCopyCollectorKey}
          onDismissKey={handleDismissCollectorKey}
          canCreate={canOperate}
          canAdmin={isAdmin}
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
            canOperate={canOperate}
          />
          <IncidentSection
            incidents={data.incidents}
            onStatusChange={handleIncidentStatusChange}
            updatingKey={updatingKey}
            canOperate={canOperate}
          />
          <ActivitySection activity={data.activity} />
        </div>
      )}
    </main>
  );
}
