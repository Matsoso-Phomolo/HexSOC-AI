import { useEffect, useMemo, useState } from "react";

import { apiGet, apiPatch, apiPost, fetchDashboardData } from "../api/client.js";

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

function StatusBadge({ status, allowedStatuses }) {
  const normalizedStatus = status ?? "unknown";
  const badgeClass = allowedStatuses.includes(normalizedStatus)
    ? `status-${normalizedStatus}`
    : "status-unknown";

  return <span className={`status-badge ${badgeClass}`}>{normalizedStatus}</span>;
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

  return (
    <main className="app-shell">
      <section className="page-header">
        <p>HexSOC AI</p>
        <h1>SOC Command Dashboard</h1>
        <span>Live backend: {import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:9000"}</span>
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

      {status === "ready" && totalRecords === 0 && (
        <div className="state-panel">No SOC records found in PostgreSQL yet.</div>
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
