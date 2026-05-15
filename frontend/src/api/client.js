export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:9000";

const TOKEN_KEY = "hexsoc_access_token";

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearStoredToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function authHeaders(extraHeaders = {}) {
  const token = getStoredToken();
  return {
    ...extraHeaders,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function parseResponse(response, path) {
  if (response.status === 401) {
    clearStoredToken();
    window.dispatchEvent(new Event("hexsoc-auth-expired"));
  }

  if (!response.ok) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = payload?.detail ? ` - ${payload.detail}` : "";
    } catch {
      detail = "";
    }
    throw new Error(`API request failed for ${path}: ${response.status}${detail}`);
  }

  return response.json();
}

export async function apiGet(path) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: authHeaders(),
  });
  return parseResponse(response, path);
}

export async function apiPatch(path, payload) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "PATCH",
    headers: authHeaders({
      "Content-Type": "application/json",
    }),
    body: JSON.stringify(payload),
  });
  return parseResponse(response, path);
}

export async function apiPost(path, payload) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: authHeaders({
      "Content-Type": "application/json",
    }),
    body: JSON.stringify(payload),
  });
  return parseResponse(response, path);
}

export async function login(payload) {
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  return parseResponse(response, "/api/auth/login");
}

export async function register(payload) {
  const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  return parseResponse(response, "/api/auth/register");
}

export async function fetchDashboardData() {
  const [assets, events, alerts, incidents, activity] = await Promise.all([
    apiGet("/api/assets/"),
    apiGet("/api/events/"),
    apiGet("/api/alerts/"),
    apiGet("/api/incidents/"),
    apiGet("/api/activity/recent"),
  ]);

  return { assets, events, alerts, incidents, activity };
}

export async function searchThreatIntel(query) {
  const params = new URLSearchParams();
  params.set("q", query);
  params.set("limit", "25");
  return apiGet(`/api/threat-intel/search?${params.toString()}`);
}

export async function correlateIndicators(indicators) {
  return apiPost("/api/threat-intel/correlate", { indicators });
}

export async function getThreatIntelSyncStatus() {
  return apiGet("/api/threat-intel/sync-status");
}

export async function getThreatIntelRelationshipSummary() {
  return apiGet("/api/threat-intel/relationship-summary?limit=25");
}

export async function graphEnrichIOC(payload) {
  return apiPost("/api/threat-intel/graph-enrich", payload);
}

export async function getIOCRelationships() {
  return apiGet("/api/graph/ioc-relationships?limit=100");
}

export async function getAttackChains(limit = 20) {
  return apiGet(`/api/attack-chains?limit=${encodeURIComponent(limit)}`);
}

export async function getAttackChain(chainId) {
  return apiGet(`/api/attack-chains/${encodeURIComponent(chainId)}`);
}

export async function getAttackChainTimeline(chainId) {
  return apiGet(`/api/attack-chains/${encodeURIComponent(chainId)}/timeline`);
}

export async function getCampaigns(limit = 20) {
  return apiGet(`/api/campaigns?limit=${encodeURIComponent(limit)}`);
}

export async function rebuildAttackChains(limit = 50) {
  return apiPost(`/api/attack-chains/rebuild?limit=${encodeURIComponent(limit)}`, {});
}
