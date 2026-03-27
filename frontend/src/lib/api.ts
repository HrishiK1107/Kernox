/**
 * Kernox API client — wires the frontend to the FastAPI backend.
 *
 * In dev mode Vite proxies /api → http://localhost:8000/api so
 * we can call relative paths without CORS issues.
 */

const BASE = '/api/v1';

async function get<T>(path: string, params?: Record<string, string>): Promise<T> {
    const url = new URL(`${BASE}${path}`, window.location.origin);
    if (params) {
        Object.entries(params).forEach(([k, v]) => {
            if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
        });
    }

    const res = await fetch(url.toString());
    if (!res.ok) {
        throw new Error(`API ${res.status}: ${res.statusText}`);
    }
    return res.json();
}

// ─── Health ─────────────────────────────────
export interface HealthResponse {
    status: string;
}

export const fetchHealth = () => get<HealthResponse>('/health');

// ─── Events ─────────────────────────────────
export interface EventPayload {
    event_id: string;
    endpoint_id: string;
    event_type: string;
    severity: string;
    timestamp: string;
    received_at: string;
    payload: Record<string, any>;
}

export interface EventListResponse {
    page: number;
    page_size: number;
    total: number;
    results: EventPayload[];
}

export const fetchEvents = (params?: Record<string, string>) =>
    get<EventListResponse>('/events', params);

// ─── Alerts ─────────────────────────────────
export interface AlertPayload {
    id: number;
    endpoint_id: number;
    severity: string;
    risk_score: number;
    status: string;
    detection_rule: string;
    payload: Record<string, any>;
    created_at: string;
    updated_at: string;
    resolved_at?: string;
}

export interface AlertListResponse {
    total: number;
    page: number;
    page_size: number;
    results: AlertPayload[];
}

export const fetchAlerts = (params?: Record<string, string>) =>
    get<AlertListResponse>('/alerts', params);

// ─── Analytics ──────────────────────────────
export interface SeverityBucket {
    severity: string;
    count: number;
}

export const fetchSeverityDistribution = () =>
    get<SeverityBucket[]>('/analytics/severity-distribution');

export interface TrendBucket {
    bucket: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
}

export const fetchTrends = (start: string, end: string, bucket = 'daily') =>
    get<TrendBucket[]>('/analytics/trends', {
        start_date: start,
        end_date: end,
        bucket,
    });

export interface EndpointRisk {
    endpoint_id: string;
    hostname: string;
    total_events: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    risk_index: number;
}

export interface EndpointRiskResponse {
    total: number;
    page: number;
    page_size: number;
    results: EndpointRisk[];
}

export const fetchEndpointRisk = (params?: Record<string, string>) =>
    get<EndpointRiskResponse>('/analytics/endpoint-risk', params);

// ─── Alerts per endpoint ────────────────────
export interface AlertsPerEndpoint {
    endpoint_id: number;
    total_alerts: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
}

export interface AlertsPerEndpointResponse {
    total: number;
    page: number;
    page_size: number;
    results: AlertsPerEndpoint[];
}

export const fetchAlertsPerEndpoint = (params?: Record<string, string>) =>
    get<AlertsPerEndpointResponse>('/analytics/alerts-per-endpoint', params);

// ─── Top Rules ──────────────────────────────
export interface TopRule {
    detection_rule: string;
    total_alerts: number;
    avg_risk: number;
}

export interface TopRulesResponse {
    total: number;
    page: number;
    page_size: number;
    results: TopRule[];
}

export const fetchTopRules = (params?: Record<string, string>) =>
    get<TopRulesResponse>('/analytics/top-rules', params);
