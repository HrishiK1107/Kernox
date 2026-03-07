export interface Alert {
  alert_id: string;
  endpoint_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  risk_score: number;
  status: 'open' | 'investigating' | 'resolved';
  detection_rule: string;
  payload: Record<string, any>;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  description: string;
  endpoint_hostname?: string;
}

export interface Endpoint {
  endpoint_id: string;
  hostname: string;
  risk_index: number;
  last_seen: string;
  status: 'online' | 'offline' | 'warning';
  os: string;
  ip_address: string;
}

export interface TrendData {
  timestamp: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DistributionData {
  severity: string;
  count: number;
  percentage: number;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'critical';
  uptime: string;
  last_check: string;
}

// Mock Data
export const mockHealth: HealthStatus = {
  status: 'healthy',
  uptime: '99.98%',
  last_check: new Date().toISOString(),
};

export const mockAlerts: Alert[] = [
  {
    alert_id: 'ALT-2026-001',
    endpoint_id: 'EP-3421',
    endpoint_hostname: 'web-prod-01.corp.internal',
    severity: 'critical',
    risk_score: 95,
    status: 'open',
    detection_rule: 'Suspicious Process Execution',
    description: 'Unauthorized PowerShell execution detected with encoded command',
    payload: {
      process: 'powershell.exe',
      command: 'Invoke-Expression(New-Object Net.WebClient).DownloadString...',
      pid: 8472,
      user: 'SYSTEM',
      parent_process: 'services.exe',
    },
    created_at: '2026-02-27T14:23:41Z',
    updated_at: '2026-02-27T14:23:41Z',
  },
  {
    alert_id: 'ALT-2026-002',
    endpoint_id: 'EP-1284',
    endpoint_hostname: 'db-primary-02.corp.internal',
    severity: 'critical',
    risk_score: 92,
    status: 'investigating',
    detection_rule: 'Lateral Movement Detected',
    description: 'Abnormal network scanning from database server',
    payload: {
      source_ip: '10.20.30.42',
      destination_ports: [22, 3389, 445, 135],
      scan_rate: 450,
      protocol: 'TCP',
    },
    created_at: '2026-02-27T13:15:22Z',
    updated_at: '2026-02-27T14:01:18Z',
  },
  {
    alert_id: 'ALT-2026-003',
    endpoint_id: 'EP-5512',
    endpoint_hostname: 'app-worker-05.corp.internal',
    severity: 'high',
    risk_score: 78,
    status: 'open',
    detection_rule: 'Privilege Escalation Attempt',
    description: 'Attempt to modify system configuration files',
    payload: {
      file_modified: '/etc/sudoers',
      user: 'appuser',
      action: 'write',
      result: 'denied',
    },
    created_at: '2026-02-27T12:42:05Z',
    updated_at: '2026-02-27T12:42:05Z',
  },
  {
    alert_id: 'ALT-2026-004',
    endpoint_id: 'EP-7823',
    endpoint_hostname: 'vpn-gateway-01.corp.internal',
    severity: 'high',
    risk_score: 81,
    status: 'open',
    detection_rule: 'Brute Force Attack',
    description: 'Multiple failed authentication attempts detected',
    payload: {
      failed_attempts: 247,
      source_ips: ['185.220.101.42', '185.220.101.43'],
      target_account: 'admin',
      timeframe: '5 minutes',
    },
    created_at: '2026-02-27T11:18:33Z',
    updated_at: '2026-02-27T11:18:33Z',
  },
  {
    alert_id: 'ALT-2026-005',
    endpoint_id: 'EP-2901',
    endpoint_hostname: 'mail-relay-03.corp.internal',
    severity: 'medium',
    risk_score: 64,
    status: 'resolved',
    detection_rule: 'Anomalous Outbound Traffic',
    description: 'Unusual data exfiltration pattern detected',
    payload: {
      bytes_sent: 2147483648,
      destination: 'unknown-cdn.example.com',
      protocol: 'HTTPS',
      duration: '45 minutes',
    },
    created_at: '2026-02-27T09:31:17Z',
    updated_at: '2026-02-27T10:15:42Z',
    resolved_at: '2026-02-27T10:15:42Z',
  },
  {
    alert_id: 'ALT-2026-006',
    endpoint_id: 'EP-4456',
    endpoint_hostname: 'workstation-dev-12.corp.internal',
    severity: 'medium',
    risk_score: 58,
    status: 'open',
    detection_rule: 'Suspicious File Download',
    description: 'Executable downloaded from untrusted source',
    payload: {
      filename: 'update_installer.exe',
      url: 'http://free-software-downloads.xyz/tools/',
      hash: 'a3f7c82b1d4e5f6a7b8c9d0e1f2a3b4c',
      size_bytes: 4567890,
    },
    created_at: '2026-02-27T08:47:59Z',
    updated_at: '2026-02-27T08:47:59Z',
  },
  {
    alert_id: 'ALT-2026-007',
    endpoint_id: 'EP-6734',
    endpoint_hostname: 'api-gateway-04.corp.internal',
    severity: 'low',
    risk_score: 28,
    status: 'resolved',
    detection_rule: 'Policy Violation',
    description: 'Non-standard port usage detected',
    payload: {
      port: 8888,
      service: 'http-alt',
      expected_port: 443,
    },
    created_at: '2026-02-27T07:22:14Z',
    updated_at: '2026-02-27T07:55:30Z',
    resolved_at: '2026-02-27T07:55:30Z',
  },
  {
    alert_id: 'ALT-2026-008',
    endpoint_id: 'EP-8921',
    endpoint_hostname: 'backup-server-01.corp.internal',
    severity: 'low',
    risk_score: 22,
    status: 'resolved',
    detection_rule: 'Configuration Drift',
    description: 'System configuration does not match baseline',
    payload: {
      setting: 'firewall_enabled',
      expected: true,
      actual: false,
      auto_remediated: true,
    },
    created_at: '2026-02-27T06:11:08Z',
    updated_at: '2026-02-27T06:30:22Z',
    resolved_at: '2026-02-27T06:30:22Z',
  },
];

export const mockEndpoints: Endpoint[] = [
  {
    endpoint_id: 'EP-3421',
    hostname: 'web-prod-01.corp.internal',
    risk_index: 87,
    last_seen: '2026-02-27T14:23:41Z',
    status: 'online',
    os: 'Windows Server 2022',
    ip_address: '10.20.30.15',
  },
  {
    endpoint_id: 'EP-1284',
    hostname: 'db-primary-02.corp.internal',
    risk_index: 82,
    last_seen: '2026-02-27T14:01:18Z',
    status: 'warning',
    os: 'Ubuntu 22.04 LTS',
    ip_address: '10.20.30.42',
  },
  {
    endpoint_id: 'EP-5512',
    hostname: 'app-worker-05.corp.internal',
    risk_index: 71,
    last_seen: '2026-02-27T12:42:05Z',
    status: 'online',
    os: 'Red Hat Enterprise Linux 9',
    ip_address: '10.20.31.28',
  },
  {
    endpoint_id: 'EP-7823',
    hostname: 'vpn-gateway-01.corp.internal',
    risk_index: 75,
    last_seen: '2026-02-27T11:18:33Z',
    status: 'online',
    os: 'pfSense 2.7',
    ip_address: '10.20.30.1',
  },
  {
    endpoint_id: 'EP-2901',
    hostname: 'mail-relay-03.corp.internal',
    risk_index: 45,
    last_seen: '2026-02-27T10:15:42Z',
    status: 'online',
    os: 'Debian 12',
    ip_address: '10.20.32.10',
  },
  {
    endpoint_id: 'EP-4456',
    hostname: 'workstation-dev-12.corp.internal',
    risk_index: 52,
    last_seen: '2026-02-27T08:47:59Z',
    status: 'online',
    os: 'Windows 11 Pro',
    ip_address: '10.20.40.87',
  },
  {
    endpoint_id: 'EP-6734',
    hostname: 'api-gateway-04.corp.internal',
    risk_index: 18,
    last_seen: '2026-02-27T07:55:30Z',
    status: 'online',
    os: 'Alpine Linux 3.19',
    ip_address: '10.20.31.5',
  },
  {
    endpoint_id: 'EP-8921',
    hostname: 'backup-server-01.corp.internal',
    risk_index: 12,
    last_seen: '2026-02-27T06:30:22Z',
    status: 'online',
    os: 'TrueNAS Scale 23.10',
    ip_address: '10.20.50.20',
  },
  {
    endpoint_id: 'EP-9032',
    hostname: 'load-balancer-02.corp.internal',
    risk_index: 24,
    last_seen: '2026-02-27T14:20:15Z',
    status: 'online',
    os: 'HAProxy 2.8',
    ip_address: '10.20.30.2',
  },
  {
    endpoint_id: 'EP-1145',
    hostname: 'monitoring-01.corp.internal',
    risk_index: 8,
    last_seen: '2026-02-27T14:25:03Z',
    status: 'online',
    os: 'Ubuntu 22.04 LTS',
    ip_address: '10.20.60.5',
  },
];

export const mockTrends: TrendData[] = [
  { timestamp: '2026-02-20', critical: 2, high: 5, medium: 12, low: 18 },
  { timestamp: '2026-02-21', critical: 1, high: 7, medium: 15, low: 22 },
  { timestamp: '2026-02-22', critical: 3, high: 6, medium: 11, low: 19 },
  { timestamp: '2026-02-23', critical: 0, high: 4, medium: 14, low: 25 },
  { timestamp: '2026-02-24', critical: 2, high: 8, medium: 16, low: 21 },
  { timestamp: '2026-02-25', critical: 1, high: 5, medium: 13, low: 20 },
  { timestamp: '2026-02-26', critical: 4, high: 9, medium: 10, low: 17 },
  { timestamp: '2026-02-27', critical: 2, high: 4, medium: 8, low: 15 },
];

export const mockDistribution: DistributionData[] = [
  { severity: 'Critical', count: 2, percentage: 6.9 },
  { severity: 'High', count: 2, percentage: 6.9 },
  { severity: 'Medium', count: 2, percentage: 6.9 },
  { severity: 'Low', count: 2, percentage: 6.9 },
];

export const calculateMetrics = () => {
  const totalAlerts = mockAlerts.length;
  const criticalAlerts = mockAlerts.filter((a) => a.severity === 'critical').length;
  const highAlerts = mockAlerts.filter((a) => a.severity === 'high').length;
  const totalEndpoints = mockEndpoints.length;
  const avgRiskIndex = Math.round(
    mockEndpoints.reduce((sum, e) => sum + e.risk_index, 0) / mockEndpoints.length
  );

  return {
    totalAlerts,
    criticalAlerts,
    highAlerts,
    totalEndpoints,
    avgRiskIndex,
  };
};
