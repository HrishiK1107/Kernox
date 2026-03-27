import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import {
  Shield,
  AlertTriangle,
  Server,
  Activity,
  AlertCircle,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Sector
} from 'recharts';
import { GlassCard } from '../components/Card';
import { MetricCard } from '../components/StatCard';
import { SystemHealthDropdown } from '../components/BackendStatusDropdown';
import {
  fetchAlerts,
  fetchSeverityDistribution,
  fetchTrends,
  type AlertPayload,
  type SeverityBucket,
  type TrendBucket,
} from '../lib/api';
import {
  mockAlerts as fallbackAlerts,
  mockTrends as fallbackTrends,
  mockDistribution as fallbackDistribution,
  calculateMetrics as fallbackMetrics,
} from '../data/mockData';
import { useTheme } from '../context/ThemeContext';

export default function HomePage() {
  const { colors } = useTheme();
  const severityColors = colors.severity;
  const pieColors = [
    severityColors.critical,
    severityColors.high,
    severityColors.medium,
    severityColors.low,
  ];

  // Live data state — falls back to mock if API unreachable
  const [alerts, setAlerts] = useState(fallbackAlerts);
  const [trends, setTrends] = useState(
    fallbackTrends.map((t) => ({
      bucket: t.timestamp,
      ...t,
    })),
  );
  const [distribution, setDistribution] = useState(fallbackDistribution);
  const [metrics, setMetrics] = useState(fallbackMetrics());
  const [live, setLive] = useState(false);

  useEffect(() => {
    let mounted = true;

    async function load() {
      try {
        // Fetch alerts
        const alertData = await fetchAlerts({ page_size: '100' });
        if (!mounted) return;

        const mapped = alertData.results.map((a) => ({
          alert_id: `ALT-${a.id}`,
          endpoint_id: String(a.endpoint_id),
          endpoint_hostname: String(a.endpoint_id),
          severity: a.severity as 'critical' | 'high' | 'medium' | 'low',
          risk_score: a.risk_score,
          status: a.status as 'open' | 'investigating' | 'resolved',
          detection_rule: a.detection_rule,
          description: a.payload?.description || a.detection_rule,
          payload: a.payload,
          created_at: a.created_at,
          updated_at: a.updated_at,
          resolved_at: a.resolved_at,
        }));
        setAlerts(mapped);

        // Compute metrics from live data
        const totalAlerts = alertData.total;
        const criticalAlerts = mapped.filter((a) => a.severity === 'critical').length;
        const highAlerts = mapped.filter((a) => a.severity === 'high').length;
        setMetrics((prev) => ({
          ...prev,
          totalAlerts,
          criticalAlerts,
          highAlerts,
        }));

        setLive(true);
      } catch {
        // keep fallback
      }

      // Severity distribution
      try {
        const dist = await fetchSeverityDistribution();
        if (!mounted) return;
        const total = dist.reduce((s, d) => s + d.count, 0) || 1;
        setDistribution(
          dist.map((d) => ({
            severity: d.severity.charAt(0).toUpperCase() + d.severity.slice(1),
            count: d.count,
            percentage: Math.round((d.count / total) * 1000) / 10,
          })),
        );
      } catch {
        // keep fallback
      }

      // Trends
      try {
        const now = new Date();
        const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        const trendData = await fetchTrends(
          weekAgo.toISOString(),
          now.toISOString(),
          'daily',
        );
        if (!mounted) return;
        if (trendData.length > 0) {
          setTrends(trendData);
        }
      } catch {
        // keep fallback
      }
    }

    load();
    const id = setInterval(load, 30_000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  const chartData = trends.map((t) => ({
    date: new Date(t.bucket || (t as any).timestamp).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    }),
    total: t.critical + t.high + t.medium + t.low,
    ...t,
  }));

  return (
    <div className="min-h-screen pb-16 relative overflow-hidden">
      {/* Animated Background Shapes */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <motion.div
          animate={{ scale: [1, 1.2, 1], opacity: [0.03, 0.05, 0.03] }}
          transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
          className="absolute -top-1/2 -left-1/2 w-full h-full bg-gradient-to-br from-accent/10 to-transparent rounded-full blur-3xl"
        />
        <motion.div
          animate={{ scale: [1, 1.3, 1], opacity: [0.03, 0.06, 0.03] }}
          transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut', delay: 1 }}
          className="absolute -bottom-1/2 -right-1/2 w-full h-full bg-gradient-to-tl from-accent/10 to-transparent rounded-full blur-3xl"
        />
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
        {/* Hero Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="mb-12"
        >
          <div className="flex items-center justify-between mb-2">
            <h1 className="text-4xl tracking-tight">Kernox Security Platform</h1>
            <SystemHealthDropdown />
          </div>
          <p className="text-muted-foreground">
            Command overview and security metrics
            {live && (
              <span className="ml-2 text-emerald-400 text-xs font-mono">● LIVE</span>
            )}
          </p>
        </motion.div>

        {/* Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-12">
          <MetricCard title="Total Alerts" value={metrics.totalAlerts} icon={Shield} delay={0.1} />
          <MetricCard title="Critical Alerts" value={metrics.criticalAlerts} icon={AlertCircle} delay={0.15} />
          <MetricCard title="High Alerts" value={metrics.highAlerts} icon={AlertTriangle} delay={0.2} />
          <MetricCard title="Total Endpoints" value={metrics.totalEndpoints} icon={Server} delay={0.25} />
          <MetricCard title="Avg Risk Index" value={metrics.avgRiskIndex} icon={Activity} delay={0.3} />
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-12">
          {/* Trend Chart */}
          <GlassCard className="lg:col-span-2" delay={0.35}>
            <h3 className="text-xl mb-6">Alert Trends (7 Days)</h3>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="whiteAreaGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FFFFFF" stopOpacity={0.22} />
                    <stop offset="60%" stopColor="#FFFFFF" stopOpacity={0.06} />
                    <stop offset="95%" stopColor="#FFFFFF" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="whiteStrokeGradient" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#A0AEBF" stopOpacity={0.6} />
                    <stop offset="50%" stopColor="#FFFFFF" stopOpacity={1} />
                    <stop offset="100%" stopColor="#A0AEBF" stopOpacity={0.6} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="date"
                  stroke="#2D3748"
                  tick={{ fill: '#5C6474', fontSize: 12 }}
                  axisLine={{ stroke: '#1a2234' }}
                  tickLine={false}
                />
                <YAxis
                  stroke="#2D3748"
                  tick={{ fill: '#5C6474', fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  formatter={(value: number, name: string) => [
                    <span style={{ fontFamily: "monospace" }}>{value}</span>,
                    name === "total" ? "Total" : name
                  ]}
                  contentStyle={{
                    backgroundColor: '#060D1A',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '0.5rem',
                  }}
                  labelStyle={{ color: '#E2DED8' }}
                  itemStyle={{ color: '#FFFFFF' }}
                />
                <Area
                  type="monotone"
                  dataKey="total"
                  stroke="url(#whiteStrokeGradient)"
                  strokeWidth={2.5}
                  fill="url(#whiteAreaGradient)"
                  dot={{ fill: '#FFFFFF', r: 4, strokeWidth: 0 }}
                  activeDot={{ r: 6, fill: '#FFFFFF', strokeWidth: 0 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </GlassCard>

          {/* Severity Distribution */}
          <GlassCard delay={0.4}>
            <h3 className="text-xl mb-6">Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={distribution}
                  dataKey="count"
                  nameKey="severity"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  paddingAngle={3}
                  activeShape={(props: any) => (
                    <Sector {...props} outerRadius={props.outerRadius + 10} />
                  )}
                  isAnimationActive={true}
                >
                  {distribution.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={pieColors[index % pieColors.length]} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const data = payload[0].payload;
                    const sev = data.severity;
                    const color =
                      severityColors[sev.toLowerCase() as keyof typeof severityColors];
                    return (
                      <div
                        style={{
                          background: '#060D1A',
                          border: '1px solid rgba(122,72,50,0.18)',
                          borderRadius: '8px',
                          padding: '8px 12px',
                        }}
                      >
                        <div style={{ color }}>
                          {sev}:{' '}
                          <span style={{ fontFamily: 'monospace' }}>{data.count}</span>
                        </div>
                      </div>
                    );
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="grid grid-cols-2 gap-2 mt-2">
              {distribution.map((item, index) => (
                <div key={item.severity} className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: pieColors[index] }} />
                  <span className="text-sm text-muted-foreground capitalize">{item.severity}</span>
                </div>
              ))}
            </div>
          </GlassCard>
        </div>

        {/* Recent Alerts Table */}
        <GlassCard delay={0.45}>
          <h3 className="text-xl mb-6">Recent Alerts</h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-muted-foreground">Alert ID</th>
                  <th className="text-left py-3 px-4 text-muted-foreground">Endpoint</th>
                  <th className="text-left py-3 px-4 text-muted-foreground">Severity</th>
                  <th className="text-left py-3 px-4 text-muted-foreground">Detection Rule</th>
                  <th className="text-left py-3 px-4 text-muted-foreground">Status</th>
                  <th className="text-left py-3 px-4 text-muted-foreground">Created</th>
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 5).map((alert, index) => (
                  <motion.tr
                    key={alert.alert_id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.5 + index * 0.05 }}
                    whileHover={{ backgroundColor: 'rgba(122, 72, 50, 0.06)' }}
                    className="border-b border-border/50 transition-colors cursor-pointer"
                  >
                    <td className="py-4 px-4 font-mono text-sm">{alert.alert_id}</td>
                    <td className="py-4 px-4 text-sm">{alert.endpoint_hostname}</td>
                    <td className="py-4 px-4">
                      <span
                        className="capitalize text-sm px-2.5 py-1 rounded-full"
                        style={{
                          color: severityColors[alert.severity],
                          backgroundColor: `${severityColors[alert.severity]}18`,
                          border: `1px solid ${severityColors[alert.severity]}30`,
                        }}
                      >
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-4 px-4 text-sm">{alert.detection_rule}</td>
                    <td className="py-4 px-4">
                      <span className="capitalize text-sm text-muted-foreground">{alert.status}</span>
                    </td>
                    <td className="py-4 px-4 text-sm text-muted-foreground">
                      {new Date(alert.created_at).toLocaleDateString()}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </GlassCard>
      </div>
    </div>
  );
}
