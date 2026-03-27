import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { TrendingUp, PieChart as PieChartIcon } from 'lucide-react';
import { GlassCard } from '../components/Card';
import {
  mockTrends as fallbackTrends,
  mockDistribution as fallbackDistribution,
} from '../data/mockData';
import { fetchTrends, fetchSeverityDistribution } from '../lib/api';
import { useTheme } from '../context/ThemeContext';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Legend,
  CartesianGrid,
} from 'recharts';

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload) return null

  const order = ['Low', 'Medium', 'High', 'Critical']

  const sorted = [...payload].sort(
    (a, b) => order.indexOf(a.name) - order.indexOf(b.name)
  )

  return (
    <div
      style={{
        background: '#0A1628',
        border: '1px solid rgba(122,72,50,0.25)',
        borderRadius: '8px',
        padding: '10px 14px',
        color: '#E2DED8'
      }}
    >
      <div style={{ marginBottom: 6 }}>{label}</div>

      {sorted.map((entry: any) => (
        <div
          key={entry.name}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: 16,
            color: entry.color
          }}
        >
          <span>{entry.name}</span>

          <span style={{ textAlign: 'right', minWidth: 24 }}>
            {entry.value}
          </span>
        </div>
      ))}
    </div>
  )
}


function TrendTooltip({ active, payload, label }: any) {
  if (!active || !payload) return null

  const order = ['Critical', 'High', 'Medium', 'Low']

  const sorted = [...payload].sort(
    (a, b) => order.indexOf(a.name) - order.indexOf(b.name)
  )

  return (
    <div
      style={{
        background: '#0A1628',
        border: '1px solid rgba(122,72,50,0.25)',
        borderRadius: '8px',
        padding: '10px 14px',
        color: '#E2DED8'
      }}
    >
      <div style={{ marginBottom: 6 }}>{label}</div>

      {sorted.map((entry: any) => (
        <div
          key={entry.name}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: 16,
            color: entry.color
          }}
        >
          <span>{entry.name}</span>

          <span style={{ fontFamily: 'monospace', textAlign: 'right', minWidth: 24 }}>
            {entry.value}
          </span>
        </div>
      ))}
    </div>
  )
}

export default function AnalyticsPage() {
  const { colors } = useTheme();

  const [trends, setTrends] = useState(fallbackTrends);
  const [distribution, setDistribution] = useState(fallbackDistribution);

  useEffect(() => {
    let mounted = true;
    async function load() {
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
          setTrends(
            trendData.map((t) => ({
              timestamp: t.bucket,
              critical: t.critical,
              high: t.high,
              medium: t.medium,
              low: t.low,
            })),
          );
        }
      } catch { /* keep fallback */ }

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
      } catch { /* keep fallback */ }
    }
    load();
    const id = setInterval(load, 30_000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  const chartData = trends.map((trend) => ({
    date: new Date(trend.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
    Critical: trend.critical,
    High: trend.high,
    Medium: trend.medium,
    Low: trend.low,
  }));

  const severityColors = {
    Critical: colors.severity.critical,
    High: colors.severity.high,
    Medium: colors.severity.medium,
    Low: colors.severity.low,
  };

  const pieColors = [
    colors.severity.critical,
    colors.severity.high,
    colors.severity.medium,
    colors.severity.low,
  ];

  return (
    <div className="min-h-screen pb-16 relative overflow-hidden">
      {/* Background Gradient */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <motion.div
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.03, 0.05, 0.03],
          }}
          transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
          className="absolute top-1/4 left-1/4 w-1/2 h-1/2 bg-gradient-to-br from-accent/10 to-transparent rounded-full blur-3xl"
        />
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="mb-8"
        >
          <h1 className="text-4xl tracking-tight mb-2">Security Analytics</h1>
          <p className="text-muted-foreground">Trend analysis and severity distribution</p>
        </motion.div>

        {/* Alert Trends*/}
        <GlassCard delay={0.1} className="mb-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-3 bg-accent/10 rounded-lg">
              <TrendingUp className="w-6 h-6 text-accent" />
            </div>
            <div>
              <h2 className="text-2xl">Alert Trends</h2>
              <p className="text-sm text-muted-foreground">7-day security alert timeline by severity</p>
            </div>
          </div>

          <ResponsiveContainer width="100%" height={400}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(122, 72, 50, 0.08)" />
              <XAxis
                dataKey="date"
                stroke="#9CA3AF"
                tick={{ fill: '#9CA3AF', fontSize: 12 }}
              />
              <YAxis stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
              <Tooltip content={<TrendTooltip />} />
              <Legend
                wrapperStyle={{ color: '#E8E6E3' }}
                iconType="circle"
              />
              <Line
                type="monotone"
                dataKey="Critical"
                stroke={severityColors.Critical}
                strokeWidth={3}
                dot={{ fill: severityColors.Critical, r: 5 }}
                activeDot={{ r: 7 }}
              />
              <Line
                type="monotone"
                dataKey="High"
                stroke={severityColors.High}
                strokeWidth={3}
                dot={{ fill: severityColors.High, r: 5 }}
                activeDot={{ r: 7 }}
              />
              <Line
                type="monotone"
                dataKey="Medium"
                stroke={severityColors.Medium}
                strokeWidth={3}
                dot={{ fill: severityColors.Medium, r: 5 }}
                activeDot={{ r: 7 }}
              />
              <Line
                type="monotone"
                dataKey="Low"
                stroke={severityColors.Low}
                strokeWidth={3}
                dot={{ fill: severityColors.Low, r: 5 }}
                activeDot={{ r: 7 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </GlassCard>

        {/* Two Column Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Severity Distribution Pie Chart */}
          <GlassCard delay={0.2}>
            <div className="flex items-center gap-3 mb-6">
              <div className="p-3 bg-accent/10 rounded-lg">
                <PieChartIcon className="w-6 h-6 text-accent" />
              </div>
              <div>
                <h2 className="text-2xl">Severity Distribution</h2>
                <p className="text-sm text-muted-foreground">Current alert breakdown</p>
              </div>
            </div>

            <ResponsiveContainer width="100%" height={350}>
              <PieChart>
                <Pie
                  data={distribution}
                  dataKey="count"
                  nameKey="severity"
                  cx="50%"
                  cy="50%"
                  innerRadius={80}
                  outerRadius={130}
                  paddingAngle={3}
                  label={({ severity, percentage }) => `${severity}: ${percentage}%`}
                  labelLine={{ stroke: '#9CA3AF' }}
                >
                  {distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={pieColors[index % pieColors.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0A1628',
                    border: '1px solid rgba(122, 72, 50, 0.25)',
                    borderRadius: '0.5rem',
                  }}
                  labelStyle={{ color: '#E2DED8' }}
                  formatter={(value: number, name: string) => [
                    <span
                      style={{
                        color: severityColors[name as keyof typeof severityColors],
                        fontFamily: 'monospace'
                      }}
                    >
                      {value}
                    </span>,
                    <span
                      style={{
                        color: severityColors[name as keyof typeof severityColors]
                      }}
                    >
                      {name}
                    </span>,
                  ]}
                />
              </PieChart>
            </ResponsiveContainer>

            <div className="grid grid-cols-2 gap-3 mt-6">
              {distribution.map((item, index) => (
                <div
                  key={item.severity}
                  className="flex items-center justify-between p-3 bg-muted/20 rounded-lg"
                >
                  <div className="flex items-center gap-2">
                    <div
                      className="w-4 h-4 rounded-sm"
                      style={{ backgroundColor: pieColors[index] }}
                    />
                    <span className="text-sm">{item.severity}</span>
                  </div>
                  <span className="text-sm font-mono">{item.count}</span>
                </div>
              ))}
            </div>
          </GlassCard>

          {/* Bar Chart */}
          <GlassCard delay={0.25}>
            <div className="mb-6">
              <h2 className="text-2xl mb-1">Daily Alert Volume</h2>
              <p className="text-sm text-muted-foreground">Stacked severity comparison</p>
            </div>

            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(122, 72, 50, 0.08)" />
                <XAxis
                  dataKey="date"
                  stroke="#9CA3AF"
                  tick={{ fill: '#9CA3AF', fontSize: 11 }}
                />
                <YAxis stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(122,72,50,0.08)' }} />
                <Legend
                  wrapperStyle={{ color: '#df1a1a' }}
                  iconType="square"
                />
                <Bar dataKey="Critical" stackId="a" fill={severityColors.Critical} />
                <Bar dataKey="High" stackId="a" fill={severityColors.High} />
                <Bar dataKey="Medium" stackId="a" fill={severityColors.Medium} />
                <Bar dataKey="Low" stackId="a" fill={severityColors.Low} />
              </BarChart>
            </ResponsiveContainer>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}