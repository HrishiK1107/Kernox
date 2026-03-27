import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Server, Circle } from 'lucide-react';
import { GlassCard } from '../components/Card';
import { mockEndpoints as fallbackEndpoints, Endpoint } from '../data/mockData';
import { fetchEndpointRisk } from '../lib/api';
import { useTheme } from '../context/ThemeContext';

export default function EndpointsPage() {
  const { colors } = useTheme();
  const [endpoints, setEndpoints] = useState(fallbackEndpoints);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const data = await fetchEndpointRisk({ page_size: '100' });
        if (!mounted) return;
        if (data.results.length > 0) {
          setEndpoints(
            data.results.map((ep) => ({
              endpoint_id: ep.endpoint_id,
              hostname: ep.hostname || ep.endpoint_id,
              risk_index: ep.risk_index,
              last_seen: new Date().toISOString(),
              status: (ep.risk_index >= 80 ? 'warning' : 'online') as Endpoint['status'],
              os: '—',
              ip_address: '—',
            })),
          );
        }
      } catch { /* keep fallback */ }
    }
    load();
    const id = setInterval(load, 30_000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  const getRiskColor = (risk: number) => {
    if (risk >= 80) return colors.severity.critical;
    if (risk >= 60) return colors.severity.high;
    if (risk >= 30) return colors.severity.medium;
    return colors.severity.low;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return colors.severity.low;
      case 'warning':
        return colors.severity.medium;
      case 'offline':
        return colors.severity.critical;
      default:
        return '#4A5568';
    }
  };

  const highRiskCount = endpoints.filter((e) => e.risk_index >= 60).length;
  const avgRisk = endpoints.length > 0
    ? Math.round(endpoints.reduce((sum, e) => sum + e.risk_index, 0) / endpoints.length)
    : 0;

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
          className="absolute bottom-0 left-0 w-2/3 h-2/3 bg-gradient-to-tr from-accent/10 to-transparent rounded-full blur-3xl"
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
          <h1 className="text-4xl tracking-tight mb-2">Endpoint Registry</h1>
          <p className="text-muted-foreground">Monitor endpoint health and risk metrics</p>
        </motion.div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <GlassCard delay={0.1}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-muted-foreground mb-2">Total Endpoints</p>
                <p className="text-3xl">{endpoints.length}</p>
              </div>
              <div className="p-3 bg-accent/10 rounded-lg">
                <Server className="w-6 h-6 text-accent" />
              </div>
            </div>
          </GlassCard>

          <GlassCard delay={0.15}>
            <div>
              <p className="text-muted-foreground mb-2">High Risk Endpoints</p>
              <p className="text-3xl">{highRiskCount}</p>
            </div>
          </GlassCard>

          <GlassCard delay={0.2}>
            <div>
              <p className="text-muted-foreground mb-2">Average Risk Index</p>
              <p className="text-3xl">{avgRisk}</p>
            </div>
          </GlassCard>
        </div>

        {/* Endpoints Table */}
        <GlassCard delay={0.25}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-4 px-4 text-muted-foreground">Status</th>
                  <th className="text-left py-4 px-4 text-muted-foreground">Endpoint ID</th>
                  <th className="text-left py-4 px-4 text-muted-foreground">Hostname</th>
                  <th className="text-left py-4 px-4 text-muted-foreground">Risk Index</th>
                  <th className="text-left py-4 px-4 text-muted-foreground">Operating System</th>
                  <th className="text-left py-4 px-4 text-muted-foreground">IP Address</th>
                  <th className="text-left py-4 px-4 text-muted-foreground">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map((endpoint, index) => (
                  <motion.tr
                    key={endpoint.endpoint_id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.3 + index * 0.04 }}
                    whileHover={{ backgroundColor: 'rgba(122, 72, 50, 0.06)' }}
                    className="border-b border-border/50 transition-colors cursor-default"
                  >
                    <td className="py-4 px-4">
                      <Circle
                        className="w-3 h-3"
                        style={{
                          fill: getStatusColor(endpoint.status),
                          color: getStatusColor(endpoint.status),
                        }}
                      />
                    </td>
                    <td className="py-4 px-4 font-mono text-sm">{endpoint.endpoint_id}</td>
                    <td className="py-4 px-4 text-sm">{endpoint.hostname}</td>
                    <td className="py-4 px-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm w-8">{endpoint.risk_index}</span>
                          <div className="flex-1 max-w-xs">
                            <div className="h-2 bg-muted rounded-full overflow-hidden">
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${endpoint.risk_index}%` }}
                                transition={{ duration: 1, delay: 0.3 + index * 0.04 }}
                                className="h-full rounded-full transition-all"
                                style={{
                                  backgroundColor: getRiskColor(endpoint.risk_index),
                                }}
                              />
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="py-4 px-4 text-sm">{endpoint.os}</td>
                    <td className="py-4 px-4 text-sm font-mono">{endpoint.ip_address}</td>
                    <td className="py-4 px-4 text-sm text-muted-foreground">
                      {new Date(endpoint.last_seen).toLocaleString()}
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