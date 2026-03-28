import { motion, AnimatePresence } from 'motion/react';
import { X, Clock, CheckCircle2, AlertTriangle, Calendar, RefreshCw, ShieldCheck } from 'lucide-react';
import { Alert } from '../data/mockData';
import { useTheme } from '../context/ThemeContext';

interface AlertDrawerProps {
  alert: Alert | null;
  isOpen: boolean;
  onClose: () => void;
}

const statusIcons = {
  open:          AlertTriangle,
  investigating: Clock,
  resolved:      CheckCircle2,
};

const statusColors = {
  open:          '#CB181D',
  investigating: '#F16913',
  resolved:      '#1B75BE',
};

export function AlertDrawer({ alert, isOpen, onClose }: AlertDrawerProps) {
  const { colors } = useTheme();

  if (!alert) return null;

  const StatusIcon = statusIcons[alert.status];
  const severityColor = colors.severity[alert.severity];

  const timelineEvents = [
    {
      icon: Calendar,
      label: 'Alert Created',
      time: new Date(alert.created_at).toLocaleString(),
      color: colors.severity.critical,
    },
    {
      icon: RefreshCw,
      label: 'Last Updated',
      time: new Date(alert.updated_at).toLocaleString(),
      color: colors.severity.medium,
    },
    ...(alert.resolved_at
      ? [{
          icon: ShieldCheck,
          label: 'Resolved',
          time: new Date(alert.resolved_at).toLocaleString(),
          color: colors.severity.low,
        }]
      : []),
  ];

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/70 backdrop-blur-md z-40"
          />

          {/* Drawer — flex column so timeline can be independently scrollable */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed right-0 top-0 bottom-0 w-full max-w-2xl flex flex-col z-50"
            style={{
              background: 'linear-gradient(135deg, rgba(6,13,26,0.98) 0%, rgba(8,17,31,0.98) 100%)',
              borderLeft: '1px solid rgba(122,72,50,0.2)',
              boxShadow: '-10px 0 40px rgba(0, 0, 0, 0.65), 0 0 16px rgba(122, 72, 50, 0.08)',
              backdropFilter: 'blur(24px)',
            }}
          >
            {/* ── Scrollable content area ── */}
            <div className="flex-1 overflow-y-auto">
              <div className="p-8 pb-4">

                {/* Header */}
                <div className="flex items-start justify-between mb-8">
                  <div>
                    <h2 className="text-2xl mb-1">Alert Details</h2>
                    <p className="text-muted-foreground font-mono text-sm">{alert.alert_id}</p>
                  </div>
                  <button
                    onClick={onClose}
                    className="p-2 hover:bg-accent/10 rounded-lg transition-colors mt-0.5"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>

                {/* Severity + Risk score */}
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div
                    className="rounded-xl p-4 border"
                    style={{
                      backgroundColor: `${severityColor}12`,
                      borderColor: `${severityColor}30`,
                    }}
                  >
                    <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wide">Severity</p>
                    <p className="text-xl capitalize" style={{ color: severityColor }}>
                      {alert.severity}
                    </p>
                  </div>
                  <div className="rounded-xl p-4 border border-[#7A4832]/14 bg-[#040A18]/70">
                    <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wide">Risk Score</p>
                    <div className="flex items-end gap-2">
                      <span className="text-xl">{alert.risk_score}</span>
                      <span className="text-muted-foreground text-sm mb-0.5">/100</span>
                    </div>
                    <div className="mt-2 h-1.5 bg-[#09152A] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${alert.risk_score}%`, backgroundColor: severityColor }}
                      />
                    </div>
                  </div>
                </div>

                {/* Status */}
                <div className="rounded-xl p-4 border border-[#7A4832]/14 bg-[#040A18]/70 mb-6">
                  <div className="flex items-center gap-3">
                    <div
                      className="p-2 rounded-lg"
                      style={{ backgroundColor: `${statusColors[alert.status]}18` }}
                    >
                      <StatusIcon
                        className="w-4 h-4"
                        style={{ color: statusColors[alert.status] }}
                      />
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground uppercase tracking-wide">Status</p>
                      <p className="capitalize">{alert.status}</p>
                    </div>
                  </div>
                </div>

                {/* Detection Rule */}
                <div className="mb-6">
                  <h3 className="text-lg mb-3">Detection Rule</h3>
                  <div className="rounded-xl p-4 border border-[#7A4832]/14 bg-[#040A18]/70">
                    <p style={{ color: '#C4855A' }}>{alert.detection_rule}</p>
                    <p className="text-muted-foreground mt-2 text-sm leading-relaxed">{alert.description}</p>
                  </div>
                </div>

                {/* Endpoint Information */}
                <div className="mb-6">
                  <h3 className="text-lg mb-3">Endpoint</h3>
                  <div className="rounded-xl p-4 border border-[#7A4832]/14 bg-[#040A18]/70">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wide">Endpoint ID</p>
                        <p className="font-mono text-sm">{alert.endpoint_id}</p>
                      </div>
                      {alert.endpoint_hostname && (
                        <div>
                          <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wide">Hostname</p>
                          <p className="font-mono text-sm">{alert.endpoint_hostname}</p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

              </div>

              {/* ── Timeline (scrollable section) ── */}
              <div className="px-8 pb-24">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-lg">Timeline</h3>
                  <span className="text-xs text-[#5C6474] font-mono">{timelineEvents.length} events</span>
                </div>

                {/* Scrollable timeline container */}
                <div
                  className="overflow-y-auto rounded-xl border border-[#7A4832]/14 bg-[#040A18]/50"
                  style={{ maxHeight: '280px' }}
                >
                  <div className="relative p-4">
                    {/* Vertical line */}
                    <div className="absolute left-9 top-6 bottom-6 w-px bg-gradient-to-b from-[#7A4832]/30 via-[#7A4832]/15 to-transparent" />

                    <div className="space-y-4">
                      {timelineEvents.map((event, i) => {
                        const Icon = event.icon;
                        return (
                          <motion.div
                            key={i}
                            initial={{ opacity: 0, x: -8 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: i * 0.08 }}
                            className="flex items-start gap-4 relative"
                          >
                            {/* Icon bubble */}
                            <div
                              className="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center z-10 border"
                              style={{
                                backgroundColor: `${event.color}18`,
                                borderColor: `${event.color}35`,
                              }}
                            >
                              <Icon className="w-3.5 h-3.5" style={{ color: event.color }} />
                            </div>

                            {/* Content */}
                            <div className="flex-1 min-w-0 pt-0.5">
                              <p className="text-sm mb-0.5" style={{ color: '#E2DED8' }}>
                                {event.label}
                              </p>
                              <p className="text-xs font-mono text-[#5C6474]">{event.time}</p>
                            </div>

                            {/* Step number */}
                            <span className="text-xs text-[#3A4455] font-mono flex-shrink-0 pt-0.5">
                              #{i + 1}
                            </span>
                          </motion.div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
