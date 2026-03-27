import {
  useState,
  useRef,
  useEffect,
  useCallback,
} from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "motion/react";
import { Filter, Search, ChevronDown, X } from "lucide-react";
import { GlassCard } from "../components/Card";
import { AlertDrawer } from "../components/AlertDrawer";
import { mockAlerts as fallbackAlerts, Alert } from "../data/mockData";
import { fetchAlerts } from "../lib/api";
import { useTheme } from "../context/ThemeContext";

// ─── Portal dropdown — renders outside stacking contexts ───────────────────
interface DropdownOption {
  value: string;
  label: string;
}
interface ThemedDropdownProps {
  value: string;
  onChange: (val: string) => void;
  options: DropdownOption[];
}

function ThemedDropdown({
  value,
  onChange,
  options,
}: ThemedDropdownProps) {
  const [open, setOpen] = useState(false);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);

  const selected = options.find((o) => o.value === value);

  const openMenu = useCallback(() => {
    if (btnRef.current) {
      setRect(btnRef.current.getBoundingClientRect());
    }
    setOpen(true);
  }, []);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (
        btnRef.current &&
        !btnRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () =>
      document.removeEventListener("mousedown", handler);
  }, [open]);

  // Close on scroll/resize so position stays accurate
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  return (
    <>
      <button
        ref={btnRef}
        onClick={() => (open ? setOpen(false) : openMenu())}
        className="flex items-center gap-2 px-3 py-2 rounded-lg border border-[#7A4832]/22 bg-[#040A18]/70 hover:bg-[#040A18]/90 hover:border-[#7A4832]/40 transition-all text-sm min-w-[140px]"
        style={{ backdropFilter: "blur(10px)" }}
      >
        <span className="flex-1 text-left text-[#E2DED8]/85">
          {selected?.label ?? "Select"}
        </span>
        <motion.span
          animate={{ rotate: open ? 180 : 0 }}
          transition={{ duration: 0.18 }}
        >
          <ChevronDown className="w-3.5 h-3.5 text-[#5C6474]" />
        </motion.span>
      </button>

      {/* Portal — renders directly on body, no stacking context issues */}
      {open &&
        rect &&
        createPortal(
          <AnimatePresence>
            <motion.div
              initial={{ opacity: 0, y: -6, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -4, scale: 0.97 }}
              transition={{ duration: 0.14 }}
              style={{
                position: "fixed",
                top: rect.bottom + 6,
                left: rect.left,
                minWidth: rect.width,
                zIndex: 9999,
                background:
                  "linear-gradient(135deg, rgba(4,10,22,0.99) 0%, rgba(6,14,28,0.99) 100%)",
                border: "1px solid rgba(122,72,50,0.3)",
                borderRadius: "0.75rem",
                boxShadow:
                  "0 16px 48px rgba(0,0,0,0.85), 0 0 0 1px rgba(122,72,50,0.08)",
                backdropFilter: "blur(24px)",
                overflow: "hidden",
              }}
            >
              {options.map((opt, i) => (
                <button
                  key={opt.value}
                  onMouseDown={(e) => {
                    e.preventDefault(); // prevent blur before click
                    onChange(opt.value);
                    setOpen(false);
                  }}
                  style={{
                    display: "block",
                    width: "100%",
                    textAlign: "left",
                    padding: "10px 16px",
                    fontSize: "0.875rem",
                    color:
                      value === opt.value
                        ? "#C4855A"
                        : "#8A9BB0",
                    background: "transparent",
                    borderBottom:
                      i < options.length - 1
                        ? "1px solid rgba(122,72,50,0.08)"
                        : "none",
                    cursor: "pointer",
                    transition: "background 0.12s, color 0.12s",
                  }}
                  onMouseEnter={(e) => {
                    (
                      e.currentTarget as HTMLButtonElement
                    ).style.background = "rgba(122,72,50,0.12)";
                    (
                      e.currentTarget as HTMLButtonElement
                    ).style.color = "#E2DED8";
                  }}
                  onMouseLeave={(e) => {
                    (
                      e.currentTarget as HTMLButtonElement
                    ).style.background = "transparent";
                    (
                      e.currentTarget as HTMLButtonElement
                    ).style.color =
                      value === opt.value
                        ? "#C4855A"
                        : "#8A9BB0";
                  }}
                >
                  {value === opt.value && (
                    <span
                      style={{
                        display: "inline-block",
                        width: 6,
                        height: 6,
                        borderRadius: "50%",
                        backgroundColor: "#C4855A",
                        marginRight: 8,
                        verticalAlign: "middle",
                        marginBottom: 1,
                      }}
                    />
                  )}
                  {opt.label}
                </button>
              ))}
            </motion.div>
          </AnimatePresence>,
          document.body,
        )}
    </>
  );
}

// ─── Main page ──────────────────────────────────────────────────────────────
export default function AlertsPage() {
  const { colors } = useTheme();
  const [selectedAlert, setSelectedAlert] =
    useState<Alert | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [allAlerts, setAllAlerts] = useState<Alert[]>(fallbackAlerts);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const data = await fetchAlerts({ page_size: '100' });
        if (!mounted) return;
        setAllAlerts(
          data.results.map((a) => ({
            alert_id: `ALT-${a.id}`,
            endpoint_id: String(a.endpoint_id),
            endpoint_hostname: String(a.endpoint_id),
            severity: a.severity as Alert['severity'],
            risk_score: a.risk_score,
            status: a.status as Alert['status'],
            detection_rule: a.detection_rule,
            description: a.payload?.description || a.detection_rule,
            payload: a.payload,
            created_at: a.created_at,
            updated_at: a.updated_at,
            resolved_at: a.resolved_at,
          })),
        );
      } catch { /* keep fallback */ }
    }
    load();
    const id = setInterval(load, 30_000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  const severityColors = colors.severity;

  const handleRowClick = (alert: Alert) => {
    setSelectedAlert(alert);
    setIsDrawerOpen(true);
  };

  const filteredAlerts = allAlerts.filter((alert) => {
    const severityMatch =
      severityFilter === "all" ||
      alert.severity === severityFilter;
    const statusMatch =
      statusFilter === "all" || alert.status === statusFilter;
    const q = searchQuery.toLowerCase();
    const searchMatch =
      !q ||
      alert.alert_id.toLowerCase().includes(q) ||
      (alert.endpoint_hostname ?? "")
        .toLowerCase()
        .includes(q) ||
      alert.detection_rule.toLowerCase().includes(q) ||
      alert.severity.toLowerCase().includes(q);
    return severityMatch && statusMatch && searchMatch;
  });

  const severityOptions: DropdownOption[] = [
    { value: "all", label: "All Severities" },
    { value: "critical", label: "Critical" },
    { value: "high", label: "High" },
    { value: "medium", label: "Medium" },
    { value: "low", label: "Low" },
  ];

  const statusOptions: DropdownOption[] = [
    { value: "all", label: "All Statuses" },
    { value: "open", label: "Open" },
    { value: "investigating", label: "Investigating" },
    { value: "resolved", label: "Resolved" },
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
          transition={{
            duration: 8,
            repeat: Infinity,
            ease: "easeInOut",
          }}
          className="absolute top-0 right-0 w-2/3 h-2/3 bg-gradient-to-bl from-accent/10 to-transparent rounded-full blur-3xl"
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
          <h1 className="text-4xl tracking-tight mb-2">
            Alert Management
          </h1>
          <p className="text-muted-foreground">
            Monitor and investigate security alerts
          </p>
        </motion.div>

        {/* Search + Filter Bar */}
        <GlassCard className="mb-6" delay={0.1}>
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            {/* Search input */}
            <div className="relative flex-1 w-full sm:w-auto">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5C6474] pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search alerts, endpoints, rules…"
                className="w-full pl-9 pr-8 py-2 rounded-lg border border-[#7A4832]/22 bg-[#040A18]/70 text-sm text-[#E2DED8]/85 placeholder-[#3A4455] focus:outline-none focus:border-[#7A4832]/50 focus:bg-[#040A18]/90 transition-all"
                style={{ backdropFilter: "blur(10px)" }}
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#5C6474] hover:text-[#E2DED8] transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Divider */}
            <div className="hidden sm:block w-px h-6 bg-[#7A4832]/15" />

            {/* Filter group */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2 text-[#5C6474]">
                <Filter className="w-4 h-4" />
                <span className="text-xs tracking-widest uppercase">
                  Filter
                </span>
              </div>
              <ThemedDropdown
                value={severityFilter}
                onChange={setSeverityFilter}
                options={severityOptions}
              />
              <ThemedDropdown
                value={statusFilter}
                onChange={setStatusFilter}
                options={statusOptions}
              />
            </div>

            {/* Result count */}
            <div className="ml-auto flex-shrink-0">
              <span className="text-sm font-mono text-[#5C6474]">
                {filteredAlerts.length}
                <span className="text-[#3A4455]">
                  /{allAlerts.length}
                </span>
              </span>
            </div>
          </div>

          {/* Active filter chips */}
          {(severityFilter !== "all" ||
            statusFilter !== "all" ||
            searchQuery) && (
              <div className="flex items-center gap-2 mt-3 pt-3 border-t border-[#7A4832]/10 flex-wrap">
                <span className="text-xs text-[#5C6474]">
                  Active:
                </span>
                {severityFilter !== "all" && (
                  <button
                    onClick={() => setSeverityFilter("all")}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-full text-xs border border-[#7A4832]/25 bg-[#7A4832]/10 text-[#C4855A] hover:bg-[#7A4832]/20 transition-colors"
                  >
                    {severityFilter} <X className="w-3 h-3" />
                  </button>
                )}
                {statusFilter !== "all" && (
                  <button
                    onClick={() => setStatusFilter("all")}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-full text-xs border border-[#7A4832]/25 bg-[#7A4832]/10 text-[#C4855A] hover:bg-[#7A4832]/20 transition-colors"
                  >
                    {statusFilter} <X className="w-3 h-3" />
                  </button>
                )}
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery("")}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-full text-xs border border-[#7A4832]/25 bg-[#7A4832]/10 text-[#C4855A] hover:bg-[#7A4832]/20 transition-colors"
                  >
                    "{searchQuery}" <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            )}
        </GlassCard>

        {/* Alerts Table */}
        <GlassCard delay={0.2}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-4 px-4 text-muted-foreground">
                    Alert ID
                  </th>
                  <th className="text-left py-4 px-4 text-muted-foreground">
                    Endpoint
                  </th>
                  <th className="text-left py-4 px-4 text-muted-foreground">
                    Severity
                  </th>
                  <th className="text-left py-4 px-4 text-muted-foreground">
                    Risk Score
                  </th>
                  <th className="text-left py-4 px-4 text-muted-foreground">
                    Detection Rule
                  </th>
                  <th className="text-left py-4 px-4 text-muted-foreground">
                    Status
                  </th>
                  <th className="text-left py-4 px-4 text-muted-foreground">
                    Created
                  </th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence mode="popLayout">
                  {filteredAlerts.length === 0 ? (
                    <tr>
                      <td
                        colSpan={7}
                        className="py-16 text-center text-[#5C6474]"
                      >
                        No alerts match your filters
                      </td>
                    </tr>
                  ) : (
                    filteredAlerts.map((alert, index) => (
                      <motion.tr
                        key={alert.alert_id}
                        layout
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{
                          delay: 0.05 + index * 0.025,
                        }}
                        onClick={() => handleRowClick(alert)}
                        whileHover={{
                          backgroundColor:
                            "rgba(122, 72, 50, 0.06)",
                        }}
                        className="border-b border-border/50 transition-colors cursor-pointer"
                      >
                        <td className="py-4 px-4 font-mono text-sm">
                          {alert.alert_id}
                        </td>
                        <td className="py-4 px-4 text-sm">
                          {alert.endpoint_hostname}
                        </td>
                        <td className="py-4 px-4">
                          <span
                            className="capitalize text-sm px-3 py-1 rounded-full"
                            style={{
                              color:
                                severityColors[alert.severity],
                              backgroundColor: `${severityColors[alert.severity]}18`,
                              border: `1px solid ${severityColors[alert.severity]}35`,
                            }}
                          >
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-4 px-4">
                          <div className="flex items-center gap-2">
                            <span className="text-sm">
                              {alert.risk_score}
                            </span>
                            <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                              <div
                                className="h-full transition-all"
                                style={{
                                  width: `${alert.risk_score}%`,
                                  backgroundColor:
                                    severityColors[
                                    alert.severity
                                    ],
                                }}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="py-4 px-4 text-sm">
                          {alert.detection_rule}
                        </td>
                        <td className="py-4 px-4">
                          <span className="capitalize text-sm text-muted-foreground">
                            {alert.status}
                          </span>
                        </td>
                        <td className="py-4 px-4 text-sm text-muted-foreground font-mono">
                          {new Date(
                            alert.created_at,
                          ).toLocaleString()}
                        </td>
                      </motion.tr>
                    ))
                  )}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </GlassCard>
      </div>

      {/* Alert Drawer */}
      <AlertDrawer
        alert={selectedAlert}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />
    </div>
  );
}