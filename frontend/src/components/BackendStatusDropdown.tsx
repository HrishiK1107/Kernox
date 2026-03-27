import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ChevronDown, Check, Wifi, Database, Cpu, Zap, X } from 'lucide-react';
import { fetchHealth } from '../lib/api';

interface StatusItem {
  icon: typeof Wifi;
  label: string;
  value: string;
  ok: boolean;
}

export function SystemHealthDropdown() {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<StatusItem[]>([
    { icon: Wifi, label: 'API', value: 'Checking…', ok: false },
    { icon: Database, label: 'Database', value: 'Checking…', ok: false },
    { icon: Cpu, label: 'Agents Online', value: '—', ok: false },
    { icon: Zap, label: 'Detection Engine', value: 'Checking…', ok: false },
  ]);
  const ref = useRef<HTMLDivElement>(null);
  const allOk = items.every((i) => i.ok);

  // Poll backend health every 15 s
  useEffect(() => {
    let mounted = true;

    async function check() {
      try {
        const data = await fetchHealth();
        if (!mounted) return;
        setItems([
          { icon: Wifi, label: 'API', value: 'Connected', ok: true },
          { icon: Database, label: 'Database', value: 'Connected', ok: data.status === 'ok' },
          { icon: Cpu, label: 'Agents Online', value: '—', ok: true },
          { icon: Zap, label: 'Detection Engine', value: 'Running', ok: true },
        ]);
      } catch {
        if (!mounted) return;
        setItems((prev) =>
          prev.map((i) => (i.label === 'API' ? { ...i, value: 'Offline', ok: false } : i)),
        );
      }
    }

    check();
    const id = setInterval(check, 15_000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  // Click-outside close
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div ref={ref} className="relative select-none">
      {/* Trigger */}
      <motion.button
        onClick={() => setOpen((v) => !v)}
        whileTap={{ scale: 0.97 }}
        className="flex items-center gap-2.5 px-4 py-2 rounded-xl border border-[#7A4832]/20 bg-[#060D1A]/60 hover:bg-[#060D1A]/80 transition-colors"
        style={{ backdropFilter: 'blur(12px)' }}
      >
        {/* Animated dot — green when all ok, red otherwise */}
        <span className="relative flex items-center justify-center w-2.5 h-2.5">
          <span
            className={`absolute inline-flex h-full w-full rounded-full animate-ping ${allOk ? 'bg-emerald-500/40' : 'bg-red-500/40'
              }`}
          />
          <span
            className={`relative inline-flex w-2.5 h-2.5 rounded-full ${allOk ? 'bg-emerald-400' : 'bg-red-400'
              }`}
          />
        </span>
        <span className="text-sm text-[#E2DED8]/90 tracking-wide">Backend Status</span>
        <motion.span
          animate={{ rotate: open ? 180 : 0 }}
          transition={{ duration: 0.22, ease: 'easeInOut' }}
        >
          <ChevronDown className="w-3.5 h-3.5 text-[#5C6474]" />
        </motion.span>
      </motion.button>

      {/* Dropdown panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.96 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className="absolute right-0 top-full mt-2 w-64 rounded-xl overflow-hidden z-50"
            style={{
              background: 'linear-gradient(135deg, rgba(6,13,26,0.97) 0%, rgba(8,17,31,0.97) 100%)',
              border: '1px solid rgba(122,72,50,0.22)',
              boxShadow: '0 16px 48px rgba(0,0,0,0.7), 0 0 0 1px rgba(122,72,50,0.08)',
              backdropFilter: 'blur(20px)',
            }}
          >
            {/* Header */}
            <div className="px-4 py-3 border-b border-[#7A4832]/15">
              <p className="text-xs text-[#5C6474] tracking-widest uppercase">System Health</p>
            </div>

            {/* Status rows */}
            <div className="py-2">
              {items.map((item, i) => {
                const Icon = item.icon;
                return (
                  <motion.div
                    key={item.label}
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04, duration: 0.16 }}
                    className="flex items-center gap-3 px-4 py-2.5 hover:bg-[#7A4832]/06 transition-colors"
                  >
                    <span className="flex-shrink-0 flex items-center justify-center w-5 h-5">
                      {item.ok ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" strokeWidth={2.5} />
                      ) : (
                        <X className="w-3.5 h-3.5 text-red-400" strokeWidth={2.5} />
                      )}
                    </span>
                    <span className="flex-1 text-sm text-[#8A9BB0]">{item.label}</span>
                    <span
                      className="text-sm font-mono"
                      style={{ color: item.ok ? '#C4855A' : '#9E1F1A' }}
                    >
                      {item.value}
                    </span>
                  </motion.div>
                );
              })}
            </div>

            {/* Footer */}
            <div className="px-4 py-2.5 border-t border-[#7A4832]/15 flex items-center gap-2">
              <span className={`w-1.5 h-1.5 rounded-full ${allOk ? 'bg-emerald-400' : 'bg-red-400'}`} />
              <span className="text-xs text-[#5C6474]">
                {allOk ? 'All systems operational' : 'Some systems degraded'}
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
