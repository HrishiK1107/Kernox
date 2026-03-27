import { useState, useEffect } from 'react';
import { Home, Shield, Server, BarChart3, Bell } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { mockAlerts as fallbackAlerts } from '../data/mockData';
import { fetchAlerts } from '../lib/api';

interface BottomNavigationProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
}

const tabs = [
  { id: 'home', label: 'Home', icon: Home },
  { id: 'alerts', label: 'Alerts', icon: Shield },
  { id: 'endpoints', label: 'Endpoints', icon: Server },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
];

export function BottomNavigation({ activeTab, onTabChange }: BottomNavigationProps) {
  const [openAlerts, setOpenAlerts] = useState(
    fallbackAlerts.filter((a) => a.status === 'open').length,
  );

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const data = await fetchAlerts({ status: 'open', page_size: '1' });
        if (mounted) setOpenAlerts(data.total);
      } catch { /* keep fallback */ }
    }
    load();
    const id = setInterval(load, 30_000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  return (
    <motion.div
      initial={{ y: 80, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ type: 'spring', damping: 22, stiffness: 120, delay: 0.2 }}
      className="fixed bottom-0 left-0 right-0 z-50"
    >
      {/* Thin top border glow line */}
      <div className="h-px w-full bg-gradient-to-r from-transparent via-[#7A4832]/30 to-transparent" />

      <div
        className="flex items-center justify-between px-8 py-3"
        style={{
          background: 'linear-gradient(to bottom, rgba(5,11,22,0.96), rgba(3,8,16,0.98))',
          backdropFilter: 'blur(24px)',
          boxShadow: '0 -8px 32px rgba(0,0,0,0.6)',
        }}
      >
        {/* Left spacer */}
        <div className="w-28" />

        {/* Centered icon group */}
        <div className="flex items-center gap-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;

            return (
              <div key={tab.id} className="relative group">
                <motion.button
                  onClick={() => onTabChange(tab.id)}
                  whileTap={{ scale: 0.92 }}
                  transition={{ type: 'spring', damping: 18, stiffness: 350 }}
                  className="relative flex items-center justify-center w-12 h-12 rounded-xl transition-colors"
                >
                  {/* Active pill background */}
                  <AnimatePresence>
                    {isActive && (
                      <motion.span
                        layoutId="navActivePill"
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.8 }}
                        transition={{ type: 'spring', damping: 22, stiffness: 300 }}
                        className="absolute inset-0 rounded-xl"
                        style={{
                          background:
                            'linear-gradient(135deg, rgba(122,72,50,0.38) 0%, rgba(122,72,50,0.18) 100%)',
                          border: '1px solid rgba(122,72,50,0.35)',
                          boxShadow: '0 0 12px rgba(122,72,50,0.2)',
                        }}
                      />
                    )}
                  </AnimatePresence>

                  <Icon
                    className="relative z-10 transition-all"
                    style={{
                      width: isActive ? 22 : 20,
                      height: isActive ? 22 : 20,
                      color: isActive ? '#C4855A' : '#4A5568',
                      strokeWidth: isActive ? 2.2 : 1.8,
                    }}
                  />
                </motion.button>

                {/* Tooltip */}
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2.5 py-1 bg-[#060D1A]/95 border border-[#7A4832]/20 rounded-md text-xs text-[#E2DED8]/80 whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
                  {tab.label}
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: Alert count badge */}
        <motion.button
          onClick={() => onTabChange('alerts')}
          whileHover={{ scale: 1.04 }}
          whileTap={{ scale: 0.96 }}
          className="flex items-center gap-2 px-4 py-2 rounded-xl border border-[#7A4832]/20 bg-[#060D1A]/60 hover:bg-[#7A4832]/10 transition-colors w-28 justify-end"
        >
          <Bell
            className="w-4 h-4"
            style={{ color: openAlerts > 0 ? '#C4855A' : '#4A5568' }}
            strokeWidth={1.8}
          />
          <span
            className="text-sm font-mono"
            style={{ color: openAlerts > 0 ? '#C4855A' : '#4A5568' }}
          >
            {openAlerts} alert{openAlerts !== 1 ? 's' : ''}
          </span>
        </motion.button>
      </div>
    </motion.div>
  );
}