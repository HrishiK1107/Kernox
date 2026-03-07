import { motion } from 'motion/react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  delay?: number;
}

export function MetricCard({ title, value, icon: Icon, trend, delay = 0 }: MetricCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
      whileHover={{ 
        scale: 1.02, 
        boxShadow: '0 12px 40px rgba(0, 0, 0, 0.65), 0 0 24px rgba(122, 72, 50, 0.2)' 
      }}
      className="backdrop-blur-xl bg-gradient-to-br from-[#060D1A]/70 via-[#08111F]/60 to-[#060D1A]/70 border border-[#7A4832]/14 rounded-xl p-6 shadow-2xl cursor-default"
      style={{
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.55), inset 0 1px 1px rgba(255, 255, 255, 0.03)',
      }}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-muted-foreground mb-2">{title}</p>
          <p className="text-3xl tracking-tight">{value}</p>
          {trend && <p className="text-sm text-muted-foreground mt-2">{trend}</p>}
        </div>
        <div className="p-3 bg-gradient-to-br from-[#7A4832]/18 to-[#7A4832]/5 backdrop-blur-sm rounded-lg border border-[#7A4832]/12">
          <Icon className="w-6 h-6 text-[#7A4832]" />
        </div>
      </div>
    </motion.div>
  );
}