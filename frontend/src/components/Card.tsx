import { motion } from 'motion/react';
import { ReactNode } from 'react';

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  delay?: number;
}

export function GlassCard({ children, className = '', delay = 0 }: GlassCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
      className={`backdrop-blur-xl bg-gradient-to-br from-[#060D1A]/70 via-[#08111F]/60 to-[#060D1A]/70 border border-[#7A4832]/14 rounded-xl p-6 shadow-2xl ${className}`}
      style={{
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.55), inset 0 1px 1px rgba(255, 255, 255, 0.03)',
      }}
    >
      {children}
    </motion.div>
  );
}