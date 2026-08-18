import React from 'react';

export default function PriorityBadge({ priority = 'P3', showLabel = false, size = 'sm' }) {
  const p = (priority || 'P3').toUpperCase();

  const configs = {
    P0: {
      bg: 'bg-red-500/20 text-red-400 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.35)] animate-pulse',
      label: 'P0 Emergency',
      sla: '24h SLA'
    },
    P1: {
      bg: 'bg-orange-500/20 text-orange-400 border-orange-500/45',
      label: 'P1 Critical',
      sla: '72h SLA'
    },
    P2: {
      bg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      label: 'P2 High',
      sla: '7d SLA'
    },
    P3: {
      bg: 'bg-sky-500/15 text-sky-300 border-sky-500/35',
      label: 'P3 Medium',
      sla: '30d SLA'
    },
    P4: {
      bg: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
      label: 'P4 Low',
      sla: '90d SLA'
    }
  };

  const cfg = configs[p] || configs.P3;

  const sizeClasses = size === 'lg' 
    ? 'px-3 py-1 text-xs font-bold' 
    : 'px-2 py-0.5 text-[11px] font-bold';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded font-mono border ${sizeClasses} ${cfg.bg}`}>
      <span>{p}</span>
      {showLabel && <span className="opacity-90">• {cfg.label}</span>}
    </span>
  );
}
