import React from 'react';

export default function SeverityBadge({ severity = 'INFO', size = 'sm' }) {
  const sev = (severity || 'INFO').toUpperCase();

  const styles = {
    CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/35',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/35',
    MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/35',
    LOW: 'bg-sky-500/15 text-sky-400 border-sky-500/35',
    INFO: 'bg-slate-500/15 text-slate-400 border-slate-500/30'
  };

  const currentStyle = styles[sev] || styles.INFO;
  const sizeClasses = size === 'lg' 
    ? 'px-3 py-1 text-xs font-bold' 
    : 'px-2 py-0.5 text-[11px] font-bold';

  return (
    <span className={`inline-flex items-center gap-1 rounded font-mono uppercase tracking-wider border ${sizeClasses} ${currentStyle}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
      {sev}
    </span>
  );
}
