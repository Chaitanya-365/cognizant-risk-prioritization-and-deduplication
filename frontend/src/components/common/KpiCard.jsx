import React from 'react';

export default function KpiCard({ label, value, subtext, icon: Icon, color = 'sky', delta, badge }) {
  const colorMap = {
    sky: 'border-sky-500/20 text-sky-400 bg-sky-500/10 shadow-sky-500/5',
    emerald: 'border-emerald-500/20 text-emerald-400 bg-emerald-500/10 shadow-emerald-500/5',
    rose: 'border-rose-500/20 text-rose-400 bg-rose-500/10 shadow-rose-500/5',
    amber: 'border-amber-500/20 text-amber-400 bg-amber-500/10 shadow-amber-500/5',
    purple: 'border-purple-500/20 text-purple-400 bg-purple-500/10 shadow-purple-500/5',
    red: 'border-red-500/25 text-red-400 bg-red-500/10 shadow-red-500/10'
  };

  const textMap = {
    sky: 'text-sky-400',
    emerald: 'text-emerald-400',
    rose: 'text-rose-400',
    amber: 'text-amber-400',
    purple: 'text-purple-400',
    red: 'text-red-400'
  };

  return (
    <div className="glass-card rounded-xl p-4 relative overflow-hidden group">
      {/* Glow highlight */}
      <div className={`absolute top-0 right-0 w-24 h-24 rounded-full blur-2xl opacity-10 pointer-events-none ${textMap[color]}`}></div>

      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">
          {label}
        </span>
        {Icon && (
          <div className={`w-7 h-7 rounded-lg flex items-center justify-center border ${colorMap[color]}`}>
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>

      <div className="flex items-baseline gap-2">
        <span className={`text-2xl lg:text-3xl font-extrabold font-mono tracking-tight ${textMap[color]}`}>
          {value}
        </span>
        {delta && (
          <span className="text-xs font-mono font-bold text-emerald-400 flex items-center">
            {delta}
          </span>
        )}
        {badge && (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold">
            {badge}
          </span>
        )}
      </div>

      {subtext && (
        <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1.5">
          {subtext}
        </div>
      )}
    </div>
  );
}
