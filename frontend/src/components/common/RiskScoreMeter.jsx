import React from 'react';

export default function RiskScoreMeter({ score = 0, size = 'md', showMeter = true }) {
  const num = Math.min(100, Math.max(0, Number(score) || 0));

  let colorClass = 'text-sky-400 bg-sky-400';
  let badgeBorder = 'border-sky-500/40';
  if (num >= 75) {
    colorClass = 'text-red-400 bg-red-500';
    badgeBorder = 'border-red-500/50';
  } else if (num >= 50) {
    colorClass = 'text-orange-400 bg-orange-500';
    badgeBorder = 'border-orange-500/40';
  } else if (num >= 25) {
    colorClass = 'text-amber-400 bg-amber-500';
    badgeBorder = 'border-amber-500/40';
  }

  const isLg = size === 'lg';

  return (
    <div className="flex items-center gap-2">
      <div className={`font-mono font-bold ${isLg ? 'text-2xl' : 'text-sm'} ${colorClass.split(' ')[0]}`}>
        {num}
        <span className="text-[10px] text-slate-500 font-normal">/100</span>
      </div>

      {showMeter && (
        <div className="w-12 h-1.5 rounded-full bg-slate-800 overflow-hidden shrink-0">
          <div 
            className={`h-full rounded-full transition-all duration-500 ${colorClass.split(' ')[1]}`} 
            style={{ width: `${num}%` }}
          />
        </div>
      )}
    </div>
  );
}
