import React from 'react';

const FACTOR_MAX_POINTS = {
  "1. CVSS Base Severity": 25,
  "2. EPSS Exploit Likelihood": 20,
  "3. CISA KEV Status": 15,
  "4. Exploit Availability": 10,
  "5. Asset Criticality": 10,
  "6. Internet Exposure": 10,
  "7. Scanner Confidence": 10
};

export default function RiskBreakdown({ breakdown = {}, totalScore = 0 }) {
  const entries = Object.entries(breakdown);

  // If breakdown object is empty or different keys, render default factors
  const factors = entries.length > 0 ? entries : [
    ["1. CVSS Base Severity", Math.min(25, Math.round(totalScore * 0.25))],
    ["2. EPSS Exploit Likelihood", Math.min(20, Math.round(totalScore * 0.20))],
    ["3. CISA KEV Status", 15],
    ["4. Exploit Availability", 10],
    ["5. Asset Criticality", 10],
    ["6. Internet Exposure", 10],
    ["7. Scanner Confidence", 10]
  ];

  return (
    <div className="space-y-2.5">
      {factors.map(([factorName, pts]) => {
        const maxPts = FACTOR_MAX_POINTS[factorName] || 20;
        const pct = Math.min(100, Math.max(0, (pts / maxPts) * 100));
        
        let barColor = 'bg-sky-400';
        if (factorName.includes('KEV') || factorName.includes('CVSS') && pts >= 20) {
          barColor = 'bg-red-500';
        } else if (factorName.includes('EPSS') || factorName.includes('Exploit')) {
          barColor = 'bg-orange-500';
        } else if (factorName.includes('Asset') || factorName.includes('Exposure')) {
          barColor = 'bg-purple-400';
        }

        return (
          <div key={factorName} className="space-y-1">
            <div className="flex justify-between items-center text-xs">
              <span className="text-slate-300 font-medium">{factorName}</span>
              <span className="font-mono font-bold text-sky-400">
                +{pts} <span className="text-slate-500 font-normal">/ {maxPts} pts</span>
              </span>
            </div>
            <div className="w-full h-1.5 rounded-full bg-slate-800/80 overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-500 ${barColor}`}
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}

      <div className="pt-3 mt-3 border-t border-slate-800 flex justify-between items-center text-xs font-bold">
        <span className="text-slate-200">Total Calculated Multi-Factor Risk:</span>
        <span className="font-mono text-sm text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/30">
          {totalScore} / 100
        </span>
      </div>
    </div>
  );
}
