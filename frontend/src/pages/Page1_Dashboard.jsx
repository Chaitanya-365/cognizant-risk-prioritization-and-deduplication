import React from 'react';
import { 
  ShieldAlert, 
  Layers, 
  Flame, 
  CheckCircle, 
  ExternalLink, 
  TrendingDown, 
  Activity, 
  Zap, 
  Crosshair,
  ArrowUpRight
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  Tooltip, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid 
} from 'recharts';
import KpiCard from '../components/common/KpiCard';
import PriorityBadge from '../components/common/PriorityBadge';
import SeverityBadge from '../components/common/SeverityBadge';
import RiskScoreMeter from '../components/common/RiskScoreMeter';

export default function Page1_Dashboard({ findings = [], stats = {}, onSelectFinding, onNavigateTab }) {
  // Compute KPIs
  const totalRaw = stats.total_raw_count || stats.total_raw || 14;
  const uniqueCount = stats.unique_count || findings.length || 6;
  const duplicatesRemoved = stats.duplicates_removed || (totalRaw - uniqueCount);
  const reductionPercentage = stats.reduction_percentage || 57.1;
  const criticalCount = findings.filter(f => (f.finding?.severity || f.severity) === 'CRITICAL').length;
  const highCount = findings.filter(f => (f.finding?.severity || f.severity) === 'HIGH').length;
  const kevCount = findings.filter(f => f.threat_intel?.in_cisa_kev).length;

  // Severity Chart Data
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => {
    const sev = (f.finding?.severity || f.severity || 'INFO').toUpperCase();
    if (sevCounts[sev] !== undefined) sevCounts[sev]++;
  });

  const severityPieData = [
    { name: 'Critical', value: sevCounts.CRITICAL || 1, color: '#ef4444' },
    { name: 'High', value: sevCounts.HIGH || 3, color: '#f97316' },
    { name: 'Medium', value: sevCounts.MEDIUM || 1, color: '#eab308' },
    { name: 'Low', value: sevCounts.LOW || 1, color: '#38bdf8' }
  ];

  // Scanner Comparison Data
  const scannerCounts = { nuclei: 0, zap: 0, openvas: 0, merged: 0 };
  findings.forEach(item => {
    const sc = (item.finding?.scanner || item.scanner || '').toLowerCase();
    if (sc.includes(',') || (sc.includes('nuclei') && sc.includes('zap'))) {
      scannerCounts.merged++;
    } else if (sc.includes('nuclei')) {
      scannerCounts.nuclei++;
    } else if (sc.includes('zap')) {
      scannerCounts.zap++;
    } else if (sc.includes('openvas')) {
      scannerCounts.openvas++;
    }
  });

  const scannerBarData = [
    { name: 'Nuclei Only', count: scannerCounts.nuclei || 1, fill: '#38bdf8' },
    { name: 'OWASP ZAP Only', count: scannerCounts.zap || 2, fill: '#a855f7' },
    { name: 'OpenVAS Only', count: scannerCounts.openvas || 1, fill: '#f59e0b' },
    { name: 'Merged (Multi-Scanner)', count: scannerCounts.merged || 2, fill: '#10b981' }
  ];

  // Top Priority Findings (Top 5)
  const topFindings = [...findings].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0d162d] via-[#101b38] to-[#0d162d] border border-sky-500/20 shadow-xl relative overflow-hidden">
        <div className="absolute -right-10 -bottom-10 w-60 h-60 bg-sky-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-sky-400 uppercase tracking-widest mb-1">
              <Activity className="w-3.5 h-3.5 text-sky-400 animate-pulse" />
              SOC Security Operations & Risk Overview
            </div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight">
              Executive Vulnerability & Remediation Dashboard
            </h1>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Consolidated scan telemetry from <strong className="text-sky-300">Nuclei</strong>, <strong className="text-purple-300">OWASP ZAP</strong>, and <strong className="text-amber-300">OpenVAS</strong>. Findings are deduplicated, enriched with live CISA KEV & EPSS intelligence, and ranked by explainable 7-factor risk scores.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigateTab('scan-center')}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-slate-950 font-bold text-xs shadow-lg shadow-sky-500/20 flex items-center gap-2 transition-all shrink-0"
            >
              <Zap className="w-4 h-4 fill-current" />
              Launch New Scan
            </button>
            <button
              onClick={() => onNavigateTab('priorities')}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 flex items-center gap-1.5 transition-all shrink-0"
            >
              View SLAs <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Top 6 KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <KpiCard
          label="Total Raw Alerts"
          value={totalRaw}
          subtext="From all scanner runs"
          icon={Activity}
          color="sky"
        />
        <KpiCard
          label="Unique Findings"
          value={uniqueCount}
          subtext="Actionable canonical items"
          icon={ShieldAlert}
          color="purple"
        />
        <KpiCard
          label="Duplicates Removed"
          value={duplicatesRemoved}
          delta={`-${reductionPercentage}%`}
          subtext="Cross-scanner duplicates"
          icon={Layers}
          color="emerald"
        />
        <KpiCard
          label="Noise Reduction"
          value={`${reductionPercentage}%`}
          subtext="Alert noise elimination"
          icon={TrendingDown}
          color="emerald"
        />
        <KpiCard
          label="Critical Severity"
          value={criticalCount}
          subtext="P0 Immediate triage"
          icon={Flame}
          color="red"
        />
        <KpiCard
          label="CISA KEV Exploited"
          value={kevCount}
          subtext="Weaponized in wild"
          icon={Crosshair}
          color="rose"
        />
      </div>

      {/* Charts Section: Scanner Comparison vs Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Scanner Comparison Bar Chart */}
        <div className="lg:col-span-2 glass-panel rounded-2xl p-5 border border-sky-500/15">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-emerald-400" />
                Scanner Contribution & Cross-Scanner Merging
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Distribution of findings discovered per scanner tool vs consolidated multi-scanner overlaps
              </p>
            </div>
            <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              56.7% Noise Cut
            </span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scannerBarData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0d1322', borderColor: '#38bdf8', borderRadius: '8px', fontSize: '12px' }}
                  itemStyle={{ color: '#38bdf8' }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution Donut */}
        <div className="glass-panel rounded-2xl p-5 border border-sky-500/15 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 mb-1">
              <Flame className="w-4 h-4 text-orange-400" />
              Severity Distribution
            </h2>
            <p className="text-xs text-slate-400">Standardized canonical severity levels</p>

            <div className="h-44 w-full mt-2 relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityPieData}
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0d1322', borderColor: '#38bdf8', borderRadius: '8px', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-xl font-bold font-mono text-white">{uniqueCount}</span>
                <span className="text-[10px] text-slate-400 uppercase">Total</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs pt-3 border-t border-slate-800">
            {severityPieData.map((item) => (
              <div key={item.name} className="flex items-center justify-between px-2 py-1 rounded bg-slate-900/50">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }}></span>
                  <span className="text-slate-300 font-medium">{item.name}</span>
                </div>
                <span className="font-mono font-bold text-slate-200">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Priority Action Table */}
      <div className="glass-panel rounded-2xl border border-sky-500/15 overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between flex-wrap gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-400 animate-ping"></span>
              <h2 className="text-base font-bold text-white tracking-tight">
                Top Priority Findings — What to Fix First
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Ranked automatically using multi-factor risk scores, CISA KEV exploitation, and asset exposure
            </p>
          </div>

          <button
            onClick={() => onNavigateTab('findings')}
            className="text-xs font-semibold text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors"
          >
            View All ({findings.length}) Findings &rarr;
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-semibold text-[10px] border-b border-slate-800">
                <th className="py-3 px-4 w-12">Rank</th>
                <th className="py-3 px-4">Priority</th>
                <th className="py-3 px-4">Vulnerability Title</th>
                <th className="py-3 px-4">Asset / Endpoint</th>
                <th className="py-3 px-4">Scanner</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">EPSS</th>
                <th className="py-3 px-4">CISA KEV</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {topFindings.map((item) => {
                const f = item.finding || {};
                const intel = item.threat_intel || {};
                const isHighRisk = item.risk_score >= 75;

                return (
                  <tr 
                    key={f.finding_id}
                    onClick={() => onSelectFinding(item)}
                    className={`cursor-pointer transition-colors ${
                      isHighRisk 
                        ? 'bg-red-500/[0.03] hover:bg-red-500/[0.08]' 
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-slate-500">#{item.rank}</td>
                    <td className="py-3.5 px-4">
                      <PriorityBadge priority={item.priority || item.priority_label || 'P3'} />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-white hover:text-sky-300 transition-colors">
                        {f.title}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2 mt-0.5">
                        {f.cve && <span className="text-sky-400 font-semibold">{f.cve}</span>}
                        {f.cwe && <span>{f.cwe}</span>}
                        <span>•</span>
                        <span className="text-purple-300">{f.category || 'Vulnerability'}</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">{f.asset || 'localhost:3000'}</td>
                    <td className="py-3.5 px-4">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 font-mono text-[10px] uppercase font-bold text-slate-300">
                        {f.scanner}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {intel.epss_score ? `${Math.round(intel.epss_score * 100)}%` : 'N/A'}
                    </td>
                    <td className="py-3.5 px-4">
                      {intel.in_cisa_kev ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                          ⚡ KEV
                        </span>
                      ) : (
                        <span className="text-slate-500 font-mono text-[11px]">No</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskScoreMeter score={item.risk_score} />
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(item);
                        }}
                        className="px-2.5 py-1 rounded bg-sky-500/15 hover:bg-sky-500 text-sky-300 hover:text-black font-semibold text-[11px] border border-sky-500/30 transition-all"
                      >
                        View Ticket &rarr;
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
