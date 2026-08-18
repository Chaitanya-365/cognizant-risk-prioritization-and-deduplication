import React, { useState, useEffect } from 'react';
import { 
  Layers, 
  TrendingDown, 
  ShieldCheck, 
  Activity, 
  GitMerge, 
  CheckCircle2, 
  ArrowRight,
  ExternalLink,
  Zap,
  Server
} from 'lucide-react';
import { api, DEMO_DEDUPLICATION_DATA } from '../services/api';
import KpiCard from '../components/common/KpiCard';
import SeverityBadge from '../components/common/SeverityBadge';

export default function Page5_Deduplication({ onSelectFinding }) {
  const [dedupData, setDedupData] = useState(DEMO_DEDUPLICATION_DATA);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await api.getDeduplicationDetails();
        if (data) setDedupData(data);
      } catch (err) {
        console.warn('Using demo deduplication data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const totalRaw = dedupData.total_raw_count || 14;
  const uniqueCount = dedupData.unique_count || 6;
  const duplicatesRemoved = dedupData.duplicates_removed || 8;
  const reductionPercentage = dedupData.reduction_percentage || 57.1;
  const groups = dedupData.duplicate_groups || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400 uppercase tracking-widest mb-1">
          <Layers className="w-3.5 h-3.5" />
          Multi-Scanner Deduplication & Alert Consolidation Engine
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          Cross-Scanner Duplicate Merging & Noise Elimination
        </h1>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
          When multiple scanners scan the same application (e.g. Juice Shop), they report overlapping alerts for the same root vulnerability with different titles, parameters, and formats. The Deduplication Engine clusters them across CVE, CWE, Asset, and Path dimensions, producing unified canonical records and eliminating alert fatigue.
        </p>
      </div>

      {/* KPI Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          label="Total Ingested Alerts"
          value={totalRaw}
          subtext="Raw scanner outputs"
          icon={Activity}
          color="sky"
        />
        <KpiCard
          label="Actionable Unique Findings"
          value={uniqueCount}
          subtext="Consolidated records"
          icon={ShieldCheck}
          color="purple"
        />
        <KpiCard
          label="Duplicates Eliminated"
          value={duplicatesRemoved}
          delta={`-${reductionPercentage}%`}
          subtext="Redundant alerts dropped"
          icon={TrendingDown}
          color="emerald"
        />
        <KpiCard
          label="Noise Reduction Rate"
          value={`${reductionPercentage}%`}
          subtext="Analyst time saved"
          icon={GitMerge}
          color="emerald"
        />
      </div>

      {/* Interactive Visual Merging Architecture Diagram */}
      <div className="glass-panel rounded-2xl p-6 border border-emerald-500/20 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <GitMerge className="w-4 h-4 text-emerald-400" />
              Visual Multi-Scanner Merging Architecture
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              How heterogenous scanner outputs converge into a single authoritative canonical finding
            </p>
          </div>
          <span className="text-[11px] font-mono font-bold px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
            Multi-Level Clustering (CVE + CWE + Asset)
          </span>
        </div>

        {/* Diagram Nodes */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center pt-2">
          {/* Node 1: Raw Scanners */}
          <div className="space-y-2.5">
            <div className="text-xs font-bold text-slate-400 uppercase tracking-wider text-center">
              1. Raw Scanner Telemetry
            </div>

            <div className="p-3.5 rounded-xl bg-sky-950/40 border border-sky-500/30 space-y-1.5 shadow-md">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-sky-300 flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5" /> Nuclei Scan
                </span>
                <span className="text-[10px] font-mono text-slate-400">JSONL Stream</span>
              </div>
              <div className="text-[11px] text-slate-300 font-mono">
                template: cve-2021-44228-log4j
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-purple-950/40 border border-purple-500/30 space-y-1.5 shadow-md">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-purple-300 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" /> OWASP ZAP Alert
                </span>
                <span className="text-[10px] font-mono text-slate-400">REST API</span>
              </div>
              <div className="text-[11px] text-slate-300 font-mono">
                pluginId: 40018 (SQLi SQLite)
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-amber-950/40 border border-amber-500/30 space-y-1.5 shadow-md">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-amber-300 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5" /> OpenVAS Report
                </span>
                <span className="text-[10px] font-mono text-slate-400">NVT Report</span>
              </div>
              <div className="text-[11px] text-slate-300 font-mono">
                nvt: CVE-2022-29078 (Express)
              </div>
            </div>
          </div>

          {/* Node 2: Deduplication Engine Clustering */}
          <div className="flex flex-col items-center justify-center p-6 rounded-2xl bg-gradient-to-b from-emerald-950/30 to-slate-900 border border-emerald-500/30 text-center space-y-3 shadow-lg">
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.3)]">
              <Layers className="w-6 h-6" />
            </div>
            <div>
              <div className="font-bold text-sm text-white">Deduplication Clustering Engine</div>
              <div className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                Matches by CVE ID, normalized CWE classification, parameter names, and URL paths
              </div>
            </div>
            <div className="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 text-xs font-mono font-bold border border-emerald-500/40">
              56.7% Noise Elimination
            </div>
          </div>

          {/* Node 3: Canonical Merged Record */}
          <div className="space-y-2.5">
            <div className="text-xs font-bold text-slate-400 uppercase tracking-wider text-center">
              3. Authoritative Canonical Finding
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-emerald-500/40 space-y-2 shadow-lg shadow-emerald-500/10">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-emerald-400">Canonical Finding</span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px] font-bold">
                  Unified Record
                </span>
              </div>
              <div className="text-xs font-bold text-white">
                Apache Log4j RCE (Log4Shell)
              </div>
              <div className="text-[11px] text-slate-300 space-y-1 font-mono">
                <div><strong className="text-slate-500">Scanners:</strong> nuclei, zap</div>
                <div><strong className="text-slate-500">URLs Merged:</strong> 2 distinct endpoints</div>
                <div><strong className="text-slate-500">Confidence:</strong> CONFIRMED (Union Evidence)</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Duplicate Groups Table */}
      <div className="glass-panel rounded-2xl border border-sky-500/15 overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white">
              Duplicate Clusters & Merging Breakdown ({groups.length} Groups)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Detailed audit trail of raw scanner findings grouped into authoritative canonical records
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-900/90 text-slate-400 uppercase tracking-wider font-semibold text-[10px] border-b border-slate-800">
                <th className="py-3 px-4">Clustering Key</th>
                <th className="py-3 px-4">Canonical Finding Title</th>
                <th className="py-3 px-4">Participating Scanners</th>
                <th className="py-3 px-4 text-center">Raw Alerts</th>
                <th className="py-3 px-4">Endpoints Aggregated</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {groups.map((g, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3.5 px-4 text-sky-400 font-semibold">{g.group_key}</td>
                  <td className="py-3.5 px-4 font-sans font-bold text-white">
                    {g.primary_finding?.title}
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="flex gap-1">
                      {g.participating_scanners?.map((s, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] uppercase font-bold text-purple-300">
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3.5 px-4 text-center">
                    <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-bold">
                      {g.duplicate_count} merged
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-slate-400 text-[11px] max-w-xs truncate">
                    {g.all_urls?.join(', ')}
                  </td>
                  <td className="py-3.5 px-4 text-right font-sans">
                    <button
                      onClick={() => onSelectFinding({ finding: g.primary_finding, risk_score: 90, priority: 'P0' })}
                      className="text-xs font-semibold text-sky-400 hover:text-sky-300"
                    >
                      View Canonical &rarr;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
