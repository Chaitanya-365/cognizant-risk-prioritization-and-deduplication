import React, { useState } from 'react';
import { 
  ListOrdered, 
  Clock, 
  ShieldAlert, 
  Flame, 
  AlertTriangle, 
  CheckCircle2, 
  Sparkles, 
  ArrowRight,
  ExternalLink,
  Copy,
  Check
} from 'lucide-react';
import PriorityBadge from '../components/common/PriorityBadge';
import SeverityBadge from '../components/common/SeverityBadge';
import RiskScoreMeter from '../components/common/RiskScoreMeter';

export default function Page6_Priorities({ findings = [], onSelectFinding, addToast }) {
  const [selectedTier, setSelectedTier] = useState('ALL');
  const [copiedId, setCopiedId] = useState(null);

  // Sort by risk score descending
  const sortedFindings = [...findings].sort((a, b) => b.risk_score - a.risk_score);

  const filtered = selectedTier === 'ALL'
    ? sortedFindings
    : sortedFindings.filter(f => (f.priority || f.priority_label || 'P3').toUpperCase() === selectedTier);

  // Group counts
  const p0Count = findings.filter(f => (f.priority || f.priority_label) === 'P0').length;
  const p1Count = findings.filter(f => (f.priority || f.priority_label) === 'P1').length;
  const p2Count = findings.filter(f => (f.priority || f.priority_label) === 'P2').length;
  const p3Count = findings.filter(f => (f.priority || f.priority_label) === 'P3').length;

  const handleCopyTicket = (e, item) => {
    e.stopPropagation();
    navigator.clipboard.writeText(item.security_ticket_markdown || '');
    setCopiedId(item.finding?.finding_id);
    addToast({ type: 'success', title: 'Ticket Copied', message: `Copied security ticket for ${item.finding?.title}` });
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <div className="space-y-6">
      {/* Hero Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-red-950/40 via-slate-900 to-indigo-950/40 border border-red-500/25 shadow-xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-red-400 uppercase tracking-widest mb-1">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Prioritized Remediation Action Plan
            </div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight">
              What Should the Security Team Fix First?
            </h1>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
              Every vulnerability is prioritized based on 7 real-world risk dimensions (CVSS severity, live EPSS likelihood, active CISA KEV exploitation, asset exposure, and verified PoCs).
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs shrink-0">
            <span className="px-3 py-1.5 rounded-xl bg-red-500/20 text-red-300 border border-red-500/40 font-bold animate-pulse">
              {p0Count} P0 Immediate Blockers
            </span>
          </div>
        </div>
      </div>

      {/* Priority Tier Filter Tabs */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <button
          onClick={() => setSelectedTier('ALL')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            selectedTier === 'ALL'
              ? 'bg-sky-500/15 border-sky-500/40 shadow-lg shadow-sky-500/10 text-white'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <div className="text-[10px] uppercase font-bold text-slate-400">All Tiers</div>
          <div className="text-xl font-bold font-mono text-white mt-0.5">{findings.length}</div>
          <div className="text-[11px] text-slate-500">Ranked backlog</div>
        </button>

        <button
          onClick={() => setSelectedTier('P0')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            selectedTier === 'P0'
              ? 'bg-red-500/20 border-red-500/50 shadow-lg shadow-red-500/20 text-white'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <div className="text-[10px] uppercase font-bold text-red-400 flex items-center justify-between">
            <span>P0 Emergency</span>
            <span className="text-[9px] font-mono">24h SLA</span>
          </div>
          <div className="text-xl font-bold font-mono text-red-400 mt-0.5">{p0Count}</div>
          <div className="text-[11px] text-slate-400">KEV & Weaponized</div>
        </button>

        <button
          onClick={() => setSelectedTier('P1')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            selectedTier === 'P1'
              ? 'bg-orange-500/20 border-orange-500/50 shadow-lg shadow-orange-500/20 text-white'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <div className="text-[10px] uppercase font-bold text-orange-400 flex items-center justify-between">
            <span>P1 Critical</span>
            <span className="text-[9px] font-mono">72h SLA</span>
          </div>
          <div className="text-xl font-bold font-mono text-orange-400 mt-0.5">{p1Count}</div>
          <div className="text-[11px] text-slate-400">High CVSS & Perimeter</div>
        </button>

        <button
          onClick={() => setSelectedTier('P2')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            selectedTier === 'P2'
              ? 'bg-amber-500/20 border-amber-500/50 shadow-lg shadow-amber-500/20 text-white'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <div className="text-[10px] uppercase font-bold text-amber-300 flex items-center justify-between">
            <span>P2 High</span>
            <span className="text-[9px] font-mono">7d SLA</span>
          </div>
          <div className="text-xl font-bold font-mono text-amber-300 mt-0.5">{p2Count}</div>
          <div className="text-[11px] text-slate-400">Next Sprint Cycle</div>
        </button>

        <button
          onClick={() => setSelectedTier('P3')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            selectedTier === 'P3'
              ? 'bg-sky-500/20 border-sky-500/50 shadow-lg shadow-sky-500/20 text-white'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <div className="text-[10px] uppercase font-bold text-sky-400 flex items-center justify-between">
            <span>P3 Medium</span>
            <span className="text-[9px] font-mono">30d SLA</span>
          </div>
          <div className="text-xl font-bold font-mono text-sky-400 mt-0.5">{p3Count}</div>
          <div className="text-[11px] text-slate-400">Standard Hardening</div>
        </button>
      </div>

      {/* Ranked Action Table */}
      <div className="glass-panel rounded-2xl border border-sky-500/15 overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white">
              Ranked Remediation Actions ({filtered.length} Items)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Assigned SLA targets and direct step-by-step remediation commands
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-900/90 text-slate-400 uppercase tracking-wider font-semibold text-[10px] border-b border-slate-800">
                <th className="py-3 px-4 w-12">Rank</th>
                <th className="py-3 px-4 w-28">Priority Tier</th>
                <th className="py-3 px-4">Vulnerability & Asset</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Key Prioritization Trigger</th>
                <th className="py-3 px-4">SLA Deadline</th>
                <th className="py-3 px-4">Recommended Action</th>
                <th className="py-3 px-4 text-right">Ticket</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map((item, idx) => {
                const f = item.finding || {};
                const intel = item.threat_intel || {};
                const priority = item.priority || item.priority_label || 'P3';
                const isP0 = priority === 'P0';

                return (
                  <tr
                    key={f.finding_id || idx}
                    onClick={() => onSelectFinding(item)}
                    className={`cursor-pointer transition-colors ${
                      isP0 
                        ? 'bg-red-500/[0.04] hover:bg-red-500/[0.09]' 
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-4 px-4 font-mono font-bold text-slate-400">
                      #{idx + 1}
                    </td>
                    <td className="py-4 px-4">
                      <PriorityBadge priority={priority} showLabel />
                    </td>
                    <td className="py-4 px-4 max-w-xs">
                      <div className="font-bold text-white hover:text-sky-300 transition-colors">
                        {f.title}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5 mt-0.5">
                        {f.cve && <span className="text-sky-400 font-semibold">{f.cve}</span>}
                        <span>•</span>
                        <span className="text-slate-300">{f.asset}</span>
                      </div>
                    </td>
                    <td className="py-4 px-4">
                      <RiskScoreMeter score={item.risk_score} />
                    </td>
                    <td className="py-4 px-4 text-slate-300 text-xs max-w-xs">
                      {item.why_prioritized && item.why_prioritized.length > 0 ? (
                        <span className="flex items-center gap-1.5 text-sky-300 font-medium">
                          <Sparkles className="w-3 h-3 text-amber-400 shrink-0" />
                          {item.why_prioritized[0]}
                        </span>
                      ) : (
                        <span className="text-slate-500">Standard vulnerability baseline</span>
                      )}
                    </td>
                    <td className="py-4 px-4 font-mono font-semibold text-sky-300 whitespace-nowrap">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5 text-sky-400" />
                        {item.sla || '24 Hours'}
                      </div>
                    </td>
                    <td className="py-4 px-4 text-slate-300 text-[11px] max-w-sm">
                      <div className="line-clamp-2 leading-relaxed">
                        {item.recommended_action || f.solution || 'Apply vendor patch.'}
                      </div>
                    </td>
                    <td className="py-4 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => handleCopyTicket(e, item)}
                        className="px-2.5 py-1 rounded bg-sky-500/20 hover:bg-sky-500 text-sky-300 hover:text-black font-semibold text-[11px] border border-sky-500/30 transition-all flex items-center gap-1 ml-auto"
                        title="Copy formatted Jira ticket to clipboard"
                      >
                        {copiedId === f.finding_id ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            Copy Ticket
                          </>
                        )}
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
