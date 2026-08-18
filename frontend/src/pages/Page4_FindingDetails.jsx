import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Copy, 
  Check, 
  Clock, 
  ExternalLink, 
  Sparkles, 
  Layers, 
  FileCode,
  Crosshair,
  Server,
  ArrowLeft
} from 'lucide-react';
import PriorityBadge from '../components/common/PriorityBadge';
import SeverityBadge from '../components/common/SeverityBadge';
import RiskBreakdown from '../components/common/RiskBreakdown';
import RiskScoreMeter from '../components/common/RiskScoreMeter';

export default function Page4_FindingDetails({ findingItem, allFindings = [], onSelectFinding, onBack }) {
  const [copied, setCopied] = useState(false);

  // Fallback to highest ranked finding if none specifically selected
  const activeItem = findingItem || allFindings[0] || null;

  if (!activeItem) {
    return (
      <div className="p-12 text-center text-slate-500 text-sm">
        No vulnerability finding selected. Please select a finding from the Findings list.
      </div>
    );
  }

  const f = activeItem.finding || {};
  const intel = activeItem.threat_intel || {};
  const breakdown = activeItem.score_breakdown || {};
  const why = activeItem.why_prioritized || [];
  const ticketText = activeItem.security_ticket_markdown || '';

  const handleCopy = () => {
    navigator.clipboard.writeText(ticketText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <div className="space-y-6">
      {/* Header & Back Action */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {onBack && (
            <button
              onClick={onBack}
              className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
            </button>
          )}
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-sky-400 uppercase tracking-widest mb-1">
              <FileCode className="w-3.5 h-3.5" />
              Detailed Vulnerability Analysis & Explainable Risk
            </div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">
              {f.title}
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <PriorityBadge priority={activeItem.priority || activeItem.priority_label || 'P3'} showLabel size="lg" />
          <SeverityBadge severity={f.severity} size="lg" />
        </div>
      </div>

      {/* Main Grid: Left Details & Right 7-Factor Score Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Context, Why, Remediation (7 Cols) */}
        <div className="lg:col-span-7 space-y-5">
          {/* Executive Metrics Header */}
          <div className="grid grid-cols-3 gap-3">
            <div className="p-4 rounded-xl glass-panel border border-slate-800 text-center">
              <div className="text-[10px] uppercase font-bold text-slate-400">Calculated Risk</div>
              <div className="text-3xl font-mono font-extrabold text-red-400 mt-0.5">
                {activeItem.risk_score}<span className="text-xs text-slate-500 font-normal">/100</span>
              </div>
            </div>

            <div className="p-4 rounded-xl glass-panel border border-slate-800 text-center">
              <div className="text-[10px] uppercase font-bold text-slate-400">Target SLA</div>
              <div className="text-sm font-mono font-bold text-sky-300 mt-2 flex items-center justify-center gap-1.5">
                <Clock className="w-4 h-4" />
                {activeItem.sla || '24 Hours'}
              </div>
            </div>

            <div className="p-4 rounded-xl glass-panel border border-slate-800 text-center">
              <div className="text-[10px] uppercase font-bold text-slate-400">EPSS Likelihood</div>
              <div className="text-3xl font-mono font-extrabold text-purple-400 mt-0.5">
                {intel.epss_score ? `${Math.round(intel.epss_score * 100)}%` : 'N/A'}
              </div>
            </div>
          </div>

          {/* Why is this Prioritized Box */}
          <div className="p-5 rounded-2xl bg-sky-950/25 border border-sky-500/25 space-y-3">
            <div className="flex items-center gap-2 text-xs font-bold text-sky-300 uppercase tracking-wider">
              <Sparkles className="w-4 h-4 text-amber-400" />
              Why is this prioritized for immediate action?
            </div>
            <ul className="space-y-2 text-xs text-slate-200">
              {why.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2.5">
                  <span className="w-4 h-4 rounded-full bg-emerald-500/20 text-emerald-400 font-bold flex items-center justify-center shrink-0 text-[10px]">
                    ✓
                  </span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Technical Context */}
          <div className="glass-panel rounded-2xl p-5 border border-sky-500/15 space-y-4 text-xs">
            <h3 className="font-bold text-white uppercase tracking-wider text-xs flex items-center gap-2">
              <Server className="w-4 h-4 text-sky-400" />
              Vulnerability Technical Details
            </h3>

            <div className="grid grid-cols-2 gap-3 text-slate-300 font-mono text-[11px] bg-slate-900/60 p-3.5 rounded-xl border border-slate-800">
              <div><strong className="text-slate-500">CVE ID:</strong> {f.cve || 'N/A'}</div>
              <div><strong className="text-slate-500">CWE ID:</strong> {f.cwe || 'N/A'}</div>
              <div><strong className="text-slate-500">CVSS v3:</strong> {f.cvss !== null ? `${f.cvss} / 10.0` : 'N/A'}</div>
              <div><strong className="text-slate-500">Confidence:</strong> {f.confidence || 'CONFIRMED'}</div>
              <div><strong className="text-slate-500">Scanner(s):</strong> <span className="uppercase text-purple-300 font-bold">{f.scanner}</span></div>
              <div><strong className="text-slate-500">Target Asset:</strong> {f.asset}</div>
            </div>

            {f.url && (
              <div>
                <div className="text-slate-400 font-semibold mb-1">Primary Affected Endpoint URL:</div>
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-sky-300 font-mono text-[11px] break-all">
                  {f.url}
                </div>
              </div>
            )}

            {f.evidence && (
              <div>
                <div className="text-slate-400 font-semibold mb-1">Scanner Evidence / Functional Payload:</div>
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-amber-300 font-mono text-[11px] break-all">
                  {f.evidence}
                </div>
              </div>
            )}

            {f.description && (
              <div>
                <div className="text-slate-400 font-semibold mb-1">Vulnerability Description:</div>
                <p className="text-slate-300 leading-relaxed bg-slate-900/40 p-3 rounded-xl border border-slate-800">
                  {f.description}
                </p>
              </div>
            )}

            {activeItem.recommended_action && (
              <div>
                <div className="text-emerald-400 font-semibold mb-1">Recommended Remediation Action:</div>
                <div className="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-slate-100 leading-relaxed">
                  {activeItem.recommended_action}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: 7-Factor Score Breakdown & Security Ticket (5 Cols) */}
        <div className="lg:col-span-5 space-y-5">
          {/* 7-Factor Explainable Score Breakdown */}
          <div className="glass-panel rounded-2xl p-5 border border-sky-500/20 space-y-4">
            <div>
              <h3 className="font-bold text-white text-sm">7-Factor Multi-Dimensional Risk Score</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Exact point contributions returned by the prioritization scoring engine
              </p>
            </div>

            <RiskBreakdown breakdown={breakdown} totalScore={activeItem.risk_score} />
          </div>

          {/* Ticket Ready Task Box */}
          <div className="glass-panel rounded-2xl p-5 border border-sky-500/15 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-bold text-white text-xs uppercase tracking-wider">Security Action Ticket</h3>
                <p className="text-[11px] text-slate-400">Jira / ServiceNow ready format</p>
              </div>
              <button
                onClick={handleCopy}
                className="px-3 py-1.5 rounded-xl bg-sky-500/20 hover:bg-sky-500/30 text-sky-300 border border-sky-500/40 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-md shadow-sky-500/10"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied!' : 'Copy Ticket'}
              </button>
            </div>

            <pre className="p-4 rounded-xl bg-black/90 border border-slate-800 text-sky-300 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-72 whitespace-pre-wrap">
              {ticketText}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
