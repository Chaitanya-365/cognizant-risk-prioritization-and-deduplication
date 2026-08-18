import React, { useState } from 'react';
import { X, Copy, Check, ShieldAlert, Clock, ExternalLink, Sparkles } from 'lucide-react';
import PriorityBadge from './PriorityBadge';
import SeverityBadge from './SeverityBadge';
import RiskScoreMeter from './RiskScoreMeter';
import RiskBreakdown from './RiskBreakdown';

export default function TicketDrawer({ findingItem, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!findingItem) return null;

  const f = findingItem.finding || {};
  const intel = findingItem.threat_intel || {};
  const breakdown = findingItem.score_breakdown || {};
  const why = findingItem.why_prioritized || [];
  const ticketText = findingItem.security_ticket_markdown || '';

  const handleCopy = () => {
    navigator.clipboard.writeText(ticketText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm animate-fadeIn">
      <div 
        className="w-full max-w-2xl bg-[#0b101e] border-l border-sky-500/20 h-full overflow-y-auto shadow-2xl flex flex-col justify-between"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-6 border-b border-sky-500/15 bg-slate-900/60 sticky top-0 z-10 backdrop-blur-md">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <PriorityBadge priority={findingItem.priority || findingItem.priority_label || 'P3'} showLabel size="lg" />
                <SeverityBadge severity={f.severity} size="lg" />
                {intel.in_cisa_kev && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                    ⚡ CISA KEV Exploited
                  </span>
                )}
              </div>
              <h2 className="text-lg font-bold text-white leading-snug">
                {f.title}
              </h2>
              <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                {f.cve && <span className="text-sky-400 font-semibold">{f.cve}</span>}
                {f.cwe && <span>{f.cwe}</span>}
                <span className="text-slate-500">•</span>
                <span className="uppercase text-purple-400 font-semibold">{f.scanner}</span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-300">{f.asset}</span>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors shrink-0"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Drawer Content */}
        <div className="p-6 space-y-6 flex-1">
          {/* Executive Metrics Box */}
          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
              <div className="text-[10px] uppercase font-bold text-slate-400">Risk Score</div>
              <div className="text-2xl font-mono font-extrabold text-red-400 mt-0.5">
                {findingItem.risk_score}<span className="text-xs text-slate-500">/100</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
              <div className="text-[10px] uppercase font-bold text-slate-400">Remediation SLA</div>
              <div className="text-sm font-mono font-bold text-sky-300 mt-1 flex items-center justify-center gap-1">
                <Clock className="w-3.5 h-3.5" />
                {findingItem.sla || '24 Hours'}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
              <div className="text-[10px] uppercase font-bold text-slate-400">EPSS Probability</div>
              <div className="text-2xl font-mono font-extrabold text-purple-400 mt-0.5">
                {intel.epss_score ? `${Math.round(intel.epss_score * 100)}%` : 'N/A'}
              </div>
            </div>
          </div>

          {/* Why is this Prioritized? */}
          <div className="p-4 rounded-xl bg-sky-950/20 border border-sky-500/20 space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-sky-300 uppercase tracking-wider">
              <Sparkles className="w-4 h-4 text-amber-400" />
              Why is this prioritized for action?
            </div>
            <ul className="space-y-1.5 text-xs text-slate-300">
              {why.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-emerald-400 font-bold shrink-0">✓</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* 7-Factor Explainable Score Breakdown */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              7-Factor Explainable Risk Scoring
            </div>
            <RiskBreakdown breakdown={breakdown} totalScore={findingItem.risk_score} />
          </div>

          {/* Technical Context */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2.5 text-xs">
            <div className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Technical Context & Target Location
            </div>
            
            <div className="grid grid-cols-2 gap-2 text-slate-300 font-mono text-[11px]">
              <div><strong className="text-slate-400">Asset:</strong> {f.asset || 'localhost:3000'}</div>
              <div><strong className="text-slate-400">Parameter:</strong> {f.parameter || 'N/A'}</div>
              <div><strong className="text-slate-400">Category:</strong> {f.category || 'Vulnerability'}</div>
              <div><strong className="text-slate-400">Confidence:</strong> {f.confidence || 'CONFIRMED'}</div>
            </div>

            {f.url && (
              <div className="pt-2 border-t border-slate-800">
                <div className="text-slate-400 font-medium mb-1">Primary Affected URL:</div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-sky-300 font-mono text-[11px] break-all">
                  {f.url}
                </div>
              </div>
            )}

            {f.evidence && (
              <div className="pt-2 border-t border-slate-800">
                <div className="text-slate-400 font-medium mb-1">Verified Scanner Proof / Payload:</div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-amber-300 font-mono text-[11px] break-all">
                  {f.evidence}
                </div>
              </div>
            )}

            {f.description && (
              <div className="pt-2 border-t border-slate-800 text-slate-300">
                <div className="text-slate-400 font-medium mb-1">Description:</div>
                <p className="leading-relaxed">{f.description}</p>
              </div>
            )}

            {findingItem.recommended_action && (
              <div className="pt-2 border-t border-slate-800">
                <div className="text-emerald-400 font-semibold mb-1">Recommended Remediation Action:</div>
                <p className="text-slate-200 leading-relaxed bg-emerald-950/20 p-2.5 rounded border border-emerald-500/20">
                  {findingItem.recommended_action}
                </p>
              </div>
            )}
          </div>

          {/* Ready-to-Copy Jira Ticket */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-300">Security Ticket (Jira / ServiceNow Ready)</span>
              <button
                onClick={handleCopy}
                className="px-3 py-1 rounded bg-sky-500/20 hover:bg-sky-500/30 text-sky-300 border border-sky-500/30 text-xs font-semibold flex items-center gap-1.5 transition-all"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied to Clipboard!' : 'Copy Ticket'}
              </button>
            </div>
            <pre className="p-3.5 rounded-xl bg-black border border-slate-800 text-sky-400 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-48 whitespace-pre-wrap">
              {ticketText}
            </pre>
          </div>
        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-sky-500/15 bg-slate-900/80 flex items-center justify-between">
          <div className="text-[11px] text-slate-400">
            Finding ID: <span className="font-mono text-slate-300">{f.finding_id}</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-all"
          >
            Close Drawer
          </button>
        </div>
      </div>
    </div>
  );
}
