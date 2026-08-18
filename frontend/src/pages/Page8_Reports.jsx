import React from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  Share2, 
  CheckCircle2, 
  ShieldAlert, 
  Layers, 
  Flame, 
  Clock,
  Sparkles
} from 'lucide-react';
import KpiCard from '../components/common/KpiCard';

export default function Page8_Reports({ findings = [], stats = {}, addToast }) {
  const totalRaw = stats.total_raw_count || stats.total_raw || 14;
  const uniqueCount = stats.unique_count || findings.length || 6;
  const duplicatesRemoved = stats.duplicates_removed || (totalRaw - uniqueCount);
  const reductionPercentage = stats.reduction_percentage || 57.1;
  const criticalCount = findings.filter(f => (f.finding?.severity || f.severity) === 'CRITICAL').length;
  const highCount = findings.filter(f => (f.finding?.severity || f.severity) === 'HIGH').length;

  // Export JSON
  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(findings, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `vulnex_security_report_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    addToast({ type: 'success', title: 'Export Generated', message: 'Downloaded complete JSON security report.' });
  };

  // Export CSV
  const handleExportCSV = () => {
    const headers = ["Rank", "Priority", "Title", "Severity", "CVE", "CWE", "Scanner", "Asset", "Risk Score", "EPSS", "CISA KEV", "SLA", "Action"];
    const rows = findings.map(item => {
      const f = item.finding || {};
      const intel = item.threat_intel || {};
      return [
        item.rank,
        item.priority || item.priority_label || 'P3',
        `"${(f.title || '').replace(/"/g, '""')}"`,
        f.severity || 'INFO',
        f.cve || 'N/A',
        f.cwe || 'N/A',
        f.scanner || 'N/A',
        f.asset || 'N/A',
        item.risk_score,
        intel.epss_score ? `${Math.round(intel.epss_score * 100)}%` : 'N/A',
        intel.in_cisa_kev ? 'Yes' : 'No',
        `"${item.sla || ''}"`,
        `"${(item.recommended_action || '').replace(/"/g, '""')}"`
      ];
    });

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", encodeURI(csvContent));
    downloadAnchor.setAttribute("download", `vulnex_prioritized_findings_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    addToast({ type: 'success', title: 'CSV Generated', message: 'Downloaded findings CSV spreadsheet.' });
  };

  // Print Report
  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-sky-400 uppercase tracking-widest mb-1">
            <FileText className="w-3.5 h-3.5" />
            Audit, Compliance & Executive Reporting
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Executive Security Reports & Exports
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Export machine-readable JSON/CSV data or generate executive briefing summaries for stakeholders
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCSV}
            className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-2 transition-all"
          >
            <Download className="w-4 h-4 text-emerald-400" />
            Export CSV
          </button>

          <button
            onClick={handleExportJSON}
            className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-2 transition-all"
          >
            <Download className="w-4 h-4 text-sky-400" />
            Export JSON
          </button>

          <button
            onClick={handlePrint}
            className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-lg shadow-sky-500/20 transition-all"
          >
            <Printer className="w-4 h-4 fill-current" />
            Print / PDF Summary
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          label="Total Scanner Telemetry"
          value={totalRaw}
          subtext="Raw vulnerability alerts"
          icon={ShieldAlert}
          color="sky"
        />
        <KpiCard
          label="Actionable Items"
          value={uniqueCount}
          subtext="Validated canonical findings"
          icon={Layers}
          color="purple"
        />
        <KpiCard
          label="Noise Reduction"
          value={`${reductionPercentage}%`}
          subtext="57.1% duplicate noise cut"
          icon={CheckCircle2}
          color="emerald"
        />
        <KpiCard
          label="Active P0 Blockers"
          value={criticalCount}
          subtext="Requires 24-hour SLA triage"
          icon={Flame}
          color="red"
        />
      </div>

      {/* Executive Briefing Summary Document Preview */}
      <div className="glass-panel rounded-2xl p-8 border border-sky-500/20 space-y-6 bg-slate-950/70">
        <div className="border-b border-slate-800 pb-5 flex items-start justify-between">
          <div>
            <div className="text-xs font-mono font-bold uppercase tracking-widest text-sky-400">
              VULNEX EXECUTIVE SECURITY BRIEFING
            </div>
            <h2 className="text-xl font-bold text-white mt-1">
              Assessment Summary: OWASP Juice Shop Target Application
            </h2>
            <div className="text-xs text-slate-400 mt-1 font-mono">
              Target: localhost:3000 • Ingestion Pipeline: Nuclei v3 + OWASP ZAP • Generated: {new Date().toLocaleDateString()}
            </div>
          </div>
          <div className="text-right">
            <span className="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 font-mono text-xs font-bold border border-emerald-500/40">
              Activity 4 Completed
            </span>
          </div>
        </div>

        {/* Business Value Highlight */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 text-xs">
          <div className="font-bold text-white uppercase tracking-wider text-xs flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-amber-400" />
            Key Strategic Value & Noise Elimination
          </div>
          <p className="text-slate-300 leading-relaxed">
            Instead of overwhelming development teams with <strong>{totalRaw} separate, unranked scanner alerts</strong> across disconnected tools, VULNEX automatically merged duplicate alerts (achieving a <strong>{reductionPercentage}% reduction rate</strong>), enriched vulnerabilities with real-world threat telemetry, and generated an unambiguous <strong>P0-P3 prioritized action plan</strong> with precise remediation SLAs.
          </p>
        </div>

        {/* Key Findings Summary */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
            Critical Action Items (What to Fix First)
          </h3>

          <div className="space-y-2">
            {findings.slice(0, 4).map((item, idx) => {
              const f = item.finding || {};
              const intel = item.threat_intel || {};

              return (
                <div key={idx} className="p-3.5 rounded-xl bg-slate-900/50 border border-slate-800/80 flex items-center justify-between gap-4 text-xs">
                  <div className="flex items-center gap-3">
                    <span className="font-mono font-bold text-slate-500">#{item.rank}</span>
                    <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                      (item.priority || item.priority_label) === 'P0' ? 'bg-red-500/20 text-red-300' : 'bg-orange-500/20 text-orange-300'
                    }`}>
                      {item.priority || item.priority_label || 'P1'}
                    </span>
                    <div>
                      <div className="font-bold text-white">{f.title}</div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        {f.cve || 'Non-CVE'} • {f.asset}
                      </div>
                    </div>
                  </div>

                  <div className="text-right shrink-0 font-mono text-[11px]">
                    <div className="text-red-400 font-bold">Risk {item.risk_score}/100</div>
                    <div className="text-sky-300">{item.sla || '24 Hours'}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
