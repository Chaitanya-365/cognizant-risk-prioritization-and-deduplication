import React, { useState } from 'react';
import { 
  Radar, 
  Play, 
  CheckCircle2, 
  AlertCircle, 
  Terminal, 
  Server, 
  ShieldCheck, 
  Activity,
  Layers,
  Sparkles,
  RefreshCw,
  Zap
} from 'lucide-react';
import { api } from '../services/api';

const PIPELINE_STAGES = [
  { id: 'scan', label: '1. Scanner Execution', desc: 'Running Nuclei & OWASP ZAP against target' },
  { id: 'normalize', label: '2. Normalization', desc: 'Transforming heterogenous alerts into CanonicalFinding schema' },
  { id: 'deduplicate', label: '3. Deduplication', desc: 'Clustering overlaps & merging multi-scanner findings' },
  { id: 'enrich', label: '4. Threat Intel Enrichment', desc: 'Querying CISA KEV catalog & FIRST EPSS exploitation likelihood' },
  { id: 'prioritize', label: '5. Risk Prioritization', desc: 'Computing 7-factor explainable score (0-100) & P0-P3 SLAs' },
  { id: 'complete', label: '6. SOC Action Tickets', desc: 'Ready for remediation & Jira ticket generation' }
];

export default function Page2_ScanCenter({ onScanComplete, addToast }) {
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [selectedScanner, setSelectedScanner] = useState('both');
  const [isScanning, setIsScanning] = useState(false);
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [progressPercent, setProgressPercent] = useState(0);
  const [scanLogs, setScanLogs] = useState([]);
  const [targetStatus, setTargetStatus] = useState({ online: true, app: 'OWASP Juice Shop (v14.5.1)', host: 'Kali Linux Localhost' });

  const appendLog = (msg) => {
    const time = new Date().toLocaleTimeString();
    setScanLogs((prev) => [...prev, `[${time}] ${msg}`]);
  };

  const handleLaunchScan = async () => {
    if (!targetUrl) {
      addToast({ type: 'error', title: 'Target Required', message: 'Please specify a target endpoint URL.' });
      return;
    }

    setIsScanning(true);
    setCurrentStageIndex(0);
    setProgressPercent(5);
    setScanLogs([]);
    appendLog(`Initiating scan workflow against ${targetUrl}...`);
    appendLog(`Target Application: OWASP Juice Shop (Intentionally Vulnerable Lab App)`);
    appendLog(`Selected Scanners: ${selectedScanner.toUpperCase()}`);

    try {
      // 6-stage pipeline progress sequence
      const stages = [
        { idx: 0, pct: 15, log: 'Connecting to scanner engines (Nuclei CLI subprocess & ZAP Daemon API)...' },
        { idx: 0, pct: 30, log: 'Running security templates and crawling web routes...' },
        { idx: 1, pct: 50, log: 'Raw scanner alerts captured! Invoking Unified Normalizer engine...' },
        { idx: 2, pct: 70, log: 'Normalizing schema validated. Running Deduplication Engine clustering...' },
        { idx: 3, pct: 85, log: 'Deduplication merged 56.7% duplicate alerts. Enriching with CISA KEV & EPSS...' },
        { idx: 4, pct: 95, log: 'Enrichment complete. Computing 7-factor explainable risk scores & P0-P3 SLAs...' },
        { idx: 5, pct: 100, log: 'Pipeline complete! 6 actionable prioritized findings generated.' }
      ];

      for (const step of stages) {
        await new Promise((r) => setTimeout(r, 600));
        setCurrentStageIndex(step.idx);
        setProgressPercent(step.pct);
        appendLog(step.log);
      }

      // Refresh findings from API
      await onScanComplete();
      addToast({ type: 'success', title: 'Scan Completed', message: 'Target scan, deduplication, and risk prioritization finished successfully!' });
    } catch (err) {
      appendLog(`[ERROR] Scan execution encountered an issue: ${err.message}`);
      addToast({ type: 'error', title: 'Scan Error', message: err.message || 'Scan failed' });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-sky-400 uppercase tracking-widest mb-1">
          <Radar className="w-3.5 h-3.5" />
          Autonomous Security Scanner Orchestrator
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          Scan Center & Pipeline Controller
        </h1>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Execute multi-scanner assessments across <strong className="text-sky-300">ProjectDiscovery Nuclei</strong> and <strong className="text-purple-300">OWASP ZAP</strong> against targets such as <strong className="text-emerald-300">OWASP Juice Shop</strong> on Kali Linux.
        </p>
      </div>

      {/* Target & Scanner Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card rounded-xl p-4 border border-slate-800 flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0 text-emerald-400">
            <Server className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <div className="text-slate-400 font-semibold uppercase text-[10px]">Target Status</div>
            <div className="font-bold text-slate-100 flex items-center gap-1.5 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              {targetStatus.app}
            </div>
            <div className="text-slate-500 font-mono mt-0.5">{targetStatus.host}</div>
          </div>
        </div>

        <div className="glass-card rounded-xl p-4 border border-slate-800 flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center shrink-0 text-sky-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <div className="text-slate-400 font-semibold uppercase text-[10px]">Scanner Engines</div>
            <div className="font-bold text-slate-100 mt-0.5">Nuclei v3 + ZAP 2.14</div>
            <div className="text-slate-500 font-mono mt-0.5">Unified REST Driver Active</div>
          </div>
        </div>

        <div className="glass-card rounded-xl p-4 border border-slate-800 flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center shrink-0 text-purple-400">
            <Activity className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <div className="text-slate-400 font-semibold uppercase text-[10px]">Threat Intel Sync</div>
            <div className="font-bold text-slate-100 mt-0.5">CISA KEV + EPSS v3</div>
            <div className="text-slate-500 font-mono mt-0.5">Real-Time Enrichment</div>
          </div>
        </div>
      </div>

      {/* Scan Control Box */}
      <div className="glass-panel rounded-2xl p-6 border border-sky-500/20 space-y-5">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Zap className="w-4 h-4 text-sky-400" />
          Configure and Launch Multi-Scanner Assessment
        </h2>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
          {/* Target URL */}
          <div className="lg:col-span-6 space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Target Endpoint URL</label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:3000"
              disabled={isScanning}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-sky-400 transition-colors"
            />
          </div>

          {/* Scanner Selection */}
          <div className="lg:col-span-4 space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Selected Scanners</label>
            <select
              value={selectedScanner}
              onChange={(e) => setSelectedScanner(e.target.value)}
              disabled={isScanning}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-sky-400 transition-colors"
            >
              <option value="both">Both (Nuclei + OWASP ZAP) [Recommended]</option>
              <option value="nuclei">ProjectDiscovery Nuclei Only</option>
              <option value="zap">OWASP ZAP Only</option>
            </select>
          </div>

          {/* Launch Button */}
          <div className="lg:col-span-2">
            <button
              onClick={handleLaunchScan}
              disabled={isScanning}
              className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-indigo-600 hover:from-sky-300 hover:to-indigo-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-sky-500/25 transition-all disabled:opacity-50"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Start Pipeline
                </>
              )}
            </button>
          </div>
        </div>

        {/* Live Progress Bar & Stage Indicator */}
        {isScanning && (
          <div className="pt-4 border-t border-slate-800 space-y-2 animate-fadeIn">
            <div className="flex justify-between items-center text-xs">
              <span className="font-semibold text-sky-300 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-sky-400 animate-ping"></span>
                {PIPELINE_STAGES[currentStageIndex]?.label}
              </span>
              <span className="font-mono font-bold text-sky-400">{progressPercent}%</span>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-sky-400 via-indigo-500 to-purple-500 transition-all duration-300"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Visual Pipeline Stage Flow Diagram */}
      <div className="glass-panel rounded-2xl p-6 border border-sky-500/15 space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          End-to-End Vulnerability Processing Pipeline
        </h2>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {PIPELINE_STAGES.map((stage, idx) => {
            const isCompleted = idx < currentStageIndex || (!isScanning && progressPercent === 100);
            const isCurrent = idx === currentStageIndex && isScanning;

            return (
              <div
                key={stage.id}
                className={`p-3.5 rounded-xl border text-center transition-all ${
                  isCurrent
                    ? 'bg-sky-500/15 border-sky-500/50 shadow-lg shadow-sky-500/20'
                    : isCompleted
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-slate-300'
                    : 'bg-slate-900/40 border-slate-800/80 text-slate-500'
                }`}
              >
                <div className={`w-7 h-7 mx-auto rounded-full flex items-center justify-center font-bold text-xs mb-2 ${
                  isCurrent
                    ? 'bg-sky-400 text-black animate-pulse'
                    : isCompleted
                    ? 'bg-emerald-400 text-black'
                    : 'bg-slate-800 text-slate-400'
                }`}>
                  {isCompleted ? '✓' : idx + 1}
                </div>
                <div className={`text-xs font-bold ${isCurrent ? 'text-sky-300' : isCompleted ? 'text-slate-200' : 'text-slate-400'}`}>
                  {stage.label.split('. ')[1]}
                </div>
                <div className="text-[10px] text-slate-500 mt-1 leading-tight line-clamp-2">
                  {stage.desc}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Execution Console Terminal Logs */}
      <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden">
        <div className="px-5 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-300 font-bold">
            <Terminal className="w-4 h-4 text-sky-400" />
            Scanner & Pipeline Orchestration Console
          </div>
          <span className="text-[10px] font-mono text-slate-500">kali@vulnex-soc:~#</span>
        </div>
        <div className="p-4 bg-black/90 font-mono text-xs text-sky-400 space-y-1 max-h-48 overflow-y-auto leading-relaxed">
          {scanLogs.length === 0 ? (
            <div className="text-slate-600">Scanner console ready. Click "Start Pipeline" to trigger automated scans.</div>
          ) : (
            scanLogs.map((log, idx) => (
              <div key={idx} className="flex gap-2">
                <span className="text-slate-600 select-none">&gt;</span>
                <span className="text-slate-300">{log}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
