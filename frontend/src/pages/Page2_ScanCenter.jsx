import React, { useState, useEffect, useRef } from 'react';
import { 
  Radar, 
  Play, 
  Square, 
  CheckCircle2, 
  AlertCircle, 
  Terminal, 
  Server, 
  ShieldCheck, 
  Activity,
  Layers,
  Sparkles,
  RefreshCw,
  Zap,
  ArrowRight,
  ExternalLink,
  Clock,
  ShieldAlert,
  Flame
} from 'lucide-react';
import { api } from '../services/api';

const PIPELINE_STAGES = [
  { id: 'target_check', label: '1. Target Reachability', desc: 'Verifying network & HTTP connectivity to target' },
  { id: 'scanner_execution', label: '2. Scanner Execution', desc: 'Executing Nuclei subprocess & OWASP ZAP API probes' },
  { id: 'normalization', label: '3. Canonical Normalization', desc: 'Mapping raw alerts into CanonicalFinding schema' },
  { id: 'deduplication', label: '4. Deduplication Engine', desc: 'Cross-scanner clustering & duplicate merging' },
  { id: 'threat_intel', label: '5. Threat Intelligence', desc: 'Querying CISA KEV catalog & FIRST EPSS likelihood' },
  { id: 'risk_prioritization', label: '6. Risk Prioritization', desc: 'Computing 7-factor explainable score (0-100) & SLAs' }
];

export default function Page2_ScanCenter({ onScanComplete, onNavigateTab, addToast }) {
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [selectedScanner, setSelectedScanner] = useState('both');
  const [isScanning, setIsScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const [scanStatusData, setScanStatusData] = useState(null);
  const [progressPercent, setProgressPercent] = useState(0);
  const [scanLogs, setScanLogs] = useState([]);
  const [currentStageKey, setCurrentStageKey] = useState('target_check');
  const [completedScanSummary, setCompletedScanSummary] = useState(null);
  const terminalEndRef = useRef(null);

  // Auto-scroll terminal log
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [scanLogs]);

  // Polling loop for active scan status
  useEffect(() => {
    let intervalId = null;

    if (isScanning && activeScanId) {
      intervalId = setInterval(async () => {
        try {
          const status = await api.getScanStatus(activeScanId);
          setScanStatusData(status);
          setProgressPercent(status.progress || 0);
          setCurrentStageKey(status.stage || 'scanner_execution');

          if (status.logs && status.logs.length > 0) {
            setScanLogs(status.logs);
          }

          // Check if scan has completed
          if (status.status === 'completed') {
            setIsScanning(false);
            clearInterval(intervalId);
            setCompletedScanSummary({
              scan_id: status.scan_id,
              total_raw: status.findings_count || status.total_findings || 0,
              unique_count: status.unique_count || 0,
              duplicates_removed: status.duplicates_removed || 0,
              reduction_percentage: status.reduction_percentage || 0.0
            });
            await onScanComplete();
            addToast({
              type: 'success',
              title: 'Live Scan Complete!',
              message: `Completed real-time scan on ${targetUrl}. Normalized, deduplicated, and prioritized findings.`
            });
          } else if (status.status === 'failed' || status.status === 'cancelled') {
            setIsScanning(false);
            clearInterval(intervalId);
            addToast({
              type: status.status === 'cancelled' ? 'info' : 'error',
              title: status.status === 'cancelled' ? 'Scan Cancelled' : 'Scan Failed',
              message: status.error || `Scan ${status.status}.`
            });
          }
        } catch (err) {
          console.warn('Status polling notice:', err);
        }
      }, 1000);
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [isScanning, activeScanId]);

  const handleLaunchScan = async () => {
    if (!targetUrl.trim()) {
      addToast({ type: 'error', title: 'Target Required', message: 'Please specify a target endpoint URL.' });
      return;
    }

    setIsScanning(true);
    setProgressPercent(5);
    setScanLogs([`[${new Date().toLocaleTimeString()}] Initializing live scan against ${targetUrl}...`]);
    setCompletedScanSummary(null);

    try {
      const startRes = await api.startScan(selectedScanner, targetUrl);
      if (startRes && startRes.scan_id) {
        setActiveScanId(startRes.scan_id);
        addToast({
          type: 'info',
          title: 'Live Scanner Dispatched',
          message: `Scan ID: ${startRes.scan_id.slice(0, 8)}... started on ${targetUrl} (${selectedScanner.toUpperCase()}).`
        });
      }
    } catch (err) {
      setIsScanning(false);
      addToast({
        type: 'error',
        title: 'Launch Failed',
        message: err.message || 'Could not trigger scan backend.'
      });
    }
  };

  const handleCancelScan = async () => {
    if (!activeScanId) return;
    try {
      await api.cancelScan(activeScanId);
      setIsScanning(false);
      addToast({
        type: 'info',
        title: 'Scan Cancelled',
        message: 'Active scanning subprocess terminated.'
      });
    } catch (err) {
      console.error('Cancellation error:', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-sky-400 uppercase tracking-widest mb-1">
            <Radar className="w-3.5 h-3.5" />
            Live Vulnerability Scanner Orchestrator
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Real-Time Scan Center & Pipeline Controller
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Execute live vulnerability assessments using <strong className="text-sky-300">ProjectDiscovery Nuclei</strong> and <strong className="text-purple-300">OWASP ZAP</strong> against targets such as <strong className="text-emerald-300">OWASP Juice Shop</strong> on Kali Linux. Telemetry is streamed in real-time.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {completedScanSummary && (
            <button
              onClick={() => onNavigateTab('dashboard')}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-lg shadow-emerald-500/20 transition-all"
            >
              <Sparkles className="w-4 h-4" />
              View Prioritized Dashboard &rarr;
            </button>
          )}
        </div>
      </div>

      {/* Target & Scanner Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card rounded-xl p-4 border border-slate-800 flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0 text-emerald-400">
            <Server className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <div className="text-slate-400 font-semibold uppercase text-[10px]">Target Application</div>
            <div className="font-bold text-slate-100 flex items-center gap-1.5 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              OWASP Juice Shop (v14.5.1)
            </div>
            <div className="text-slate-500 font-mono mt-0.5">Target: {targetUrl}</div>
          </div>
        </div>

        <div className="glass-card rounded-xl p-4 border border-slate-800 flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center shrink-0 text-sky-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <div className="text-slate-400 font-semibold uppercase text-[10px]">Scanner Engines</div>
            <div className="font-bold text-slate-100 mt-0.5">Nuclei Subprocess + ZAP Daemon</div>
            <div className="text-slate-500 font-mono mt-0.5">Unified Normalization Driver</div>
          </div>
        </div>

        <div className="glass-card rounded-xl p-4 border border-slate-800 flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center shrink-0 text-purple-400">
            <Activity className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <div className="text-slate-400 font-semibold uppercase text-[10px]">Threat Intelligence</div>
            <div className="font-bold text-slate-100 mt-0.5">CISA KEV + FIRST EPSS v3</div>
            <div className="text-slate-500 font-mono mt-0.5">Live Exploit Correlation</div>
          </div>
        </div>
      </div>

      {/* Scan Control Box */}
      <div className="glass-panel rounded-2xl p-6 border border-sky-500/20 space-y-5">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Zap className="w-4 h-4 text-sky-400" />
            Configure & Launch Live Security Assessment
          </h2>
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400">Quick Targets:</span>
            <button
              onClick={() => setTargetUrl('http://localhost:3000')}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-300 font-mono text-[11px] transition-colors"
            >
              Juice Shop (3000)
            </button>
            <button
              onClick={() => setTargetUrl('http://127.0.0.1:8080')}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-[11px] transition-colors"
            >
              Port 8080
            </button>
          </div>
        </div>

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
            <label className="text-xs font-semibold text-slate-300">Selected Scanner Engines</label>
            <select
              value={selectedScanner}
              onChange={(e) => setSelectedScanner(e.target.value)}
              disabled={isScanning}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-sky-400 transition-colors"
            >
              <option value="both">Both (Nuclei CLI + OWASP ZAP) [Recommended]</option>
              <option value="nuclei">ProjectDiscovery Nuclei CLI Only</option>
              <option value="zap">OWASP ZAP API Only</option>
            </select>
          </div>

          {/* Action Buttons */}
          <div className="lg:col-span-2 flex gap-2">
            {!isScanning ? (
              <button
                onClick={handleLaunchScan}
                className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-indigo-600 hover:from-sky-300 hover:to-indigo-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-sky-500/25 transition-all"
              >
                <Play className="w-4 h-4 fill-current" />
                Start Scan
              </button>
            ) : (
              <button
                onClick={handleCancelScan}
                className="w-full py-2.5 px-4 rounded-xl bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/50 font-bold text-xs flex items-center justify-center gap-2 transition-all"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                Stop Scan
              </button>
            )}
          </div>
        </div>

        {/* Live Progress Bar & Stage Indicator */}
        {isScanning && (
          <div className="pt-4 border-t border-slate-800 space-y-2 animate-fadeIn">
            <div className="flex justify-between items-center text-xs">
              <span className="font-semibold text-sky-300 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-sky-400 animate-ping"></span>
                {scanStatusData?.stage_label || 'Scanning target...'}
              </span>
              <span className="font-mono font-bold text-sky-400">{progressPercent}%</span>
            </div>
            <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-sky-400 via-indigo-500 to-purple-500 transition-all duration-300"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
            {activeScanId && (
              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                <span>Scan ID: {activeScanId}</span>
                <span>Polling interval: 1000ms</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Completed Scan Metrics Summary Banner */}
      {completedScanSummary && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-emerald-950/40 via-slate-900 to-emerald-950/40 border border-emerald-500/30 shadow-xl space-y-3 animate-fadeIn">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <h3 className="font-bold text-white text-sm">
                Scan Pipeline Finished Successfully
              </h3>
            </div>
            <span className="px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-xs font-bold border border-emerald-500/40">
              {completedScanSummary.reduction_percentage}% Noise Eliminated
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="text-slate-400 text-[10px] uppercase font-bold">Raw Alerts Captured</div>
              <div className="text-xl font-mono font-bold text-sky-400 mt-0.5">{completedScanSummary.total_raw}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="text-slate-400 text-[10px] uppercase font-bold">Canonical Unique Items</div>
              <div className="text-xl font-mono font-bold text-purple-400 mt-0.5">{completedScanSummary.unique_count}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="text-slate-400 text-[10px] uppercase font-bold">Duplicates Merged</div>
              <div className="text-xl font-mono font-bold text-emerald-400 mt-0.5">-{completedScanSummary.duplicates_removed}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="text-slate-400 text-[10px] uppercase font-bold">Noise Reduction Rate</div>
              <div className="text-xl font-mono font-bold text-emerald-400 mt-0.5">{completedScanSummary.reduction_percentage}%</div>
            </div>
          </div>

          <div className="flex justify-end pt-1">
            <button
              onClick={() => onNavigateTab('dashboard')}
              className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black font-bold text-xs flex items-center gap-1.5 transition-all shadow-md"
            >
              Explore Prioritized Findings &rarr;
            </button>
          </div>
        </div>
      )}

      {/* Visual Pipeline Stage Flow Diagram */}
      <div className="glass-panel rounded-2xl p-6 border border-sky-500/15 space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          Real-Time Pipeline Execution Stages
        </h2>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {PIPELINE_STAGES.map((stage, idx) => {
            const isCompleted = completedScanSummary !== null || (progressPercent > (idx + 1) * 16);
            const isCurrent = isScanning && (
              currentStageKey === stage.id || 
              (currentStageKey === 'scanner_execution' && idx === 1) ||
              (currentStageKey === 'normalization' && idx === 2) ||
              (currentStageKey === 'deduplication' && idx === 3) ||
              (currentStageKey === 'threat_intel' && idx === 4) ||
              (currentStageKey === 'risk_prioritization' && idx === 5)
            );

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
            Scanner & Pipeline Orchestration Console Stream
          </div>
          <span className="text-[10px] font-mono text-slate-500">kali@vulnex-soc:~#</span>
        </div>
        <div className="p-4 bg-black/90 font-mono text-xs text-sky-400 space-y-1.5 max-h-56 overflow-y-auto leading-relaxed">
          {scanLogs.length === 0 ? (
            <div className="text-slate-600">Scanner console ready. Click "Start Scan" to trigger automated pipeline execution.</div>
          ) : (
            scanLogs.map((log, idx) => (
              <div key={idx} className="flex gap-2">
                <span className="text-slate-600 select-none">&gt;</span>
                <span className="text-slate-300">{log}</span>
              </div>
            ))
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
}
