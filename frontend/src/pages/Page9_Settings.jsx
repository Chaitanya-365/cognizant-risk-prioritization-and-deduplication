import React, { useState } from 'react';
import { 
  Settings, 
  Save, 
  Server, 
  Key, 
  Clock, 
  ShieldCheck, 
  RotateCcw,
  CheckCircle2,
  Database
} from 'lucide-react';

export default function Page9_Settings({ isDemo, onToggleDemo, addToast }) {
  const [zapHost, setZapHost] = useState('127.0.0.1');
  const [zapPort, setZapPort] = useState('8080');
  const [zapApiKey, setZapApiKey] = useState('kali-zap-secret-api-key');
  const [nucleiConcurrency, setNucleiConcurrency] = useState('25');
  const [p0SlaHours, setP0SlaHours] = useState('24');
  const [p1SlaHours, setP1SlaHours] = useState('72');
  const [p2SlaDays, setP2SlaDays] = useState('7');
  const [p3SlaDays, setP3SlaDays] = useState('30');

  const handleSave = (e) => {
    e.preventDefault();
    addToast({
      type: 'success',
      title: 'Configuration Saved',
      message: 'Scanner integration settings and SLA thresholds updated successfully.'
    });
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-sky-400 uppercase tracking-widest mb-1">
          <Settings className="w-3.5 h-3.5" />
          System Configuration & Integrations
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          Platform Settings & Scanner Connectivity
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Configure OWASP ZAP daemons, Nuclei runners, threat intel API caches, and remediation SLA boundaries
        </p>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Demo Mode Toggle Box */}
        <div className="glass-panel rounded-2xl p-6 border border-sky-500/20 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white">Interactive Juice Shop Demo Mode</h2>
            <p className="text-xs text-slate-400 mt-0.5 max-w-xl">
              When enabled, the frontend loads realistic, verified multi-scanner findings from OWASP Juice Shop offline fixtures when the live Kali scanner daemons are inactive.
            </p>
          </div>

          <button
            type="button"
            onClick={onToggleDemo}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-bold border transition-all ${
              isDemo
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-md shadow-amber-500/20'
                : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50'
            }`}
          >
            {isDemo ? 'DEMO DATA ACTIVE' : 'LIVE API ACTIVE'}
          </button>
        </div>

        {/* Scanner Engine Config */}
        <div className="glass-panel rounded-2xl p-6 border border-sky-500/15 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" />
            Scanner Engine Connectivity (Kali Linux / Localhost)
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-300">OWASP ZAP Daemon Host</label>
              <input
                type="text"
                value={zapHost}
                onChange={(e) => setZapHost(e.target.value)}
                className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 font-mono text-white focus:outline-none focus:border-sky-400"
              />
            </div>

            <div className="space-y-1.5">
              <label className="font-semibold text-slate-300">OWASP ZAP Port</label>
              <input
                type="text"
                value={zapPort}
                onChange={(e) => setZapPort(e.target.value)}
                className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 font-mono text-white focus:outline-none focus:border-sky-400"
              />
            </div>

            <div className="space-y-1.5">
              <label className="font-semibold text-slate-300">ZAP API Key (ZAP_API_KEY)</label>
              <input
                type="password"
                value={zapApiKey}
                onChange={(e) => setZapApiKey(e.target.value)}
                className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 font-mono text-white focus:outline-none focus:border-sky-400"
              />
            </div>

            <div className="space-y-1.5">
              <label className="font-semibold text-slate-300">Nuclei Concurrency Threads</label>
              <input
                type="text"
                value={nucleiConcurrency}
                onChange={(e) => setNucleiConcurrency(e.target.value)}
                className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 font-mono text-white focus:outline-none focus:border-sky-400"
              />
            </div>
          </div>
        </div>

        {/* SLA Thresholds Configuration */}
        <div className="glass-panel rounded-2xl p-6 border border-sky-500/15 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400" />
            Priority Remediation SLA Targets
          </h2>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div className="space-y-1.5">
              <label className="font-semibold text-red-400">P0 SLA (Hours)</label>
              <input
                type="number"
                value={p0SlaHours}
                onChange={(e) => setP0SlaHours(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 font-mono text-white"
              />
            </div>

            <div className="space-y-1.5">
              <label className="font-semibold text-orange-400">P1 SLA (Hours)</label>
              <input
                type="number"
                value={p1SlaHours}
                onChange={(e) => setP1SlaHours(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 font-mono text-white"
              />
            </div>

            <div className="space-y-1.5">
              <label className="font-semibold text-amber-400">P2 SLA (Days)</label>
              <input
                type="number"
                value={p2SlaDays}
                onChange={(e) => setP2SlaDays(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 font-mono text-white"
              />
            </div>

            <div className="space-y-1.5">
              <label className="font-semibold text-sky-400">P3 SLA (Days)</label>
              <input
                type="number"
                value={p3SlaDays}
                onChange={(e) => setP3SlaDays(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 font-mono text-white"
              />
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex justify-end gap-3 pt-2">
          <button
            type="submit"
            className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-lg shadow-sky-500/20 transition-all"
          >
            <Save className="w-4 h-4 fill-current" />
            Save Configuration
          </button>
        </div>
      </form>
    </div>
  );
}
