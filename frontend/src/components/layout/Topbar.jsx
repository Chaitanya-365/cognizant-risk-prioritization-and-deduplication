import React from 'react';
import { 
  Activity, 
  Clock, 
  Database, 
  RefreshCw, 
  ShieldCheck, 
  AlertTriangle, 
  UserCircle
} from 'lucide-react';

export default function Topbar({ isDemo, onRefresh, isRefreshing, backendStatus, lastScanTime, onToggleDemo }) {
  return (
    <header className="h-14 border-b border-sky-500/15 bg-[#080d1a]/80 backdrop-blur-md px-6 flex items-center justify-between shrink-0 z-20">
      {/* System Status Indicators */}
      <div className="flex items-center gap-5 text-xs">
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full ${
            backendStatus === 'ok' 
              ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' 
              : 'bg-amber-400 shadow-[0_0_8px_#f59e0b]'
          }`}></span>
          <span className="font-semibold text-slate-300">
            {backendStatus === 'ok' ? 'Scanner API Online' : 'Demo / Standalone Mode'}
          </span>
        </div>

        <div className="h-4 w-px bg-slate-800 hidden sm:block"></div>

        <div className="hidden sm:flex items-center gap-1.5 text-slate-400">
          <Clock className="w-3.5 h-3.5 text-sky-400" />
          <span>Last Ingest:</span>
          <span className="font-mono text-slate-300">{lastScanTime || 'Just now'}</span>
        </div>

        <div className="h-4 w-px bg-slate-800 hidden md:block"></div>

        <div className="hidden md:flex items-center gap-1.5 text-slate-400">
          <Database className="w-3.5 h-3.5 text-purple-400" />
          <span>Threat Feeds:</span>
          <span className="font-semibold text-purple-300">CISA KEV + EPSS v3</span>
        </div>
      </div>

      {/* Action Controls & Profile */}
      <div className="flex items-center gap-3">
        {/* Demo Mode Toggle Badge */}
        <button
          onClick={onToggleDemo}
          className={`px-2.5 py-1 rounded-full text-xs font-mono font-semibold transition-all border flex items-center gap-1.5 ${
            isDemo
              ? 'bg-amber-500/15 text-amber-300 border-amber-500/30 hover:bg-amber-500/25'
              : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/25'
          }`}
          title="Click to toggle between live backend and Juice Shop verified scan demo fixtures"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
          {isDemo ? 'DEMO DATA (Juice Shop)' : 'LIVE BACKEND'}
        </button>

        {/* Refresh button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-1.5 rounded-lg text-slate-400 hover:text-sky-300 hover:bg-slate-800 border border-slate-700/60 transition-all disabled:opacity-50"
          title="Refresh Data from Pipeline"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
        </button>

        <div className="h-4 w-px bg-slate-800"></div>

        {/* Analyst Profile Pill */}
        <div className="flex items-center gap-2 pl-1 text-xs">
          <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center font-bold text-slate-900 text-xs shadow-md">
            AS
          </div>
          <div className="hidden lg:block text-left">
            <div className="font-semibold text-slate-200 leading-none">Aegis SOC Analyst</div>
            <div className="text-[10px] text-slate-500">Tier-3 Lead</div>
          </div>
        </div>
      </div>
    </header>
  );
}
