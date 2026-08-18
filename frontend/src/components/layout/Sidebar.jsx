import React from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Radar, 
  Flame, 
  Layers, 
  Binary, 
  FileText, 
  Settings, 
  ListOrdered,
  ChevronRight
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, badge: null },
  { id: 'scan-center', label: 'Scan Center', icon: Radar, badge: 'Live' },
  { id: 'findings', label: 'Findings', icon: Flame, badge: null },
  { id: 'priorities', label: 'Priorities (SLA)', icon: ListOrdered, badge: 'P0' },
  { id: 'deduplication', label: 'Deduplication', icon: Layers, badge: '-57%' },
  { id: 'threat-intel', label: 'Threat Intel', icon: Binary, badge: 'KEV' },
  { id: 'reports', label: 'Reports & Export', icon: FileText, badge: null },
  { id: 'settings', label: 'Settings', icon: Settings, badge: null }
];

export default function Sidebar({ currentTab, onSelectTab, isDemo }) {
  return (
    <aside className="w-64 bg-[#080d1a] border-r border-sky-500/15 flex flex-col justify-between shrink-0 select-none z-30">
      {/* Brand Header */}
      <div>
        <div className="p-5 flex items-center gap-3 border-b border-sky-500/10">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-sky-400 via-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-sky-500/25">
            <ShieldAlert className="w-5 h-5 text-black" strokeWidth={2.5} />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-extrabold text-lg tracking-wider bg-gradient-to-r from-sky-400 via-sky-200 to-white bg-clip-text text-transparent">
                VULNEX
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 font-semibold border border-sky-500/30">
                v2.4
              </span>
            </div>
            <div className="text-[11px] text-slate-400 font-medium">
              Vulnerability Risk Management
            </div>
          </div>
        </div>

        {/* Target Context */}
        <div className="mx-3 mt-3 px-3 py-2 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 overflow-hidden">
            <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399] animate-pulse"></span>
            <span className="text-slate-300 truncate font-mono font-medium">localhost:3000</span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">JuiceShop</span>
        </div>

        {/* Navigation List */}
        <nav className="p-3 space-y-1">
          <div className="px-3 pt-2 pb-1 text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Navigation
          </div>
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-all duration-150 group ${
                  isActive
                    ? 'bg-gradient-to-r from-sky-500/20 to-sky-500/5 text-sky-300 border border-sky-500/30 shadow-[0_0_15px_rgba(56,189,248,0.15)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-sky-400' : 'text-slate-500 group-hover:text-slate-300'}`} />
                  <span>{item.label}</span>
                </div>

                <div className="flex items-center gap-1.5">
                  {item.badge && (
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-bold ${
                      isActive ? 'bg-sky-400/20 text-sky-300' : 'bg-slate-800 text-slate-400'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                  {isActive && <ChevronRight className="w-3.5 h-3.5 text-sky-400" />}
                </div>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-3 border-t border-sky-500/10 text-xs">
        <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-800">
          <div className="flex items-center justify-between text-[11px] font-semibold text-slate-300 mb-1">
            <span>Hackathon Activity 4</span>
            <span className="text-emerald-400 font-mono">100% Ready</span>
          </div>
          <p className="text-[10px] text-slate-500 leading-tight">
            Multi-Scanner Deduplication & Explainable 7-Factor Prioritization
          </p>
        </div>
      </div>
    </aside>
  );
}
