import React, { useState, useMemo } from 'react';
import { 
  Search, 
  Filter, 
  ArrowUpDown, 
  ExternalLink, 
  ShieldAlert, 
  Flame, 
  Crosshair, 
  Layers,
  ChevronLeft,
  ChevronRight,
  Download
} from 'lucide-react';
import PriorityBadge from '../components/common/PriorityBadge';
import SeverityBadge from '../components/common/SeverityBadge';
import RiskScoreMeter from '../components/common/RiskScoreMeter';

export default function Page3_Findings({ findings = [], onSelectFinding }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterScanner, setFilterScanner] = useState('ALL');
  const [filterPriority, setFilterPriority] = useState('ALL');
  const [filterKevOnly, setFilterKevOnly] = useState(false);
  const [sortBy, setSortBy] = useState('risk_score');
  const [sortOrder, setSortOrder] = useState('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 8;

  // Filter & Sort
  const filteredFindings = useMemo(() => {
    return findings.filter((item) => {
      const f = item.finding || {};
      const intel = item.threat_intel || {};
      const priority = (item.priority || item.priority_label || 'P3').toUpperCase();
      const sev = (f.severity || '').toUpperCase();
      const scanner = (f.scanner || '').toLowerCase();

      // Severity filter
      if (filterSeverity !== 'ALL' && sev !== filterSeverity) return false;

      // Priority filter
      if (filterPriority !== 'ALL' && priority !== filterPriority) return false;

      // Scanner filter
      if (filterScanner !== 'ALL' && !scanner.includes(filterScanner.toLowerCase())) return false;

      // KEV filter
      if (filterKevOnly && !intel.in_cisa_kev) return false;

      // Search Query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const text = `${f.title} ${f.cve || ''} ${f.cwe || ''} ${f.asset || ''} ${f.category || ''} ${f.description || ''} ${f.parameter || ''}`.toLowerCase();
        if (!text.includes(q)) return false;
      }

      return true;
    }).sort((a, b) => {
      let valA = a[sortBy] ?? (a.finding ? a.finding[sortBy] : 0);
      let valB = b[sortBy] ?? (b.finding ? b.finding[sortBy] : 0);
      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
  }, [findings, searchQuery, filterSeverity, filterScanner, filterPriority, filterKevOnly, sortBy, sortOrder]);

  // Pagination
  const totalPages = Math.ceil(filteredFindings.length / pageSize) || 1;
  const paginatedFindings = filteredFindings.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const toggleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-sky-400 uppercase tracking-widest mb-1">
            <ShieldAlert className="w-3.5 h-3.5" />
            Canonical Vulnerability Repository
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Security Findings ({filteredFindings.length})
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Standardized multi-scanner security alerts with threat intel attributes and multi-factor risk scores
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
            Total Unique: <strong className="text-sky-400">{findings.length}</strong>
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
            KEV Exploited: <strong className="text-rose-400">{findings.filter(f => f.threat_intel?.in_cisa_kev).length}</strong>
          </span>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="glass-panel rounded-2xl p-4 border border-sky-500/15 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Search bar */}
          <div className="relative min-w-[280px] flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
              placeholder="Search by CVE, CWE, title, category, parameter, or asset..."
              className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-sky-400 transition-colors"
            />
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Priority Filter */}
            <select
              value={filterPriority}
              onChange={(e) => { setFilterPriority(e.target.value); setCurrentPage(1); }}
              className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-sky-400"
            >
              <option value="ALL">All Priorities</option>
              <option value="P0">P0 (Emergency)</option>
              <option value="P1">P1 (Critical)</option>
              <option value="P2">P2 (High)</option>
              <option value="P3">P3 (Medium)</option>
            </select>

            {/* Severity Filter */}
            <select
              value={filterSeverity}
              onChange={(e) => { setFilterSeverity(e.target.value); setCurrentPage(1); }}
              className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-sky-400"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Scanner Filter */}
            <select
              value={filterScanner}
              onChange={(e) => { setFilterScanner(e.target.value); setCurrentPage(1); }}
              className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-sky-400"
            >
              <option value="ALL">All Scanners</option>
              <option value="nuclei">Nuclei</option>
              <option value="zap">OWASP ZAP</option>
              <option value="openvas">OpenVAS</option>
            </select>

            {/* KEV Toggle Button */}
            <button
              onClick={() => { setFilterKevOnly(!filterKevOnly); setCurrentPage(1); }}
              className={`px-3 py-1.5 rounded-xl font-semibold border flex items-center gap-1.5 transition-all ${
                filterKevOnly
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/50 shadow-md shadow-rose-500/20'
                  : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-slate-200'
              }`}
            >
              <Crosshair className="w-3.5 h-3.5" />
              CISA KEV Only
            </button>
          </div>
        </div>
      </div>

      {/* Table Card */}
      <div className="glass-panel rounded-2xl border border-sky-500/15 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-900/90 text-slate-400 uppercase tracking-wider font-semibold text-[10px] border-b border-slate-800">
                <th className="py-3 px-4 w-12 cursor-pointer" onClick={() => toggleSort('rank')}>
                  <div className="flex items-center gap-1">Rank <ArrowUpDown className="w-3 h-3" /></div>
                </th>
                <th className="py-3 px-4">Priority</th>
                <th className="py-3 px-4">Vulnerability Title</th>
                <th className="py-3 px-4">CVE / CWE</th>
                <th className="py-3 px-4">Scanner</th>
                <th className="py-3 px-4">Asset</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">CVSS</th>
                <th className="py-3 px-4">EPSS</th>
                <th className="py-3 px-4">CISA KEV</th>
                <th className="py-3 px-4 cursor-pointer" onClick={() => toggleSort('risk_score')}>
                  <div className="flex items-center gap-1">Risk Score <ArrowUpDown className="w-3 h-3 text-sky-400" /></div>
                </th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {paginatedFindings.length === 0 ? (
                <tr>
                  <td colSpan={12} className="py-12 text-center text-slate-500 text-xs">
                    No matching vulnerability findings found for the selected filters.
                  </td>
                </tr>
              ) : (
                paginatedFindings.map((item) => {
                  const f = item.finding || {};
                  const intel = item.threat_intel || {};
                  const isP0 = (item.priority || item.priority_label) === 'P0';

                  return (
                    <tr
                      key={f.finding_id}
                      onClick={() => onSelectFinding(item)}
                      className={`cursor-pointer transition-colors ${
                        isP0 
                          ? 'bg-red-500/[0.03] hover:bg-red-500/[0.08]' 
                          : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-slate-500">#{item.rank}</td>
                      <td className="py-3.5 px-4">
                        <PriorityBadge priority={item.priority || item.priority_label || 'P3'} />
                      </td>
                      <td className="py-3.5 px-4 max-w-xs">
                        <div className="font-bold text-white hover:text-sky-300 transition-colors truncate">
                          {f.title}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5 mt-0.5">
                          <span className="text-purple-300">{f.category || 'Vulnerability'}</span>
                          {f.parameter && (
                            <>
                              <span>•</span>
                              <span className="text-slate-500 font-mono">param: {f.parameter}</span>
                            </>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px]">
                        {f.cve ? <span className="text-sky-400 font-semibold">{f.cve}</span> : <span className="text-slate-600">None</span>}
                        {f.cwe && <div className="text-slate-400 text-[10px]">{f.cwe}</div>}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 font-mono text-[10px] uppercase font-bold text-slate-300">
                          {f.scanner}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-300">{f.asset || 'localhost:3000'}</td>
                      <td className="py-3.5 px-4">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="py-3.5 px-4 font-mono font-bold text-slate-300">
                        {f.cvss !== null && f.cvss !== undefined ? f.cvss : 'N/A'}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-300">
                        {intel.epss_score ? `${Math.round(intel.epss_score * 100)}%` : 'N/A'}
                      </td>
                      <td className="py-3.5 px-4">
                        {intel.in_cisa_kev ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                            ⚡ KEV
                          </span>
                        ) : (
                          <span className="text-slate-500 font-mono text-[11px]">No</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4">
                        <RiskScoreMeter score={item.risk_score} />
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectFinding(item);
                          }}
                          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-sky-300 transition-colors"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Toolbar */}
        <div className="px-5 py-3 bg-slate-900/60 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <strong className="text-slate-200">{paginatedFindings.length}</strong> of <strong className="text-slate-200">{filteredFindings.length}</strong> findings
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="p-1 rounded hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-mono px-2">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage === totalPages}
              className="p-1 rounded hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
