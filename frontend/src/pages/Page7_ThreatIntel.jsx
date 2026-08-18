import React, { useState, useEffect } from 'react';
import { 
  Binary, 
  Search, 
  ExternalLink, 
  Crosshair, 
  Flame, 
  ShieldAlert, 
  Database,
  CheckCircle2,
  XCircle,
  HelpCircle,
  TrendingUp,
  AlertTriangle
} from 'lucide-react';
import { api, DEMO_THREAT_INTEL_DATA } from '../services/api';
import KpiCard from '../components/common/KpiCard';

export default function Page7_ThreatIntel() {
  const [intelData, setIntelData] = useState(DEMO_THREAT_INTEL_DATA);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchIntel() {
      setLoading(true);
      try {
        const data = await api.getThreatIntelligence();
        if (data) setIntelData(data);
      } catch (err) {
        console.warn('Using demo threat intel data:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchIntel();
  }, []);

  const records = intelData.intel_records || [];

  const filtered = records.filter(r => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      (r.cve || '').toLowerCase().includes(q) ||
      (r.cvss_vector || '').toLowerCase().includes(q) ||
      (r.exploit_poc_sources || []).some(s => s.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-purple-400 uppercase tracking-widest mb-1">
          <Binary className="w-3.5 h-3.5" />
          Global Threat Intelligence & Exploitation Telemetry
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          CISA KEV Catalog & FIRST EPSS v3 Intelligence Feeds
        </h1>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
          The threat intelligence layer enriches vulnerability findings with real-world weaponization signals: active presence in the <strong>CISA Known Exploited Vulnerabilities (KEV)</strong> catalog, 30-day empirical exploitation probability from <strong>FIRST.org EPSS v3</strong>, and public exploit module availability (Metasploit, Exploit-DB).
        </p>
      </div>

      {/* Threat Intel KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          label="Tracked High-Profile CVEs"
          value={records.length}
          subtext="Locally cached verified feeds"
          icon={Database}
          color="purple"
        />
        <KpiCard
          label="In CISA KEV Catalog"
          value={records.filter(r => r.in_cisa_kev).length}
          subtext="Actively exploited in the wild"
          icon={Crosshair}
          color="rose"
        />
        <KpiCard
          label="Ransomware Weaponized"
          value={records.filter(r => r.ransomware_campaign_use).length}
          subtext="Documented campaign use"
          icon={Flame}
          color="red"
        />
        <KpiCard
          label="Public Exploits Verified"
          value={records.filter(r => r.exploit_available).length}
          subtext="Metasploit / Exploit-DB"
          icon={ShieldAlert}
          color="amber"
        />
      </div>

      {/* Threat Intel Records Table */}
      <div className="glass-panel rounded-2xl border border-sky-500/15 overflow-hidden space-y-4">
        <div className="p-5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-white">
              Enriched CVE Threat Records
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Verified public intelligence data mapped to vulnerability findings
            </p>
          </div>

          <div className="relative min-w-[260px]">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by CVE ID or exploit..."
              className="w-full pl-9 pr-4 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-sky-400"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-slate-900/90 text-slate-400 uppercase tracking-wider font-semibold text-[10px] border-b border-slate-800">
                <th className="py-3 px-4">CVE Identifier</th>
                <th className="py-3 px-4">CVSS v3 Score</th>
                <th className="py-3 px-4">EPSS Probability</th>
                <th className="py-3 px-4">EPSS Percentile</th>
                <th className="py-3 px-4">CISA KEV Status</th>
                <th className="py-3 px-4">Ransomware Use</th>
                <th className="py-3 px-4">Exploit Availability</th>
                <th className="py-3 px-4 text-right">NVD Link</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filtered.map((record, idx) => {
                const epssScore = record.epss_score ? (record.epss_score * 100).toFixed(1) + '%' : 'Unavailable';
                const epssPct = record.epss_percentile ? (record.epss_percentile * 100).toFixed(1) + 'th' : 'Unknown';

                return (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3.5 px-4 font-bold text-sky-400">{record.cve}</td>
                    <td className="py-3.5 px-4 font-bold text-slate-200">
                      {record.cvss_v3_score ? `${record.cvss_v3_score} / 10.0` : 'N/A'}
                    </td>
                    <td className="py-3.5 px-4 font-bold text-purple-300">{epssScore}</td>
                    <td className="py-3.5 px-4 text-slate-400">{epssPct}</td>
                    <td className="py-3.5 px-4">
                      {record.in_cisa_kev ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                          ⚡ Known Exploited (Added {record.kev_date_added || '2021'})
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Not Listed</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      {record.ransomware_campaign_use ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-300 border border-red-500/40">
                          Active Campaign Use
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">No</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      {record.exploit_available ? (
                        <div className="flex flex-wrap gap-1">
                          {record.exploit_poc_sources?.map((s, i) => (
                            <span key={i} className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 text-[10px]">
                              {s}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-slate-500 text-[11px]">No public PoC</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${record.cve}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-sky-400 hover:text-sky-300 p-1 inline-flex"
                      >
                        <ExternalLink className="w-4 h-4" />
                      </a>
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
