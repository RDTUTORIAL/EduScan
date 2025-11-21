import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Globe, Smartphone, Mail, Download } from 'lucide-react';
import TerminalOutput from '../components/TerminalOutput';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { runOsintScan, runWappalyzer } from '../utils/apiClient';

const uniqueId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

const TABS = [
  { id: 'phone', label: 'Phone', icon: Smartphone, placeholder: '+628123456789' },
  { id: 'domain', label: 'Domain', icon: Globe, placeholder: 'example.com' },
  { id: 'email', label: 'Email', icon: Mail, placeholder: 'user@example.com' },
];

const OsintHub = () => {
  const { addHistoryEntry, setStatus } = useScanContext();
  const [activeTab, setActiveTab] = useState('phone');
  const [inputValue, setInputValue] = useState('');
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [filterQuery, setFilterQuery] = useState('');
  const [filterCodes, setFilterCodes] = useState({ '+': true, '-': false, x: false, '!': false });
  const [expandedTools, setExpandedTools] = useState({});
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [truecallerCookie, setTruecallerCookie] = useState(() => {
    try {
      return localStorage.getItem('eduscan_truecaller_cookie') || '';
    } catch {
      return '';
    }
  });
  const [wappalyzerData, setWappalyzerData] = useState(null);

  const tabMeta = useMemo(() => TABS.find((tab) => tab.id === activeTab) || TABS[0], [activeTab]);

  // Aggregate counts across all tool outputs for quick summary
  const aggCounts = useMemo(() => {
    const empty = { '+': 0, '-': 0, x: 0, '!': 0 };
    if (!result?.tool_outputs?.length) return empty;
    return result.tool_outputs.reduce((acc, t) => {
      const c = t?.counts || empty;
      return {
        '+': acc['+'] + (c['+'] || 0),
        '-': acc['-'] + (c['-'] || 0),
        x: acc.x + (c.x || 0),
        '!': acc['!'] + (c['!'] || 0),
      };
    }, { ...empty });
  }, [result]);

  // For domain/web scans we want to surface web-related tool outputs in the
  // OSINT Summary panel instead of the Tool Results list. Define helpers to
  // split tool outputs into web vs non-web so we can render them separately.
  const webToolNames = useMemo(() => new Set(['whois', 'nuclei', 'nikto', 'ffuf', 'http', 'crawler']), []);
  const { nonWebToolOutputs, webToolOutputs } = useMemo(() => {
    const nonWeb = [];
    const web = [];
    const outs = Array.isArray(result?.tool_outputs) ? result.tool_outputs : [];
    for (const t of outs) {
      const name = (t?.name || '').toLowerCase();
      // treat standard web/domain tools as web-related when current tab is domain
      if (result?.tab === 'domain' && webToolNames.has(name)) {
        web.push(t);
      } else {
        nonWeb.push(t);
      }
    }
    return { nonWebToolOutputs: nonWeb, webToolOutputs: web };
  }, [result, webToolNames]);

  // Prefer phonenumbers details for phone summary if available
  const phoneSummary = useMemo(() => {
    if (!result || result.tab !== 'phone') return null;
    const outputs = Array.isArray(result.tool_outputs) ? result.tool_outputs : [];
    const pn = outputs.find((t) => (t?.name || '').toLowerCase() === 'phonenumbers');
    const det = (pn && typeof pn.details === 'object') ? pn.details : {};
    const tz = Array.isArray(det?.timezones) ? det.timezones.join(', ') : (det?.timezones || '');
    const tc = outputs.find((t) => (t?.name || '').toLowerCase() === 'truecaller')
      || outputs.find((t) => (t?.name || '').toLowerCase() === 'truecaller-web');
    const tcDet = (tc && typeof tc.details === 'object') ? tc.details : {};

    // Derive fallback info from phoneinfoga entries (which often only return text)
    const phoneinfoga = outputs.find((t) => (t?.name || '').toLowerCase() === 'phoneinfoga');
    const derived = {};
    const parseEntries = Array.isArray(phoneinfoga?.entries) ? phoneinfoga.entries : [];
    for (const entry of parseEntries) {
      const raw = String(entry.site || '');
      const text = raw.replace(/^URL:\s*/i, '');
      const mE = text.match(/E164:\s*([+\d]+)/i);
      const mInt = text.match(/International:\s*([+\d]+)/i);
      const mNat = text.match(/Local:\s*([+\d-]+)/i) || text.match(/Raw local:\s*([+\d-]+)/i);
      const mCountry = text.match(/Country:\s*([A-Z]{2,})/i);
      if (mE) derived.e164 = mE[1];
      if (mInt) derived.international = mInt[1];
      if (mNat) derived.national = mNat[1];
      if (mCountry) derived.country = mCountry[1];
    }

    return {
      source: pn ? 'phonenumbers' : phoneinfoga ? 'phoneinfoga' : null,
      e164: det.e164 || result.e164 || derived.e164 || '-',
      international: det.international || result.international || derived.international || '-',
      national: det.national || result.national || derived.national || '-',
      country: result.country || det.location || derived.country || '-',
      countryCode: det.country_code || result.country_code || derived.country || '-',
      timezone: tz || result.timezone || '-',
      carrier: det.carrier || result.carrier || '-',
      region: result.region || result.location || det.location || '-',
      name: (tcDet?.name || result?.name || '').trim() || '-',
      nameSource: tc ? (tc.name || 'truecaller') : null,
    };
  }, [result]);
  const pushLog = (message) => setLogs((prev) => [...prev, { id: uniqueId(), message, variant: 'default' }]);

  const handleScan = async () => {
    if (!inputValue.trim() || scanning) return;
    setLogs([]);
    setScanning(true);
    setStatus('Scanning...');
    pushLog(`Mengumpulkan OSINT ${activeTab} dari sumber publik`);
    try {
      const payload = await runOsintScan({
        tab: activeTab,
        value: inputValue,
        ...(activeTab === 'phone' && truecallerCookie ? { truecaller_cookie: truecallerCookie } : {}),
      });
      // Minimal terminal logs: per-tool summary only
      if (Array.isArray(payload?.tool_outputs) && payload.tool_outputs.length) {
        payload.tool_outputs.forEach((t) => {
          const c = t?.counts || { '+': 0, '-': 0, x: 0, '!': 0 };
          pushLog(`[${t.name}] +${c['+'] || 0} -${c['-'] || 0} x${c['x'] || 0} !${c['!'] || 0}`);
        });
      }
      // Log tool statuses (skipped/error) to help troubleshooting
      if (Array.isArray(payload?.tools) && payload.tools.length) {
        for (const t of payload.tools) {
          const name = t?.name || 'tool';
          const status = t?.status || 'unknown';
          const notes = t?.notes ? ` - ${t.notes}` : '';
          if (status === 'skipped' || status === 'error') {
            pushLog(`[!] ${name}: ${status}${notes}`);
          }
        }
      }
      // Also surface summary_text if present
      if (payload?.summary_text) {
        pushLog(`Summary: ${payload.summary_text}`);
      }
      // For domain scans, also run Wappalyzer to get technology information
      if (activeTab === 'domain') {
        try {
          pushLog('Menjalankan analisis teknologi dengan Wappalyzer...');
          const wappData = await runWappalyzer({ domain: inputValue });
          setWappalyzerData(wappData);
          pushLog(`[wappalyzer] Ditemukan ${Object.keys(wappData?.technologies || {}).length} teknologi`);
          
          // Merge Wappalyzer data into payload
          if (wappData?.technologies) {
            payload.wappalyzer_technologies = wappData.technologies;
            payload.technologies = Object.entries(wappData.technologies).map(([category, techs]) => 
              techs.map(tech => `${tech.name}${tech.version ? ` ${tech.version}` : ''}`).join(', ')
            ).join(' | ');
          }
        } catch (wappError) {
          pushLog(`[wappalyzer] Error: ${wappError.message}`, 'error');
        }
      }
      
      setResult(payload);
      setStatus('Done');
      pushLog('Profil OSINT berhasil disusun.');
      addHistoryEntry({
        id: uniqueId(),
        tool: 'OSINT Hub',
        target: inputValue,
        risk: payload.confidence === 'High' ? 68 : 35,
        timestamp: new Date().toISOString(),
        status: 'Completed',
        result: payload,
      });
    } catch (error) {
      pushLog(error.message || 'Gagal mengambil data OSINT', 'error');
      setStatus('Error');
    } finally {
      setScanning(false);
    }
  };

  const handleClear = () => {
    setInputValue('');
    setLogs([]);
    setResult(null);
    setWappalyzerData(null);
    setStatus('Ready');
  };

  return (
    <motion.section className="flex flex-col gap-6 min-w-0" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/5 bg-gradient-to-r from-slate-900/60 to-slate-900/30 p-6">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-500">Active Tool</p>
          <h2 className="text-2xl font-semibold text-white">OSINT Hub</h2>
          <p className="text-sm text-slate-400">PhoneInfoga-style lookup untuk phone, domain, email, dan username.</p>
        </div>
      </header>

      <div className="glass-panel space-y-5 p-6 min-w-0">
        <div className="flex flex-wrap gap-2">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              className={`rounded-2xl border px-4 py-2 text-sm font-semibold transition ${
                activeTab === tab.id ? 'border-cyan-400 bg-cyan-400/10 text-cyan-100' : 'border-transparent bg-white/5 text-slate-400'
              }`}
              onClick={() => {
                setActiveTab(tab.id);
                setResult(null);
                setLogs([]);
                setFilterQuery('');
                setFilterCodes({ '+': true, '-': false, x: false, '!': false });
              }}
            >
              <tab.icon className="mr-2 inline h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
          <input
            type="text"
            className="w-full rounded-2xl border border-slate-800/60 bg-slate-900/40 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 sm:flex-1"
            placeholder={tabMeta.placeholder}
            value={inputValue}
            onChange={(event) => setInputValue(event.target.value)}
          />
          <button
            type="button"
            className="btn-primary w-full sm:w-auto"
            disabled={!inputValue.trim() || scanning}
            onClick={handleScan}
          >
            Start Scan
          </button>
          <button type="button" className="btn-secondary w-full sm:w-auto" onClick={handleClear}>
            Clear
          </button>
          <button
            type="button"
            className="btn-secondary w-full sm:w-auto"
            disabled={!result}
            onClick={() => result && exportToJson(result, 'osint-report.json')}
          >
            <Download className="h-4 w-4" />
            Export JSON
          </button>
          {activeTab === 'phone' && (
            <button
              type="button"
              className="btn-secondary w-full sm:w-auto"
              onClick={() => setShowAdvanced((p) => !p)}
            >
              {showAdvanced ? 'Hide Advanced' : 'Advanced'}
            </button>
          )}
        </div>
        {activeTab === 'phone' && showAdvanced && (
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <input
              type="text"
              className="w-full rounded-2xl border border-slate-800/60 bg-slate-900/40 px-4 py-3 text-xs text-slate-100 placeholder:text-slate-500 sm:flex-1"
              placeholder="Truecaller Cookie (tc_session=...; ...)"
              value={truecallerCookie}
              onChange={(e) => {
                setTruecallerCookie(e.target.value);
                try { localStorage.setItem('eduscan_truecaller_cookie', e.target.value); } catch {}
              }}
            />
            <span className="text-[11px] text-slate-500">Cookie ini hanya dikirim untuk tab Phone</span>
          </div>
        )}
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-5 min-w-0">
        <div className="space-y-6 lg:col-span-3 min-w-0">
          <TerminalOutput logs={logs} status={scanning ? 'Scanning...' : result ? 'Done' : 'Ready'} />
          <div className="glass-panel space-y-4 p-6 min-w-0">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm font-semibold text-slate-200">OSINT Summary {result ? `• ${new Date(result.timestamp).toLocaleString()}` : ''}</p>
              {result?.value && (
                <span className="rounded-xl border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-300 break-all">Target: {result.value}</span>
              )}
            </div>
            {!result && <p className="text-sm text-slate-500">Masukkan data lalu jalankan scan.</p>}
            {result && (
              <>
                {/* PHONE NUMBER LAYOUT - Elegant card-based design */}
                {result.tab === 'phone' && (
                  <div className="space-y-4">
                    {result.tool_outputs?.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        <span className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-200">+ {aggCounts['+']}</span>
                        <span className="rounded-xl border border-slate-500/30 bg-slate-500/10 px-3 py-1 text-xs text-slate-300">- {aggCounts['-']}</span>
                        <span className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs text-amber-200">x {aggCounts['x']}</span>
                        <span className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-1 text-xs text-rose-200">! {aggCounts['!']}</span>
                      </div>
                    )}
                    <div className="grid gap-4 md:grid-cols-3">
                      <div className="rounded-2xl border border-blue-500/20 bg-gradient-to-br from-blue-500/10 to-blue-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-blue-300/70">Name {phoneSummary?.nameSource ? <span className="ml-1 rounded bg-blue-400/20 px-1.5 py-0.5 text-[10px] text-blue-300">via {phoneSummary.nameSource}</span> : null}</p>
                        <p className="mt-1 text-lg font-bold text-blue-100">{phoneSummary?.name || '-'}</p>
                      </div>
                      <div className="rounded-2xl border border-cyan-500/20 bg-gradient-to-br from-cyan-500/10 to-cyan-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-cyan-300/70">E.164 {phoneSummary?.source ? <span className="ml-1 rounded bg-cyan-400/20 px-1.5 py-0.5 text-[10px] text-cyan-300">via {phoneSummary.source}</span> : null}</p>
                        <p className="mt-1 font-mono text-base font-semibold text-cyan-100">{phoneSummary?.e164 || '-'}</p>
                      </div>
                      <div className="rounded-2xl border border-purple-500/20 bg-gradient-to-br from-purple-500/10 to-purple-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-purple-300/70">Country</p>
                        <p className="mt-1 text-base font-semibold text-purple-100">{phoneSummary?.country || '-'}</p>
                      </div>
                      <div className="rounded-2xl border border-indigo-500/20 bg-gradient-to-br from-indigo-500/10 to-indigo-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-indigo-300/70">International</p>
                        <p className="mt-1 font-mono text-base font-semibold text-indigo-100">{phoneSummary?.international || '-'}</p>
                      </div>
                      <div className="rounded-2xl border border-violet-500/20 bg-gradient-to-br from-violet-500/10 to-violet-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-violet-300/70">National</p>
                        <p className="mt-1 font-mono text-base font-semibold text-violet-100">{phoneSummary?.national || '-'}</p>
                      </div>
                      <div className="rounded-2xl border border-pink-500/20 bg-gradient-to-br from-pink-500/10 to-pink-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-pink-300/70">Country Code</p>
                        <p className="mt-1 text-base font-semibold text-pink-100">{phoneSummary?.countryCode ? `+${phoneSummary.countryCode}` : '-'}</p>
                      </div>
                      <div className="rounded-2xl border border-teal-500/20 bg-gradient-to-br from-teal-500/10 to-teal-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-teal-300/70">Timezone</p>
                        <p className="mt-1 text-base font-semibold text-teal-100">{phoneSummary?.timezone || '-'}</p>
                      </div>
                      <div className="rounded-2xl border border-emerald-500/20 bg-gradient-to-br from-emerald-500/10 to-emerald-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-emerald-300/70">Carrier</p>
                        <p className="mt-1 text-base font-semibold text-emerald-100">{phoneSummary?.carrier || '-'}</p>
                      </div>
                      <div className="rounded-2xl border border-sky-500/20 bg-gradient-to-br from-sky-500/10 to-sky-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-sky-300/70">Region</p>
                        <p className="mt-1 text-base font-semibold text-sky-100">{phoneSummary?.region || '-'}</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* EMAIL LAYOUT - Security-focused design */}
                {result.tab === 'email' && (
                  <div className="space-y-4">
                    {result.tool_outputs?.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        <span className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-200">+ {aggCounts['+']}</span>
                        <span className="rounded-xl border border-slate-500/30 bg-slate-500/10 px-3 py-1 text-xs text-slate-300">- {aggCounts['-']}</span>
                        <span className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs text-amber-200">x {aggCounts['x']}</span>
                        <span className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-1 text-xs text-rose-200">! {aggCounts['!']}</span>
                      </div>
                    )}
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                      {result.gravatar && (
                        <div className="flex items-center gap-3 rounded-2xl border border-purple-500/20 bg-gradient-to-br from-purple-500/10 to-purple-600/5 p-4">
                          <img src={result.gravatar} alt="gravatar" className="h-12 w-12 rounded-full border-2 border-purple-400/30" />
                          <div className="text-sm">
                            <p className="text-xs uppercase tracking-wider text-purple-300/70">Avatar</p>
                            <p className="font-semibold text-purple-100">Gravatar</p>
                          </div>
                        </div>
                      )}
                      <div className="rounded-2xl border border-rose-500/20 bg-gradient-to-br from-rose-500/10 to-rose-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-rose-300/70">Breaches</p>
                        <p className="mt-1 text-2xl font-bold text-rose-100">{result.breaches ?? 0}</p>
                        <p className="mt-1 text-[10px] text-rose-300/60">Security incidents</p>
                      </div>
                      <div className="rounded-2xl border border-amber-500/20 bg-gradient-to-br from-amber-500/10 to-amber-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-amber-300/70">Disposable</p>
                        <p className="mt-1 text-lg font-semibold text-amber-100">{result.disposable ? 'Yes' : 'No'}</p>
                        <p className="mt-1 text-[10px] text-amber-300/60">Temporary email</p>
                      </div>
                      <div className="rounded-2xl border border-emerald-500/20 bg-gradient-to-br from-emerald-500/10 to-emerald-600/5 p-4 text-sm">
                        <p className="text-xs uppercase tracking-wider text-emerald-300/70">Used Sites</p>
                        <p className="mt-1 text-2xl font-bold text-emerald-100">{aggCounts['+'] || 0}</p>
                        <p className="mt-1 text-[10px] text-emerald-300/60">Active platforms</p>
                      </div>
                    </div>
                  </div>
                )}


                {/* DOMAIN/WEB LAYOUT - Technical & comprehensive */}
                {result.tab === 'domain' && (
                  <div className="space-y-6">
                    
                    {/* Extract whois data from summary or tool_outputs */}
                    {(() => {
                      const whoisData = result.summary?.whois?.details || 
                                       result.tool_outputs?.find(t => t.name === 'whois')?.details || {};
                      
                      return (
                        <>
                          {/* Domain Registration Info */}
                          <div>
                            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">Domain Registration</h3>
                            <div className="grid gap-3 md:grid-cols-3">
                              <div className="rounded-xl border border-indigo-500/20 bg-gradient-to-br from-indigo-500/10 to-indigo-600/5 p-3 text-sm">
                                <p className="text-[10px] uppercase tracking-wider text-indigo-300/70">Domain</p>
                                <p className="mt-1 text-sm font-semibold text-indigo-100">{whoisData.domain || result.value || '-'}</p>
                              </div>
                              <div className="rounded-xl border border-blue-500/20 bg-gradient-to-br from-blue-500/10 to-blue-600/5 p-3 text-sm">
                                <p className="text-[10px] uppercase tracking-wider text-blue-300/70">Registrar</p>
                                <p className="mt-1 text-sm font-semibold text-blue-100">{whoisData.registrar || result.registrar || '-'}</p>
                              </div>
                              <div className="rounded-xl border border-green-500/20 bg-gradient-to-br from-green-500/10 to-green-600/5 p-3 text-sm">
                                <p className="text-[10px] uppercase tracking-wider text-green-300/70">Created</p>
                                <p className="mt-1 font-mono text-xs font-semibold text-green-100">
                                  {whoisData.created ? new Date(whoisData.created).toLocaleDateString() : (result.created || '-')}
                                </p>
                              </div>
                              <div className="rounded-xl border border-orange-500/20 bg-gradient-to-br from-orange-500/10 to-orange-600/5 p-3 text-sm">
                                <p className="text-[10px] uppercase tracking-wider text-orange-300/70">Expires</p>
                                <p className="mt-1 font-mono text-xs font-semibold text-orange-100">
                                  {whoisData.expires ? new Date(whoisData.expires).toLocaleDateString() : (result.expires || '-')}
                                </p>
                              </div>
                              <div className="rounded-xl border border-purple-500/20 bg-gradient-to-br from-purple-500/10 to-purple-600/5 p-3 text-sm">
                                <p className="text-[10px] uppercase tracking-wider text-purple-300/70">Updated</p>
                                <p className="mt-1 font-mono text-xs font-semibold text-purple-100">
                                  {whoisData.updated ? new Date(whoisData.updated).toLocaleDateString() : (result.updated || '-')}
                                </p>
                              </div>
                              <div className="rounded-xl border border-pink-500/20 bg-gradient-to-br from-pink-500/10 to-pink-600/5 p-3 text-sm">
                                <p className="text-[10px] uppercase tracking-wider text-pink-300/70">Status</p>
                                <p className="mt-1 text-xs font-semibold text-pink-100">
                                  {Array.isArray(whoisData.status) ? whoisData.status.join(', ') : (whoisData.status || result.status || '-')}
                                </p>
                              </div>
                            </div>
                          </div>

                          {/* Technical Info */}
                          <div>
                            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">Technical Details</h3>
                            <div className="grid gap-3 md:grid-cols-2">
                              <div className="rounded-xl border border-cyan-500/20 bg-gradient-to-br from-cyan-500/10 to-cyan-600/5 p-3 text-sm">
                                <p className="text-[10px] uppercase tracking-wider text-cyan-300/70">Name Servers</p>
                                <p className="mt-1 font-mono text-xs text-cyan-100">
                                  {Array.isArray(whoisData.nameservers) 
                                    ? whoisData.nameservers.join(', ') 
                                    : (Array.isArray(result.nameservers) ? result.nameservers.join(', ') : (result.nameservers || '-'))
                                  }
                                </p>
                              </div>
                              <div className="rounded-xl border border-teal-500/20 bg-gradient-to-br from-teal-500/10 to-teal-600/5 p-3 text-sm">
                                <p className="text-[10px] uppercase tracking-wider text-teal-300/70">DNS Records</p>
                                <p className="mt-1 font-mono text-xs text-teal-100">
                                  {Array.isArray(result.dns) ? result.dns.join(', ') : (result.dns_records || result.dns || '-')}
                                </p>
                              </div>
                              <div className="rounded-xl border border-violet-500/20 bg-gradient-to-br from-violet-500/10 to-violet-600/5 p-3 text-sm md:col-span-2">
                                <p className="text-[10px] uppercase tracking-wider text-violet-300/70">Technologies (Wappalyzer)</p>
                                {result.wappalyzer_technologies ? (
                                  <div className="mt-2 space-y-1">
                                    {Object.entries(result.wappalyzer_technologies).map(([category, techs]) => (
                                      <div key={category} className="text-xs break-words">
                                        <span className="text-violet-400 font-semibold">{category}:</span>
                                        <span className="ml-2 text-violet-200">
                                          {techs.map(tech => `${tech.name}${tech.version ? ` ${tech.version}` : ''}`).join(', ')}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <p className="mt-1 text-xs text-violet-100 break-words">
                                    {Array.isArray(result.technologies) ? result.technologies.join(', ') : (result.technologies || 'Scanning...')}
                                  </p>
                                )}
                              </div>
                            </div>
                          </div>

                        </>
                      );
                    })()}
                  </div>
                )}
              </>
            )}
          </div>
          {nonWebToolOutputs.length > 0 && (
            <div className="glass-panel space-y-4 p-6">
              <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
                <p className="text-sm font-semibold text-slate-200">Tool Results</p>
                <div className="flex flex-wrap items-center gap-2">
                  {['+', '-', 'x', '!'].map((code) => (
                    <button
                      key={code}
                      type="button"
                      onClick={() => setFilterCodes((prev) => ({ ...prev, [code]: !prev[code] }))}
                      className={`rounded-full border px-2 py-1 text-[11px] ${
                        filterCodes[code]
                          ? 'border-cyan-400 bg-cyan-400/10 text-cyan-100'
                          : 'border-white/10 bg-white/5 text-slate-400'
                      }`}
                      title={`Toggle ${code}`}
                    >
                      {code}
                    </button>
                  ))}
                  <input
                    type="text"
                    value={filterQuery}
                    onChange={(e) => setFilterQuery(e.target.value)}
                    placeholder="Filter situs..."
                    className="w-full rounded-xl border border-slate-800/60 bg-slate-900/40 px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 sm:w-auto sm:min-w-[180px]"
                  />
                  <button
                    type="button"
                    className="rounded-xl border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-300"
                    onClick={() => {
                      setFilterCodes({ '+': true, '-': false, x: false, '!': false });
                      setFilterQuery('');
                    }}
                  >
                    Reset
                  </button>
                </div>
              </div>
              <div className={`grid gap-4 ${nonWebToolOutputs.length > 1 ? 'md:grid-cols-2' : 'md:grid-cols-1'}`}>
                {nonWebToolOutputs.map((tool) => {
                  const c = tool.counts || { '+': 0, '-': 0, x: 0, '!': 0 };
                  const entries = Array.isArray(tool.entries) ? tool.entries : [];
                  const filtered = entries
                    .filter((e) => !!filterCodes[e.code])
                    .filter((e) => !filterQuery || (e.site || '').toLowerCase().includes(filterQuery.toLowerCase()));
                  // Dedupe and sort for tidy display
                  const order = { '+': 0, '-': 1, x: 2, '!': 3 };
                  const uniq = [];
                  const seen = new Set();
                  for (const e of filtered) {
                    const key = `${e.code}-${e.site}`;
                    if (seen.has(key)) continue;
                    seen.add(key);
                    uniq.push(e);
                  }
                  uniq.sort((a, b) => (order[a.code] - order[b.code]) || String(a.site).localeCompare(String(b.site)));
                  const limit = expandedTools[tool.name] ? 200 : 20;
                  const sliced = uniq.slice(0, limit);
                  return (
                    <div key={tool.name} className="rounded-2xl border border-white/5 bg-white/5 p-4 text-sm text-slate-300">
                      <div className="mb-2 flex items-center justify-between">
                        <span className="font-semibold text-slate-100">{tool.name}</span>
                        <div className="flex flex-wrap gap-2 text-[11px]">
                          <span className="rounded-full border border-white/10 px-2 py-0.5">+ {c['+'] || 0}</span>
                          <span className="rounded-full border border-white/10 px-2 py-0.5">- {c['-'] || 0}</span>
                          <span className="rounded-full border border-white/10 px-2 py-0.5">x {c['x'] || 0}</span>
                          <span className="rounded-full border border-white/10 px-2 py-0.5">! {c['!'] || 0}</span>
                        </div>
                      </div>
                      <ul className="max-h-52 space-y-1 overflow-auto pr-2 font-mono text-[12px] sm:max-h-60">
                        {sliced.map((e, idx) => {
                          const rawSite = e.site || '';
                          const cleanSite = rawSite.replace(/^URL:\\s*/i, '');
                          const shortSite = cleanSite.length > 70 ? `${cleanSite.slice(0, 70)}…` : cleanSite;
                          return (
                            <li key={`${tool.name}-${idx}`} className="flex items-start justify-between gap-2">
                              <span
                                className={`mr-2 rounded px-1 py-0.5 text-[10px] ${
                                  e.code === '+'
                                    ? 'bg-emerald-500/20 text-emerald-200'
                                    : e.code === '-'
                                    ? 'bg-slate-500/20 text-slate-300'
                                    : e.code === 'x'
                                    ? 'bg-amber-500/20 text-amber-200'
                                    : 'bg-rose-500/20 text-rose-200'
                                }`}
                              >
                                {e.code}
                              </span>
                              <span className="break-words" title={cleanSite || undefined}>{shortSite}</span>
                            </li>
                          );
                        })}
                        {sliced.length === 0 && (
                          <li className="text-slate-500">Tidak ada entri yang cocok dengan filter.</li>
                        )}
                      </ul>
                      {uniq.length > 50 && (
                        <div className="mt-3 text-right">
                          <button
                            type="button"
                            className="rounded-xl border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-300"
                            onClick={() => setExpandedTools((prev) => ({ ...prev, [tool.name]: !prev[tool.name] }))}
                          >
                            {expandedTools[tool.name] ? 'Show less' : `Show more (${uniq.length - 50})`}
                          </button>
                        </div>
                      )}
                      <p className="mt-2 text-[11px] text-slate-500">[+] used, [-] not used, [x] rate limit, [!] error</p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
        <div className="space-y-6 lg:col-span-2">
          <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
            <p className="font-semibold">Intel summary</p>
            <p>
              EduScan hanya menggunakan data mock. Di dunia nyata, gabungkan banyak sumber OSINT seperti Shodan, Hunter,
              HaveIBeenPwned, dan arsip publik lainnya.
            </p>
          </div>
        </div>
      </div>
    </motion.section>
  );
};

export default OsintHub;
