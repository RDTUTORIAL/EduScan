import { useState } from 'react';
import { motion } from 'framer-motion';
import { FolderSearch2, Download } from 'lucide-react';
import ScanForm from '../components/ScanForm';
import TerminalOutput from '../components/TerminalOutput';
import RiskChart from '../components/RiskChart';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { runDirectoryScan } from '../utils/apiClient';

const uniqueId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

const DirectoryBuster = () => {
  const { addHistoryEntry, setStatus } = useScanContext();
  const [formData, setFormData] = useState({ baseUrl: '', wordlist: 'admin' });
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const isValid = formData.baseUrl.trim().length > 3;
  const pushLog = (message) => setLogs((prev) => [...prev, { id: uniqueId(), message, variant: 'default' }]);

  const handleScan = async () => {
    if (!isValid || scanning) return;
    setLogs([]);
    setStatus('Scanning...');
    setScanning(true);
    pushLog(`Generate request menggunakan wordlist ${formData.wordlist}`);
    setTimeout(() => pushLog('Mengurai respons 200, 301, 403...'), 600);
    try {
      const payload = await runDirectoryScan(formData);
      setResult(payload);
      setStatus('Done');
      pushLog('Directory enumeration selesai.');
      addHistoryEntry({
        id: uniqueId(),
        tool: 'Directory Buster',
        target: payload.base_url,
        risk: payload.risk_score,
        timestamp: new Date().toISOString(),
        status: 'Completed',
        result: payload,
      });
    } catch (error) {
      pushLog(error.message || 'Gagal menjalankan directory scan', 'error');
      setStatus('Error');
    } finally {
      setScanning(false);
    }
  };

  const handleClear = () => {
    setFormData({ baseUrl: '', wordlist: 'admin' });
    setLogs([]);
    setResult(null);
    setStatus('Ready');
  };

  const formFields = [
    { name: 'baseUrl', label: 'Base URL', type: 'text', placeholder: 'https://example.com' },
    {
      name: 'wordlist',
      label: 'Wordlist',
      type: 'select',
      options: [
        { label: 'admin', value: 'admin' },
        { label: 'config', value: 'config' },
        { label: '.env', value: 'env' },
        { label: 'fuzz (umum)', value: 'fuzz' },
        { label: 'wp-content', value: 'wp-content' },
        { label: 'phpunit', value: 'phpunit' },
        { label: 'phpMyAdmin', value: 'phpmyadmin' },
      ],
    },
  ];

  const badgeClass = (status) => {
    const code = Number(status);
    if (code >= 200 && code < 300) return 'text-emerald-200 border-emerald-500/40 bg-emerald-500/5';
    if (code >= 300 && code < 400) return 'text-sky-200 border-sky-500/40 bg-sky-500/5';
    if (code === 401 || code === 403) return 'text-rose-200 border-rose-500/40 bg-rose-500/5';
    if (code >= 500) return 'text-red-200 border-red-500/40 bg-red-500/5';
    return 'text-amber-200 border-amber-500/40 bg-amber-500/5';
  };

  return (
    <motion.section className="flex flex-col gap-6 min-w-0" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/5 bg-gradient-to-r from-purple-900/30 to-slate-900/50 p-5 sm:p-6">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-500">Active Tool</p>
          <h2 className="text-2xl font-semibold text-white">Directory Buster</h2>
          <p className="text-sm text-slate-400">Fast directory enumeration dengan ffuf dan dirb wordlist.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-secondary w-full sm:w-auto" onClick={handleClear}>
            Reset
          </button>
          <button type="button" className="btn-primary w-full sm:w-auto" disabled={!isValid || scanning} onClick={handleScan}>
            <FolderSearch2 className="h-4 w-4" />
            Start Scan
          </button>
        </div>
      </header>

      <ScanForm fields={formFields} formData={formData} onChange={setFormData}>
        <div className="flex flex-wrap gap-3">
          <button type="button" className="btn-primary text-xs" disabled={!isValid || scanning} onClick={handleScan}>
            Scan
          </button>
          <button type="button" className="btn-secondary text-xs" onClick={handleClear}>
            Clear
          </button>
          <button
            type="button"
            className="btn-secondary text-xs"
            disabled={!result}
            onClick={() => result && exportToJson(result, 'dirbuster-report.json')}
          >
            <Download className="h-4 w-4" />
            Export JSON
          </button>
        </div>
      </ScanForm>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-5 min-w-0">
        <div className="space-y-6 lg:col-span-3 min-w-0">
          <TerminalOutput logs={logs} status={scanning ? 'Scanning...' : result ? 'Done' : 'Ready'} />
          <div className="glass-panel space-y-3 p-4 sm:p-6">
            <p className="text-sm font-semibold text-slate-200">Directory Tree</p>
            <ul className="space-y-3 text-sm text-slate-300">
              {!result?.entries?.length && <p className="text-slate-500">Belum ada enumerasi.</p>}
              {result?.entries?.map((entry) => (
                <li
                  key={entry.path}
                  className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/5 bg-white/5 px-4 py-3"
                >
                  <span className="font-mono text-slate-200 break-all">{entry.path}</span>
                  <div className="flex items-center gap-2 text-xs">
                    <span className={`rounded-full border px-3 py-1 ${badgeClass(entry.status)}`}>{entry.status}</span>
                    <span className="rounded-full border border-white/10 px-2 py-1 text-slate-400">{entry.size}</span>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
        <div className="space-y-6 lg:col-span-2 min-w-0">
          <div className="glass-panel p-4 sm:p-6">
            <RiskChart score={result?.risk_score ?? 0} label="Exposure indicator" />
          </div>
          <div className="glass-panel space-y-2 p-4 sm:p-6 text-sm text-slate-300">
            <p className="font-semibold">Wordlist detail</p>
            <p>
              Menggunakan wordlist "{formData.wordlist}" di server (ffuf). Simpan file txt di services/wordlist
              sesuai nama untuk cakupan optimal.
            </p>
          </div>
          {result?.recommendations && (
            <div className="glass-panel space-y-2 p-4 sm:p-6 text-xs text-slate-400">
              <p className="font-semibold text-slate-100">Rekomendasi</p>
              {(result.recommendations.length ? result.recommendations : ['Tidak ada rekomendasi tambahan.']).map(
                (item) => (
                  <p key={item}>• {item}</p>
                ),
              )}
            </div>
          )}
        </div>
      </div>
    </motion.section>
  );
};

export default DirectoryBuster;
