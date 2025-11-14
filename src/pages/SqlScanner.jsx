import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldOff, Download } from 'lucide-react';
import ScanForm from '../components/ScanForm';
import ResultsTable from '../components/ResultsTable';
import TerminalOutput from '../components/TerminalOutput';
import RiskChart from '../components/RiskChart';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { runSqlScan } from '../utils/apiClient';

const uniqueId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

const getSeverityMeta = (score) => {
  if (score <= 0)
    return {
      label: 'Secure',
      message: 'Nuclei tidak menemukan SQLi pada target ini.',
      className: 'border-emerald-400/30 bg-emerald-500/10 text-emerald-200',
    };
  if (score < 40)
    return {
      label: 'Low',
      message: 'Hanya temuan information/low severity, tetap lakukan review.',
      className: 'border-cyan-400/30 bg-cyan-500/10 text-cyan-200',
    };
  if (score < 70)
    return {
      label: 'Medium',
      message: 'Ada payload SQLi medium, segera lakukan hardening.',
      className: 'border-amber-400/30 bg-amber-500/10 text-amber-200',
    };
  return {
    label: 'High',
    message: 'Payload SQLi high/critical ditemukan! Prioritaskan patch.',
    className: 'border-rose-400/40 bg-rose-500/10 text-rose-200',
  };
};

const SqlScanner = () => {
  const { addHistoryEntry, setStatus } = useScanContext();
  const [formData, setFormData] = useState({
    url: '',
    parameter: 'id',
    payloadType: 'error',
  });
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const severityMeta = result ? getSeverityMeta(result.risk_score || 0) : null;

  const isValid = formData.url.trim().length > 5;
  const pushLog = (message, variant = 'default') =>
    setLogs((prev) => [...prev, { id: uniqueId(), message, variant }]);

  const handleScan = async () => {
    if (!isValid || scanning) return;
    setResult(null);
    setScanning(true);
    setStatus('Scanning...');
    setLogs([]);
    pushLog(`Mengirim payload tipe ${formData.payloadType} ke ${formData.url}`);
    setTimeout(() => pushLog('Memvalidasi respon server & error leakage'), 800);
    try {
      const payload = await runSqlScan(formData);
      setResult(payload);
      setStatus('Done');
      pushLog('Scan selesai. Laporan siap diunduh.');
      addHistoryEntry({
        id: uniqueId(),
        tool: 'SQLi Scanner',
        target: payload.url,
        risk: payload.risk_score,
        timestamp: new Date().toISOString(),
        status: 'Completed',
        result: payload,
      });
    } catch (error) {
      pushLog(error.message || 'Gagal menjalankan SQLi scan', 'error');
      setStatus('Error');
    } finally {
      setScanning(false);
    }
  };

  const handleClear = () => {
    setFormData({ url: '', parameter: 'id', payloadType: 'error' });
    setResult(null);
    setLogs([]);
    setStatus('Ready');
  };

  useEffect(() => {
    if (!result) return;
    const trimmed = formData.url.trim();
    if (!trimmed) return;
    if (trimmed !== result.url) {
      setResult(null);
      setLogs([]);
      setStatus('Ready');
    }
  }, [formData.url, result, setStatus]);

  // Auto-sync the 'parameter' field with the first query param found in the URL
  useEffect(() => {
    const raw = (formData.url || '').trim();
    if (!raw) return;
    try {
      const urlObj = new URL(raw);
      const firstParamRaw = Array.from(urlObj.searchParams.keys())[0];
      const firstParam = firstParamRaw ? firstParamRaw.replace(/^\/+/, '') : '';
      if (firstParam && firstParam !== formData.parameter) {
        setFormData((prev) => ({ ...prev, parameter: firstParam }));
      }
    } catch (e) {
      // Ignore invalid URL while typing
    }
  }, [formData.url]);

  const formFields = [
    { name: 'url', label: 'Target URL', type: 'text', placeholder: 'https://example.com/product.php?id=1' },
    { name: 'parameter', label: 'Parameter', type: 'text', placeholder: 'id' },
    {
      name: 'payloadType',
      label: 'Payload Preset',
      type: 'select',
      options: [
        { label: 'Error based', value: 'error' },
        { label: 'Union select', value: 'union' },
        { label: 'Blind (time based)', value: 'blind' },
      ],
    },
  ];

  return (
    <motion.section
      className="flex flex-col gap-6"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/5 bg-gradient-to-r from-rose-900/40 via-slate-900/60 to-slate-900/60 p-6">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-500">Active Tool</p>
          <h2 className="text-2xl font-semibold text-white">SQLi Scanner</h2>
          <p className="text-sm text-slate-400">Kombinasi manual testing + Nuclei templates dengan payload preset.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-secondary" onClick={handleClear}>
            Reset
          </button>
          <button type="button" className="btn-primary" disabled={!isValid || scanning} onClick={handleScan}>
            <ShieldOff className="h-4 w-4" />
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
            onClick={() => result && exportToJson(result, 'sqli-report.json')}
          >
            <Download className="h-4 w-4" />
            Export JSON
          </button>
        </div>
      </ScanForm>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-3">
          <TerminalOutput logs={logs} status={scanning ? 'Scanning...' : result ? 'Done' : 'Ready'} />
          <ResultsTable
            title="Payload Matrix"
            columns={[
              { key: 'payload', label: 'Payload', mono: true },
              { key: 'result', label: 'Deteksi' },
              { key: 'response', label: 'Response / Source' },
              { key: 'evidence', label: 'Evidence / Notes', mono: true },
            ]}
            data={result?.table || []}
            emptyText="Belum ada payload dijalankan."
          />
        </div>
        <div className="space-y-6 lg:col-span-2">
          <RiskChart score={result?.risk_score ?? 0} label="SQL Injection Risk" />
          {severityMeta ? (
            <div className={`rounded-2xl border p-4 text-xs ${severityMeta.className}`}>
              <p className="text-sm font-semibold text-white">{severityMeta.label}</p>
              <p className="text-slate-200">{severityMeta.message}</p>
            </div>
          ) : (
            <div className="rounded-2xl border border-white/5 bg-white/5 p-4 text-xs text-slate-400">
              Belum ada informasi risiko. Jalankan pemindaian terlebih dahulu.
            </div>
          )}
          <div className="glass-panel space-y-3 p-6">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-slate-200">Code Remediation</p>
              {result?.payload_type && (
                <span className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-200">
                  {(result.payload_type || '').toUpperCase()}
                </span>
              )}
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4 text-xs font-mono text-rose-100">
                <p className="mb-2 font-semibold text-rose-200">Before</p>
                <pre className="whitespace-pre-wrap break-words">{result?.diff_original || "SELECT * FROM users WHERE id = '1';"}</pre>
              </div>
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-xs font-mono text-emerald-100">
                <p className="mb-2 font-semibold text-emerald-200">After</p>
                <pre className="whitespace-pre-wrap break-words">{result?.diff_patched || 'db.prepare("SELECT * FROM users WHERE id = ?")'}</pre>
              </div>
            </div>
            <p className="text-xs text-slate-400">
              Mitigation hint: {result?.mitigation || 'Gunakan prepared statement untuk memutuskan injeksi.'}
            </p>
            {result?.recommendations && (
              <div className="rounded-2xl border border-white/5 bg-white/5 p-4 text-xs text-slate-400">
                <p className="mb-2 font-semibold text-slate-100">Rekomendasi</p>
                {(result.recommendations.length ? result.recommendations : ['Tidak ada rekomendasi tambahan.']).map(
                  (item) => (
                    <p key={item}>• {item}</p>
                  ),
                )}
              </div>
            )}
            {result?.log && result.log.length > 0 && (
              <div>
                <p className="text-xs uppercase text-slate-500">scan log</p>
                <pre className="mt-2 max-h-56 overflow-y-auto rounded-2xl border border-white/5 bg-black/70 p-3 text-[11px] text-emerald-100">
                  {result.log.join('\n')}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </motion.section>
  );
};

export default SqlScanner;
