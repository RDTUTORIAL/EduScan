import { useState } from 'react';
import { motion } from 'framer-motion';
import { Lock, Download } from 'lucide-react';
import ScanForm from '../components/ScanForm';
import TerminalOutput from '../components/TerminalOutput';
import RiskChart from '../components/RiskChart';
import ResultsTable from '../components/ResultsTable';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { runTlsAudit } from '../utils/apiClient';

const uniqueId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

const TlsInspector = () => {
  const { addHistoryEntry, setStatus } = useScanContext();
  const [formData, setFormData] = useState({ url: 'https://example.com' });
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const pushLog = (message, variant = 'default') =>
    setLogs((prev) => [...prev, { id: uniqueId(), message, variant }]);

  const handleScan = async () => {
    if (!formData.url || scanning) return;
    setLogs([]);
    setScanning(true);
    setStatus('Scanning...');
    pushLog('Memulai sslyze handshake...');
    setTimeout(() => pushLog('Enumerasi cipher suite & sertifikat...'), 700);
    try {
      const payload = await runTlsAudit(formData);
      setResult(payload);
      setStatus('Done');
      pushLog('TLS audit selesai.');
      addHistoryEntry({
        id: uniqueId(),
        tool: 'TLS Inspector',
        target: formData.url,
        risk: payload.risk_score,
        timestamp: new Date().toISOString(),
        status: 'Completed',
        result: payload,
      });
    } catch (error) {
      pushLog(error.message || 'Gagal menjalankan TLS audit', 'error');
      setStatus('Error');
    } finally {
      setScanning(false);
    }
  };

  const handleClear = () => {
    setFormData({ url: '' });
    setResult(null);
    setLogs([]);
    setStatus('Ready');
  };

  return (
    <motion.section className="flex flex-col gap-6" initial={{ opacity: 0.9, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/5 bg-gradient-to-r from-emerald-900/40 to-slate-900/50 p-6">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-500">Active Tool</p>
          <h2 className="text-2xl font-semibold text-white">TLS Inspector</h2>
          <p className="text-sm text-slate-400">Mirip sslyze/sslscan dengan ringkasan certificate & protocol hygiene.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-secondary" onClick={handleClear}>
            Clear
          </button>
          <button type="button" className="btn-primary" disabled={!formData.url || scanning} onClick={handleScan}>
            <Lock className="h-4 w-4" />
            Audit TLS
          </button>
        </div>
      </header>

      <ScanForm
        fields={[{ name: 'url', label: 'Target HTTPS URL', type: 'text', placeholder: 'https://example.com' }]}
        formData={formData}
        onChange={setFormData}
      >
        <div className="flex flex-wrap gap-3">
          <button type="button" className="btn-primary text-xs" disabled={!formData.url || scanning} onClick={handleScan}>
            Scan
          </button>
          <button type="button" className="btn-secondary text-xs" onClick={handleClear}>
            Clear
          </button>
          <button
            type="button"
            className="btn-secondary text-xs"
            disabled={!result}
            onClick={() => result && exportToJson(result, 'tls-audit.json')}
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
            title="Protocol Matrix"
            columns={[
              { key: 'name', label: 'Protocol' },
              { key: 'supported', label: 'Supported' },
              { key: 'cipher', label: 'Cipher' },
              { key: 'grade', label: 'Grade' },
            ]}
            data={
              result?.protocols?.map((item) => ({
                ...item,
                supported: item.supported ? 'Yes' : 'No',
              })) || []
            }
            emptyText="Belum ada data TLS."
          />
        </div>
        <div className="space-y-6 lg:col-span-2">
          <RiskChart score={result?.risk_score || 16} label="TLS Hygiene" />
          <div className="glass-panel space-y-3 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">Certificate</p>
            {result ? (
              <div className="space-y-1 text-xs">
                <p>Issuer: {result.certificate.issuer}</p>
                <p>Subject: {result.certificate.subject}</p>
                <p>
                  Valid: {result.certificate.valid_from} → {result.certificate.valid_to} (
                  {result.certificate.days_remaining} hari)
                </p>
              </div>
            ) : (
              <p className="text-slate-500">Jalankan scan untuk melihat detail sertifikat.</p>
            )}
          </div>
          <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">Findings</p>
            {(result?.findings || []).map((finding) => (
              <div key={`${finding.issue}-${finding.tool}`} className="rounded-xl border border-white/5 bg-white/5 p-3">
                <p className="text-xs uppercase text-slate-500">{finding.tool}</p>
                <p className="font-semibold text-white">{finding.issue}</p>
                <p className="text-xs text-slate-500">{finding.recommendation}</p>
              </div>
            ))}
            {!result?.findings?.length && <p className="text-xs text-slate-500">Tidak ada temuan kritikal.</p>}
          </div>
          {result?.recommendations && (
            <div className="glass-panel space-y-2 p-6 text-xs text-slate-400">
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

export default TlsInspector;
