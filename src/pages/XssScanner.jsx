import { useState } from 'react';
import { motion } from 'framer-motion';
import { TestTube2, Download } from 'lucide-react';
import ScanForm from '../components/ScanForm';
import TerminalOutput from '../components/TerminalOutput';
import RiskChart from '../components/RiskChart';
import ResultsTable from '../components/ResultsTable';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { runXssScan } from '../utils/apiClient';

const uniqueId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

const XssScanner = () => {
  const { addHistoryEntry, setStatus } = useScanContext();
  const [formData, setFormData] = useState({ url: 'https://example.com/search.php?test=1' });
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const pushLog = (message, variant = 'default') =>
    setLogs((prev) => [...prev, { id: uniqueId(), message, variant }]);

  const handleScan = async () => {
    if (!formData.url.trim() || scanning) return;
    setLogs([]);
    setScanning(true);
    setStatus('Scanning...');
    pushLog(`Menjalankan Dalfox + Nuclei ke ${formData.url}`);
    try {
      const payload = await runXssScan({ url: formData.url });
      setResult(payload);
      setStatus('Done');
      pushLog(payload.detection);
      addHistoryEntry({
        id: uniqueId(),
        tool: 'XSS Scanner',
        target: payload.url,
        risk: payload.risk_score,
        timestamp: new Date().toISOString(),
        status: 'Completed',
        result: payload,
      });
    } catch (error) {
      pushLog(error.message || 'Gagal menjalankan XSS scan', 'error');
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

  const formFields = [
    { name: 'url', label: 'Target URL', type: 'text', placeholder: 'https://target.com/search?q=1' },
  ];

  const tableData = (result?.findings || []).map((f, idx) => ({ id: idx, ...f }));

  return (
    <motion.section className="flex flex-col gap-6" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/5 bg-gradient-to-r from-amber-900/40 to-slate-900/60 p-6">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-500">Active Tool</p>
          <h2 className="text-2xl font-semibold text-white">XSS Scanner</h2>
          <p className="text-sm text-slate-400">Kombinasi Dalfox + Nuclei. Tabel hasil seperti SQLi.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-secondary" onClick={handleClear}>
            Clear
          </button>
          <button type="button" className="btn-primary" disabled={!formData.url.trim() || scanning} onClick={handleScan}>
            <TestTube2 className="h-4 w-4" />
            Run Scan
          </button>
          <button
            type="button"
            className="btn-secondary"
            disabled={!result}
            onClick={() => result && exportToJson(result, 'xss-report.json')}
          >
            <Download className="h-4 w-4" />Export JSON
          </button>
        </div>
      </header>

      <ScanForm fields={formFields} formData={formData} onChange={setFormData}>
        <div className="flex flex-wrap gap-3">
          <button type="button" className="btn-primary text-xs" disabled={!formData.url.trim() || scanning} onClick={handleScan}>
            Scan
          </button>
          <button type="button" className="btn-secondary text-xs" onClick={handleClear}>
            Clear
          </button>
        </div>
      </ScanForm>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-3">
          <TerminalOutput logs={logs} status={scanning ? 'Scanning...' : result ? 'Done' : 'Ready'} />
          <ResultsTable
            title="XSS Findings (Dalfox + Nuclei)"
            columns={[
              { key: 'source', label: 'Source' },
              { key: 'severity', label: 'Severity', className: 'capitalize' },
              { key: 'param', label: 'Param' },
              { key: 'method', label: 'Method' },
              { key: 'payload', label: 'Payload', mono: true },
              { key: 'evidence', label: 'Evidence', mono: true },
              { key: 'url', label: 'URL', mono: true },
            ]}
            data={tableData}
            emptyText="Belum ada temuan."
          />
          {result?.recommendation && (
            <div className="glass-panel space-y-2 p-6 text-xs text-slate-400">
              <p className="text-sm font-semibold text-slate-200">Ringkasan</p>
              <p>{result?.detection}</p>
              <p className="font-semibold text-slate-100">Rekomendasi</p>
              <p>{result.recommendation}</p>
            </div>
          )}
        </div>
        <div className="space-y-6 lg:col-span-2">
          <RiskChart score={result?.risk_score ?? 0} label="XSS Risk" />
        </div>
      </div>
    </motion.section>
  );
};

export default XssScanner;
