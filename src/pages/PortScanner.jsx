import { useEffect, useMemo, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { Activity, RefreshCcw } from 'lucide-react';
import { motion } from 'framer-motion';
import ScanForm from '../components/ScanForm';
import TerminalOutput from '../components/TerminalOutput';
import ResultsTable from '../components/ResultsTable';
import RiskChart from '../components/RiskChart';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { runPortScan } from '../utils/apiClient';

const uniqueId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

const PortScanner = () => {
  const { addHistoryEntry, setStatus } = useScanContext();
  const [formData, setFormData] = useState({ target: '', mode: 'common', customPorts: '' });
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState(null);
  const [progress, setProgress] = useState(0);
  const [scanning, setScanning] = useState(false);

  const isValid = formData.target.trim().length > 3;

  useEffect(() => {
    let timer;
    if (scanning && progress < 100) {
      timer = setInterval(() => {
        setProgress((prev) => Math.min(prev + 8, 100));
      }, 380);
    }
    return () => clearInterval(timer);
  }, [scanning, progress]);

  const pushLog = (message, variant = 'default') => {
    setLogs((prev) => [...prev, { id: uniqueId(), message, variant }]);
  };

  const handleScan = async () => {
    if (!isValid || scanning) return;
    setScanning(true);
    setStatus('Scanning...');
    setProgress(5);
    setLogs([]);

    const steps = [
      `Memulai koneksi ke ${formData.target}`,
      'Memuat fingerprint service',
      'Enumerasi port & service version',
      'Menghitung baseline risiko',
      'Scan selesai. Menyusun laporan...',
    ];

    steps.forEach((step, index) => {
      setTimeout(() => pushLog(step), index * 700);
    });

    try {
      const payload = await runPortScan(formData);
      setResults(payload);
      setProgress(100);
      setStatus('Done');
      addHistoryEntry({
        id: uniqueId(),
        tool: 'Port Scanner',
        target: payload.target,
        risk: payload.risk_score,
        timestamp: new Date().toISOString(),
        status: 'Completed',
        result: payload,
      });
    } catch (error) {
      pushLog(error.message || 'Gagal menjalankan port scan', 'error');
      setStatus('Error');
    } finally {
      setScanning(false);
    }
  };

  const handleClear = () => {
    setFormData({ target: '', mode: 'common', customPorts: '' });
    setResults(null);
    setLogs([]);
    setProgress(0);
    setStatus('Ready');
  };

  const chartData = useMemo(() => {
    if (!results) return [];
    return [
      { name: 'Open', value: results.summary.open, color: '#22d3ee' },
      { name: 'Closed', value: results.summary.closed, color: '#475569' },
      { name: 'Filtered', value: results.summary.filtered, color: '#f97316' },
    ];
  }, [results]);

  const formFields = [
    { name: 'target', label: 'Target Host / Domain', type: 'text', placeholder: 'https://example.com' },
    {
      name: 'mode',
      label: 'Mode Scan',
      type: 'select',
      options: [
        { label: 'Common ports (1-1000)', value: 'common' },
        { label: 'Custom ports', value: 'custom' },
      ],
    },
    {
      name: 'customPorts',
      label: 'Custom Ports',
      type: 'text',
      placeholder: '80,443,8080',
      helper: 'Pisahkan dengan koma, contoh: 22,443,3306',
    },
  ];

  return (
    <motion.section
      className="flex flex-col gap-6"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/5 bg-gradient-to-r from-slate-900/70 via-slate-900/40 to-slate-900/70 p-6 shadow-2xl shadow-black/30">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-500">Active Tool</p>
          <h2 className="text-2xl font-semibold text-white">Port Scanner</h2>
          <p className="text-sm text-slate-400">Mirip Nmap dengan visual interaktif & log real-time.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-secondary" onClick={handleClear}>
            <RefreshCcw className="h-4 w-4" />
            Clear
          </button>
          <button type="button" className="btn-primary" disabled={!isValid || scanning} onClick={handleScan}>
            <Activity className="h-4 w-4" />
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
            disabled={!results}
            onClick={() => results && exportToJson(results, 'port-scan.json')}
          >
            Export JSON
          </button>
        </div>
      </ScanForm>

      {scanning && (
        <div className="glass-panel relative overflow-hidden p-5">
          <div className="flex items-center justify-between text-sm text-slate-400">
            <span className="flex items-center gap-2">
              <span className="inline-flex h-3 w-3 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
              Scanning...
            </span>
            <span>{progress}%</span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-800/60">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-emerald-300 transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3 space-y-6">
          <TerminalOutput logs={logs} status={scanning ? 'Scanning...' : results ? 'Done' : 'Ready'} />
          <ResultsTable
            title="Port & Service Mapping"
            columns={[
              { key: 'port', label: 'Port' },
              { key: 'status', label: 'Status' },
              { key: 'service', label: 'Service' },
              { key: 'version', label: 'Version' },
            ]}
            data={results?.table || []}
            emptyText="Belum ada data. Jalankan scan untuk melihat hasil."
          />
        </div>
        <div className="lg:col-span-2 space-y-6">
          <RiskChart score={results?.risk_score || 12} label="Risk Meter" />
          <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">Intel Ring</p>
            {(results?.insights || ['Belum ada insight, jalankan scan terlebih dahulu.']).map((insight) => (
              <p key={insight} className="flex items-start gap-2 text-xs text-slate-400">
                <span className="mt-1 h-1.5 w-1.5 rounded-full bg-cyan-400" />
                {insight}
              </p>
            ))}
          </div>
          {results?.analysis && (
            <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
              <p className="font-semibold text-slate-100">Analisis</p>
              {(results.analysis.length ? results.analysis : ['Belum ada port terbuka.']).map((item) => (
                <p key={item} className="text-xs text-slate-400">
                  {item}
                </p>
              ))}
            </div>
          )}
          {results?.recommendations && (
            <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
              <p className="font-semibold text-slate-100">Rekomendasi</p>
              {(results.recommendations.length ? results.recommendations : ['Tidak ada rekomendasi khusus.']).map(
                (item) => (
                  <p key={item} className="text-xs text-slate-400">
                    {item}
                  </p>
                ),
              )}
            </div>
          )}
          <div className="glass-panel space-y-4 p-6">
            <p className="text-sm font-semibold text-slate-200">Port Status Overview</p>
            <div className="h-48">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={chartData} dataKey="value" innerRadius={50} outerRadius={70} paddingAngle={4}>
                    {chartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-2 text-xs text-slate-400">
              {chartData.map((entry) => (
                <div key={entry.name} className="flex items-center justify-between">
                  <span>{entry.name}</span>
                  <span className="font-semibold text-slate-100">{entry.value}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="glass-panel space-y-2 p-6">
            <p className="text-sm font-semibold text-slate-200">Command Equivalent</p>
            <pre className="rounded-xl border border-slate-800/80 bg-black/70 p-4 font-mono text-xs text-emerald-200">
              {results?.command || 'nmap -sV -p 1-1000 eduscan-demo.local'}
            </pre>
          </div>
        </div>
      </div>
    </motion.section>
  );
};

export default PortScanner;
