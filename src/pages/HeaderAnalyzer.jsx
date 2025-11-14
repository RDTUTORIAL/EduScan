import { useState } from 'react';
import { motion } from 'framer-motion';
import { Network, Download } from 'lucide-react';
import ScanForm from '../components/ScanForm';
import ResultsTable from '../components/ResultsTable';
import RiskChart from '../components/RiskChart';
import TerminalOutput from '../components/TerminalOutput';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { runHeaderScan } from '../utils/apiClient';

const uniqueId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

const HeaderAnalyzer = () => {
  const { addHistoryEntry, setStatus } = useScanContext();
  const [formData, setFormData] = useState({ url: '' });
  const [result, setResult] = useState(null);
  const [logs, setLogs] = useState([]);
  const [scanning, setScanning] = useState(false);

  const pushLog = (message, variant = 'default') => setLogs((prev) => [...prev, { id: uniqueId(), message, variant }]);
  const isValid = formData.url.trim().length > 3;

  const handleScan = async () => {
    if (!isValid || scanning) return;
    setScanning(true);
    setStatus('Scanning...');
    setLogs([]);
    pushLog('Fetch header via HEAD request');
    setTimeout(() => pushLog('Evaluating CSP, HSTS, X-Frame-Options, nmap NSE...'), 800);
    try {
      const payload = await runHeaderScan(formData.url);
      setResult(payload);
      setStatus('Done');
      pushLog('Finished analyzing response headers');
      addHistoryEntry({
        id: uniqueId(),
        tool: 'Header Analyzer',
        target: payload.url,
        risk: payload.risk_score,
        timestamp: new Date().toISOString(),
        status: 'Completed',
        result: payload,
      });
    } catch (error) {
      pushLog(error.message || 'Gagal menganalisis header', 'error');
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

  const columns = [
    { key: 'name', label: 'Header' },
    { key: 'status', label: 'Status' },
    { key: 'score', label: 'Score' },
    { key: 'value', label: 'Value' },
  ];

  return (
    <motion.section className="flex flex-col gap-6" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/5 bg-gradient-to-r from-cyan-900/40 to-slate-900/60 p-6">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-500">Active Tool</p>
          <h2 className="text-2xl font-semibold text-white">Header Analyzer</h2>
          <p className="text-sm text-slate-400">Evaluasi CSP, HSTS, referrer, dan header keamanan lainnya.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-secondary" onClick={handleClear}>
            Clear
          </button>
          <button type="button" className="btn-primary" disabled={!isValid || scanning} onClick={handleScan}>
            <Network className="h-4 w-4" />
            Start Scan
          </button>
        </div>
      </header>

      <ScanForm
        fields={[{ name: 'url', label: 'Target URL', type: 'text', placeholder: 'https://example.com' }]}
        formData={formData}
        onChange={setFormData}
      >
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
            onClick={() => result && exportToJson(result, 'headers-report.json')}
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
            title="Security Headers Analysis"
            columns={columns}
            data={
              result?.headers?.map((header) => ({
                ...header,
                status: (
                  <span
                    className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs ${
                      header.status?.includes('Missing')
                        ? 'bg-rose-500/10 text-rose-200'
                        : header.severity === 'critical'
                        ? 'bg-rose-500/10 text-rose-200'
                        : header.severity === 'weak' || header.status?.includes('Partial')
                        ? 'bg-amber-500/10 text-amber-200'
                        : 'bg-emerald-500/10 text-emerald-200'
                    }`}
                  >
                    {header.status?.includes('Missing') && <span className="h-1.5 w-1.5 bg-rose-400 rounded-full" />}
                    {header.severity === 'critical' && <span className="h-1.5 w-1.5 bg-rose-400 rounded-full" />}
                    {header.severity === 'weak' && <span className="h-1.5 w-1.5 bg-amber-400 rounded-full" />}
                    {header.severity === 'good' && <span className="h-1.5 w-1.5 bg-emerald-400 rounded-full" />}
                    {header.status}
                  </span>
                ),
                score: (
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">
                      {Math.round(header.score || 0)}/{header.weight || 0}
                    </span>
                    <div className="w-12 bg-slate-700 rounded-full overflow-hidden">
                      <div 
                        className={`h-1 ${header.severity === 'good' ? 'bg-emerald-400' : header.severity === 'weak' ? 'bg-amber-400' : 'bg-rose-400'}`}
                        style={{ width: `${((header.score || 0) / Math.max(header.weight || 1, 1)) * 100}%` }}
                      />
                    </div>
                  </div>
                ),
                value: header.value && header.value.length > 0 ? (
                  <span className="text-xs text-slate-400 font-mono truncate max-w-xs" title={header.value}>
                    {header.value}
                  </span>
                ) : (
                  <span className="text-xs text-slate-500">-</span>
                )
              })) || []
            }
            emptyText="Belum ada header dianalisis."
          />
        </div>
        <div className="space-y-6 lg:col-span-2">
          <RiskChart score={result?.risk_score || 0} label="Security Risk" />
          
          {/* Security Level Indicator */}
          {result && (
            <div className="glass-panel p-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">Security Level</span>
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                    result.security_level === 'Excellent' ? 'bg-emerald-500/20 text-emerald-300' :
                    result.security_level === 'Low Risk' ? 'bg-green-500/20 text-green-300' :
                    result.security_level === 'Medium Risk' ? 'bg-amber-500/20 text-amber-300' :
                    result.security_level === 'High Risk' ? 'bg-orange-500/20 text-orange-300' :
                    'bg-rose-500/20 text-rose-300'
                  }`}>
                    {result.security_level}
                  </span>
                </div>
                
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Coverage</span>
                  <span className="text-slate-200">{result.coverage}/{result.headers?.length || 0} headers</span>
                </div>
                
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Critical Headers</span>
                  <span className="text-slate-200">{result.critical_coverage}</span>
                </div>
                
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Security Score</span>
                  <span className="text-slate-200">{result.total_score}/{result.max_score}</span>
                </div>
                
                {result.nmap_enabled && (
                  <div className="flex items-center gap-2 text-xs text-emerald-400 bg-emerald-500/10 rounded-full px-3 py-1">
                    <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></div>
                    nmap NSE enhanced
                  </div>
                )}
              </div>
            </div>
          )}
          
          {/* Insights Panel */}
          <div className="glass-panel space-y-3 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">Analysis Insights</p>
            <p>
              {result?.tool_note || 'Run a header scan to get security analysis and recommendations.'}
            </p>
            {result?.recommendations?.slice(0, 3).map((rec, idx) => (
              <p key={idx} className="text-xs text-slate-400">• {rec}</p>
            ))}
          </div>
          
          {/* Logs Panel */}
          {result?.logs && result.logs.length > 0 && (
            <div className="glass-panel p-6">
              <p className="font-semibold text-slate-100 mb-3 text-sm">Scan Logs</p>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {result.logs.slice(-5).map((log, idx) => (
                  <p key={idx} className="text-xs text-slate-400 font-mono">{log}</p>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </motion.section>
  );
};

export default HeaderAnalyzer;
