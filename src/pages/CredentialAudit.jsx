import { useState } from 'react';
import { motion } from 'framer-motion';
import { KeyRound, Download } from 'lucide-react';
import TerminalOutput from '../components/TerminalOutput';
import RiskChart from '../components/RiskChart';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { runCredentialAudit } from '../utils/apiClient';

const uniqueId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));

const CredentialAudit = () => {
  const { addHistoryEntry, setStatus } = useScanContext();
  const [samples, setSamples] = useState('admin:admin123\nops:P@ssw0rd!\nbackup:backup123\nuser:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\ntest:$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj8xCfHOxJMm\nsecure_user:Kx9#mP2$vL8@nQ5!');
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const pushLog = (message, variant = 'default') =>
    setLogs((prev) => [...prev, { id: uniqueId(), message, variant }]);

  const handleScan = async () => {
    if (!samples.trim() || scanning) return;
    setLogs([]);
    setScanning(true);
    setStatus('Scanning...');
    pushLog('Running password analysis with John the Ripper & Hashcat...');
    try {
      const payload = await runCredentialAudit({ samples: samples.split('\n') });
      setResult(payload);
      setStatus('Done');
      pushLog('Credential audit selesai.');
      addHistoryEntry({
        id: uniqueId(),
        tool: 'Credential Audit',
        target: 'local sample',
        risk: payload.risk_score,
        timestamp: new Date().toISOString(),
        status: 'Completed',
        result: payload,
      });
    } catch (error) {
      pushLog(error.message || 'Gagal menjalankan audit credential', 'error');
      setStatus('Error');
    } finally {
      setScanning(false);
    }
  };

  const handleClear = () => {
    setSamples('');
    setResult(null);
    setLogs([]);
    setStatus('Ready');
  };

  const loadTestScenario = (scenario) => {
    const scenarios = {
      weak: 'admin:admin\nroot:123456\nuser:password\nguest:guest\ntest:qwerty',
      strong: 'admin:Kx9#mP2$vL8@nQ5!\nuser:Zt7&bN4$wM9@xR2!\nops:Qw3#rT8$yU1@pL6!',
      mixed: 'admin:admin123\nops:P@ssw0rd!\nbackup:backup123\nuser:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\ntest:$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj8xCfHOxJMm\nsecure_user:Kx9#mP2$vL8@nQ5!',
      hashes: 'user1:5d41402abc4b2a76b9719d911017c592\nuser2:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d\nuser3:$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj8xCfHOxJMm\nuser4:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntest_user:098f6bcd4621d373cade4e832627b4f6\npassword_user:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
    };
    setSamples(scenarios[scenario] || '');
    setResult(null);
    setLogs([]);
    setStatus('Ready');
  };

  return (
    <motion.section className="flex flex-col gap-6" initial={{ opacity: 0.9, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/5 bg-gradient-to-r from-slate-900/60 to-purple-900/40 p-6">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-500">Credential Suite</p>
          <h2 className="text-2xl font-semibold text-white">Credential Audit</h2>
          <p className="text-sm text-slate-400">Advanced password analysis dengan John the Ripper & Hashcat style detection. Supports hash analysis, entropy calculation, dan weakness detection.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-secondary" onClick={handleClear}>
            Reset
          </button>
          <button type="button" className="btn-primary" disabled={!samples.trim() || scanning} onClick={handleScan}>
            <KeyRound className="h-4 w-4" />
            Audit
          </button>
        </div>
      </header>

      <div className="glass-panel space-y-4 p-6">
        <label className="flex flex-col gap-2 text-sm font-semibold text-slate-300">
          Credential Samples
          <textarea
            className="rounded-2xl border border-slate-800/70 bg-slate-900/60 p-4 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
            rows={6}
            value={samples}
            onChange={(event) => setSamples(event.target.value)}
          />
          <span className="text-xs font-normal text-slate-500">Format username:password atau username:hash per baris. Supports MD5, SHA1, SHA256, NTLM, bcrypt, dll.</span>
        </label>
        <div className="flex flex-wrap gap-3">
          <button type="button" className="btn-primary text-xs" disabled={!samples.trim() || scanning} onClick={handleScan}>
            Scan
          </button>
          <button type="button" className="btn-secondary text-xs" onClick={handleClear}>
            Clear
          </button>
          <button
            type="button"
            className="btn-secondary text-xs"
            disabled={!result}
            onClick={() => result && exportToJson(result, 'credential-audit.json')}
          >
            <Download className="h-4 w-4" />
            Export JSON
          </button>
        </div>
        <div className="flex flex-wrap gap-2 mt-3">
          <span className="text-xs text-slate-400">Test Scenarios:</span>
          <button 
            type="button" 
            className="px-2 py-1 bg-red-900/30 text-red-300 rounded text-xs hover:bg-red-900/50"
            onClick={() => loadTestScenario('weak')}
          >
            Weak Passwords
          </button>
          <button 
            type="button" 
            className="px-2 py-1 bg-green-900/30 text-green-300 rounded text-xs hover:bg-green-900/50"
            onClick={() => loadTestScenario('strong')}
          >
            Strong Passwords
          </button>
          <button 
            type="button" 
            className="px-2 py-1 bg-blue-900/30 text-blue-300 rounded text-xs hover:bg-blue-900/50"
            onClick={() => loadTestScenario('mixed')}
          >
            Mixed Sample
          </button>
          <button 
            type="button" 
            className="px-2 py-1 bg-purple-900/30 text-purple-300 rounded text-xs hover:bg-purple-900/50"
            onClick={() => loadTestScenario('hashes')}
          >
            Hash Analysis
          </button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-3">
          <TerminalOutput logs={logs} status={scanning ? 'Scanning...' : result ? 'Done' : 'Ready'} />
          <div className="glass-panel space-y-3 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">🔥 Weak Passwords ({(result?.weak || []).length})</p>
            {(result?.weak_detailed || []).length ? (
              <div className="space-y-2">
                {result.weak_detailed.map((item, idx) => (
                  <div key={idx} className="border-l-2 border-red-500 pl-3 py-1 bg-red-900/20">
                    <p className="font-mono text-xs">{item.entry}</p>
                    <p className="text-xs text-red-400">
                      Entropy: {item.entropy} bits • JtR estimate: {item.jtr_estimate}
                    </p>
                    <p className="text-xs text-slate-400">
                      Issues: {item.reasons.join(', ') || 'Low entropy'}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500">✅ Tidak ada password lemah terdeteksi.</p>
            )}
          </div>
          
          <div className="glass-panel space-y-3 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">♻️ Reused Credentials ({(result?.reused || []).length})</p>
            {(result?.reused_detailed || []).length ? (
              <div className="space-y-2">
                {result.reused_detailed.map((item, idx) => (
                  <div key={idx} className="border-l-2 border-yellow-500 pl-3 py-1 bg-yellow-900/20">
                    <p className="font-mono text-xs">{item.current}</p>
                    <p className="text-xs text-yellow-400">
                      Also used by: {item.previous} (Hash: {item.password_hash})
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500">✅ Tidak ada reuse terdeteksi.</p>
            )}
          </div>

          {(result?.hash_analysis || []).length > 0 && (
            <div className="glass-panel space-y-3 p-6 text-sm text-slate-300">
              <p className="font-semibold text-slate-100">🔐 Hash Analysis ({result.hash_analysis.length})</p>
              <div className="space-y-2">
                {result.hash_analysis.map((hash, idx) => (
                  <div key={idx} className={`border-l-2 pl-3 py-1 ${
                    hash.crackability === 'high' ? 'border-red-500 bg-red-900/20' :
                    hash.crackability === 'medium' ? 'border-yellow-500 bg-yellow-900/20' :
                    'border-green-500 bg-green-900/20'
                  }`}>
                    <p className="font-mono text-xs">{hash.username}:{hash.hash}</p>
                    <p className="text-xs">
                      <span className={`font-semibold ${
                        hash.crackability === 'high' ? 'text-red-400' :
                        hash.crackability === 'medium' ? 'text-yellow-400' :
                        'text-green-400'
                      }`}>
                        {hash.hash_type}
                      </span>
                      {' • '}
                      <span className="text-slate-400">
                        Crackability: {hash.crackability}
                      </span>
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {(result?.crackable_hashes || []).length > 0 && (
            <div className="glass-panel space-y-3 p-6 text-sm text-slate-300">
              <p className="font-semibold text-slate-100">💀 Crackable Hashes ({result.crackable_hashes.length})</p>
              <div className="space-y-1">
                {result.crackable_hashes.map((hash, idx) => (
                  <p key={idx} className="font-mono text-xs text-red-400 bg-red-900/20 p-2 rounded">
                    {hash}
                  </p>
                ))}
              </div>
            </div>
          )}

          {(result?.jtr_commands || []).length > 0 && (
            <div className="glass-panel space-y-3 p-6 text-sm text-slate-300">
              <p className="font-semibold text-slate-100">🛠️ JtR/Hashcat Commands</p>
              <div className="space-y-2">
                {result.jtr_commands.map((cmd, idx) => (
                  <div key={idx} className="bg-slate-800/50 p-2 rounded font-mono text-xs">
                    <code className="text-cyan-400">{cmd}</code>
                  </div>
                ))}
                {result.hash_analysis?.length > 0 && (
                  <div className="bg-slate-800/50 p-2 rounded font-mono text-xs">
                    <code className="text-purple-400">hashcat -a 0 -m 0 hashfile.txt rockyou.txt</code>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
        <div className="space-y-6 lg:col-span-2">
          <RiskChart score={result?.risk_score ?? 0} label="Credential Risk" />
          
          <div className="glass-panel space-y-3 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">📊 Complexity Statistics</p>
            {result?.complexity_stats ? (
              <div className="space-y-2 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div>Min Length: <span className="text-cyan-400">{result.complexity_stats.min_length === Infinity ? 'N/A' : result.complexity_stats.min_length}</span></div>
                  <div>Max Length: <span className="text-cyan-400">{result.complexity_stats.max_length}</span></div>
                  <div>Avg Length: <span className="text-cyan-400">{result.complexity_stats.avg_length?.toFixed(1) || 'N/A'}</span></div>
                  <div>Avg Entropy: <span className="text-cyan-400">{result.complexity_stats.total_entropy?.toFixed(1) || 'N/A'} bits</span></div>
                </div>
                <div className="mt-3 space-y-1">
                  <div className="flex justify-between">
                    <span>Uppercase:</span>
                    <span className={result.complexity_stats.has_uppercase > 0 ? 'text-green-400' : 'text-red-400'}>
                      {result.complexity_stats.has_uppercase || 0} passwords
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Numbers:</span>
                    <span className={result.complexity_stats.has_numbers > 0 ? 'text-green-400' : 'text-red-400'}>
                      {result.complexity_stats.has_numbers || 0} passwords
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Symbols:</span>
                    <span className={result.complexity_stats.has_symbols > 0 ? 'text-green-400' : 'text-red-400'}>
                      {result.complexity_stats.has_symbols || 0} passwords
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500">Run audit to see statistics</p>
            )}
          </div>

          <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">🔒 Policy Coverage</p>
            <div className="text-xs space-y-2">
              <div className="grid grid-cols-2 gap-2">
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${result?.policy?.uppercase ? 'bg-green-400' : 'bg-red-400'}`}></span>
                  <span>Uppercase</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${result?.policy?.numbers ? 'bg-green-400' : 'bg-red-400'}`}></span>
                  <span>Numbers</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${result?.policy?.symbols ? 'bg-green-400' : 'bg-red-400'}`}></span>
                  <span>Symbols</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${result?.policy?.min_length_8 ? 'bg-green-400' : 'bg-red-400'}`}></span>
                  <span>Min 8 chars</span>
                </div>
              </div>
              {result?.policy?.avg_entropy && (
                <div className="mt-2 p-2 bg-slate-800/50 rounded">
                  <span className="text-slate-400">Average Entropy: </span>
                  <span className={`font-semibold ${
                    result.policy.avg_entropy >= 40 ? 'text-green-400' :
                    result.policy.avg_entropy >= 25 ? 'text-yellow-400' : 'text-red-400'
                  }`}>
                    {result.policy.avg_entropy} bits
                  </span>
                </div>
              )}
            </div>
          </div>

          {result?.tools_used && result.tools_used.length > 0 && (
            <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
              <p className="font-semibold text-slate-100">🔧 Tools Used</p>
              <div className="flex flex-wrap gap-2">
                {result.tools_used.map((tool) => (
                  <span key={tool} className="px-2 py-1 bg-green-900/30 text-green-300 rounded text-xs font-mono">
                    ✓ {tool}
                  </span>
                ))}
              </div>
              {result.tool_results && Object.keys(result.tool_results).length > 0 && (
                <div className="mt-3 space-y-1 text-xs">
                  {Object.entries(result.tool_results).map(([tool, result_data]) => (
                    <div key={tool} className="flex justify-between items-center">
                      <span className="text-slate-400">{tool}:</span>
                      <span className={`font-semibold ${
                        result_data.status === 'completed' ? 'text-green-400' :
                        result_data.status === 'timeout' ? 'text-yellow-400' :
                        result_data.status === 'not_installed' ? 'text-red-400' : 'text-slate-400'
                      }`}>
                        {result_data.status} 
                        {result_data.time_taken && ` (${result_data.time_taken}s)`}
                        {result_data.cracked && ` - ${result_data.cracked.length} cracked`}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {result?.tools_suggested && (
            <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
              <p className="font-semibold text-slate-100">💡 Suggested Tools</p>
              <div className="flex flex-wrap gap-2">
                {result.tools_suggested.map((tool) => (
                  <span key={tool} className="px-2 py-1 bg-purple-900/30 text-purple-300 rounded text-xs font-mono">
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="glass-panel space-y-2 p-6 text-sm text-slate-300">
            <p className="font-semibold text-slate-100">💡 Recommendations</p>
            {result?.recommendations && (
              <div className="text-xs text-slate-400 space-y-1 max-h-40 overflow-y-auto">
                {(result.recommendations.length ? result.recommendations : ['Tambahkan aturan kompleksitas minimal.']).map(
                  (item, idx) => (
                    <p key={idx} className="leading-relaxed">• {item}</p>
                  ),
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </motion.section>
  );
};

export default CredentialAudit;
