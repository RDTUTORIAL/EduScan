import PropTypes from 'prop-types';
import { motion } from 'framer-motion';
import { Brush, Database } from 'lucide-react';

const Settings = ({ darkMode, onToggleTheme, onClearHistory }) => (
  <motion.section className="flex flex-col gap-6" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
    <header className="rounded-2xl border border-white/5 bg-gradient-to-r from-slate-900/60 to-slate-900/30 p-6">
      <p className="text-xs uppercase tracking-[0.4em] text-slate-500">EduScan</p>
      <h2 className="text-2xl font-semibold text-white">Settings</h2>
      <p className="text-sm text-slate-400">Atur tema, data retention, dan preferensi lain.</p>
    </header>

    <div className="grid gap-5 md:grid-cols-2">
      <div className="glass-panel space-y-3 p-6">
        <div className="flex items-center gap-3">
          <Brush className="h-5 w-5 text-cyan-300" />
          <div>
            <p className="font-semibold text-white">Tema</p>
            <p className="text-xs text-slate-500">Pilih light / dark mode sesuai preferensi</p>
          </div>
        </div>
        <button type="button" className="btn-primary text-xs" onClick={onToggleTheme}>
          {darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        </button>
      </div>
      <div className="glass-panel space-y-3 p-6">
        <div className="flex items-center gap-3">
          <Database className="h-5 w-5 text-rose-300" />
          <div>
            <p className="font-semibold text-white">Scan History</p>
            <p className="text-xs text-slate-500">Hapus semua riwayat dari localStorage</p>
          </div>
        </div>
        <button type="button" className="btn-secondary text-xs text-rose-200" onClick={onClearHistory}>
          Clear History
        </button>
      </div>
    </div>
  </motion.section>
);

Settings.propTypes = {
  darkMode: PropTypes.bool.isRequired,
  onToggleTheme: PropTypes.func.isRequired,
  onClearHistory: PropTypes.func.isRequired,
};

export default Settings;
