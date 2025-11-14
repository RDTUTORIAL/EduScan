import PropTypes from 'prop-types';
import { Moon, Sun, DownloadCloud } from 'lucide-react';

const BottomBar = ({ status, darkMode, onToggleTheme, onExportHistory }) => (
  <div className="mt-6 flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-800/60 bg-slate-900/50 px-6 py-4 text-sm shadow-2xl shadow-black/20 dark:bg-slate-900/80">
    <div className="flex items-center gap-3 text-slate-300">
      <span
        className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${
          status === 'Scanning...'
            ? 'bg-amber-500/10 text-amber-200'
            : status === 'Done'
            ? 'bg-emerald-500/10 text-emerald-200'
            : 'bg-slate-700/40 text-slate-300'
        }`}
      >
        {status}
      </span>
      <p className="text-xs text-slate-500">Status sistem live</p>
    </div>
    <div className="flex flex-wrap items-center gap-3">
      <button type="button" className="btn-secondary text-xs" onClick={onExportHistory}>
        <DownloadCloud className="h-4 w-4" />
        Export All History
      </button>
      <button
        type="button"
        className="btn-primary text-xs"
        onClick={onToggleTheme}
        aria-label="Toggle dark mode"
      >
        {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        {darkMode ? 'Light Mode' : 'Dark Mode'}
      </button>
    </div>
  </div>
);

BottomBar.propTypes = {
  status: PropTypes.string.isRequired,
  darkMode: PropTypes.bool.isRequired,
  onToggleTheme: PropTypes.func.isRequired,
  onExportHistory: PropTypes.func.isRequired,
};

export default BottomBar;
