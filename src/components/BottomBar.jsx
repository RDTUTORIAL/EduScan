import PropTypes from 'prop-types';
import { Moon, Sun, DownloadCloud } from 'lucide-react';

const BottomBar = ({ status, darkMode, onToggleTheme, onExportHistory }) => (
  <div className="mt-6 flex flex-col gap-4 rounded-2xl border border-slate-800/60 bg-slate-900/50 px-4 py-4 text-sm shadow-2xl shadow-black/20 dark:bg-slate-900/80 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between sm:px-6">
    <div className="flex items-center gap-3 text-slate-300 sm:w-auto">
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
    <div className="flex flex-wrap items-center gap-3 sm:w-auto">
      <button type="button" className="btn-secondary text-xs w-full sm:w-auto" onClick={onExportHistory}>
        <DownloadCloud className="h-4 w-4" />
        Export All History
      </button>
      <button
        type="button"
        className="hidden"
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
