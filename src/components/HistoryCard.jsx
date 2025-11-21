import PropTypes from 'prop-types';
import { Clock, ArrowUpRight } from 'lucide-react';

const riskColor = (risk) => {
  if (risk >= 70) return 'text-rose-300 bg-rose-500/10 border border-rose-500/40';
  if (risk >= 40) return 'text-amber-200 bg-amber-500/10 border border-amber-500/40';
  return 'text-emerald-200 bg-emerald-500/10 border border-emerald-500/40';
};

const HistoryCard = ({ entry, onSelect, onDelete, onExport }) => (
  <div className="glass-panel flex flex-col gap-3 p-5 min-w-0">
    <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <p className="text-xs uppercase tracking-[0.3em] text-slate-500">{entry.tool}</p>
        <h4 className="text-base font-semibold text-white break-all sm:text-lg">{entry.target}</h4>
      </div>
      <span className={`self-start rounded-full px-3 py-1 text-xs font-semibold ${riskColor(entry.risk)} shrink-0 sm:self-auto`}>
        Risk {entry.risk}
      </span>
    </div>
    <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
      <span className="inline-flex items-center gap-1">
        <Clock className="h-3.5 w-3.5" />
        {new Date(entry.timestamp).toLocaleString()}
      </span>
      <span className="rounded-full border border-white/10 px-2 py-0.5 tracking-wide text-slate-300">
        {entry.status}
      </span>
    </div>
    <div className="flex flex-wrap gap-3">
      <button type="button" className="btn-primary text-xs w-full sm:w-auto" onClick={() => onSelect(entry)}>
        Reload <ArrowUpRight className="h-3.5 w-3.5" />
      </button>
      <button type="button" className="btn-secondary text-xs w-full sm:w-auto" onClick={() => onExport(entry)}>
        Export JSON
      </button>
      <button
        type="button"
        className="btn-secondary text-xs border border-rose-400/40 text-rose-200 hover:text-rose-100 w-full sm:w-auto"
        onClick={() => onDelete(entry)}
      >
        Delete
      </button>
    </div>
  </div>
);

HistoryCard.propTypes = {
  entry: PropTypes.shape({
    id: PropTypes.string.isRequired,
    tool: PropTypes.string.isRequired,
    target: PropTypes.string.isRequired,
    risk: PropTypes.number.isRequired,
    timestamp: PropTypes.string.isRequired,
    status: PropTypes.string,
    result: PropTypes.object,
  }).isRequired,
  onSelect: PropTypes.func,
  onDelete: PropTypes.func,
  onExport: PropTypes.func,
};

HistoryCard.defaultProps = {
  onSelect: () => {},
  onDelete: () => {},
  onExport: () => {},
};

export default HistoryCard;
