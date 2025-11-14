import PropTypes from 'prop-types';
import { Clock, ArrowUpRight } from 'lucide-react';

const riskColor = (risk) => {
  if (risk >= 70) return 'text-rose-300 bg-rose-500/10 border border-rose-500/40';
  if (risk >= 40) return 'text-amber-200 bg-amber-500/10 border border-amber-500/40';
  return 'text-emerald-200 bg-emerald-500/10 border border-emerald-500/40';
};

const HistoryCard = ({ entry, onSelect, onDelete, onExport }) => (
  <div className="glass-panel flex flex-col gap-3 p-5">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-slate-500">{entry.tool}</p>
        <h4 className="text-lg font-semibold text-white">{entry.target}</h4>
      </div>
      <span className={`rounded-full px-3 py-1 text-xs font-semibold ${riskColor(entry.risk)}`}>
        Risk {entry.risk}
      </span>
    </div>
    <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
      <span className="inline-flex items-center gap-1">
        <Clock className="h-3.5 w-3.5" />
        {new Date(entry.timestamp).toLocaleString()}
      </span>
      <span className="rounded-full border border-white/10 px-2 py-0.5 text-[11px] tracking-wide text-slate-300">
        {entry.status}
      </span>
    </div>
    <div className="flex flex-wrap gap-3">
      <button type="button" className="btn-primary text-xs" onClick={() => onSelect(entry)}>
        Reload <ArrowUpRight className="h-3.5 w-3.5" />
      </button>
      <button type="button" className="btn-secondary text-xs" onClick={() => onExport(entry)}>
        Export JSON
      </button>
      <button
        type="button"
        className="btn-secondary text-xs border border-rose-400/40 text-rose-200 hover:text-rose-100"
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
