import PropTypes from 'prop-types';

const baseAlignClass = {
  left: 'text-left',
  center: 'text-center',
  right: 'text-right',
};

const ResultsTable = ({ title, columns, data, emptyText }) => (
  <div className="glass-panel overflow-hidden">
    <div className="flex items-center justify-between border-b border-slate-800/70 px-6 py-4">
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      <span className="text-xs text-slate-500">{data.length} row(s)</span>
    </div>
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-800/80 text-left text-sm">
        <thead className="bg-slate-900/60 text-xs uppercase tracking-wider text-slate-400">
          <tr>
            {columns.map((column) => (
              <th key={column.key} className="px-6 py-3 font-semibold">
                {column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 bg-slate-900/30 text-slate-200">
          {data.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-6 py-4 text-center text-slate-500">
                {emptyText}
              </td>
            </tr>
          )}
          {data.map((row) => (
            <tr key={row.id || row.port || row.payload || row.path}>
              {columns.map((column) => {
                const value = column.render ? column.render(row[column.key], row) : row[column.key];
                const alignClass = baseAlignClass[column.align || 'left'];
                const extraClass = column.className || '';
                const monoClass = column.mono ? 'font-mono text-xs' : '';
                return (
                  <td key={column.key} className={`px-6 py-3 text-slate-300 ${alignClass} ${monoClass} ${extraClass}`}>
                    {value ?? '—'}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

ResultsTable.propTypes = {
  title: PropTypes.string.isRequired,
  columns: PropTypes.arrayOf(
    PropTypes.shape({
      key: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
      align: PropTypes.oneOf(['left', 'center', 'right']),
      className: PropTypes.string,
      mono: PropTypes.bool,
      render: PropTypes.func,
    }),
  ).isRequired,
  data: PropTypes.arrayOf(PropTypes.object),
  emptyText: PropTypes.string,
};

ResultsTable.defaultProps = {
  data: [],
  emptyText: 'Belum ada data.',
};

export default ResultsTable;
