import PropTypes from 'prop-types';

const baseInputClasses =
  'w-full rounded-xl border border-slate-800/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 dark:bg-slate-900/60 dark:text-slate-100';

const ScanForm = ({ fields, formData, onChange, children }) => {
  const handleChange = (field, value) => {
    onChange({ ...formData, [field]: value });
  };

  const renderField = (field) => {
    const { name, label, type, placeholder, options, rows, helper } = field;
    const value = formData[name] ?? '';

    if (type === 'select') {
      return (
        <label key={name} className="flex flex-col gap-2 text-sm font-semibold text-slate-300">
          {label}
          <select
            className={`${baseInputClasses} appearance-none`}
            value={value}
            onChange={(event) => handleChange(name, event.target.value)}
          >
            {options?.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          {helper && <span className="text-xs font-normal text-slate-500">{helper}</span>}
        </label>
      );
    }

    if (type === 'textarea') {
      return (
        <label key={name} className="flex flex-col gap-2 text-sm font-semibold text-slate-300">
          {label}
          <textarea
            className={`${baseInputClasses} resize-none`}
            placeholder={placeholder}
            value={value}
            rows={rows || 4}
            onChange={(event) => handleChange(name, event.target.value)}
          />
          {helper && <span className="text-xs font-normal text-slate-500">{helper}</span>}
        </label>
      );
    }

    if (type === 'checkbox') {
      return (
        <label
          key={name}
          className="flex items-center gap-3 rounded-xl border border-slate-800/70 bg-slate-900/40 px-4 py-3 text-sm text-slate-300"
        >
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={(event) => handleChange(name, event.target.checked)}
            className="h-4 w-4 accent-cyan-500"
          />
          <span>{label}</span>
        </label>
      );
    }

    return (
      <label key={name} className="flex flex-col gap-2 text-sm font-semibold text-slate-300">
        {label}
        <input
          type={type}
          className={baseInputClasses}
          placeholder={placeholder}
          value={value}
          onChange={(event) => handleChange(name, event.target.value)}
        />
        {helper && <span className="text-xs font-normal text-slate-500">{helper}</span>}
      </label>
    );
  };

  return (
    <div className="glass-panel space-y-5 p-6">
      <div className="grid gap-5 md:grid-cols-2">{fields.map(renderField)}</div>
      {children}
    </div>
  );
};

ScanForm.propTypes = {
  fields: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
      type: PropTypes.string,
      placeholder: PropTypes.string,
      options: PropTypes.arrayOf(
        PropTypes.shape({
          value: PropTypes.string.isRequired,
          label: PropTypes.string.isRequired,
        }),
      ),
    }),
  ).isRequired,
  formData: PropTypes.object.isRequired,
  onChange: PropTypes.func.isRequired,
  children: PropTypes.node,
};

ScanForm.defaultProps = {
  children: null,
};

export default ScanForm;
