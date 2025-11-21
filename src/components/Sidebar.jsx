import { NavLink } from 'react-router-dom';
import { Shield } from 'lucide-react';
import PropTypes from 'prop-types';

const Sidebar = ({ routes, mobileOpen, onToggle }) => (
  <>
    {mobileOpen && (
      <div
        className="fixed inset-0 z-20 bg-slate-950/70 backdrop-blur-sm md:hidden"
        onClick={onToggle}
        aria-hidden="true"
      />
    )}
    <aside
      className={`fixed inset-y-0 left-0 z-30 flex w-[min(18rem,86vw)] flex-col border-r border-slate-200 bg-white/95 px-5 pb-8 pt-6 text-slate-900 backdrop-blur-2xl shadow-2xl shadow-black/10 transition-transform duration-300 dark:border-slate-800/80 dark:bg-slate-900/95 dark:text-slate-100 sm:w-72 md:translate-x-0 ${
        mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
      }`}
    >
      <div className="flex items-center gap-3 pb-8">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyan-500/15 text-cyan-600 dark:bg-cyan-500/20 dark:text-cyan-300">
          <Shield className="h-6 w-6" />
        </div>
        <div className="leading-tight">
          <p className="text-[11px] uppercase tracking-[0.3em] text-slate-500 dark:text-slate-400">Cyber Range</p>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">EduScan</h1>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto pr-2">
        {routes.map(({ id, label, path, icon: Icon }) => (
          <NavLink
            key={id}
            to={path}
            className={({ isActive }) =>
              [
                'group flex items-center gap-3 rounded-xl px-3 py-3 text-sm font-semibold transition',
                isActive
                  ? 'bg-cyan-500/15 text-cyan-700 border border-cyan-500/40 shadow-glow dark:bg-cyan-500/20 dark:text-cyan-100'
                  : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-white/5 dark:hover:text-white',
              ].join(' ')
            }
            onClick={() => mobileOpen && onToggle()}
          >
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-white text-cyan-600 transition group-hover:border-cyan-400/60 dark:border-white/10 dark:bg-white/5 dark:text-cyan-200">
              <Icon className="h-4 w-4" />
            </span>
            <span className="truncate">{label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="mt-6 rounded-2xl border border-dashed border-cyan-500/30 bg-cyan-500/5 p-4 text-sm text-slate-700 dark:border-cyan-500/40 dark:bg-cyan-500/10 dark:text-slate-200">
        <p className="font-semibold text-cyan-700 dark:text-cyan-100">Edu tips</p>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Gunakan hasil scan hanya untuk pembelajaran. Pastikan mendapat izin tertulis sebelum menguji sistem nyata.
        </p>
      </div>
    </aside>
  </>
);

Sidebar.propTypes = {
  routes: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
      path: PropTypes.string.isRequired,
      icon: PropTypes.elementType.isRequired,
    }),
  ).isRequired,
  mobileOpen: PropTypes.bool,
  onToggle: PropTypes.func,
};

Sidebar.defaultProps = {
  mobileOpen: false,
  onToggle: () => {},
};

export default Sidebar;
