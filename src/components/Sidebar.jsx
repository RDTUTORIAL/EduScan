import { NavLink } from 'react-router-dom';
import { Shield, Menu, X } from 'lucide-react';
import PropTypes from 'prop-types';

const Sidebar = ({ routes, mobileOpen, onToggle }) => (
  <>
    <aside
      className={`fixed inset-y-0 left-0 z-30 flex w-72 transform flex-col border-r border-slate-800/80 bg-slate-900/95 px-5 pb-8 pt-6 backdrop-blur-2xl shadow-2xl shadow-black/40 transition-transform duration-300 md:translate-x-0 ${
        mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
      }`}
    >
      <div className="flex items-center gap-3 pb-8">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyan-500/20 text-cyan-300">
          <Shield className="h-6 w-6" />
        </div>
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Cyber Range</p>
          <h1 className="text-xl font-semibold text-white">EduScan</h1>
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
                  ? 'bg-cyan-500/20 text-cyan-100 shadow-glow border border-cyan-500/40'
                  : 'text-slate-300 hover:bg-white/5 hover:text-white',
              ].join(' ')
            }
            onClick={() => mobileOpen && onToggle()}
          >
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-cyan-200 transition group-hover:border-cyan-400/40">
              <Icon className="h-4 w-4" />
            </span>
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="mt-6 rounded-2xl border border-dashed border-cyan-500/40 bg-cyan-500/10 p-4 text-sm text-slate-200">
        <p className="font-semibold text-cyan-100">Edu tips</p>
        <p className="text-xs text-slate-400">
          Gunakan hasil scan hanya untuk pembelajaran. Pastikan mendapat izin tertulis sebelum menguji sistem nyata.
        </p>
      </div>
    </aside>
    <button
      type="button"
      className="fixed bottom-6 left-6 z-40 inline-flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/90 text-slate-950 shadow-2xl shadow-cyan-500/40 transition hover:bg-cyan-400 md:hidden"
      onClick={onToggle}
      aria-label="Toggle navigation"
    >
      {mobileOpen ? <X /> : <Menu />}
    </button>
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
