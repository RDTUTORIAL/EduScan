import { useCallback, useEffect, useMemo, useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import {
  LayoutDashboard,
  Server,
  ShieldAlert,
  Code2,
  ListChecks,
  FolderGit2,
  SatelliteDish,
  KeyRound,
  History as HistoryIcon,
  Settings as SettingsIcon,
  MessageCircle,
  Menu,
  Sun,
  Moon,
} from 'lucide-react';
import Sidebar from './components/Sidebar';
import BottomBar from './components/BottomBar';
import HomeDashboard from './pages/HomeDashboard';
import PortScanner from './pages/PortScanner';
import SqlScanner from './pages/SqlScanner';
import XssScanner from './pages/XssScanner';
import HeaderAnalyzer from './pages/HeaderAnalyzer';
import DirectoryBuster from './pages/DirectoryBuster';
import OsintHub from './pages/OsintHub';
import CredentialAudit from './pages/CredentialAudit';
import HistoryCenter from './pages/HistoryCenter';
import Settings from './pages/Settings';
import Contact from './pages/Contact';
import { ScanContext } from './context/ScanContext';
import { exportToJson } from './utils/exportHelpers';
import { 
  fetchHistory, 
  addHistoryEntry, 
  deleteHistoryEntry, 
  clearAllHistory 
} from './utils/apiClient';

const NAV_ITEMS = [
  { id: 'home', label: 'Home', path: '/', icon: LayoutDashboard },
  { id: 'port', label: 'Port Scanner', path: '/port-scanner', icon: Server },
  { id: 'sqli', label: 'SQLi Scanner', path: '/sqli-scanner', icon: ShieldAlert },
  { id: 'xss', label: 'XSS Scanner', path: '/xss-scanner', icon: Code2 },
  { id: 'headers', label: 'Header Analyzer', path: '/header-analyzer', icon: ListChecks },
  { id: 'dirb', label: 'Directory Buster', path: '/directory-buster', icon: FolderGit2 },
  { id: 'osint', label: 'OSINT Hub', path: '/osint-hub', icon: SatelliteDish },
  { id: 'cred', label: 'Credential Audit', path: '/credential-audit', icon: KeyRound },
  { id: 'history', label: 'Scan History', path: '/scan-history', icon: HistoryIcon },
  { id: 'contact', label: 'Contact', path: '/contact', icon: MessageCircle },
  { id: 'settings', label: 'Settings', path: '/settings', icon: SettingsIcon },
];

const App = () => {
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem('eduscan_theme') !== 'light');
  const [history, setHistory] = useState(() => {
    const cached = localStorage.getItem('eduscan_history');
    return cached ? JSON.parse(cached) : [];
  });
  const [status, setStatus] = useState('Ready');
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('eduscan_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('eduscan_theme', 'light');
    }
  }, [darkMode]);

  useEffect(() => {
    localStorage.setItem('eduscan_history', JSON.stringify(history));
  }, [history]);

  useEffect(() => {
    if (history.length) return;
    let active = true;
    
    // Load history from new API with pagination
    fetchHistory(1, 10)
      .then((response) => {
        if (!active || !response?.items?.length) return;
        const normalized = response.items.map((item) => ({ result: null, ...item }));
        setHistory(normalized);
      })
      .catch(() => null);
      
    return () => {
      active = false;
    };
  }, [history.length]);

  const handleClearHistory = useCallback(() => setHistory([]), []);

  const providerValue = useMemo(
    () => ({
      history,
      addHistoryEntry: async (entry) => {
        try {
          // Add to server first
          await addHistoryEntry(entry);
          // Then update local state
          setHistory((prev) => {
            const next = [entry, ...prev];
            return next.slice(0, 25);
          });
        } catch (error) {
          console.error('Failed to add history entry:', error);
          // Still add locally as fallback
          setHistory((prev) => {
            const next = [entry, ...prev];
            return next.slice(0, 25);
          });
        }
      },
      removeHistoryEntry: async (id) => {
        try {
          await deleteHistoryEntry(id);
          setHistory((prev) => prev.filter((item) => item.id !== id));
        } catch (error) {
          console.error('Failed to delete history entry:', error);
          // Still remove locally as fallback
          setHistory((prev) => prev.filter((item) => item.id !== id));
        }
      },
      clearHistory: async () => {
        try {
          await clearAllHistory();
          setHistory([]);
        } catch (error) {
          console.error('Failed to clear history:', error);
          // Still clear locally as fallback
          setHistory([]);
        }
      },
      reloadHistoryEntry: (entry) => setStatus(`Reloaded ${entry.tool}`),
      status,
      setStatus,
    }),
    [history, status],
  );

  const toggleTheme = () => setDarkMode((prev) => !prev);
  const exportHistory = () => exportToJson(history, 'eduscan-history.json');

  const routesWithComponents = [
    { path: '/', element: <HomeDashboard routes={NAV_ITEMS} /> },
    { path: '/port-scanner', element: <PortScanner /> },
    { path: '/sqli-scanner', element: <SqlScanner /> },
    { path: '/xss-scanner', element: <XssScanner /> },
    { path: '/header-analyzer', element: <HeaderAnalyzer /> },
    { path: '/directory-buster', element: <DirectoryBuster /> },
    { path: '/osint-hub', element: <OsintHub /> },
    { path: '/credential-audit', element: <CredentialAudit /> },
    { path: '/scan-history', element: <HistoryCenter /> },
    {
      path: '/settings',
      element: <Settings darkMode={darkMode} onToggleTheme={toggleTheme} onClearHistory={handleClearHistory} />,
    },
    { path: '/contact', element: <Contact /> },
    { path: '*', element: <HomeDashboard routes={NAV_ITEMS} /> },
  ];

  return (
    <ScanContext.Provider value={providerValue}>
      <div className="flex min-h-screen overflow-x-hidden bg-slate-100 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
        <Sidebar routes={NAV_ITEMS} mobileOpen={mobileOpen} onToggle={() => setMobileOpen((prev) => !prev)} />
        <div className="flex min-h-screen min-w-0 flex-1 flex-col bg-gradient-to-b from-slate-100 via-white to-slate-200 px-4 pb-14 pt-3 text-slate-900 transition-colors duration-300 dark:from-slate-950 dark:via-slate-950 dark:to-slate-900 dark:text-slate-100 sm:px-5 md:ml-72 md:px-6 md:pb-6 md:pt-6">
          <div className="sticky top-0 z-20 mb-4 flex items-center justify-between rounded-2xl border border-slate-800/70 bg-slate-900/85 px-3 py-2.5 shadow-xl shadow-black/30 backdrop-blur md:hidden">
            <div className="flex items-center gap-2.5">
              <button
                type="button"
                className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-800/80 bg-slate-900/70 text-slate-200 shadow-lg shadow-black/20"
                onClick={() => setMobileOpen((prev) => !prev)}
                aria-label="Open navigation"
              >
                <Menu className="h-4.5 w-4.5" />
              </button>
              <div className="leading-tight">
                <p className="text-[10px] uppercase tracking-[0.28em] text-slate-500">EduScan</p>
                <p className="text-[13px] font-semibold text-white">Cyber Range</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="hidden"
                onClick={toggleTheme}
                aria-label="Toggle dark mode"
              >
                {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </button>
              <span className="rounded-full border border-slate-800/60 bg-slate-900/60 px-2.5 py-1 text-[10px] font-semibold text-slate-400">
                {status}
              </span>
            </div>
          </div>
          <main className="flex-1 min-w-0 overflow-x-hidden">
            <Routes>
              {routesWithComponents.map((route) => (
                <Route key={route.path} path={route.path} element={route.element} />
              ))}
            </Routes>
          </main>
          <BottomBar
            status={status}
            darkMode={darkMode}
            onToggleTheme={toggleTheme}
            onExportHistory={exportHistory}
          />
          <footer className="mt-6 text-center text-xs text-slate-500">
            EduScan adalah tool edukasi. Jangan gunakan pada sistem tanpa izin. Pelajari etika hacking.
          </footer>
        </div>
      </div>
    </ScanContext.Provider>
  );
};

export default App;
