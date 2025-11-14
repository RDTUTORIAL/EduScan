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
      <div className="flex min-h-screen bg-slate-100 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
        <Sidebar routes={NAV_ITEMS} mobileOpen={mobileOpen} onToggle={() => setMobileOpen((prev) => !prev)} />
        <div className="flex min-h-screen flex-1 flex-col bg-gradient-to-b from-slate-950 via-slate-950 to-slate-900 px-6 pb-6 pt-6 md:ml-72">
          <main className="flex-1 overflow-x-hidden">
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
