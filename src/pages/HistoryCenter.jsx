import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Trash2, RotateCcw, ChevronLeft, ChevronRight } from 'lucide-react';
import HistoryCard from '../components/HistoryCard';
import { useScanContext } from '../context/ScanContext';
import { exportToJson } from '../utils/exportHelpers';
import { fetchHistory } from '../utils/apiClient';

const HistoryCenter = () => {
  const { removeHistoryEntry, reloadHistoryEntry, clearHistory } = useScanContext();
  const [selected, setSelected] = useState(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [historyData, setHistoryData] = useState({ items: [], pagination: {} });
  const [loading, setLoading] = useState(false);

  const loadHistory = async (page = 1) => {
    setLoading(true);
    try {
      const data = await fetchHistory(page, 5); // 5 items per page
      setHistoryData(data);
      setCurrentPage(page);
    } catch (error) {
      console.error('Failed to load history:', error);
      setHistoryData({ items: [], pagination: {} });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory(1);
  }, []);

  useEffect(() => {
    if (!historyData.items.length) {
      setSelected(null);
    }
  }, [historyData.items]);

  return (
    <motion.section className="flex flex-col gap-6 min-w-0" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <header className="rounded-2xl border border-white/5 bg-gradient-to-r from-slate-900/60 to-slate-900/30 p-5 sm:p-6">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-[11px] uppercase tracking-[0.35em] text-slate-500">EduScan</p>
            <h2 className="text-xl font-semibold text-white sm:text-2xl">Scan History</h2>
            <p className="text-[11px] text-slate-500">
              {loading ? 'Loading...' : `Total ${historyData.pagination.total || 0} records`}
            </p>
          </div>
          <button
            type="button"
            className="btn-secondary text-xs w-full sm:w-auto"
            onClick={() => loadHistory(currentPage)}
            disabled={loading}
          >
            <RotateCcw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </header>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-5 min-w-0">
        <div className="space-y-4 lg:col-span-3 min-w-0">
          {historyData.items.length === 0 && !loading && (
            <p className="text-slate-500">Belum ada history. Jalankan salah satu tool.</p>
          )}
          {loading && (
            <div className="flex items-center justify-center p-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
            </div>
          )}
          {historyData.items.map((entry) => (
            <HistoryCard
              key={entry.id}
              entry={entry}
              onSelect={(item) => {
                setSelected(item);
                setShowDetailModal(window.innerWidth < 768);
                reloadHistoryEntry(item);
              }}
              onDelete={async () => {
                await removeHistoryEntry(entry.id);
                await loadHistory(currentPage); // Refresh current page
              }}
              onExport={() => exportToJson(entry, `${entry.tool.toLowerCase().replace(/\s+/g, '-')}-${entry.id}.json`)}
            />
          ))}
          
          {/* Pagination Controls */}
          {historyData.pagination.total_pages > 1 && (
            <div className="mt-6 flex flex-col gap-3 rounded-xl bg-slate-800/50 p-4 sm:flex-row sm:items-center sm:justify-between">
              <button
                type="button"
                className="btn-secondary text-xs flex items-center justify-center gap-2 w-full sm:w-auto"
                onClick={() => loadHistory(currentPage - 1)}
                disabled={!historyData.pagination.has_prev || loading}
              >
                <ChevronLeft className="h-4 w-4" />
                Previous
              </button>
              
              <div className="flex flex-wrap items-center justify-center gap-2 text-sm text-slate-400">
                <span>Page {currentPage} of {historyData.pagination.total_pages}</span>
                <span>•</span>
                <span>{historyData.pagination.per_page} per page</span>
              </div>
              
              <button
                type="button"
                className="btn-secondary text-xs flex items-center justify-center gap-2 w-full sm:w-auto"
                onClick={() => loadHistory(currentPage + 1)}
                disabled={!historyData.pagination.has_next || loading}
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
        <div className="space-y-4 lg:col-span-2 min-w-0">
          <div className="glass-panel space-y-3 p-5 sm:p-6">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-slate-200">Detail</p>
              {selected && (
                <button
                  type="button"
                  className="rounded-lg border border-white/10 px-3 py-1 text-[11px] text-slate-300 hover:border-cyan-400/40"
                  onClick={() => setShowDetailModal(true)}
                >
                  Buka popup
                </button>
              )}
            </div>
            {!selected && <p className="text-sm text-slate-500">Klik entry untuk memuat detail.</p>}
            {selected && (
              <>
                <div className="rounded-xl border border-white/5 bg-white/5 p-4 text-sm text-slate-300">
                  <p className="text-xs uppercase text-slate-500">Tool</p>
                  <p className="text-base font-semibold text-white break-words">{selected.tool}</p>
                  <p className="text-[11px] text-slate-500 break-words">{new Date(selected.timestamp).toLocaleString()}</p>
                  {selected.target && (
                    <p className="text-[11px] text-slate-400 break-all">Target: {selected.target}</p>
                  )}
                </div>
                <pre className="rounded-xl border border-slate-800/60 bg-black/70 p-4 text-xs text-emerald-100 overflow-auto">
                  {JSON.stringify(selected.result, null, 2)}
                </pre>
              </>
            )}
          </div>
          <button
            type="button"
            className="btn-secondary flex w-full items-center justify-center text-xs text-rose-200 hover:text-rose-100"
            onClick={clearHistory}
            disabled={!historyData.items.length}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Hapus Semua
          </button>
        </div>
      </div>

      {/* Mobile detail popup */}
      {showDetailModal && selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-3 backdrop-blur-sm">
          <div className="w-full max-h-[85vh] overflow-y-auto rounded-2xl bg-slate-900 p-4 sm:w-[520px] sm:p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Detail</p>
                <p className="text-base font-semibold text-white break-words">{selected.tool}</p>
              </div>
              <button
                type="button"
                className="rounded-lg border border-white/10 px-3 py-1 text-[11px] text-slate-300 hover:border-cyan-400/40"
                onClick={() => setShowDetailModal(false)}
              >
                Tutup
              </button>
            </div>
            <p className="mt-1 text-[11px] text-slate-500">{new Date(selected.timestamp).toLocaleString()}</p>
            {selected.target && (
              <p className="text-[11px] text-slate-400 break-all">Target: {selected.target}</p>
            )}
            <pre className="mt-3 max-h-[60vh] overflow-y-auto rounded-xl border border-slate-800/60 bg-black/70 p-4 text-xs text-emerald-100">
              {JSON.stringify(selected.result, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </motion.section>
  );
};

export default HistoryCenter;
