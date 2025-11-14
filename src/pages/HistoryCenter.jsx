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
    <motion.section className="flex flex-col gap-6" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <header className="rounded-2xl border border-white/5 bg-gradient-to-r from-slate-900/60 to-slate-900/30 p-6">
        <p className="text-xs uppercase tracking-[0.4em] text-slate-500">EduScan</p>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-2xl font-semibold text-white">Scan History</h2>
          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
            <span>
              {loading ? 'Loading...' : `Total ${historyData.pagination.total || 0} records`}
            </span>
            <button
              type="button"
              className="btn-secondary text-xs"
              onClick={() => loadHistory(1)}
              disabled={loading}
            >
              <RotateCcw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        </div>
      </header>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-3">
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
            <div className="flex items-center justify-between mt-6 p-4 bg-slate-800/50 rounded-xl">
              <button
                type="button"
                className="btn-secondary text-xs flex items-center gap-2"
                onClick={() => loadHistory(currentPage - 1)}
                disabled={!historyData.pagination.has_prev || loading}
              >
                <ChevronLeft className="h-4 w-4" />
                Previous
              </button>
              
              <div className="flex items-center gap-2 text-sm text-slate-400">
                <span>Page {currentPage} of {historyData.pagination.total_pages}</span>
                <span>•</span>
                <span>{historyData.pagination.per_page} per page</span>
              </div>
              
              <button
                type="button"
                className="btn-secondary text-xs flex items-center gap-2"
                onClick={() => loadHistory(currentPage + 1)}
                disabled={!historyData.pagination.has_next || loading}
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
        <div className="space-y-4 lg:col-span-2">
          <div className="glass-panel space-y-3 p-6">
            <p className="text-sm font-semibold text-slate-200">Detail</p>
            {!selected && <p className="text-sm text-slate-500">Klik entry untuk memuat detail.</p>}
            {selected && (
              <>
                <div className="rounded-xl border border-white/5 bg-white/5 p-4 text-sm text-slate-300">
                  <p className="text-xs uppercase text-slate-500">Tool</p>
                  <p className="text-base font-semibold text-white">{selected.tool}</p>
                  <p className="text-xs text-slate-500">{new Date(selected.timestamp).toLocaleString()}</p>
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
    </motion.section>
  );
};

export default HistoryCenter;
