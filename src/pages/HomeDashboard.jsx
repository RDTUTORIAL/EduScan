import { useMemo, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { Layers3, ShieldCheck, Activity, Clock4, Users, TrendingUp } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis } from 'recharts';
import { useScanContext } from '../context/ScanContext';
import { getUserStats } from '../utils/apiClient';

const HomeDashboard = ({ routes }) => {
  const { history } = useScanContext();
  const [userStats, setUserStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadUserStats = async () => {
      try {
        const stats = await getUserStats();
        setUserStats(stats);
      } catch (error) {
        console.error('Failed to load user stats:', error);
      } finally {
        setLoading(false);
      }
    };

    loadUserStats();
  }, []);

  const stats = useMemo(() => {
    if (userStats) {
      const totalRisk = userStats.recent_scans.reduce((acc, entry) => acc + (entry.risk || 0), 0);
      const highRisk = userStats.recent_scans.filter((entry) => (entry.risk || 0) >= 70).length;
      return {
        totalScans: userStats.total_scans,
        avgRisk: userStats.recent_scans.length ? Math.round(totalRisk / userStats.recent_scans.length) : 0,
        highRisk,
        toolsUsed: userStats.tools_used,
        memberSince: new Date(userStats.created_at).toLocaleDateString(),
      };
    }
    
    // Fallback to local history if server stats not available
    const totalRisk = history.reduce((acc, entry) => acc + entry.risk, 0);
    const highRisk = history.filter((entry) => entry.risk >= 70).length;
    return {
      totalScans: history.length,
      avgRisk: history.length ? Math.round(totalRisk / history.length) : 0,
      highRisk,
      toolsUsed: new Set(history.map(h => h.tool)).size,
      memberSince: 'Today',
    };
  }, [history, userStats]);

  const timeline = useMemo(() => {
    const recentData = userStats ? userStats.recent_scans : history;
    return (recentData || []).slice(0, 6).map((entry) => ({
      name: entry.tool,
      risk: entry.risk || 0,
    }));
  }, [history, userStats]);

  const chartData = useMemo(() => [...timeline].reverse(), [timeline]);

  const quickActions = routes.filter((route) => route.id !== 'home' && route.id !== 'settings').slice(0, 4);

  return (
    <motion.section className="flex flex-col gap-6 min-w-0" initial={{ opacity: 0.7, y: 15 }} animate={{ opacity: 1, y: 0 }}>
      <div className="rounded-3xl border border-white/5 bg-gradient-to-r from-slate-900/60 via-slate-900/20 to-slate-900/70 p-6 shadow-2xl shadow-black/30 md:p-8">
        <p className="text-xs uppercase tracking-[0.4em] text-slate-400">Welcome back</p>
        <div className="mt-3 flex flex-wrap items-start justify-between gap-4 md:items-center">
          <div>
            <h1 className="text-3xl font-semibold text-white">EduScan Threat Lab</h1>
            <p className="text-sm text-slate-400">
              Platform comprehensive dengan integrasi Nuclei, Dalfox, nmap, Hashcat, dan tools security lainnya.
            </p>
          </div>
          <Link to="/port-scanner" className="btn-primary">
            Mulai Port Scan
          </Link>
        </div>
      </div>

      <div className="grid min-w-0 gap-5 md:grid-cols-2 lg:grid-cols-4">
        <div className="glass-panel space-y-2 p-6">
          <p className="text-sm text-slate-400">Total Scans</p>
          <p className="text-3xl font-semibold text-white">{loading ? '...' : stats.totalScans}</p>
          <span className="inline-flex items-center gap-2 text-xs text-slate-500">
            <Layers3 className="h-4 w-4" /> All tools
          </span>
        </div>
        <div className="glass-panel space-y-2 p-6">
          <p className="text-sm text-slate-400">Tools Used</p>
          <p className="text-3xl font-semibold text-white">{loading ? '...' : stats.toolsUsed}</p>
          <span className="inline-flex items-center gap-2 text-xs text-slate-500">
            <TrendingUp className="h-4 w-4" /> Different types
          </span>
        </div>
        <div className="glass-panel space-y-2 p-6">
          <p className="text-sm text-slate-400">Average Risk</p>
          <p className="text-3xl font-semibold text-white">{loading ? '...' : stats.avgRisk}</p>
          <span className="inline-flex items-center gap-2 text-xs text-slate-500">
            <ShieldCheck className="h-4 w-4" /> Lower is better
          </span>
        </div>
        <div className="glass-panel space-y-2 p-6">
          <p className="text-sm text-slate-400">High Risk Findings</p>
          <p className="text-3xl font-semibold text-white">{loading ? '...' : stats.highRisk}</p>
          <span className="inline-flex items-center gap-2 text-xs text-slate-500">
            <Activity className="h-4 w-4" /> &gt; 70 score
          </span>
        </div>
      </div>
      
      {/* User Session Info */}
      <div className="glass-panel p-4 md:p-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="space-y-1">
            <p className="text-sm text-slate-400">Session Information</p>
            <p className="text-base font-semibold text-white">
              {loading ? 'Loading user data...' : `Member since ${stats.memberSince}`}
            </p>
            {userStats && (
              <p className="text-xs text-slate-500">
                Last active: {new Date(userStats.last_active).toLocaleString()}
              </p>
            )}
          </div>
          <div className="inline-flex items-center gap-2 rounded-full bg-emerald-500/10 px-3 py-1.5">
            <Users className="h-4 w-4 text-emerald-400" />
            <span className="text-xs text-emerald-300">
              {userStats ? 'Synced' : 'Local'} Session
            </span>
          </div>
        </div>
      </div>

      <div className="grid min-w-0 gap-6 md:grid-cols-2 lg:grid-cols-5">
        <div className="glass-panel p-6 lg:col-span-3 min-w-0">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-slate-200">Trend Risiko Terakhir</p>
            <span className="text-xs text-slate-500 inline-flex items-center gap-1">
              <Clock4 className="h-4 w-4" />
              Real-time
            </span>
          </div>
          <div className="mt-4 h-36 w-full min-w-0 sm:h-48 md:h-56">
            <ResponsiveContainer minWidth={180} minHeight={140} width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 5, right: 6, left: -10, bottom: 20 }}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="name"
                  stroke="#475569"
                  tickLine={false}
                  axisLine={false}
                  interval={0}
                  tickMargin={10}
                  tick={{ fill: '#94a3b8', fontSize: 10 }}
                  angle={-20}
                  tickFormatter={(value) => (value?.length > 10 ? `${value.slice(0, 10)}…` : value)}
                />
                <YAxis stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 10 }} width={28} />
                <Area type="monotone" dataKey="risk" stroke="#06b6d4" fillOpacity={1} fill="url(#colorRisk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="glass-panel space-y-4 p-6 lg:col-span-2 min-w-0">
          <p className="text-sm font-semibold text-slate-200">Quick Actions</p>
          <div className="grid gap-3 sm:grid-cols-2">
            {quickActions.map((action) => (
              <Link
                key={action.id}
                to={action.path}
                className="flex items-center justify-between rounded-2xl border border-white/5 bg-white/5 p-4 text-sm text-slate-200 transition hover:border-cyan-400/40 hover:text-white"
              >
                <span>{action.label}</span>
                <action.icon className="h-4 w-4 text-cyan-300" />
              </Link>
            ))}
          </div>
        </div>
      </div>
    </motion.section>
  );
};

export default HomeDashboard;
