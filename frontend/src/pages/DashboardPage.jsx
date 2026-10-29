import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, ShieldAlert, AlertTriangle, CheckCircle,
  Search, Trash2, Eye, RefreshCw, Copy, Check, Filter, ArrowRight
} from 'lucide-react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Cell
} from 'recharts';

import { api } from '../services/api';
import StatsCard from '../components/StatsCard';
import QuickScanInput from '../components/QuickScanInput';
import { getRiskLevelConfig, formatDate } from '../utils/formatters';

const RISK_COLORS = {
  low: '#10B981',
  moderate: '#F59E0B',
  high: '#F97316',
  critical: '#EF4444',
};

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRisk, setSelectedRisk] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [copiedId, setCopiedId] = useState(null);

  const fetchDashboardData = async () => {
    setIsLoading(true);
    setError('');
    try {
      const [statsData, historyData] = await Promise.all([
        api.getStats(),
        api.getHistory({ page, limit, search: searchTerm, risk_level: selectedRisk }),
      ]);
      setStats(statsData);
      setHistory(historyData.items || []);
      setTotalRecords(historyData.total || 0);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard data.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, [page, selectedRisk]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchDashboardData();
  };

  const handleDelete = async (scanId) => {
    if (!window.confirm("Delete this scan from history?")) return;
    try {
      await api.deleteScan(scanId);
      await fetchDashboardData();
    } catch (err) {
      alert(`Error deleting scan: ${err.message}`);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const chartData = stats?.risk_distribution ? [
    { name: 'Low Risk', count: stats.risk_distribution.low || 0, fill: RISK_COLORS.low },
    { name: 'Moderate', count: stats.risk_distribution.moderate || 0, fill: RISK_COLORS.moderate },
    { name: 'High', count: stats.risk_distribution.high || 0, fill: RISK_COLORS.high },
    { name: 'Critical', count: stats.risk_distribution.critical || 0, fill: RISK_COLORS.critical },
  ] : [];

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8 space-y-8">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Dashboard</h1>
          <p className="text-xs text-slate-400">Overview of analyzed links and threat distribution.</p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={fetchDashboardData}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>
          <Link
            to="/analyzer"
            className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors"
          >
            New Scan
          </Link>
        </div>
      </div>

      {/* Quick Search */}
      <div className="p-4 rounded-xl panel">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Quick Scan</h2>
        <QuickScanInput />
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatsCard
          title="Total Scans"
          value={stats ? stats.total_scans : '—'}
          subtitle="Stored scan records"
          icon={Activity}
          colorClass="text-cyan-400"
        />
        <StatsCard
          title="Critical Risk"
          value={stats ? stats.critical_risk : '—'}
          subtitle="Score 75–100 or known bad"
          icon={ShieldAlert}
          colorClass="text-red-400"
        />
        <StatsCard
          title="High & Moderate"
          value={stats ? (stats.high_risk + stats.medium_risk) : '—'}
          subtitle="Suspicious anomalies"
          icon={AlertTriangle}
          colorClass="text-amber-400"
        />
        <StatsCard
          title="Low Risk"
          value={stats ? stats.low_risk : '—'}
          subtitle="Clean baseline checks"
          icon={CheckCircle}
          colorClass="text-emerald-400"
        />
      </div>

      {/* Risk Distribution Chart */}
      {stats && stats.total_scans > 0 && (
        <div className="p-5 rounded-xl panel space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Risk Breakdown
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              Average Score: <strong className="text-white">{stats.avg_risk_score}</strong>/100
            </span>
          </div>

          <div className="h-48 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} allowDecimals={false} tickLine={false} />
                <RechartsTooltip
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '0.5rem', fontSize: '11px' }}
                  itemStyle={{ color: '#F3F4F6' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* History Table */}
      <div className="rounded-xl panel overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Scan History ({totalRecords})
            </h3>
          </div>

          <div className="flex items-center space-x-2">
            <form onSubmit={handleSearchSubmit} className="relative">
              <input
                type="text"
                placeholder="Search link or host..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-7 pr-3 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-slate-600 w-44 sm:w-56"
              />
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2 top-2" />
            </form>

            <select
              value={selectedRisk}
              onChange={(e) => {
                setSelectedRisk(e.target.value);
                setPage(1);
              }}
              className="bg-slate-900 border border-slate-800 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
            >
              <option value="">All Tiers</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="moderate">Moderate</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        {/* Table Rows */}
        {isLoading && history.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">Loading scans...</div>
        ) : history.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            {searchTerm || selectedRisk ? "No scans match your search." : "No scans logged yet. Try analyzing a URL."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-900/60 border-b border-slate-800 text-slate-400 font-medium">
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3">Target URL</th>
                  <th className="py-2.5 px-3">Host</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {history.map((item) => {
                  const config = getRiskLevelConfig(item.risk_level);
                  return (
                    <tr key={item.scan_id} className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {formatDate(item.analyzed_at)}
                      </td>
                      <td className="py-2.5 px-3 max-w-xs truncate font-mono text-slate-200">
                        {item.submitted_url}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-400 truncate max-w-[140px]">
                        {item.hostname}
                      </td>
                      <td className="py-2.5 px-3 font-mono">
                        <span className="font-semibold text-white">{item.risk_score}</span>
                        <span className="text-slate-400 text-[10px]">/100</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-medium border ${config.badgeClass}`}>
                          {item.risk_level}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end space-x-1.5">
                          <button
                            onClick={() => handleCopy(item.submitted_url, item.scan_id)}
                            title="Copy link"
                            className="p-1 rounded text-slate-400 hover:text-slate-200"
                          >
                            {copiedId === item.scan_id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                          <Link
                            to={`/results/${item.scan_id}`}
                            className="p-1 rounded text-slate-400 hover:text-cyan-400"
                            title="View report"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </Link>
                          <button
                            onClick={() => handleDelete(item.scan_id)}
                            className="p-1 rounded text-slate-400 hover:text-red-400"
                            title="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {totalRecords > limit && (
          <div className="p-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Page {page} of {Math.ceil(totalRecords / limit)}</span>
            <div className="flex items-center space-x-1.5">
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40"
              >
                Previous
              </button>
              <button
                disabled={page >= Math.ceil(totalRecords / limit)}
                onClick={() => setPage(page + 1)}
                className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
