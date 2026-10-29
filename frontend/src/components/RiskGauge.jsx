import React from 'react';
import { getRiskLevelConfig } from '../utils/formatters';

export default function RiskGauge({ score = 0, riskLevel = 'low', size = 'lg' }) {
  const config = getRiskLevelConfig(riskLevel);
  const clampedScore = Math.max(0, Math.min(100, score));

  return (
    <div className="w-full flex flex-col items-center sm:items-start space-y-3">
      {/* Score Header */}
      <div className="flex items-baseline space-x-3">
        <span className="text-4xl sm:text-5xl font-bold tracking-tight text-white font-mono">
          {clampedScore}
        </span>
        <span className="text-sm text-slate-400 font-mono">/ 100</span>
        <span className={`px-2.5 py-1 rounded-md text-xs font-semibold uppercase tracking-wider border ${config.badgeClass}`}>
          {config.label}
        </span>
      </div>

      {/* Clean horizontal segmented score bar */}
      <div className="w-full max-w-md space-y-1.5">
        <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden flex">
          <div
            className={`h-full transition-all duration-700 rounded-full ${
              clampedScore >= 75 ? 'bg-red-500' :
              clampedScore >= 50 ? 'bg-orange-500' :
              clampedScore >= 25 ? 'bg-amber-400' :
              'bg-emerald-400'
            }`}
            style={{ width: `${Math.max(4, clampedScore)}%` }}
          />
        </div>

        {/* Level markers */}
        <div className="flex justify-between text-[10px] text-slate-400 font-mono">
          <span>0 (Low)</span>
          <span>25 (Moderate)</span>
          <span>50 (High)</span>
          <span>75 (Critical)</span>
          <span>100</span>
        </div>
      </div>
    </div>
  );
}
