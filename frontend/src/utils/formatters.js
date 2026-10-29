export function getRiskLevelConfig(level) {
  switch ((level || '').toLowerCase()) {
    case 'critical':
      return {
        label: 'Critical Observed Risk',
        badgeClass: 'bg-red-500/10 text-red-400 border-red-500/30',
        color: '#EF4444',
        borderGlow: 'shadow-[0_0_20px_rgba(239,68,68,0.25)]',
        accentBg: 'bg-red-500',
        textColor: 'text-red-400',
        description: 'Severe malicious signals detected. Immediate avoidance advised.',
      };
    case 'high':
      return {
        label: 'High Observed Risk',
        badgeClass: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
        color: '#F97316',
        borderGlow: 'shadow-[0_0_20px_rgba(249,115,22,0.25)]',
        accentBg: 'bg-orange-500',
        textColor: 'text-orange-400',
        description: 'Significant deceptive or suspicious patterns identified.',
      };
    case 'moderate':
      return {
        label: 'Moderate Observed Risk',
        badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
        color: '#F59E0B',
        borderGlow: 'shadow-[0_0_20px_rgba(245,158,11,0.25)]',
        accentBg: 'bg-amber-500',
        textColor: 'text-amber-400',
        description: 'Anomalies present. Proceed with verified caution.',
      };
    case 'low':
    default:
      return {
        label: 'Low Observed Risk',
        badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
        color: '#10B981',
        borderGlow: 'shadow-[0_0_20px_rgba(16,185,129,0.25)]',
        accentBg: 'bg-emerald-500',
        textColor: 'text-emerald-400',
        description: 'No known suspicious indicators detected during scan.',
      };
  }
}

export function getSeverityConfig(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return { badge: 'bg-red-500/20 text-red-300 border-red-500/40', text: 'text-red-400' };
    case 'high':
      return { badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40', text: 'text-orange-400' };
    case 'medium':
      return { badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40', text: 'text-amber-400' };
    case 'low':
      return { badge: 'bg-sky-500/20 text-sky-300 border-sky-500/40', text: 'text-sky-400' };
    case 'info':
    default:
      return { badge: 'bg-slate-700/40 text-slate-400 border-slate-600/40', text: 'text-slate-400' };
  }
}

export function formatDate(isoString) {
  if (!isoString) return 'Just now';
  try {
    const d = new Date(isoString);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return isoString;
  }
}

export function truncateString(str, max = 50) {
  if (!str) return '';
  return str.length > max ? `${str.slice(0, max)}...` : str;
}
