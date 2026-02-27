import { useMemo } from 'react';
import { useForensic } from '@/context/ForensicContext';
import { useNavigate } from 'react-router-dom';
import { normalizeMetadata } from '@/lib/metadata-normalizer';
import { analyzePrivacyRisk } from '@/lib/privacy-risk-analyzer';
import { analyzeNetworkOrigin } from '@/lib/network-origin-analyzer';
import { reconstructLifecycle } from '@/lib/lifecycle-analyzer';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
    Shield, AlertTriangle, CheckCircle, XCircle, Upload,
    TrendingUp, Clock, Network, EyeOff, Lock, Fingerprint,
    Hash, ChevronRight, Activity, BarChart3, Info,
} from 'lucide-react';

// ── Scoring constants (mirrored from tampering-detector.ts) ─────────────────
const SEVERITY_POINTS: Record<string, number> = { high: 30, medium: 15, low: 7 };

interface ScoreRow {
    category: string;
    icon: React.ComponentType<{ className?: string }>;
    iconColor: string;
    items: {
        label: string;
        severity: 'high' | 'medium' | 'low' | 'info' | 'clean';
        points: number;
        description: string;
        source: string;
    }[];
    subtotal: number;
    maxPossible: number;
}

// ── Severity config ──────────────────────────────────────────────────────────
const SEV_CONFIG = {
    high: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/25', label: 'HIGH', badge: 'destructive' as const },
    medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/25', label: 'MEDIUM', badge: 'outline' as const },
    low: { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/25', label: 'LOW', badge: 'secondary' as const },
    info: { color: 'text-slate-400', bg: 'bg-slate-800/40', border: 'border-slate-700/50', label: 'INFO', badge: 'secondary' as const },
    clean: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', label: 'CLEAN', badge: 'secondary' as const },
};

// ── Score bar ─────────────────────────────────────────────────────────────────
function ScoreBar({ value, max, color }: { value: number; max: number; color: string }) {
    const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
    return (
        <div className="h-1.5 rounded-full bg-slate-700/60 overflow-hidden">
            <div
                className={`h-full rounded-full transition-all duration-700 ${color}`}
                style={{ width: `${pct}%` }}
            />
        </div>
    );
}

// ── Risk gauge ────────────────────────────────────────────────────────────────
function RiskGauge({ score, level }: { score: number; level: string }) {
    const color = level === 'high' ? '#ef4444' : level === 'medium' ? '#eab308' : '#22c55e';
    const r = 60;
    const circ = 2 * Math.PI * r;
    return (
        <div className="relative flex items-center justify-center w-36 h-36">
            <svg className="absolute inset-0 -rotate-90" width="144" height="144" viewBox="0 0 144 144">
                <circle cx="72" cy="72" r={r} fill="none" stroke="hsl(222,30%,12%)" strokeWidth="10" />
                <circle cx="72" cy="72" r={r} fill="none" stroke={color} strokeWidth="10"
                    strokeLinecap="round"
                    strokeDasharray={`${(score / 100) * circ} ${circ}`}
                    style={{ filter: `drop-shadow(0 0 8px ${color}88)`, transition: 'stroke-dasharray 1.2s ease' }}
                />
            </svg>
            <div className="text-center z-10">
                <p className="text-3xl font-black font-mono tabular-nums" style={{ color }}>{score}</p>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest mt-0.5">/100</p>
            </div>
        </div>
    );
}

// ── Category table ────────────────────────────────────────────────────────────
function CategoryTable({ row }: { row: ScoreRow }) {
    const Icon = row.icon;
    const riskPct = row.maxPossible > 0 ? (row.subtotal / row.maxPossible) * 100 : 0;
    const barColor = riskPct >= 60 ? 'bg-red-500' : riskPct >= 30 ? 'bg-yellow-500' : 'bg-emerald-500';

    return (
        <div className="rounded-2xl border border-slate-700/50 bg-slate-900/60 overflow-hidden">
            {/* Category header */}
            <div className="flex items-center gap-3 px-5 py-3 border-b border-slate-700/40 bg-slate-800/40">
                <div className={`h-8 w-8 rounded-lg bg-slate-800 border border-slate-700/60 flex items-center justify-center shrink-0`}>
                    <Icon className={`h-4 w-4 ${row.iconColor}`} />
                </div>
                <span className="font-semibold text-slate-200 flex-1 text-sm">{row.category}</span>
                <div className="flex items-center gap-3">
                    <div className="w-24 hidden sm:block">
                        <ScoreBar value={row.subtotal} max={row.maxPossible} color={barColor} />
                    </div>
                    <span className={`text-sm font-black font-mono tabular-nums ${riskPct >= 60 ? 'text-red-400' : riskPct >= 30 ? 'text-yellow-400' : 'text-emerald-400'
                        }`}>
                        +{row.subtotal}
                    </span>
                    <span className="text-[10px] text-slate-600 font-mono">/{row.maxPossible}</span>
                </div>
            </div>

            {/* Rows */}
            {row.items.length === 0 ? (
                <div className="flex items-center gap-2 px-5 py-3 text-emerald-400 text-xs">
                    <CheckCircle className="h-3.5 w-3.5" />
                    <span>No issues detected in this category</span>
                </div>
            ) : (
                <table className="w-full text-xs">
                    <thead>
                        <tr className="border-b border-slate-700/30">
                            <th className="text-left px-5 py-2 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Finding</th>
                            <th className="text-center px-3 py-2 text-[10px] text-slate-500 uppercase tracking-wider font-semibold hidden md:table-cell">Severity</th>
                            <th className="text-center px-3 py-2 text-[10px] text-slate-500 uppercase tracking-wider font-semibold hidden sm:table-cell">Source</th>
                            <th className="text-right px-5 py-2 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Points</th>
                        </tr>
                    </thead>
                    <tbody>
                        {row.items.map((item, i) => {
                            const sev = SEV_CONFIG[item.severity];
                            return (
                                <tr key={i} className={`border-b border-slate-700/20 last:border-0 ${sev.bg} hover:bg-slate-800/30 transition-colors`}>
                                    {/* Finding */}
                                    <td className="px-5 py-3">
                                        <p className={`font-semibold ${sev.color} mb-0.5`}>{item.label}</p>
                                        <p className="text-slate-500 text-[11px] leading-snug max-w-md">{item.description}</p>
                                    </td>
                                    {/* Severity */}
                                    <td className="px-3 py-3 text-center hidden md:table-cell">
                                        <Badge variant={sev.badge} className={`text-[9px] px-1.5 py-0 ${sev.color} border-current`}>
                                            {sev.label}
                                        </Badge>
                                    </td>
                                    {/* Source */}
                                    <td className="px-3 py-3 text-center hidden sm:table-cell">
                                        <span className="text-[10px] font-mono text-slate-500 bg-slate-800/60 px-2 py-0.5 rounded border border-slate-700/40">
                                            {item.source}
                                        </span>
                                    </td>
                                    {/* Points */}
                                    <td className="px-5 py-3 text-right">
                                        {item.points > 0 ? (
                                            <span className={`font-black font-mono text-sm ${sev.color}`}>+{item.points}</span>
                                        ) : (
                                            <span className="text-slate-600 font-mono text-sm">—</span>
                                        )}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            )}
        </div>
    );
}

// ── Summary stat tile ─────────────────────────────────────────────────────────
function StatTile({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color: string }) {
    return (
        <div className="rounded-xl border border-slate-700/50 bg-slate-900/60 px-4 py-3">
            <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">{label}</p>
            <p className={`text-xl font-black font-mono ${color}`}>{value}</p>
            {sub && <p className="text-[10px] text-slate-500 mt-0.5">{sub}</p>}
        </div>
    );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function RiskScorePage() {
    const { currentAnalysis } = useForensic();
    const navigate = useNavigate();

    const data = useMemo(() => {
        if (!currentAnalysis) return null;
        const r = currentAnalysis;
        const m = r.metadata;

        // ── 1. Timestamp & Date Anomalies ────────────────────────────────────────
        const timestampItems = r.anomalies
            .filter(a => a.type === 'date_mismatch' || a.type === 'timezone_inconsistency')
            .map(a => ({
                label: a.title,
                severity: a.severity as 'high' | 'medium' | 'low',
                points: SEVERITY_POINTS[a.severity] ?? 0,
                description: a.description,
                source: 'timestamp_analyzer',
            }));

        // ── 2. Metadata Integrity ────────────────────────────────────────────────
        const metaItems = r.anomalies
            .filter(a => a.type === 'metadata_wiped' || a.type === 'missing_metadata' || a.type === 'multiple_software')
            .map(a => ({
                label: a.title,
                severity: a.severity as 'high' | 'medium' | 'low',
                points: SEVERITY_POINTS[a.severity] ?? 0,
                description: a.description,
                source: 'metadata_analyzer',
            }));

        // ── 3. Network & Identity ────────────────────────────────────────────────
        const networkItems = r.anomalies
            .filter(a => a.type === 'network_artifact' || a.type === 'identity_leakage')
            .map(a => ({
                label: a.title,
                severity: a.severity as 'high' | 'medium' | 'low',
                points: SEVERITY_POINTS[a.severity] ?? 0,
                description: a.description,
                source: 'network_scanner',
            }));

        // ── 4. Hidden Artifacts ──────────────────────────────────────────────────
        const artifactItems = r.anomalies
            .filter(a => a.type === 'hidden_artifact')
            .map(a => ({
                label: a.title,
                severity: a.severity as 'high' | 'medium' | 'low',
                points: SEVERITY_POINTS[a.severity] ?? 0,
                description: a.description,
                source: 'artifact_scanner',
            }));

        // ── 5. Privacy Risk sub-score ────────────────────────────────────────────
        let privacyScore = 0;
        const privacyItems: ScoreRow['items'] = [];
        try {
            const n = normalizeMetadata(r);
            const privacy = analyzePrivacyRisk(r, n);
            privacyScore = privacy.overall_risk_score;

            if (privacy.identity_leakage.score > 0) {
                privacyItems.push({
                    label: 'Identity Leakage',
                    severity: privacy.identity_leakage.score >= 60 ? 'high' : privacy.identity_leakage.score >= 30 ? 'medium' : 'low',
                    points: Math.round(privacy.identity_leakage.score * 0.3),
                    description: `Author name, email, device owner, or OS fingerprint exposed. Score: ${privacy.identity_leakage.score}/100`,
                    source: 'privacy_analyzer',
                });
            }
            if (privacy.location_exposure.score > 0) {
                privacyItems.push({
                    label: 'Location Exposure',
                    severity: privacy.location_exposure.score >= 60 ? 'high' : 'medium',
                    points: Math.round(privacy.location_exposure.score * 0.2),
                    description: `GPS coordinates or timezone data reveals physical location. Score: ${privacy.location_exposure.score}/100`,
                    source: 'privacy_analyzer',
                });
            }
            if (privacy.device_traceability.score > 0) {
                privacyItems.push({
                    label: 'Device Traceability',
                    severity: privacy.device_traceability.score >= 60 ? 'medium' : 'low',
                    points: Math.round(privacy.device_traceability.score * 0.1),
                    description: `Camera model, software version, or OS build exposes device identity. Score: ${privacy.device_traceability.score}/100`,
                    source: 'privacy_analyzer',
                });
            }
        } catch { /* privacy engine unavailable */ }

        // ── 6. Lifecycle / Integrity ──────────────────────────────────────────────
        const lifecycleItems: ScoreRow['items'] = [];
        try {
            const lc = reconstructLifecycle(r);
            if (lc.tampering_events.length > 0) {
                lc.tampering_events.slice(0, 5).forEach(t => {
                    lifecycleItems.push({
                        label: t.title,
                        severity: t.severity as 'high' | 'medium' | 'low',
                        points: t.severity === 'high' ? 10 : t.severity === 'medium' ? 5 : 2,
                        description: t.description,
                        source: 'lifecycle_engine',
                    });
                });
            }
        } catch { /* lifecycle engine unavailable */ }

        // ── Compile rows ─────────────────────────────────────────────────────────
        const rows: ScoreRow[] = [
            {
                category: 'Timestamp & Date Integrity',
                icon: Clock,
                iconColor: 'text-orange-400',
                items: timestampItems,
                subtotal: timestampItems.reduce((s, i) => s + i.points, 0),
                maxPossible: 90,
            },
            {
                category: 'Metadata Completeness & Consistency',
                icon: Hash,
                iconColor: 'text-violet-400',
                items: metaItems,
                subtotal: metaItems.reduce((s, i) => s + i.points, 0),
                maxPossible: 60,
            },
            {
                category: 'Network & Identity Exposure',
                icon: Network,
                iconColor: 'text-cyan-400',
                items: networkItems,
                subtotal: networkItems.reduce((s, i) => s + i.points, 0),
                maxPossible: 60,
            },
            {
                category: 'Hidden & Suspicious Artifacts',
                icon: EyeOff,
                iconColor: 'text-red-400',
                items: artifactItems,
                subtotal: artifactItems.reduce((s, i) => s + i.points, 0),
                maxPossible: 75,
            },
            {
                category: 'Privacy Exposure Risk',
                icon: Lock,
                iconColor: 'text-pink-400',
                items: privacyItems,
                subtotal: privacyItems.reduce((s, i) => s + i.points, 0),
                maxPossible: 30,
            },
            {
                category: 'Lifecycle & Tampering Events',
                icon: Activity,
                iconColor: 'text-emerald-400',
                items: lifecycleItems,
                subtotal: lifecycleItems.reduce((s, i) => s + i.points, 0),
                maxPossible: 40,
            },
        ];

        // ── Compute totals ────────────────────────────────────────────────────────
        const totalRaw = r.anomalies.reduce((s, a) => s + (SEVERITY_POINTS[a.severity] ?? 0), 0);
        const finalScore = r.riskScore;  // already clamped to 100
        const highCount = r.anomalies.filter(a => a.severity === 'high').length;
        const medCount = r.anomalies.filter(a => a.severity === 'medium').length;
        const lowCount = r.anomalies.filter(a => a.severity === 'low').length;

        return { rows, finalScore, totalRaw, highCount, medCount, lowCount, privacyScore, r, m };
    }, [currentAnalysis]);

    if (!currentAnalysis || !data) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4 text-center p-8">
                <div className="h-20 w-20 rounded-2xl bg-slate-800/60 border border-slate-700/50 flex items-center justify-center">
                    <BarChart3 className="h-10 w-10 text-slate-600" />
                </div>
                <div>
                    <h2 className="text-xl font-bold text-white mb-2">No File Analyzed Yet</h2>
                    <p className="text-slate-400 text-sm">Upload and analyze a file first to see the risk score breakdown.</p>
                </div>
                <Button onClick={() => navigate('/upload')} className="gap-2 bg-violet-600 hover:bg-violet-700 text-white">
                    <Upload className="h-4 w-4" /> Upload a File
                </Button>
            </div>
        );
    }

    const { rows, finalScore, totalRaw, highCount, medCount, lowCount, r, m } = data;
    const level = r.riskLevel;
    const levelConfig = {
        high: { color: 'text-red-400', bg: 'bg-red-950/30', border: 'border-red-500/30', label: 'HIGH RISK', icon: XCircle, desc: 'Strong indicators of metadata tampering or file manipulation detected.' },
        medium: { color: 'text-yellow-400', bg: 'bg-yellow-950/20', border: 'border-yellow-500/25', label: 'MEDIUM RISK', icon: AlertTriangle, desc: 'Suspicious characteristics detected. Further investigation recommended.' },
        low: { color: 'text-emerald-400', bg: 'bg-emerald-950/20', border: 'border-emerald-500/20', label: 'LOW RISK', icon: CheckCircle, desc: 'No critical anomalies found. File appears consistent and authentic.' },
    }[level];
    const LevelIcon = levelConfig.icon;

    return (
        <div className="max-w-5xl mx-auto px-4 py-6 space-y-6">

            {/* ── Page header ── */}
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <BarChart3 className="h-5 w-5 text-violet-400" />
                        <h1 className="text-xl font-bold text-white">Risk Score Breakdown</h1>
                    </div>
                    <p className="text-slate-400 text-xs font-mono truncate max-w-xl">{m.fileName}</p>
                    <p className="text-slate-600 text-[11px] font-mono mt-0.5">{m.sha256Hash}</p>
                </div>
                <Button variant="outline" size="sm" className="gap-1.5 border-slate-700 text-slate-400 hover:text-white" onClick={() => navigate('/analysis')}>
                    <ChevronRight className="h-3.5 w-3.5" /> Full Analysis
                </Button>
            </div>

            {/* ── Score overview ── */}
            <div className={`rounded-2xl border ${levelConfig.border} ${levelConfig.bg} p-6`}>
                <div className="flex items-center gap-8 flex-wrap">
                    {/* Gauge */}
                    <RiskGauge score={finalScore} level={level} />

                    {/* Summary */}
                    <div className="flex-1 min-w-[200px]">
                        <div className="flex items-center gap-2 mb-2">
                            <LevelIcon className={`h-5 w-5 ${levelConfig.color}`} />
                            <span className={`text-2xl font-black ${levelConfig.color}`}>{levelConfig.label}</span>
                        </div>
                        <p className="text-slate-400 text-sm mb-4">{levelConfig.desc}</p>
                        <p className="text-slate-500 text-xs leading-relaxed">{r.riskExplanation}</p>
                    </div>

                    {/* Stat tiles */}
                    <div className="grid grid-cols-2 gap-3 shrink-0">
                        <StatTile label="Composite Score" value={`${finalScore}/100`} sub="clamped to 100" color={levelConfig.color} />
                        <StatTile label="Raw Score" value={`${totalRaw} pts`} sub="before cap" color="text-slate-400" />
                        <StatTile label="Total Findings" value={r.anomalies.length} sub="anomalies detected" color="text-slate-300" />
                        <StatTile label="Integrity Status" value={r.integrityStatus.toUpperCase()} color={r.integrityStatus === 'authentic' ? 'text-emerald-400' : r.integrityStatus === 'suspicious' ? 'text-yellow-400' : 'text-red-400'} />
                    </div>
                </div>
            </div>

            {/* ── Scoring methodology ── */}
            <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 p-4">
                <div className="flex items-center gap-2 mb-3">
                    <Info className="h-4 w-4 text-slate-400" />
                    <span className="text-sm font-semibold text-slate-300">Scoring Methodology</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    {[
                        { sev: 'HIGH', pts: 30, color: 'text-red-400    bg-red-500/10    border-red-500/25', desc: 'Critical tampering indicator' },
                        { sev: 'MEDIUM', pts: 15, color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/25', desc: 'Suspicious pattern detected' },
                        { sev: 'LOW', pts: 7, color: 'text-blue-400   bg-blue-500/10   border-blue-500/25', desc: 'Minor or informational flag' },
                    ].map(({ sev, pts, color, desc }) => (
                        <div key={sev} className={`flex items-center gap-3 px-3 py-2.5 rounded-xl border ${color} text-xs`}>
                            <span className="font-black text-base font-mono tabular-nums w-8 text-right">+{pts}</span>
                            <div>
                                <p className="font-bold">{sev}</p>
                                <p className="text-slate-500">{desc}</p>
                            </div>
                        </div>
                    ))}
                </div>
                <p className="text-[11px] text-slate-600 mt-3">
                    Final score = sum of all finding points, capped at 100. Risk level: LOW (0–24) · MEDIUM (25–59) · HIGH (60–100).
                </p>
            </div>

            {/* ── Anomaly count summary ── */}
            <div className="grid grid-cols-3 gap-3">
                {[
                    { label: 'Critical Findings', count: highCount, pts: highCount * 30, color: 'text-red-400', bg: 'bg-red-950/20', border: 'border-red-500/25', icon: XCircle },
                    { label: 'Medium Findings', count: medCount, pts: medCount * 15, color: 'text-yellow-400', bg: 'bg-yellow-950/20', border: 'border-yellow-500/25', icon: AlertTriangle },
                    { label: 'Low Findings', count: lowCount, pts: lowCount * 7, color: 'text-blue-400', bg: 'bg-blue-950/20', border: 'border-blue-500/25', icon: Shield },
                ].map(({ label, count, pts, color, bg, border, icon: Icon }) => (
                    <div key={label} className={`rounded-xl border ${border} ${bg} p-4 flex items-center gap-3`}>
                        <Icon className={`h-5 w-5 ${color} shrink-0`} />
                        <div>
                            <p className={`text-2xl font-black font-mono ${color}`}>{count}</p>
                            <p className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</p>
                            <p className="text-[10px] text-slate-600 font-mono">+{pts} pts</p>
                        </div>
                    </div>
                ))}
            </div>

            {/* ── Detailed breakdown tables ── */}
            <div className="space-y-2">
                <div className="flex items-center gap-2 mb-3">
                    <TrendingUp className="h-4 w-4 text-slate-400" />
                    <h2 className="text-sm font-semibold text-slate-300">Detailed Score Breakdown by Category</h2>
                </div>
                {rows.map((row) => (
                    <CategoryTable key={row.category} row={row} />
                ))}
            </div>

            {/* ── Score computation summary table ── */}
            <div className="rounded-2xl border border-slate-700/50 bg-slate-900/60 overflow-hidden">
                <div className="px-5 py-3 border-b border-slate-700/40 bg-slate-800/40 flex items-center gap-2">
                    <Fingerprint className="h-4 w-4 text-violet-400" />
                    <span className="text-sm font-semibold text-slate-200">Score Computation Summary</span>
                </div>
                <table className="w-full text-xs">
                    <thead>
                        <tr className="border-b border-slate-700/30">
                            <th className="text-left px-5 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Category</th>
                            <th className="text-center px-4 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold hidden sm:table-cell">Findings</th>
                            <th className="text-center px-4 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold hidden md:table-cell">Max Possible</th>
                            <th className="text-center px-4 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Risk %</th>
                            <th className="text-right px-5 py-2.5 text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((row, i) => {
                            const Icon = row.icon;
                            const pct = row.maxPossible > 0 ? Math.round((row.subtotal / row.maxPossible) * 100) : 0;
                            const rowColor = pct >= 60 ? 'text-red-400' : pct >= 30 ? 'text-yellow-400' : 'text-emerald-400';
                            return (
                                <tr key={i} className="border-b border-slate-700/20 last:border-0 hover:bg-slate-800/20 transition-colors">
                                    <td className="px-5 py-3">
                                        <div className="flex items-center gap-2">
                                            <Icon className={`h-3.5 w-3.5 ${row.iconColor} shrink-0`} />
                                            <span className="text-slate-300">{row.category}</span>
                                        </div>
                                    </td>
                                    <td className="px-4 py-3 text-center hidden sm:table-cell">
                                        <span className={`font-mono font-bold ${row.items.length > 0 ? 'text-slate-300' : 'text-slate-600'}`}>
                                            {row.items.length}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-center hidden md:table-cell">
                                        <span className="text-slate-600 font-mono">{row.maxPossible}</span>
                                    </td>
                                    <td className="px-4 py-3 text-center">
                                        <div className="flex items-center gap-2 justify-center">
                                            <div className="w-16 hidden sm:block">
                                                <ScoreBar value={row.subtotal} max={row.maxPossible} color={pct >= 60 ? 'bg-red-500' : pct >= 30 ? 'bg-yellow-500' : 'bg-emerald-500'} />
                                            </div>
                                            <span className={`font-mono font-bold ${rowColor}`}>{pct}%</span>
                                        </div>
                                    </td>
                                    <td className="px-5 py-3 text-right">
                                        <span className={`font-black font-mono text-sm ${row.subtotal > 0 ? rowColor : 'text-slate-600'}`}>
                                            {row.subtotal > 0 ? `+${row.subtotal}` : '0'}
                                        </span>
                                    </td>
                                </tr>
                            );
                        })}
                        {/* Totals row */}
                        <tr className="border-t-2 border-slate-600/50 bg-slate-800/40">
                            <td className="px-5 py-3 font-bold text-slate-200">TOTAL</td>
                            <td className="px-4 py-3 text-center font-bold text-slate-300 hidden sm:table-cell">{r.anomalies.length}</td>
                            <td className="px-4 py-3 text-center hidden md:table-cell" />
                            <td className="px-4 py-3 text-center" />
                            <td className="px-5 py-3 text-right">
                                <span className="text-slate-500 font-mono text-xs line-through mr-2">+{totalRaw} raw</span>
                                <span className={`font-black font-mono text-base ${level === 'high' ? 'text-red-400' : level === 'medium' ? 'text-yellow-400' : 'text-emerald-400'}`}>
                                    {finalScore}/100
                                </span>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

        </div>
    );
}
