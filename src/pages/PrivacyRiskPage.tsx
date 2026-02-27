import { useMemo, useState } from 'react';
import { useForensic } from '@/context/ForensicContext';
import { normalizeMetadata } from '@/lib/metadata-normalizer';
import { analyzePrivacyRisk, PrivacyRiskReport, RiskDimension, LeakSource, SanitizationAction } from '@/lib/privacy-risk-analyzer';
import {
    ShieldAlert, ShieldCheck, ShieldX, User, MapPin, Cpu, Wifi,
    ChevronDown, ChevronUp, AlertTriangle, CheckCircle2, ClipboardList,
    Terminal, Info, Zap, Eye, Layers, Circle
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';

// ── Risk level helpers ───────────────────────────────────────────────────────

const LEVEL_CONFIG: Record<string, { bg: string; border: string; text: string; badge: string; icon: typeof ShieldAlert }> = {
    critical: { bg: 'bg-red-950/30', border: 'border-red-500/50', text: 'text-red-400', badge: 'bg-red-500/20 text-red-400 border-red-500/40', icon: ShieldX },
    high: { bg: 'bg-orange-950/20', border: 'border-orange-500/40', text: 'text-orange-400', badge: 'bg-orange-500/20 text-orange-400 border-orange-500/40', icon: ShieldAlert },
    medium: { bg: 'bg-amber-950/20', border: 'border-amber-500/40', text: 'text-amber-400', badge: 'bg-amber-500/20 text-amber-400 border-amber-500/40', icon: ShieldAlert },
    low: { bg: 'bg-sky-950/20', border: 'border-sky-500/40', text: 'text-sky-400', badge: 'bg-sky-500/20 text-sky-400 border-sky-500/40', icon: ShieldCheck },
    minimal: { bg: 'bg-emerald-950/20', border: 'border-emerald-500/40', text: 'text-emerald-400', badge: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40', icon: ShieldCheck },
};

const SEV_BADGE: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    low: 'bg-sky-500/20 text-sky-400 border-sky-500/30',
};

const PRIORITY_CONFIG = {
    1: { label: 'Immediate', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/25', dot: 'bg-red-500' },
    2: { label: 'Recommended', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/25', dot: 'bg-amber-500' },
    3: { label: 'Optional', color: 'text-sky-400', bg: 'bg-sky-500/10 border-sky-500/25', dot: 'bg-sky-400' },
};

function riskBarColor(level: string): string {
    if (level === 'critical') return 'bg-red-500';
    if (level === 'high') return 'bg-orange-500';
    if (level === 'medium') return 'bg-amber-400';
    if (level === 'low') return 'bg-sky-400';
    return 'bg-emerald-500';
}

// ── Score Arc SVG ────────────────────────────────────────────────────────────

function ScoreArc({ score, level }: { score: number; level: string }) {
    const cfg = LEVEL_CONFIG[level] ?? LEVEL_CONFIG.minimal;
    const strokeColors: Record<string, string> = {
        critical: '#ef4444', high: '#f97316', medium: '#f59e0b',
        low: '#38bdf8', minimal: '#10b981',
    };
    const stroke = strokeColors[level] ?? strokeColors.minimal;
    const r = 54;
    const cx = 70, cy = 70;
    const circumference = Math.PI * r; // semicircle
    const offset = circumference - (score / 100) * circumference;

    return (
        <div className="relative flex flex-col items-center justify-center">
            <svg width="140" height="90" viewBox="0 0 140 90">
                {/* Track */}
                <path
                    d={`M ${cx - r},${cy} A ${r},${r} 0 0,1 ${cx + r},${cy}`}
                    fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" strokeLinecap="round"
                />
                {/* Progress */}
                <path
                    d={`M ${cx - r},${cy} A ${r},${r} 0 0,1 ${cx + r},${cy}`}
                    fill="none" stroke={stroke} strokeWidth="10" strokeLinecap="round"
                    strokeDasharray={circumference} strokeDashoffset={offset}
                    style={{ transition: 'stroke-dashoffset 1s ease' }}
                />
            </svg>
            <div className="absolute bottom-0 text-center pb-1">
                <p className={`text-4xl font-black ${cfg.text} leading-none`}>{score}</p>
                <p className="text-[10px] text-slate-400 uppercase tracking-widest mt-0.5">/ 100</p>
            </div>
        </div>
    );
}

// ── Dimension Bar Card ────────────────────────────────────────────────────────

const DIM_ICONS: Record<string, React.ElementType> = {
    'Identity Leakage Risk': User,
    'Location Exposure Risk': MapPin,
    'Device Traceability': Cpu,
    'Network Attribution Risk': Wifi,
};

function DimensionCard({ dim }: { dim: RiskDimension }) {
    const [open, setOpen] = useState(false);
    const cfg = LEVEL_CONFIG[dim.level] ?? LEVEL_CONFIG.minimal;
    const Icon = DIM_ICONS[dim.name] ?? Layers;

    return (
        <Card className={`${cfg.bg} border ${cfg.border} transition-all`}>
            <CardHeader className="pb-2 pt-4 px-4">
                <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                        <div className={`p-1.5 rounded-lg ${cfg.bg} border ${cfg.border}`}>
                            <Icon className={`h-4 w-4 ${cfg.text}`} />
                        </div>
                        <div>
                            <p className="text-xs font-semibold text-slate-200">{dim.name}</p>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase tracking-wider ${cfg.badge}`}>
                                {dim.level}
                            </span>
                        </div>
                    </div>
                    <div className="text-right">
                        <span className={`text-2xl font-black ${cfg.text}`}>{dim.score}</span>
                        <span className="text-slate-500 text-xs">/100</span>
                    </div>
                </div>
                {/* Score bar */}
                <div className="mt-3 h-1.5 rounded-full bg-white/5 overflow-hidden">
                    <div
                        className={`h-full rounded-full ${riskBarColor(dim.level)} transition-all duration-700`}
                        style={{ width: `${dim.score}%` }}
                    />
                </div>
            </CardHeader>
            <CardContent className="px-4 pb-3">
                {/* Top findings */}
                <div className="space-y-1.5 mb-2">
                    {dim.top_findings.map((f, i) => (
                        <div key={i} className="flex items-start gap-2">
                            <Circle className={`h-1.5 w-1.5 mt-1.5 shrink-0 ${cfg.text} fill-current`} />
                            <p className="text-xs text-slate-300 leading-relaxed">{f}</p>
                        </div>
                    ))}
                </div>

                {dim.contributing_factors.length > 0 && (
                    <button
                        onClick={() => setOpen(v => !v)}
                        className="flex items-center gap-1.5 text-[10px] text-slate-500 hover:text-slate-300 transition-colors mt-1"
                    >
                        {open ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                        {open ? 'Hide' : 'Show'} {dim.contributing_factors.length} contributing factors
                    </button>
                )}

                {open && (
                    <div className="mt-3 space-y-2 border-t border-white/5 pt-3">
                        {dim.contributing_factors.map((f, i) => (
                            <div key={i} className="p-2 rounded-lg bg-black/20 border border-white/5">
                                <div className="flex items-center justify-between mb-1">
                                    <code className="text-[10px] text-slate-400 font-mono">{f.field}</code>
                                    <div className="flex items-center gap-1.5">
                                        <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase ${SEV_BADGE[f.severity]}`}>{f.severity}</span>
                                        <span className="text-[10px] font-bold text-slate-300">+{f.points}pt</span>
                                    </div>
                                </div>
                                <p className="text-[11px] font-mono text-slate-200 truncate mb-1">"{f.value}"</p>
                                <p className="text-[10px] text-slate-500 leading-relaxed">{f.rationale}</p>
                            </div>
                        ))}
                    </div>
                )}
            </CardContent>
        </Card>
    );
}

// ── Leak Source Row ───────────────────────────────────────────────────────────

const CAT_ICONS: Record<string, React.ElementType> = {
    identity: User, location: MapPin, device: Cpu, network: Wifi,
};
const CAT_COLORS: Record<string, string> = {
    identity: 'text-violet-400', location: 'text-emerald-400',
    device: 'text-sky-400', network: 'text-orange-400',
};

function LeakRow({ leak, idx }: { leak: LeakSource; idx: number }) {
    const Icon = CAT_ICONS[leak.category] ?? Eye;
    const color = CAT_COLORS[leak.category] ?? 'text-slate-400';

    return (
        <div className="flex items-start gap-3 py-3 border-b border-white/5 last:border-0">
            <div className="flex-shrink-0 w-6 h-6 rounded-full bg-white/5 border border-white/10 flex items-center justify-center mt-0.5">
                <span className="text-[9px] font-bold text-slate-400">{idx + 1}</span>
            </div>
            <div className="flex-shrink-0 p-1 rounded bg-white/5 mt-0.5">
                <Icon className={`h-3.5 w-3.5 ${color}`} />
            </div>
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-0.5">
                    <code className="text-[10px] text-slate-400 font-mono">{leak.field}</code>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase ${SEV_BADGE[leak.severity]}`}>{leak.severity}</span>
                </div>
                <p className="text-xs font-mono text-slate-200 truncate mb-1">"{leak.value}"</p>
                <p className="text-[11px] text-slate-400 leading-relaxed">{leak.exposure_description}</p>
                <p className="text-[10px] text-slate-500 mt-0.5">OSINT vector: {leak.osint_vector}</p>
            </div>
        </div>
    );
}

// ── Sanitization Card ─────────────────────────────────────────────────────────

function SanitizationCard({ action, idx }: { action: SanitizationAction; idx: number }) {
    const [expanded, setExpanded] = useState(idx === 0);
    const cfg = PRIORITY_CONFIG[action.priority];

    return (
        <div className={`rounded-xl border ${cfg.bg} overflow-hidden`}>
            <button
                onClick={() => setExpanded(v => !v)}
                className="w-full flex items-start gap-3 p-4 text-left hover:bg-white/3 transition-colors"
            >
                <div className="flex-shrink-0 mt-0.5">
                    <div className={`w-5 h-5 rounded-full ${cfg.dot} flex items-center justify-center`}>
                        <span className="text-[9px] font-black text-white">{action.priority}</span>
                    </div>
                </div>
                <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className={`text-[10px] font-bold uppercase tracking-wider ${cfg.color}`}>{cfg.label}</span>
                        <span className="text-[10px] text-slate-500">~{action.risk_reduction_estimate}pt reduction</span>
                    </div>
                    <p className="text-sm font-medium text-slate-200">{action.action}</p>
                </div>
                {expanded ? <ChevronUp className="h-3.5 w-3.5 text-slate-500 shrink-0 mt-1" /> : <ChevronDown className="h-3.5 w-3.5 text-slate-500 shrink-0 mt-1" />}
            </button>

            {expanded && (
                <div className="px-4 pb-4 space-y-3">
                    {/* Affected fields */}
                    {action.affected_fields.length > 0 && (
                        <div>
                            <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-1.5">Affected Fields</p>
                            <div className="flex flex-wrap gap-1.5">
                                {action.affected_fields.slice(0, 6).map((f, i) => (
                                    <code key={i} className="text-[10px] px-2 py-0.5 rounded bg-black/30 border border-white/10 text-slate-300">{f}</code>
                                ))}
                                {action.affected_fields.length > 6 && (
                                    <span className="text-[10px] text-slate-500 px-2 py-0.5">+{action.affected_fields.length - 6} more</span>
                                )}
                            </div>
                        </div>
                    )}
                    {/* Tool suggestions */}
                    <div>
                        <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-1.5 flex items-center gap-1">
                            <Terminal className="h-3 w-3" /> Tools &amp; Commands
                        </p>
                        <div className="space-y-1.5">
                            {action.tool_suggestions.map((t, i) => (
                                <div key={i} className="p-2 rounded-lg bg-black/40 border border-white/5">
                                    <p className="text-[11px] font-mono text-emerald-300 leading-relaxed">{t}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function PrivacyRiskPage() {
    const { analyses, currentAnalysis } = useForensic();
    const navigate = useNavigate();
    const latest = currentAnalysis ?? analyses[0] ?? null;

    const report: PrivacyRiskReport | null = useMemo(() => {
        if (!latest) return null;
        const norm = normalizeMetadata(latest);
        return analyzePrivacyRisk(latest, norm);
    }, [latest]);

    const [activeTab, setActiveTab] = useState<'overview' | 'leaks' | 'sanitation'>('overview');

    if (!latest || !report) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4 p-8">
                <div className="p-5 rounded-2xl bg-orange-500/10 border border-orange-500/20">
                    <ShieldAlert className="h-10 w-10 text-orange-400" />
                </div>
                <div className="text-center">
                    <h2 className="text-xl font-bold text-white mb-2">No File Analyzed Yet</h2>
                    <p className="text-slate-400 text-sm max-w-md">Upload and analyze a file first to run the privacy exposure risk assessment.</p>
                </div>
                <Button onClick={() => navigate('/upload')} className="bg-orange-600 hover:bg-orange-700 text-white">Upload a File</Button>
            </div>
        );
    }

    const overall = report.overall_risk_score;
    const cfg = LEVEL_CONFIG[report.risk_level] ?? LEVEL_CONFIG.minimal;
    const LevelIcon = cfg.icon;

    const criticalLeaks = report.key_leak_sources.filter(l => l.severity === 'critical' || l.severity === 'high');
    const p1Actions = report.recommended_sanitization_actions.filter(a => a.priority === 1);

    return (
        <div className="max-w-6xl mx-auto px-4 py-6 space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <ShieldAlert className="h-5 w-5 text-orange-400" />
                        <h1 className="text-xl font-bold text-white">Privacy & Forensic Exposure Risk</h1>
                    </div>
                    <p className="text-slate-400 text-sm">Identity · Location · Device · Network — 4-dimension scoring with sanitization plan</p>
                    <p className="text-xs text-slate-500 mt-1 font-mono">File: <span className="text-violet-300">{report.file_name}</span></p>
                </div>
                <span className="text-xs text-slate-500">{new Date(report.analyzed_at).toLocaleTimeString()}</span>
            </div>

            {/* ── Hero Score Card ── */}
            <Card className={`border-2 ${cfg.border} ${cfg.bg} backdrop-blur-sm`}>
                <CardContent className="p-6">
                    <div className="flex flex-col md:flex-row items-center gap-6">
                        {/* Arc gauge */}
                        <div className="flex-shrink-0">
                            <ScoreArc score={overall} level={report.risk_level} />
                            <p className={`text-center text-sm font-bold uppercase tracking-wide mt-1 ${cfg.text}`}>
                                {report.risk_level}
                            </p>
                        </div>

                        <div className="flex-1 space-y-4 w-full">
                            {/* Metadata density */}
                            <div>
                                <div className="flex items-center justify-between mb-1.5">
                                    <span className="text-xs text-slate-400">Metadata Density (Identifying Fields)</span>
                                    <span className="text-xs font-mono text-slate-300">{report.metadata_density_pct}%</span>
                                </div>
                                <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
                                    <div className={`h-full rounded-full ${riskBarColor(report.risk_level)} transition-all`}
                                        style={{ width: `${report.metadata_density_pct}%` }} />
                                </div>
                            </div>

                            {/* 4 dimension mini-bars */}
                            <div className="grid grid-cols-2 gap-3">
                                {[
                                    { label: 'Identity', dim: report.identity_leakage },
                                    { label: 'Location', dim: report.location_exposure },
                                    { label: 'Device', dim: report.device_traceability },
                                    { label: 'Network', dim: report.network_attribution },
                                ].map(({ label, dim }) => (
                                    <div key={label}>
                                        <div className="flex justify-between mb-1">
                                            <span className="text-[10px] text-slate-400">{label}</span>
                                            <span className={`text-[10px] font-bold ${LEVEL_CONFIG[dim.level]?.text}`}>{dim.score}</span>
                                        </div>
                                        <div className="h-1 rounded-full bg-white/5 overflow-hidden">
                                            <div className={`h-full rounded-full ${riskBarColor(dim.level)}`} style={{ width: `${dim.score}%` }} />
                                        </div>
                                    </div>
                                ))}
                            </div>

                            {/* Summary stats */}
                            <div className="flex gap-3 flex-wrap">
                                <div className="px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-center">
                                    <p className="text-lg font-black text-white">{report.key_leak_sources.length}</p>
                                    <p className="text-[10px] text-slate-400">Leak Sources</p>
                                </div>
                                <div className="px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-center">
                                    <p className="text-lg font-black text-red-400">{criticalLeaks.length}</p>
                                    <p className="text-[10px] text-slate-400">Critical/High</p>
                                </div>
                                <div className="px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-center">
                                    <p className="text-lg font-black text-amber-400">{p1Actions.length}</p>
                                    <p className="text-[10px] text-slate-400">P1 Actions</p>
                                </div>
                                <div className="px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-center">
                                    <p className="text-lg font-black text-emerald-400">{report.recommended_sanitization_actions.length}</p>
                                    <p className="text-[10px] text-slate-400">Total Actions</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Executive summary */}
                    <div className="mt-5 p-4 rounded-xl bg-black/20 border border-white/5 flex gap-3">
                        <Info className="h-4 w-4 text-slate-400 shrink-0 mt-0.5" />
                        <p className="text-xs text-slate-300 leading-relaxed">{report.executive_summary}</p>
                    </div>
                </CardContent>
            </Card>

            {/* ── Tab Navigation ── */}
            <div className="flex gap-1 p-1 bg-slate-800/60 border border-slate-700/50 rounded-xl w-fit">
                {[
                    { key: 'overview', label: 'Dimension Scores', icon: Layers },
                    { key: 'leaks', label: `Leak Sources (${report.key_leak_sources.length})`, icon: Eye },
                    { key: 'sanitation', label: `Sanitization Plan (${report.recommended_sanitization_actions.length})`, icon: ClipboardList },
                ].map(({ key, label, icon: Icon }) => (
                    <button
                        key={key}
                        onClick={() => setActiveTab(key as typeof activeTab)}
                        className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${activeTab === key
                                ? 'bg-white/10 text-white shadow'
                                : 'text-slate-400 hover:text-slate-200'
                            }`}
                    >
                        <Icon className="h-3.5 w-3.5" />
                        {label}
                    </button>
                ))}
            </div>

            {/* ── Overview Tab: 4 dimensions ── */}
            {activeTab === 'overview' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <DimensionCard dim={report.identity_leakage} />
                    <DimensionCard dim={report.location_exposure} />
                    <DimensionCard dim={report.device_traceability} />
                    <DimensionCard dim={report.network_attribution} />
                </div>
            )}

            {/* ── Leaks Tab ── */}
            {activeTab === 'leaks' && (
                <Card className="bg-slate-800/50 border-slate-700/50">
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                            <Eye className="h-4 w-4 text-orange-400" />
                            Key Leak Sources — Sorted by Severity
                        </CardTitle>
                        <CardDescription className="text-xs text-slate-400">
                            Every identified data field that contributes to privacy or forensic exposure, with OSINT attack vectors
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {report.key_leak_sources.length === 0 ? (
                            <div className="flex flex-col items-center py-8 gap-3 text-center">
                                <ShieldCheck className="h-10 w-10 text-emerald-400" />
                                <p className="text-sm text-emerald-400 font-semibold">No significant leak sources detected</p>
                                <p className="text-xs text-slate-500">This file has minimal identifiable data embedded in its metadata</p>
                            </div>
                        ) : (
                            <div className="divide-y divide-white/5">
                                {report.key_leak_sources.map((leak, i) => (
                                    <LeakRow key={leak.id} leak={leak} idx={i} />
                                ))}
                            </div>
                        )}
                    </CardContent>
                </Card>
            )}

            {/* ── Sanitization Tab ── */}
            {activeTab === 'sanitation' && (
                <div className="space-y-4">
                    {/* Priority legend */}
                    <div className="flex gap-4 p-3 bg-slate-800/40 border border-slate-700/40 rounded-xl flex-wrap">
                        {([1, 2, 3] as const).map(p => {
                            const c = PRIORITY_CONFIG[p];
                            return (
                                <div key={p} className="flex items-center gap-2">
                                    <div className={`w-3 h-3 rounded-full ${c.dot}`} />
                                    <span className="text-xs text-slate-400"><span className={`font-bold ${c.color}`}>P{p}</span> — {c.label}</span>
                                </div>
                            );
                        })}
                        <div className="flex items-center gap-2 ml-auto">
                            <Zap className="h-3.5 w-3.5 text-slate-400" />
                            <span className="text-xs text-slate-400">Point reduction shown per action</span>
                        </div>
                    </div>

                    {report.recommended_sanitization_actions.length === 0 ? (
                        <div className="flex flex-col items-center py-8 gap-3 text-center">
                            <CheckCircle2 className="h-10 w-10 text-emerald-400" />
                            <p className="text-sm text-emerald-400 font-semibold">No sanitization required</p>
                            <p className="text-xs text-slate-500">This file's metadata is already clean</p>
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {report.recommended_sanitization_actions.map((action, i) => (
                                <SanitizationCard key={i} action={action} idx={i} />
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* Footer disclaimer */}
            <div className="flex items-start gap-2.5 p-4 rounded-xl bg-slate-800/40 border border-slate-700/40 text-xs text-slate-400">
                <AlertTriangle className="h-4 w-4 text-slate-500 shrink-0 mt-0.5" />
                <p>
                    Risk scores are computed from available metadata signals only. Files with stripped metadata may score low while still
                    carrying embedded risks in the file body. Always perform a full content scan in addition to metadata analysis.
                    Sanitization commands target common tools — verify compatibility with your operating system and file format before running.
                </p>
            </div>
        </div>
    );
}
