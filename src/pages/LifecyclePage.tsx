import { useMemo, useState } from 'react';
import { useForensic } from '@/context/ForensicContext';
import {
    reconstructLifecycle,
    ChronologyReport,
    TimelineEvent,
    EditingGap,
    TimezoneSignal,
    TamperingEvent,
    AnomalySeverity,
    TamperingMechanism,
} from '@/lib/lifecycle-analyzer';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
    Clock, AlertTriangle, CheckCircle, XCircle, Download, Code2,
    ChevronDown, ChevronUp, Calendar, GitCommit, Globe,
    Zap, ShieldAlert, Copy, Check, Info, Activity,
    TrendingDown, ArrowRight, Minus,
} from 'lucide-react';

// ── Visual config ─────────────────────────────────────────────────────────

const VERDICT_CONFIG = {
    authentic: { label: 'Authentic', icon: CheckCircle, color: 'text-emerald-400', bg: 'bg-emerald-500/8', border: 'border-emerald-500/25' },
    suspect: { label: 'Suspect', icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/8', border: 'border-yellow-500/25' },
    tampered: { label: 'Tampered', icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/8', border: 'border-red-500/25' },
    insufficient_data: { label: 'Insufficient Data', icon: Info, color: 'text-muted-foreground', bg: 'bg-muted/30', border: 'border-border/40' },
};

const INTEGRITY_COLOR = (s: number) =>
    s >= 80 ? '#22c55e' : s >= 50 ? '#eab308' : '#ef4444';

const SEV_CONFIG: Record<AnomalySeverity, { label: string; color: string; bg: string; border: string }> = {
    critical: { label: 'CRITICAL', color: 'text-purple-400', bg: 'bg-purple-500/8', border: 'border-purple-500/30' },
    high: { label: 'HIGH', color: 'text-red-400', bg: 'bg-red-500/8', border: 'border-red-500/25' },
    medium: { label: 'MEDIUM', color: 'text-yellow-400', bg: 'bg-yellow-500/8', border: 'border-yellow-500/25' },
    low: { label: 'LOW', color: 'text-blue-400', bg: 'bg-blue-500/8', border: 'border-blue-500/25' },
    info: { label: 'INFO', color: 'text-muted-foreground', bg: 'bg-muted/30', border: 'border-border/30' },
};

const MECHANISM_LABEL: Record<TamperingMechanism, string> = {
    timestamp_rollback: 'Timestamp Rollback',
    timestamp_forward: 'Future Timestamp',
    metadata_rewrite: 'Metadata Rewrite',
    clock_skew: 'Clock Skew',
    precision_fabrication: 'Precision Fabrication',
    impossible_sequence: 'Impossible Sequence',
    timezone_forgery: 'Timezone Forgery',
    revision_stripping: 'Revision Stripping',
    gap_anomaly: 'Gap Anomaly',
};

const GAP_CONFIG = {
    normal: { color: 'text-muted-foreground', dot: 'bg-muted-foreground/50' },
    short_suspicious: { color: 'text-yellow-400', dot: 'bg-yellow-400' },
    long_suspicious: { color: 'text-orange-400', dot: 'bg-orange-400' },
    impossible_negative: { color: 'text-red-400', dot: 'bg-red-400' },
};

const CREATION_INTEGRITY = {
    intact: { label: 'Intact', color: 'text-emerald-400', icon: CheckCircle },
    suspect: { label: 'Suspect', color: 'text-yellow-400', icon: AlertTriangle },
    compromised: { label: 'Compromised', color: 'text-red-400', icon: XCircle },
};

// ── Sub-components ─────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
    const [ok, setOk] = useState(false);
    return (
        <button onClick={() => { navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1800); }}
            className="text-muted-foreground hover:text-foreground transition-colors shrink-0" title="Copy">
            {ok ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
        </button>
    );
}

function SectionCard({ icon: Icon, iconColor, title, children, defaultOpen = true }: {
    icon: React.ComponentType<{ className?: string }>;
    iconColor: string; title: string; children: React.ReactNode; defaultOpen?: boolean;
}) {
    const [open, setOpen] = useState(defaultOpen);
    return (
        <Card className="overflow-hidden">
            <button className="w-full flex items-center gap-2 px-5 py-3 border-b border-border/50 hover:bg-accent/20 transition-colors text-left"
                onClick={() => setOpen(o => !o)}>
                <Icon className={`h-4 w-4 ${iconColor} shrink-0`} />
                <span className="text-sm font-semibold flex-1">{title}</span>
                {open ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" />
                    : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
            </button>
            {open && <CardContent className="p-5">{children}</CardContent>}
        </Card>
    );
}

// ── Integrity ring ────────────────────────────────────────────────────────
function IntegrityRing({ score }: { score: number }) {
    const r = 44; const circ = 2 * Math.PI * r;
    const color = INTEGRITY_COLOR(score);
    return (
        <div className="relative flex items-center justify-center w-24 h-24">
            <svg className="absolute inset-0 -rotate-90" width="96" height="96" viewBox="0 0 96 96">
                <circle cx="48" cy="48" r={r} fill="none" stroke="hsl(222,30%,14%)" strokeWidth="8" />
                <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={`${(score / 100) * circ} ${circ}`}
                    style={{ filter: `drop-shadow(0 0 5px ${color})`, transition: 'stroke-dasharray 1.2s ease' }} />
            </svg>
            <div className="text-center z-10">
                <p className="text-xl font-black font-mono" style={{ color }}>{score}</p>
                <p className="text-[9px] text-muted-foreground uppercase tracking-widest">/100</p>
            </div>
        </div>
    );
}

// ── Timeline node ─────────────────────────────────────────────────────────
function TimelineNode({ event, isLast }: { event: TimelineEvent; isLast: boolean }) {
    const [expanded, setExpanded] = useState(false);
    const auth = event.authenticity_score;
    const authColor = auth >= 70 ? '#22c55e' : auth >= 40 ? '#eab308' : '#ef4444';

    return (
        <div className="flex gap-3">
            {/* Spine */}
            <div className="flex flex-col items-center">
                <div className={`h-3 w-3 rounded-full border-2 mt-1 shrink-0 ${event.flagged ? 'border-red-400 bg-red-400/20' : 'border-emerald-400 bg-emerald-400/20'
                    }`} />
                {!isLast && <div className="w-px flex-1 bg-border/40 mt-1" />}
            </div>

            {/* Content */}
            <div className="pb-4 flex-1 min-w-0">
                <div className="flex items-start gap-2 flex-wrap">
                    <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold text-foreground">{event.label}</p>
                        <p className="text-[11px] font-mono text-emerald-300 mt-0.5">{event.utc}</p>
                        <p className="text-[10px] text-muted-foreground font-mono">{event.source_field}</p>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                        {/* Authenticity bar */}
                        <div title={`Authenticity: ${auth}%`} className="flex items-center gap-1">
                            <div className="w-12 h-1.5 rounded-full bg-muted overflow-hidden">
                                <div className="h-full rounded-full" style={{ width: `${auth}%`, background: authColor }} />
                            </div>
                            <span className="text-[10px] font-mono" style={{ color: authColor }}>{auth}%</span>
                        </div>
                        {event.flagged && <AlertTriangle className="h-3 w-3 text-red-400" />}
                        {event.notes.length > 0 && (
                            <button onClick={() => setExpanded(e => !e)} className="text-muted-foreground hover:text-foreground transition-colors">
                                {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                            </button>
                        )}
                        <CopyBtn text={event.utc} />
                    </div>
                </div>

                {expanded && event.notes.length > 0 && (
                    <div className="mt-2 space-y-1">
                        {event.notes.map((n, i) => (
                            <p key={i} className="text-[11px] text-muted-foreground bg-muted/30 rounded px-2 py-1 border border-border/30 leading-relaxed">{n}</p>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

// ── Gap row ───────────────────────────────────────────────────────────────
function GapRow({ gap }: { gap: EditingGap }) {
    const cfg = GAP_CONFIG[gap.assessment];
    const [expanded, setExpanded] = useState(gap.assessment !== 'normal');

    return (
        <div className={`rounded-lg border p-3 ${gap.assessment === 'impossible_negative' ? 'border-red-500/30 bg-red-500/5' :
                gap.assessment === 'short_suspicious' ? 'border-yellow-500/25 bg-yellow-500/5' :
                    gap.assessment === 'long_suspicious' ? 'border-orange-500/25 bg-orange-500/5' :
                        'border-border/30 bg-muted/20'
            }`}>
            <div className="flex items-center gap-2">
                <div className={`h-2 w-2 rounded-full shrink-0 ${cfg.dot}`} />
                <div className="flex-1 min-w-0 flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-mono text-muted-foreground truncate">{gap.from_label}</span>
                    <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
                    <span className="text-[10px] font-mono text-muted-foreground truncate">{gap.to_label}</span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                    <span className={`text-xs font-mono font-bold ${cfg.color}`}>{gap.gap_human}</span>
                    {gap.assessment !== 'normal' && (
                        <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${cfg.color} border-current`}>
                            {gap.assessment.replace(/_/g, ' ')}
                        </Badge>
                    )}
                    <button onClick={() => setExpanded(e => !e)} className="text-muted-foreground hover:text-foreground transition-colors">
                        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                    </button>
                </div>
            </div>
            {expanded && (
                <p className="text-[11px] text-muted-foreground mt-2 leading-relaxed pl-4 border-l-2 border-border/40">
                    {gap.explanation}
                </p>
            )}
        </div>
    );
}

// ── Tampering card ─────────────────────────────────────────────────────────
function TamperingCard({ event }: { event: TamperingEvent }) {
    const [expanded, setExpanded] = useState(true);
    const sev = SEV_CONFIG[event.severity];

    return (
        <div className={`rounded-xl border ${sev.border} ${sev.bg} overflow-hidden`}>
            <button className="w-full flex items-start gap-3 p-3 text-left hover:bg-white/5 transition-colors"
                onClick={() => setExpanded(e => !e)}>
                <div className="flex flex-col items-start gap-1 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5">
                        <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${sev.color} border-current`}>
                            {sev.label}
                        </Badge>
                        <Badge variant="secondary" className="text-[9px] px-1.5 py-0 font-mono">
                            {MECHANISM_LABEL[event.mechanism]}
                        </Badge>
                    </div>
                    <p className="text-xs font-semibold text-foreground">{event.title}</p>
                </div>
                {expanded ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground shrink-0 mt-0.5" />
                    : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0 mt-0.5" />}
            </button>

            {expanded && (
                <div className="px-4 pb-4 space-y-3 border-t border-border/20">
                    <p className="text-xs text-foreground leading-relaxed pt-3">{event.description}</p>

                    {event.involved_timestamps.length > 0 && (
                        <div>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Involved Timestamps</p>
                            <div className="space-y-1">
                                {event.involved_timestamps.map((ts, i) => (
                                    <div key={i} className="flex items-center gap-2 px-2 py-1 rounded bg-muted/40 border border-border/30">
                                        <span className="text-[11px] font-mono text-emerald-300 flex-1">{ts}</span>
                                        <CopyBtn text={ts} />
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {event.involved_fields.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                            {event.involved_fields.map((f, i) => (
                                <span key={i} className="text-[10px] font-mono px-1.5 py-0 rounded bg-muted border border-border/50 text-muted-foreground">{f}</span>
                            ))}
                        </div>
                    )}

                    <div className="flex items-start gap-2 p-2.5 rounded-lg bg-muted/50 border border-border/30">
                        <ShieldAlert className="h-3.5 w-3.5 text-primary mt-0.5 shrink-0" />
                        <div>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">Recommended Action</p>
                            <p className="text-xs text-foreground">{event.recommended_action}</p>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

// ── Main Page ──────────────────────────────────────────────────────────────
export default function LifecyclePage() {
    const { currentAnalysis } = useForensic();
    const [showJSON, setShowJSON] = useState(false);

    const report: ChronologyReport | null = useMemo(
        () => (currentAnalysis ? reconstructLifecycle(currentAnalysis) : null),
        [currentAnalysis]
    );

    if (!currentAnalysis || !report) {
        return (
            <div className="flex flex-col items-center justify-center h-[60vh] gap-4 text-center">
                <div className="p-5 rounded-2xl bg-muted">
                    <Activity className="h-12 w-12 text-muted-foreground/30" />
                </div>
                <div>
                    <p className="font-medium text-foreground">No analysis loaded</p>
                    <p className="text-sm text-muted-foreground mt-1">
                        Upload and analyse a file first, then return here to reconstruct its lifecycle.
                    </p>
                </div>
            </div>
        );
    }

    const vc = VERDICT_CONFIG[report.verdict];
    const VIcon = vc.icon;

    const downloadJSON = () => {
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `lifecycle_${report.file_name.replace(/[^a-z0-9]/gi, '_')}.json`;
        a.click(); URL.revokeObjectURL(url);
    };

    const critIc = report.anomaly_counts;
    const ce = report.creation_event;
    const ceIntegrity = CREATION_INTEGRITY[ce.integrity];
    const CEIcon = ceIntegrity.icon;

    return (
        <div className="max-w-5xl mx-auto space-y-4">

            {/* ── Header ── */}
            <div className="flex items-start justify-between flex-wrap gap-3">
                <div>
                    <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-widest mb-1">
                        Lifecycle Chronology · {new Date(report.analysed_at).toUTCString()}
                    </p>
                    <h1 className="text-xl font-bold text-foreground truncate max-w-xl">{report.file_name}</h1>
                    <p className="text-[11px] text-muted-foreground mt-0.5 font-mono">SHA-256: {report.sha256}</p>
                </div>
                <div className="flex gap-2 flex-wrap">
                    <Button id="toggle-lifecycle-json" variant="outline" size="sm" className="gap-1.5"
                        onClick={() => setShowJSON(v => !v)}>
                        <Code2 className="h-3.5 w-3.5" /> {showJSON ? 'Hide' : 'View'} JSON
                    </Button>
                    <Button id="download-lifecycle" size="sm" className="gap-1.5" onClick={downloadJSON}>
                        <Download className="h-3.5 w-3.5" /> Download
                    </Button>
                </div>
            </div>

            {/* ── Integrity dashboard ── */}
            <Card className={`border ${vc.border} ${vc.bg}`}>
                <CardContent className="p-4 flex items-center gap-5 flex-wrap">
                    <IntegrityRing score={report.integrity_score} />
                    <div className="flex-1 min-w-[200px]">
                        <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-0.5">Lifecycle Integrity</p>
                        <div className={`flex items-center gap-2 ${vc.color}`}>
                            <VIcon className="h-5 w-5" />
                            <p className="text-2xl font-black">{vc.label}</p>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed max-w-lg">{report.verdict_explanation}</p>
                    </div>
                    {/* Anomaly counts */}
                    <div className="flex gap-3 flex-wrap">
                        {(Object.entries(critIc) as [AnomalySeverity, number][])
                            .filter(([, v]) => v > 0)
                            .map(([sev, count]) => (
                                <div key={sev} className="text-center">
                                    <p className={`text-lg font-black font-mono ${SEV_CONFIG[sev].color}`}>{count}</p>
                                    <p className="text-[9px] uppercase tracking-wider text-muted-foreground">{sev}</p>
                                </div>
                            ))}
                        {report.tampering_events.length === 0 && (
                            <div className="flex items-center gap-1.5 text-emerald-400 text-xs">
                                <CheckCircle className="h-4 w-4" /> No anomalies
                            </div>
                        )}
                    </div>
                </CardContent>
            </Card>

            {/* ── Detected mechanisms pills ── */}
            {report.detected_mechanisms.length > 0 && (
                <div className="flex flex-wrap gap-2">
                    {report.detected_mechanisms.map(m => (
                        <span key={m} className="text-[11px] px-2.5 py-1 rounded-lg bg-muted border border-border/50 text-muted-foreground font-medium">
                            {MECHANISM_LABEL[m]}
                        </span>
                    ))}
                </div>
            )}

            {/* ══ 1. CREATION EVENT ════════════════════════════════════════════ */}
            <SectionCard icon={Calendar} iconColor="text-blue-400" title="1 · Creation Event">
                <div className={`flex items-start gap-4 p-4 rounded-xl border ${ce.integrity === 'intact' ? 'border-emerald-500/30 bg-emerald-500/5' :
                        ce.integrity === 'compromised' ? 'border-red-500/30 bg-red-500/5' :
                            'border-yellow-500/25 bg-yellow-500/5'
                    }`}>
                    <div className="flex flex-col items-center gap-1">
                        <CEIcon className={`h-5 w-5 ${ceIntegrity.color}`} />
                        <span className={`text-[9px] uppercase tracking-wider font-bold ${ceIntegrity.color}`}>{ceIntegrity.label}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                        <p className="text-xs text-muted-foreground">Best-Estimated Creation UTC</p>
                        <p className="text-sm font-mono font-bold text-foreground mt-0.5">
                            {ce.utc ?? '— not determinable —'}
                        </p>
                        <p className="text-[11px] text-muted-foreground mt-1">
                            Authority source: <span className="font-mono">{ce.authority_source}</span>
                        </p>
                        {ce.corroborating_sources.length > 0 && (
                            <p className="text-[11px] text-muted-foreground">
                                Corroborated by: <span className="font-mono">{ce.corroborating_sources.join(', ')}</span>
                            </p>
                        )}
                        {/* Confidence bar */}
                        <div className="mt-2 flex items-center gap-2">
                            <span className="text-[10px] text-muted-foreground">Confidence</span>
                            <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                                <div className="h-full rounded-full transition-all"
                                    style={{ width: `${ce.confidence}%`, background: INTEGRITY_COLOR(ce.confidence) }} />
                            </div>
                            <span className="text-[10px] font-mono font-bold" style={{ color: INTEGRITY_COLOR(ce.confidence) }}>
                                {ce.confidence}%
                            </span>
                        </div>
                        {ce.notes.length > 0 && (
                            <div className="mt-2 space-y-1">
                                {ce.notes.map((n, i) => (
                                    <p key={i} className="text-[11px] text-muted-foreground">{n}</p>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </SectionCard>

            {/* ══ 2. MODIFICATION CHAIN (TIMELINE) ═════════════════════════════ */}
            <SectionCard icon={GitCommit} iconColor="text-emerald-400" title={`2 · Modification Chain — ${report.timeline.length} timestamp signal${report.timeline.length !== 1 ? 's' : ''}`}>
                {report.timeline.length === 0 ? (
                    <p className="text-xs text-muted-foreground italic">No timestamp metadata found in this file.</p>
                ) : (
                    <div className="mt-1">
                        {report.timeline.map((ev, i) => (
                            <TimelineNode key={ev.id} event={ev} isLast={i === report.timeline.length - 1} />
                        ))}
                    </div>
                )}
            </SectionCard>

            {/* ══ 3. EDITING GAPS ══════════════════════════════════════════════ */}
            <SectionCard icon={Minus} iconColor="text-orange-400" title={`3 · Editing Gaps — ${report.editing_gaps.length} interval${report.editing_gaps.length !== 1 ? 's' : ''}`}>
                {report.editing_gaps.length === 0 ? (
                    <p className="text-xs text-muted-foreground italic">Insufficient timestamps to compute gaps.</p>
                ) : (
                    <div className="space-y-2">
                        {/* Legend */}
                        <div className="flex flex-wrap gap-3 text-[10px] text-muted-foreground mb-3">
                            {Object.entries(GAP_CONFIG).map(([k, v]) => (
                                <span key={k} className="flex items-center gap-1">
                                    <span className={`inline-block h-2 w-2 rounded-full ${v.dot}`} />
                                    {k.replace(/_/g, ' ')}
                                </span>
                            ))}
                        </div>
                        {report.editing_gaps.map(g => <GapRow key={g.id} gap={g} />)}
                    </div>
                )}
            </SectionCard>

            {/* ══ 4. TIMEZONE SIGNALS ══════════════════════════════════════════ */}
            <SectionCard icon={Globe} iconColor="text-cyan-400"
                title={`4 · Timezone Signals${report.timezone_conflict ? ' ⚠ CONFLICT' : ''}`}>
                {report.timezone_signals.length === 0 ? (
                    <p className="text-xs text-muted-foreground italic">No timezone metadata found.</p>
                ) : (
                    <div className="space-y-2">
                        {report.timezone_conflict && (
                            <div className="flex items-start gap-2 p-3 rounded-lg border border-yellow-500/30 bg-yellow-500/5 mb-3">
                                <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0 mt-0.5" />
                                <p className="text-xs text-foreground">
                                    Conflicting timezone offsets detected across metadata fields. A difference greater than 60 minutes between signals indicates the file was created or edited on systems configured for different time zones.
                                </p>
                            </div>
                        )}
                        {report.timezone_signals.map((tz, i) => (
                            <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg bg-muted/30 border border-border/30">
                                <Globe className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
                                <div className="flex-1 min-w-0">
                                    <p className="text-[10px] font-mono text-muted-foreground">{tz.source}</p>
                                    <p className="text-xs font-mono font-bold text-foreground">{tz.raw_value}</p>
                                    {tz.region_hint && (
                                        <p className="text-[11px] text-muted-foreground mt-0.5">{tz.region_hint}</p>
                                    )}
                                </div>
                                {tz.utc_offset_minutes !== null && (
                                    <span className="text-xs font-mono text-cyan-400 shrink-0">
                                        UTC{tz.utc_offset_minutes >= 0 ? '+' : ''}{(tz.utc_offset_minutes / 60).toFixed(1).replace('.0', '')}
                                    </span>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </SectionCard>

            {/* ══ 5. TAMPERING EVENTS ══════════════════════════════════════════ */}
            <SectionCard icon={ShieldAlert} iconColor="text-red-400"
                title={`5 · Tampering & Anomaly Detection — ${report.tampering_events.length} finding${report.tampering_events.length !== 1 ? 's' : ''}`}
                defaultOpen>
                {report.tampering_events.length === 0 ? (
                    <div className="flex items-center gap-2 text-emerald-400 text-sm py-2">
                        <CheckCircle className="h-4 w-4 shrink-0" />
                        No tampering indicators found. All timestamp signals appear consistent.
                    </div>
                ) : (
                    <div className="space-y-3">
                        {/* Sort: critical first */}
                        {[...report.tampering_events]
                            .sort((a, b) => {
                                const order: Record<AnomalySeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                                return order[a.severity] - order[b.severity];
                            })
                            .map(t => <TamperingCard key={t.id} event={t} />)}
                    </div>
                )}
            </SectionCard>

            {/* ── JSON output ── */}
            {showJSON && (
                <Card>
                    <CardHeader className="pb-2 flex flex-row items-center gap-2">
                        <Code2 className="h-4 w-4 text-primary" />
                        <CardTitle className="text-sm">Lifecycle Chronology JSON</CardTitle>
                        <Badge variant="secondary" className="ml-auto font-mono text-xs">
                            {JSON.stringify(report).length.toLocaleString()} chars
                        </Badge>
                    </CardHeader>
                    <CardContent className="p-0">
                        <pre className="text-[11px] font-mono leading-relaxed text-emerald-300 bg-[hsl(222,47%,5%)] p-4 rounded-b-xl overflow-auto max-h-[70vh] whitespace-pre-wrap break-all">
                            {JSON.stringify(report, null, 2)}
                        </pre>
                    </CardContent>
                </Card>
            )}
        </div>
    );
}
