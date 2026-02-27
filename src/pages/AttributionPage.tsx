import { useMemo, useState } from 'react';
import { useForensic } from '@/context/ForensicContext';
import { normalizeMetadata } from '@/lib/metadata-normalizer';
import { analyzeAttribution, AttributionReport, ConfidenceTier, EvidenceField, IdentityConflict } from '@/lib/attribution-analyst';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
    User, Building2, Cpu, AtSign, GitCompare, AlertTriangle,
    CheckCircle, ChevronDown, ChevronUp, Download, Code2,
    Fingerprint, Shield, Zap, Copy, Check, Info, XCircle,
    TrendingUp, Search
} from 'lucide-react';

// ── Confidence tier visuals ────────────────────────────────────────────────
const TIER_CONFIG: Record<ConfidenceTier, { label: string; color: string; bg: string; border: string }> = {
    definitive: { label: 'Definitive', color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
    high: { label: 'High', color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30' },
    moderate: { label: 'Moderate', color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30' },
    low: { label: 'Low', color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
    none: { label: 'None', color: 'text-muted-foreground', bg: 'bg-muted/30', border: 'border-border/30' },
};

const CONFLICT_SEVERITY: Record<string, { icon: typeof AlertTriangle; color: string; bg: string; border: string }> = {
    high: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/5', border: 'border-red-500/25' },
    medium: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/5', border: 'border-yellow-500/25' },
    low: { icon: Info, color: 'text-blue-400', bg: 'bg-blue-500/5', border: 'border-blue-500/20' },
};

// ── Sub-components ─────────────────────────────────────────────────────────

function ConfidenceBadge({ tier, score }: { tier: ConfidenceTier; score: number }) {
    const cfg = TIER_CONFIG[tier];
    return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${cfg.color} ${cfg.bg} ${cfg.border}`}>
            <TrendingUp className="h-3 w-3" />
            {cfg.label} · {score}/100
        </span>
    );
}

function ScoreBar({ score, tier }: { score: number; tier: ConfidenceTier }) {
    const cfg = TIER_CONFIG[tier];
    return (
        <div className="mt-2 flex items-center gap-2">
            <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                        width: `${score}%`,
                        background: tier === 'definitive' ? '#22c55e'
                            : tier === 'high' ? '#60a5fa'
                                : tier === 'moderate' ? '#eab308'
                                    : tier === 'low' ? '#f97316'
                                        : '#6b7280',
                    }}
                />
            </div>
            <span className={`text-[10px] font-mono font-bold ${cfg.color}`}>{score}%</span>
        </div>
    );
}

function EvidenceTable({ fields }: { fields: EvidenceField[] }) {
    if (fields.length === 0) return <p className="text-xs text-muted-foreground italic">No supporting fields</p>;
    return (
        <div className="space-y-1.5 mt-2">
            {fields.map((f, i) => (
                <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-muted/40 border border-border/30">
                    <div className="flex-1 min-w-0">
                        <p className="text-[10px] text-muted-foreground font-mono">{f.field}</p>
                        <p className="text-xs text-foreground font-medium break-all">{f.value}</p>
                        <p className="text-[10px] text-muted-foreground italic mt-0.5">{f.source}</p>
                    </div>
                    <span className="shrink-0 text-[10px] font-mono font-bold text-primary bg-primary/10 border border-primary/20 px-1.5 py-0.5 rounded">
                        +{f.weight}
                    </span>
                </div>
            ))}
        </div>
    );
}

function CollapsibleCard({
    id, icon: Icon, iconColor, title, score, tier, children,
}: {
    id: string;
    icon: React.ComponentType<{ className?: string }>;
    iconColor: string;
    title: string;
    score: number;
    tier: ConfidenceTier;
    children: React.ReactNode;
}) {
    const [open, setOpen] = useState(true);
    const cfg = TIER_CONFIG[tier];
    return (
        <Card className={`overflow-hidden border ${cfg.border} transition-all`}>
            <button
                id={`section-${id}`}
                className="w-full flex items-center gap-3 px-5 py-3 border-b border-border/50 hover:bg-accent/20 transition-colors text-left"
                onClick={() => setOpen(o => !o)}
            >
                <span className={`h-7 w-7 flex items-center justify-center rounded-lg ${cfg.bg} border ${cfg.border}`}>
                    <Icon className={`h-4 w-4 ${iconColor}`} />
                </span>
                <span className="text-sm font-semibold flex-1 text-foreground">{title}</span>
                <ConfidenceBadge tier={tier} score={score} />
                {open ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground ml-1" />
                    : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground ml-1" />}
            </button>
            {open && <CardContent className="p-5">{children}</CardContent>}
        </Card>
    );
}

function Field({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) {
    if (!value) return (
        <div className="flex items-start gap-3 py-1.5 border-b border-border/30 last:border-0">
            <span className="text-[11px] text-muted-foreground shrink-0 w-44">{label}</span>
            <span className="text-[11px] text-muted-foreground italic">null — not found</span>
        </div>
    );
    return (
        <div className="flex items-start gap-3 py-1.5 border-b border-border/30 last:border-0">
            <span className="text-[11px] text-muted-foreground shrink-0 w-44 pt-0.5">{label}</span>
            <span className={`text-xs break-all ${mono ? 'font-mono text-emerald-300' : 'font-medium text-foreground'}`}>
                {value}
            </span>
        </div>
    );
}

function CopyBtn({ text }: { text: string }) {
    const [ok, setOk] = useState(false);
    return (
        <button onClick={() => { navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1800); }}
            className="text-muted-foreground hover:text-foreground transition-colors shrink-0" title="Copy">
            {ok ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
        </button>
    );
}

function TagList({ items, color = '' }: { items: string[]; color?: string }) {
    if (!items.length) return <p className="text-[11px] text-muted-foreground italic">None</p>;
    return (
        <div className="flex flex-wrap gap-1.5 mt-1">
            {items.map((v, i) => (
                <span key={i} className={`text-[11px] font-mono px-2 py-0.5 rounded bg-muted border border-border/50 ${color}`}>{v}</span>
            ))}
        </div>
    );
}

function SectionLabel({ text }: { text: string }) {
    return <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-2 mt-4 first:mt-0">{text}</p>;
}

// ── Conflict Card ─────────────────────────────────────────────────────────
function ConflictCard({ conflict }: { conflict: IdentityConflict }) {
    const cfg = CONFLICT_SEVERITY[conflict.severity];
    const Icon = cfg.icon;
    return (
        <div className={`p-3 rounded-xl border ${cfg.border} ${cfg.bg} space-y-1.5`}>
            <div className="flex items-center gap-2">
                <Icon className={`h-3.5 w-3.5 ${cfg.color} shrink-0`} />
                <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${cfg.color} border-current`}>
                    {conflict.severity.toUpperCase()}
                </Badge>
                <Badge variant="secondary" className="text-[10px] px-1.5 py-0 font-mono">
                    {conflict.type.replace(/_/g, ' ')}
                </Badge>
            </div>
            <p className="text-xs text-foreground leading-relaxed">{conflict.description}</p>
            <div className="flex flex-wrap gap-1 mt-1">
                {conflict.fieldsInvolved.map((f, i) => (
                    <span key={i} className="text-[10px] font-mono px-1.5 py-0 rounded bg-muted border border-border/50 text-muted-foreground">{f}</span>
                ))}
            </div>
        </div>
    );
}

// ── Donut gauge ───────────────────────────────────────────────────────────
function Donut({ score, tier }: { score: number; tier: ConfidenceTier }) {
    const r = 44;
    const circ = 2 * Math.PI * r;
    const color = tier === 'definitive' ? '#22c55e'
        : tier === 'high' ? '#60a5fa'
            : tier === 'moderate' ? '#eab308'
                : tier === 'low' ? '#f97316'
                    : '#6b7280';
    return (
        <div className="relative flex items-center justify-center w-24 h-24">
            <svg className="absolute inset-0 -rotate-90" width="96" height="96" viewBox="0 0 96 96">
                <circle cx="48" cy="48" r={r} fill="none" stroke="hsl(222,30%,14%)" strokeWidth="8" />
                <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={`${(score / 100) * circ} ${circ}`}
                    style={{ filter: `drop-shadow(0 0 4px ${color})`, transition: 'stroke-dasharray 1s ease' }}
                />
            </svg>
            <div className="text-center z-10">
                <p className="text-xl font-black font-mono tabular-nums" style={{ color }}>{score}</p>
                <p className="text-[9px] text-muted-foreground uppercase tracking-widest">/100</p>
            </div>
        </div>
    );
}

// ── Main Page ──────────────────────────────────────────────────────────────
export default function AttributionPage() {
    const { currentAnalysis } = useForensic();
    const [showJSON, setShowJSON] = useState(false);

    const report: AttributionReport | null = useMemo(() => {
        if (!currentAnalysis) return null;
        const normalized = normalizeMetadata(currentAnalysis);
        return analyzeAttribution(normalized);
    }, [currentAnalysis]);

    if (!currentAnalysis || !report) {
        return (
            <div className="flex flex-col items-center justify-center h-[60vh] gap-4 text-center">
                <div className="p-5 rounded-2xl bg-muted">
                    <Fingerprint className="h-12 w-12 text-muted-foreground/30" />
                </div>
                <div>
                    <p className="font-medium text-foreground">No analysis loaded</p>
                    <p className="text-sm text-muted-foreground mt-1">
                        Upload and analyse a file first, then return here for attribution analysis.
                    </p>
                </div>
            </div>
        );
    }

    const downloadJSON = () => {
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `attribution_${report.file_name.replace(/[^a-z0-9]/gi, '_')}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const r = report;
    const au = r.author;
    const or = r.organization;
    const dv = r.device_ownership;
    const ua = r.username_analysis;
    const cm = r.creator_modifier;

    return (
        <div className="max-w-5xl mx-auto space-y-4">

            {/* ── Header ── */}
            <div className="flex items-start justify-between flex-wrap gap-3">
                <div>
                    <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-widest mb-1">
                        Digital Attribution Analysis · {new Date(r.analysed_at).toUTCString()}
                    </p>
                    <h1 className="text-xl font-bold text-foreground truncate max-w-xl">{r.file_name}</h1>
                    <p className="text-[11px] text-muted-foreground mt-0.5 font-mono">SHA-256: {r.sha256}</p>
                </div>
                <div className="flex gap-2 flex-wrap">
                    <Button id="toggle-attr-json" variant="outline" size="sm" className="gap-1.5"
                        onClick={() => setShowJSON(v => !v)}>
                        <Code2 className="h-3.5 w-3.5" /> {showJSON ? 'Hide' : 'View'} JSON
                    </Button>
                    <Button id="download-attribution" size="sm" className="gap-1.5" onClick={downloadJSON}>
                        <Download className="h-3.5 w-3.5" /> Download
                    </Button>
                </div>
            </div>

            {/* ── Overall Confidence Panel ── */}
            <Card className={`border ${TIER_CONFIG[r.overall_confidence_tier].border} ${TIER_CONFIG[r.overall_confidence_tier].bg}`}>
                <CardContent className="p-4 flex items-center gap-5 flex-wrap">
                    <Donut score={r.overall_confidence_score} tier={r.overall_confidence_tier} />
                    <div className="flex-1 min-w-[200px]">
                        <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Overall Attribution Confidence</p>
                        <p className={`text-2xl font-black ${TIER_CONFIG[r.overall_confidence_tier].color}`}>
                            {TIER_CONFIG[r.overall_confidence_tier].label}
                        </p>
                        <div className="flex flex-wrap gap-3 mt-3">
                            {[
                                { label: 'Author', score: au.confidence_score, tier: au.confidence_tier },
                                { label: 'Org', score: or.confidence_score, tier: or.confidence_tier },
                                { label: 'Device', score: dv.confidence_score, tier: dv.confidence_tier },
                                { label: 'Username', score: ua.confidence_score, tier: ua.confidence_tier },
                                { label: 'Roles', score: cm.confidence_score, tier: cm.confidence_tier },
                            ].map(({ label, score, tier: t }) => (
                                <div key={label} className="text-center">
                                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
                                    <p className={`text-sm font-bold font-mono ${TIER_CONFIG[t].color}`}>{score}</p>
                                </div>
                            ))}
                            <div className="text-center">
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Conflicts</p>
                                <p className={`text-sm font-bold font-mono ${r.possible_identity_conflicts.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                    {r.possible_identity_conflicts.length}
                                </p>
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* ══ 1. AUTHOR IDENTITY ════════════════════════════════════════════ */}
            <CollapsibleCard id="author" icon={User} iconColor="text-blue-400"
                title="1 · Probable Author Identity" score={au.confidence_score} tier={au.confidence_tier}>
                <div className="space-y-0">
                    <Field label="Probable Name" value={au.probable_name} />
                    <Field label="Probable Email" value={au.probable_email} mono />
                    <Field label="Confidence Tier" value={TIER_CONFIG[au.confidence_tier].label} />
                </div>
                <ScoreBar score={au.confidence_score} tier={au.confidence_tier} />

                <SectionLabel text="Reasoning" />
                <p className="text-xs text-muted-foreground leading-relaxed bg-muted/30 rounded-lg p-3 border border-border/30">
                    {au.reasoning}
                </p>

                <SectionLabel text="Supporting Metadata Fields" />
                <EvidenceTable fields={au.supporting_metadata_fields} />
            </CollapsibleCard>

            {/* ══ 2. ORGANIZATION AFFILIATION ══════════════════════════════════ */}
            <CollapsibleCard id="org" icon={Building2} iconColor="text-violet-400"
                title="2 · Organization Affiliation" score={or.confidence_score} tier={or.confidence_tier}>
                <div className="space-y-0">
                    <Field label="Probable Organization" value={or.probable_organization} />
                    <Field label="Org Domain" value={or.org_domain} mono />
                    <Field label="Confidence Tier" value={TIER_CONFIG[or.confidence_tier].label} />
                </div>
                <ScoreBar score={or.confidence_score} tier={or.confidence_tier} />

                <SectionLabel text="Reasoning" />
                <p className="text-xs text-muted-foreground leading-relaxed bg-muted/30 rounded-lg p-3 border border-border/30">
                    {or.reasoning}
                </p>

                <SectionLabel text="Supporting Metadata Fields" />
                <EvidenceTable fields={or.supporting_metadata_fields} />
            </CollapsibleCard>

            {/* ══ 3. DEVICE OWNERSHIP ══════════════════════════════════════════ */}
            <CollapsibleCard id="device" icon={Cpu} iconColor="text-cyan-400"
                title="3 · Device Ownership Indicators" score={dv.confidence_score} tier={dv.confidence_tier}>
                <div className="space-y-0">
                    <Field label="Probable Owner" value={dv.probable_owner} />
                    <Field label="Device Fingerprint" value={dv.device_fingerprint} />
                    <Field label="OS Fingerprint" value={dv.os_fingerprint} />
                    <Field label="Username on Device" value={dv.username_on_device} mono />
                    <Field label="Confidence Tier" value={TIER_CONFIG[dv.confidence_tier].label} />
                </div>
                <ScoreBar score={dv.confidence_score} tier={dv.confidence_tier} />

                <SectionLabel text="Reasoning" />
                <p className="text-xs text-muted-foreground leading-relaxed bg-muted/30 rounded-lg p-3 border border-border/30">
                    {dv.reasoning}
                </p>

                <SectionLabel text="Supporting Metadata Fields" />
                <EvidenceTable fields={dv.supporting_metadata_fields} />
            </CollapsibleCard>

            {/* ══ 4. RECURRING USERNAMES ════════════════════════════════════════ */}
            <CollapsibleCard id="usernames" icon={AtSign} iconColor="text-emerald-400"
                title="4 · Recurring Username Analysis" score={ua.confidence_score} tier={ua.confidence_tier}>
                <div className="space-y-0">
                    <Field label="Canonical Username" value={ua.canonical_username} mono />
                    <Field label="Email Username" value={ua.email_username} mono />
                    <Field label="Path Username" value={ua.path_username} mono />
                    <div className="flex items-start gap-3 py-1.5 border-b border-border/30">
                        <span className="text-[11px] text-muted-foreground shrink-0 w-44">Name ↔ Username Match</span>
                        {ua.name_username_match
                            ? <span className="flex items-center gap-1 text-xs text-emerald-400"><CheckCircle className="h-3 w-3" /> Yes — aliases likely the same person</span>
                            : <span className="flex items-center gap-1 text-xs text-muted-foreground"><XCircle className="h-3 w-3" /> No — no clear slug match</span>}
                    </div>
                    <Field label="Confidence Tier" value={TIER_CONFIG[ua.confidence_tier].label} />
                </div>
                <ScoreBar score={ua.confidence_score} tier={ua.confidence_tier} />

                <SectionLabel text="Recurring Usernames (≥2 sources)" />
                <TagList items={ua.recurring} color="text-emerald-400" />

                <SectionLabel text="All Detected Usernames" />
                <TagList items={ua.all_usernames} color="text-blue-300" />

                <SectionLabel text="Supporting Metadata Fields" />
                <EvidenceTable fields={ua.supporting_metadata_fields} />
            </CollapsibleCard>

            {/* ══ 5. CREATOR vs MODIFIER ═══════════════════════════════════════ */}
            <CollapsibleCard id="roles" icon={GitCompare} iconColor="text-orange-400"
                title="5 · Creator vs Modifier Distinction" score={cm.confidence_score} tier={cm.confidence_tier}>

                {/* Visual role split diagram */}
                <div className={`flex items-center gap-3 p-3 rounded-xl border mb-4 ${cm.role_split ? 'border-yellow-500/30 bg-yellow-500/5' : 'border-emerald-500/25 bg-emerald-500/5'}`}>
                    <div className="text-center flex-1">
                        <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Creator</p>
                        <p className={`text-sm font-bold ${cm.creator_name ? 'text-foreground' : 'text-muted-foreground italic'}`}>
                            {cm.creator_name ?? '— unknown —'}
                        </p>
                        {cm.creator_source && <p className="text-[10px] font-mono text-muted-foreground mt-0.5">{cm.creator_source}</p>}
                    </div>
                    <div className="flex flex-col items-center">
                        <GitCompare className={`h-5 w-5 ${cm.role_split ? 'text-yellow-400' : 'text-emerald-400'}`} />
                        <p className="text-[9px] uppercase tracking-widest mt-1 text-muted-foreground">
                            {cm.role_split ? 'split' : cm.same_person ? 'same' : 'unknown'}
                        </p>
                    </div>
                    <div className="text-center flex-1">
                        <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Modifier</p>
                        <p className={`text-sm font-bold ${cm.modifier_name ? 'text-foreground' : 'text-muted-foreground italic'}`}>
                            {cm.modifier_name ?? '— not detected —'}
                        </p>
                        {cm.modifier_introduced_at && (
                            <p className="text-[10px] font-mono text-muted-foreground mt-0.5">{cm.modifier_introduced_at.slice(0, 10)}</p>
                        )}
                    </div>
                </div>

                <div className="space-y-0">
                    <div className="flex items-start gap-3 py-1.5 border-b border-border/30">
                        <span className="text-[11px] text-muted-foreground shrink-0 w-44">Role Split</span>
                        {cm.role_split
                            ? <Badge variant="destructive" className="text-[10px]">Yes — different people</Badge>
                            : cm.same_person
                                ? <Badge variant="secondary" className="text-[10px] text-emerald-400 border-emerald-500/30">No — same person</Badge>
                                : <Badge variant="outline" className="text-[10px]">Unknown</Badge>}
                    </div>
                    <Field label="Modifier Introduced" value={cm.modifier_introduced_at} mono />
                    <Field label="Confidence Tier" value={TIER_CONFIG[cm.confidence_tier].label} />
                </div>
                <ScoreBar score={cm.confidence_score} tier={cm.confidence_tier} />

                <SectionLabel text="Reasoning" />
                <p className="text-xs text-muted-foreground leading-relaxed bg-muted/30 rounded-lg p-3 border border-border/30">
                    {cm.reasoning}
                </p>

                <SectionLabel text="Supporting Metadata Fields" />
                <EvidenceTable fields={cm.supporting_metadata_fields} />
            </CollapsibleCard>

            {/* ══ 6. IDENTITY CONFLICTS ═════════════════════════════════════════ */}
            <Card className={`overflow-hidden border ${r.possible_identity_conflicts.length > 0 ? 'border-red-500/25' : 'border-emerald-500/20'}`}>
                <CardHeader className="pb-2 px-5 pt-4 flex flex-row items-center gap-2">
                    <Shield className={`h-4 w-4 ${r.possible_identity_conflicts.length > 0 ? 'text-red-400' : 'text-emerald-400'}`} />
                    <CardTitle className="text-sm font-semibold">6 · Possible Identity Conflicts</CardTitle>
                    {r.possible_identity_conflicts.length > 0
                        ? <Badge variant="destructive" className="ml-auto text-[10px]">{r.possible_identity_conflicts.length} conflict{r.possible_identity_conflicts.length > 1 ? 's' : ''}</Badge>
                        : <Badge variant="secondary" className="ml-auto text-[10px] text-emerald-400">Clean — no conflicts</Badge>}
                </CardHeader>
                <CardContent className="p-5">
                    {r.possible_identity_conflicts.length === 0 ? (
                        <div className="flex items-center gap-2 text-emerald-400 text-xs">
                            <CheckCircle className="h-4 w-4 shrink-0" />
                            No identity conflicts detected. All metadata sources point to a consistent identity.
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {r.possible_identity_conflicts.map(c => <ConflictCard key={c.id} conflict={c} />)}
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* ══ 7. OSINT LEADS ════════════════════════════════════════════════ */}
            {r.osint_leads.length > 0 && (
                <Card className="border border-yellow-500/20 bg-yellow-500/3">
                    <CardHeader className="pb-2 px-5 pt-4 flex flex-row items-center gap-2">
                        <Search className="h-4 w-4 text-yellow-400" />
                        <CardTitle className="text-sm font-semibold">OSINT Investigation Leads</CardTitle>
                        <Badge variant="outline" className="ml-auto text-[10px] text-yellow-400 border-yellow-500/30">
                            {r.osint_leads.length} lead{r.osint_leads.length > 1 ? 's' : ''}
                        </Badge>
                    </CardHeader>
                    <CardContent className="p-5">
                        <div className="space-y-2">
                            {r.osint_leads.map((lead, i) => (
                                <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-muted/40 border border-border/30">
                                    <Zap className="h-3.5 w-3.5 text-yellow-400 mt-0.5 shrink-0" />
                                    <span className="text-xs text-foreground">{lead}</span>
                                    <CopyBtn text={lead} />
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* ── JSON output ── */}
            {showJSON && (
                <Card>
                    <CardHeader className="pb-2 flex flex-row items-center gap-2">
                        <Code2 className="h-4 w-4 text-primary" />
                        <CardTitle className="text-sm">Attribution Report JSON</CardTitle>
                        <Badge variant="secondary" className="ml-auto font-mono text-xs">
                            {JSON.stringify(r).length.toLocaleString()} chars
                        </Badge>
                    </CardHeader>
                    <CardContent className="p-0">
                        <pre className="text-[11px] font-mono leading-relaxed text-emerald-300 bg-[hsl(222,47%,5%)] p-4 rounded-b-xl overflow-auto max-h-[70vh] whitespace-pre-wrap break-all">
                            {JSON.stringify(r, null, 2)}
                        </pre>
                    </CardContent>
                </Card>
            )}

        </div>
    );
}
