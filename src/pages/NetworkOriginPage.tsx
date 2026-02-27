import { useMemo, useState, useEffect } from 'react';
import { useForensic } from '@/context/ForensicContext';
import {
    analyzeNetworkOrigin,
    NetworkOriginReport,
    NetworkArtifact,
    OriginClass,
    ExposureSeverity,
} from '@/lib/network-origin-analyzer';
import { geolocateIPs, IPGeoResult, formatGeoSummary } from '@/lib/ip-geolocator';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
    Globe, Server, HardDrive, HelpCircle, Download, Code2,
    AlertTriangle, CheckCircle, ChevronDown, ChevronUp,
    Wifi, WifiOff, Cloud, FolderOpen, Mail, Link, Network,
    Eye, ShieldAlert, Copy, Check, Filter, LayoutGrid,
    MapPin, Building2, Radio, ShieldCheck, Loader2, User,
} from 'lucide-react';

// ── Visual config ──────────────────────────────────────────────────────────
const CLASS_CONFIG: Record<OriginClass, {
    label: string; icon: typeof Globe;
    color: string; bg: string; border: string; dot: string;
}> = {
    public_origin: { label: 'Public Origin', icon: Globe, color: 'text-red-400', bg: 'bg-red-500/8', border: 'border-red-500/25', dot: 'bg-red-400' },
    private_network: { label: 'Private Network', icon: Server, color: 'text-yellow-400', bg: 'bg-yellow-500/8', border: 'border-yellow-500/25', dot: 'bg-yellow-400' },
    local_machine: { label: 'Local Machine', icon: HardDrive, color: 'text-blue-400', bg: 'bg-blue-500/8', border: 'border-blue-500/25', dot: 'bg-blue-400' },
    unknown_source: { label: 'Unknown Source', icon: HelpCircle, color: 'text-muted-foreground', bg: 'bg-muted/30', border: 'border-border/40', dot: 'bg-muted-foreground' },
};

const SEVERITY_CONFIG: Record<ExposureSeverity, { label: string; color: string; ring: string }> = {
    critical: { label: 'CRITICAL', color: 'text-purple-400', ring: 'border-purple-500/40 bg-purple-500/8' },
    high: { label: 'HIGH', color: 'text-red-400', ring: 'border-red-500/30   bg-red-500/5' },
    medium: { label: 'MEDIUM', color: 'text-yellow-400', ring: 'border-yellow-500/30 bg-yellow-500/5' },
    low: { label: 'LOW', color: 'text-blue-400', ring: 'border-blue-500/25  bg-blue-500/5' },
    info: { label: 'INFO', color: 'text-muted-foreground', ring: 'border-border/30 bg-muted/20' },
};

const CATEGORY_ICON: Record<NetworkArtifact['category'], typeof Globe> = {
    ip_address: Server,
    cloud_storage: Cloud,
    remote_url: Link,
    unc_path: FolderOpen,
    internal_path: FolderOpen,
    shared_drive: FolderOpen,
    hostname: Globe,
    email_domain: Mail,
};

const CATEGORY_LABEL: Record<NetworkArtifact['category'], string> = {
    ip_address: 'IP Address',
    cloud_storage: 'Cloud Storage',
    remote_url: 'Remote URL',
    unc_path: 'UNC Path',
    internal_path: 'Internal Path',
    shared_drive: 'Shared Drive',
    hostname: 'Hostname',
    email_domain: 'Email Domain',
};

// ── Score ring ─────────────────────────────────────────────────────────────
function RiskRing({ score, sev }: { score: number; sev: ExposureSeverity }) {
    const r = 44;
    const circ = 2 * Math.PI * r;
    const color = sev === 'critical' ? '#a855f7'
        : sev === 'high' ? '#ef4444'
            : sev === 'medium' ? '#eab308'
                : sev === 'low' ? '#60a5fa'
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
                <p className="text-xl font-black font-mono" style={{ color }}>{score}</p>
                <p className="text-[9px] text-muted-foreground uppercase tracking-widest">/100</p>
            </div>
        </div>
    );
}

// ── Stat tile ─────────────────────────────────────────────────────────────
function StatTile({ cls, count }: { cls: OriginClass; count: number }) {
    const cfg = CLASS_CONFIG[cls];
    const Icon = cfg.icon;
    return (
        <div className={`flex items-center gap-3 p-3 rounded-xl border ${cfg.border} ${cfg.bg}`}>
            <span className={`h-8 w-8 flex items-center justify-center rounded-lg ${cfg.bg} border ${cfg.border}`}>
                <Icon className={`h-4 w-4 ${cfg.color}`} />
            </span>
            <div>
                <p className={`text-lg font-black font-mono ${cfg.color}`}>{count}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider leading-tight">{cfg.label}</p>
            </div>
        </div>
    );
}

// ── Copy button ────────────────────────────────────────────────────────────
function CopyBtn({ text }: { text: string }) {
    const [ok, setOk] = useState(false);
    return (
        <button onClick={() => { navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1800); }}
            className="text-muted-foreground hover:text-foreground transition-colors shrink-0 p-1" title="Copy">
            {ok ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
        </button>
    );
}

// ── IP Geo Badge ───────────────────────────────────────────────────────────
function IPGeoBadge({ geo }: { geo: IPGeoResult | undefined }) {
    if (!geo || geo.status !== 'success') return null;
    return (
        <div className="mt-2 flex flex-wrap gap-1.5">
            {geo.country && (
                <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-emerald-400">
                    <MapPin className="h-2.5 w-2.5" />
                    {geo.city ? `${geo.city}, ` : ''}{geo.regionName ? `${geo.regionName}, ` : ''}{geo.country}
                </span>
            )}
            {(geo.org || geo.isp) && (
                <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/25 text-blue-400">
                    <Building2 className="h-2.5 w-2.5" />
                    {geo.org || geo.isp}
                </span>
            )}
            {geo.as && (
                <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-violet-500/10 border border-violet-500/25 text-violet-400">
                    <Radio className="h-2.5 w-2.5" />
                    {geo.as}
                </span>
            )}
            {geo.proxy && (
                <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-orange-500/10 border border-orange-500/25 text-orange-400">
                    <ShieldAlert className="h-2.5 w-2.5" />
                    VPN / Proxy
                </span>
            )}
            {geo.hosting && (
                <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-slate-500/10 border border-slate-500/25 text-slate-400">
                    <Server className="h-2.5 w-2.5" />
                    Datacenter / Hosting
                </span>
            )}
        </div>
    );
}

// ── Artifact Card ─────────────────────────────────────────────────────────
function ArtifactCard({ art, geoMap }: { art: NetworkArtifact; geoMap: Map<string, IPGeoResult> }) {
    const [expanded, setExpanded] = useState(false);
    const clsCfg = CLASS_CONFIG[art.origin_class];
    const sevCfg = SEVERITY_CONFIG[art.exposure_severity];
    const CatIcon = CATEGORY_ICON[art.category];
    const ClassIcon = clsCfg.icon;
    const geo = art.category === 'ip_address' ? geoMap.get(art.raw_value) : undefined;

    return (
        <div className={`rounded-xl border ${clsCfg.border} overflow-hidden transition-all`}>
            {/* Header row */}
            <div className={`flex items-start gap-3 p-3 ${clsCfg.bg}`}>
                {/* Category icon */}
                <span className={`h-8 w-8 flex items-center justify-center rounded-lg bg-background/60 border ${clsCfg.border} shrink-0 mt-0.5`}>
                    <CatIcon className={`h-4 w-4 ${clsCfg.color}`} />
                </span>

                {/* Main content */}
                <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5 mb-1">
                        <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${clsCfg.color} border-current`}>
                            {CATEGORY_LABEL[art.category]}
                        </Badge>
                        <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${sevCfg.color} border-current`}>
                            {sevCfg.label}
                        </Badge>
                        <Badge variant="secondary" className="text-[10px] px-1.5 py-0 ml-auto">
                            {art.confidence}% confidence
                        </Badge>
                    </div>

                    <p className="text-xs font-mono text-foreground break-all leading-snug">{art.normalized_value}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{art.type_label}</p>

                    {/* Geo inline for IPs */}
                    {geo && geo.status === 'success' && (
                        <IPGeoBadge geo={geo} />
                    )}
                </div>

                {/* Origin class badge */}
                <div className="flex flex-col items-end gap-1 shrink-0">
                    <span className={`flex items-center gap-1 text-[9px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${clsCfg.border} ${clsCfg.color}`}>
                        <ClassIcon className="h-2.5 w-2.5" />
                        {clsCfg.label}
                    </span>
                    <div className="flex items-center gap-1">
                        <CopyBtn text={art.raw_value} />
                        <button onClick={() => setExpanded(e => !e)}
                            className="text-muted-foreground hover:text-foreground transition-colors p-1">
                            {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                        </button>
                    </div>
                </div>
            </div>

            {/* Expanded: implication + geo detail + source + details */}
            {expanded && (
                <div className="px-4 pb-4 pt-3 border-t border-border/30 space-y-3 bg-background/40">
                    {/* Full geo details for IPs */}
                    {geo && geo.status === 'success' && (
                        <div>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-2 flex items-center gap-1 font-bold">
                                <MapPin className="h-3 w-3 text-emerald-400" /> Live IP Geolocation
                            </p>
                            <div className="grid grid-cols-2 gap-2 p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/20">
                                {[
                                    ['IP Address', geo.ip],
                                    ['Country', `${geo.country} (${geo.countryCode})`],
                                    ['Region', geo.regionName],
                                    ['City', geo.city || '—'],
                                    ['ZIP/Postal', geo.zip || '—'],
                                    ['Coordinates', `${geo.lat.toFixed(4)}°, ${geo.lon.toFixed(4)}°`],
                                    ['Timezone', geo.timezone],
                                    ['ISP', geo.isp],
                                    ['Organisation', geo.org || '—'],
                                    ['ASN', geo.as],
                                    ['VPN/Proxy', geo.proxy ? '⚠ YES' : 'No'],
                                    ['Hosting/DC', geo.hosting ? '⚠ YES (Datacenter)' : 'No'],
                                ].map(([k, v]) => (
                                    <div key={k} className="flex flex-col">
                                        <span className="text-[9px] text-muted-foreground uppercase tracking-wider">{k}</span>
                                        <span className="text-[11px] font-mono text-foreground break-all">{v}</span>
                                    </div>
                                ))}
                            </div>
                            <p className="text-[10px] text-muted-foreground mt-1.5 italic">
                                Source: ip-api.com · Accuracy: city-level ± 50km · Data may reflect ISP region not physical location
                            </p>
                        </div>
                    )}

                    {/* Exposure implication */}
                    <div>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1 flex items-center gap-1">
                            <Eye className="h-3 w-3" /> Exposure Implication
                        </p>
                        <p className="text-xs text-foreground leading-relaxed bg-muted/30 rounded-lg p-3 border border-border/30">
                            {art.exposure_implication}
                        </p>
                    </div>

                    {/* Source field */}
                    <div className="flex items-center gap-2">
                        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Source Field:</span>
                        <span className="text-[11px] font-mono text-muted-foreground">{art.source_field}</span>
                    </div>

                    {/* Extra details */}
                    {Object.keys(art.details).length > 0 && (
                        <div className="flex flex-wrap gap-2">
                            {Object.entries(art.details).map(([k, v]) => (
                                <div key={k} className="flex items-center gap-1.5 px-2 py-1 rounded bg-muted/40 border border-border/30 text-[10px]">
                                    <span className="text-muted-foreground">{k.replace(/_/g, ' ')}:</span>
                                    <span className="font-mono text-foreground">{v}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// ── Author IP Attribution Panel ────────────────────────────────────────────
function AuthorIPPanel({ publicIPs, geoMap, loading }: {
    publicIPs: string[];
    geoMap: Map<string, IPGeoResult>;
    loading: boolean;
}) {
    if (publicIPs.length === 0) {
        return (
            <Card className="border-slate-700/50 bg-slate-800/20">
                <CardContent className="p-5 flex items-center gap-4">
                    <div className="h-10 w-10 rounded-xl bg-slate-700/50 border border-slate-600/40 flex items-center justify-center shrink-0">
                        <User className="h-5 w-5 text-slate-400" />
                    </div>
                    <div>
                        <p className="text-sm font-semibold text-slate-200">Author IP Attribution</p>
                        <p className="text-xs text-slate-400 mt-0.5">
                            No public IP addresses were found embedded in this file's metadata or content.
                            Author IP attribution is only possible when an IP is directly embedded in the file.
                            IPs are never inferred from external sources.
                        </p>
                    </div>
                </CardContent>
            </Card>
        );
    }

    return (
        <Card className="border-red-500/30 bg-red-950/10">
            <CardHeader className="pb-2 pt-4 px-5 flex flex-row items-center gap-2">
                <div className="h-8 w-8 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center shrink-0">
                    <User className="h-4 w-4 text-red-400" />
                </div>
                <div className="flex-1">
                    <CardTitle className="text-sm text-red-300">Author IP Attribution</CardTitle>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{publicIPs.length} public IP{publicIPs.length > 1 ? 's' : ''} found embedded · Live geolocation active</p>
                </div>
                {loading && <Loader2 className="h-4 w-4 text-muted-foreground animate-spin" />}
            </CardHeader>
            <CardContent className="px-5 pb-5 space-y-3">
                {publicIPs.map(ip => {
                    const geo = geoMap.get(ip);
                    return (
                        <div key={ip} className="rounded-xl border border-red-500/20 bg-background/40 overflow-hidden">
                            {/* IP Header */}
                            <div className="flex items-center justify-between px-4 py-2.5 border-b border-red-500/15 bg-red-950/20">
                                <div className="flex items-center gap-2">
                                    <Server className="h-3.5 w-3.5 text-red-400" />
                                    <code className="text-sm font-mono font-bold text-red-300">{ip}</code>
                                    <CopyBtn text={ip} />
                                </div>
                                {geo?.status === 'success' && (
                                    <div className="flex gap-1.5">
                                        {geo.proxy && <span className="text-[9px] px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/30 font-bold">VPN</span>}
                                        {geo.hosting && <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-500/20 text-slate-400 border border-slate-500/30 font-bold">DC</span>}
                                        {!geo.proxy && !geo.hosting && <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold">RESIDENTIAL</span>}
                                    </div>
                                )}
                            </div>

                            {/* Geo details or loading */}
                            <div className="p-4">
                                {loading && !geo ? (
                                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                        Looking up geolocation…
                                    </div>
                                ) : !geo || geo.status !== 'success' ? (
                                    <p className="text-xs text-muted-foreground">Geolocation unavailable for this IP.</p>
                                ) : (
                                    <div className="space-y-3">
                                        {/* Location row */}
                                        <div className="flex items-start gap-3">
                                            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0 mt-0.5">
                                                <MapPin className="h-4 w-4 text-emerald-400" />
                                            </div>
                                            <div>
                                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Physical Location (City-Level)</p>
                                                <p className="text-sm font-semibold text-foreground">
                                                    {[geo.city, geo.regionName, geo.country].filter(Boolean).join(', ')}
                                                </p>
                                                <p className="text-[11px] text-muted-foreground font-mono">
                                                    {geo.lat.toFixed(4)}°N, {geo.lon.toFixed(4)}°E · TZ: {geo.timezone}
                                                </p>
                                            </div>
                                        </div>

                                        {/* ISP / Org row */}
                                        <div className="flex items-start gap-3">
                                            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0 mt-0.5">
                                                <Building2 className="h-4 w-4 text-blue-400" />
                                            </div>
                                            <div>
                                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Network / Organisation</p>
                                                <p className="text-sm font-semibold text-foreground">{geo.org || geo.isp}</p>
                                                <p className="text-[11px] text-muted-foreground font-mono">{geo.as}</p>
                                            </div>
                                        </div>

                                        {/* Classification row */}
                                        <div className="grid grid-cols-3 gap-2 pt-1">
                                            <div className={`rounded-lg p-2 text-center border ${geo.proxy ? 'bg-orange-500/10 border-orange-500/25' : 'bg-muted/30 border-border/30'}`}>
                                                <p className={`text-xs font-bold ${geo.proxy ? 'text-orange-400' : 'text-emerald-400'}`}>{geo.proxy ? 'YES ⚠' : 'NO'}</p>
                                                <p className="text-[9px] text-muted-foreground">VPN/Proxy</p>
                                            </div>
                                            <div className={`rounded-lg p-2 text-center border ${geo.hosting ? 'bg-slate-500/10 border-slate-500/25' : 'bg-muted/30 border-border/30'}`}>
                                                <p className={`text-xs font-bold ${geo.hosting ? 'text-slate-300' : 'text-emerald-400'}`}>{geo.hosting ? 'YES' : 'NO'}</p>
                                                <p className="text-[9px] text-muted-foreground">Datacenter</p>
                                            </div>
                                            <div className={`rounded-lg p-2 text-center border ${geo.mobile ? 'bg-violet-500/10 border-violet-500/25' : 'bg-muted/30 border-border/30'}`}>
                                                <p className={`text-xs font-bold ${geo.mobile ? 'text-violet-400' : 'text-slate-400'}`}>{geo.mobile ? 'YES' : 'NO'}</p>
                                                <p className="text-[9px] text-muted-foreground">Mobile</p>
                                            </div>
                                        </div>

                                        {/* Forensic note */}
                                        <div className="flex items-start gap-2 p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/20">
                                            <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
                                            <p className="text-[11px] text-amber-200/80 leading-relaxed">
                                                {geo.proxy
                                                    ? 'This IP is a VPN or proxy exit node. The actual author location is masked — the VPN provider may hold connection logs.'
                                                    : geo.hosting
                                                        ? 'This IP belongs to a datacenter or hosting provider. The author may be using a cloud server, CDN, or shared proxy infrastructure.'
                                                        : `This IP appears to be a residential or business connection attributed to ${geo.org || geo.isp} in ${geo.country}. Geolocation accuracy is typically ±50km at city level.`}
                                            </p>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    );
                })}

                <div className="flex items-start gap-2 p-2.5 rounded-lg bg-slate-800/50 border border-slate-700/40">
                    <ShieldCheck className="h-3.5 w-3.5 text-slate-400 shrink-0 mt-0.5" />
                    <p className="text-[10px] text-slate-400 leading-relaxed">
                        <strong>Forensic note:</strong> IP addresses shown here were found embedded directly in the file's metadata or body content.
                        This system does not perform live network interception. IP owner attribution requires a legal process served to the ISP.
                        Geolocation data sourced from ip-api.com and is accurate to city-level only.
                    </p>
                </div>
            </CardContent>
        </Card>
    );
}

// ── Collapsible class group ────────────────────────────────────────────────
function ClassGroup({
    cls, artifacts, defaultOpen = true, geoMap,
}: {
    cls: OriginClass; artifacts: NetworkArtifact[]; defaultOpen?: boolean; geoMap: Map<string, IPGeoResult>;
}) {
    const [open, setOpen] = useState(defaultOpen);
    const cfg = CLASS_CONFIG[cls];
    const Icon = cfg.icon;
    if (artifacts.length === 0) return null;

    return (
        <Card className={`overflow-hidden border ${cfg.border}`}>
            <button
                id={`group-${cls}`}
                className={`w-full flex items-center gap-3 px-5 py-3 border-b ${cfg.border} hover:bg-accent/20 transition-colors text-left`}
                onClick={() => setOpen(o => !o)}
            >
                <span className={`h-7 w-7 flex items-center justify-center rounded-lg ${cfg.bg} border ${cfg.border}`}>
                    <Icon className={`h-4 w-4 ${cfg.color}`} />
                </span>
                <span className={`text-sm font-semibold ${cfg.color} flex-1`}>{cfg.label}</span>
                <Badge variant="secondary" className="text-[10px] font-mono">{artifacts.length}</Badge>
                {open ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground ml-1" />
                    : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground ml-1" />}
            </button>
            {open && (
                <CardContent className="p-4 space-y-2">
                    {artifacts.map(a => <ArtifactCard key={a.id} art={a} geoMap={geoMap} />)}
                </CardContent>
            )}
        </Card>
    );
}

// ── Main Page ──────────────────────────────────────────────────────────────
export default function NetworkOriginPage() {
    const { currentAnalysis } = useForensic();
    const [filter, setFilter] = useState<OriginClass | 'all'>('all');
    const [catFilter, setCatFilter] = useState<NetworkArtifact['category'] | 'all'>('all');
    const [showJSON, setShowJSON] = useState(false);
    const [viewMode, setViewMode] = useState<'grouped' | 'flat'>('grouped');
    const [geoMap, setGeoMap] = useState<Map<string, IPGeoResult>>(new Map());
    const [geoLoading, setGeoLoading] = useState(false);

    const report: NetworkOriginReport | null = useMemo(
        () => (currentAnalysis ? analyzeNetworkOrigin(currentAnalysis) : null),
        [currentAnalysis]
    );

    // Extract all public IPs and geolocate them
    const publicIPs = useMemo(() => {
        if (!report) return [];
        return report.artifacts
            .filter(a => a.category === 'ip_address' && a.origin_class === 'public_origin')
            .map(a => a.raw_value);
    }, [report]);

    useEffect(() => {
        if (publicIPs.length === 0) return;
        setGeoLoading(true);
        geolocateIPs(publicIPs).then(results => {
            setGeoMap(results);
            setGeoLoading(false);
        });
    }, [publicIPs]);

    if (!currentAnalysis || !report) {
        return (
            <div className="flex flex-col items-center justify-center h-[60vh] gap-4 text-center">
                <div className="p-5 rounded-2xl bg-muted">
                    <WifiOff className="h-12 w-12 text-muted-foreground/30" />
                </div>
                <div>
                    <p className="font-medium text-foreground">No analysis loaded</p>
                    <p className="text-sm text-muted-foreground mt-1">
                        Upload and analyse a file first, then return here to inspect network-origin evidence.
                    </p>
                </div>
            </div>
        );
    }

    const s = report.summary;
    const maxSev = SEVERITY_CONFIG[s.max_severity];

    const downloadJSON = () => {
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `network_origin_${report.file_name.replace(/[^a-z0-9]/gi, '_')}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    // Filtered artifacts for flat view
    const flatArtifacts = report.artifacts.filter(a =>
        (filter === 'all' || a.origin_class === filter) &&
        (catFilter === 'all' || a.category === catFilter)
    );

    const allCats = [...new Set(report.artifacts.map(a => a.category))];

    return (
        <div className="max-w-5xl mx-auto space-y-4">

            {/* ── Header ── */}
            <div className="flex items-start justify-between flex-wrap gap-3">
                <div>
                    <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-widest mb-1">
                        Network Origin Analysis · {new Date(report.analysed_at).toUTCString()}
                    </p>
                    <h1 className="text-xl font-bold text-foreground truncate max-w-xl">{report.file_name}</h1>
                    <p className="text-[11px] text-muted-foreground mt-0.5 font-mono">SHA-256: {report.sha256}</p>
                </div>
                <div className="flex gap-2 flex-wrap">
                    {/* View toggle */}
                    <div className="flex rounded-lg border border-border overflow-hidden">
                        <button id="view-grouped" onClick={() => setViewMode('grouped')}
                            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${viewMode === 'grouped' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent/40'}`}>
                            <Network className="h-3 w-3" /> Grouped
                        </button>
                        <button id="view-flat" onClick={() => setViewMode('flat')}
                            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${viewMode === 'flat' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent/40'}`}>
                            <LayoutGrid className="h-3 w-3" /> Flat
                        </button>
                    </div>
                    <Button id="toggle-net-json" variant="outline" size="sm" className="gap-1.5"
                        onClick={() => setShowJSON(v => !v)}>
                        <Code2 className="h-3.5 w-3.5" /> {showJSON ? 'Hide' : 'View'} JSON
                    </Button>
                    <Button id="download-network-origin" size="sm" className="gap-1.5" onClick={downloadJSON}>
                        <Download className="h-3.5 w-3.5" /> Download
                    </Button>
                </div>
            </div>

            {/* ── Author IP Attribution Panel ── */}
            <AuthorIPPanel publicIPs={publicIPs} geoMap={geoMap} loading={geoLoading} />

            {/* ── Summary dashboard ── */}
            <Card className={`border ${SEVERITY_CONFIG[s.max_severity].ring}`}>
                <CardContent className="p-4">
                    <div className="flex items-center gap-5 flex-wrap">
                        <RiskRing score={s.network_risk_score} sev={s.max_severity} />
                        <div className="flex-1 min-w-[200px]">
                            <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-0.5">Network Risk Score</p>
                            <p className={`text-2xl font-black ${maxSev.color}`}>{maxSev.label} SEVERITY</p>
                            <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{s.verdict}</p>
                        </div>
                    </div>

                    {/* Four stat tiles */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-4">
                        <StatTile cls="public_origin" count={s.public_origin_count} />
                        <StatTile cls="private_network" count={s.private_network_count} />
                        <StatTile cls="local_machine" count={s.local_machine_count} />
                        <StatTile cls="unknown_source" count={s.unknown_source_count} />
                    </div>
                </CardContent>
            </Card>

            {/* ── No artifacts state ── */}
            {report.artifacts.length === 0 && (
                <Card className="border-emerald-500/20 bg-emerald-500/5">
                    <CardContent className="p-5 flex items-center gap-3">
                        <CheckCircle className="h-5 w-5 text-emerald-400 shrink-0" />
                        <div>
                            <p className="text-sm font-semibold text-emerald-400">No Network Artifacts Found</p>
                            <p className="text-xs text-muted-foreground mt-0.5">
                                This file contains no embedded IP addresses, remote URLs, cloud storage traces, UNC paths, or shared drive references.
                            </p>
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* ── Forensic implications ── */}
            {report.forensic_implications.length > 0 && (
                <Card className="border-yellow-500/20 bg-yellow-500/3">
                    <CardHeader className="pb-2 pt-4 px-5 flex flex-row items-center gap-2">
                        <ShieldAlert className="h-4 w-4 text-yellow-400" />
                        <CardTitle className="text-sm">Forensic Exposure Implications</CardTitle>
                    </CardHeader>
                    <CardContent className="px-5 pb-4">
                        <div className="space-y-2">
                            {report.forensic_implications.map((imp, i) => (
                                <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-muted/40 border border-border/30">
                                    <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 mt-0.5 shrink-0" />
                                    <p className="text-xs text-foreground leading-relaxed">{imp}</p>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* ── Artifact views ── */}
            {report.artifacts.length > 0 && (
                <>
                    {viewMode === 'grouped' ? (
                        /* ── Grouped by origin class ── */
                        <>
                            <ClassGroup cls="public_origin" artifacts={report.by_class.public_origin} defaultOpen geoMap={geoMap} />
                            <ClassGroup cls="private_network" artifacts={report.by_class.private_network} defaultOpen geoMap={geoMap} />
                            <ClassGroup cls="local_machine" artifacts={report.by_class.local_machine} defaultOpen={false} geoMap={geoMap} />
                            <ClassGroup cls="unknown_source" artifacts={report.by_class.unknown_source} defaultOpen={false} geoMap={geoMap} />
                        </>
                    ) : (
                        /* ── Flat / filtered view ── */
                        <Card>
                            <CardHeader className="pb-2 pt-4 px-5 flex flex-row items-center gap-2 flex-wrap">
                                <Filter className="h-4 w-4 text-muted-foreground" />
                                <CardTitle className="text-sm">All Artifacts</CardTitle>
                                <div className="ml-auto flex flex-wrap gap-1.5">
                                    {/* Origin class filter */}
                                    {(['all', 'public_origin', 'private_network', 'local_machine', 'unknown_source'] as const).map(f => (
                                        <button key={f} id={`filter-${f}`}
                                            onClick={() => setFilter(f)}
                                            className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors ${filter === f
                                                ? f === 'all' ? 'bg-primary text-primary-foreground border-primary'
                                                    : `${CLASS_CONFIG[f as OriginClass].bg} ${CLASS_CONFIG[f as OriginClass].color} ${CLASS_CONFIG[f as OriginClass].border}`
                                                : 'text-muted-foreground border-border/50 hover:bg-accent/30'
                                                }`}
                                        >
                                            {f === 'all' ? 'All' : CLASS_CONFIG[f as OriginClass].label}
                                        </button>
                                    ))}
                                </div>
                            </CardHeader>
                            {/* Category filter */}
                            <div className="px-5 pb-3 flex flex-wrap gap-1.5 border-b border-border/30">
                                <button id="cat-all" onClick={() => setCatFilter('all')}
                                    className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors ${catFilter === 'all' ? 'bg-primary text-primary-foreground border-primary' : 'text-muted-foreground border-border/50 hover:bg-accent/30'}`}>
                                    All categories
                                </button>
                                {allCats.map(c => (
                                    <button key={c} id={`cat-${c}`} onClick={() => setCatFilter(c)}
                                        className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors ${catFilter === c ? 'bg-primary text-primary-foreground border-primary' : 'text-muted-foreground border-border/50 hover:bg-accent/30'}`}>
                                        {CATEGORY_LABEL[c]}
                                    </button>
                                ))}
                            </div>
                            <CardContent className="p-4 space-y-2">
                                {flatArtifacts.length === 0
                                    ? <p className="text-xs text-muted-foreground italic text-center py-4">No artifacts match the current filter.</p>
                                    : flatArtifacts.map(a => <ArtifactCard key={a.id} art={a} geoMap={geoMap} />)}
                            </CardContent>
                        </Card>
                    )}
                </>
            )}

            {/* ── JSON output ── */}
            {showJSON && (
                <Card>
                    <CardHeader className="pb-2 flex flex-row items-center gap-2">
                        <Code2 className="h-4 w-4 text-primary" />
                        <CardTitle className="text-sm">Network Origin Report JSON</CardTitle>
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
