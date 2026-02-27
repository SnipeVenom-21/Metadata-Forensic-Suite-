import { useMemo, useState } from 'react';
import { useForensic } from '@/context/ForensicContext';
import { normalizeMetadata, NormalizedMetadata } from '@/lib/metadata-normalizer';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
    User, Network, Cpu, Clock, MapPin, Package, Download,
    CheckCircle, AlertTriangle, ChevronDown, ChevronUp,
    Shield, Mail, Server, Globe, FolderOpen, Calendar,
    Layers, Fingerprint, Wifi, WifiOff, Code2, Copy, Check,
} from 'lucide-react';

// ── Colour tokens per group ────────────────────────────────────────────────
const GROUP_META = {
    identity: { icon: User, label: 'Identity Data', color: 'text-blue-400', bg: 'bg-blue-500/8', border: 'border-blue-500/25' },
    device: { icon: Cpu, label: 'Device Data', color: 'text-violet-400', bg: 'bg-violet-500/8', border: 'border-violet-500/25' },
    network: { icon: Network, label: 'Network Data', color: 'text-cyan-400', bg: 'bg-cyan-500/8', border: 'border-cyan-500/25' },
    timeline: { icon: Clock, label: 'Timeline Data', color: 'text-emerald-400', bg: 'bg-emerald-500/8', border: 'border-emerald-500/25' },
    location: { icon: MapPin, label: 'Location Data', color: 'text-orange-400', bg: 'bg-orange-500/8', border: 'border-orange-500/25' },
    software: { icon: Package, label: 'Software Data', color: 'text-pink-400', bg: 'bg-pink-500/8', border: 'border-pink-500/25' },
} as const;

// ── Sub-components ─────────────────────────────────────────────────────────

function CollapsibleGroup({
    id, children, defaultOpen = true,
}: {
    id: keyof typeof GROUP_META; children: React.ReactNode; defaultOpen?: boolean;
}) {
    const [open, setOpen] = useState(defaultOpen);
    const { icon: Icon, label, color, bg, border } = GROUP_META[id];
    return (
        <Card className={`overflow-hidden border ${border} transition-all duration-200`}>
            <button
                id={`group-${id}`}
                className={`w-full flex items-center gap-3 px-5 py-3 border-b ${border} hover:bg-accent/20 transition-colors text-left`}
                onClick={() => setOpen(o => !o)}
            >
                <span className={`flex items-center justify-center h-7 w-7 rounded-lg ${bg} border ${border}`}>
                    <Icon className={`h-4 w-4 ${color}`} />
                </span>
                <span className={`text-sm font-semibold ${color} flex-1`}>{label}</span>
                {open
                    ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" />
                    : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
            </button>
            {open && <CardContent className="p-5">{children}</CardContent>}
        </Card>
    );
}

function Row({ label, value, mono, warn }: { label: string; value?: string | null; mono?: boolean; warn?: boolean }) {
    if (!value) return null;
    return (
        <div className="flex items-start gap-3 py-1.5 border-b border-border/30 last:border-0">
            <span className="text-[11px] text-muted-foreground shrink-0 w-44 pt-0.5">{label}</span>
            <span className={`text-xs break-all ${mono ? 'font-mono text-emerald-300' : 'font-medium text-foreground'} ${warn ? 'text-yellow-400' : ''}`}>
                {value}
            </span>
        </div>
    );
}

function Null({ label }: { label: string }) {
    return (
        <div className="flex items-start gap-3 py-1.5 border-b border-border/30 last:border-0">
            <span className="text-[11px] text-muted-foreground shrink-0 w-44 pt-0.5">{label}</span>
            <span className="text-[11px] text-muted-foreground italic">null</span>
        </div>
    );
}

function TagChips({ items, color = 'text-foreground', emptyMsg = 'None' }: { items: string[]; color?: string; emptyMsg?: string }) {
    if (items.length === 0) return <p className="text-[11px] text-muted-foreground italic">{emptyMsg}</p>;
    return (
        <div className="flex flex-wrap gap-1.5 mt-1">
            {items.map((v, i) => (
                <span key={i} className={`text-[11px] font-mono px-2 py-0.5 rounded bg-muted border border-border/50 ${color}`}>{v}</span>
            ))}
        </div>
    );
}

function SectionLabel({ icon: Icon, text }: { icon: React.ComponentType<{ className?: string }>; text: string }) {
    return (
        <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-2 flex items-center gap-1.5 mt-4 first:mt-0">
            <Icon className="h-3 w-3" /> {text}
        </p>
    );
}

// ── IP badge ──────────────────────────────────────────────────────────────
const IP_CLASS_COLORS: Record<string, string> = {
    public: 'text-red-400   border-red-500/30   bg-red-500/5',
    private: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/5',
    loopback: 'text-muted-foreground border-border/50 bg-muted/30',
    'link-local': 'text-blue-400  border-blue-500/30  bg-blue-500/5',
};

function IPChip({ ip, classification }: { ip: string; classification: string }) {
    return (
        <span className={`inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded border ${IP_CLASS_COLORS[classification] || ''}`}>
            {classification === 'public' ? <Wifi className="h-2.5 w-2.5" /> : <WifiOff className="h-2.5 w-2.5" />}
            {ip}
            <span className="opacity-50 text-[9px] uppercase">{classification}</span>
        </span>
    );
}

// ── Timestamp row ─────────────────────────────────────────────────────────
function TimeRow({ label, utc }: { label: string; utc: string | null }) {
    if (!utc) return <Null label={label} />;
    const d = new Date(utc);
    return (
        <div className="flex items-start gap-3 py-1.5 border-b border-border/30 last:border-0">
            <span className="text-[11px] text-muted-foreground shrink-0 w-44 pt-0.5">{label}</span>
            <div>
                <p className="text-xs font-mono text-emerald-300">{utc}</p>
                <p className="text-[10px] text-muted-foreground">{d.toUTCString()}</p>
            </div>
        </div>
    );
}

// ── Copy button ───────────────────────────────────────────────────────────
function CopyButton({ text }: { text: string }) {
    const [copied, setCopied] = useState(false);
    return (
        <button
            onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1800); }}
            className="text-muted-foreground hover:text-foreground transition-colors"
            title="Copy to clipboard"
        >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
    );
}

// ── Suspicion badge ───────────────────────────────────────────────────────
const SUSPICION_BADGE: Record<string, { label: string; cls: string }> = {
    none: { label: 'Normal', cls: 'border-emerald-500/30 text-emerald-400' },
    null_island: { label: '⚠ Null Island (0°,0°)', cls: 'border-red-500/30 text-red-400' },
    excessive_precision: { label: '⚠ Excessive Precision', cls: 'border-yellow-500/30 text-yellow-400' },
};

// ── Main Page ──────────────────────────────────────────────────────────────
export default function NormalizerPage() {
    const { currentAnalysis } = useForensic();
    const [showJSON, setShowJSON] = useState(false);

    const normalized: NormalizedMetadata | null = useMemo(
        () => (currentAnalysis ? normalizeMetadata(currentAnalysis) : null),
        [currentAnalysis]
    );

    if (!currentAnalysis || !normalized) {
        return (
            <div className="flex flex-col items-center justify-center h-[60vh] gap-4 text-center">
                <div className="p-5 rounded-2xl bg-muted">
                    <Layers className="h-12 w-12 text-muted-foreground/30" />
                </div>
                <div>
                    <p className="font-medium text-foreground">No analysis loaded</p>
                    <p className="text-sm text-muted-foreground mt-1">
                        Upload and analyse a file first, then return here to normalize its metadata.
                    </p>
                </div>
            </div>
        );
    }

    const n = normalized;

    const downloadJSON = () => {
        const blob = new Blob([JSON.stringify(n, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `normalized_${n.fileName.replace(/[^a-z0-9]/gi, '_')}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="max-w-5xl mx-auto space-y-4">

            {/* ── Header ── */}
            <div className="flex items-start justify-between flex-wrap gap-3">
                <div>
                    <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-widest mb-1">
                        Metadata Normalization · {new Date(n.normalizedAt).toUTCString()}
                    </p>
                    <h1 className="text-xl font-bold text-foreground truncate max-w-xl">{n.fileName}</h1>
                    <p className="text-[11px] text-muted-foreground mt-0.5 font-mono">SHA-256: {n.sha256}</p>
                </div>
                <div className="flex gap-2 flex-wrap">
                    <Button
                        id="toggle-json-btn"
                        variant="outline"
                        size="sm"
                        className="gap-1.5"
                        onClick={() => setShowJSON(v => !v)}
                    >
                        <Code2 className="h-3.5 w-3.5" /> {showJSON ? 'Hide' : 'View'} JSON
                    </Button>
                    <Button id="download-normalized-btn" size="sm" className="gap-1.5" onClick={downloadJSON}>
                        <Download className="h-3.5 w-3.5" /> Download
                    </Button>
                </div>
            </div>

            {/* ── Summary pills ── */}
            <div className="flex flex-wrap gap-2">
                {[
                    { label: 'Author', val: n.identity_data.author ?? '—' },
                    { label: 'OS', val: n.device_data.operatingSystem ?? '—' },
                    { label: 'IPs', val: String(n.network_data.ipv4Addresses.length) },
                    { label: 'Emails', val: String(n.network_data.emails.length) },
                    { label: 'Vendors', val: n.software_data.vendors.join(', ') || '—' },
                    { label: 'GPS', val: n.location_data.latitude !== null ? `${n.location_data.latitude?.toFixed(4)}, ${n.location_data.longitude?.toFixed(4)}` : 'No GPS' },
                ].map(({ label, val }) => (
                    <div key={label} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-muted border border-border/50 text-xs">
                        <span className="text-muted-foreground">{label}:</span>
                        <span className="font-medium text-foreground">{val}</span>
                    </div>
                ))}
            </div>

            {/* ══ 1. IDENTITY DATA ══════════════════════════════════════════════ */}
            <CollapsibleGroup id="identity">
                <div className="space-y-0">
                    <Row label="Author / Creator" value={n.identity_data.author} />
                    <Row label="Last Modified By" value={n.identity_data.lastModifiedBy} />
                    <Row label="Device Owner" value={n.identity_data.deviceOwner} />
                    <Row label="Organization" value={n.identity_data.organization} />
                    {!n.identity_data.author && !n.identity_data.lastModifiedBy && !n.identity_data.deviceOwner && (
                        <p className="text-xs text-muted-foreground italic py-2">No author/owner metadata found.</p>
                    )}
                </div>

                {n.identity_data.usernamesFromPaths.length > 0 && (
                    <>
                        <SectionLabel icon={FolderOpen} text="Usernames Extracted from Paths" />
                        <TagChips items={n.identity_data.usernamesFromPaths} color="text-blue-300" />
                    </>
                )}

                {n.identity_data.pathSources.length > 0 && (
                    <>
                        <SectionLabel icon={FolderOpen} text="Source Paths" />
                        <div className="space-y-1">
                            {n.identity_data.pathSources.map((p, i) => (
                                <div key={i} className="flex items-center gap-2 px-2 py-1 rounded bg-muted/40 border border-border/30">
                                    <span className="text-[11px] font-mono text-muted-foreground break-all">{p}</span>
                                    <CopyButton text={p} />
                                </div>
                            ))}
                        </div>
                    </>
                )}

                {n.identity_data.emails.length > 0 && (
                    <>
                        <SectionLabel icon={Mail} text="Email Addresses" />
                        <TagChips items={n.identity_data.emails} color="text-cyan-400" />
                    </>
                )}
            </CollapsibleGroup>

            {/* ══ 2. DEVICE DATA ════════════════════════════════════════════════ */}
            <CollapsibleGroup id="device">
                <div className="space-y-0">
                    <Row label="Device / Camera" value={n.device_data.device} />
                    <Row label="Operating System" value={n.device_data.operatingSystem}
                        warn={n.device_data.osSource === 'path_pattern'} />
                    {n.device_data.operatingSystem && (
                        <div className="flex items-start gap-3 py-1.5 border-b border-border/30">
                            <span className="text-[11px] text-muted-foreground shrink-0 w-44">OS Detection Source</span>
                            <Badge variant="secondary" className="text-[10px]">
                                {n.device_data.osSource === 'metadata' ? 'Explicit metadata field' :
                                    n.device_data.osSource === 'software_string' ? 'Software string inference' :
                                        'Path heuristic'}
                            </Badge>
                        </div>
                    )}
                    <Row label="Color Space" value={n.device_data.colorSpace} />
                    <Row label="Dimensions" value={n.device_data.dimensions
                        ? `${n.device_data.dimensions.width} × ${n.device_data.dimensions.height} px` : null} />
                    <Row label="DPI" value={n.device_data.dpi ? `${n.device_data.dpi} dpi` : null} />
                    {!n.device_data.device && !n.device_data.operatingSystem && (
                        <p className="text-xs text-muted-foreground italic py-2">No device fingerprint found.</p>
                    )}
                </div>
            </CollapsibleGroup>

            {/* ══ 3. NETWORK DATA ═══════════════════════════════════════════════ */}
            <CollapsibleGroup id="network">
                <SectionLabel icon={Mail} text="Email Addresses" />
                {n.network_data.emails.length > 0
                    ? <TagChips items={n.network_data.emails} color="text-cyan-400" />
                    : <p className="text-[11px] text-muted-foreground italic">None found</p>}

                <SectionLabel icon={Server} text="IPv4 Addresses" />
                {n.network_data.ipv4Addresses.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 mt-1">
                        {n.network_data.ipv4Addresses.map((p, i) => (
                            <IPChip key={i} ip={p.ip} classification={p.classification} />
                        ))}
                    </div>
                ) : <p className="text-[11px] text-muted-foreground italic">None found</p>}

                {n.network_data.ipv6Addresses.length > 0 && (
                    <>
                        <SectionLabel icon={Server} text="IPv6 Addresses" />
                        <TagChips items={n.network_data.ipv6Addresses} color="text-blue-400" />
                    </>
                )}

                <SectionLabel icon={Globe} text="URLs &amp; External References" />
                {n.network_data.urls.length > 0 ? (
                    <div className="space-y-1 mt-1 max-h-36 overflow-y-auto pr-1">
                        {n.network_data.urls.map((u, i) => (
                            <div key={i} className="flex items-center gap-2 px-2 py-1 rounded bg-muted/40 border border-border/30">
                                <a href={u} target="_blank" rel="noopener noreferrer"
                                    className="text-[11px] font-mono text-violet-400 underline break-all hover:opacity-80">{u}</a>
                                <CopyButton text={u} />
                            </div>
                        ))}
                    </div>
                ) : <p className="text-[11px] text-muted-foreground italic">None found</p>}

                {n.network_data.uncPaths.length > 0 && (
                    <>
                        <SectionLabel icon={FolderOpen} text="UNC / Network Share Paths" />
                        <TagChips items={n.network_data.uncPaths} color="text-red-400" />
                    </>
                )}

                {n.network_data.hostnames.length > 0 && (
                    <>
                        <SectionLabel icon={Globe} text="Hostnames" />
                        <TagChips items={n.network_data.hostnames} />
                    </>
                )}
            </CollapsibleGroup>

            {/* ══ 4. TIMELINE DATA ══════════════════════════════════════════════ */}
            <CollapsibleGroup id="timeline">
                <p className="text-[10px] text-muted-foreground italic mb-3">
                    All timestamps normalized to UTC (ISO 8601).
                </p>
                <div className="space-y-0">
                    <TimeRow label="Creation Date (UTC)" utc={n.timeline_data.creationDateUTC} />
                    <TimeRow label="Modification Date (UTC)" utc={n.timeline_data.modificationDateUTC} />
                    <TimeRow label="Filesystem Last Modified (UTC)" utc={n.timeline_data.filesystemLastModifiedUTC} />
                    <TimeRow label="Upload Timestamp (UTC)" utc={n.timeline_data.uploadTimestampUTC} />
                    <TimeRow label="Access Date (UTC)" utc={n.timeline_data.accessDateUTC} />
                    <Row label="Embedded Timezone" value={n.timeline_data.embeddedTimezone} />
                    <TimeRow label="GPS Timestamp (UTC)" utc={n.timeline_data.gpsTimestampUTC} />
                </div>

                {n.timeline_data.eventChronology.length > 0 && (
                    <>
                        <SectionLabel icon={Calendar} text="Chronological Event Sequence" />
                        <div className="relative mt-2 border-l-2 border-emerald-500/30 pl-4 space-y-3">
                            {n.timeline_data.eventChronology.map((ev, i) => (
                                <div key={i} className="relative">
                                    <div className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full bg-emerald-500/60 border border-emerald-400/40" />
                                    <p className="text-[11px] text-muted-foreground">{ev.label}</p>
                                    <p className="text-xs font-mono text-emerald-300">{ev.utc}</p>
                                </div>
                            ))}
                        </div>
                    </>
                )}
            </CollapsibleGroup>

            {/* ══ 5. LOCATION DATA ══════════════════════════════════════════════ */}
            <CollapsibleGroup id="location">
                {n.location_data.latitude !== null ? (
                    <div className="space-y-3">
                        <div className="space-y-0">
                            <Row label="Latitude (decimal °)" value={n.location_data.latitude?.toFixed(8) + '°'} mono />
                            <Row label="Longitude (decimal °)" value={n.location_data.longitude?.toFixed(8) + '°'} mono />
                            <Row label="Altitude" value={n.location_data.altitudeMetres !== null
                                ? `${n.location_data.altitudeMetres} m` : null} />
                            <Row label="Precision Estimate" value={n.location_data.precisionEstimateMetres} />
                            <Row label="Location Reference" value={n.location_data.locationReference} />
                        </div>

                        {/* Suspicion badge */}
                        <div className="flex items-center gap-2">
                            <span className="text-[11px] text-muted-foreground">Coordinate Quality:</span>
                            {(() => {
                                const s = SUSPICION_BADGE[n.location_data.coordinateSuspicion];
                                return <Badge variant="outline" className={`text-[10px] ${s.cls}`}>{s.label}</Badge>;
                            })()}
                        </div>

                        {/* Google Maps link */}
                        <a
                            href={n.location_data.googleMapsUrl!}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 text-xs text-primary underline hover:opacity-80 transition"
                        >
                            <MapPin className="h-3 w-3" /> View on Google Maps ↗
                        </a>
                    </div>
                ) : (
                    <p className="text-xs text-muted-foreground italic">No GPS coordinates found in this file.</p>
                )}
            </CollapsibleGroup>

            {/* ══ 6. SOFTWARE DATA ══════════════════════════════════════════════ */}
            <CollapsibleGroup id="software">
                <div className="space-y-0">
                    <Row label="Primary Software" value={n.software_data.primarySoftware} />
                    <Row label="Version" value={n.software_data.version} />
                    <Row label="Operating System" value={n.software_data.operatingSystem} />
                    <Row label="Creator Tool (XMP)" value={n.software_data.creatorTool} />
                </div>

                {/* Vendor detection */}
                <SectionLabel icon={Fingerprint} text="Detected Software Vendors" />
                {n.software_data.vendors.length > 0 ? (
                    <div className="flex flex-wrap gap-2 mt-1">
                        {n.software_data.vendors.map((v, i) => (
                            <Badge key={i} variant="secondary" className="text-xs font-medium">{v}</Badge>
                        ))}
                    </div>
                ) : <p className="text-[11px] text-muted-foreground italic">No recognized vendors detected</p>}

                {/* Multi-editor pipeline flag */}
                <div className="mt-4 flex items-center gap-2 p-2.5 rounded-lg border
          border-border/50 bg-muted/30 text-xs">
                    {n.software_data.multipleEditorsPipeline
                        ? <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0" />
                        : <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" />}
                    <span className="text-foreground font-medium mr-1">Multi-Editor Pipeline:</span>
                    <span className="text-muted-foreground">
                        {n.software_data.multipleEditorsPipeline
                            ? 'Multiple editing tools detected — file may have been processed through several applications.'
                            : 'No multiple-editor pipeline detected.'}
                    </span>
                </div>

                {/* All software strings */}
                {n.software_data.allSoftwareStrings.length > 0 && (
                    <>
                        <SectionLabel icon={Package} text="All Software Strings Found" />
                        <TagChips items={n.software_data.allSoftwareStrings} color="text-pink-300" />
                    </>
                )}
            </CollapsibleGroup>

            {/* ── JSON output ── */}
            {showJSON && (
                <Card>
                    <CardHeader className="pb-2 flex flex-row items-center gap-2">
                        <Code2 className="h-4 w-4 text-primary" />
                        <CardTitle className="text-sm">Normalized JSON Output</CardTitle>
                        <Badge variant="secondary" className="ml-auto font-mono text-xs">
                            {JSON.stringify(n).length.toLocaleString()} chars
                        </Badge>
                    </CardHeader>
                    <CardContent className="p-0">
                        <pre className="text-[11px] font-mono leading-relaxed text-emerald-300 bg-[hsl(222,47%,5%)] p-4 rounded-b-xl overflow-auto max-h-[70vh] whitespace-pre-wrap break-all">
                            {JSON.stringify(n, null, 2)}
                        </pre>
                    </CardContent>
                </Card>
            )}
        </div>
    );
}
