/**
 * Network Origin Analyzer
 * ────────────────────────
 * Analyses metadata and file content for network-origin evidence.
 *
 * Identifies:  IP addresses · internal network paths · cloud storage traces
 *              · remote URLs · shared drive references
 *
 * Classifies each artifact as:
 *   public_origin | private_network | local_machine | unknown_source
 *
 * Produces:
 *   confidence score (0–100) · supporting fields · exposure implications
 */

import { AnalysisResult } from './types';

// ── Classification enum ────────────────────────────────────────────────────
export type OriginClass =
    | 'public_origin'
    | 'private_network'
    | 'local_machine'
    | 'unknown_source';

// ── Exposure severity ──────────────────────────────────────────────────────
export type ExposureSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ── Individual network artifact ────────────────────────────────────────────
export interface NetworkArtifact {
    id: string;
    /** Artifact category */
    category:
    | 'ip_address'
    | 'internal_path'
    | 'cloud_storage'
    | 'remote_url'
    | 'shared_drive'
    | 'unc_path'
    | 'hostname'
    | 'email_domain';
    /** Raw value as found in the file */
    raw_value: string;
    /** Normalized/cleaned value */
    normalized_value: string;
    /** Origin classification */
    origin_class: OriginClass;
    /** Sub-type label (e.g. "Private RFC-1918 IPv4", "OneDrive URL") */
    type_label: string;
    /** Confidence in classification (0–100) */
    confidence: number;
    /** Exposure severity */
    exposure_severity: ExposureSeverity;
    /** Human-readable exposure implication */
    exposure_implication: string;
    /** Which metadata field this was found in */
    source_field: string;
    /** Any additional details (e.g. detected cloud provider) */
    details: Record<string, string>;
}

// ── Summary statistics ─────────────────────────────────────────────────────
export interface OriginSummary {
    public_origin_count: number;
    private_network_count: number;
    local_machine_count: number;
    unknown_source_count: number;
    total_artifacts: number;
    /** Highest severity found across all artifacts */
    max_severity: ExposureSeverity;
    /** Overall network-origin risk score 0–100 */
    network_risk_score: number;
    /** One-sentence verdict */
    verdict: string;
}

/** Full network-origin analysis report */
export interface NetworkOriginReport {
    analysed_at: string;
    file_name: string;
    sha256: string;
    summary: OriginSummary;
    artifacts: NetworkArtifact[];
    /** Grouped for display */
    by_class: Record<OriginClass, NetworkArtifact[]>;
    /** Forensic takeaways */
    forensic_implications: string[];
}

// ── Detection patterns ─────────────────────────────────────────────────────

/** Cloud provider URL patterns */
const CLOUD_PATTERNS: Array<{ pattern: RegExp; provider: string; label: string }> = [
    { pattern: /sharepoint\.com/i, provider: 'Microsoft SharePoint', label: 'SharePoint Online URL' },
    { pattern: /onedrive\.live\.com/i, provider: 'Microsoft OneDrive', label: 'OneDrive Personal URL' },
    { pattern: /1drv\.ms/i, provider: 'Microsoft OneDrive', label: 'OneDrive Short Link' },
    { pattern: /\\.sharepoint\\.com/i, provider: 'Microsoft SharePoint', label: 'SharePoint Tenant URL' },
    { pattern: /drive\.google\.com/i, provider: 'Google Drive', label: 'Google Drive URL' },
    { pattern: /docs\.google\.com/i, provider: 'Google Docs', label: 'Google Docs URL' },
    { pattern: /storage\.googleapis\.com/i, provider: 'Google Cloud Storage', label: 'GCS Bucket URL' },
    { pattern: /dropbox\.com/i, provider: 'Dropbox', label: 'Dropbox URL' },
    { pattern: /dl\.dropbox/i, provider: 'Dropbox', label: 'Dropbox Direct Download' },
    { pattern: /box\.com/i, provider: 'Box', label: 'Box Cloud URL' },
    { pattern: /icloud\.com/i, provider: 'Apple iCloud', label: 'iCloud URL' },
    { pattern: /amazonaws\.com/i, provider: 'Amazon AWS S3', label: 'AWS S3 / CloudFront URL' },
    { pattern: /s3[.-][a-z0-9-]+\.amazonaws/i, provider: 'Amazon S3', label: 'S3 Bucket URL' },
    { pattern: /blob\.core\.windows\.net/i, provider: 'Azure Blob Storage', label: 'Azure Blob Storage URL' },
    { pattern: /azure\.com/i, provider: 'Microsoft Azure', label: 'Azure Service URL' },
    { pattern: /slack-files\.com/i, provider: 'Slack', label: 'Slack File Upload URL' },
    { pattern: /notion\.so/i, provider: 'Notion', label: 'Notion Page URL' },
    { pattern: /github\.com/i, provider: 'GitHub', label: 'GitHub Repository URL' },
    { pattern: /raw\.githubusercontent\.com/i, provider: 'GitHub', label: 'GitHub Raw File URL' },
    { pattern: /gitlab\.com/i, provider: 'GitLab', label: 'GitLab URL' },
];

/** Shared-drive path patterns (Windows mapped drives, DFS) */
const SHARED_DRIVE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /\\\\[A-Za-z0-9_\-\.]+\\[A-Za-z0-9_\-\.\$ ]+/, label: 'UNC Network Share (\\\\server\\share)' },
    { pattern: /\/\/([\w\-\.]+)\/([\w\-\.\/]+)/, label: 'SMB / CIFS Share (//server/share)' },
    { pattern: /[A-Z]:\\Users\\[^\\]+\\OneDrive/i, label: 'OneDrive Sync Folder (local)' },
    { pattern: /[A-Z]:\\Users\\[^\\]+\\Dropbox/i, label: 'Dropbox Sync Folder (local)' },
    { pattern: /[A-Z]:\\Users\\[^\\]+\\Google Drive/i, label: 'Google Drive Sync Folder (local)' },
    { pattern: /[A-Z]:\\Users\\[^\\]+\\Box Sync/i, label: 'Box Sync Folder (local)' },
    { pattern: /[A-Z]:\\Users\\[^\\]+\\iCloudDrive/i, label: 'iCloud Drive Sync Folder (local)' },
    { pattern: /\/Volumes\/[^\/]+\//, label: 'macOS Mounted Network Volume' },
    { pattern: /\/mnt\/[^\/]+\//, label: 'Linux Mounted Network Drive' },
    { pattern: /DFS|dfs/, label: 'DFS (Distributed File System) Path' },
];

/** Internal / corporate hostname or domain patterns */
const INTERNAL_HOST_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /\.local$/i, label: 'mDNS Local Hostname (.local)' },
    { pattern: /\.corp$/i, label: 'Corporate Internal Domain (.corp)' },
    { pattern: /\.internal$/i, label: 'Internal Domain (.internal)' },
    { pattern: /\.lan$/i, label: 'LAN-only Domain (.lan)' },
    { pattern: /\.intranet$/i, label: 'Intranet Domain (.intranet)' },
    { pattern: /\.office$/i, label: 'Office Domain (.office)' },
    { pattern: /\.ad$/i, label: 'Active Directory Domain (.ad)' },
];

/** Free email domains (not useful for origin classification) */
const FREE_MAIL = new Set([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
    'protonmail.com', 'me.com', 'live.com', 'aol.com', 'mail.com',
]);

// ── IP classification helpers ──────────────────────────────────────────────
function classifyIPv4(ip: string): { class: OriginClass; label: string; confidence: number } {
    if (ip === '127.0.0.1' || ip.startsWith('127.'))
        return { class: 'local_machine', label: 'Loopback (127.x.x.x)', confidence: 99 };
    if (ip === '0.0.0.0')
        return { class: 'unknown_source', label: 'Null address (0.0.0.0)', confidence: 90 };
    if (ip.startsWith('10.'))
        return { class: 'private_network', label: 'RFC-1918 Class A (10.x.x.x)', confidence: 98 };
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip))
        return { class: 'private_network', label: 'RFC-1918 Class B (172.16–31.x)', confidence: 98 };
    if (ip.startsWith('192.168.'))
        return { class: 'private_network', label: 'RFC-1918 Class C (192.168.x.x)', confidence: 99 };
    if (ip.startsWith('169.254.'))
        return { class: 'local_machine', label: 'APIPA / Link-local (169.254.x.x)', confidence: 95 };
    if (ip.startsWith('224.') || ip.startsWith('239.'))
        return { class: 'private_network', label: 'Multicast (224–239.x.x.x)', confidence: 90 };
    if (ip.startsWith('255.'))
        return { class: 'unknown_source', label: 'Broadcast (255.x.x.x)', confidence: 85 };
    return { class: 'public_origin', label: 'Public Internet IPv4', confidence: 92 };
}

function severityForIP(cls: OriginClass): ExposureSeverity {
    if (cls === 'public_origin') return 'high';
    if (cls === 'private_network') return 'medium';
    if (cls === 'local_machine') return 'low';
    return 'info';
}

function ipImplication(cls: OriginClass, ip: string, label: string): string {
    if (cls === 'public_origin')
        return `Public IP ${ip} (${label}) found embedded in the file. Can be geolocated, reverse-DNS looked up, and WHOIS queried to identify the originating network or ISP — a major attribution pivot.`;
    if (cls === 'private_network')
        return `Internal IP ${ip} (${label}) reveals the author's local network architecture. Can expose subnet structure, DHCP ranges, and internal addressing schemes — significant for lateral recon.`;
    if (cls === 'local_machine')
        return `Loopback/link-local address ${ip} indicates a local machine reference. Low network exposure risk but confirms the file contained server or service configuration data.`;
    return `Unknown-purpose IP ${ip} (${label}). Requires manual investigation.`;
}

// ── URL classification ────────────────────────────────────────────────────
function classifyURL(url: string): {
    class: OriginClass; label: string; confidence: number;
    cloud?: { provider: string; label: string };
} {
    // Cloud detection (highest priority)
    for (const cp of CLOUD_PATTERNS) {
        if (cp.pattern.test(url)) {
            return {
                class: 'public_origin',
                label: cp.label,
                confidence: 95,
                cloud: { provider: cp.provider, label: cp.label },
            };
        }
    }
    // Internal-only patterns
    if (/localhost|127\.0\.0\.1/.test(url))
        return { class: 'local_machine', label: 'Localhost URL', confidence: 99 };
    if (/192\.168\.|10\.\d|172\.(1[6-9]|2\d|3[01])\./.test(url))
        return { class: 'private_network', label: 'Private-IP URL', confidence: 95 };
    if (/\.(local|corp|internal|lan|intranet)\b/i.test(url))
        return { class: 'private_network', label: 'Internal-domain URL', confidence: 90 };
    if (/^https?:\/\//.test(url))
        return { class: 'public_origin', label: 'Public HTTP/HTTPS URL', confidence: 80 };
    return { class: 'unknown_source', label: 'Unclassified URL', confidence: 50 };
}

function urlImplication(cls: OriginClass, url: string, cloud?: { provider: string }): string {
    if (cloud)
        return `${cloud.provider} URL embedded in the file (${url.slice(0, 60)}…). Confirms the file was stored in or transferred via ${cloud.provider}. The URL may still be valid and could expose the document or its sharing context publicly.`;
    if (cls === 'public_origin')
        return `External URL "${url.slice(0, 60)}…" references an internet resource. Visiting this URL creates a network beacon traceable to the requester. May also indicate where the file was sourced or linked from.`;
    if (cls === 'private_network')
        return `Internal URL references a private or corporate server. Reveals internal service topology and may expose an intranet resource to anyone who receives this file.`;
    if (cls === 'local_machine')
        return `Localhost URL indicates a development or local-service reference. Suggests the file was generated by a local server process — typically low external risk but useful for software fingerprinting.`;
    return `Unclassified URL "${url.slice(0, 60)}…". Requires manual verification.`;
}

// ── Path / shared-drive classification ────────────────────────────────────
function classifyPath(path: string): {
    class: OriginClass; label: string; confidence: number; isSharedDrive: boolean;
} {
    // UNC / network shares
    if (/^\\\\/.test(path))
        return { class: 'private_network', label: 'UNC Network Share Path', confidence: 97, isSharedDrive: true };
    // Cloud sync folders
    for (const sp of SHARED_DRIVE_PATTERNS) {
        if (sp.pattern.test(path)) {
            const isCloud = ['OneDrive', 'Dropbox', 'Google Drive', 'Box', 'iCloud'].some(c => sp.label.includes(c));
            return {
                class: isCloud ? 'public_origin' : 'private_network',
                label: sp.label,
                confidence: 90,
                isSharedDrive: true,
            };
        }
    }
    // Internal hostname in path
    for (const hp of INTERNAL_HOST_PATTERNS) {
        if (hp.pattern.test(path)) {
            return { class: 'private_network', label: hp.label, confidence: 88, isSharedDrive: false };
        }
    }
    // Regular local path
    if (/^[A-Za-z]:\\/.test(path) || /^\/home\/|^\/Users\//.test(path))
        return { class: 'local_machine', label: 'Local Filesystem Path', confidence: 90, isSharedDrive: false };
    return { class: 'unknown_source', label: 'Unclassified Path', confidence: 40, isSharedDrive: false };
}

function pathImplication(cls: OriginClass, path: string, label: string): string {
    if (cls === 'private_network' && label.includes('UNC'))
        return `UNC path "${path}" exposes the internal server hostname and share name. An attacker can map internal network topology, identify file servers, and potentially attempt SMB access to the listed path.`;
    if (label.includes('OneDrive') || label.includes('Dropbox') || label.includes('Google Drive') || label.includes('iCloud') || label.includes('Box'))
        return `Cloud-sync folder path "${path}" confirms the file lived inside a cloud-synchronised folder. The full absolute path leaks the OS username and cloud service in use — and implies the file may have been auto-synced to the cloud.`;
    if (cls === 'private_network')
        return `Internal path "${path}" (${label}) reveals corporate or LAN infrastructure. Internal service names and directory structures aid both OSINT and lateral movement planning.`;
    if (cls === 'local_machine')
        return `Local filesystem path "${path}" reveals the user account name and directory structure of the machine that created this file. Useful for OS-account attribution.`;
    return `Unclassified path "${path}" could not be matched to a known origin pattern. Manual review recommended.`;
}

// ── Hostname classification ────────────────────────────────────────────────
function classifyHostname(host: string): { class: OriginClass; label: string; confidence: number } {
    for (const hp of INTERNAL_HOST_PATTERNS) {
        if (hp.pattern.test(host))
            return { class: 'private_network', label: hp.label, confidence: 88 };
    }
    if (FREE_MAIL.has(host))
        return { class: 'public_origin', label: 'Free Email Service Domain', confidence: 80 };
    // Check for cloud patterns
    for (const cp of CLOUD_PATTERNS) {
        if (cp.pattern.test(host))
            return { class: 'public_origin', label: cp.label, confidence: 92 };
    }
    if (/\.(com|net|org|io|co|gov|edu)$/.test(host))
        return { class: 'public_origin', label: 'Public Internet Domain', confidence: 75 };
    return { class: 'unknown_source', label: 'Unclassified Hostname', confidence: 45 };
}

// ── Regex patterns ─────────────────────────────────────────────────────────
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const URL_RE = /https?:\/\/[^\s"'<>()\[\]\\,;]{4,}/g;
const UNC_RE = /\\\\[A-Za-z0-9_\-\.]+\\[^\s"'<>\\]{1,}/g;
const WINPATH_RE = /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\?)+/g;
const UNIXPATH_RE = /\/(?:home|Users|mnt|Volumes|var|opt|srv)\/[^\s"'<>,;]{3,}/g;

// ── Scoring helpers ────────────────────────────────────────────────────────
const SEVERITY_WEIGHT: Record<ExposureSeverity, number> = {
    critical: 30, high: 20, medium: 12, low: 5, info: 1,
};

function maxSeverity(artifacts: NetworkArtifact[]): ExposureSeverity {
    const order: ExposureSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
    for (const s of order) {
        if (artifacts.some(a => a.exposure_severity === s)) return s;
    }
    return 'info';
}

let _idCounter = 0;
function nextId() { return `net_${++_idCounter}`; }

// ── Main analysis function ─────────────────────────────────────────────────
export function analyzeNetworkOrigin(result: AnalysisResult): NetworkOriginReport {
    _idCounter = 0;
    const artifacts: NetworkArtifact[] = [];
    const m = result.metadata;
    const net = result.networkIndicators;

    // ── 1. IP Addresses ───────────────────────────────────────────────────────
    // From content scanner
    const allIPs = new Set<string>(net.ips);
    // Scan rawForensicJSON for extra IPs
    const rawText = JSON.stringify(result.rawForensicJSON);
    const extraIPs = rawText.match(IPV4_RE) || [];
    extraIPs.forEach(ip => allIPs.add(ip));

    for (const ip of allIPs) {
        if (ip.startsWith('0.') || ip.startsWith('255.') || ip === '0.0.0.0') continue;
        const cls = classifyIPv4(ip);
        artifacts.push({
            id: nextId(),
            category: 'ip_address',
            raw_value: ip,
            normalized_value: ip,
            origin_class: cls.class,
            type_label: cls.label,
            confidence: cls.confidence,
            exposure_severity: severityForIP(cls.class),
            exposure_implication: ipImplication(cls.class, ip, cls.label),
            source_field: 'network_indicators.ips / raw_content_scan',
            details: { classification: cls.label },
        });
    }

    // ── 2. Remote URLs (cloud + general) ──────────────────────────────────────
    const allURLs = new Set<string>(net.urls);
    // Scan exifData for extra URLs
    const exifText = JSON.stringify(m.exifData || {});
    const exifURLs = exifText.match(URL_RE) || [];
    exifURLs.forEach(u => allURLs.add(u));

    const NOISE_DOMAINS = ['schemas.openxmlformats.org', 'schemas.microsoft.com', 'www.w3.org', 'purl.org', 'ns.adobe.com', 'xmlsoap.org', 'dublincore.org'];
    for (const url of allURLs) {
        if (NOISE_DOMAINS.some(n => url.includes(n))) continue;
        const cls = classifyURL(url);
        const sev: ExposureSeverity = cls.cloud ? 'high' : cls.class === 'public_origin' ? 'medium' : cls.class === 'private_network' ? 'high' : 'low';
        artifacts.push({
            id: nextId(),
            category: cls.cloud ? 'cloud_storage' : 'remote_url',
            raw_value: url,
            normalized_value: url.length > 120 ? url.slice(0, 120) + '…' : url,
            origin_class: cls.class,
            type_label: cls.label,
            confidence: cls.confidence,
            exposure_severity: sev,
            exposure_implication: urlImplication(cls.class, url, cls.cloud),
            source_field: 'network_indicators.urls / exif_data',
            details: cls.cloud ? { cloud_provider: cls.cloud.provider, cloud_service: cls.cloud.label } : {},
        });
    }

    // ── 3. UNC / Shared drive paths ───────────────────────────────────────────
    for (const unc of net.uncPaths) {
        const cls = classifyPath(unc);
        artifacts.push({
            id: nextId(),
            category: 'unc_path',
            raw_value: unc,
            normalized_value: unc,
            origin_class: cls.class,
            type_label: cls.label,
            confidence: cls.confidence,
            exposure_severity: 'high',
            exposure_implication: pathImplication(cls.class, unc, cls.label),
            source_field: 'network_indicators.uncPaths',
            details: { is_shared_drive: String(cls.isSharedDrive) },
        });
    }

    // ── 4. Embedded Windows / UNIX local/cloud-sync paths ─────────────────────
    const pathCandidates: Array<{ val: string; src: string }> = [];

    // From exif author/software fields
    [m.author, m.creator, m.lastModifiedBy, m.software, m.deviceOwner,
    ...Object.values(m.exifData || {}).map(v => String(v ?? ''))
    ].forEach(s => {
        if (!s) return;
        (s.match(WINPATH_RE) || []).forEach(p => pathCandidates.push({ val: p, src: 'exif_field' }));
        (s.match(UNIXPATH_RE) || []).forEach(p => pathCandidates.push({ val: p, src: 'exif_field' }));
    });

    // From rawForensicJSON
    (rawText.match(WINPATH_RE) || []).forEach(p => pathCandidates.push({ val: p, src: 'raw_forensic_json' }));
    (rawText.match(UNIXPATH_RE) || []).forEach(p => pathCandidates.push({ val: p, src: 'raw_forensic_json' }));

    const seenPaths = new Set<string>();
    for (const { val: p, src } of pathCandidates) {
        if (seenPaths.has(p)) continue;
        seenPaths.add(p);

        const cls = classifyPath(p);
        const isCloud = ['OneDrive', 'Dropbox', 'Google Drive', 'iCloud', 'Box'].some(c => cls.label.includes(c));
        const sev: ExposureSeverity = cls.isSharedDrive && isCloud ? 'high' : cls.class === 'local_machine' ? 'low' : 'medium';

        artifacts.push({
            id: nextId(),
            category: isCloud ? 'cloud_storage' : cls.isSharedDrive ? 'shared_drive' : 'internal_path',
            raw_value: p,
            normalized_value: p,
            origin_class: cls.class,
            type_label: cls.label,
            confidence: cls.confidence,
            exposure_severity: sev,
            exposure_implication: pathImplication(cls.class, p, cls.label),
            source_field: src,
            details: { is_shared_drive: String(cls.isSharedDrive), is_cloud_sync: String(isCloud) },
        });
    }

    // ── 5. Hostnames ─────────────────────────────────────────────────────────
    for (const host of net.hostnames) {
        if (NOISE_DOMAINS.some(n => host.includes(n))) continue;
        const cls = classifyHostname(host);
        artifacts.push({
            id: nextId(),
            category: 'hostname',
            raw_value: host,
            normalized_value: host.toLowerCase(),
            origin_class: cls.class,
            type_label: cls.label,
            confidence: cls.confidence,
            exposure_severity: cls.class === 'private_network' ? 'medium' : 'low',
            exposure_implication: cls.class === 'private_network'
                ? `Hostname "${host}" (${cls.label}) reveals internal network naming conventions. Can be used to enumerate other internal hosts and map corporate infrastructure.`
                : `Domain/hostname "${host}" is a public internet reference. Useful as an OSINT pivot to identify associated organizations or services.`,
            source_field: 'network_indicators.hostnames',
            details: { hostname_type: cls.label },
        });
    }

    // ── 6. Email domains as origin signals ────────────────────────────────────
    for (const email of net.emails) {
        const domain = email.split('@')[1] ?? '';
        if (!domain) continue;
        const cls = classifyHostname(domain);
        const isFree = FREE_MAIL.has(domain);
        artifacts.push({
            id: nextId(),
            category: 'email_domain',
            raw_value: email,
            normalized_value: email.toLowerCase(),
            origin_class: cls.class,
            type_label: isFree ? 'Free Email Service' : 'Corporate / Custom Email Domain',
            confidence: isFree ? 70 : 85,
            exposure_severity: isFree ? 'medium' : 'high',
            exposure_implication: isFree
                ? `Email address "${email}" uses a free provider (${domain}). Cannot be used for corporate attribution but can be searched in breach databases and social media for identity correlation.`
                : `Corporate email "${email}" (domain: ${domain}) directly attributes to an organization. The domain can be WHOIS-queried, and the address can be cross-referenced against LinkedIn and breach databases.`,
            source_field: 'network_indicators.emails',
            details: { email_domain: domain, is_free_provider: String(isFree) },
        });
    }

    // ── Dedup by normalized_value ─────────────────────────────────────────────
    const seen = new Set<string>();
    const unique = artifacts.filter(a => {
        if (seen.has(a.normalized_value)) return false;
        seen.add(a.normalized_value);
        return true;
    });

    // ── Compute summary ───────────────────────────────────────────────────────
    const byClass: Record<OriginClass, NetworkArtifact[]> = {
        public_origin: unique.filter(a => a.origin_class === 'public_origin'),
        private_network: unique.filter(a => a.origin_class === 'private_network'),
        local_machine: unique.filter(a => a.origin_class === 'local_machine'),
        unknown_source: unique.filter(a => a.origin_class === 'unknown_source'),
    };

    const maxSev = maxSeverity(unique);
    const rawRisk = unique.reduce((s, a) => s + SEVERITY_WEIGHT[a.exposure_severity], 0);
    const networkRisk = Math.min(100, Math.round(rawRisk));

    // Verdict string
    let verdict = 'No network-origin artifacts detected.';
    if (unique.length > 0) {
        const parts: string[] = [];
        if (byClass.public_origin.length > 0) parts.push(`${byClass.public_origin.length} public-internet artifact${byClass.public_origin.length > 1 ? 's' : ''}`);
        if (byClass.private_network.length > 0) parts.push(`${byClass.private_network.length} private-network artifact${byClass.private_network.length > 1 ? 's' : ''}`);
        if (byClass.local_machine.length > 0) parts.push(`${byClass.local_machine.length} local-machine artifact${byClass.local_machine.length > 1 ? 's' : ''}`);
        if (byClass.unknown_source.length > 0) parts.push(`${byClass.unknown_source.length} unknown-source artifact${byClass.unknown_source.length > 1 ? 's' : ''}`);
        verdict = `File contains ${parts.join(', ')}. Network risk score: ${networkRisk}/100 (${maxSev} severity).`;
    }

    // Forensic implications
    const forensic: string[] = [];
    if (byClass.public_origin.some(a => a.category === 'ip_address'))
        forensic.push('Public IP addresses can be geolocated and correlated with ISP/ASN data to identify the originating country, city, and organization.');
    if (byClass.private_network.some(a => a.category === 'unc_path' || a.category === 'internal_path'))
        forensic.push('Internal network paths expose corporate infrastructure topology — server names, share names, and directory structures can enable targeted lateral movement.');
    if (unique.some(a => a.category === 'cloud_storage'))
        forensic.push('Cloud storage URLs may still be live and publicly accessible, potentially exposing the original document or its access-control configuration.');
    if (byClass.local_machine.length > 0)
        forensic.push('Local machine artifacts (loopback IPs, local paths) reveal the software environment and account structure of the machine that created the file.');
    if (unique.some(a => a.category === 'email_domain' && a.details.is_free_provider === 'false'))
        forensic.push('Corporate email domains enable organizational attribution via WHOIS, LinkedIn, and breach-database cross-referencing.');
    if (unique.some(a => a.category === 'shared_drive' || (a.category === 'cloud_storage' && a.details.is_cloud_sync === 'true')))
        forensic.push('Cloud-sync folder paths (OneDrive, Dropbox, etc.) indicate the file was continuously synchronised to the cloud — the cloud account may hold additional evidence.');

    return {
        analysed_at: new Date().toISOString(),
        file_name: m.fileName,
        sha256: m.sha256Hash,
        summary: {
            public_origin_count: byClass.public_origin.length,
            private_network_count: byClass.private_network.length,
            local_machine_count: byClass.local_machine.length,
            unknown_source_count: byClass.unknown_source.length,
            total_artifacts: unique.length,
            max_severity: maxSev,
            network_risk_score: networkRisk,
            verdict,
        },
        artifacts: unique,
        by_class: byClass,
        forensic_implications: forensic,
    };
}
