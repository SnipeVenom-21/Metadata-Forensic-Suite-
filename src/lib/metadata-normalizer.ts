/**
 * Metadata Normalization System
 * ─────────────────────────────
 * Cleans and standardizes raw extracted metadata into 6 canonical output groups:
 *   identity_data  · device_data  · network_data
 *   timeline_data  · location_data · software_data
 */

import { AnalysisResult } from './types';

// ── Vendor keyword mapping ─────────────────────────────────────────────────
const VENDOR_PATTERNS: Record<string, string[]> = {
    Adobe: ['adobe', 'acrobat', 'photoshop', 'lightroom', 'indesign', 'illustrator', 'premiere', 'after effects'],
    Microsoft: ['microsoft', 'word', 'excel', 'powerpoint', 'office', 'windows', 'msword', 'msofficelive'],
    Apple: ['apple', 'macos', 'iphone', 'ipad', 'ios', 'safari', 'keynote', 'pages', 'numbers', 'quartz', 'coreimage'],
    Google: ['google', 'android', 'chrome', 'docs', 'sheets', 'slides', 'pixel', 'gboard'],
    Canon: ['canon'],
    Nikon: ['nikon'],
    Sony: ['sony'],
    Fujifilm: ['fujifilm', 'fuji'],
    Samsung: ['samsung'],
    Huawei: ['huawei'],
    GIMP: ['gimp'],
    LibreOffice: ['libreoffice', 'openoffice', 'wps office'],
    FFmpeg: ['ffmpeg', 'handbrake', 'lavf', 'lavc'],
    DaVinci: ['davinci', 'blackmagic'],
    Canva: ['canva'],
};

// ── OS detection keyword map ───────────────────────────────────────────────
const OS_PATTERNS: Record<string, string[]> = {
    'Windows 11': ['windows 11', 'win11'],
    'Windows 10': ['windows 10', 'win10'],
    'Windows 7': ['windows 7', 'win7'],
    'Windows': ['windows', 'winnt', 'microsoft windows'],
    'macOS': ['macos', 'mac os x', 'darwin', 'osx'],
    'iOS': ['ios', 'iphone os'],
    'Android': ['android'],
    'Linux': ['linux', 'ubuntu', 'debian', 'fedora', 'centos', 'arch'],
    'ChromeOS': ['chromeos', 'chrome os'],
};

// ── Regex patterns ─────────────────────────────────────────────────────────
const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
const URL_RE = /https?:\/\/[^\s"'<>()\[\]\\]+/g;
const UNC_RE = /\\\\[A-Za-z0-9_\-\.]+\\[^\s"'<>]+/g;
const PATH_WIN_RE = /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\?)+/g;
const PATH_UNIX_RE = /\/(?:home|Users|var|etc|opt|usr)\/[^\s"'<>]+/g;
const USERNAME_WIN_RE = /[A-Za-z]:\\[Uu]sers\\([^\\]+)/;
const USERNAME_UNC_RE = /\\\\[^\\]+\\([^\\]+)/;

// ── Helpers ────────────────────────────────────────────────────────────────
function dedup<T>(arr: T[]): T[] {
    return [...new Set(arr)].filter(Boolean) as T[];
}

function normalizeToUTC(d: Date | undefined | null): string | null {
    if (!d || isNaN(d.getTime())) return null;
    return d.toISOString(); // ISO 8601 UTC
}

function detectVendors(text: string): string[] {
    const lower = text.toLowerCase();
    const found: string[] = [];
    for (const [vendor, keywords] of Object.entries(VENDOR_PATTERNS)) {
        if (keywords.some(k => lower.includes(k))) found.push(vendor);
    }
    return dedup(found);
}

function detectOS(text: string): string | null {
    const lower = text.toLowerCase();
    for (const [os, keywords] of Object.entries(OS_PATTERNS)) {
        if (keywords.some(k => lower.includes(k))) return os;
    }
    return null;
}

function extractUsernameFromPath(path: string): string | null {
    const winMatch = path.match(USERNAME_WIN_RE);
    if (winMatch) return winMatch[1];
    const uncMatch = path.match(USERNAME_UNC_RE);
    if (uncMatch) return uncMatch[1];
    return null;
}

function classifyIP(ip: string): 'private' | 'loopback' | 'link-local' | 'public' {
    if (ip === '127.0.0.1' || ip.startsWith('127.')) return 'loopback';
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return 'private';
    if (ip.startsWith('169.254.')) return 'link-local';
    return 'public';
}

// ── Output Types ───────────────────────────────────────────────────────────

export interface NormalizedIdentity {
    /** Cleaned author/creator name */
    author: string | null;
    /** Last editor (if different from author) */
    lastModifiedBy: string | null;
    /** Device owner */
    deviceOwner: string | null;
    /** Organization */
    organization: string | null;
    /** Usernames extracted from embedded file paths */
    usernamesFromPaths: string[];
    /** All emails found in the file */
    emails: string[];
    /** Source paths where usernames were extracted */
    pathSources: string[];
}

export interface NormalizedDevice {
    /** Device make + model */
    device: string | null;
    /** Detected operating system */
    operatingSystem: string | null;
    /** OS detection method */
    osSource: 'metadata' | 'software_string' | 'path_pattern' | null;
    /** Color space (for images) */
    colorSpace: string | null;
    /** Image dimensions */
    dimensions: { width: number; height: number } | null;
    /** DPI */
    dpi: number | null;
}

export interface NormalizedNetwork {
    /** All email addresses found */
    emails: string[];
    /** IPv4 addresses with classification */
    ipv4Addresses: Array<{ ip: string; classification: 'public' | 'private' | 'loopback' | 'link-local' }>;
    /** IPv6 addresses */
    ipv6Addresses: string[];
    /** External URLs */
    urls: string[];
    /** UNC / SMB network share paths */
    uncPaths: string[];
    /** Resolved hostnames */
    hostnames: string[];
}

export interface NormalizedTimeline {
    /** ISO 8601 UTC — from embedded metadata creation date */
    creationDateUTC: string | null;
    /** ISO 8601 UTC — from embedded metadata modification */
    modificationDateUTC: string | null;
    /** ISO 8601 UTC — file system last-modified date */
    filesystemLastModifiedUTC: string | null;
    /** ISO 8601 UTC — time file was uploaded to this system */
    uploadTimestampUTC: string | null;
    /** ISO 8601 UTC — access date (if available) */
    accessDateUTC: string | null;
    /** UTC offset or timezone string embedded in the file */
    embeddedTimezone: string | null;
    /** GPS timestamp */
    gpsTimestampUTC: string | null;
    /** Ordered events for forensic sequencing */
    eventChronology: Array<{ label: string; utc: string }>;
}

export interface NormalizedLocation {
    /** Decimal degrees latitude */
    latitude: number | null;
    /** Decimal degrees longitude */
    longitude: number | null;
    /** Altitude in metres */
    altitudeMetres: number | null;
    /** Precision estimate in metres */
    precisionEstimateMetres: string | null;
    /** Google Maps deep link */
    googleMapsUrl: string | null;
    /** Reference string (e.g. country/region from IPTC) */
    locationReference: string | null;
    /** Whether coordinates appear suspicious */
    coordinateSuspicion: 'none' | 'null_island' | 'excessive_precision';
}

export interface NormalizedSoftware {
    /** Primary software string */
    primarySoftware: string | null;
    /** Normalized version string */
    version: string | null;
    /** Detected OS (from any source) */
    operatingSystem: string | null;
    /** Software vendor brands detected */
    vendors: string[];
    /** ExifTool-style creator tool (XMP) */
    creatorTool: string | null;
    /** All software-related strings found */
    allSoftwareStrings: string[];
    /** Whether the file passed through multiple editing pipelines */
    multipleEditorsPipeline: boolean;
}

export interface NormalizedMetadata {
    /** Timestamp when normalization ran (UTC) */
    normalizedAt: string;
    /** Source file name */
    fileName: string;
    /** SHA-256 of the original file */
    sha256: string;
    identity_data: NormalizedIdentity;
    device_data: NormalizedDevice;
    network_data: NormalizedNetwork;
    timeline_data: NormalizedTimeline;
    location_data: NormalizedLocation;
    software_data: NormalizedSoftware;
}

// ── Main Normalization Function ────────────────────────────────────────────

export function normalizeMetadata(result: AnalysisResult): NormalizedMetadata {
    const m = result.metadata;
    const net = result.networkIndicators;
    const rawJSON = result.rawForensicJSON as Record<string, unknown>;

    // Collect all text strings to scan for extra patterns
    const allStrings: string[] = [
        m.software, m.softwareVersion, m.appVersion, m.operatingSystem,
        m.author, m.creator, m.lastModifiedBy, m.organization, m.deviceOwner, m.device,
        ...(net.uncPaths),
        ...Object.values(m.exifData || {}).map(v => String(v ?? '')),
    ].filter(Boolean) as string[];
    const combinedText = allStrings.join(' ');

    // ── identity_data ─────────────────────────────────────────────────────────
    // Extract usernames from all path-like strings
    const pathsToCheck = [
        ...(net.uncPaths),
        ...allStrings.filter(s => PATH_WIN_RE.test(s) || PATH_UNIX_RE.test(s)),
    ];
    const usernamesFromPaths = dedup(
        pathsToCheck.map(p => extractUsernameFromPath(p)).filter(Boolean) as string[]
    );
    const pathSources = dedup(pathsToCheck.filter(p =>
        PATH_WIN_RE.test(p) || PATH_UNIX_RE.test(p) || p.includes('\\\\')
    ));

    const identity_data: NormalizedIdentity = {
        author: m.author ? m.author.trim() : null,
        lastModifiedBy: m.lastModifiedBy ? m.lastModifiedBy.trim() : null,
        deviceOwner: m.deviceOwner ? m.deviceOwner.trim() : null,
        organization: m.organization ? m.organization.trim() : null,
        usernamesFromPaths,
        emails: dedup(net.emails.map(e => e.toLowerCase().trim())),
        pathSources: pathSources.slice(0, 10),
    };

    // ── device_data ───────────────────────────────────────────────────────────
    let osSource: NormalizedDevice['osSource'] = null;
    let operatingSystem: string | null = m.operatingSystem ?? null;

    if (operatingSystem) {
        osSource = 'metadata';
    } else if (m.software) {
        const detected = detectOS(m.software);
        if (detected) { operatingSystem = detected; osSource = 'software_string'; }
    }
    if (!operatingSystem) {
        const detected = detectOS(combinedText);
        if (detected) { operatingSystem = detected; osSource = 'path_pattern'; }
    }

    const device_data: NormalizedDevice = {
        device: m.device ? m.device.trim() : null,
        operatingSystem,
        osSource,
        colorSpace: m.colorSpace ? m.colorSpace.trim() : null,
        dimensions: m.dimensions ?? null,
        dpi: m.dpi ?? null,
    };

    // ── network_data ──────────────────────────────────────────────────────────
    // Also scan rawForensicJSON fields for extra IPs/emails
    const rawText = JSON.stringify(rawJSON);
    const extraEmails = (rawText.match(EMAIL_RE) || []).map(e => e.toLowerCase());
    const extraIPv4 = (rawText.match(IPV4_RE) || []);
    const extraIPv6 = (rawText.match(IPV6_RE) || []);

    const allEmails = dedup([...net.emails, ...extraEmails]).map(e => e.toLowerCase());
    const allIPv4 = dedup([...net.ips, ...extraIPv4]).filter(ip =>
        !ip.startsWith('0.') && !ip.startsWith('255.') && ip !== '0.0.0.0'
    );
    const allIPv6 = dedup([...extraIPv6]);

    const network_data: NormalizedNetwork = {
        emails: allEmails,
        ipv4Addresses: allIPv4.map(ip => ({ ip, classification: classifyIP(ip) })),
        ipv6Addresses: allIPv6,
        urls: dedup(net.urls),
        uncPaths: dedup(net.uncPaths),
        hostnames: dedup(net.hostnames),
    };

    // ── timeline_data ─────────────────────────────────────────────────────────
    const events: Array<{ label: string; utc: string }> = [];
    const addEvent = (label: string, d: Date | undefined | null) => {
        const utc = normalizeToUTC(d);
        if (utc) events.push({ label, utc });
    };
    addEvent('Created (embedded)', m.creationDate);
    addEvent('Modified (embedded)', m.modificationDate);
    addEvent('File system last-modified', m.lastModified);
    addEvent('Access date', m.accessDate);
    addEvent('Upload timestamp', m.uploadTimestamp);

    events.sort((a, b) => a.utc.localeCompare(b.utc));

    // Normalize GPS timestamp to UTC if it looks like a time string
    let gpsUTC: string | null = null;
    if (m.gpsTimestamp) {
        const d = new Date(m.gpsTimestamp);
        gpsUTC = isNaN(d.getTime()) ? m.gpsTimestamp : d.toISOString();
    }

    const timeline_data: NormalizedTimeline = {
        creationDateUTC: normalizeToUTC(m.creationDate),
        modificationDateUTC: normalizeToUTC(m.modificationDate),
        filesystemLastModifiedUTC: normalizeToUTC(m.lastModified),
        uploadTimestampUTC: normalizeToUTC(m.uploadTimestamp),
        accessDateUTC: normalizeToUTC(m.accessDate),
        embeddedTimezone: m.timezone ?? null,
        gpsTimestampUTC: gpsUTC,
        eventChronology: events,
    };

    // ── location_data ─────────────────────────────────────────────────────────
    const lat = m.gpsLatitude ?? null;
    const lon = m.gpsLongitude ?? null;
    let coordinateSuspicion: NormalizedLocation['coordinateSuspicion'] = 'none';

    if (lat !== null && lon !== null) {
        if (Math.abs(lat) < 0.001 && Math.abs(lon) < 0.001) {
            coordinateSuspicion = 'null_island';
        } else {
            const latDec = (lat.toString().split('.')[1] || '').length;
            const lonDec = (lon.toString().split('.')[1] || '').length;
            if (latDec > 6 || lonDec > 6) coordinateSuspicion = 'excessive_precision';
        }
    }

    const location_data: NormalizedLocation = {
        latitude: lat,
        longitude: lon,
        altitudeMetres: m.gpsAltitude ?? null,
        precisionEstimateMetres: lat !== null ? '~1–5 m (consumer GPS)' : null,
        googleMapsUrl: lat !== null && lon !== null
            ? `https://www.google.com/maps?q=${lat},${lon}`
            : null,
        locationReference: m.locationReference ?? null,
        coordinateSuspicion,
    };

    // ── software_data ──────────────────────────────────────────────────────────
    const softwareStrings = dedup([
        m.software, m.softwareVersion, m.appVersion, m.creator, m.operatingSystem,
        (m.exifData as Record<string, unknown>)?.['CreatorTool'] as string | undefined,
        (m.exifData as Record<string, unknown>)?.['Software'] as string | undefined,
    ].filter(Boolean) as string[]);

    const vendors = detectVendors(combinedText);

    // Check for multi-editor pipeline
    const editorKeywords = [
        'photoshop', 'gimp', 'lightroom', 'affinity', 'pixelmator', 'canva',
        'ffmpeg', 'handbrake', 'davinci', 'premiere', 'final cut',
    ];
    const editorsDetected = editorKeywords.filter(k => combinedText.toLowerCase().includes(k));
    const multipleEditorsPipeline = editorsDetected.length > 1;

    // Normalize version string
    let version: string | null = m.softwareVersion ?? m.appVersion ?? null;
    if (!version && m.software) {
        const vMatch = m.software.match(/v?(\d+[\.\d]*)/i);
        if (vMatch) version = vMatch[1];
    }

    const creatorTool = (m.exifData as Record<string, unknown>)?.['CreatorTool'] as string | null ?? null;

    const software_data: NormalizedSoftware = {
        primarySoftware: m.software ?? null,
        version,
        operatingSystem: operatingSystem,
        vendors,
        creatorTool,
        allSoftwareStrings: softwareStrings,
        multipleEditorsPipeline,
    };

    return {
        normalizedAt: new Date().toISOString(),
        fileName: m.fileName,
        sha256: m.sha256Hash,
        identity_data,
        device_data,
        network_data,
        timeline_data,
        location_data,
        software_data,
    };
}
