/**
 * Privacy & Forensic Exposure Risk Analyzer
 * ───────────────────────────────────────────
 * Scores four independent exposure dimensions then fuses them into a
 * single overall_risk_score with prioritised sanitization recommendations.
 *
 * Dimensions:
 *   1. Identity Leakage Risk       – author names, emails, usernames, org fields
 *   2. Location Exposure Risk      – GPS, timezone, location references
 *   3. Device Traceability         – camera make/model, OS, software fingerprints
 *   4. Network Attribution Risk    – IPs, UNC paths, URLs, cloud storage references
 */

import { AnalysisResult } from './types';
import { NormalizedMetadata } from './metadata-normalizer';

// ── Shared enums ────────────────────────────────────────────────────────────

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'minimal';

// ── Per-dimension result ─────────────────────────────────────────────────────

export interface RiskDimension {
    /** Dimension name */
    name: string;
    /** Sub-score 0–100 */
    score: number;
    /** Colour-coded level */
    level: RiskLevel;
    /** Specific data fields that contributed points */
    contributing_factors: ContributingFactor[];
    /** Top 3 findings in plain English */
    top_findings: string[];
}

export interface ContributingFactor {
    field: string;          // e.g. "metadata.author"
    value: string;          // e.g. "Jane Smith"
    points: number;         // raw points added (before clamping)
    rationale: string;      // one-sentence forensic rationale
    severity: 'critical' | 'high' | 'medium' | 'low';
}

// ── Leak source (aggregated across all dimensions) ───────────────────────────

export interface LeakSource {
    id: string;
    category: 'identity' | 'location' | 'device' | 'network';
    field: string;
    value: string;
    exposure_description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    /** Short OSINT vector title */
    osint_vector: string;
}

// ── Sanitization action ──────────────────────────────────────────────────────

export interface SanitizationAction {
    priority: 1 | 2 | 3;   // 1 = immediate, 2 = recommended, 3 = optional
    action: string;         // imperative sentence
    tool_suggestions: string[];
    affected_fields: string[];
    risk_reduction_estimate: number;   // pts removed from overall score if done
}

// ── Full report ──────────────────────────────────────────────────────────────

export interface PrivacyRiskReport {
    analyzed_at: string;
    file_name: string;
    sha256: string;

    /** Composite 0–100 */
    overall_risk_score: number;
    risk_level: RiskLevel;

    /** Per-dimension breakdowns */
    identity_leakage: RiskDimension;
    location_exposure: RiskDimension;
    device_traceability: RiskDimension;
    network_attribution: RiskDimension;

    /** Consolidated unique leak sources (sorted by severity) */
    key_leak_sources: LeakSource[];

    /** Ordered sanitization plan */
    recommended_sanitization_actions: SanitizationAction[];

    /** One-paragraph executive summary */
    executive_summary: string;

    /** Percentage of metadata fields that contain identifying data */
    metadata_density_pct: number;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function clamp(n: number, max = 100): number {
    return Math.max(0, Math.min(max, Math.round(n)));
}

function levelFromScore(s: number): RiskLevel {
    if (s >= 80) return 'critical';
    if (s >= 60) return 'high';
    if (s >= 35) return 'medium';
    if (s >= 10) return 'low';
    return 'minimal';
}

function severityFromPts(pts: number): ContributingFactor['severity'] {
    if (pts >= 25) return 'critical';
    if (pts >= 15) return 'high';
    if (pts >= 8) return 'medium';
    return 'low';
}

let _lid = 0;
function lid() { return `ls_${++_lid}`; }

const FREE_MAIL = new Set([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
    'protonmail.com', 'me.com', 'live.com', 'aol.com', 'mail.com', 'ymail.com',
]);

// ── Dimension 1: Identity Leakage ────────────────────────────────────────────

function scoreIdentityLeakage(
    result: AnalysisResult,
    n: NormalizedMetadata,
): { dim: RiskDimension; leaks: LeakSource[] } {
    const factors: ContributingFactor[] = [];
    const leaks: LeakSource[] = [];
    let raw = 0;

    const id = n.identity_data;
    const net = n.network_data;

    // Author / Creator name
    if (id.author) {
        const pts = 25;
        factors.push({
            field: 'metadata.author', value: id.author, points: pts, severity: 'high',
            rationale: 'The author name directly identifies the human who created the file and can be cross-referenced on LinkedIn, GitHub, and OSINT databases.'
        });
        leaks.push({
            id: lid(), category: 'identity', field: 'metadata.author', value: id.author,
            exposure_description: `Real name "${id.author}" embedded in author field — cross-referenceable on social platforms and professional networks.`,
            severity: 'high', osint_vector: 'Social media / LinkedIn search'
        });
        raw += pts;
    }

    // Last modified by (second identity)
    if (id.lastModifiedBy && id.lastModifiedBy !== id.author) {
        const pts = 20;
        factors.push({
            field: 'metadata.lastModifiedBy', value: id.lastModifiedBy, points: pts, severity: 'high',
            rationale: 'A secondary editor name reveals a second individual identity and suggests collaborative editing history.'
        });
        leaks.push({
            id: lid(), category: 'identity', field: 'metadata.lastModifiedBy', value: id.lastModifiedBy,
            exposure_description: `Secondary editor "${id.lastModifiedBy}" identified — reveals a second individual who touched this file.`,
            severity: 'high', osint_vector: 'Author ↔ editor split analysis'
        });
        raw += pts;
    }

    // Device owner
    if (id.deviceOwner) {
        const pts = 20;
        factors.push({
            field: 'metadata.deviceOwner', value: id.deviceOwner, points: pts, severity: 'high',
            rationale: 'Device owner links a physical device (and its geolocation history) directly to a named individual.'
        });
        leaks.push({
            id: lid(), category: 'identity', field: 'metadata.deviceOwner', value: id.deviceOwner,
            exposure_description: `Device owner "${id.deviceOwner}" — ties the hardware to a real person.`,
            severity: 'high', osint_vector: 'Device-to-person attribution'
        });
        raw += pts;
    }

    // Organization
    if (id.organization) {
        const pts = 15;
        factors.push({
            field: 'metadata.organization', value: id.organization, points: pts, severity: 'medium',
            rationale: 'Organization name enables targeted corporate OSINT and can narrow down the creator\'s employer.'
        });
        leaks.push({
            id: lid(), category: 'identity', field: 'metadata.organization', value: id.organization,
            exposure_description: `Organization "${id.organization}" embedded — enables corporate attribution.`,
            severity: 'medium', osint_vector: 'LinkedIn / WHOIS / Crunchbase'
        });
        raw += pts;
    }

    // Emails
    for (const email of net.emails.slice(0, 5)) {
        const domain = email.split('@')[1] ?? '';
        const isCorp = domain && !FREE_MAIL.has(domain);
        const pts = isCorp ? 30 : 18;
        factors.push({
            field: 'network.email', value: email, points: pts, severity: isCorp ? 'critical' : 'high',
            rationale: isCorp
                ? `Corporate email "${email}" provides organizational attribution and can be cross-referenced against breach databases, WHOIS, and LinkedIn.`
                : `Personal email "${email}" can be searched for in breach databases and linked across platforms.`
        });
        leaks.push({
            id: lid(), category: 'identity', field: 'network.email', value: email,
            exposure_description: isCorp
                ? `Corporate email "${email}" — enables org + individual attribution simultaneously.`
                : `Personal email "${email}" — searchable in HaveIBeenPwned and social platforms.`,
            severity: isCorp ? 'critical' : 'high', osint_vector: isCorp ? 'HaveIBeenPwned / LinkedIn / WHOIS' : 'HaveIBeenPwned breach lookup'
        });
        raw += pts;
    }

    // Usernames from paths
    for (const u of id.usernamesFromPaths.slice(0, 3)) {
        const pts = 15;
        factors.push({
            field: 'path.username', value: u, points: pts, severity: 'medium',
            rationale: `OS account username "${u}" extracted from embedded file path — links the file to a specific system account.`
        });
        leaks.push({
            id: lid(), category: 'identity', field: 'path.username', value: u,
            exposure_description: `OS login username "${u}" found in embedded path — can correlate with email local-parts and GitHub handles.`,
            severity: 'medium', osint_vector: 'Username enumeration across platforms'
        });
        raw += pts;
    }

    const score = clamp(raw);
    const top_findings: string[] = [];
    if (id.author || id.lastModifiedBy) top_findings.push(`Real name(s) embedded: ${[id.author, id.lastModifiedBy].filter(Boolean).join(', ')}`);
    if (net.emails.length > 0) top_findings.push(`${net.emails.length} email address${net.emails.length > 1 ? 'es' : ''} found: ${net.emails.slice(0, 2).join(', ')}${net.emails.length > 2 ? '…' : ''}`);
    if (id.organization) top_findings.push(`Organization field present: "${id.organization}"`);
    if (id.usernamesFromPaths.length > 0) top_findings.push(`OS username(s) in embedded paths: ${id.usernamesFromPaths.slice(0, 2).join(', ')}`);

    return {
        dim: { name: 'Identity Leakage Risk', score, level: levelFromScore(score), contributing_factors: factors, top_findings: top_findings.slice(0, 4) },
        leaks,
    };
}

// ── Dimension 2: Location Exposure ───────────────────────────────────────────

function scoreLocationExposure(
    result: AnalysisResult,
    n: NormalizedMetadata,
): { dim: RiskDimension; leaks: LeakSource[] } {
    const factors: ContributingFactor[] = [];
    const leaks: LeakSource[] = [];
    let raw = 0;

    const loc = n.location_data;
    const tl = n.timeline_data;
    const m = result.metadata;

    // GPS coordinates (highest risk)
    if (loc.latitude !== null && loc.longitude !== null) {
        const suspicion = loc.coordinateSuspicion;
        if (suspicion === 'null_island') {
            // Low risk — coords are fake/zeroed
            const pts = 5;
            factors.push({
                field: 'gps.coordinates', value: '0°, 0°', points: pts, severity: 'low',
                rationale: 'GPS zeroed to Null Island — probably cleared, but the presence of GPS fields is itself a signal.'
            });
            raw += pts;
        } else {
            const pts = suspicion === 'excessive_precision' ? 30 : 40;
            factors.push({
                field: 'gps.coordinates',
                value: `${loc.latitude?.toFixed(5)}, ${loc.longitude?.toFixed(5)}`,
                points: pts, severity: 'critical',
                rationale: 'Precise GPS coordinates reveal exactly where the photo/file was taken, potentially exposing a home, office, or secret location.'
            });
            leaks.push({
                id: lid(), category: 'location', field: 'gps.coordinates',
                value: `${loc.latitude?.toFixed(5)}°N, ${loc.longitude?.toFixed(5)}°E`,
                exposure_description: `GPS coordinates ${loc.latitude?.toFixed(5)}, ${loc.longitude?.toFixed(5)} — pinpoints exact physical location at time of capture.`,
                severity: 'critical', osint_vector: 'Google Maps reverse geocode / Google Street View'
            });
            raw += pts;

            // Altitude adds precision
            if (loc.altitudeMetres !== null) {
                const apt = 5;
                factors.push({
                    field: 'gps.altitude', value: `${loc.altitudeMetres} m`, points: apt, severity: 'low',
                    rationale: 'Altitude data allows vertical location identification (floor in a building, mountain elevation).'
                });
                raw += apt;
            }
        }
    }

    // GPS Timestamp
    if (tl.gpsTimestampUTC) {
        const pts = 10;
        factors.push({
            field: 'gps.timestamp', value: tl.gpsTimestampUTC, points: pts, severity: 'medium',
            rationale: 'GPS timestamp provides temporal context for the physical location — can be correlated with CCTV, cell records, or other time-anchored evidence.'
        });
        raw += pts;
    }

    // Timezone (softer signal)
    if (tl.embeddedTimezone) {
        const pts = 10;
        factors.push({
            field: 'metadata.timezone', value: tl.embeddedTimezone, points: pts, severity: 'low',
            rationale: `Embedded timezone "${tl.embeddedTimezone}" narrows the creator's geographic region to the corresponding timezone band.`
        });
        leaks.push({
            id: lid(), category: 'location', field: 'metadata.timezone', value: tl.embeddedTimezone,
            exposure_description: `Timezone "${tl.embeddedTimezone}" narrows probable geographic region.`,
            severity: 'low', osint_vector: 'Geographic region narrowing'
        });
        raw += pts;
    }

    // Location reference field
    if (m.locationReference) {
        const pts = 20;
        factors.push({
            field: 'metadata.locationReference', value: m.locationReference, points: pts, severity: 'high',
            rationale: 'Explicit location reference field (country/city/landmark) provides direct geographic attribution.'
        });
        leaks.push({
            id: lid(), category: 'location', field: 'metadata.locationReference', value: m.locationReference,
            exposure_description: `Location reference "${m.locationReference}" directly names a geographic location.`,
            severity: 'high', osint_vector: 'Direct location identification'
        });
        raw += pts;
    }

    const score = clamp(raw);
    const top_findings: string[] = [];
    if (loc.latitude !== null && loc.coordinateSuspicion !== 'null_island')
        top_findings.push(`GPS coordinates present: ${loc.latitude?.toFixed(5)}, ${loc.longitude?.toFixed(5)}`);
    if (tl.embeddedTimezone)
        top_findings.push(`Timezone embedded: ${tl.embeddedTimezone}`);
    if (m.locationReference)
        top_findings.push(`Location reference: "${m.locationReference}"`);
    if (score === 0)
        top_findings.push('No location data embedded — minimal location exposure');

    return {
        dim: { name: 'Location Exposure Risk', score, level: levelFromScore(score), contributing_factors: factors, top_findings: top_findings.slice(0, 4) },
        leaks,
    };
}

// ── Dimension 3: Device Traceability ─────────────────────────────────────────

function scoreDeviceTraceability(
    result: AnalysisResult,
    n: NormalizedMetadata,
): { dim: RiskDimension; leaks: LeakSource[] } {
    const factors: ContributingFactor[] = [];
    const leaks: LeakSource[] = [];
    let raw = 0;

    const dev = n.device_data;
    const sw = n.software_data;
    const m = result.metadata;

    // Camera / device model
    if (dev.device) {
        const pts = 25;
        factors.push({
            field: 'metadata.device', value: dev.device, points: pts, severity: 'high',
            rationale: 'Camera/device make & model creates a hardware fingerprint. Combined with GPS and timestamps, this can uniquely identify a device across multiple files.'
        });
        leaks.push({
            id: lid(), category: 'device', field: 'metadata.device', value: dev.device,
            exposure_description: `Device "${dev.device}" fingerprinted — paired with GPS/timestamps this links multiple files to the same hardware.`,
            severity: 'high', osint_vector: 'Cross-file device matching / IMEI lookup'
        });
        raw += pts;
    }

    // Operating system
    if (dev.operatingSystem) {
        const pts = 12;
        factors.push({
            field: 'device.operatingSystem', value: `${dev.operatingSystem} (via ${dev.osSource})`, points: pts, severity: 'medium',
            rationale: 'OS identification narrows the software environment and reveals the computing ecosystem of the creator.'
        });
        leaks.push({
            id: lid(), category: 'device', field: 'device.operatingSystem', value: dev.operatingSystem,
            exposure_description: `OS "${dev.operatingSystem}" identified — narrows creator's computing environment.`,
            severity: 'medium', osint_vector: 'OS ecosystem fingerprinting'
        });
        raw += pts;
    }

    // Software / creator tool
    if (sw.primarySoftware) {
        const pts = 15;
        factors.push({
            field: 'metadata.software', value: sw.primarySoftware, points: pts, severity: 'medium',
            rationale: 'Software version strings can fingerprint a specific app version, potentially revealing unpatched vulnerabilities or license key data.'
        });
        leaks.push({
            id: lid(), category: 'device', field: 'metadata.software', value: sw.primarySoftware,
            exposure_description: `Software "${sw.primarySoftware}" — version fingerprint reveals app ecosystem and potential CVE exposure.`,
            severity: 'medium', osint_vector: 'Software version / CVE correlation'
        });
        raw += pts;
    }

    if (sw.creatorTool && sw.creatorTool !== sw.primarySoftware) {
        const pts = 8;
        factors.push({
            field: 'software.creatorTool', value: sw.creatorTool, points: pts, severity: 'low',
            rationale: 'XMP CreatorTool field reveals a second application in the creation pipeline.'
        });
        raw += pts;
    }

    // Version string exposure
    if (sw.version) {
        const pts = 8;
        factors.push({
            field: 'software.version', value: sw.version, points: pts, severity: 'low',
            rationale: 'Specific version number can be matched against known CVE databases or used to identify a narrow release window.'
        });
        raw += pts;
    }

    // Multi-editor pipeline (higher traceability)
    if (sw.multipleEditorsPipeline) {
        const pts = 10;
        factors.push({
            field: 'software.multipleEditorsPipeline', value: 'true', points: pts, severity: 'medium',
            rationale: 'Multiple editing tools detected — more software fingerprints = more traceability vectors.'
        });
        raw += pts;
    }

    // Image dimensions (can help identify exact camera sensor)
    if (dev.dimensions) {
        const { width, height } = dev.dimensions;
        const megapixels = ((width * height) / 1_000_000).toFixed(1);
        const pts = 5;
        factors.push({
            field: 'device.dimensions', value: `${width}×${height} (${megapixels} MP)`, points: pts, severity: 'low',
            rationale: `Image resolution ${width}×${height} can help narrow down the exact camera model or sensor within a device family.`
        });
        raw += pts;
    }

    const score = clamp(raw);
    const top_findings: string[] = [];
    if (dev.device) top_findings.push(`Camera/device model: "${dev.device}"`);
    if (dev.operatingSystem) top_findings.push(`OS fingerprint: ${dev.operatingSystem} (detected via ${dev.osSource})`);
    if (sw.primarySoftware) top_findings.push(`Software: "${sw.primarySoftware}"${sw.version ? ` v${sw.version}` : ''}`);
    if (sw.multipleEditorsPipeline) top_findings.push('Multiple editing tools detected — enhanced device traceability');
    if (score === 0) top_findings.push('No device or software metadata embedded');

    return {
        dim: { name: 'Device Traceability', score, level: levelFromScore(score), contributing_factors: factors, top_findings: top_findings.slice(0, 4) },
        leaks,
    };
}

// ── Dimension 4: Network Attribution Risk ────────────────────────────────────

function scoreNetworkAttribution(
    result: AnalysisResult,
    n: NormalizedMetadata,
): { dim: RiskDimension; leaks: LeakSource[] } {
    const factors: ContributingFactor[] = [];
    const leaks: LeakSource[] = [];
    let raw = 0;

    const net = n.network_data;
    const m = result.metadata;

    // Public IPs
    const publicIPs = net.ipv4Addresses.filter(p => p.classification === 'public');
    const privateIPs = net.ipv4Addresses.filter(p => p.classification === 'private');

    for (const { ip } of publicIPs.slice(0, 5)) {
        const pts = 30;
        factors.push({
            field: 'network.ip_public', value: ip, points: pts, severity: 'critical',
            rationale: `Public IP ${ip} can be geolocated, WHOIS-queried, and correlated with ISP/ASN data to identify the originating network.`
        });
        leaks.push({
            id: lid(), category: 'network', field: 'network.ip.public', value: ip,
            exposure_description: `Public IP ${ip} — geolocatable, WHOIS-queryable, ISP/ASN attribution possible.`,
            severity: 'critical', osint_vector: 'IP geolocation / WHOIS / Shodan'
        });
        raw += pts;
    }

    for (const { ip } of privateIPs.slice(0, 5)) {
        const pts = 15;
        factors.push({
            field: 'network.ip_private', value: ip, points: pts, severity: 'medium',
            rationale: `Private IP ${ip} reveals internal subnet structure — useful for network topology mapping and lateral movement.`
        });
        leaks.push({
            id: lid(), category: 'network', field: 'network.ip.private', value: ip,
            exposure_description: `Private IP ${ip} — reveals internal network architecture and DHCP assignment ranges.`,
            severity: 'medium', osint_vector: 'Internal network topology mapping'
        });
        raw += pts;
    }

    // UNC paths
    for (const unc of net.uncPaths.slice(0, 3)) {
        const pts = 25;
        factors.push({
            field: 'network.uncPath', value: unc, points: pts, severity: 'critical',
            rationale: `UNC path "${unc}" exposes internal server hostnames and share names — represents a serious internal-network disclosure.`
        });
        leaks.push({
            id: lid(), category: 'network', field: 'network.uncPath', value: unc,
            exposure_description: `UNC path "${unc}" reveals internal server name and share structure.`,
            severity: 'critical', osint_vector: 'Internal infrastructure enumeration / SMB access attempt'
        });
        raw += pts;
    }

    // External URLs
    const noiseDomains = ['schemas.openxmlformats.org', 'schemas.microsoft.com', 'www.w3.org', 'purl.org', 'ns.adobe.com'];
    const cleanURLs = net.urls.filter(u => !noiseDomains.some(d => u.includes(d)));
    for (const url of cleanURLs.slice(0, 3)) {
        const isCloud = /dropbox|onedrive|drive\.google|s3\.amazonaws|azure\.blob|box\.com|icloud/i.test(url);
        const pts = isCloud ? 20 : 10;
        factors.push({
            field: 'network.url', value: url.slice(0, 80), points: pts, severity: isCloud ? 'high' : 'medium',
            rationale: isCloud
                ? `Cloud storage URL reveals the cloud service used and may still link to a live, accessible document.`
                : `Embedded URL "${url.slice(0, 60)}…" creates a network beacon when fetched and may reveal source origin.`
        });
        if (isCloud) {
            leaks.push({
                id: lid(), category: 'network', field: 'network.url.cloud', value: url.slice(0, 80),
                exposure_description: `Cloud URL — may be live and publicly accessible; reveals cloud storage service used.`,
                severity: 'high', osint_vector: 'Cloud storage access / sharing analysis'
            });
        }
        raw += pts;
    }

    // Hostnames
    const internalHosts = net.hostnames.filter(h => /\.(local|corp|internal|lan|intranet|ad)$/i.test(h));
    for (const host of internalHosts.slice(0, 3)) {
        const pts = 15;
        factors.push({
            field: 'network.hostname.internal', value: host, points: pts, severity: 'high',
            rationale: `Internal hostname "${host}" reveals corporate naming conventions and internal DNS zones.`
        });
        leaks.push({
            id: lid(), category: 'network', field: 'network.hostname.internal', value: host,
            exposure_description: `Internal hostname "${host}" reveals corporate network naming and DNS structure.`,
            severity: 'high', osint_vector: 'Internal DNS enumeration / hostname pivoting'
        });
        raw += pts;
    }

    const score = clamp(raw);
    const top_findings: string[] = [];
    if (publicIPs.length > 0) top_findings.push(`${publicIPs.length} public IP${publicIPs.length > 1 ? 's' : ''}: ${publicIPs.slice(0, 2).map(p => p.ip).join(', ')}`);
    if (net.uncPaths.length > 0) top_findings.push(`${net.uncPaths.length} UNC path${net.uncPaths.length > 1 ? 's' : ''}: ${net.uncPaths[0]}`);
    if (cleanURLs.length > 0) top_findings.push(`${cleanURLs.length} external URL${cleanURLs.length > 1 ? 's' : ''} embedded`);
    if (internalHosts.length > 0) top_findings.push(`Internal hostnames: ${internalHosts.join(', ')}`);
    if (privateIPs.length > 0) top_findings.push(`${privateIPs.length} private/internal IP${privateIPs.length > 1 ? 's' : ''}: ${privateIPs.slice(0, 2).map(p => p.ip).join(', ')}`);
    if (score === 0) top_findings.push('No network artifacts detected — minimal network attribution risk');

    return {
        dim: { name: 'Network Attribution Risk', score, level: levelFromScore(score), contributing_factors: factors, top_findings: top_findings.slice(0, 4) },
        leaks,
    };
}

// ── Sanitization plan ────────────────────────────────────────────────────────

function buildSanitizationPlan(
    identity: RiskDimension,
    location: RiskDimension,
    device: RiskDimension,
    network: RiskDimension,
    n: NormalizedMetadata,
): SanitizationAction[] {
    const actions: SanitizationAction[] = [];

    // GPS removal (P1 if GPS is critical)
    if (location.score >= 35) {
        actions.push({
            priority: 1,
            action: 'Strip all GPS / location metadata from the file before distribution',
            tool_suggestions: ['ExifTool: exiftool -gps:all= -location:all= file.jpg', 'Adobe Photoshop → File Info → delete GPS fields', 'GIMP → File → Export As → uncheck "Save EXIF data"'],
            affected_fields: ['gps.latitude', 'gps.longitude', 'gps.altitude', 'gps.timestamp', 'metadata.locationReference'],
            risk_reduction_estimate: location.score,
        });
    }

    // Author / identity wipe (P1 if identity is high)
    if (identity.score >= 35) {
        actions.push({
            priority: 1,
            action: 'Remove all author, editor, and owner identity fields from document metadata',
            tool_suggestions: ['ExifTool: exiftool -Author= -Artist= -Creator= -LastModifiedBy= file', 'Microsoft Word → File → Info → Check for Issues → Inspect Document → Remove Personal Information', 'LibreOffice → Tools → Macros → remove personal data on save'],
            affected_fields: ['metadata.author', 'metadata.lastModifiedBy', 'metadata.deviceOwner', 'metadata.organization'],
            risk_reduction_estimate: Math.round(identity.score * 0.7),
        });
    }

    // Email scrub
    if (n.network_data.emails.length > 0) {
        actions.push({
            priority: 1,
            action: 'Scan and redact all embedded email addresses from the file body and metadata',
            tool_suggestions: ['ExifTool: exiftool -email= file', 'PDF: use PDF redaction tools (Adobe Acrobat Pro → Redact → Find & Redact Text)', 'Manual search-and-replace in source documents before export'],
            affected_fields: n.network_data.emails.map(e => `network.email:${e}`),
            risk_reduction_estimate: Math.round(identity.score * 0.4),
        });
    }

    // UNC path removal
    if (n.network_data.uncPaths.length > 0) {
        actions.push({
            priority: 1,
            action: 'Remove all embedded internal network paths (UNC paths, server share references)',
            tool_suggestions: ['Save document from a local path (not a network share) to prevent UNC path embedding', 'ExifTool: exiftool -xmp:all= file (removes XMP paths)', 'Microsoft Office: File → Inspect Document → Hidden Data → Remove All'],
            affected_fields: n.network_data.uncPaths.map(p => `network.unc:${p.slice(0, 40)}`),
            risk_reduction_estimate: Math.round(network.score * 0.5),
        });
    }

    // Software version sanitization
    if (device.score >= 20) {
        actions.push({
            priority: 2,
            action: 'Sanitize or normalize software version strings and creator tool fields',
            tool_suggestions: ['ExifTool: exiftool -Software= -CreatorTool= file', 'Re-export through a privacy-aware tool (e.g. print-to-PDF, then re-process)', 'GIMP → Export As → uncheck "Save creation time/software"'],
            affected_fields: ['metadata.software', 'software.creatorTool', 'software.version'],
            risk_reduction_estimate: Math.round(device.score * 0.5),
        });
    }

    // Device make/model removal
    if (n.device_data.device) {
        actions.push({
            priority: 2,
            action: 'Remove camera/device make and model EXIF fields to prevent hardware fingerprinting',
            tool_suggestions: ['ExifTool: exiftool -Make= -Model= -LensModel= file', 'ImageMagick: convert -strip input.jpg output.jpg', 'Online tools: ExifPurge, VerExif, or Metapho (iOS)'],
            affected_fields: ['metadata.device', 'exif.Make', 'exif.Model'],
            risk_reduction_estimate: Math.round(device.score * 0.6),
        });
    }

    // Full metadata strip (P2 if any significant risk)
    const maxScore = Math.max(identity.score, location.score, device.score, network.score);
    if (maxScore >= 25) {
        actions.push({
            priority: 2,
            action: 'Perform a complete metadata strip and re-export the file through a clean tool',
            tool_suggestions: ['ExifTool: exiftool -all= output_clean.jpg input.jpg', 'Mat2: mat2 --inplace file (supports PDFs, images, docs)', 'Python: pillow library with Image.save() stripping EXIF', 'Online: Metadata2Go.com → upload → strip all → download'],
            affected_fields: ['ALL metadata fields'],
            risk_reduction_estimate: Math.round(maxScore * 0.8),
        });
    }

    // Public IP scrub
    if (network.contributing_factors.some(f => f.field === 'network.ip_public')) {
        actions.push({
            priority: 2,
            action: 'Redact all embedded public IP addresses from document body',
            tool_suggestions: ['PDF: Adobe Acrobat Pro → Redaction → Search & Redact with regex /\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b/', 'DOCX: Search-and-replace IP strings before final export', 'Manual audit of all hyperlinks for IP-based URLs'],
            affected_fields: network.contributing_factors.filter(f => f.field.includes('ip_public')).map(f => f.value),
            risk_reduction_estimate: Math.round(network.score * 0.4),
        });
    }

    // Timezone removal (P3)
    if (n.timeline_data.embeddedTimezone) {
        actions.push({
            priority: 3,
            action: 'Remove or standardize embedded timezone information to UTC',
            tool_suggestions: ['ExifTool: exiftool -OffsetTimeOriginal= -OffsetTime= file', 'Re-export file in a timezone-neutral context (e.g. VM set to UTC)'],
            affected_fields: ['metadata.timezone', 'timeline.embeddedTimezone'],
            risk_reduction_estimate: 10,
        });
    }

    // Sort: P1 → P2 → P3, then by reduction estimate desc
    return actions.sort((a, b) => a.priority - b.priority || b.risk_reduction_estimate - a.risk_reduction_estimate);
}

// ── Executive summary ────────────────────────────────────────────────────────

function buildExecutiveSummary(
    fileName: string,
    overall: number,
    level: RiskLevel,
    identity: RiskDimension,
    location: RiskDimension,
    device: RiskDimension,
    network: RiskDimension,
    leaks: LeakSource[],
): string {
    const levelDesc: Record<RiskLevel, string> = {
        critical: 'CRITICAL — this file exposes severely sensitive personal and forensic data',
        high: 'HIGH — this file contains significant privacy risks that warrant immediate remediation',
        medium: 'MEDIUM — this file contains moderate privacy exposure requiring attention before distribution',
        low: 'LOW — this file has minor privacy risks that are generally acceptable but worth reviewing',
        minimal: 'MINIMAL — this file contains little to no identifiable personal or network data',
    };

    const highestDim = [identity, location, device, network].sort((a, b) => b.score - a.score)[0];
    const criticalLeaks = leaks.filter(l => l.severity === 'critical' || l.severity === 'high');

    let summary = `Privacy and forensic exposure analysis of "${fileName}" returned an overall risk score of ${overall}/100 (${levelDesc[level]}). `;

    summary += `The highest-risk dimension is "${highestDim.name}" (${highestDim.score}/100, ${highestDim.level.toUpperCase()}). `;

    if (criticalLeaks.length > 0) {
        summary += `${criticalLeaks.length} high-severity leak source${criticalLeaks.length > 1 ? 's were' : ' was'} identified, including: ${criticalLeaks.slice(0, 3).map(l => `${l.field} → "${l.value.slice(0, 30)}${l.value.length > 30 ? '…' : ''}"`).join('; ')}. `;
    }

    if (level === 'critical' || level === 'high') {
        summary += 'Immediate metadata sanitization is strongly recommended before sharing this file externally. Do not distribute without completing the priority-1 remediation actions.';
    } else if (level === 'medium') {
        summary += 'Apply the recommended sanitization actions before public distribution. The file is acceptable for internal use but should be cleaned for external sharing.';
    } else {
        summary += 'The file presents an acceptable privacy profile. Consider completing optional sanitization steps if sharing with untrusted parties.';
    }

    return summary;
}

// ── Master function ──────────────────────────────────────────────────────────

export function analyzePrivacyRisk(
    result: AnalysisResult,
    n: NormalizedMetadata,
): PrivacyRiskReport {
    _lid = 0;

    const { dim: identity, leaks: idLeaks } = scoreIdentityLeakage(result, n);
    const { dim: location, leaks: locLeaks } = scoreLocationExposure(result, n);
    const { dim: device, leaks: devLeaks } = scoreDeviceTraceability(result, n);
    const { dim: network, leaks: netLeaks } = scoreNetworkAttribution(result, n);

    // Weighted composite (identity & location weighted heavier)
    const overall = clamp(
        identity.score * 0.30 +
        location.score * 0.25 +
        device.score * 0.20 +
        network.score * 0.25
    );

    const risk_level = levelFromScore(overall);

    // Merge and sort leak sources
    const allLeaks: LeakSource[] = [...idLeaks, ...locLeaks, ...devLeaks, ...netLeaks];
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const key_leak_sources = allLeaks.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    const recommended_sanitization_actions = buildSanitizationPlan(identity, location, device, network, n);

    // Metadata density
    const m = result.metadata;
    const identifyingFields = [
        m.author, m.lastModifiedBy, m.deviceOwner, m.organization, m.device,
        m.software, m.operatingSystem, m.gpsLatitude, m.timezone, m.locationReference,
        ...result.networkIndicators.emails, ...result.networkIndicators.ips,
        ...result.networkIndicators.uncPaths,
    ].filter(v => v !== undefined && v !== null && v !== '');
    const totalPossibleFields = 15;
    const metadata_density_pct = Math.round((identifyingFields.length / totalPossibleFields) * 100);

    return {
        analyzed_at: new Date().toISOString(),
        file_name: m.fileName,
        sha256: m.sha256Hash,
        overall_risk_score: overall,
        risk_level,
        identity_leakage: identity,
        location_exposure: location,
        device_traceability: device,
        network_attribution: network,
        key_leak_sources,
        recommended_sanitization_actions,
        executive_summary: buildExecutiveSummary(m.fileName, overall, risk_level, identity, location, device, network, allLeaks),
        metadata_density_pct,
    };
}
