/**
 * Forensic Analyst Report Generator
 * ────────────────────────────────────
 * Produces a structured, evidence-cited forensic analyst report from all
 * available engine outputs.
 *
 * Principles:
 *  - Every finding MUST cite the specific field and value that produced it
 *  - Confidence is expressed as a tier with explicit reasoning
 *  - No inference beyond what the metadata directly evidences
 *  - All limitations and gaps are disclosed
 */

import { AnalysisResult } from './types';
import { NormalizedMetadata } from './metadata-normalizer';
import { AttributionReport } from './attribution-analyst';
import { ChronologyReport } from './lifecycle-analyzer';
import { NetworkOriginReport } from './network-origin-analyzer';
import { GeoDeviceReport } from './geo-device-analyzer';
import { PrivacyRiskReport } from './privacy-risk-analyzer';

// ── Output Types ─────────────────────────────────────────────────────────────

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ConfidenceTier = 'definitive' | 'high' | 'moderate' | 'low' | 'insufficient';

// A single, discrete forensic finding
export interface ForensicFinding {
    id: string;
    /** Finding sequence number */
    number: number;
    /** Short headline */
    title: string;
    /** Category of finding */
    category: 'identity' | 'timeline' | 'location' | 'device' | 'network' | 'integrity' | 'privacy' | 'content';
    severity: FindingSeverity;

    /** What was discovered — stated as fact, citing specific fields  */
    what_was_discovered: string;
    /** Why it matters forensically — no speculation, direct implications only */
    why_it_matters: string;

    /** Specific evidence references: field + value pairs */
    evidence_references: EvidenceRef[];
    /** Confidence assessment with reasoning */
    confidence: ConfidenceAssessment;
    /** Any limitations or caveats for this finding */
    limitations: string[];
}

export interface EvidenceRef {
    /** Metadata field path (e.g. "exif.Make") */
    field: string;
    /** Verbatim value from the metadata */
    value: string;
    /** Which part of the system produced this */
    source: 'exif' | 'xmp' | 'iptc' | 'docx_core' | 'pdf_info' | 'content_scan' | 'filesystem' | 'derived';
    /** Whether this value corroborates or contradicts other findings */
    role: 'primary' | 'corroborating' | 'contradicting';
}

export interface ConfidenceAssessment {
    tier: ConfidenceTier;
    score: number;         // 0–100
    reasoning: string;     // explicit chain of reasoning
    limiting_factors: string[];  // what would raise confidence further
}

// Report sections
export interface ReportSection {
    title: string;
    findings: ForensicFinding[];
    section_summary: string;
    /** Total finding count by severity */
    severity_counts: Record<FindingSeverity, number>;
}

export interface AnalystReportMeta {
    report_id: string;
    generated_at: string;
    report_version: '1.0';
    examiner_note: string;
    methodology: string;
    scope_of_analysis: string[];
    limitations_of_analysis: string[];
}

export interface ForensicAnalystReport {
    meta: AnalystReportMeta;
    subject: {
        file_name: string;
        file_type: string;
        file_size_bytes: number;
        sha256: string;
        mime_type: string;
        analyzed_at: string;
    };

    /** One-paragraph executive summary */
    executive_summary: string;

    /** Overall integrity verdict */
    integrity_verdict: {
        status: 'authentic' | 'suspicious' | 'tampered' | 'insufficient_data';
        confidence: ConfidenceTier;
        summary: string;
    };

    sections: ReportSection[];

    /** Chronological list of all provable events */
    established_timeline: TimelineEntry[];

    /** Items that could not be determined from available metadata */
    gaps_and_unknowns: string[];

    /** Total findings */
    total_findings: number;
    findings_by_severity: Record<FindingSeverity, number>;
}

export interface TimelineEntry {
    utc: string;
    event: string;
    field: string;
    confidence: ConfidenceTier;
    flagged: boolean;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

let _fid = 0;
function fid() { return `F${String(++_fid).padStart(3, '0')}`; }

function tierFromScore(s: number): ConfidenceTier {
    if (s >= 85) return 'definitive';
    if (s >= 65) return 'high';
    if (s >= 40) return 'moderate';
    if (s >= 15) return 'low';
    return 'insufficient';
}

function countBySeverity(findings: ForensicFinding[]): Record<FindingSeverity, number> {
    const c: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    for (const f of findings) c[f.severity]++;
    return c;
}

function formatDate(d: Date | string | null | undefined): string {
    if (!d) return 'not available';
    const dt = typeof d === 'string' ? new Date(d) : d;
    if (isNaN(dt.getTime())) return String(d);
    return dt.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

// ── Section builders ─────────────────────────────────────────────────────────

// ── 1. File Identity & Integrity ─────────────────────────────────────────────
function buildIntegritySection(
    result: AnalysisResult,
    lifecycle: ChronologyReport | null,
): ReportSection {
    const findings: ForensicFinding[] = [];
    const m = result.metadata;

    // Hash integrity
    findings.push({
        id: fid(), number: findings.length + 1,
        title: 'File Hash (SHA-256) Computed',
        category: 'integrity',
        severity: 'informational',
        what_was_discovered: `The file "${m.fileName}" has SHA-256 hash ${m.sha256Hash}. This hash uniquely identifies the exact byte-for-byte content of this file as submitted for analysis.`,
        why_it_matters: 'SHA-256 is a cryptographically strong hash. If any single byte of the file changes, the hash will differ entirely. This value serves as the chain-of-custody fingerprint for this evidence item. Any future copy of this file can be verified against this hash.',
        evidence_references: [
            { field: 'computed.sha256', value: m.sha256Hash, source: 'derived', role: 'primary' },
            { field: 'file.name', value: m.fileName, source: 'filesystem', role: 'corroborating' },
            { field: 'file.size', value: `${m.fileSize} bytes`, source: 'filesystem', role: 'corroborating' },
        ],
        confidence: { tier: 'definitive', score: 99, reasoning: 'SHA-256 is computed deterministically from the file bytes. The result is unambiguous — no estimation is involved.', limiting_factors: [] },
        limitations: ['Hash verification only confirms file integrity at the bytes level; it does not prove the metadata within the file is authentic.'],
    });

    // Tampering events from lifecycle engine
    if (lifecycle && lifecycle.tampering_events.length > 0) {
        for (const t of lifecycle.tampering_events.filter(te => te.severity === 'critical' || te.severity === 'high')) {
            findings.push({
                id: fid(), number: findings.length + 1,
                title: t.title,
                category: 'integrity',
                severity: t.severity === 'critical' ? 'critical' : 'high',
                what_was_discovered: t.description,
                why_it_matters: `This constitutes a ${t.severity.toUpperCase()} integrity anomaly. ${t.recommended_action}`,
                evidence_references: [
                    ...t.involved_fields.map(f => ({ field: f, value: t.involved_timestamps[0] ?? 'see description', source: 'derived' as const, role: 'primary' as const })),
                ],
                confidence: { tier: 'high', score: 80, reasoning: `The logical contradiction between ${t.involved_fields.join(' and ')} is self-evident from the metadata values. No external reference is needed to identify this as anomalous.`, limiting_factors: ['Access to the original device clock records or alternative hash of the original file would increase confidence to definitive.'] },
                limitations: ['Metadata analysis alone cannot determine the intent behind the anomaly — it proves the inconsistency exists, not why it was introduced.'],
            });
        }

        for (const t of lifecycle.tampering_events.filter(te => te.severity === 'medium')) {
            findings.push({
                id: fid(), number: findings.length + 1,
                title: t.title,
                category: 'integrity',
                severity: 'medium',
                what_was_discovered: t.description,
                why_it_matters: `Medium-severity integrity concern. ${t.recommended_action}`,
                evidence_references: t.involved_fields.map(f => ({ field: f, value: t.involved_timestamps[0] ?? 'see description', source: 'derived' as const, role: 'primary' as const })),
                confidence: { tier: 'moderate', score: 60, reasoning: 'This anomaly is statistically unusual but not logically impossible — it may have a benign explanation.', limiting_factors: ['Device timezone records and original source metadata required for definitive determination.'] },
                limitations: ['Moderate anomalies require corroboration from additional sources before drawing tampered conclusions.'],
            });
        }
    } else if (lifecycle && lifecycle.tampering_events.length === 0 && lifecycle.timeline.length > 0) {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: 'No Temporal Integrity Anomalies Detected',
            category: 'integrity',
            severity: 'informational',
            what_was_discovered: `${lifecycle.timeline.length} timestamp(s) were examined and found to be internally consistent. No reversed sequences, future dates, or logically impossible orderings were detected.`,
            why_it_matters: 'The absence of temporal anomalies supports the authenticity of the file\'s lifecycle chronology. This does not prove the file is unmodified — it proves the embedded timestamps do not contradict each other.',
            evidence_references: lifecycle.timeline.map(e => ({ field: e.source_field, value: e.utc, source: 'derived' as const, role: 'corroborating' as const })),
            confidence: { tier: 'high', score: 75, reasoning: 'All examined timestamp fields are internally consistent. Confidence is high but not definitive because absence of evidence is not evidence of absence — sophisticated tampering could produce consistent false timestamps.', limiting_factors: ['Comparison with original device logs or the file publisher\'s records would allow definitive authentication.'] },
            limitations: ['Only metadata timestamps are examined. Content-level integrity (pixel manipulation, text alteration) is outside the scope of metadata forensics.'],
        });
    }

    const section_summary = findings.some(f => f.severity === 'critical')
        ? `CRITICAL integrity anomalies detected. This file's timestamp chain contains logically impossible sequences that are definitive indicators of metadata manipulation.`
        : findings.some(f => f.severity === 'high')
            ? `High-severity integrity concerns detected. Temporal anomalies found that strongly suggest timestamp manipulation.`
            : `No significant integrity anomalies detected. File's timestamp metadata appears internally consistent.`;

    return { title: 'File Identity & Integrity', findings, section_summary, severity_counts: countBySeverity(findings) };
}

// ── 2. Author & Identity Attribution ─────────────────────────────────────────
function buildIdentitySection(
    result: AnalysisResult,
    n: NormalizedMetadata,
    attribution: AttributionReport | null,
): ReportSection {
    const findings: ForensicFinding[] = [];
    const m = result.metadata;
    const id = n.identity_data;

    // Author identity
    if (id.author || id.lastModifiedBy || id.deviceOwner) {
        const names = [id.author, id.lastModifiedBy, id.deviceOwner].filter(Boolean) as string[];
        const isConflict = id.author && id.lastModifiedBy && id.author.toLowerCase() !== id.lastModifiedBy.toLowerCase();

        findings.push({
            id: fid(), number: findings.length + 1,
            title: isConflict ? 'Creator–Editor Identity Split Detected' : `Author Identity: "${names[0]}"`,
            category: 'identity',
            severity: isConflict ? 'high' : 'medium',
            what_was_discovered: isConflict
                ? `The file metadata records two distinct individuals: creator "${id.author}" (author field) and "${id.lastModifiedBy}" (lastModifiedBy field). These fields record different names, indicating the file was created by one person and subsequently edited by another.`
                : `The author field contains the name "${names[0]}". This is the name embedded by the creating application at the time of document creation or last save.`,
            why_it_matters: isConflict
                ? 'A creator-modifier split is forensically significant because it establishes a chain of custody with two distinct individuals. The lastModifiedBy field records whoever last saved the document — this person may have altered the file after the original author\'s involvement.'
                : 'Author metadata is the most direct personal identification signal in document metadata. It was embedded by the application and reflects the user account profile at time of creation.',
            evidence_references: [
                ...(id.author ? [{ field: 'metadata.author', value: id.author, source: 'docx_core' as const, role: 'primary' as const }] : []),
                ...(id.lastModifiedBy ? [{ field: 'metadata.lastModifiedBy', value: id.lastModifiedBy, source: 'docx_core' as const, role: isConflict ? 'contradicting' as const : 'corroborating' as const }] : []),
                ...(id.deviceOwner ? [{ field: 'metadata.deviceOwner', value: id.deviceOwner, source: 'exif' as const, role: 'corroborating' as const }] : []),
            ],
            confidence: {
                tier: 'high', score: 75,
                reasoning: `The author name comes directly from the document\'s embedded metadata field — it was written by the application, not inferred. Confidence is high but not definitive because author fields can be manually edited by anyone with a metadata editor.`,
                limiting_factors: ['Comparison with the account profile of the identified individual\'s known software installation would allow verification.', 'If the document was emailed, examining email headers for the sending account would corroborate.'],
            },
            limitations: ['Author fields can be changed in seconds with ExifTool or document properties editors. The presence of a name does not constitute proof of authorship — it constitutes a lead.'],
        });
    } else {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: 'No Author Identity Metadata Found',
            category: 'identity', severity: 'medium',
            what_was_discovered: 'The file contains no author, creator, last-modified-by, or device-owner metadata fields. All identity fields examined returned null or empty values.',
            why_it_matters: 'Complete absence of author metadata is atypical for files created by standard applications such as Microsoft Office, Adobe products, or smartphone cameras. This pattern is consistent with deliberate metadata stripping — though it may also result from the file being exported through a privacy-aware tool or created programmatically.',
            evidence_references: [
                { field: 'metadata.author', value: '[null]', source: 'derived', role: 'primary' },
                { field: 'metadata.lastModifiedBy', value: '[null]', source: 'derived', role: 'corroborating' },
                { field: 'metadata.deviceOwner', value: '[null]', source: 'derived', role: 'corroborating' },
            ],
            confidence: { tier: 'high', score: 70, reasoning: 'The absence of fields is reliably determined from parsing. The interpretation (stripped vs. never present) cannot be definitively determined from the file alone.', limiting_factors: ['Version history or prior copies of the file would reveal whether metadata was present and then removed.'] },
            limitations: ['Absence of author metadata does not prove the file was tampered with — some file creation workflows legitimately produce anonymous metadata.'],
        });
    }

    // Email identity
    if (n.network_data.emails.length > 0) {
        const emails = n.network_data.emails.slice(0, 5);
        findings.push({
            id: fid(), number: findings.length + 1,
            title: `${emails.length} Email Address${emails.length > 1 ? 'es' : ''} Embedded`,
            category: 'identity', severity: emails.some(e => !['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'].includes(e.split('@')[1] ?? '')) ? 'high' : 'medium',
            what_was_discovered: `The following email address${emails.length > 1 ? 'es are' : ' is'} embedded in the file's metadata or body: ${emails.join(', ')}.`,
            why_it_matters: 'Email addresses are direct personal identifiers. Corporate emails (non-free-mail domains) simultaneously identify an individual and their organization. Any embedded email address provides an OSINT pivot for identity attribution.',
            evidence_references: emails.map(e => ({ field: 'network.email', value: e, source: 'content_scan' as const, role: 'primary' as const })),
            confidence: { tier: 'definitive', score: 95, reasoning: 'Email addresses were extracted by regex pattern from the file content. Their presence is certain — the only question is whether they belong to the file\'s author or are incidental references.', limiting_factors: ['Determine whether the email appears in the author/metadata section (more attributable) vs. the document body (may be a quoted third party).'] },
            limitations: ['An embedded email address identifies an account, not necessarily the physical person who created the file. Shared accounts and spoofed addresses are possible.'],
        });
    }

    // OS username from path
    if (id.usernamesFromPaths.length > 0) {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: `OS Account Username Extracted: "${id.usernamesFromPaths[0]}"`,
            category: 'identity', severity: 'medium',
            what_was_discovered: `The embedded file path(s) contain the OS account username "${id.usernamesFromPaths[0]}". This was extracted from the path pattern C:\\Users\\[username]\\ or equivalent.`,
            why_it_matters: 'OS account usernames reveal the system login identity of the person who created the file. This can match email local-parts, GitHub handles, and other platform identifiers, making it a strong cross-platform correlation signal.',
            evidence_references: id.pathSources.slice(0, 3).map(p => ({ field: 'embedded.path', value: p, source: 'content_scan' as const, role: 'primary' as const })),
            confidence: { tier: 'high', score: 80, reasoning: 'Path patterns are deterministically parsed. The username is a direct extraction, not an inference.', limiting_factors: ['The username could belong to a shared or generic account (e.g. "user", "admin") rather than an individual.'] },
            limitations: ['Path usernames reflect the OS account name at time of creation, not necessarily the real name of the user.'],
        });
    }

    const section_summary = findings.some(f => f.severity === 'high' || f.severity === 'critical')
        ? `Significant identity signals detected. ${attribution ? `Overall attribution confidence: ${attribution.overall_confidence_tier}.` : ''}`
        : findings.some(f => f.severity === 'medium')
            ? 'Moderate identity metadata present. Attribution is possible with additional investigation.'
            : 'Minimal identity information detected.';

    return { title: 'Author & Identity Attribution', findings, section_summary, severity_counts: countBySeverity(findings) };
}

// ── 3. Temporal Chronology ────────────────────────────────────────────────────
function buildTimelineSection(
    result: AnalysisResult,
    n: NormalizedMetadata,
): ReportSection {
    const findings: ForensicFinding[] = [];
    const tl = n.timeline_data;
    const m = result.metadata;

    const hasTimestamps = !!(tl.creationDateUTC || tl.modificationDateUTC || tl.filesystemLastModifiedUTC);

    if (hasTimestamps) {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: 'Temporal Metadata Established',
            category: 'timeline', severity: 'informational',
            what_was_discovered: [
                tl.creationDateUTC && `Creation date (embedded): ${formatDate(tl.creationDateUTC)}`,
                tl.modificationDateUTC && `Last modification date (embedded): ${formatDate(tl.modificationDateUTC)}`,
                tl.filesystemLastModifiedUTC && `Filesystem last-modified: ${formatDate(tl.filesystemLastModifiedUTC)}`,
                tl.accessDateUTC && `Last access date: ${formatDate(tl.accessDateUTC)}`,
                tl.uploadTimestampUTC && `Upload timestamp (analysis system): ${formatDate(tl.uploadTimestampUTC)}`,
            ].filter(Boolean).join(' | '),
            why_it_matters: 'Temporal metadata establishes the provable chronological bounds of this file\'s existence. The creation date bounds when the file could have been made. The modification date bounds when it was last changed. The upload timestamp provides a verified upper bound anchored to the analysis system clock.',
            evidence_references: [
                ...(tl.creationDateUTC ? [{ field: 'metadata.creationDate', value: tl.creationDateUTC, source: 'exif' as const, role: 'primary' as const }] : []),
                ...(tl.modificationDateUTC ? [{ field: 'metadata.modificationDate', value: tl.modificationDateUTC, source: 'exif' as const, role: 'corroborating' as const }] : []),
                ...(tl.filesystemLastModifiedUTC ? [{ field: 'metadata.lastModified', value: tl.filesystemLastModifiedUTC, source: 'filesystem' as const, role: 'corroborating' as const }] : []),
            ],
            confidence: { tier: 'high', score: 70, reasoning: 'Timestamps are extracted directly from embedded metadata fields. Confidence is high for the existence of these values; whether the values are authentic is assessed separately by the integrity checks.', limiting_factors: ['Original device clock records would allow verification of embedded timestamps against ground truth.'] },
            limitations: ['Embedded timestamps can be altered without trace by metadata editors. Filesystem timestamps can be changed by copying, moving, or touching files.'],
        });
    }

    if (tl.embeddedTimezone) {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: `Timezone Embedded: "${tl.embeddedTimezone}"`,
            category: 'timeline', severity: 'low',
            what_was_discovered: `The file contains an embedded timezone value of "${tl.embeddedTimezone}". This value was written by the creating device or application to indicate the UTC offset at time of creation.`,
            why_it_matters: 'Timezone data allows timestamps to be converted to local time for the creation context. It also provides a geographic region signal — devices typically run on the timezone of their physical location.',
            evidence_references: [{ field: 'metadata.timezone', value: tl.embeddedTimezone, source: 'exif', role: 'primary' }],
            confidence: { tier: 'moderate', score: 55, reasoning: 'Timezone fields are embedded by devices but can be modified by anyone with a metadata editor. The field value reflects what was set at save time — not necessarily where the device was physically located.', limiting_factors: ['GPS coordinates (if present) provide an independent location signal that can validate or contradict the timezone.'] },
            limitations: ['Timezone does not prove physical location — a device can be configured to any timezone regardless of physical position.'],
        });
    }

    if (!hasTimestamps) {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: 'No Embedded Timestamps Detected',
            category: 'timeline', severity: 'medium',
            what_was_discovered: 'None of the expected timestamp fields (creation date, modification date, or GPS timestamp) contain values. Only the filesystem last-modified date is available from the file system record.',
            why_it_matters: 'Complete absence of embedded timestamps is atypical for files created by standard applications. This may indicate the file was exported through a metadata-stripping tool, or that the file format does not support timestamp embedding.',
            evidence_references: [
                { field: 'metadata.creationDate', value: '[null]', source: 'derived', role: 'primary' },
                { field: 'metadata.modificationDate', value: '[null]', source: 'derived', role: 'corroborating' },
            ],
            confidence: { tier: 'high', score: 80, reasoning: 'The absence of fields is definitively determined by parsing. Whether this is deliberate or format-related cannot be determined.', limiting_factors: [] },
            limitations: [],
        });
    }

    const section_summary = `${Object.values(tl).filter(Boolean).length} temporal signals extracted. Timezone: ${tl.embeddedTimezone ?? 'not embedded'}.`;
    return { title: 'Temporal Chronology', findings, section_summary, severity_counts: countBySeverity(findings) };
}

// ── 4. Geographic & Device Origin ────────────────────────────────────────────
function buildGeoDeviceSection(
    result: AnalysisResult,
    geo: GeoDeviceReport | null,
): ReportSection {
    const findings: ForensicFinding[] = [];
    const m = result.metadata;

    // GPS
    if (geo?.gpsAvailable && geo.gpsCoordinates) {
        const gps = geo.gpsCoordinates;
        findings.push({
            id: fid(), number: findings.length + 1,
            title: 'GPS Coordinates Embedded',
            category: 'location', severity: gps.suspicion === 'none' ? 'high' : 'medium',
            what_was_discovered: `GPS coordinates are embedded in this file: latitude ${gps.latitude.toFixed(6)}° (${gps.latitude >= 0 ? 'N' : 'S'}), longitude ${gps.longitude.toFixed(6)}° (${gps.longitude >= 0 ? 'E' : 'W'}).${gps.altitudeMetres !== null ? ` Altitude: ${gps.altitudeMetres} metres.` : ''} Coordinate suspicion flag: ${gps.suspicion}.`,
            why_it_matters: gps.suspicion === 'none'
                ? 'GPS coordinates provide the most precise physical location evidence in file metadata. These coordinates identify the geographic point where the capturing device was located at the time the file was created. This is actionable intelligence for physical location identification.'
                : `The coordinates are flagged as "${gps.suspicion}" — treat with caution. Null Island (0°, 0°) indicates cleared or fabricated coordinates; excessive precision suggests synthetic data.`,
            evidence_references: [
                { field: 'gps.latitude', value: String(gps.latitude), source: 'exif', role: 'primary' },
                { field: 'gps.longitude', value: String(gps.longitude), source: 'exif', role: 'primary' },
                ...(gps.altitudeMetres !== null ? [{ field: 'gps.altitude', value: `${gps.altitudeMetres} m`, source: 'exif' as const, role: 'corroborating' as const }] : []),
            ],
            confidence: { tier: gps.suspicion === 'none' ? 'high' : 'low', score: gps.suspicion === 'none' ? 85 : 25, reasoning: gps.suspicion === 'none' ? 'GPS coordinates are embedded by the device hardware at capture time. The values are extracted directly from the EXIF GPS IFD with no transformation. Consumer GPS accuracy is typically ±5 metres.' : `Suspicion flag "${gps.suspicion}" reduces confidence significantly.`, limiting_factors: ['Cross-reference with known travel records or network IP geolocation to validate the claimed location.'] },
            limitations: ['GPS coordinates show where the capturing device was located — not necessarily where the file was created or who possessed the device.', 'GPS data can be injected or modified using metadata editors after capture.'],
        });
    }

    // Device model
    if (geo?.deviceProfile.fullDeviceString || m.device) {
        const device = geo?.deviceProfile.fullDeviceString ?? m.device ?? '';
        findings.push({
            id: fid(), number: findings.length + 1,
            title: `Capture Device Identified: "${device}"`,
            category: 'device', severity: 'medium',
            what_was_discovered: `The EXIF Make and Model fields identify the capturing device as "${device}". Device category: ${geo?.deviceProfile.category?.replace(/_/g, ' ') ?? 'unknown'}.`,
            why_it_matters: 'Device make and model create a hardware-class fingerprint. When combined with other metadata (GPS, timestamps, author fields), this narrows attribution to a specific class of device. Multiple files sharing the same device fingerprint can be cross-correlated as originating from the same hardware.',
            evidence_references: [
                { field: 'exif.Make + exif.Model', value: device, source: 'exif', role: 'primary' },
            ],
            confidence: { tier: 'definitive', score: 90, reasoning: 'EXIF Make and Model fields are embedded by device firmware at capture time. The values are read directly — no inference is applied. These fields are rarely falsified in organic captures, though metadata editors can alter them.', limiting_factors: [] },
            limitations: ['Device model identifies the category of hardware, not the specific unit. Without serial numbers or unique sensor noise patterns, individual device attribution is not possible from metadata alone.'],
        });
    }

    // OS ecosystem
    if (geo?.osEcosystem) {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: `OS Ecosystem Identified: ${geo.osEcosystem}`,
            category: 'device', severity: 'low',
            what_was_discovered: `The operating system ecosystem is identified as "${geo.osEcosystem}" with ${geo.osConfidence} confidence. Detection source(s): ${geo.osEvidenceSources.join('; ')}.`,
            why_it_matters: 'OS identification narrows the software environment of the file creator and can corroborate or contradict device attribution. An iOS file should have iOS metadata patterns; Windows metadata found in a purportedly iOS file would be anomalous.',
            evidence_references: geo.osEvidenceSources.map(s => ({ field: 'device.os_inference', value: s, source: 'derived' as const, role: 'corroborating' as const })),
            confidence: { tier: tierFromScore(geo.osConfidence === 'high' ? 80 : geo.osConfidence === 'moderate' ? 55 : 30), score: geo.osConfidence === 'high' ? 80 : 45, reasoning: `OS ecosystem is inferred from ${geo.osEvidenceSources[0] ?? 'software patterns'}, not read from a dedicated OS field. ${geo.osConfidence} confidence tier.`, limiting_factors: ['A dedicated OS metadata field (when present) would raise this to definitive.'] },
            limitations: ['OS inference is based on software signatures which can be edited or spoofed.'],
        });
    }

    // Origin estimate (only when GPS absent)
    if (geo && !geo.gpsAvailable && geo.originEstimate.confidence !== 'unknown') {
        const origin = geo.originEstimate;
        findings.push({
            id: fid(), number: findings.length + 1,
            title: `Geographic Origin Estimated: ${origin.region}${origin.subRegion ? ' — ' + origin.subRegion : ''}`,
            category: 'location', severity: 'low',
            what_was_discovered: `Without GPS data, geographic origin is estimated as "${origin.region}" (${origin.subRegion ?? 'no sub-region'}) using ${origin.inferenceMethod.replace(/_/g, ' ')}. Estimation confidence: ${origin.confidence}. Reasoning: ${origin.reasoning.join(' | ')}.`,
            why_it_matters: 'Geographic origin, even when estimated, narrows the investigative focus and can corroborate or contradict claimed origins. The inference is based on objective metadata signals (timezone, language codes, device make) — not assumption.',
            evidence_references: [{ field: 'origin.estimate', value: `${origin.region} (${origin.confidence} confidence)`, source: 'derived', role: 'primary' }],
            confidence: { tier: tierFromScore(origin.confidence === 'high' ? 65 : origin.confidence === 'moderate' ? 40 : 20), score: origin.confidence === 'high' ? 65 : origin.confidence === 'moderate' ? 40 : 20, reasoning: `Estimated from indirect signals (${origin.inferenceMethod.replace(/_/g, ' ')}). Each signal is factual; confidence reflects uncertainty in the inference chain.`, limiting_factors: origin.caveats },
            limitations: [...origin.caveats, 'Geographic estimation is probabilistic without GPS data. It identifies probable regions, not specific locations.'],
        });
    }

    const section_summary = geo?.gpsAvailable
        ? `GPS coordinates present — precise location evidence available.`
        : `No GPS data. ${geo?.deviceProfile.fullDeviceString ? `Device: ${geo.deviceProfile.fullDeviceString}.` : ''} ${geo?.originEstimate.confidence !== 'unknown' ? `Estimated origin: ${geo?.originEstimate.region}.` : ''}`;

    return { title: 'Geographic & Device Origin', findings, section_summary, severity_counts: countBySeverity(findings) };
}

// ── 5. Network & Infrastructure Exposure ──────────────────────────────────────
function buildNetworkSection(
    result: AnalysisResult,
    network: NetworkOriginReport | null,
): ReportSection {
    const findings: ForensicFinding[] = [];
    const net = result.networkIndicators;

    if (network && network.artifacts.length > 0) {
        const publicIPs = network.artifacts.filter(a => a.category === 'ip_address' && a.origin_class === 'public_origin');
        const uncPaths = network.artifacts.filter(a => a.category === 'unc_path');
        const cloudURLs = network.artifacts.filter(a => a.category === 'cloud_storage');

        if (publicIPs.length > 0) {
            findings.push({
                id: fid(), number: findings.length + 1,
                title: `${publicIPs.length} Public IP Address${publicIPs.length > 1 ? 'es' : ''} Embedded`,
                category: 'network', severity: 'high',
                what_was_discovered: `The following public IP address${publicIPs.length > 1 ? 'es are' : ' is'} embedded in the file content: ${publicIPs.map(a => a.raw_value).join(', ')}.`,
                why_it_matters: 'Public IP addresses can be submitted to geolocation databases and WHOIS services to identify the ISP, ASN, geographic region, and potentially the organization responsible for that IP block. This is an actionable network attribution pivot.',
                evidence_references: publicIPs.map(a => ({ field: a.source_field, value: a.raw_value, source: 'content_scan' as const, role: 'primary' as const })),
                confidence: { tier: 'definitive', score: 95, reasoning: 'IP addresses are extracted by exact regex pattern matching. The presence of these strings in the file is certain. Their ownership at the time of file creation requires separate WHOIS/ARIN lookup.', limiting_factors: ['WHOIS records for these IPs at the time of file creation (historical WHOIS) would provide definitive network attribution.'] },
                limitations: ['IP addresses embedded in documents may belong to third-party services referenced in the content, not necessarily to the file author.', 'Dynamic IP addresses may have changed hands since file creation.'],
            });
        }

        if (uncPaths.length > 0) {
            findings.push({
                id: fid(), number: findings.length + 1,
                title: `${uncPaths.length} Internal Network Path${uncPaths.length > 1 ? 's' : ''} Exposed`,
                category: 'network', severity: 'critical',
                what_was_discovered: `The following UNC/network paths are embedded: ${uncPaths.map(a => a.raw_value).join(', ')}.`,
                why_it_matters: 'UNC paths reveal the internal network architecture of the organization that created the file. The server hostnames and share names can be used to enumerate internal infrastructure and may enable targeted network access attempts. This is a critical infrastructure disclosure.',
                evidence_references: uncPaths.map(a => ({ field: 'network.uncPath', value: a.raw_value, source: 'content_scan' as const, role: 'primary' as const })),
                confidence: { tier: 'definitive', score: 97, reasoning: 'UNC path patterns are unambiguous string patterns beginning with \\\\server\\share. Their presence in the file content is certain.', limiting_factors: [] },
                limitations: ['Server names may refer to decommissioned or renamed servers that no longer exist at the time of analysis.'],
            });
        }

        if (cloudURLs.length > 0) {
            const providers = [...new Set(cloudURLs.map(a => a.details.cloud_provider ?? 'Unknown'))];
            findings.push({
                id: fid(), number: findings.length + 1,
                title: `Cloud Storage URLs Found: ${providers.join(', ')}`,
                category: 'network', severity: 'high',
                what_was_discovered: `${cloudURLs.length} cloud storage URL${cloudURLs.length > 1 ? 's' : ''} detected in the file, referencing the following services: ${providers.join(', ')}. Sample URL: ${cloudURLs[0]?.normalized_value?.slice(0, 80) ?? '—'}.`,
                why_it_matters: 'Cloud storage URLs reveal which services were used to store or share this file. URLs may still be live and publicly accessible. They provide evidence of the cloud account used and may link to the sharing configuration, access logs, or additional files in the same folder.',
                evidence_references: cloudURLs.slice(0, 3).map(a => ({ field: a.source_field, value: a.normalized_value, source: 'content_scan' as const, role: 'primary' as const })),
                confidence: { tier: 'definitive', score: 92, reasoning: 'Cloud provider domain patterns are exact string matches. The presence of these URLs is certain.', limiting_factors: ['Whether URLs are still active requires live verification (access the URL).'] },
                limitations: ['Cloud URLs may have been embedded as hyperlinks referencing external content, not necessarily the file\'s own storage location.'],
            });
        }
    }

    if (net.emails.length === 0 && net.ips.length === 0 && net.uncPaths.length === 0 && net.urls.length === 0) {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: 'No Network Artifacts Detected',
            category: 'network', severity: 'informational',
            what_was_discovered: 'The file body and metadata were scanned for IP addresses, URLs, UNC paths, email addresses, and hostnames. No network-related artifacts were found.',
            why_it_matters: 'The absence of network artifacts reduces the network attribution surface of this file. It cannot be used as a direct pivot to identify associated network infrastructure.',
            evidence_references: [],
            confidence: { tier: 'high', score: 80, reasoning: 'Content scanning covers the full file body and all metadata fields using established regex patterns.', limiting_factors: ['Encrypted or encoded content may contain hidden network references that regex cannot detect.'] },
            limitations: ['Network artifacts encoded in binary, base64, or encrypted form are not detectable by metadata analysis alone.'],
        });
    }

    const section_summary = network
        ? `${network.summary.total_artifacts} network artifact(s) detected. Network risk score: ${network.summary.network_risk_score}/100.`
        : 'Network scan data unavailable.';

    return { title: 'Network & Infrastructure Exposure', findings, section_summary, severity_counts: countBySeverity(findings) };
}

// ── 6. Privacy Exposure Assessment ───────────────────────────────────────────
function buildPrivacySection(privacy: PrivacyRiskReport | null): ReportSection {
    const findings: ForensicFinding[] = [];

    if (!privacy) {
        return { title: 'Privacy Exposure Assessment', findings, section_summary: 'Privacy risk data unavailable.', severity_counts: countBySeverity([]) };
    }

    findings.push({
        id: fid(), number: findings.length + 1,
        title: `Overall Privacy Risk Score: ${privacy.overall_risk_score}/100 (${privacy.risk_level.toUpperCase()})`,
        category: 'privacy',
        severity: privacy.risk_level === 'critical' ? 'critical' : privacy.risk_level === 'high' ? 'high' : privacy.risk_level === 'medium' ? 'medium' : 'low',
        what_was_discovered: `Composite privacy risk score: ${privacy.overall_risk_score}/100 (${privacy.risk_level}). Dimension scores: Identity Leakage ${privacy.identity_leakage.score}/100 (${privacy.identity_leakage.level}), Location Exposure ${privacy.location_exposure.score}/100 (${privacy.location_exposure.level}), Device Traceability ${privacy.device_traceability.score}/100 (${privacy.device_traceability.level}), Network Attribution ${privacy.network_attribution.score}/100 (${privacy.network_attribution.level}). Total identified leak sources: ${privacy.key_leak_sources.length}. Metadata density: ${privacy.metadata_density_pct}% of identifying fields present.`,
        why_it_matters: 'The privacy risk score quantifies how much personal, locational, and infrastructure information is disclosed by this file\'s metadata. A high score means this file, if distributed, would expose significant identifiable information about its creator or organization.',
        evidence_references: privacy.key_leak_sources.slice(0, 5).map(l => ({ field: l.field, value: l.value, source: 'derived' as const, role: 'primary' as const })),
        confidence: { tier: 'high', score: 80, reasoning: 'Privacy scoring is computed deterministically from the extracted metadata values. Each dimension score reflects the presence or absence of specific fields.', limiting_factors: [] },
        limitations: ['Privacy scoring reflects metadata-layer exposure only. Sensitive content within the file body (e.g., embedded images with faces, document text) is not assessed.'],
    });

    const criticalLeaks = privacy.key_leak_sources.filter(l => l.severity === 'critical' || l.severity === 'high').slice(0, 3);
    if (criticalLeaks.length > 0) {
        findings.push({
            id: fid(), number: findings.length + 1,
            title: `${criticalLeaks.length} Critical/High-Severity Leak Source${criticalLeaks.length > 1 ? 's' : ''}`,
            category: 'privacy', severity: 'high',
            what_was_discovered: `The following high-severity privacy leak sources were identified: ${criticalLeaks.map(l => `${l.field}="${l.value}" (${l.osint_vector})`).join('; ')}.`,
            why_it_matters: 'Each identified leak source represents a specific data field that enables external attribution. High-severity leaks enable attribution without additional research; critical leaks combine identification and contact vectors simultaneously.',
            evidence_references: criticalLeaks.map(l => ({ field: l.field, value: l.value, source: 'derived' as const, role: 'primary' as const })),
            confidence: { tier: 'definitive', score: 95, reasoning: 'Each leak source is a direct extraction from a specific metadata field. Their presence is factual, not inferred.', limiting_factors: [] },
            limitations: ['Leak severity ratings are based on the data type, not the specific individual named. Real-world impact depends on the sensitivity of the individual\'s profile.'],
        });
    }

    const section_summary = `Risk level: ${privacy.risk_level.toUpperCase()} (${privacy.overall_risk_score}/100). ${privacy.key_leak_sources.length} leak sources. ${privacy.recommended_sanitization_actions.filter(a => a.priority === 1).length} immediate remediation actions recommended.`;
    return { title: 'Privacy Exposure Assessment', findings, section_summary, severity_counts: countBySeverity(findings) };
}

// ── Timeline assembly ─────────────────────────────────────────────────────────
function buildTimeline(n: NormalizedMetadata, lifecycle: ChronologyReport | null): TimelineEntry[] {
    const entries: TimelineEntry[] = [];
    const tl = n.timeline_data;

    const add = (utc: string | null, event: string, field: string, conf: ConfidenceTier, flagged = false) => {
        if (!utc) return;
        const d = new Date(utc);
        if (isNaN(d.getTime())) return;
        entries.push({ utc, event, field, confidence: conf, flagged });
    };

    add(tl.creationDateUTC, 'File created (embedded metadata)', 'metadata.creationDate', 'high', lifecycle?.timeline.find(e => e.source_field === 'metadata.creationDate')?.flagged ?? false);
    add(tl.modificationDateUTC, 'File last modified (embedded metadata)', 'metadata.modificationDate', 'high', lifecycle?.timeline.find(e => e.source_field === 'metadata.modificationDate')?.flagged ?? false);
    add(tl.gpsTimestampUTC, 'GPS timestamp (device clock at capture)', 'metadata.gpsTimestamp', 'definitive');
    add(tl.filesystemLastModifiedUTC, 'Filesystem last-modified', 'metadata.lastModified', 'moderate');
    add(tl.uploadTimestampUTC, 'File submitted for analysis', 'metadata.uploadTimestamp', 'definitive');

    return entries.sort((a, b) => a.utc.localeCompare(b.utc));
}

// ── Gaps & unknowns ──────────────────────────────────────────────────────────
function buildGaps(result: AnalysisResult, n: NormalizedMetadata, geo: GeoDeviceReport | null): string[] {
    const gaps: string[] = [];
    const m = result.metadata;
    const id = n.identity_data;

    if (!m.creationDate) gaps.push('Creation date: not embedded — cannot establish earliest provable timestamp from metadata alone.');
    if (!id.author && !id.lastModifiedBy) gaps.push('Author identity: no name fields present — creator cannot be identified from metadata.');
    if (!m.gpsLatitude) gaps.push('Physical location: no GPS data — precise location cannot be determined; only estimated from indirect signals.');
    if (!m.device) gaps.push('Device model: not present — capturing hardware cannot be identified from metadata.');
    if (!m.software) gaps.push('Creating software: not present — application stack cannot be fingerprinted.');
    if (result.networkIndicators.emails.length === 0) gaps.push('Email identity: no email addresses found — no direct email-based attribution pivot.');
    if (n.network_data.uncPaths.length === 0 && n.network_data.ipv4Addresses.length === 0) gaps.push('Network infrastructure: no IPs or network paths — no direct network attribution possible.');
    if (m.sha256Hash && !gaps.includes('hash')) { } // Hash always present

    return gaps;
}

// ── Executive summary ────────────────────────────────────────────────────────
function buildExecutiveSummary(
    result: AnalysisResult,
    sections: ReportSection[],
    lifecycle: ChronologyReport | null,
    privacy: PrivacyRiskReport | null,
): string {
    const m = result.metadata;
    const allFindings = sections.flatMap(s => s.findings);
    const criticalCount = allFindings.filter(f => f.severity === 'critical').length;
    const highCount = allFindings.filter(f => f.severity === 'high').length;

    let summary = `FORENSIC ANALYST REPORT — This report documents the findings of an automated metadata forensic examination of the file "${m.fileName}" (${m.fileType}, ${(m.fileSize / 1024).toFixed(1)} KB, SHA-256: ${m.sha256Hash.slice(0, 16)}…). `;

    if (criticalCount > 0) {
        summary += `CRITICAL: ${criticalCount} critical finding${criticalCount > 1 ? 's' : ''} were identified, requiring immediate attention. `;
    }
    if (highCount > 0) {
        summary += `${highCount} high-severity finding${highCount > 1 ? 's' : ''} detected. `;
    }

    if (lifecycle) {
        summary += `Lifecycle integrity: ${lifecycle.verdict.toUpperCase()} (score: ${lifecycle.integrity_score}/100). `;
    }
    if (privacy) {
        summary += `Privacy exposure: ${privacy.risk_level.toUpperCase()} (score: ${privacy.overall_risk_score}/100). `;
    }

    summary += `All findings are derived exclusively from embedded metadata — no content-level analysis, no speculation beyond evidence. `;
    summary += `Total: ${allFindings.length} findings across ${sections.length} analysis sections.`;

    return summary;
}

// ── MASTER function ──────────────────────────────────────────────────────────

export function generateForensicReport(
    result: AnalysisResult,
    n: NormalizedMetadata,
    attribution: AttributionReport | null,
    lifecycle: ChronologyReport | null,
    networkReport: NetworkOriginReport | null,
    geo: GeoDeviceReport | null,
    privacy: PrivacyRiskReport | null,
): ForensicAnalystReport {
    _fid = 0;

    const sections: ReportSection[] = [
        buildIntegritySection(result, lifecycle),
        buildIdentitySection(result, n, attribution),
        buildTimelineSection(result, n),
        buildGeoDeviceSection(result, geo),
        buildNetworkSection(result, networkReport),
        buildPrivacySection(privacy),
    ];

    const allFindings = sections.flatMap(s => s.findings);
    const findingsBySeverity: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    for (const f of allFindings) findingsBySeverity[f.severity]++;

    const integrityVerdict = lifecycle
        ? lifecycle.verdict === 'authentic' ? 'authentic'
            : lifecycle.verdict === 'tampered' ? 'tampered'
                : lifecycle.verdict === 'insufficient_data' ? 'insufficient_data'
                    : 'suspicious'
        : result.integrityStatus;

    const m = result.metadata;

    return {
        meta: {
            report_id: `MFS-${m.sha256Hash.slice(0, 8).toUpperCase()}-${Date.now()}`,
            generated_at: new Date().toISOString(),
            report_version: '1.0',
            examiner_note: 'This report was produced by an automated forensic metadata analysis system. All findings are based solely on the embedded metadata of the submitted file. No content-level analysis is performed. Human expert review is recommended before use in legal or investigative proceedings.',
            methodology: 'Multi-engine metadata extraction (EXIF/XMP/IPTC/DOCX-core/PDF-info), SHA-256 hash computation, temporal anomaly detection, network artifact scanning, geographic inference, and privacy exposure scoring.',
            scope_of_analysis: [
                'File hash and identity verification',
                'Embedded metadata extraction (EXIF, XMP, IPTC, document properties)',
                'Temporal chronology reconstruction and anomaly detection',
                'Author/identity attribution from metadata fields',
                'Network and infrastructure artifact scanning',
                'Geographic and device indicator analysis',
                'Privacy and forensic exposure risk scoring',
            ],
            limitations_of_analysis: [
                'Analysis is limited to file metadata — file content (text, images, audio, video) is not analyzed for semantic content',
                'Metadata fields can be altered in seconds using commercially available tools; their presence does not guarantee authenticity',
                'This system does not have access to external databases (IP WHOIS, GPS geocoding, OSINT) — all inferences are made from the file alone',
                'File formats not natively supported may yield incomplete metadata extraction',
                'No chain-of-custody verification is performed on the submitted file',
            ],
        },
        subject: {
            file_name: m.fileName,
            file_type: m.fileType,
            file_size_bytes: m.fileSize,
            sha256: m.sha256Hash,
            mime_type: m.mimeType,
            analyzed_at: result.analyzedAt.toISOString(),
        },
        executive_summary: buildExecutiveSummary(result, sections, lifecycle, privacy),
        integrity_verdict: {
            status: integrityVerdict,
            confidence: lifecycle ? tierFromScore(lifecycle.integrity_score) : 'insufficient',
            summary: lifecycle?.verdict_explanation ?? result.riskExplanation,
        },
        sections,
        established_timeline: buildTimeline(n, lifecycle),
        gaps_and_unknowns: buildGaps(result, n, geo),
        total_findings: allFindings.length,
        findings_by_severity: findingsBySeverity,
    };
}
