/**
 * File Lifecycle Chronology Reconstructor
 * ─────────────────────────────────────────
 * Reconstructs the full temporal lifecycle of a file from its embedded metadata.
 *
 * Determines:
 *   - Creation event (source, confidence)
 *   - Modification chain (ordered sequence of timestamp signals)
 *   - Editing gaps (suspiciously long/short intervals)
 *   - Timezone mismatches (conflicting UTC offsets across fields)
 *   - Timestamp anomalies (future dates, midnight precision, impossible sequences)
 *
 * Detects:
 *   - Possible tampering events (classified by mechanism)
 *   - Metadata rewriting indicators
 *   - Clock inconsistencies (filesystem vs embedded vs GPS)
 */

import { AnalysisResult } from './types';

// ── Output Types ───────────────────────────────────────────────────────────

export type TamperingMechanism =
    | 'timestamp_rollback'     // modification date set before creation date
    | 'timestamp_forward'      // any date in the future
    | 'metadata_rewrite'       // software / author changed post-creation
    | 'clock_skew'             // filesystem clock vs embedded clock differ significantly
    | 'precision_fabrication'  // suspiciously round timestamps (midnight, Jan 1st)
    | 'impossible_sequence'    // logical ordering violated
    | 'timezone_forgery'       // timezone does not match GPS or system region
    | 'revision_stripping'     // revision count reset / unexpectedly low
    | 'gap_anomaly';           // editing gap too large or too small to be organic

export type AnomalySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface TimelineEvent {
    id: string;
    /** UTC ISO-8601 timestamp */
    utc: string;
    /** Label describing the event */
    label: string;
    /** Source field in the metadata */
    source_field: string;
    /** How confident we are this timestamp is authentic (0-100) */
    authenticity_score: number;
    /** Whether this event has any anomaly flags */
    flagged: boolean;
    /** Optional extra context */
    notes: string[];
}

export interface EditingGap {
    id: string;
    from_event: string;   // TimelineEvent.id
    to_event: string;     // TimelineEvent.id
    from_label: string;
    to_label: string;
    from_utc: string;
    to_utc: string;
    gap_seconds: number;
    gap_human: string;
    /** Classification of the gap */
    assessment: 'normal' | 'short_suspicious' | 'long_suspicious' | 'impossible_negative';
    explanation: string;
}

export interface TimezoneSignal {
    source: string;       // Where this TZ was seen
    raw_value: string;    // Raw offset / IANA string
    utc_offset_minutes: number | null;
    region_hint: string | null;
}

export interface TamperingEvent {
    id: string;
    mechanism: TamperingMechanism;
    severity: AnomalySeverity;
    title: string;
    description: string;
    /** UTC timestamps involved in the detection */
    involved_timestamps: string[];
    /** Metadata fields involved */
    involved_fields: string[];
    /** Recommended forensic action */
    recommended_action: string;
}

export interface CreationEvent {
    /** Best-estimated UTC of file creation */
    utc: string | null;
    /** Which field provides the authoritative creation date */
    authority_source: string;
    /** Secondary corroborating sources */
    corroborating_sources: string[];
    /** Confidence that this is the true creation time (0–100) */
    confidence: number;
    /** Whether the creation event appears intact */
    integrity: 'intact' | 'suspect' | 'compromised';
    notes: string[];
}

export interface ChronologyReport {
    analysed_at: string;
    file_name: string;
    sha256: string;
    /** Overall lifecycle integrity score (0–100, higher = more authentic) */
    integrity_score: number;
    /** Overall verdict */
    verdict: 'authentic' | 'suspect' | 'tampered' | 'insufficient_data';
    verdict_explanation: string;
    creation_event: CreationEvent;
    timeline: TimelineEvent[];
    editing_gaps: EditingGap[];
    timezone_signals: TimezoneSignal[];
    timezone_conflict: boolean;
    tampering_events: TamperingEvent[];
    /** Total anomaly counts by severity */
    anomaly_counts: Record<AnomalySeverity, number>;
    /** Summary of all detected mechanisms */
    detected_mechanisms: TamperingMechanism[];
}

// ── Helpers ────────────────────────────────────────────────────────────────

let _seq = 0;
const uid = (prefix: string) => `${prefix}_${++_seq}`;

function clamp(n: number): number {
    return Math.max(0, Math.min(100, Math.round(n)));
}

/** Format a duration in seconds to a human-readable string */
function humanDuration(seconds: number): string {
    const abs = Math.abs(seconds);
    if (abs < 60) return `${Math.round(abs)}s`;
    if (abs < 3600) return `${Math.round(abs / 60)}m`;
    if (abs < 86400) return `${(abs / 3600).toFixed(1)}h`;
    if (abs < 86400 * 30) return `${Math.round(abs / 86400)}d`;
    if (abs < 86400 * 365) return `${Math.round(abs / (86400 * 30))} months`;
    return `${(abs / (86400 * 365)).toFixed(1)} years`;
}

/** Try to extract UTC offset in minutes from a timezone string */
function parseUTCOffset(tz: string): number | null {
    // e.g. "+05:30", "-07:00", "UTC+8", "Z"
    const m = tz.match(/([+-])(\d{1,2}):?(\d{2})?/);
    if (!m) return tz === 'Z' || tz === 'UTC' ? 0 : null;
    const sign = m[1] === '+' ? 1 : -1;
    const hours = parseInt(m[2]);
    const mins = parseInt(m[3] ?? '0');
    return sign * (hours * 60 + mins);
}

/** IANA-region hints for common UTC offsets (minutes) */
const OFFSET_REGION: Record<number, string> = {
    0: 'UTC / UK / West Africa',
    60: 'Central Europe / West Africa +1',
    120: 'Eastern Europe / South Africa',
    180: 'East Africa / Moscow / Gulf',
    210: 'Iran',
    240: 'Gulf / Caucasus',
    270: 'Afghanistan',
    300: 'Pakistan / Yekaterinburg',
    330: 'India (IST)',
    345: 'Nepal',
    360: 'Bangladesh / Omsk',
    390: 'Myanmar',
    420: 'SE Asia / China (ICT)',
    480: 'China / Aus W / Singapore',
    525: 'Australia Central-West',
    540: 'Japan / Korea',
    570: 'Australia Central',
    600: 'Australia East',
    660: 'Solomon Islands',
    720: 'New Zealand',
    [-60]: 'Cape Verde / Azores',
    [-120]: 'Mid-Atlantic',
    [-180]: 'Brazil / Greenland',
    [-210]: 'Newfoundland',
    [-240]: 'Atlantic / Venezuela',
    [-300]: 'Eastern US/Canada',
    [-360]: 'Central US',
    [-420]: 'Mountain US',
    [-480]: 'Pacific US',
    [-540]: 'Alaska',
    [-600]: 'Hawaii',
};

function regionForOffset(offsetMins: number | null): string | null {
    if (offsetMins === null) return null;
    return OFFSET_REGION[offsetMins] ?? `UTC${offsetMins >= 0 ? '+' : ''}${(offsetMins / 60).toFixed(1).replace('.0', '')}`;
}

/** Check if a date is suspiciously precisely midnight (00:00:00) */
function isMidnight(d: Date): boolean {
    return d.getUTCHours() === 0 && d.getUTCMinutes() === 0 && d.getUTCSeconds() === 0;
}

/** Check if a date is Jan 1 (common default reset date) */
function isJanFirst(d: Date): boolean {
    return d.getUTCMonth() === 0 && d.getUTCDate() === 1;
}

/** Check if year is implausibly old for digital files */
function isTooOld(d: Date): boolean {
    return d.getFullYear() < 1990;
}

/** Current analysis time — anchored to when the report is built */
const NOW_UTC = new Date('2026-02-27T16:55:19Z'); // 2026-02-27T22:25:19+05:30 → UTC

// ── Main analysis ──────────────────────────────────────────────────────────
export function reconstructLifecycle(result: AnalysisResult): ChronologyReport {
    _seq = 0;
    const m = result.metadata;
    const art = result.hiddenArtifacts;

    // ── Step 1: Collect all timestamps with provenance ─────────────────────
    type TSEntry = { date: Date; label: string; field: string; weight: number };
    const rawTS: TSEntry[] = [];

    const add = (d: Date | undefined | null, label: string, field: string, weight: number) => {
        if (d && !isNaN(d.getTime())) rawTS.push({ date: d, label, field, weight });
    };

    add(m.creationDate, 'Creation Date (embedded)', 'metadata.creationDate', 10);
    add(m.modificationDate, 'Modification Date (embedded)', 'metadata.modificationDate', 9);
    add(m.lastModified, 'Filesystem Last-Modified', 'metadata.lastModified', 8);
    add(m.accessDate, 'Last Access Date', 'metadata.accessDate', 5);
    add(m.uploadTimestamp, 'Upload Timestamp (system clock)', 'metadata.uploadTimestamp', 6);

    // GPS timestamp as an independent clock source
    if (m.gpsTimestamp) {
        const gd = new Date(m.gpsTimestamp);
        if (!isNaN(gd.getTime())) add(gd, 'GPS Timestamp', 'metadata.gpsTimestamp', 9);
    }

    // Sort chronologically
    rawTS.sort((a, b) => a.date.getTime() - b.date.getTime());

    // ── Step 2: Build TimelineEvent list with per-event authenticity scoring ──
    const timeline: TimelineEvent[] = rawTS.map(({ date, label, field, weight }) => {
        const notes: string[] = [];
        let authScore = 80; // Base authenticity
        let flagged = false;

        // Future date
        if (date > NOW_UTC) {
            notes.push(`⚠ Date is in the future (${date.toISOString()}) — physically impossible.`);
            authScore -= 40;
            flagged = true;
        }
        // Implausibly old
        if (isTooOld(date)) {
            notes.push(`⚠ Date predates consumer digital formats (${date.getFullYear()}).`);
            authScore -= 35;
            flagged = true;
        }
        // Midnight precision
        if (isMidnight(date)) {
            notes.push('ℹ Timestamp is exactly midnight UTC — suspicious for organic timestamps.');
            authScore -= 12;
            flagged = true;
        }
        // Jan 1st default
        if (isJanFirst(date)) {
            notes.push('ℹ Date is January 1st — a common default/reset value in metadata editors.');
            authScore -= 10;
        }
        // Very recent file with very old claimed creation date
        if (m.uploadTimestamp) {
            const uploadYear = m.uploadTimestamp.getFullYear();
            if (date.getFullYear() > uploadYear) {
                notes.push(`⚠ Date (${date.getFullYear()}) is after the upload year (${uploadYear}).`);
                authScore -= 30;
                flagged = true;
            }
        }

        return {
            id: uid('evt'),
            utc: date.toISOString(),
            label,
            source_field: field,
            authenticity_score: clamp(authScore),
            flagged,
            notes,
        };
    });

    // ── Step 3: Editing gaps analysis ─────────────────────────────────────────
    const editingGaps: EditingGap[] = [];
    for (let i = 1; i < timeline.length; i++) {
        const prev = timeline[i - 1];
        const curr = timeline[i];
        const gapSec = (new Date(curr.utc).getTime() - new Date(prev.utc).getTime()) / 1000;

        let assessment: EditingGap['assessment'] = 'normal';
        let explanation = '';

        if (gapSec < 0) {
            assessment = 'impossible_negative';
            explanation = `Timestamp sequence is reversed — "${curr.label}" (${curr.utc}) precedes "${prev.label}" (${prev.utc}). This is a logical impossibility and strongly suggests tampering or metadata rewriting.`;
        } else if (gapSec < 5 && gapSec >= 0) {
            // Less than 5 seconds between creation and modification is unusual unless auto-saved
            if (prev.label.includes('Creation') && curr.label.includes('Modification')) {
                assessment = 'short_suspicious';
                explanation = `Only ${humanDuration(gapSec)} between creation and first modification. Legitimate software rarely modifies metadata within seconds of creation — suggests automated metadata stamping or rewriting.`;
            }
        } else if (gapSec > 86400 * 365 * 5) {
            assessment = 'long_suspicious';
            explanation = `${humanDuration(gapSec)} gap between "${prev.label}" and "${curr.label}". A gap exceeding 5 years is unusual and may indicate a stale timestamp was deliberately reused or that the file was reconstructed from old metadata.`;
        } else {
            explanation = `${humanDuration(gapSec)} between "${prev.label}" and "${curr.label}" — within normal organic editing parameters.`;
        }

        editingGaps.push({
            id: uid('gap'),
            from_event: prev.id,
            to_event: curr.id,
            from_label: prev.label,
            to_label: curr.label,
            from_utc: prev.utc,
            to_utc: curr.utc,
            gap_seconds: gapSec,
            gap_human: gapSec < 0 ? `−${humanDuration(gapSec)}` : humanDuration(gapSec),
            assessment,
            explanation,
        });
    }

    // ── Step 4: Timezone signal collection ────────────────────────────────────
    const tzSignals: TimezoneSignal[] = [];

    if (m.timezone) {
        const off = parseUTCOffset(m.timezone);
        tzSignals.push({
            source: 'metadata.timezone',
            raw_value: m.timezone,
            utc_offset_minutes: off,
            region_hint: regionForOffset(off),
        });
    }

    // Inspect raw EXIF offsetTime fields if present
    const exif = (m.exifData || {}) as Record<string, { description?: string; value?: unknown }>;
    for (const key of ['OffsetTime', 'OffsetTimeOriginal', 'OffsetTimeDigitized']) {
        const val = exif[key]?.description ?? '';
        if (val) {
            const off = parseUTCOffset(val);
            tzSignals.push({
                source: `exif.${key}`,
                raw_value: val,
                utc_offset_minutes: off,
                region_hint: regionForOffset(off),
            });
        }
    }

    // GPS-implied timezone (latitude longitude → rough offset estimate)
    if (m.gpsLatitude !== undefined && m.gpsLongitude !== undefined) {
        const gpsOffsetMins = Math.round((m.gpsLongitude! / 15) * 60);
        tzSignals.push({
            source: 'gps.longitude_inference',
            raw_value: `${m.gpsLongitude!.toFixed(4)}° (≈ UTC${gpsOffsetMins >= 0 ? '+' : ''}${(gpsOffsetMins / 60).toFixed(1)})`,
            utc_offset_minutes: gpsOffsetMins,
            region_hint: regionForOffset(Math.round(gpsOffsetMins / 60) * 60),
        });
    }

    // Check for timezone conflict: multiple signals with differing offsets > 60 min
    const offsets = tzSignals.map(s => s.utc_offset_minutes).filter(o => o !== null) as number[];
    const uniqueOffsets = [...new Set(offsets)];
    const timezoneConflict = uniqueOffsets.length > 1 &&
        Math.max(...uniqueOffsets) - Math.min(...uniqueOffsets) > 60;

    // ── Step 5: Tampering event detection ─────────────────────────────────────
    const tampering: TamperingEvent[] = [];

    // T1 — Creation after modification
    if (m.creationDate && m.modificationDate && m.creationDate > m.modificationDate) {
        tampering.push({
            id: uid('tamp'),
            mechanism: 'timestamp_rollback',
            severity: 'critical',
            title: 'Creation Date Follows Modification Date',
            description: `The embedded creation date (${m.creationDate.toISOString()}) is chronologically AFTER the modification date (${m.modificationDate.toISOString()}). It is physically impossible for a file to be modified before it exists — this is a definitive indicator of timestamp rollback or metadata rewriting.`,
            involved_timestamps: [m.creationDate.toISOString(), m.modificationDate.toISOString()],
            involved_fields: ['metadata.creationDate', 'metadata.modificationDate'],
            recommended_action: 'Compare against filesystem creation time and original source if available. Consider this file tampered and flag for expert review.',
        });
    }

    // T2 — Future-dated timestamps
    for (const { date, label, field } of rawTS) {
        if (date > NOW_UTC) {
            tampering.push({
                id: uid('tamp'),
                mechanism: 'timestamp_forward',
                severity: 'high',
                title: `Future Timestamp: ${label}`,
                description: `"${label}" is dated ${date.toISOString()}, which is after the current timestamp (${NOW_UTC.toISOString()}). No legitimate process can produce a future-dated timestamp without manual manipulation of the system clock or metadata editor.`,
                involved_timestamps: [date.toISOString()],
                involved_fields: [field],
                recommended_action: 'Confirm system clock of the original device and contact the submitting party for explanation.',
            });
        }
    }

    // T3 — Implausibly old creation date
    if (m.creationDate && isTooOld(m.creationDate)) {
        tampering.push({
            id: uid('tamp'),
            mechanism: 'timestamp_rollback',
            severity: 'high',
            title: `Implausibly Old Creation Date: ${m.creationDate.getFullYear()}`,
            description: `Creation date of ${m.creationDate.getFullYear()} predates digital file formats. This is almost certainly a fabricated timestamp, possibly used to make a recently-created file appear historically authentic.`,
            involved_timestamps: [m.creationDate.toISOString()],
            involved_fields: ['metadata.creationDate'],
            recommended_action: 'Cross-reference with filesystem timestamps and file format version numbers.',
        });
    }

    // T4 — Filesystem date vs embedded date discrepancy > 30 days
    if (m.modificationDate && m.lastModified) {
        const diffDays = Math.abs(
            (m.modificationDate.getTime() - m.lastModified.getTime()) / (1000 * 60 * 60 * 24)
        );
        if (diffDays > 30) {
            tampering.push({
                id: uid('tamp'),
                mechanism: 'clock_skew',
                severity: 'medium',
                title: `Filesystem ↔ Embedded Date Discrepancy (${Math.round(diffDays)} days)`,
                description: `The filesystem last-modified date (${m.lastModified.toISOString()}) differs from the embedded modification date (${m.modificationDate.toISOString()}) by ${Math.round(diffDays)} days. This indicates the file was either re-exported with a synthetic timestamp, moved between systems, or had its metadata selectively edited.`,
                involved_timestamps: [m.modificationDate.toISOString(), m.lastModified.toISOString()],
                involved_fields: ['metadata.modificationDate', 'metadata.lastModified'],
                recommended_action: 'Obtain original file from the stated source and compare both filesystem and embedded timestamps.',
            });
        }
    }

    // T5 — Creation date after upload
    if (m.creationDate && m.uploadTimestamp) {
        if (m.creationDate.getFullYear() > m.uploadTimestamp.getFullYear()) {
            tampering.push({
                id: uid('tamp'),
                mechanism: 'impossible_sequence',
                severity: 'critical',
                title: 'Creation Date Later Than Upload Year',
                description: `File claims a creation year of ${m.creationDate.getFullYear()}, but was uploaded in ${m.uploadTimestamp.getFullYear()}. A file cannot be created after it is uploaded — this timestamp is fabricated.`,
                involved_timestamps: [m.creationDate.toISOString(), m.uploadTimestamp.toISOString()],
                involved_fields: ['metadata.creationDate', 'metadata.uploadTimestamp'],
                recommended_action: 'Reject the stated creation date. Treat the upload timestamp as the earliest verifiable bound.',
            });
        }
    }

    // T6 — Midnight timestamps (precision fabrication)
    const midnightHits = rawTS.filter(({ date }) => isMidnight(date));
    if (midnightHits.length >= 2) {
        tampering.push({
            id: uid('tamp'),
            mechanism: 'precision_fabrication',
            severity: 'medium',
            title: `${midnightHits.length} Timestamps Set to Exactly Midnight`,
            description: `${midnightHits.map(h => h.label).join(', ')} are all timestamped at exactly 00:00:00 UTC. Legitimate software timestamps are almost never exactly midnight — this pattern strongly suggests these timestamps were manually set using a metadata editor without specifying a time component.`,
            involved_timestamps: midnightHits.map(h => h.date.toISOString()),
            involved_fields: midnightHits.map(h => h.field),
            recommended_action: 'Treat all midnight timestamps as possibly fabricated. Seek alternative sources for temporal verification.',
        });
    } else if (midnightHits.length === 1) {
        tampering.push({
            id: uid('tamp'),
            mechanism: 'precision_fabrication',
            severity: 'low',
            title: `Suspiciously Round Timestamp: ${midnightHits[0].label}`,
            description: `"${midnightHits[0].label}" is exactly midnight (00:00:00). While not conclusive on its own, organic timestamps rarely land on exactly midnight.`,
            involved_timestamps: [midnightHits[0].date.toISOString()],
            involved_fields: [midnightHits[0].field],
            recommended_action: 'Consider this a weak indicator; evaluate alongside other anomalies.',
        });
    }

    // T7 — Timezone conflict
    if (timezoneConflict && tzSignals.length >= 2) {
        const [lo, hi] = [Math.min(...uniqueOffsets), Math.max(...uniqueOffsets)];
        tampering.push({
            id: uid('tamp'),
            mechanism: 'timezone_forgery',
            severity: 'medium',
            title: 'Conflicting Timezone Signals Detected',
            description: `Multiple timezone signals found with offsets spanning from UTC${lo >= 0 ? '+' : ''}${(lo / 60).toFixed(1)} to UTC${hi >= 0 ? '+' : ''}${(hi / 60).toFixed(1)} (a difference of ${Math.round(hi - lo)} minutes). Conflicting timezones can indicate the file was created on a device in one region but had its metadata edited on a system configured for a different timezone.`,
            involved_timestamps: [],
            involved_fields: tzSignals.map(s => s.source),
            recommended_action: 'Identify the device timezone from the OS or network logs and compare against embedded signals.',
        });
    }

    // T8 — Negative editing gaps
    const negativeGaps = editingGaps.filter(g => g.assessment === 'impossible_negative');
    for (const gap of negativeGaps) {
        tampering.push({
            id: uid('tamp'),
            mechanism: 'impossible_sequence',
            severity: 'critical',
            title: `Reversed Timestamp Sequence: ${gap.from_label} → ${gap.to_label}`,
            description: `"${gap.to_label}" (${gap.to_utc}) appears ${humanDuration(Math.abs(gap.gap_seconds))} BEFORE "${gap.from_label}" (${gap.from_utc}) in the metadata. This logical impossibility is a clear sign of timestamp manipulation.`,
            involved_timestamps: [gap.from_utc, gap.to_utc],
            involved_fields: [gap.from_event, gap.to_event],
            recommended_action: 'Flag as tampered. No legitimate process produces a reversed timestamp chain.',
        });
    }

    // T9 — Suspicious short gap (creation ↔ modification within 5s)
    const shortGaps = editingGaps.filter(g => g.assessment === 'short_suspicious');
    for (const gap of shortGaps) {
        tampering.push({
            id: uid('tamp'),
            mechanism: 'metadata_rewrite',
            severity: 'medium',
            title: `Suspiciously Short Edit Gap (${gap.gap_human})`,
            description: `Only ${gap.gap_human} separates "${gap.from_label}" and "${gap.to_label}". Automated metadata tools (ExifTool, ffmpeg) often produce near-simultaneous creation and modification dates when bulk-rewriting metadata.`,
            involved_timestamps: [gap.from_utc, gap.to_utc],
            involved_fields: [],
            recommended_action: 'Inspect software field for known metadata-editing tools. Cross-reference with hash of original file.',
        });
    }

    // T10 — High revision count with low/no author info (rewrite indicator)
    if (art.revisionCount > 20 && !m.author && !m.lastModifiedBy) {
        tampering.push({
            id: uid('tamp'),
            mechanism: 'revision_stripping',
            severity: 'medium',
            title: `High Revision Count (${art.revisionCount}) with No Author Metadata`,
            description: `The document has been revised ${art.revisionCount} times but carries no author or last-modified-by metadata. This combination suggests the author identity was deliberately stripped from a heavily-edited document — common in anti-forensic sanitization.`,
            involved_timestamps: [],
            involved_fields: ['metadata.author', 'metadata.lastModifiedBy', 'hiddenArtifacts.revisionCount'],
            recommended_action: 'Attempt to recover revision history embedded in the document body (e.g. DOCX undo history, PDF incremental updates).',
        });
    }

    // ── Step 6: Creation event determination ──────────────────────────────────
    // Pick the most authoritative creation timestamp
    const creationCandidates: Array<{ utc: string; source: string; confidence: number }> = [];

    if (m.creationDate) {
        let conf = 75;
        if (isTooOld(m.creationDate)) conf -= 40;
        if (isMidnight(m.creationDate)) conf -= 10;
        if (m.creationDate > NOW_UTC) conf -= 50;
        creationCandidates.push({ utc: m.creationDate.toISOString(), source: 'metadata.creationDate', confidence: clamp(conf) });
    }
    if (m.lastModified) {
        // Filesystem date is less reliable but often authentic
        let conf = 60;
        if (m.lastModified > NOW_UTC) conf -= 30;
        creationCandidates.push({ utc: m.lastModified.toISOString(), source: 'metadata.lastModified (filesystem)', confidence: clamp(conf) });
    }

    creationCandidates.sort((a, b) => b.confidence - a.confidence);
    const bestCreation = creationCandidates[0] ?? null;

    const corroborating = creationCandidates.slice(1).map(c => c.source);
    const creationIntegrity: CreationEvent['integrity'] =
        (bestCreation?.confidence ?? 0) >= 70 && tampering.filter(t => t.severity === 'critical').length === 0
            ? 'intact'
            : tampering.some(t => t.severity === 'critical') ? 'compromised'
                : 'suspect';

    const creationEvent: CreationEvent = {
        utc: bestCreation?.utc ?? null,
        authority_source: bestCreation?.source ?? 'none',
        corroborating_sources: corroborating,
        confidence: bestCreation?.confidence ?? 0,
        integrity: creationIntegrity,
        notes: [
            ...(creationIntegrity === 'compromised' ? ['Critical anomalies detected — creation timestamp cannot be trusted.'] : []),
            ...(corroborating.length > 0 ? [`Corroborated by: ${corroborating.join(', ')}`] : []),
            ...(bestCreation === null ? ['No timestamps available for creation event reconstruction.'] : []),
        ],
    };

    // ── Step 7: Compute overall integrity score ────────────────────────────────
    const severityPenalty: Record<AnomalySeverity, number> = {
        critical: 25, high: 15, medium: 8, low: 3, info: 0,
    };
    const totalPenalty = tampering.reduce((s, t) => s + severityPenalty[t.severity], 0);
    const integrityScore = clamp(100 - totalPenalty);

    const verdict: ChronologyReport['verdict'] =
        rawTS.length === 0 ? 'insufficient_data'
            : integrityScore >= 80 ? 'authentic'
                : integrityScore >= 50 ? 'suspect'
                    : 'tampered';

    const verdictExplanation =
        verdict === 'insufficient_data'
            ? 'No timestamp metadata was found. Cannot reconstruct a lifecycle chronology.'
            : verdict === 'authentic'
                ? `All ${timeline.length} timestamp signal(s) appear consistent and ordered. No critical anomalies detected. Integrity score: ${integrityScore}/100.`
                : verdict === 'suspect'
                    ? `${tampering.length} anomal${tampering.length === 1 ? 'y' : 'ies'} detected across the lifecycle timeline. Some timestamps appear inconsistent. Integrity score: ${integrityScore}/100 — file warrants further investigation.`
                    : `${tampering.filter(t => t.severity === 'critical').length} critical tampering indicator(s) found. Timestamp chain is logically broken. Integrity score: ${integrityScore}/100 — this file should NOT be trusted as an authentic evidence source.`;

    // Anomaly count map
    const anomalyCounts: Record<AnomalySeverity, number> = {
        critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    for (const t of tampering) anomalyCounts[t.severity]++;

    const detectedMechanisms = [...new Set(tampering.map(t => t.mechanism))];

    return {
        analysed_at: new Date().toISOString(),
        file_name: m.fileName,
        sha256: m.sha256Hash,
        integrity_score: integrityScore,
        verdict,
        verdict_explanation: verdictExplanation,
        creation_event: creationEvent,
        timeline,
        editing_gaps: editingGaps,
        timezone_signals: tzSignals,
        timezone_conflict: timezoneConflict,
        tampering_events: tampering,
        anomaly_counts: anomalyCounts,
        detected_mechanisms: detectedMechanisms,
    };
}
