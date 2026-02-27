/**
 * Digital Attribution Analyst
 * ────────────────────────────
 * Infers probable author identity, organization affiliation, device ownership,
 * recurring usernames, and creator-vs-modifier distinctions from normalized metadata.
 *
 * Produces per-inference confidence scores (0–100), supporting metadata fields,
 * and catalogued identity conflicts.
 */

import { NormalizedMetadata } from './metadata-normalizer';

// ── Output Types ───────────────────────────────────────────────────────────

/** Confidence tier derived from a numeric score */
export type ConfidenceTier = 'definitive' | 'high' | 'moderate' | 'low' | 'none';

/** A single supporting piece of evidence */
export interface EvidenceField {
    field: string;            // Human-readable field name
    value: string;            // Actual value observed
    weight: number;           // Points this field contributed (1-30)
    source: string;           // Where in the metadata this came from
}

/** An identity conflict — contradictory signals */
export interface IdentityConflict {
    id: string;
    type: 'name_mismatch' | 'username_alias' | 'multi_org' | 'email_name_gap' | 'creator_modifier_split' | 'ghost_editor';
    severity: 'high' | 'medium' | 'low';
    description: string;
    fieldsInvolved: string[];
}

/** Inferred author identity */
export interface AuthorInference {
    probable_name: string | null;
    probable_email: string | null;
    confidence_score: number;
    confidence_tier: ConfidenceTier;
    supporting_metadata_fields: EvidenceField[];
    reasoning: string;
}

/** Inferred organization affiliation */
export interface OrganizationInference {
    probable_organization: string | null;
    org_domain: string | null;        // Extracted from email domain
    confidence_score: number;
    confidence_tier: ConfidenceTier;
    supporting_metadata_fields: EvidenceField[];
    reasoning: string;
}

/** Inferred device ownership */
export interface DeviceOwnershipInference {
    probable_owner: string | null;
    device_fingerprint: string | null;
    os_fingerprint: string | null;
    username_on_device: string | null;
    confidence_score: number;
    confidence_tier: ConfidenceTier;
    supporting_metadata_fields: EvidenceField[];
    reasoning: string;
}

/** Recurring username analysis */
export interface UsernameAnalysis {
    canonical_username: string | null;     // Most-repeated / most reliable username
    all_usernames: string[];
    recurring: string[];                   // Appears in ≥2 independent fields
    email_username: string | null;         // Local-part of first email
    path_username: string | null;          // From embedded path
    name_username_match: boolean;          // Whether display name ≈ username
    confidence_score: number;
    confidence_tier: ConfidenceTier;
    supporting_metadata_fields: EvidenceField[];
}

/** Creator vs modifier distinction */
export interface CreatorModifierAnalysis {
    creator_name: string | null;
    creator_source: string | null;          // Which field held the creator name
    modifier_name: string | null;
    modifier_source: string | null;
    same_person: boolean;
    role_split: boolean;                    // true when creator ≠ modifier
    modifier_introduced_at: string | null;  // UTC ISO date
    confidence_score: number;
    confidence_tier: ConfidenceTier;
    supporting_metadata_fields: EvidenceField[];
    reasoning: string;
}

/** Complete attribution report */
export interface AttributionReport {
    analysed_at: string;               // UTC ISO
    file_name: string;
    sha256: string;
    /** Overall composite attribution confidence (0–100) */
    overall_confidence_score: number;
    overall_confidence_tier: ConfidenceTier;
    author: AuthorInference;
    organization: OrganizationInference;
    device_ownership: DeviceOwnershipInference;
    username_analysis: UsernameAnalysis;
    creator_modifier: CreatorModifierAnalysis;
    possible_identity_conflicts: IdentityConflict[];
    /** OSINT investigation leads derived from the attribution */
    osint_leads: string[];
}

// ── Helpers ────────────────────────────────────────────────────────────────

function tier(score: number): ConfidenceTier {
    if (score >= 85) return 'definitive';
    if (score >= 65) return 'high';
    if (score >= 40) return 'moderate';
    if (score >= 15) return 'low';
    return 'none';
}

function clamp(n: number): number {
    return Math.max(0, Math.min(100, Math.round(n)));
}

/** Extract local-part of an email address */
function emailLocal(email: string): string {
    return email.split('@')[0];
}

/** Extract domain of an email address */
function emailDomain(email: string): string {
    return email.split('@')[1] ?? '';
}

/** Naïve name-slug similarity: "John Smith" vs "jsmith" or "johnsmith" */
function namesAlign(displayName: string | null, username: string | null): boolean {
    if (!displayName || !username) return false;
    const slug = displayName.toLowerCase().replace(/\s+/g, '');
    const slug2 = displayName.toLowerCase().split(/\s+/).map(p => p[0]).join(''); // initials
    const u = username.toLowerCase().replace(/[._\-]/g, '');
    return u.includes(slug.slice(0, 4)) || slug.includes(u.slice(0, 4)) || u === slug2;
}

/** Free-mail domains — not useful for org inference */
const FREE_MAIL_DOMAINS = new Set([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
    'protonmail.com', 'me.com', 'live.com', 'aol.com', 'mail.com', 'yandex.com',
]);

/** Vendor-to-org domain guesses  */
const KNOWN_VENDOR_DOMAINS: Record<string, string> = {
    Microsoft: 'microsoft.com',
    Adobe: 'adobe.com',
    Apple: 'apple.com',
    Google: 'google.com',
};

// ── Core inference functions ───────────────────────────────────────────────

function inferAuthor(n: NormalizedMetadata): AuthorInference {
    const ev: EvidenceField[] = [];
    let score = 0;

    const id = n.identity_data;
    const net = n.network_data;

    // Priority 1: explicit author field
    if (id.author) {
        ev.push({ field: 'metadata.author', value: id.author, weight: 30, source: 'Document author field' });
        score += 30;
    }

    // Priority 2: lastModifiedBy corroborates or conflicts
    if (id.lastModifiedBy && id.lastModifiedBy === id.author) {
        ev.push({ field: 'metadata.lastModifiedBy', value: id.lastModifiedBy, weight: 10, source: 'Last-modified-by field matches author' });
        score += 10;
    }

    // Priority 3: device owner
    if (id.deviceOwner) {
        ev.push({ field: 'metadata.deviceOwner', value: id.deviceOwner, weight: 15, source: 'Device owner field' });
        score += 15;
    }

    // Priority 4: email local-part
    const primaryEmail = net.emails[0] ?? null;
    if (primaryEmail) {
        ev.push({ field: 'network.email', value: primaryEmail, weight: 20, source: 'Embedded email address' });
        score += 20;
    }

    // Priority 5: username from path corroborates name
    if (id.usernamesFromPaths.length > 0) {
        const pu = id.usernamesFromPaths[0];
        ev.push({ field: 'path.username', value: pu, weight: 15, source: 'Username extracted from embedded file path' });
        score += 15;
    }

    // Priority 6: creator tool implies a person used a specific app (weak signal)
    if (n.software_data.creatorTool) {
        ev.push({ field: 'software.creatorTool', value: n.software_data.creatorTool, weight: 5, source: 'XMP CreatorTool field' });
        score += 5;
    }

    const probable_name = id.author ?? id.deviceOwner ?? id.lastModifiedBy ??
        (id.usernamesFromPaths[0] ?? null);
    const probable_email = primaryEmail;

    let reasoning = '';
    if (probable_name && probable_email) {
        reasoning = `Strong attribution: display name "${probable_name}" found in document metadata and corroborated by embedded email "${probable_email}".`;
    } else if (probable_name) {
        reasoning = `Moderate attribution: name "${probable_name}" found in metadata field(s), but no corroborating email address detected.`;
    } else if (probable_email) {
        reasoning = `Weak attribution: no explicit name found; email "${probable_email}" is the only identity anchor.`;
    } else {
        reasoning = 'Insufficient attribution data. No author name, email, or device-owner fields were present in the metadata.';
    }

    return {
        probable_name,
        probable_email,
        confidence_score: clamp(score),
        confidence_tier: tier(score),
        supporting_metadata_fields: ev,
        reasoning,
    };
}

function inferOrganization(n: NormalizedMetadata): OrganizationInference {
    const ev: EvidenceField[] = [];
    let score = 0;

    const id = n.identity_data;
    const net = n.network_data;
    const sw = n.software_data;

    // Priority 1: explicit org field
    if (id.organization) {
        ev.push({ field: 'metadata.organization', value: id.organization, weight: 35, source: 'Organization metadata field' });
        score += 35;
    }

    // Priority 2: corporate email domain
    let orgDomain: string | null = null;
    const corpEmail = net.emails.find(e => !FREE_MAIL_DOMAINS.has(emailDomain(e)));
    if (corpEmail) {
        orgDomain = emailDomain(corpEmail);
        ev.push({ field: 'network.email_domain', value: orgDomain, weight: 25, source: `Corporate email domain from "${corpEmail}"` });
        score += 25;
    }

    // Priority 3: UNC paths contain org hostname
    if (net.uncPaths.length > 0) {
        const serverMatch = net.uncPaths[0].match(/\\\\([^\\]+)/);
        if (serverMatch) {
            ev.push({ field: 'network.unc_server', value: serverMatch[1], weight: 15, source: `Internal server name from UNC path: ${net.uncPaths[0]}` });
            score += 15;
        }
    }

    // Priority 4: vendor corroboration — if org matches known vendor
    if (id.organization && sw.vendors.length > 0) {
        const orgLower = id.organization.toLowerCase();
        const matchedVendor = sw.vendors.find(v => orgLower.includes(v.toLowerCase()) || v.toLowerCase().includes(orgLower));
        if (matchedVendor) {
            ev.push({ field: 'software.vendor_match', value: matchedVendor, weight: 10, source: `Software vendor "${matchedVendor}" matches stated organization` });
            score += 10;
            if (!orgDomain) orgDomain = KNOWN_VENDOR_DOMAINS[matchedVendor] ?? null;
        }
    }

    // Priority 5: hostname as org domain hint
    if (!orgDomain && net.hostnames.length > 0) {
        const h = net.hostnames[0];
        if (!FREE_MAIL_DOMAINS.has(h)) {
            orgDomain = h;
            ev.push({ field: 'network.hostname', value: h, weight: 8, source: `Internal hostname may indicate org domain` });
            score += 8;
        }
    }

    const probable_organization = id.organization ??
        (orgDomain ? orgDomain.split('.').slice(0, -1).join('.').replace(/^www\./, '') : null);

    let reasoning = '';
    if (id.organization && orgDomain) {
        reasoning = `High-confidence org attribution: "${id.organization}" stated explicitly, corroborated by corporate email domain "${orgDomain}".`;
    } else if (id.organization) {
        reasoning = `Organization "${id.organization}" found in metadata. No corroborating email domain to confirm.`;
    } else if (orgDomain) {
        reasoning = `Organization inferred from corporate email domain "${orgDomain}". No explicit org field present.`;
    } else {
        reasoning = 'No organizational metadata found. Cannot determine affiliation.';
    }

    return {
        probable_organization,
        org_domain: orgDomain,
        confidence_score: clamp(score),
        confidence_tier: tier(score),
        supporting_metadata_fields: ev,
        reasoning,
    };
}

function inferDeviceOwnership(n: NormalizedMetadata): DeviceOwnershipInference {
    const ev: EvidenceField[] = [];
    let score = 0;

    const id = n.identity_data;
    const dev = n.device_data;
    const loc = n.location_data;

    // Explicit device owner field
    if (id.deviceOwner) {
        ev.push({ field: 'metadata.deviceOwner', value: id.deviceOwner, weight: 30, source: 'Explicit device owner field' });
        score += 30;
    }

    // Device model fingerprint
    if (dev.device) {
        ev.push({ field: 'metadata.device', value: dev.device, weight: 20, source: 'Camera/device model from EXIF Make+Model' });
        score += 20;
    }

    // OS fingerprint
    if (dev.operatingSystem) {
        ev.push({ field: 'device.os', value: `${dev.operatingSystem} (via ${dev.osSource})`, weight: 10, source: `OS inferred from ${dev.osSource}` });
        score += 10;
    }

    // Username from path = likely the OS login for the owning account
    const pathUser = id.usernamesFromPaths[0] ?? null;
    if (pathUser) {
        ev.push({ field: 'path.system_username', value: pathUser, weight: 25, source: 'System login username extracted from embedded file path' });
        score += 25;
    }

    // GPS ties device to physical location = strong ownership signal
    if (loc.latitude !== null && loc.coordinateSuspicion === 'none') {
        ev.push({ field: 'gps.coordinates', value: `${loc.latitude?.toFixed(5)}, ${loc.longitude?.toFixed(5)}`, weight: 10, source: 'GPS coordinates embedded by device camera' });
        score += 10;
    }

    const probable_owner = id.deviceOwner ?? id.author ?? pathUser ?? null;

    let reasoning = '';
    if (id.deviceOwner) {
        reasoning = `Explicit device owner metadata present: "${id.deviceOwner}".`;
    } else if (pathUser && dev.device) {
        reasoning = `Device model "${dev.device}" identified, and system username "${pathUser}" found in embedded paths — strongly suggests personal device ownership.`;
    } else if (pathUser) {
        reasoning = `System-account username "${pathUser}" found in embedded paths, suggesting the file was created on an account belonging to this user.`;
    } else if (dev.device) {
        reasoning = `Device "${dev.device}" identified but no username or owner name found — device ownership cannot be confidently attributed to an individual.`;
    } else {
        reasoning = 'No device ownership indicators found in the metadata.';
    }

    return {
        probable_owner,
        device_fingerprint: dev.device,
        os_fingerprint: dev.operatingSystem,
        username_on_device: pathUser,
        confidence_score: clamp(score),
        confidence_tier: tier(score),
        supporting_metadata_fields: ev,
        reasoning,
    };
}

function analyzeUsernames(n: NormalizedMetadata): UsernameAnalysis {
    const ev: EvidenceField[] = [];
    let score = 0;

    const id = n.identity_data;
    const net = n.network_data;

    const emailUser = net.emails.length > 0 ? emailLocal(net.emails[0]) : null;
    const pathUser = id.usernamesFromPaths[0] ?? null;

    // Collect all candidate usernames from multiple sources
    const candidates: string[] = [
        ...(emailUser ? [emailUser] : []),
        ...(pathUser ? [pathUser] : []),
        ...(id.author ? [id.author.toLowerCase().replace(/\s+/g, '.')] : []),
        ...(id.deviceOwner ? [id.deviceOwner.toLowerCase().replace(/\s+/g, '.')] : []),
    ].map(u => u.toLowerCase().replace(/\s+/g, ''));

    // Find recurring (appears in ≥2 sources)
    const freqMap: Record<string, number> = {};
    for (const c of candidates) { freqMap[c] = (freqMap[c] ?? 0) + 1; }
    const recurring = Object.entries(freqMap)
        .filter(([, count]) => count >= 2)
        .map(([u]) => u);

    const canonicalUsername = recurring[0] ?? candidates[0] ?? null;

    if (emailUser) {
        ev.push({ field: 'email.local_part', value: emailUser, weight: 25, source: `Local-part of email "${net.emails[0]}"` });
        score += 25;
    }
    if (pathUser) {
        ev.push({ field: 'path.username', value: pathUser, weight: 25, source: 'OS account username from embedded path' });
        score += 25;
    }
    if (recurring.length > 0) {
        ev.push({ field: 'username.recurring', value: recurring.join(', '), weight: 20, source: 'Username appears in ≥2 independent metadata sources' });
        score += 20;
    }

    const nameUsernameMatch = namesAlign(id.author, canonicalUsername);
    if (nameUsernameMatch) {
        ev.push({ field: 'username.name_match', value: `"${id.author}" ≈ "${canonicalUsername}"`, weight: 15, source: 'Display name slug matches detected username' });
        score += 15;
    }

    return {
        canonical_username: canonicalUsername,
        all_usernames: [...new Set(candidates)],
        recurring,
        email_username: emailUser,
        path_username: pathUser,
        name_username_match: nameUsernameMatch,
        confidence_score: clamp(score),
        confidence_tier: tier(score),
        supporting_metadata_fields: ev,
    };
}

function analyzeCreatorModifier(n: NormalizedMetadata): CreatorModifierAnalysis {
    const ev: EvidenceField[] = [];
    let score = 0;

    const id = n.identity_data;
    const tl = n.timeline_data;
    const sw = n.software_data;

    // Creator = original author field OR XMP:Creator
    const creatorName = id.author ?? (sw.creatorTool ? null : null);
    const creatorSource = id.author
        ? 'metadata.author'
        : sw.creatorTool
            ? 'software.creatorTool'
            : null;

    // Modifier = lastModifiedBy field
    const modifierName = id.lastModifiedBy ?? null;
    const modifierSource = id.lastModifiedBy ? 'metadata.lastModifiedBy' : null;

    if (creatorName) {
        ev.push({ field: creatorSource!, value: creatorName, weight: 30, source: 'Original creator name' });
        score += 30;
    }
    if (modifierName) {
        ev.push({ field: 'metadata.lastModifiedBy', value: modifierName, weight: 25, source: 'Last-modified-by name' });
        score += 25;
    }

    // Are they the same person?
    const samePerson = !!(creatorName && modifierName &&
        creatorName.toLowerCase().trim() === modifierName.toLowerCase().trim());

    const roleSplit = !!(creatorName && modifierName && !samePerson);

    if (roleSplit) {
        ev.push({ field: 'creator_vs_modifier', value: `"${creatorName}" → "${modifierName}"`, weight: 20, source: 'Creator and modifier names differ — role split detected' });
        score += 20;
    } else if (samePerson) {
        ev.push({ field: 'creator_vs_modifier', value: `"${creatorName}" (same person)`, weight: 10, source: 'Creator and modifier are the same individual' });
        score += 10;
    }

    // Modification date gives temporal context for when a modifier took over
    const modifierDate = tl.modificationDateUTC ?? null;
    if (modifierDate && roleSplit) {
        ev.push({ field: 'timeline.modificationDateUTC', value: modifierDate, weight: 10, source: 'Timestamp when the modifier last touched the file' });
        score += 10;
    }

    // Multi-editor pipeline raises role-split confidence
    if (sw.multipleEditorsPipeline) {
        ev.push({ field: 'software.multipleEditorsPipeline', value: 'true', weight: 10, source: 'Multiple editing tools detected — suggests multi-person workflow' });
        score += 10;
    }

    let reasoning = '';
    if (roleSplit) {
        reasoning = `Creator-modifier split detected: "${creatorName}" originally created the file; "${modifierName}" performed subsequent edits${modifierDate ? ` (last edit: ${modifierDate})` : ''}. This suggests collaborative authorship or unauthorized post-creation editing.`;
    } else if (samePerson) {
        reasoning = `Creator and modifier are the same individual: "${creatorName}". No role split detected; the file appears to have been authored and edited by a single person.`;
    } else if (creatorName) {
        reasoning = `Creator "${creatorName}" identified, but no "last modified by" field present — cannot determine whether a second editor was involved.`;
    } else {
        reasoning = 'No creator or modifier metadata found. Role distinction cannot be established.';
    }

    return {
        creator_name: creatorName,
        creator_source: creatorSource,
        modifier_name: modifierName,
        modifier_source: modifierSource,
        same_person: samePerson,
        role_split: roleSplit,
        modifier_introduced_at: modifierDate,
        confidence_score: clamp(score),
        confidence_tier: tier(score),
        supporting_metadata_fields: ev,
        reasoning,
    };
}

function detectConflicts(
    n: NormalizedMetadata,
    author: AuthorInference,
    org: OrganizationInference,
    cm: CreatorModifierAnalysis,
    ua: UsernameAnalysis,
): IdentityConflict[] {
    const conflicts: IdentityConflict[] = [];
    let idx = 0;
    const id = n.identity_data;
    const net = n.network_data;

    // 1. Author name vs. last-modified-by name mismatch
    if (id.author && id.lastModifiedBy &&
        id.author.toLowerCase().trim() !== id.lastModifiedBy.toLowerCase().trim()) {
        conflicts.push({
            id: `conflict_${++idx}`,
            type: 'creator_modifier_split',
            severity: 'high',
            description: `Creator name "${id.author}" does not match modifier name "${id.lastModifiedBy}". The file was created by one person and later edited by another, which may indicate unauthorized alteration or collaborative editing without proper disclosure.`,
            fieldsInvolved: ['metadata.author', 'metadata.lastModifiedBy'],
        });
    }

    // 2. Email local-part does not match display name
    if (ua.email_username && id.author && !namesAlign(id.author, ua.email_username)) {
        conflicts.push({
            id: `conflict_${++idx}`,
            type: 'email_name_gap',
            severity: 'medium',
            description: `Display name "${id.author}" does not match the username portion "${ua.email_username}" of the embedded email "${net.emails[0]}". This could indicate a pseudonym, shared account, or a borrowed device.`,
            fieldsInvolved: ['metadata.author', 'network.email'],
        });
    }

    // 3. Multiple different usernames from different sources
    if (ua.all_usernames.length > 2 && ua.recurring.length === 0) {
        conflicts.push({
            id: `conflict_${++idx}`,
            type: 'username_alias',
            severity: 'medium',
            description: `Multiple distinct usernames detected (${ua.all_usernames.join(', ')}) with no single recurring value. This suggests aliases, multiple accounts, or aggregated metadata from different authors.`,
            fieldsInvolved: ['path.username', 'email.local_part', 'metadata.author'],
        });
    }

    // 4. Organization field conflicts with email domain
    if (org.probable_organization && org.org_domain) {
        const orgSlug = org.probable_organization.toLowerCase().replace(/\s+/g, '');
        const domainSlug = org.org_domain.split('.')[0].toLowerCase();
        if (!orgSlug.includes(domainSlug) && !domainSlug.includes(orgSlug)) {
            conflicts.push({
                id: `conflict_${++idx}`,
                type: 'multi_org',
                severity: 'medium',
                description: `Stated organization "${org.probable_organization}" does not match the email domain "${org.org_domain}". The file may have been created on behalf of one organization but sent or stored under another.`,
                fieldsInvolved: ['metadata.organization', 'network.email_domain'],
            });
        }
    }

    // 5. Author name present but path username completely different
    if (id.author && ua.path_username && !namesAlign(id.author, ua.path_username)) {
        conflicts.push({
            id: `conflict_${++idx}`,
            type: 'ghost_editor',
            severity: 'low',
            description: `The file claims author "${id.author}", but the embedded system path contains username "${ua.path_username}". The file may have been modified on a different machine or by a different OS account than the stated author.`,
            fieldsInvolved: ['metadata.author', 'path.username'],
        });
    }

    return conflicts;
}

function buildOsintLeads(
    n: NormalizedMetadata,
    author: AuthorInference,
    org: OrganizationInference,
    ua: UsernameAnalysis,
): string[] {
    const leads: string[] = [];
    const net = n.network_data;
    const loc = n.location_data;

    if (author.probable_name) leads.push(`Search "${author.probable_name}" on LinkedIn, GitHub, Twitter, and Google`);
    if (author.probable_email) leads.push(`Run "${author.probable_email}" through HaveIBeenPwned for breach exposure`);
    if (ua.canonical_username) leads.push(`Search username "${ua.canonical_username}" across platforms: GitHub, Reddit, Twitter, HackerNews`);
    if (org.probable_organization) leads.push(`OSINT the organization "${org.probable_organization}": LinkedIn employees, Crunchbase, WHOIS`);
    if (org.org_domain) leads.push(`Perform WHOIS, DNS, and certificate transparency search on domain "${org.org_domain}"`);
    if (net.ipv4Addresses.some(p => p.classification === 'public')) {
        const pub = net.ipv4Addresses.filter(p => p.classification === 'public').map(p => p.ip);
        leads.push(`Geolocate and WHOIS public IP${pub.length > 1 ? 's' : ''}: ${pub.join(', ')}`);
    }
    if (loc.latitude !== null && loc.coordinateSuspicion === 'none') {
        leads.push(`Reverse-geocode GPS (${loc.latitude?.toFixed(5)}, ${loc.longitude?.toFixed(5)}) to identify the physical location of capture`);
    }
    if (net.uncPaths.length > 0) {
        leads.push(`Analyse UNC hostnames for internal infrastructure mapping: ${net.uncPaths.join(', ')}`);
    }

    return leads;
}

// ── Master analysis function ────────────────────────────────────────────────

export function analyzeAttribution(normalized: NormalizedMetadata): AttributionReport {
    const author = inferAuthor(normalized);
    const organization = inferOrganization(normalized);
    const device = inferDeviceOwnership(normalized);
    const usernames = analyzeUsernames(normalized);
    const creatorModifier = analyzeCreatorModifier(normalized);

    const conflicts = detectConflicts(normalized, author, organization, creatorModifier, usernames);
    const osint = buildOsintLeads(normalized, author, organization, usernames);

    // Overall composite: weighted average of individual scores, penalised by conflicts
    const subScores = [
        author.confidence_score * 0.30,
        organization.confidence_score * 0.20,
        device.confidence_score * 0.20,
        usernames.confidence_score * 0.15,
        creatorModifier.confidence_score * 0.15,
    ];
    const rawComposite = subScores.reduce((a, b) => a + b, 0);
    const conflictPenalty = conflicts.reduce((p, c) =>
        p + (c.severity === 'high' ? 10 : c.severity === 'medium' ? 5 : 2), 0);

    const overallScore = clamp(rawComposite - conflictPenalty);

    return {
        analysed_at: new Date().toISOString(),
        file_name: normalized.fileName,
        sha256: normalized.sha256,
        overall_confidence_score: overallScore,
        overall_confidence_tier: tier(overallScore),
        author,
        organization,
        device_ownership: device,
        username_analysis: usernames,
        creator_modifier: creatorModifier,
        possible_identity_conflicts: conflicts,
        osint_leads: osint,
    };
}
