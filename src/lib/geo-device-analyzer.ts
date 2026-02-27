/**
 * Geographic & Device Indicator Analyzer
 * ────────────────────────────────────────
 * Extracts and infers:
 *  - GPS coordinates (exact or estimated)
 *  - Camera / device model fingerprint
 *  - OS ecosystem
 *  - Regional settings (timezone, locale, date formats)
 *  - Language fingerprints
 *  - Estimated origin region with reasoning when GPS is absent
 */

import { NormalizedMetadata } from './metadata-normalizer';

// ── Output Types ────────────────────────────────────────────────────────────

export type RegionConfidence = 'exact' | 'high' | 'moderate' | 'low' | 'unknown';

export interface GpsCoordinates {
  latitude: number;
  longitude: number;
  altitudeMetres: number | null;
  googleMapsUrl: string;
  precision: string;
  suspicion: 'none' | 'null_island' | 'excessive_precision';
}

export interface DeviceProfile {
  make: string | null;
  model: string | null;
  fullDeviceString: string | null;
  category: 'smartphone' | 'dslr_mirrorless' | 'laptop_desktop' | 'tablet' | 'unknown';
  brand: string | null;
  osEcosystem: OsEcosystem | null;
}

export type OsEcosystem =
  | 'Apple iOS / iPadOS'
  | 'Apple macOS'
  | 'Android'
  | 'Windows'
  | 'Linux'
  | 'ChromeOS'
  | 'Unknown';

export interface RegionalProfile {
  detectedTimezone: string | null;
  timezoneUtcOffset: string | null;
  likelyRegionFromTimezone: string | null;
  embeddedLocale: string | null;
  dateFormatHint: 'DMY' | 'MDY' | 'YMD' | 'unknown';
  currencySymbolDetected: string | null;
  numberFormatHint: ',' | '.' | 'unknown';   // decimal separator
}

export interface LanguageFingerprint {
  detectedLanguages: string[];
  primaryLanguage: string | null;
  languageSource: string[];   // which fields the language was found in
  scriptDetected: string | null;  // Latin, Cyrillic, Arabic, CJK, etc.
  rtlScript: boolean;
  languageClues: string[];  // human-readable clues
}

export interface OriginEstimate {
  /** Broad region name */
  region: string;
  /** Sub-region or country when confidence allows */
  subRegion: string | null;
  /** Confidence in the estimate */
  confidence: RegionConfidence;
  /** Method used to arrive at this estimate */
  inferenceMethod: 'gps_exact' | 'timezone' | 'device_make' | 'language' | 'software_locale' | 'combined' | 'none';
  /** Step-by-step reasoning */
  reasoning: string[];
  /** Any caveats or limitations */
  caveats: string[];
  /** Approximate flag emoji for display */
  regionEmoji: string;
}

export interface GeoDeviceReport {
  analyzedAt: string;
  fileName: string;

  // Direct GPS (if available)
  gpsCoordinates: GpsCoordinates | null;
  gpsAvailable: boolean;

  // Device fingerprint
  deviceProfile: DeviceProfile;

  // OS ecosystem
  osEcosystem: OsEcosystem | null;
  osConfidence: 'high' | 'moderate' | 'low' | 'none';
  osEvidenceSources: string[];

  // Regional settings
  regionalProfile: RegionalProfile;

  // Language fingerprints
  languageFingerprint: LanguageFingerprint;

  // Estimated origin (always present, even without GPS)
  originEstimate: OriginEstimate;

  // OSINT leads
  osintLeads: string[];
}

// ── Timezone → Region mapping ───────────────────────────────────────────────

const TZ_REGION_MAP: Record<string, { region: string; sub: string; emoji: string }> = {
  // Americas
  'America/New_York':       { region: 'North America', sub: 'Eastern USA / Canada',   emoji: '🇺🇸' },
  'America/Chicago':        { region: 'North America', sub: 'Central USA / Canada',   emoji: '🇺🇸' },
  'America/Denver':         { region: 'North America', sub: 'Mountain USA',           emoji: '🇺🇸' },
  'America/Los_Angeles':    { region: 'North America', sub: 'Western USA / Canada',   emoji: '🇺🇸' },
  'America/Phoenix':        { region: 'North America', sub: 'Arizona, USA',           emoji: '🇺🇸' },
  'America/Anchorage':      { region: 'North America', sub: 'Alaska, USA',            emoji: '🇺🇸' },
  'America/Honolulu':       { region: 'North America', sub: 'Hawaii, USA',            emoji: '🇺🇸' },
  'America/Toronto':        { region: 'North America', sub: 'Eastern Canada',         emoji: '🇨🇦' },
  'America/Vancouver':      { region: 'North America', sub: 'British Columbia, Canada',emoji: '🇨🇦' },
  'America/Mexico_City':    { region: 'Latin America', sub: 'Mexico',                 emoji: '🇲🇽' },
  'America/Sao_Paulo':      { region: 'Latin America', sub: 'Brazil',                 emoji: '🇧🇷' },
  'America/Buenos_Aires':   { region: 'Latin America', sub: 'Argentina',              emoji: '🇦🇷' },
  'America/Bogota':         { region: 'Latin America', sub: 'Colombia',               emoji: '🇨🇴' },
  // Europe
  'Europe/London':          { region: 'Europe',        sub: 'United Kingdom',         emoji: '🇬🇧' },
  'Europe/Dublin':          { region: 'Europe',        sub: 'Ireland',                emoji: '🇮🇪' },
  'Europe/Paris':           { region: 'Europe',        sub: 'Western Europe (Fr/Be/Lu)',emoji: '🇫🇷' },
  'Europe/Berlin':          { region: 'Europe',        sub: 'Germany / Austria',      emoji: '🇩🇪' },
  'Europe/Amsterdam':       { region: 'Europe',        sub: 'Netherlands',            emoji: '🇳🇱' },
  'Europe/Madrid':          { region: 'Europe',        sub: 'Spain',                  emoji: '🇪🇸' },
  'Europe/Rome':            { region: 'Europe',        sub: 'Italy',                  emoji: '🇮🇹' },
  'Europe/Stockholm':       { region: 'Europe',        sub: 'Sweden / Norway',        emoji: '🇸🇪' },
  'Europe/Warsaw':          { region: 'Europe',        sub: 'Poland',                 emoji: '🇵🇱' },
  'Europe/Prague':          { region: 'Europe',        sub: 'Czech Republic',         emoji: '🇨🇿' },
  'Europe/Bucharest':       { region: 'Europe',        sub: 'Romania',                emoji: '🇷🇴' },
  'Europe/Athens':          { region: 'Europe',        sub: 'Greece',                 emoji: '🇬🇷' },
  'Europe/Helsinki':        { region: 'Europe',        sub: 'Finland',                emoji: '🇫🇮' },
  'Europe/Kiev':            { region: 'Europe',        sub: 'Ukraine',                emoji: '🇺🇦' },
  'Europe/Moscow':          { region: 'Europe / Russia', sub: 'Moscow, Russia',       emoji: '🇷🇺' },
  // Asia
  'Asia/Kolkata':           { region: 'South Asia',    sub: 'India',                  emoji: '🇮🇳' },
  'Asia/Calcutta':          { region: 'South Asia',    sub: 'India',                  emoji: '🇮🇳' },
  'Asia/Dhaka':             { region: 'South Asia',    sub: 'Bangladesh',             emoji: '🇧🇩' },
  'Asia/Karachi':           { region: 'South Asia',    sub: 'Pakistan',               emoji: '🇵🇰' },
  'Asia/Colombo':           { region: 'South Asia',    sub: 'Sri Lanka',              emoji: '🇱🇰' },
  'Asia/Kathmandu':         { region: 'South Asia',    sub: 'Nepal',                  emoji: '🇳🇵' },
  'Asia/Shanghai':          { region: 'East Asia',     sub: 'China',                  emoji: '🇨🇳' },
  'Asia/Hong_Kong':         { region: 'East Asia',     sub: 'Hong Kong',              emoji: '🇭🇰' },
  'Asia/Tokyo':             { region: 'East Asia',     sub: 'Japan',                  emoji: '🇯🇵' },
  'Asia/Seoul':             { region: 'East Asia',     sub: 'South Korea',            emoji: '🇰🇷' },
  'Asia/Taipei':            { region: 'East Asia',     sub: 'Taiwan',                 emoji: '🇹🇼' },
  'Asia/Singapore':         { region: 'Southeast Asia',sub: 'Singapore',              emoji: '🇸🇬' },
  'Asia/Bangkok':           { region: 'Southeast Asia',sub: 'Thailand',               emoji: '🇹🇭' },
  'Asia/Jakarta':           { region: 'Southeast Asia',sub: 'Indonesia (Java)',        emoji: '🇮🇩' },
  'Asia/Kuala_Lumpur':      { region: 'Southeast Asia',sub: 'Malaysia',               emoji: '🇲🇾' },
  'Asia/Manila':            { region: 'Southeast Asia',sub: 'Philippines',            emoji: '🇵🇭' },
  'Asia/Ho_Chi_Minh':       { region: 'Southeast Asia',sub: 'Vietnam',                emoji: '🇻🇳' },
  'Asia/Dubai':             { region: 'Middle East',   sub: 'UAE',                    emoji: '🇦🇪' },
  'Asia/Riyadh':            { region: 'Middle East',   sub: 'Saudi Arabia',           emoji: '🇸🇦' },
  'Asia/Tehran':            { region: 'Middle East',   sub: 'Iran',                   emoji: '🇮🇷' },
  'Asia/Jerusalem':         { region: 'Middle East',   sub: 'Israel',                 emoji: '🇮🇱' },
  'Asia/Istanbul':          { region: 'Europe / Middle East', sub: 'Turkey',          emoji: '🇹🇷' },
  // Africa
  'Africa/Cairo':           { region: 'North Africa',  sub: 'Egypt',                  emoji: '🇪🇬' },
  'Africa/Lagos':           { region: 'West Africa',   sub: 'Nigeria',                emoji: '🇳🇬' },
  'Africa/Nairobi':         { region: 'East Africa',   sub: 'Kenya',                  emoji: '🇰🇪' },
  'Africa/Johannesburg':    { region: 'Southern Africa',sub: 'South Africa',          emoji: '🇿🇦' },
  'Africa/Casablanca':      { region: 'North Africa',  sub: 'Morocco',                emoji: '🇲🇦' },
  // Pacific / Oceania
  'Australia/Sydney':       { region: 'Oceania',       sub: 'Eastern Australia',      emoji: '🇦🇺' },
  'Australia/Melbourne':    { region: 'Oceania',       sub: 'Victoria, Australia',    emoji: '🇦🇺' },
  'Australia/Perth':        { region: 'Oceania',       sub: 'Western Australia',      emoji: '🇦🇺' },
  'Pacific/Auckland':       { region: 'Oceania',       sub: 'New Zealand',            emoji: '🇳🇿' },
};

// UTC offset → approximate region (fallback when no IANA tz)
const UTC_OFFSET_REGION: Record<string, { region: string; candidates: string[] }> = {
  '-12': { region: 'Pacific (Far East)',    candidates: ['Baker Island (US)'] },
  '-11': { region: 'Pacific',              candidates: ['American Samoa', 'Niue'] },
  '-10': { region: 'Pacific / Hawaii',     candidates: ['Hawaii (USA)', 'Tahiti'] },
  '-9':  { region: 'North America',        candidates: ['Alaska (USA)'] },
  '-8':  { region: 'North America',        candidates: ['Pacific USA/Canada', 'Baja California (MX)'] },
  '-7':  { region: 'North America',        candidates: ['Mountain USA/Canada', 'Arizona (USA)'] },
  '-6':  { region: 'North America',        candidates: ['Central USA/Canada', 'Mexico City'] },
  '-5':  { region: 'North America',        candidates: ['Eastern USA/Canada', 'Colombia', 'Peru'] },
  '-4':  { region: 'Americas',             candidates: ['Atlantic Canada', 'Venezuela', 'Bolivia', 'Chile'] },
  '-3':  { region: 'South America',        candidates: ['Brazil', 'Argentina', 'Uruguay'] },
  '-2':  { region: 'South Atlantic',       candidates: ['South Georgia', 'Brazil DST zone'] },
  '-1':  { region: 'Atlantic',             candidates: ['Azores', 'Cape Verde'] },
  '+0':  { region: 'Western Europe / Africa', candidates: ['UK', 'Ireland', 'Portugal', 'Ghana', 'Iceland'] },
  '+1':  { region: 'Central Europe / West Africa', candidates: ['France', 'Germany', 'Nigeria', 'Morocco'] },
  '+2':  { region: 'Eastern Europe / South Africa', candidates: ['Romania', 'Ukraine', 'South Africa', 'Egypt'] },
  '+3':  { region: 'Eastern Europe / East Africa', candidates: ['Russia (Moscow)', 'Kenya', 'Saudi Arabia'] },
  '+4':  { region: 'Middle East / Central Asia', candidates: ['UAE', 'Oman', 'Azerbaijan'] },
  '+5':  { region: 'Central Asia / South Asia', candidates: ['Pakistan', 'Uzbekistan'] },
  '+5.5':{ region: 'South Asia',           candidates: ['India', 'Sri Lanka'] },
  '+5:30':{ region: 'South Asia',          candidates: ['India', 'Sri Lanka'] },
  '+6':  { region: 'South / Central Asia', candidates: ['Bangladesh', 'Kazakhstan'] },
  '+7':  { region: 'Southeast Asia',       candidates: ['Thailand', 'Vietnam', 'Indonesia (WIB)'] },
  '+8':  { region: 'East / Southeast Asia',candidates: ['China', 'Singapore', 'Philippines', 'Australia (WA)'] },
  '+9':  { region: 'East Asia',            candidates: ['Japan', 'South Korea'] },
  '+9.5':{ region: 'Oceania',              candidates: ['Australia (ACT)'] },
  '+10': { region: 'Oceania / East Asia',  candidates: ['Australia (AEST)', 'Papua New Guinea'] },
  '+11': { region: 'Pacific',              candidates: ['Solomon Islands', 'Vanuatu'] },
  '+12': { region: 'Pacific',              candidates: ['New Zealand', 'Fiji'] },
};

// Device make → likely region
const MAKE_REGION_HINTS: Record<string, { region: string; emoji: string }> = {
  apple:    { region: 'Global (US HQ)', emoji: '🇺🇸' },
  samsung:  { region: 'East Asia (South Korea)', emoji: '🇰🇷' },
  huawei:   { region: 'East Asia (China)', emoji: '🇨🇳' },
  xiaomi:   { region: 'East Asia (China)', emoji: '🇨🇳' },
  oppo:     { region: 'East Asia (China)', emoji: '🇨🇳' },
  vivo:     { region: 'East Asia (China)', emoji: '🇨🇳' },
  oneplus:  { region: 'East Asia (China)', emoji: '🇨🇳' },
  realme:   { region: 'South / East Asia', emoji: '🇮🇳' },
  nokia:    { region: 'Europe (Finland)', emoji: '🇫🇮' },
  sony:     { region: 'East Asia (Japan)', emoji: '🇯🇵' },
  canon:    { region: 'East Asia (Japan)', emoji: '🇯🇵' },
  nikon:    { region: 'East Asia (Japan)', emoji: '🇯🇵' },
  fujifilm: { region: 'East Asia (Japan)', emoji: '🇯🇵' },
  panasonic:{ region: 'East Asia (Japan)', emoji: '🇯🇵' },
  olympus:  { region: 'East Asia (Japan)', emoji: '🇯🇵' },
  google:   { region: 'Global (US HQ)', emoji: '🇺🇸' },
  motorola: { region: 'North America (US)', emoji: '🇺🇸' },
  lg:       { region: 'East Asia (South Korea)', emoji: '🇰🇷' },
};

// Language code → info
const LANG_INFO: Record<string, { name: string; regions: string[]; script: string; rtl: boolean }> = {
  en: { name: 'English',    regions: ['USA','UK','Australia','Canada','India'], script: 'Latin', rtl: false },
  'en-US': { name: 'English (US)', regions: ['USA'],  script: 'Latin', rtl: false },
  'en-GB': { name: 'English (UK)', regions: ['UK'],   script: 'Latin', rtl: false },
  'en-AU': { name: 'English (Australia)', regions: ['Australia'], script: 'Latin', rtl: false },
  'en-IN': { name: 'English (India)', regions: ['India'], script: 'Latin', rtl: false },
  fr: { name: 'French',     regions: ['France','Belgium','Canada','Switzerland'], script: 'Latin', rtl: false },
  de: { name: 'German',     regions: ['Germany','Austria','Switzerland'], script: 'Latin', rtl: false },
  es: { name: 'Spanish',    regions: ['Spain','Latin America'], script: 'Latin', rtl: false },
  pt: { name: 'Portuguese', regions: ['Brazil','Portugal'], script: 'Latin', rtl: false },
  'pt-BR': { name: 'Portuguese (Brazil)', regions: ['Brazil'], script: 'Latin', rtl: false },
  it: { name: 'Italian',    regions: ['Italy'], script: 'Latin', rtl: false },
  nl: { name: 'Dutch',      regions: ['Netherlands','Belgium'], script: 'Latin', rtl: false },
  ru: { name: 'Russian',    regions: ['Russia','Eastern Europe'], script: 'Cyrillic', rtl: false },
  uk: { name: 'Ukrainian',  regions: ['Ukraine'], script: 'Cyrillic', rtl: false },
  pl: { name: 'Polish',     regions: ['Poland'], script: 'Latin', rtl: false },
  zh: { name: 'Chinese',    regions: ['China','Taiwan','Hong Kong'], script: 'CJK', rtl: false },
  'zh-CN': { name: 'Chinese Simplified', regions: ['China'], script: 'CJK', rtl: false },
  'zh-TW': { name: 'Chinese Traditional', regions: ['Taiwan','Hong Kong'], script: 'CJK', rtl: false },
  ja: { name: 'Japanese',   regions: ['Japan'], script: 'CJK/Kana', rtl: false },
  ko: { name: 'Korean',     regions: ['South Korea'], script: 'Hangul', rtl: false },
  ar: { name: 'Arabic',     regions: ['Middle East','North Africa'], script: 'Arabic', rtl: true },
  he: { name: 'Hebrew',     regions: ['Israel'], script: 'Hebrew', rtl: true },
  fa: { name: 'Persian',    regions: ['Iran','Afghanistan'], script: 'Arabic', rtl: true },
  hi: { name: 'Hindi',      regions: ['India'], script: 'Devanagari', rtl: false },
  bn: { name: 'Bengali',    regions: ['Bangladesh','India (West Bengal)'], script: 'Bengali', rtl: false },
  tr: { name: 'Turkish',    regions: ['Turkey'], script: 'Latin', rtl: false },
  vi: { name: 'Vietnamese', regions: ['Vietnam'], script: 'Latin', rtl: false },
  th: { name: 'Thai',       regions: ['Thailand'], script: 'Thai', rtl: false },
  id: { name: 'Indonesian', regions: ['Indonesia'], script: 'Latin', rtl: false },
  ms: { name: 'Malay',      regions: ['Malaysia','Singapore'], script: 'Latin', rtl: false },
  sv: { name: 'Swedish',    regions: ['Sweden'], script: 'Latin', rtl: false },
  no: { name: 'Norwegian',  regions: ['Norway'], script: 'Latin', rtl: false },
  da: { name: 'Danish',     regions: ['Denmark'], script: 'Latin', rtl: false },
  fi: { name: 'Finnish',    regions: ['Finland'], script: 'Latin', rtl: false },
};

// ── Helper functions ─────────────────────────────────────────────────────────

function classifyDeviceCategory(make: string | null, model: string | null, os: string | null): DeviceProfile['category'] {
  const combined = `${make ?? ''} ${model ?? ''} ${os ?? ''}`.toLowerCase();
  if (/iphone|android|pixel|galaxy\s+[as]|oneplus|xiaomi|oppo|vivo|redmi|realme|nokia|moto[g e]/.test(combined)) return 'smartphone';
  if (/ipad|tablet|tab\s+[a-z0-9]/.test(combined)) return 'tablet';
  if (/eos|d[0-9]{3}|z[0-9]|α|alpha|ilce|a[0-9]{4}|x-t|x-pro|gh[0-9]|mirrorless|dslr|fuji|olympus/.test(combined)) return 'dslr_mirrorless';
  if (/macbook|laptop|thinkpad|xps|surface|windows|linux|macos/.test(combined)) return 'laptop_desktop';
  return 'unknown';
}

function extractMake(device: string | null): string | null {
  if (!device) return null;
  const parts = device.trim().split(/\s+/);
  return parts[0] ? parts[0].toLowerCase() : null;
}

function inferOsEcosystem(n: NormalizedMetadata): { os: OsEcosystem | null; confidence: 'high' | 'moderate' | 'low' | 'none'; sources: string[] } {
  const sources: string[] = [];
  const dev = n.device_data;
  const sw = n.software_data;
  const make = extractMake(dev.device);

  // Highest confidence: explicit OS field
  if (dev.operatingSystem) {
    const osLower = dev.operatingSystem.toLowerCase();
    let os: OsEcosystem = 'Unknown';
    if (/ios|iphone\s*os/.test(osLower)) os = 'Apple iOS / iPadOS';
    else if (/ipad/.test(osLower)) os = 'Apple iOS / iPadOS';
    else if (/macos|mac\s*os/.test(osLower)) os = 'Apple macOS';
    else if (/android/.test(osLower)) os = 'Android';
    else if (/windows/.test(osLower)) os = 'Windows';
    else if (/linux|ubuntu|debian/.test(osLower)) os = 'Linux';
    else if (/chromeos/.test(osLower)) os = 'ChromeOS';
    sources.push(`OS field: "${dev.operatingSystem}"`);
    return { os, confidence: 'high', sources };
  }

  // Software vendor implies OS
  if (sw.vendors.includes('Apple') && !sw.vendors.includes('Microsoft')) {
    sources.push('Apple software stack detected');
    // Distinguish macOS vs iOS by device
    if (make === 'apple' && dev.device?.toLowerCase().includes('iphone')) {
      return { os: 'Apple iOS / iPadOS', confidence: 'high', sources };
    }
    return { os: 'Apple macOS', confidence: 'moderate', sources };
  }
  if (sw.vendors.includes('Microsoft') && !sw.vendors.includes('Apple')) {
    sources.push('Microsoft software stack detected');
    return { os: 'Windows', confidence: 'moderate', sources };
  }

  // Camera make implies mobile OS
  if (make) {
    if (['apple'].includes(make)) {
      sources.push(`Device make "${make}" → Apple ecosystem`);
      return { os: 'Apple iOS / iPadOS', confidence: 'high', sources };
    }
    if (['samsung', 'google', 'huawei', 'xiaomi', 'oneplus', 'oppo', 'vivo'].includes(make)) {
      sources.push(`Device make "${make}" → Android ecosystem`);
      return { os: 'Android', confidence: 'high', sources };
    }
    if (['canon', 'nikon', 'sony', 'fujifilm', 'panasonic', 'olympus'].includes(make)) {
      sources.push(`Camera make "${make}" → dedicated camera (embedded firmware)`);
      return { os: 'Unknown', confidence: 'low', sources };
    }
  }

  return { os: null, confidence: 'none', sources };
}

function inferRegionalProfile(n: NormalizedMetadata): RegionalProfile {
  const tl = n.timeline_data;
  const tz = tl.embeddedTimezone ?? null;

  // UTC offset from timezone string e.g. "+05:30" or "-08:00"
  let utcOffset: string | null = null;
  let likelyRegion: string | null = null;

  if (tz) {
    // Try IANA lookup first
    const tzEntry = TZ_REGION_MAP[tz];
    if (tzEntry) {
      likelyRegion = `${tzEntry.sub}, ${tzEntry.region}`;
    }
    // Try to extract UTC offset pattern
    const offsetMatch = tz.match(/([+-]\d{1,2}):?(\d{2})?/);
    if (offsetMatch) {
      const h = parseInt(offsetMatch[1]);
      const m = offsetMatch[2] ? parseInt(offsetMatch[2]) : 0;
      utcOffset = `UTC${h >= 0 ? '+' : ''}${h}:${m.toString().padStart(2, '0')}`;
      if (!likelyRegion) {
        const key = m > 0 ? `${h}.${m}` : `${h >= 0 ? '+' : ''}${h}`;
        const utcEntry = UTC_OFFSET_REGION[key] ?? UTC_OFFSET_REGION[String(h)];
        if (utcEntry) likelyRegion = utcEntry.region;
      }
    }
  }

  // Date format hint from software strings
  let dateFormatHint: RegionalProfile['dateFormatHint'] = 'unknown';
  const swStr = (n.software_data.allSoftwareStrings.join(' ') + ' ' + (n.device_data.operatingSystem ?? '')).toLowerCase();
  if (/united states|us locale|en-us|en_us/.test(swStr)) dateFormatHint = 'MDY';
  else if (/en-gb|uk locale|europe|fr-|de-|es-|pt-br/.test(swStr)) dateFormatHint = 'DMY';
  else if (/japan|zh-cn|ko-|iso\s*8601/.test(swStr)) dateFormatHint = 'YMD';

  return {
    detectedTimezone: tz,
    timezoneUtcOffset: utcOffset,
    likelyRegionFromTimezone: likelyRegion,
    embeddedLocale: null, // could be expanded from richer EXIF
    dateFormatHint,
    currencySymbolDetected: null,
    numberFormatHint: 'unknown',
  };
}

function inferLanguageFingerprint(n: NormalizedMetadata): LanguageFingerprint {
  const allText = JSON.stringify(n).toLowerCase();
  const detected: string[] = [];
  const sources: string[] = [];
  const clues: string[] = [];

  // Scan for language codes in software/metadata strings
  const langCodeRe = /\b([a-z]{2})[-_]([A-Z]{2})\b/g;
  const matches = [...allText.matchAll(langCodeRe)];
  for (const m of matches) {
    const code = `${m[1]}-${m[2].toUpperCase()}`;
    const base = m[1];
    if (LANG_INFO[code]) { detected.push(code); sources.push(`locale code "${code}" found in metadata`); }
    else if (LANG_INFO[base]) { detected.push(base); sources.push(`language code "${base}" found in metadata`); }
  }

  // Software-string keyword hints
  const softCombined = n.software_data.allSoftwareStrings.join(' ');
  if (/microsoft\s+word|office/.test(softCombined.toLowerCase())) {
    clues.push('Microsoft Office suite detected — commonly used in corporate/English-speaking environments');
  }
  if (/iwork|pages|keynote|numbers/.test(softCombined.toLowerCase())) {
    clues.push('Apple iWork suite detected — macOS/iOS ecosystem');
  }
  if (/wps/.test(softCombined.toLowerCase())) {
    clues.push('WPS Office detected — popular in China and South/Southeast Asia');
    if (!detected.includes('zh')) detected.push('zh');
    sources.push('WPS Office software string (common in CJK markets)');
  }

  // Author name script detection
  const authorStr = n.identity_data.author ?? '';
  let scriptDetected: string | null = null;
  let rtlScript = false;
  if (/[\u0400-\u04FF]/.test(authorStr)) { scriptDetected = 'Cyrillic'; clues.push('Cyrillic characters in author name → Russian/Eastern European origin likely'); }
  else if (/[\u0600-\u06FF]/.test(authorStr)) { scriptDetected = 'Arabic'; rtlScript = true; clues.push('Arabic/RTL script in author name → Middle East / North Africa origin likely'); }
  else if (/[\u4E00-\u9FFF]/.test(authorStr)) { scriptDetected = 'CJK'; clues.push('CJK characters in author name → East Asian origin likely'); }
  else if (/[\u3040-\u30FF]/.test(authorStr)) { scriptDetected = 'Japanese Kana'; clues.push('Japanese Kana characters in author name → Japan origin likely'); }
  else if (/[\uAC00-\uD7A3]/.test(authorStr)) { scriptDetected = 'Hangul'; clues.push('Hangul characters in author name → South Korea origin likely'); }
  else if (/[\u0900-\u097F]/.test(authorStr)) { scriptDetected = 'Devanagari'; clues.push('Devanagari characters in author name → India/Nepal origin likely'); }
  else if (/[\u0980-\u09FF]/.test(authorStr)) { scriptDetected = 'Bengali'; clues.push('Bengali characters in author name → Bangladesh/India origin likely'); }
  else if (/[a-zA-Z]/.test(authorStr) && authorStr.length > 1) { scriptDetected = 'Latin'; }

  const uniqueDetected = [...new Set(detected)];
  const primaryLanguage = uniqueDetected[0]
    ? (LANG_INFO[uniqueDetected[0]]?.name ?? uniqueDetected[0])
    : null;

  return {
    detectedLanguages: uniqueDetected,
    primaryLanguage,
    languageSource: sources,
    scriptDetected,
    rtlScript,
    languageClues: clues,
  };
}

function buildOriginEstimate(
  gps: GpsCoordinates | null,
  device: DeviceProfile,
  regional: RegionalProfile,
  lang: LanguageFingerprint,
  n: NormalizedMetadata,
): OriginEstimate {
  const reasoning: string[] = [];
  const caveats: string[] = [];

  // ── Case 1: GPS available ──────────────────────────────────────────────────
  if (gps && gps.suspicion === 'none') {
    reasoning.push(`Exact GPS coordinates embedded: ${gps.latitude.toFixed(5)}, ${gps.longitude.toFixed(5)}`);
    reasoning.push(`GPS altitude: ${gps.altitudeMetres !== null ? gps.altitudeMetres + ' m' : 'not available'}`);
    // Rough continent/region from lat/lon
    const lat = gps.latitude;
    const lon = gps.longitude;
    let region = 'Unknown';
    let sub: string | null = null;
    let emoji = '🌍';
    if (lat > 24 && lat < 50 && lon > -125 && lon < -65) { region = 'North America'; sub = 'Continental USA/Canada'; emoji = '🇺🇸'; }
    else if (lat > 50 && lat < 70 && lon > -130 && lon < -55) { region = 'North America'; sub = 'Northern Canada / Alaska'; emoji = '🇨🇦'; }
    else if (lat > 15 && lat < 32 && lon > -117 && lon < -86) { region = 'North America'; sub = 'Mexico / Central America'; emoji = '🇲🇽'; }
    else if (lat > -55 && lat < 15 && lon > -82 && lon < -34) { region = 'South America'; sub = null; emoji = '🇧🇷'; }
    else if (lat > 34 && lat < 72 && lon > -10 && lon < 40) { region = 'Europe'; sub = null; emoji = '🇪🇺'; }
    else if (lat > 45 && lat < 82 && lon > 40 && lon < 180) { region = 'Russia / Central Asia'; sub = null; emoji = '🇷🇺'; }
    else if (lat > 5 && lat < 38 && lon > 26 && lon < 63) { region = 'Middle East'; sub = null; emoji = '🌙'; }
    else if (lat > 5 && lat < 38 && lon > -20 && lon < 55) { region = 'Africa / North Africa'; sub = null; emoji = '🌍'; }
    else if (lat > -35 && lat < 38 && lon > 55 && lon < 180) {
      if (lat > 20 && lat < 40 && lon > 70 && lon < 145) { region = 'East / South Asia'; sub = null; emoji = '🌏'; }
      else if (lat > -12 && lat < 22 && lon > 90 && lon < 145) { region = 'Southeast Asia'; sub = null; emoji = '🌏'; }
      else { region = 'Asia'; sub = null; emoji = '🌏'; }
    }
    else if (lat > -50 && lat < -10 && lon > 110 && lon < 180) { region = 'Oceania'; sub = 'Australia / New Zealand'; emoji = '🇦🇺'; }
    reasoning.push(`Coordinates map to: ${region}${sub ? ' — ' + sub : ''}`);
    return { region, subRegion: sub, confidence: 'exact', inferenceMethod: 'gps_exact', reasoning, caveats, regionEmoji: emoji };
  }

  // ── Case 2: No GPS — infer from other signals ─────────────────────────────
  let region = 'Unknown';
  let subRegion: string | null = null;
  let emoji = '🌍';
  let confidence: RegionConfidence = 'unknown';
  let method: OriginEstimate['inferenceMethod'] = 'none';
  let score = 0;

  // Timezone signal (strong)
  if (regional.detectedTimezone) {
    const tzEntry = TZ_REGION_MAP[regional.detectedTimezone];
    if (tzEntry) {
      region = tzEntry.region;
      subRegion = tzEntry.sub;
      emoji = tzEntry.emoji;
      score += 40;
      method = 'timezone';
      reasoning.push(`Timezone "${regional.detectedTimezone}" → ${tzEntry.sub} (${tzEntry.region})`);
    } else if (regional.likelyRegionFromTimezone) {
      region = regional.likelyRegionFromTimezone;
      score += 25;
      method = 'timezone';
      reasoning.push(`UTC offset "${regional.timezoneUtcOffset}" maps to: ${regional.likelyRegionFromTimezone}`);
    }
  } else {
    caveats.push('No timezone information embedded — timezone-based inference skipped');
  }

  // Language signal
  if (lang.primaryLanguage) {
    const langCode = lang.detectedLanguages[0];
    const info = langCode ? LANG_INFO[langCode] : null;
    if (info) {
      score += 20;
      if (method === 'none') { method = 'language'; region = info.regions[0]; }
      else method = 'combined';
      reasoning.push(`Language "${info.name}" detected → typical regions: ${info.regions.join(', ')}`);
    }
  }
  if (lang.scriptDetected && lang.scriptDetected !== 'Latin') {
    score += 15;
    method = method === 'none' ? 'language' : 'combined';
    reasoning.push(`Script "${lang.scriptDetected}" detected in metadata → narrows geographic origin`);
  }
  for (const clue of lang.languageClues) {
    reasoning.push(`Language clue: ${clue}`);
  }

  // Device make signal (weak but useful)
  const make = extractMake(device.fullDeviceString);
  if (make) {
    const makeHint = MAKE_REGION_HINTS[make];
    if (makeHint && method === 'none') {
      method = 'device_make';
      region = makeHint.region;
      emoji = makeHint.emoji;
      score += 10;
      reasoning.push(`Device make "${make}" → manufactured/popular in: ${makeHint.region}`);
      caveats.push('Device make is a weak geographic signal — devices are sold globally');
    } else if (makeHint) {
      score += 5;
      reasoning.push(`Device make "${make}" corroborates ${makeHint.region} origin`);
    }
  }

  // OS ecosystem signal
  if (device.osEcosystem === 'Android') {
    reasoning.push('Android ecosystem — prevalent across Asia, Europe, and Global South');
  } else if (device.osEcosystem === 'Apple iOS / iPadOS' || device.osEcosystem === 'Apple macOS') {
    reasoning.push('Apple ecosystem — higher market share in USA, Western Europe, Japan, Australia');
  } else if (device.osEcosystem === 'Windows') {
    reasoning.push('Windows ecosystem — near-universal OS, no strong geographic signal');
  }

  // Derive confidence from score
  if (score >= 55) confidence = 'high';
  else if (score >= 35) confidence = 'moderate';
  else if (score >= 15) confidence = 'low';
  else {
    caveats.push('Insufficient metadata signals to estimate geographic origin');
    reasoning.push('No GPS, timezone, language, or device signals strong enough to determine origin');
  }

  if (method === 'none') caveats.push('Origin could not be determined from available metadata');

  return { region, subRegion, confidence, inferenceMethod: method, reasoning, caveats, regionEmoji: emoji };
}

// ── OSINT Leads ──────────────────────────────────────────────────────────────

function buildOsintLeads(gps: GpsCoordinates | null, origin: OriginEstimate, device: DeviceProfile): string[] {
  const leads: string[] = [];
  if (gps) {
    leads.push(`Reverse-geocode GPS (${gps.latitude.toFixed(5)}, ${gps.longitude.toFixed(5)}) on Google Maps, OpenStreetMap`);
    leads.push(`Check Google Street View at this location for visual corroboration`);
    leads.push(`Cross-reference GPS timestamp with known events or weather data at coordinates`);
  }
  if (device.make) {
    leads.push(`Look up device model "${device.fullDeviceString}" in IMEI databases for carrier/region info`);
  }
  if (origin.subRegion) {
    leads.push(`Correlate file timestamps with ${origin.subRegion} timezone to detect daylight-saving anomalies`);
  }
  if (origin.confidence !== 'unknown' && origin.confidence !== 'exact') {
    leads.push(`Cross-reference inferred region "${origin.region}" against IP geolocation if network metadata is available`);
  }
  return leads;
}

// ── Master Function ──────────────────────────────────────────────────────────

export function analyzeGeoDevice(n: NormalizedMetadata): GeoDeviceReport {
  // GPS
  const loc = n.location_data;
  let gps: GpsCoordinates | null = null;
  if (loc.latitude !== null && loc.longitude !== null) {
    gps = {
      latitude: loc.latitude,
      longitude: loc.longitude,
      altitudeMetres: loc.altitudeMetres,
      googleMapsUrl: loc.googleMapsUrl!,
      precision: loc.precisionEstimateMetres ?? '~1–5 m (consumer GPS)',
      suspicion: loc.coordinateSuspicion,
    };
  }

  // Device
  const dev = n.device_data;
  const make = extractMake(dev.device);
  const osResult = inferOsEcosystem(n);

  let deviceBrand: string | null = null;
  if (make) {
    for (const key of Object.keys(MAKE_REGION_HINTS)) {
      if (make.includes(key)) { deviceBrand = key.charAt(0).toUpperCase() + key.slice(1); break; }
    }
  }

  const deviceProfile: DeviceProfile = {
    make: dev.device ? dev.device.split(' ')[0] : null,
    model: dev.device ? dev.device.split(' ').slice(1).join(' ') || null : null,
    fullDeviceString: dev.device,
    category: classifyDeviceCategory(dev.device, null, dev.operatingSystem),
    brand: deviceBrand,
    osEcosystem: osResult.os,
  };

  // Regional & Language
  const regional = inferRegionalProfile(n);
  const lang = inferLanguageFingerprint(n);

  // Origin
  const origin = buildOriginEstimate(gps, deviceProfile, regional, lang, n);
  const osintLeads = buildOsintLeads(gps, origin, deviceProfile);

  return {
    analyzedAt: new Date().toISOString(),
    fileName: n.fileName,
    gpsCoordinates: gps,
    gpsAvailable: gps !== null,
    deviceProfile,
    osEcosystem: osResult.os,
    osConfidence: osResult.confidence,
    osEvidenceSources: osResult.sources,
    regionalProfile: regional,
    languageFingerprint: lang,
    originEstimate: origin,
    osintLeads,
  };
}
