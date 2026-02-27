/**
 * IP Geolocation Service
 * ─────────────────────
 * Live geolocation of IP addresses using ip-api.com (free tier, no key needed).
 * 45 requests/minute limit. Results are cached in-memory for the session.
 *
 * Returns: country, city, ISP, org, ASN, lat/lon, timezone, proxy/VPN detection.
 */

export interface IPGeoResult {
    ip: string;
    status: 'success' | 'fail';
    // Location
    country: string;
    countryCode: string;
    region: string;
    regionName: string;
    city: string;
    zip: string;
    lat: number;
    lon: number;
    timezone: string;
    // Network
    isp: string;
    org: string;
    as: string;       // ASN string, e.g. "AS15169 Google LLC"
    asname: string;
    // Classification
    mobile: boolean;
    proxy: boolean;
    hosting: boolean;  // datacenter / hosting IP
    // Error
    message?: string;
}

// In-memory cache for the session
const _cache = new Map<string, IPGeoResult>();

/**
 * Geolocate a single public IP address.
 * Returns null for private/loopback IPs or on error.
 */
export async function geolocateIP(ip: string): Promise<IPGeoResult | null> {
    // Skip private / special IPs
    if (
        ip.startsWith('192.168.') ||
        ip.startsWith('10.') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
        ip.startsWith('127.') ||
        ip.startsWith('169.254.') ||
        ip === '0.0.0.0'
    ) {
        return null;
    }

    if (_cache.has(ip)) return _cache.get(ip)!;

    try {
        const res = await fetch(
            `https://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query`,
            { signal: AbortSignal.timeout(6000) }
        );
        if (!res.ok) return null;
        const data: IPGeoResult & { query: string } = await res.json();
        const result: IPGeoResult = { ...data, ip: data.query ?? ip };
        _cache.set(ip, result);
        return result;
    } catch {
        return null;
    }
}

/**
 * Geolocate multiple IPs in parallel (batched to 5 at a time to respect rate limits).
 */
export async function geolocateIPs(ips: string[]): Promise<Map<string, IPGeoResult>> {
    const results = new Map<string, IPGeoResult>();
    const publicIPs = ips.filter(ip =>
        !ip.startsWith('192.168.') &&
        !ip.startsWith('10.') &&
        !/^172\.(1[6-9]|2\d|3[01])\./.test(ip) &&
        !ip.startsWith('127.') &&
        !ip.startsWith('169.254.') &&
        ip !== '0.0.0.0'
    );

    // Batch 5 at a time
    for (let i = 0; i < publicIPs.length; i += 5) {
        const batch = publicIPs.slice(i, i + 5);
        const resolved = await Promise.allSettled(batch.map(geolocateIP));
        resolved.forEach((r, idx) => {
            if (r.status === 'fulfilled' && r.value && r.value.status === 'success') {
                results.set(batch[idx], r.value);
            }
        });
        if (i + 5 < publicIPs.length) {
            await new Promise(r => setTimeout(r, 250)); // brief pause between batches
        }
    }
    return results;
}

/**
 * Format a geo result as a one-line summary string.
 */
export function formatGeoSummary(geo: IPGeoResult): string {
    const parts: string[] = [];
    if (geo.city) parts.push(geo.city);
    if (geo.regionName) parts.push(geo.regionName);
    if (geo.country) parts.push(geo.country);
    const loc = parts.join(', ');
    const isp = geo.org || geo.isp;
    const flags: string[] = [];
    if (geo.proxy) flags.push('VPN/Proxy');
    if (geo.hosting) flags.push('Hosting/Datacenter');
    if (geo.mobile) flags.push('Mobile');
    return [loc, isp, ...flags].filter(Boolean).join(' · ');
}
