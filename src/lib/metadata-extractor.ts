import ExifReader from 'exifreader';
import { FileMetadata } from './types';

async function computeSHA256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseExifDate(dateStr: string | undefined): Date | undefined {
  if (!dateStr) return undefined;
  const cleaned = dateStr.replace(/^(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3');
  const d = new Date(cleaned);
  return isNaN(d.getTime()) ? undefined : d;
}

async function extractExifData(file: File): Promise<Partial<FileMetadata>> {
  try {
    const buffer = await file.arrayBuffer();
    const tags = ExifReader.load(buffer, { expanded: true });
    const exif = tags.exif || {};
    const gps = tags.gps || {};
    const file_tags = tags.file || {};
    const xmp = (tags as any).xmp || {};

    const result: Partial<FileMetadata> = {
      exifData: { ...exif, ...gps, ...xmp },
    };

    // Creation date — prefer DateTimeOriginal > DateTimeDigitized > CreateDate (XMP)
    if (exif.DateTimeOriginal?.description) {
      result.creationDate = parseExifDate(exif.DateTimeOriginal.description);
    } else if (exif.DateTimeDigitized?.description) {
      result.creationDate = parseExifDate(exif.DateTimeDigitized.description);
    } else if (xmp?.CreateDate?.description) {
      result.creationDate = parseExifDate(xmp.CreateDate.description);
    }

    // Modification date
    if (exif.DateTime?.description) {
      result.modificationDate = parseExifDate(exif.DateTime.description);
    } else if (xmp?.ModifyDate?.description) {
      result.modificationDate = parseExifDate(xmp.ModifyDate.description);
    }

    // Software — check both EXIF and XMP
    const exifSoftware = exif.Software?.description;
    const xmpSoftware = xmp?.CreatorTool?.description;
    result.software = exifSoftware || xmpSoftware;

    // Camera device
    if (exif.Make?.description || exif.Model?.description) {
      result.device = [exif.Make?.description, exif.Model?.description].filter(Boolean).join(' ');
    }

    // Author — check EXIF Artist, XMP creator
    result.author = exif.Artist?.description || xmp?.creator?.description || xmp?.Creator?.description;

    // GPS coordinates (validated range)
    if (gps?.Latitude !== undefined && gps?.Longitude !== undefined) {
      const lat = Number(gps.Latitude);
      const lon = Number(gps.Longitude);
      if (lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180) {
        result.gpsLatitude = lat;
        result.gpsLongitude = lon;
      }
    }

    // Dimensions — prefer EXIF pixel dimensions > file tags
    const exifW = exif['PixelXDimension']?.value;
    const exifH = exif['PixelYDimension']?.value;
    const fileW = (file_tags as any)?.['Image Width']?.value;
    const fileH = (file_tags as any)?.['Image Height']?.value;

    if (exifW && exifH) {
      result.dimensions = { width: Number(exifW), height: Number(exifH) };
    } else if (fileW && fileH) {
      result.dimensions = { width: Number(fileW), height: Number(fileH) };
    }

    if (exif.ColorSpace?.description) {
      result.colorSpace = exif.ColorSpace.description;
    }

    return result;
  } catch {
    return {};
  }
}

/**
 * Extract metadata from DOCX files (they are ZIP files containing XML)
 * Reads docProps/core.xml for author, dates, etc.
 */
async function extractDocxMetadata(file: File): Promise<Partial<FileMetadata>> {
  try {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);

    // DOCX/ZIP magic bytes: PK (0x50 0x4B)
    if (bytes[0] !== 0x50 || bytes[1] !== 0x4B) return {};

    // Scan for core.xml content embedded in the ZIP
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const coreXmlMatch = text.match(/dc:creator[^>]*>([^<]+)<\/dc:creator/);
    const createdMatch = text.match(/dcterms:created[^>]*>([^<]+)<\/dcterms:created/);
    const modifiedMatch = text.match(/dcterms:modified[^>]*>([^<]+)<\/dcterms:modified/);
    const lastModByMatch = text.match(/cp:lastModifiedBy[^>]*>([^<]+)<\/cp:lastModifiedBy/);
    const revisionMatch = text.match(/cp:revision[^>]*>([^<]+)<\/cp:revision/);
    const appMatch = text.match(/AppVersion[^>]*>([^<]+)<\/AppVersion/);
    const appNameMatch = text.match(/<Application>([^<]+)<\/Application>/);

    const result: Partial<FileMetadata> = {};
    if (coreXmlMatch?.[1]) result.author = coreXmlMatch[1].trim();
    if (createdMatch?.[1]) result.creationDate = new Date(createdMatch[1].trim());
    if (modifiedMatch?.[1]) result.modificationDate = new Date(modifiedMatch[1].trim());

    // Build software string
    const parts = [appNameMatch?.[1], appMatch?.[1] ? `v${appMatch[1]}` : null].filter(Boolean);
    if (parts.length > 0) result.software = parts.join(' ');

    // If last-modified-by differs from creator — flag it
    if (lastModByMatch?.[1] && coreXmlMatch?.[1] &&
      lastModByMatch[1].trim() !== coreXmlMatch[1].trim()) {
      result.author = `${coreXmlMatch[1].trim()} (last edited by: ${lastModByMatch[1].trim()})`;
    }

    if (revisionMatch?.[1] && parseInt(revisionMatch[1]) > 50) {
      // High revision count suggests heavy editing history — captured in exifData
      result.exifData = { revisionCount: parseInt(revisionMatch[1]) };
    }

    return result;
  } catch {
    return {};
  }
}

/**
 * Extract metadata from PDF binary
 * PDFs store metadata in /Info dictionary or XMP stream
 */
async function extractPdfMetadata(file: File): Promise<Partial<FileMetadata>> {
  try {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);

    // Check PDF magic: %PDF
    if (bytes[0] !== 0x25 || bytes[1] !== 0x50 || bytes[2] !== 0x44 || bytes[3] !== 0x46) return {};

    const text = new TextDecoder('latin1').decode(bytes);

    const extract = (key: string): string | undefined => {
      const patterns = [
        new RegExp(`/${key}\\s*\\(([^)]+)\\)`, 'i'),
        new RegExp(`/${key}\\s*<([^>]+)>`, 'i'),
      ];
      for (const p of patterns) {
        const m = text.match(p);
        if (m?.[1]) {
          // Decode hex strings if needed
          const val = m[1].trim();
          if (/^[0-9a-fA-F]+$/.test(val) && val.length % 2 === 0) {
            try {
              return Buffer.from(val, 'hex').toString('utf-8').replace(/\0/g, '').trim();
            } catch { return val; }
          }
          return val.replace(/\\n/g, ' ').replace(/\\/g, '').trim();
        }
      }
      return undefined;
    };

    const parseDate = (s: string | undefined): Date | undefined => {
      if (!s) return undefined;
      // PDF date format: D:YYYYMMDDHHmmSSOHH'mm
      const m = s.match(/D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
      if (m) {
        return new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}`);
      }
      const d = new Date(s);
      return isNaN(d.getTime()) ? undefined : d;
    };

    const result: Partial<FileMetadata> = {};
    const author = extract('Author');
    const creator = extract('Creator');
    const producer = extract('Producer');
    const creationDate = extract('CreationDate');
    const modDate = extract('ModDate');
    const title = extract('Title');

    if (author) result.author = author;
    else if (creator) result.author = creator;

    if (creationDate) result.creationDate = parseDate(creationDate);
    if (modDate) result.modificationDate = parseDate(modDate);

    const swParts = [creator, producer].filter(Boolean);
    if (swParts.length) result.software = swParts.join(' / ');

    if (title) result.exifData = { ...(result.exifData || {}), title };

    return result;
  } catch {
    return {};
  }
}

export async function extractMetadata(file: File): Promise<FileMetadata> {
  const sha256Hash = await computeSHA256(file);

  const ext = file.name.split('.').pop()?.toLowerCase() || '';
  const isImage = file.type.startsWith('image/');
  const isPdf = ext === 'pdf' || file.type === 'application/pdf';
  const isDocx = ext === 'docx' || file.type.includes('wordprocessingml');
  const isVideo = file.type.startsWith('video/');

  let extracted: Partial<FileMetadata> = {};

  if (isImage) {
    extracted = await extractExifData(file);
  } else if (isPdf) {
    extracted = await extractPdfMetadata(file);
  } else if (isDocx) {
    extracted = await extractDocxMetadata(file);
  } else if (isVideo) {
    // For video, use file system dates as best approximation
    extracted = {
      software: 'Unknown Video Encoder',
    };
  }

  return {
    fileName: file.name,
    fileSize: file.size,
    fileType: ext.toUpperCase() || 'UNKNOWN',
    mimeType: file.type || 'application/octet-stream',
    lastModified: new Date(file.lastModified),
    uploadTimestamp: new Date(),
    sha256Hash,
    ...extracted,
  };
}
