/**
 * Forensic JSON Builder
 * Builds a complete structured JSON report with ALL metadata fields,
 * preserving original field names and including null for unavailable fields.
 */
import { AnalysisResult, NetworkIndicators, HiddenArtifacts } from './types';

function nullify<T>(v: T | undefined | null): T | null {
    return v !== undefined && v !== null ? v : null;
}

function dateToISO(d: Date | undefined | null): string | null {
    return d ? d.toISOString() : null;
}

/** Flatten ExifReader tag object to plain { fieldName: description | value | null } */
function flattenTags(tags: Record<string, unknown>): Record<string, unknown> {
    const flat: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(tags)) {
        if (v && typeof v === 'object') {
            const t = v as Record<string, unknown>;
            flat[k] = t['description'] ?? t['value'] ?? null;
        } else {
            flat[k] = v ?? null;
        }
    }
    return flat;
}

export function buildRawForensicJSON(result: Omit<AnalysisResult, 'rawForensicJSON'>): Record<string, unknown> {
    const m = result.metadata;
    const net = result.networkIndicators;
    const art = result.hiddenArtifacts;
    const fa = result.forensicAssessment;

    const rawExif = m.exifData ? flattenTags(m.exifData as Record<string, unknown>) : {};

    return {
        forensic_report_version: "2.0",
        generated_at: new Date().toISOString(),
        engine: "Metadata Forensic Suite — Deep Forensic Inspector v2.0",

        // ── File Info ──────────────────────────────────────────────────────
        file_info: {
            file_name: m.fileName,
            file_type: m.fileType,
            mime_type: m.mimeType,
            file_size_bytes: m.fileSize,
            file_size_readable: `${(m.fileSize / 1024).toFixed(2)} KB`,
            last_modified_fs: dateToISO(m.lastModified),
            upload_timestamp: dateToISO(m.uploadTimestamp),
            analyzed_at: result.analyzedAt.toISOString(),
        },

        // ── Hash Verification ──────────────────────────────────────────────
        hash_verification: {
            sha256: m.sha256Hash,
            md5: null,   // not computed client-side (unavailable)
            sha1: null,   // not computed client-side (unavailable)
        },

        // ── EXIF Metadata (complete raw dump) ─────────────────────────────
        exif: {
            // Core camera/image EXIF
            Make: rawExif['Make'] ?? null,
            Model: rawExif['Model'] ?? null,
            Software: rawExif['Software'] ?? null,
            Artist: rawExif['Artist'] ?? null,
            Copyright: rawExif['Copyright'] ?? null,
            ImageDescription: rawExif['ImageDescription'] ?? null,
            UserComment: rawExif['UserComment'] ?? null,
            DateTime: rawExif['DateTime'] ?? null,
            DateTimeOriginal: rawExif['DateTimeOriginal'] ?? null,
            DateTimeDigitized: rawExif['DateTimeDigitized'] ?? null,
            SubSecTime: rawExif['SubSecTime'] ?? null,
            SubSecTimeOriginal: rawExif['SubSecTimeOriginal'] ?? null,
            OffsetTime: rawExif['OffsetTime'] ?? null,
            OffsetTimeOriginal: rawExif['OffsetTimeOriginal'] ?? null,
            ExifVersion: rawExif['ExifVersion'] ?? null,
            FlashPixVersion: rawExif['FlashPixVersion'] ?? null,
            ColorSpace: rawExif['ColorSpace'] ?? null,
            PixelXDimension: rawExif['PixelXDimension'] ?? null,
            PixelYDimension: rawExif['PixelYDimension'] ?? null,
            Orientation: rawExif['Orientation'] ?? null,
            XResolution: rawExif['XResolution'] ?? null,
            YResolution: rawExif['YResolution'] ?? null,
            ResolutionUnit: rawExif['ResolutionUnit'] ?? null,
            BitsPerSample: rawExif['BitsPerSample'] ?? null,
            Compression: rawExif['Compression'] ?? null,
            PhotometricInterpretation: rawExif['PhotometricInterpretation'] ?? null,
            SamplesPerPixel: rawExif['SamplesPerPixel'] ?? null,
            // Camera settings
            ExposureTime: rawExif['ExposureTime'] ?? null,
            FNumber: rawExif['FNumber'] ?? null,
            ExposureProgram: rawExif['ExposureProgram'] ?? null,
            ISO: rawExif['ISOSpeedRatings'] ?? rawExif['ISO'] ?? null,
            ShutterSpeedValue: rawExif['ShutterSpeedValue'] ?? null,
            ApertureValue: rawExif['ApertureValue'] ?? null,
            BrightnessValue: rawExif['BrightnessValue'] ?? null,
            ExposureBiasValue: rawExif['ExposureBiasValue'] ?? null,
            MaxApertureValue: rawExif['MaxApertureValue'] ?? null,
            MeteringMode: rawExif['MeteringMode'] ?? null,
            Flash: rawExif['Flash'] ?? null,
            FocalLength: rawExif['FocalLength'] ?? null,
            FocalLengthIn35mmFilm: rawExif['FocalLengthIn35mmFilm'] ?? null,
            WhiteBalance: rawExif['WhiteBalance'] ?? null,
            DigitalZoomRatio: rawExif['DigitalZoomRatio'] ?? null,
            SceneCaptureType: rawExif['SceneCaptureType'] ?? null,
            LensModel: rawExif['LensModel'] ?? null,
            LensMake: rawExif['LensMake'] ?? null,
            // Thumbnail
            ThumbnailLength: rawExif['ThumbnailLength'] ?? null,
            ThumbnailOffset: rawExif['ThumbnailOffset'] ?? null,
            // All other raw fields
            _all_raw_fields: rawExif,
        },

        // ── XMP Metadata ─────────────────────────────────────────────────
        xmp: {
            CreatorTool: rawExif['CreatorTool'] ?? null,
            CreateDate: rawExif['CreateDate'] ?? null,
            ModifyDate: rawExif['ModifyDate'] ?? null,
            MetadataDate: rawExif['MetadataDate'] ?? null,
            Rating: rawExif['Rating'] ?? null,
            Label: rawExif['Label'] ?? null,
            DocumentID: rawExif['DocumentID'] ?? null,
            OriginalDocumentID: rawExif['OriginalDocumentID'] ?? null,
            InstanceID: rawExif['InstanceID'] ?? null,
            Format: rawExif['Format'] ?? null,
            Lens: rawExif['Lens'] ?? null,
            SerialNumber: rawExif['SerialNumber'] ?? null,
            RawFileName: rawExif['RawFileName'] ?? null,
            // DerivedFrom (tracks original file path)
            DerivedFrom: rawExif['DerivedFrom'] ?? null,
            // Photoshop-specific
            'photoshop:DateCreated': rawExif['DateCreated'] ?? null,
            'photoshop:City': rawExif['City'] ?? null,
            'photoshop:Country': rawExif['Country'] ?? null,
            'photoshop:Credit': rawExif['Credit'] ?? null,
            'photoshop:Source': rawExif['Source'] ?? null,
            'photoshop:Category': rawExif['Category'] ?? null,
            'photoshop:Instructions': rawExif['Instructions'] ?? null,
            'photoshop:AuthorsPosition': rawExif['AuthorsPosition'] ?? null,
        },

        // ── IPTC Metadata ─────────────────────────────────────────────────
        iptc: {
            'By-line': rawExif['By-line'] ?? null,
            'By-lineTitle': rawExif['By-lineTitle'] ?? null,
            Byline: rawExif['Byline'] ?? null,
            BylineTitle: rawExif['BylineTitle'] ?? null,
            Caption: rawExif['Caption'] ?? rawExif['Caption-Abstract'] ?? null,
            CaptionAbstract: rawExif['Caption-Abstract'] ?? null,
            Credit: rawExif['Credit'] ?? null,
            DateCreated: rawExif['DateCreated'] ?? null,
            TimeCreated: rawExif['TimeCreated'] ?? null,
            City: rawExif['City'] ?? null,
            Province: rawExif['Province-State'] ?? null,
            Country: rawExif['Country-PrimaryLocationName'] ?? rawExif['Country'] ?? null,
            CountryCode: rawExif['Country-PrimaryLocationCode'] ?? null,
            Headline: rawExif['Headline'] ?? null,
            Keywords: rawExif['Keywords'] ?? null,
            ObjectName: rawExif['ObjectName'] ?? null,
            Source: rawExif['Source'] ?? null,
            SpecialInstructions: rawExif['Special Instructions'] ?? null,
            Writer: rawExif['Writer-Editor'] ?? null,
            CopyrightNotice: rawExif['Copyright Notice'] ?? rawExif['Copyright'] ?? null,
            Category: rawExif['Category'] ?? null,
            SubjectReference: rawExif['Subject Reference'] ?? null,
            SupplementalCategories: rawExif['Supplemental Category'] ?? null,
        },

        // ── Document Properties ───────────────────────────────────────────
        document_properties: {
            author: nullify(m.author),
            creator: nullify(m.creator),
            last_modified_by: nullify(m.lastModifiedBy),
            organization: nullify(m.organization),
            device_owner: nullify(m.deviceOwner),
            title: nullify((m.exifData as any)?.title) ?? null,
            subject: nullify((m.exifData as any)?.subject) ?? null,
            description: nullify((m.exifData as any)?.description) ?? null,
            keywords: nullify((m.exifData as any)?.keywords) ?? null,
            revision_count: art.revisionCount > 0 ? art.revisionCount : null,
        },

        // ── Software Signatures ───────────────────────────────────────────
        software_signatures: {
            primary_software: nullify(m.software),
            software_version: nullify(m.softwareVersion ?? m.appVersion),
            operating_system: nullify(m.operatingSystem),
            device_model: nullify(m.device),
            exif_version: rawExif['ExifVersion'] ?? null,
            flashpix_version: rawExif['FlashPixVersion'] ?? null,
            encoding_software: rawExif['Software'] ?? null,
            creator_tool_xmp: rawExif['CreatorTool'] ?? null,
        },

        // ── Embedded Objects & Hidden Fields ──────────────────────────────
        embedded_objects: {
            has_macros: art.hasMacros,
            has_embedded_scripts: art.hasEmbeddedScripts,
            has_embedded_files: art.hasEmbeddedFiles,
            embedded_object_types: art.embeddedObjectTypes.length > 0 ? art.embeddedObjectTypes : null,
            has_hidden_text: art.hasHiddenText,
            has_acroform: art.embeddedObjectTypes.includes('AcroForm (Interactive PDF Form)'),
            has_ole_objects: art.embeddedObjectTypes.includes('OLE Object'),
        },

        // ── Revision History ──────────────────────────────────────────────
        revision_history: {
            revision_count: art.revisionCount,
            has_track_changes: art.deletedContent,
            has_deleted_content: art.deletedContent,
            suspicious_streams: art.suspiciousStreams.length > 0 ? art.suspiciousStreams : null,
        },

        // ── GPS / Location ────────────────────────────────────────────────
        gps: {
            GPSLatitude: m.gpsLatitude ?? null,
            GPSLongitude: m.gpsLongitude ?? null,
            GPSAltitude: m.gpsAltitude ?? null,
            GPSTimestamp: m.gpsTimestamp ?? null,
            GPSLatitudeRef: rawExif['GPSLatitudeRef'] ?? null,
            GPSLongitudeRef: rawExif['GPSLongitudeRef'] ?? null,
            GPSAltitudeRef: rawExif['GPSAltitudeRef'] ?? null,
            GPSSpeedRef: rawExif['GPSSpeedRef'] ?? null,
            GPSSpeed: rawExif['GPSSpeed'] ?? null,
            GPSImgDirection: rawExif['GPSImgDirection'] ?? null,
            GPSMapDatum: rawExif['GPSMapDatum'] ?? null,
            GPSProcessingMethod: rawExif['GPSProcessingMethod'] ?? null,
            google_maps_url: m.gpsLatitude !== undefined
                ? `https://www.google.com/maps?q=${m.gpsLatitude},${m.gpsLongitude}`
                : null,
        },

        // ── Timeline ──────────────────────────────────────────────────────
        timeline: {
            creation_date: dateToISO(m.creationDate),
            modification_date: dateToISO(m.modificationDate),
            filesystem_last_modified: dateToISO(m.lastModified),
            upload_timestamp: dateToISO(m.uploadTimestamp),
            access_date: dateToISO(m.accessDate),
            timezone: m.timezone ?? null,
            gps_timestamp: m.gpsTimestamp ?? null,
        },

        // ── Network Indicators ────────────────────────────────────────────
        network_indicators: {
            emails: net.emails.length > 0 ? net.emails : null,
            ip_addresses: net.ips.length > 0 ? net.ips : null,
            urls: net.urls.length > 0 ? net.urls : null,
            unc_paths: net.uncPaths.length > 0 ? net.uncPaths : null,
            hostnames: net.hostnames.length > 0 ? net.hostnames : null,
            external_refs: net.externalRefs.length > 0 ? net.externalRefs : null,
        },

        // ── Anomalies ─────────────────────────────────────────────────────
        anomalies: result.anomalies.map(a => ({
            id: a.id,
            type: a.type,
            severity: a.severity,
            title: a.title,
            description: a.description,
        })),

        // ── Forensic Risk Assessment ──────────────────────────────────────
        forensic_risk_assessment: {
            risk_score: result.riskScore,
            risk_level: result.riskLevel,
            integrity_status: result.integrityStatus,
            evidence_integrity_score: fa.evidenceIntegrityScore,
            attribution_confidence: fa.attributionConfidence,
            identity_leakage_risks: fa.identityLeakageRisks.length > 0 ? fa.identityLeakageRisks : null,
            osint_potential: fa.osintPotential.length > 0 ? fa.osintPotential : null,
            suspicious_indicators: fa.suspiciousIndicators.length > 0 ? fa.suspiciousIndicators : null,
            risk_explanation: result.riskExplanation,
        },
    };
}
