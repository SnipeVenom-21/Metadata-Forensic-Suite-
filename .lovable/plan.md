

# Metadata Forensic Suite — Implementation Plan

## 1. Dark Theme & Layout Shell
- Set up dark professional theme with custom color variables (deep navy/charcoal palette with green/yellow/red accent colors for risk indicators)
- Create sidebar navigation layout with three sections: **Upload**, **Analysis**, **Reports**
- Add app header with "Metadata Forensic Suite" branding

## 2. File Upload Module
- Drag-and-drop upload zone supporting PDF, DOCX, JPG, PNG, MP4
- Display uploaded file info: filename, size, upload timestamp, and file type icon
- File preview for images; placeholder for other formats
- Upload progress indicator with animated bar

## 3. Metadata Extraction Engine
- Client-side extraction of available metadata (file name, size, type, last modified, MIME type)
- Generate SHA-256 file hash using Web Crypto API
- Parse EXIF data from images (author, GPS, device, software, timestamps)
- For non-image files, simulate/extract what's available and use mock data for fields like author, creation software, etc.
- Display all extracted metadata in a structured card layout

## 4. Tampering Detection & Risk Scoring
- Rule-based anomaly detection checking for:
  - Creation date after modification date
  - Missing/wiped metadata fields
  - Multiple software signatures
  - Timezone inconsistencies
- Calculate risk score (0-100) and assign label: **Low / Medium / High Risk**
- Risk score visualization chart (gauge or bar chart using Recharts)

## 5. Forensic Report Dashboard
- Structured result cards: Metadata Summary, Detected Anomalies, Risk Score, Integrity Status
- Color-coded indicators: green (Authentic), yellow (Suspicious), red (Possible Tampering)
- "Explain Risk" section with a plain-language AI-style summary of detected issues

## 6. Reports & PDF Export
- Reports page listing past analyses in a table
- "Generate Report" button that exports a downloadable PDF containing file details, metadata, detected risks, and analysis timestamp
- Uses browser-based PDF generation

## 7. File History & State Management
- Store uploaded files and analysis results in React state
- Allow users to revisit previous analyses from the Reports tab

