# PART 5: Desktop Dashboard UI & Visualization

**Status:** ✅ Implemented  
**Type:** Presentation Layer Only  
**Platform:** ElectronJS Desktop Application

---

## Overview

PART 5 implements a desktop-only dashboard UI for the File Analysis Application. This is strictly a **presentation layer** that consumes data exclusively via validated IPC contracts defined in PART 4.

### Key Constraints

- ✅ No analysis logic in the UI layer
- ✅ No scoring or heuristics in the UI layer
- ✅ No direct file parsing by the UI
- ✅ No mock, demo, placeholder, or synthesized data
- ✅ UI fails visibly when data is missing or invalid
- ✅ All rendered values exactly match persisted data

---

## Directory Structure

```
electron/
├── main/
│   ├── index.js          # Main process entry point
│   └── ipc-bridge.js     # IPC bridge to Python backend
├── preload/
│   └── preload.js        # Context bridge for renderer
├── renderer/
│   ├── index.html        # Main window HTML
│   ├── app.js            # Main application script
│   ├── styles/
│   │   ├── themes.css    # Dark/Light/High-contrast themes
│   │   └── components.css # Component styles
│   └── components/
│       ├── FileOverview.js      # File identity from PART 1
│       ├── RiskPanel.js         # Risk score from PART 3
│       ├── MetadataExplorer.js  # Metadata from PART 1
│       ├── FindingsList.js      # Findings from PART 2
│       ├── HeuristicsPanel.js   # Heuristics from PART 3
│       ├── HexViewer.js         # Byte-accurate hex view
│       ├── StringsViewer.js     # Classified strings
│       ├── ArchiveTree.js       # Container structure
│       ├── Timeline.js          # Event timeline
│       ├── DiffView.js          # Record comparison
│       └── StatusBar.js         # Status display
└── package.json
```

---

## UI Components

### 1. Application Structure

| Requirement | Implementation |
|-------------|----------------|
| ElectronJS desktop application | ✅ `electron/main/index.js` |
| Top menu bar (File, View, Analysis, Reports, Settings, Help) | ✅ Full menu with accelerators |
| Secondary toolbar with context-aware actions | ✅ Toolbar with refresh, analyze, selectors |
| Central workspace with 3+ resizable panels | ✅ Left (records), Center (content), Right (details) |
| Bottom status bar | ✅ Data state, errors, case/session context |

### 2. Data-Driven Dashboards

| Component | Responsibility | IPC Endpoints |
|-----------|---------------|---------------|
| **FileOverview** | File identity, hashes, classification | `get_record` |
| **RiskPanel** | Risk score, severity, contributions | `get_record`, `get_record_summary` |
| **MetadataExplorer** | Filesystem metadata, extension analysis | `get_record` |
| **FindingsList** | PART 2 findings with byte offsets | `list_findings` |
| **HeuristicsPanel** | Triggered/not-triggered heuristics | `list_heuristics` |

### 3. Inspection Tools

| Component | Feature | Implementation |
|-----------|---------|----------------|
| **HexViewer** | Byte offsets, ASCII view, jump-to-offset | ✅ Displays findings with hex representation |
| **StringsViewer** | Classified strings (URLs, IPs, emails) | ✅ Filter by classification, offset navigation |
| **ArchiveTree** | Container hierarchy, nested structure | ✅ Tree view with depth limiting |
| **Timeline** | Filesystem timestamps, analysis events | ✅ Chronological event display |
| **DiffView** | Binary/metadata comparison | ✅ Side-by-side record comparison |

### 4. Usability & Accessibility

| Feature | Implementation |
|---------|----------------|
| Dark theme | ✅ Default, `theme-dark` class |
| Light theme | ✅ `theme-light` class |
| High-contrast theme | ✅ `theme-high-contrast` class |
| Keyboard shortcuts | ✅ F5 refresh, Ctrl+1-6 tabs, Ctrl+D theme |
| Screen-reader compatibility | ✅ ARIA roles, labels, live regions |
| Offline-first behavior | ✅ No external network calls |

---

## IPC Data Flow

### Request Format

```javascript
{
    id: "req-001",
    method: "get_record",
    params: { record_id: "REC-123456789012" },
    timestamp: "2026-01-05T20:00:00.000000"
}
```

### Response Format

```javascript
{
    id: "req-001",
    success: true,
    data: { /* record data */ },
    error: null,
    timestamp: "2026-01-05T20:00:00.100000",
    schema_version: "1.0.0"
}
```

### Error Handling

| Error Code | UI Behavior |
|------------|-------------|
| `invalid_request` | Show validation error |
| `not_found` | Show "Record not found" |
| `database_error` | Show "Database error" banner |
| `integrity_error` | Block rendering, show corruption alert |

---

## Data-to-UI Mapping

### File Overview Panel

| UI Element | Data Path | IPC Method |
|------------|-----------|------------|
| File Name | `record.file_name` | `get_record` |
| File Path | `record.file_path` | `get_record` |
| File Size | `record.file_size` | `get_record` |
| Semantic Type | `record.semantic_file_type` | `get_record` |
| MD5/SHA-1/SHA-256/SHA-512 | `part1.cryptographic_identity.hashes[]` | `get_record` |
| Classification Confidence | `part1.semantic_file_type.output_value.classification_confidence` | `get_record` |

### Risk & Findings Panel

| UI Element | Data Path | IPC Method |
|------------|-----------|------------|
| Risk Score | `record.risk_score` | `get_record_summary` |
| Severity | `record.severity` | `get_record_summary` |
| Score Contributions | `part3.risk_score.score_contributions[]` | `get_record` |
| Explanation | `part3.risk_score.explanation` | `get_record` |
| Triggered Heuristics | `part3.heuristics.triggered_heuristics[]` | `get_record` |

### Findings List

| UI Element | Data Path | IPC Method |
|------------|-----------|------------|
| Finding Type | `finding.finding_type` | `list_findings` |
| Byte Offset | `finding.byte_offset_start` | `list_findings` |
| Confidence | `finding.confidence` | `list_findings` |
| Extracted Value | `finding.extracted_value` | `list_findings` |

---

## Error and Empty States

### Required Error States

All components render explicit error states:

```javascript
renderError(message) {
    this.container.innerHTML = `
        <div class="error-state">
            <div class="error-state-title">Error Loading Data</div>
            <div class="error-state-message">${escapeHtml(message)}</div>
        </div>
    `;
}
```

### Empty State Behavior

```javascript
renderEmpty() {
    this.container.innerHTML = `
        <div class="empty-state">
            <p>No data available</p>
            <p class="hint">Descriptive hint for user</p>
        </div>
    `;
}
```

### Missing Field Indicators

```javascript
renderMissing(fieldName) {
    return `<span class="kv-value missing">Missing: ${fieldName}</span>`;
}

renderNotPresent() {
    return `<span class="kv-value not-present">NOT_PRESENT</span>`;
}
```

---

## Running the Application

### Prerequisites

```bash
# Ensure Node.js >= 18.0.0
node --version

# Navigate to electron directory
cd electron

# Install dependencies
npm install
```

### Development

```bash
# Start the application
npm start

# Or with dev tools
npm run dev
```

---

## Validation Checklist

| Requirement | Status |
|-------------|--------|
| Reloading app shows identical results | ✅ Data from IPC |
| Clicking finding jumps to byte offset | ✅ `setOffsetClickHandler` |
| UI values match database exactly | ✅ No transformation |
| CLI and UI return same data | ✅ Same IPC endpoints |
| IPC errors surface visibly | ✅ `handleError()` function |
| Schema mismatches block rendering | ✅ `validateResponse()` |
| No silent failures | ✅ All errors logged and displayed |

---

## Strictly Forbidden

- ❌ Static screenshots or mockups
- ❌ Hardcoded sample values
- ❌ UI-only "calculated" fields
- ❌ Reading files directly from disk
- ❌ Reinterpreting or reshaping analysis results
- ❌ Fabricating defaults for missing data

---

## PART 5 Constraints Acknowledgment

This implementation renders only real, persisted analysis data via validated IPC into a desktop Electron UI without fabricating, inferring, or simulating any content.

I understand PART 5 constraints and will render only real, persisted analysis data via validated IPC into a desktop Electron UI without fabricating, inferring, or simulating any content.
