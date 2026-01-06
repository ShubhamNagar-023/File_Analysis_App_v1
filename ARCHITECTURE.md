# Application Architecture - Visual Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    FILE ANALYSIS APPLICATION                             │
│                         Architecture v1.0.0                              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                          USER INTERFACES                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐        │
│  │   PyQt6 GUI     │  │  Command Line   │  │   REST API      │        │
│  │   (Desktop)     │  │     (CLI)       │  │  (Integration)  │        │
│  │                 │  │                 │  │                 │        │
│  │ • Case selector │  │ • analyze_file  │  │ • HTTP Client   │        │
│  │ • File overview │  │ • Batch mode    │  │ • curl/Python   │        │
│  │ • Risk panel    │  │ • Automation    │  │ • JavaScript    │        │
│  │ • Export        │  │ • Scripts       │  │ • CI/CD         │        │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘        │
│           │                    │                     │                  │
└───────────┼────────────────────┼─────────────────────┼──────────────────┘
            │                    │                     │
            └────────────────────┴─────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   DIRECT INTEGRATION    │
                    │  (PyQt6: Direct calls)  │
                    │  (CLI: analyze_file.py) │
                    │  (API: HTTP/REST/JSON)  │
                    └────────────┬────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────────────┐
│                        FLASK API SERVER                                   │
│                        (api_server.py)                                    │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  REST API ENDPOINTS:                                                      │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ GET  /api/health              → Health check                    │     │
│  │ POST /api/analyze             → Analyze uploaded file           │     │
│  │ GET  /api/cases               → List all cases                  │     │
│  │ GET  /api/cases/<id>          → Get specific case               │     │
│  │ GET  /api/sessions            → List all sessions               │     │
│  │ GET  /api/sessions?case_id=X  → Filter sessions by case         │     │
│  │ GET  /api/sessions/<id>       → Get specific session            │     │
│  │ GET  /api/records             → List all records                │     │
│  │ GET  /api/records?params      → Filter records (session, type)  │     │
│  │ GET  /api/records/<id>        → Get specific record             │     │
│  │ GET  /api/records/<id>/export → Export record (json/html/pdf)   │     │
│  │ GET  /api/stats               → Get statistics                  │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                           │
└───────────────────────────────────┬───────────────────────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │   ANALYSIS ENGINE             │
                    │   (src/file_analyzer/)        │
                    │                               │
                    │ ┌───────────────────────────┐ │
                    │ │ PART 1: File Ingestion   │ │
                    │ │ • Hash computation        │ │
                    │ │ • Type detection          │ │
                    │ │ • Container identification│ │
                    │ └───────────┬───────────────┘ │
                    │             │                 │
                    │ ┌───────────▼───────────────┐ │
                    │ │ PART 2: Deep Analysis    │ │
                    │ │ • Entropy analysis        │ │
                    │ │ • String extraction       │ │
                    │ │ • Container inspection    │ │
                    │ └───────────┬───────────────┘ │
                    │             │                 │
                    │ ┌───────────▼───────────────┐ │
                    │ │ PART 3: Risk Scoring     │ │
                    │ │ • Heuristic evaluation    │ │
                    │ │ • Risk calculation        │ │
                    │ │ • Severity assessment     │ │
                    │ └───────────┬───────────────┘ │
                    │             │                 │
                    └─────────────┼─────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │ PART 4: Persistence       │
                    │ (persistence.py)          │
                    │                           │
                    │ • AnalysisDatabase        │
                    │ • create_case()           │
                    │ • create_session()        │
                    │ • import_analysis()       │
                    │ • query_records()         │
                    │ • get_statistics()        │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   SQLITE DATABASE         │
                    │   (analysis.db)           │
                    │                           │
                    │ Tables:                   │
                    │ • cases                   │
                    │ • sessions                │
                    │ • records                 │
                    │ • findings                │
                    │ • heuristics              │
                    │ • errors                  │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │    EXPORTER               │
                    │    (exporter.py)          │
                    │                           │
                    │ Export Formats:           │
                    │ • JSON (complete data)    │
                    │ • HTML (web report)       │
                    │ • PDF (printable)         │
                    └───────────────────────────┘


═══════════════════════════════════════════════════════════════════════════
                            DATA FLOW EXAMPLE
═══════════════════════════════════════════════════════════════════════════

USER ACTION: Analyze file "suspicious.exe"
│
├─► 1. User uploads file via Electron UI
│   │
│   └─► apiClient.analyzeFile(file, "Case A", "Session 1")
│       │
│       └─► POST http://localhost:5000/api/analyze
│           FormData: { file: <binary>, case_name, session_name }
│
├─► 2. API Server receives request
│   │
│   ├─► Save file to /tmp/file_analysis_uploads_XXX/
│   │
│   ├─► Run analysis pipeline:
│   │   ├─► PART 1: analyze_file(path)
│   │   │   └─► Returns: { hashes, file_type, container_info }
│   │   │
│   │   ├─► PART 2: deep_analyze_file(path, part1)
│   │   │   └─► Returns: { entropy, strings, findings }
│   │   │
│   │   └─► PART 3: analyze_part3(path, part1, part2)
│   │       └─► Returns: { risk_score, severity, heuristics }
│   │
│   ├─► Create case and session:
│   │   ├─► case_id = db.create_case("Case A")
│   │   └─► session_id = db.create_session(case_id, "Session 1")
│   │
│   ├─► Import to database:
│   │   └─► record_id = db.import_analysis(session_id, part1, part2, part3)
│   │       ├─► INSERT INTO records
│   │       ├─► INSERT INTO findings
│   │       └─► INSERT INTO heuristics
│   │
│   ├─► Export results:
│   │   ├─► exporter.export_record(record_id, "path/file.json", JSON)
│   │   ├─► exporter.export_record(record_id, "path/file.html", HTML)
│   │   └─► exporter.export_record(record_id, "path/file.pdf", PDF)
│   │
│   └─► Return response:
│       └─► {
│             "success": true,
│             "record_id": "REC-ABC123",
│             "case_id": "CASE-XYZ789",
│             "session_id": "SES-DEF456",
│             "results": {
│               "file_name": "suspicious.exe",
│               "risk_score": 85.5,
│               "severity": "HIGH"
│             },
│             "exports": { ... }
│           }
│
└─► 3. Electron UI receives response
    │
    ├─► Update state with new record
    │
    ├─► Refresh data to show in lists
    │
    └─► Display results in UI
        ├─► File Overview tab: Show hashes, file type
        ├─► Risk & Findings tab: Show risk score, findings
        ├─► Metadata tab: Show extracted metadata
        └─► Hex Viewer tab: Show raw content


═══════════════════════════════════════════════════════════════════════════
                         CASCADE WORKFLOW
═══════════════════════════════════════════════════════════════════════════

User selects Case from dropdown
│
├─► Frontend: handleCaseChange("CASE-123")
│   │
│   ├─► API: GET /api/cases/CASE-123
│   │   └─► Returns: { case_id, name, description, status, ... }
│   │
│   ├─► API: GET /api/sessions?case_id=CASE-123
│   │   └─► Returns: [
│   │         { session_id: "SES-456", name: "Session 1" },
│   │         { session_id: "SES-789", name: "Session 2" }
│   │       ]
│   │
│   └─► UI: Populate session dropdown with sessions
│
User selects Session from dropdown
│
├─► Frontend: handleSessionChange("SES-456")
│   │
│   ├─► API: GET /api/sessions/SES-456
│   │   └─► Returns: { session_id, name, case_id, status, ... }
│   │
│   ├─► API: GET /api/records?session_id=SES-456
│   │   └─► Returns: [
│   │         { record_id: "REC-AAA", file_name: "file1.exe", ... },
│   │         { record_id: "REC-BBB", file_name: "file2.pdf", ... }
│   │       ]
│   │
│   └─► UI: Display records in left panel list
│
User clicks on a Record
│
└─► Frontend: loadRecord("REC-AAA")
    │
    ├─► API: GET /api/records/REC-AAA
    │   └─► Returns: {
    │         record_id, file_name, file_size, risk_score,
    │         part1: { hashes, file_type, ... },
    │         part2: { entropy, strings, findings, ... },
    │         part3: { risk_score, heuristics, ... }
    │       }
    │
    └─► UI: Render all tabs with record data
        ├─► FileOverview component
        ├─► RiskPanel component
        ├─► MetadataExplorer component
        ├─► HexViewer component
        ├─► StringsViewer component
        └─► Timeline component


═══════════════════════════════════════════════════════════════════════════
                      DEPLOYMENT ARCHITECTURE
═══════════════════════════════════════════════════════════════════════════

OPTION 1: Integrated Desktop Application (Recommended)
┌─────────────────────────────────────────────────────────────┐
│  User executes: python start.py                             │
│                                                              │
│  ┌────────────────────┐         ┌────────────────────┐     │
│  │  API Server        │◄────────┤  Electron UI       │     │
│  │  (Background)      │  HTTP   │  (Desktop Window)  │     │
│  │  localhost:5000    │────────►│  127.0.0.1:5000   │     │
│  └────────────────────┘         └────────────────────┘     │
│           │                                                  │
│           ▼                                                  │
│  ┌────────────────────┐                                     │
│  │  SQLite Database   │                                     │
│  │  analysis.db       │                                     │
│  └────────────────────┘                                     │
└─────────────────────────────────────────────────────────────┘

OPTION 2: Separate Components (Development)
┌──────────────────┐         ┌──────────────────┐
│  Terminal 1      │         │  Terminal 2      │
│                  │         │                  │
│  python          │         │  cd electron     │
│  api_server.py   │         │  npm start       │
│  --port 5000     │         │                  │
└────────┬─────────┘         └────────┬─────────┘
         │                            │
         └────────────┬───────────────┘
                      │
                      ▼
              ┌───────────────┐
              │   Database    │
              └───────────────┘

OPTION 3: API-Only (CI/CD Integration)
┌─────────────────────────────────────────┐
│  CI/CD Pipeline                          │
│                                          │
│  ┌────────────────────┐                 │
│  │  API Server        │                 │
│  │  (Docker)          │                 │
│  │  0.0.0.0:8080     │                 │
│  └────────┬───────────┘                 │
│           │                              │
│           ▼                              │
│  ┌────────────────────┐                 │
│  │  Python/curl       │                 │
│  │  Client            │                 │
│  └────────────────────┘                 │
└─────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════
                           KEY COMPONENTS
═══════════════════════════════════════════════════════════════════════════

FILE                                  PURPOSE
──────────────────────────────────────────────────────────────────────────
start.py                              Integrated launcher (API + UI)
api_server.py                         Flask REST API server
analyze_file.py                       CLI analysis tool

src/file_analyzer/analyzer.py        PART 1: File ingestion
src/file_analyzer/deep_analyzer.py   PART 2: Deep analysis
src/file_analyzer/part3_analyzer.py  PART 3: Risk scoring
src/file_analyzer/part4/persistence.py  Database operations
src/file_analyzer/part4/exporter.py     Export functionality

electron/main/index.js                Electron main process
electron/renderer/index.html          UI layout
electron/renderer/app.js              Application logic
electron/renderer/api-client.js       REST API client

USER_WORKFLOW_GUIDE.md                Complete user guide
API.md                                API reference
docs/FRONTEND_BACKEND_INTEGRATION.md  Integration details
docs/API_INTEGRATION_TEST_RESULTS.md  Test verification
docs/INTEGRATION_COMPLETE_SUMMARY.md  Final summary

═══════════════════════════════════════════════════════════════════════════
```

**Status**: Production Ready ✅  
**Version**: 1.0.0  
**Last Updated**: 2026-01-06
