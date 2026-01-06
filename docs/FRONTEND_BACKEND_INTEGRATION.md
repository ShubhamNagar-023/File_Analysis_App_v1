# Frontend-Backend Integration Guide

## Overview

The File Analysis Application consists of two main components:
1. **Backend**: Flask REST API server (Python) that handles file analysis
2. **Frontend**: Electron desktop application that provides the UI

## Architecture

### Backend (Flask API Server)
- **File**: `api_server.py`
- **Port**: 5000 (default)
- **Endpoints**:
  - `GET /api/health` - Health check
  - `POST /api/analyze` - Analyze uploaded files
  - `GET /api/records` - List all analysis records
  - `GET /api/records/<id>` - Get specific record details
  - `GET /api/records/<id>/export/<format>` - Export record (json/html/pdf)
  - `GET /api/cases` - List all cases
  - `GET /api/stats` - Get statistics

### Frontend (Electron App)
- **Location**: `electron/` directory
- **Main Files**:
  - `electron/main/index.js` - Electron main process
  - `electron/renderer/index.html` - UI layout
  - `electron/renderer/app.js` - Application logic
  - `electron/renderer/api-client.js` - REST API client

## How It Works

### 1. Starting the Application

**Integrated Mode** (Recommended):
```bash
python start.py
```
This will:
1. Check dependencies
2. Install Electron dependencies (first run only)
3. Start the Flask API server in the background on port 5000
4. Launch the Electron desktop UI

**Separate Mode** (For Development):
```bash
# Terminal 1: Start API server
python api_server.py --port 5000

# Terminal 2: Start Electron UI
cd electron
npm start
```

### 2. Data Flow

```
User Action (Electron UI)
    ↓
APIClient.analyzeFile(file)
    ↓
HTTP POST to http://localhost:5000/api/analyze
    ↓
Flask API Server processes request
    ↓
Python backend analyzes file (Parts 1-3)
    ↓
Results saved to database (Part 4)
    ↓
JSON response returned to Electron
    ↓
UI updates with analysis results
```

### 3. Connection Mechanism

The frontend uses the `APIClient` class to communicate with the backend:

```javascript
// Initialize API client
const apiClient = new APIClient('http://localhost:5000');

// Check connection
const health = await apiClient.checkHealth();

// Analyze file
const result = await apiClient.analyzeFile(file, caseName, sessionName);

// List records
const records = await apiClient.listRecords();

// Get specific record
const record = await apiClient.getRecord(recordId);
```

## Key Changes Made

### Issue
The original code had the API client defined but never actually used it. The frontend had commented-out IPC bridge code that was never connected to the backend.

### Solution
1. **Updated `electron/renderer/app.js`**:
   - Initialized `APIClient` on application startup
   - Connected all data loading functions to use the API client
   - Added backend connection status indicator
   - Implemented actual file analysis through the API

2. **Updated `electron/renderer/index.html`**:
   - Included `api-client.js` script
   - Updated Content Security Policy to allow connections to `localhost:5000`

3. **Added Helper Functions**:
   - `checkBackendConnection()` - Verifies API server is running
   - `updateBackendStatus()` - Updates UI connection indicator
   - `extractFindings()` - Extracts findings from API response
   - `extractHeuristics()` - Extracts heuristics from API response

## Workflow

### Analyzing a File

1. **Start the Application**:
   ```bash
   python start.py
   ```

2. **In the Electron UI**:
   - The backend status indicator should show "● Connected" (green)
   - Click "Analyze" button or use menu File → Analyze File
   - Select a file to analyze
   - The file is sent to the API server via HTTP POST
   - Results are displayed in real-time

3. **View Results**:
   - File Overview: Basic file information and hashes
   - Risk & Findings: Risk score, severity, and detected issues
   - Metadata: Extracted metadata
   - Hex Viewer: Raw file content
   - Strings: Extracted strings
   - Timeline: Analysis timeline

### Viewing Historical Data

1. The API automatically loads:
   - Available cases (from `/api/cases`)
   - Analysis records (from `/api/records`)

2. Select a case and session from the dropdowns

3. Click on a record to view its details

## Testing the Integration

### Manual Test
1. Start the API server:
   ```bash
   python api_server.py
   ```

2. Open a browser and navigate to:
   ```
   file:///path/to/File_Analysis_App_v1/test_api_integration.html
   ```

3. Click "Run All Tests" to verify:
   - Health check works
   - Cases can be listed
   - Records can be listed
   - Specific records can be retrieved
   - Statistics can be fetched

### API Test via curl
```bash
# Health check
curl http://localhost:5000/api/health

# Analyze a file
curl -X POST http://localhost:5000/api/analyze \
  -F "file=@test_files/sample.pdf" \
  -F "case_name=Test Case"

# List records
curl http://localhost:5000/api/records

# Get specific record
curl http://localhost:5000/api/records/REC-XXXXX
```

## Troubleshooting

### Backend Not Connected
**Symptom**: Red "● Disconnected" indicator in UI

**Solutions**:
1. Check if API server is running:
   ```bash
   curl http://localhost:5000/api/health
   ```

2. If not running, start it:
   ```bash
   python api_server.py
   ```

3. Check for port conflicts:
   ```bash
   lsof -i :5000  # Unix/Mac
   netstat -ano | findstr :5000  # Windows
   ```

### CORS Errors
**Symptom**: "Cross-Origin Request Blocked" in browser console

**Solution**: The API server has CORS enabled via `flask-cors`. If issues persist:
1. Verify `flask-cors` is installed: `pip install flask-cors`
2. Check the API server logs for errors

### File Upload Fails
**Symptom**: Error when analyzing files

**Solutions**:
1. Check file size (very large files may timeout)
2. Verify file permissions
3. Check API server logs for detailed error messages
4. Ensure sufficient disk space in `/tmp` for uploads

## Development Notes

### Adding New API Endpoints

1. **Backend** (`api_server.py`):
   ```python
   @app.route('/api/new-endpoint', methods=['GET'])
   def new_endpoint():
       return jsonify({'data': 'value'})
   ```

2. **API Client** (`electron/renderer/api-client.js`):
   ```javascript
   async newEndpoint() {
       const response = await fetch(`${this.baseURL}/api/new-endpoint`);
       return response.json();
   }
   ```

3. **Frontend** (`electron/renderer/app.js`):
   ```javascript
   async function useNewEndpoint() {
       const data = await apiClient.newEndpoint();
       // Process data...
   }
   ```

### Security Considerations

1. **API Server**:
   - Currently no authentication (add for production)
   - File size limits recommended
   - Input validation on all endpoints

2. **Electron App**:
   - Content Security Policy restricts external resources
   - Sandbox enabled for renderer processes
   - Context isolation enabled

## Summary

The frontend and backend now properly communicate via REST API:
- **Backend**: Flask server provides RESTful endpoints
- **Frontend**: Electron app uses APIClient to consume endpoints
- **Integration**: Seamless data flow from UI to analysis and back

This architecture allows for:
- Clean separation of concerns
- Easy testing of components independently
- Potential for web-based frontend in the future
- Multiple clients accessing the same backend
