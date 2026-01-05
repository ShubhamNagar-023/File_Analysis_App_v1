/**
 * PART 5: IPC Bridge to Python Backend
 * 
 * This module provides the communication layer between Electron and
 * the Python backend (PART 4 IPC Handler).
 * 
 * CONSTRAINTS:
 * - All data must come from validated IPC
 * - No data fabrication or inference
 * - Schema validation on responses
 * - Visible error states for failures
 */

const { spawn } = require('child_process');
const path = require('path');

class IPCBridge {
    constructor(dbPath = null) {
        this.dbPath = dbPath;
        this.pythonProcess = null;
        this.pendingRequests = new Map();
        this.requestCounter = 0;
        this.schemaVersion = '1.0.0';
    }

    /**
     * Initialize the IPC bridge with database path
     */
    async initialize(dbPath) {
        this.dbPath = dbPath;
        return this.ping();
    }

    /**
     * Generate unique request ID
     */
    generateRequestId() {
        this.requestCounter++;
        return `req-${Date.now()}-${this.requestCounter}`;
    }

    /**
     * Send IPC request to Python backend
     * @param {string} method - IPC method name
     * @param {object} params - Method parameters
     * @returns {Promise} Response data or error
     */
    async sendRequest(method, params = {}) {
        const request = {
            id: this.generateRequestId(),
            method: method,
            params: params,
            timestamp: new Date().toISOString()
        };

        try {
            // Execute Python command directly
            const response = await this.executePythonIPC(request);
            
            // Validate response schema
            if (!this.validateResponse(response)) {
                throw new Error('Invalid response schema');
            }

            if (!response.success) {
                throw new Error(response.error?.message || 'Request failed');
            }

            return response.data;
        } catch (error) {
            // Re-throw with context - errors must be visible
            throw new Error(`IPC Error [${method}]: ${error.message}`);
        }
    }

    /**
     * Execute Python IPC command
     */
    async executePythonIPC(request) {
        return new Promise((resolve, reject) => {
            const scriptPath = path.join(__dirname, '..', '..', 'src', 'file_analyzer', 'part4');
            const pythonCode = `
import sys
import json
sys.path.insert(0, '${scriptPath.replace(/\\/g, '/')}/../..')
from file_analyzer.part4.ipc import IPCHandler
from file_analyzer.part4.persistence import AnalysisDatabase

db_path = '${(this.dbPath || '').replace(/\\/g, '/')}'
if not db_path:
    db_path = None

try:
    if db_path:
        db = AnalysisDatabase(db_path)
        handler = IPCHandler(db)
        request = ${JSON.stringify(request)}
        response = handler.handle_request(request)
        print(response.to_json())
    else:
        # No database configured - return empty but valid response
        response = {
            "id": "${request.id}",
            "success": True,
            "data": None,
            "error": None,
            "timestamp": "${new Date().toISOString()}",
            "schema_version": "1.0.0"
        }
        print(json.dumps(response))
except Exception as e:
    error_response = {
        "id": "${request.id}",
        "success": False,
        "data": None,
        "error": {"code": "internal_error", "message": str(e), "details": None},
        "timestamp": "${new Date().toISOString()}",
        "schema_version": "1.0.0"
    }
    print(json.dumps(error_response))
`;

            const pythonProcess = spawn('python', ['-c', pythonCode], {
                cwd: path.join(__dirname, '..', '..')
            });

            let stdout = '';
            let stderr = '';

            pythonProcess.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            pythonProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            pythonProcess.on('close', (code) => {
                if (code !== 0) {
                    reject(new Error(`Python process exited with code ${code}: ${stderr}`));
                    return;
                }

                try {
                    const response = JSON.parse(stdout.trim());
                    resolve(response);
                } catch (e) {
                    reject(new Error(`Failed to parse response: ${stdout}`));
                }
            });

            pythonProcess.on('error', (error) => {
                reject(new Error(`Failed to start Python process: ${error.message}`));
            });
        });
    }

    /**
     * Validate response against schema
     */
    validateResponse(response) {
        // Required fields
        if (typeof response.id !== 'string') return false;
        if (typeof response.success !== 'boolean') return false;
        if (!('data' in response)) return false;
        if (!('error' in response)) return false;
        if (!('schema_version' in response)) return false;

        // Check schema version compatibility
        if (response.schema_version !== this.schemaVersion) {
            console.warn(`Schema version mismatch: expected ${this.schemaVersion}, got ${response.schema_version}`);
        }

        return true;
    }

    // =========================================================================
    // IPC Method Wrappers - One for each PART 4 IPC endpoint
    // =========================================================================

    /**
     * Health check
     */
    async ping() {
        return this.sendRequest('ping', {});
    }

    /**
     * List investigation cases
     */
    async listCases(params = {}) {
        return this.sendRequest('list_cases', params);
    }

    /**
     * Get case details
     */
    async getCase(caseId) {
        return this.sendRequest('get_case', { case_id: caseId });
    }

    /**
     * List analysis sessions
     */
    async listSessions(params = {}) {
        return this.sendRequest('list_sessions', params);
    }

    /**
     * Get session details
     */
    async getSession(sessionId) {
        return this.sendRequest('get_session', { session_id: sessionId });
    }

    /**
     * List analysis records
     */
    async listRecords(params = {}) {
        return this.sendRequest('list_records', params);
    }

    /**
     * Get full analysis record
     */
    async getRecord(recordId) {
        return this.sendRequest('get_record', { record_id: recordId });
    }

    /**
     * Get lightweight record summary
     */
    async getRecordSummary(recordId) {
        return this.sendRequest('get_record_summary', { record_id: recordId });
    }

    /**
     * List PART 2 findings
     */
    async listFindings(params = {}) {
        return this.sendRequest('list_findings', params);
    }

    /**
     * List PART 3 heuristics
     */
    async listHeuristics(params = {}) {
        return this.sendRequest('list_heuristics', params);
    }

    /**
     * Get session correlations
     */
    async getCorrelations(sessionId) {
        return this.sendRequest('get_correlations', { session_id: sessionId });
    }

    /**
     * Get analysis timeline
     */
    async getTimeline(params = {}) {
        return this.sendRequest('get_timeline', params);
    }

    /**
     * Get database statistics
     */
    async getStatistics() {
        return this.sendRequest('get_statistics', {});
    }

    /**
     * List logged errors
     */
    async listErrors(params = {}) {
        return this.sendRequest('list_errors', params);
    }
}

module.exports = { IPCBridge };
