/**
 * API Client for File Analysis Backend
 * Connects Electron frontend to Flask REST API
 */

class APIClient {
    constructor(baseURL = 'http://localhost:5000') {
        this.baseURL = baseURL;
    }

    async checkHealth() {
        const response = await fetch(`${this.baseURL}/api/health`);
        return response.json();
    }

    async analyzeFile(file, caseName = null, sessionName = null) {
        const formData = new FormData();
        formData.append('file', file);
        if (caseName) formData.append('case_name', caseName);
        if (sessionName) formData.append('session_name', sessionName);

        const response = await fetch(`${this.baseURL}/api/analyze`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Analysis failed');
        }

        return response.json();
    }

    async listRecords(params = {}) {
        let url = `${this.baseURL}/api/records`;
        const queryParams = new URLSearchParams();
        
        if (params.session_id) queryParams.append('session_id', params.session_id);
        if (params.file_type) queryParams.append('file_type', params.file_type);
        if (params.severity) queryParams.append('severity', params.severity);
        if (params.min_score !== undefined) queryParams.append('min_score', params.min_score);
        if (params.max_score !== undefined) queryParams.append('max_score', params.max_score);
        if (params.limit) queryParams.append('limit', params.limit);
        if (params.offset) queryParams.append('offset', params.offset);
        
        if (queryParams.toString()) {
            url += '?' + queryParams.toString();
        }
        
        const response = await fetch(url);
        const data = await response.json();
        return data.records || [];
    }

    async getRecord(recordId) {
        const response = await fetch(`${this.baseURL}/api/records/${recordId}`);
        const data = await response.json();
        return data.record;
    }

    async exportRecord(recordId, format) {
        const response = await fetch(`${this.baseURL}/api/records/${recordId}/export/${format}`);
        const blob = await response.blob();
        return blob;
    }

    async listCases() {
        const response = await fetch(`${this.baseURL}/api/cases`);
        const data = await response.json();
        return data.cases || [];
    }

    async getCase(caseId) {
        const response = await fetch(`${this.baseURL}/api/cases/${caseId}`);
        const data = await response.json();
        return data.case;
    }

    async listSessions(caseId = null) {
        let url = `${this.baseURL}/api/sessions`;
        if (caseId) {
            url += `?case_id=${encodeURIComponent(caseId)}`;
        }
        const response = await fetch(url);
        const data = await response.json();
        return data.sessions || [];
    }

    async getSession(sessionId) {
        const response = await fetch(`${this.baseURL}/api/sessions/${sessionId}`);
        const data = await response.json();
        return data.session;
    }

    async getStats() {
        const response = await fetch(`${this.baseURL}/api/stats`);
        const data = await response.json();
        return data.statistics;
    }
}

// Export for both Node and browser environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = APIClient;
}
