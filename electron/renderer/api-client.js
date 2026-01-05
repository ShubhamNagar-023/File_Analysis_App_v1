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

    async listRecords() {
        const response = await fetch(`${this.baseURL}/api/records`);
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
