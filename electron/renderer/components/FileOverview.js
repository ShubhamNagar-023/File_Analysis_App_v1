/**
 * PART 5: File Overview Component
 * 
 * Displays file identity information from PART 1 analysis.
 * All data must come from IPC - no fabrication or inference.
 * 
 * Data Sources:
 * - record.file_name, file_path, file_size
 * - record.semantic_file_type
 * - part1.cryptographic_identity.hashes
 * - part1.semantic_file_type.classification_confidence
 */

class FileOverviewComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.currentRecord = null;
    }

    /**
     * Render file overview from record data
     * @param {object} record - Full analysis record from get_record IPC
     */
    render(record) {
        if (!record) {
            this.renderEmpty();
            return;
        }

        this.currentRecord = record;

        const part1 = record.part1 || {};
        const fileInfo = part1.file_info || {};
        const cryptoIdentity = part1.cryptographic_identity || {};
        const semanticType = part1.semantic_file_type || {};
        const hashes = cryptoIdentity.hashes || [];

        // Build hash data from PART 1 - exact values only
        const hashData = this.extractHashes(hashes);

        const html = `
            <div class="file-overview">
                <section class="overview-section">
                    <h3>File Identity</h3>
                    <div class="kv-list">
                        <span class="kv-key">File Name</span>
                        <span class="kv-value">${this.escapeHtml(record.file_name) || this.renderMissing('file_name')}</span>
                        
                        <span class="kv-key">File Path</span>
                        <span class="kv-value">${this.escapeHtml(record.file_path) || this.renderMissing('file_path')}</span>
                        
                        <span class="kv-key">File Size</span>
                        <span class="kv-value">${this.formatFileSize(record.file_size)}</span>
                        
                        <span class="kv-key">Semantic Type</span>
                        <span class="kv-value">${this.escapeHtml(record.semantic_file_type) || this.renderMissing('semantic_file_type')}</span>
                        
                        <span class="kv-key">Container Type</span>
                        <span class="kv-value">${this.renderContainerType(semanticType)}</span>
                        
                        <span class="kv-key">Classification Confidence</span>
                        <span class="kv-value">${this.renderConfidence(semanticType.output_value?.classification_confidence)}</span>
                    </div>
                </section>

                <section class="overview-section">
                    <h3>Cryptographic Identity</h3>
                    <div class="kv-list">
                        <span class="kv-key">MD5</span>
                        <span class="kv-value">${hashData.md5 || this.renderMissing('MD5')}</span>
                        
                        <span class="kv-key">SHA-1</span>
                        <span class="kv-value">${hashData.sha1 || this.renderMissing('SHA-1')}</span>
                        
                        <span class="kv-key">SHA-256</span>
                        <span class="kv-value">${record.sha256_hash || this.renderMissing('SHA-256')}</span>
                        
                        <span class="kv-key">SHA-512</span>
                        <span class="kv-value">${hashData.sha512 || this.renderMissing('SHA-512')}</span>
                    </div>
                </section>

                <section class="overview-section">
                    <h3>Analysis Metadata</h3>
                    <div class="kv-list">
                        <span class="kv-key">Record ID</span>
                        <span class="kv-value">${this.escapeHtml(record.record_id) || this.renderMissing('record_id')}</span>
                        
                        <span class="kv-key">Session ID</span>
                        <span class="kv-value">${this.escapeHtml(record.session_id) || this.renderMissing('session_id')}</span>
                        
                        <span class="kv-key">Created At</span>
                        <span class="kv-value">${this.formatTimestamp(record.created_at)}</span>
                        
                        <span class="kv-key">Schema Version</span>
                        <span class="kv-value">${this.escapeHtml(record.schema_version) || this.renderMissing('schema_version')}</span>
                    </div>
                </section>
            </div>
        `;

        this.container.innerHTML = html;
    }

    /**
     * Extract hashes from PART 1 hash array
     * @param {array} hashes - Array of hash objects from cryptographic_identity
     */
    extractHashes(hashes) {
        const result = { md5: null, sha1: null, sha256: null, sha512: null };

        for (const hash of hashes) {
            const algorithm = hash.evidence?.algorithm?.toLowerCase() || 
                             hash.analysis_name?.replace('hash_', '').toLowerCase();
            const value = hash.output_value;

            if (algorithm === 'md5') result.md5 = value;
            else if (algorithm === 'sha1') result.sha1 = value;
            else if (algorithm === 'sha256') result.sha256 = value;
            else if (algorithm === 'sha512') result.sha512 = value;
        }

        return result;
    }

    /**
     * Render container type - exact value from PART 1
     */
    renderContainerType(semanticType) {
        const containerType = semanticType.output_value?.container_type;
        if (containerType === null || containerType === undefined) {
            return '<span class="kv-value not-present">None</span>';
        }
        return this.escapeHtml(containerType);
    }

    /**
     * Render confidence level with color
     */
    renderConfidence(confidence) {
        if (!confidence) {
            return '<span class="kv-value not-present">NOT_PRESENT</span>';
        }

        const classes = {
            'HIGH': 'severity-low',
            'MEDIUM': 'severity-medium',
            'LOW': 'severity-high',
            'AMBIGUOUS': 'severity-critical'
        };

        const className = classes[confidence] || '';
        return `<span class="${className}">${this.escapeHtml(confidence)}</span>`;
    }

    /**
     * Render empty state
     */
    renderEmpty() {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No file selected</p>
                <p class="hint">Select a record from the list to view details</p>
            </div>
        `;
    }

    /**
     * Render error state - errors must be visible
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading File Overview</div>
                <div class="error-state-message">${this.escapeHtml(message)}</div>
            </div>
        `;
    }

    /**
     * Render missing field indicator - no fabrication
     */
    renderMissing(fieldName) {
        return `<span class="kv-value missing">Missing: ${this.escapeHtml(fieldName)}</span>`;
    }

    /**
     * Format file size with units
     */
    formatFileSize(bytes) {
        if (bytes === undefined || bytes === null) {
            return this.renderMissing('file_size');
        }

        if (bytes === 0) return '0 bytes';
        
        const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        const size = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 2 : 0);
        
        return `${size} ${units[i]} (${bytes.toLocaleString()} bytes)`;
    }

    /**
     * Format timestamp
     */
    formatTimestamp(timestamp) {
        if (!timestamp) {
            return this.renderMissing('timestamp');
        }
        return this.escapeHtml(timestamp);
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }
}

// Export for use in main app
window.FileOverviewComponent = FileOverviewComponent;
