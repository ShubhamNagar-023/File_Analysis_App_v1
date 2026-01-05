/**
 * PART 5: Diff View Component
 * 
 * Displays binary diff and metadata diff between records.
 * For comparing multiple file analyses.
 * 
 * Data Sources:
 * - Two records from get_record IPC
 * - Comparison of persisted data only
 */

class DiffViewComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.recordA = null;
        this.recordB = null;
    }

    /**
     * Render diff view comparing two records
     * @param {object} recordA - First analysis record
     * @param {object} recordB - Second analysis record (optional)
     */
    render(recordA, recordB) {
        if (!recordA) {
            this.renderEmpty();
            return;
        }

        this.recordA = recordA;
        this.recordB = recordB;

        if (!recordB) {
            this.renderSelectSecond(recordA);
            return;
        }

        const html = `
            <div class="diff-viewer">
                <div class="diff-header">
                    <h3>Comparison View</h3>
                </div>
                
                <div class="diff-summary">
                    <div class="diff-file">
                        <strong>File A:</strong> ${this.escapeHtml(recordA.file_name)}
                    </div>
                    <div class="diff-file">
                        <strong>File B:</strong> ${this.escapeHtml(recordB.file_name)}
                    </div>
                </div>

                <div class="diff-tabs">
                    <button class="tab-btn active" data-diff-tab="metadata">Metadata Diff</button>
                    <button class="tab-btn" data-diff-tab="hashes">Hash Comparison</button>
                    <button class="tab-btn" data-diff-tab="risk">Risk Comparison</button>
                </div>

                <div class="diff-content">
                    <div id="diff-metadata" class="diff-tab-content active">
                        ${this.renderMetadataDiff(recordA, recordB)}
                    </div>
                    <div id="diff-hashes" class="diff-tab-content" style="display: none;">
                        ${this.renderHashDiff(recordA, recordB)}
                    </div>
                    <div id="diff-risk" class="diff-tab-content" style="display: none;">
                        ${this.renderRiskDiff(recordA, recordB)}
                    </div>
                </div>
            </div>
        `;

        this.container.innerHTML = html;
        this.setupEventHandlers();
    }

    /**
     * Render metadata diff
     */
    renderMetadataDiff(recordA, recordB) {
        const fields = [
            { key: 'file_name', label: 'File Name' },
            { key: 'file_size', label: 'File Size' },
            { key: 'semantic_file_type', label: 'Semantic Type' },
            { key: 'severity', label: 'Severity' },
            { key: 'risk_score', label: 'Risk Score' },
            { key: 'created_at', label: 'Analyzed At' }
        ];

        const rows = fields.map(field => {
            const valA = recordA[field.key];
            const valB = recordB[field.key];
            const match = this.valuesMatch(valA, valB);

            return `
                <tr class="${match ? '' : 'diff-mismatch'}">
                    <td>${this.escapeHtml(field.label)}</td>
                    <td class="value-cell">${this.formatValue(valA)}</td>
                    <td class="value-cell">${this.formatValue(valB)}</td>
                    <td>${match ? '✓' : '✗'}</td>
                </tr>
            `;
        }).join('');

        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Field</th>
                        <th>File A</th>
                        <th>File B</th>
                        <th>Match</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;
    }

    /**
     * Render hash comparison
     */
    renderHashDiff(recordA, recordB) {
        const hashesA = this.extractHashes(recordA);
        const hashesB = this.extractHashes(recordB);

        const hashTypes = ['md5', 'sha1', 'sha256', 'sha512'];
        const rows = hashTypes.map(type => {
            const valA = hashesA[type];
            const valB = hashesB[type];
            const match = valA === valB;

            return `
                <tr class="${match ? 'diff-match' : 'diff-mismatch'}">
                    <td>${type.toUpperCase()}</td>
                    <td class="value-cell" style="font-size: 10px;">${this.escapeHtml(valA || 'N/A')}</td>
                    <td class="value-cell" style="font-size: 10px;">${this.escapeHtml(valB || 'N/A')}</td>
                    <td class="${match ? 'severity-low' : 'severity-critical'}">${match ? 'MATCH' : 'DIFFER'}</td>
                </tr>
            `;
        }).join('');

        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Hash</th>
                        <th>File A</th>
                        <th>File B</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;
    }

    /**
     * Render risk comparison
     */
    renderRiskDiff(recordA, recordB) {
        const scoreA = recordA.risk_score || 0;
        const scoreB = recordB.risk_score || 0;
        const severityA = recordA.severity || 'informational';
        const severityB = recordB.severity || 'informational';

        return `
            <div class="risk-comparison">
                <div class="risk-comparison-side">
                    <h4>File A: ${this.escapeHtml(recordA.file_name)}</h4>
                    <div class="risk-score-display">
                        <div class="risk-score-value ${severityA}">${scoreA.toFixed(1)}</div>
                        <span class="severity-badge ${severityA}">${severityA.toUpperCase()}</span>
                    </div>
                </div>
                <div class="risk-comparison-divider">
                    <span class="text-muted">vs</span>
                </div>
                <div class="risk-comparison-side">
                    <h4>File B: ${this.escapeHtml(recordB.file_name)}</h4>
                    <div class="risk-score-display">
                        <div class="risk-score-value ${severityB}">${scoreB.toFixed(1)}</div>
                        <span class="severity-badge ${severityB}">${severityB.toUpperCase()}</span>
                    </div>
                </div>
            </div>
            <div class="risk-comparison-summary">
                <p>
                    Score difference: <strong>${Math.abs(scoreA - scoreB).toFixed(1)}</strong>
                    (${scoreA > scoreB ? 'File A is higher risk' : scoreB > scoreA ? 'File B is higher risk' : 'Equal risk'})
                </p>
            </div>
        `;
    }

    /**
     * Extract hashes from record
     */
    extractHashes(record) {
        const result = { md5: null, sha1: null, sha256: record.sha256_hash, sha512: null };
        
        const part1 = record.part1 || {};
        const hashes = part1.cryptographic_identity?.hashes || [];

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
     * Check if values match
     */
    valuesMatch(a, b) {
        if (a === b) return true;
        if (typeof a === 'number' && typeof b === 'number') {
            return Math.abs(a - b) < 0.001;
        }
        return String(a) === String(b);
    }

    /**
     * Format value for display
     */
    formatValue(value) {
        if (value === undefined || value === null) {
            return '<span class="not-present">N/A</span>';
        }
        if (typeof value === 'number') {
            return value.toLocaleString();
        }
        return this.escapeHtml(String(value));
    }

    /**
     * Setup event handlers
     */
    setupEventHandlers() {
        const tabs = this.container.querySelectorAll('.tab-btn[data-diff-tab]');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // Update active tab
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                // Show corresponding content
                const tabId = tab.dataset.diffTab;
                const contents = this.container.querySelectorAll('.diff-tab-content');
                contents.forEach(c => c.style.display = 'none');
                
                const activeContent = document.getElementById(`diff-${tabId}`);
                if (activeContent) {
                    activeContent.style.display = '';
                }
            });
        });
    }

    /**
     * Render prompt to select second file
     */
    renderSelectSecond(recordA) {
        this.container.innerHTML = `
            <div class="diff-viewer">
                <div class="diff-header">
                    <h3>Comparison View</h3>
                </div>
                <div class="empty-state">
                    <p>File A selected: ${this.escapeHtml(recordA.file_name)}</p>
                    <p class="hint">Select a second record to compare</p>
                </div>
            </div>
        `;
    }

    /**
     * Render empty state
     */
    renderEmpty() {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No files selected</p>
                <p class="hint">Select two records to compare</p>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Diff</div>
                <div class="error-state-message">${this.escapeHtml(message)}</div>
            </div>
        `;
    }

    /**
     * Escape HTML
     */
    escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }
}

// Export for use in main app
window.DiffViewComponent = DiffViewComponent;
