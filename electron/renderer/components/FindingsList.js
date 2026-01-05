/**
 * PART 5: Findings List Component
 * 
 * Displays PART 2 findings from deep static analysis.
 * All data must come from IPC - no fabrication or inference.
 * 
 * Data Sources:
 * - list_findings IPC endpoint
 * - finding.finding_type, byte_offset_start, byte_offset_end
 * - finding.confidence, extracted_value
 */

class FindingsListComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.findings = [];
        this.onOffsetClick = null; // Callback for jumping to offset
    }

    /**
     * Render findings list
     * @param {array} findings - Array of findings from list_findings IPC
     */
    render(findings) {
        if (!findings || findings.length === 0) {
            this.renderEmpty();
            return;
        }

        this.findings = findings;

        // Group findings by type
        const grouped = this.groupByType(findings);

        const html = `
            <div class="findings-list">
                <div class="findings-header">
                    <h3>Findings (${findings.length})</h3>
                </div>
                <div class="findings-content">
                    ${Object.entries(grouped).map(([type, items]) => this.renderGroup(type, items)).join('')}
                </div>
            </div>
        `;

        this.container.innerHTML = html;

        // Setup offset click handlers
        this.setupOffsetClickHandlers();
    }

    /**
     * Group findings by type
     */
    groupByType(findings) {
        const grouped = {};
        for (const finding of findings) {
            const type = finding.finding_type || 'Unknown';
            if (!grouped[type]) {
                grouped[type] = [];
            }
            grouped[type].push(finding);
        }
        return grouped;
    }

    /**
     * Render a group of findings
     */
    renderGroup(type, findings) {
        return `
            <div class="finding-group">
                <h4 class="finding-group-title">${this.escapeHtml(type)} (${findings.length})</h4>
                ${findings.map(f => this.renderFinding(f)).join('')}
            </div>
        `;
    }

    /**
     * Render individual finding
     */
    renderFinding(finding) {
        const hasOffset = finding.byte_offset_start !== null && finding.byte_offset_start !== undefined;
        const confidence = finding.confidence || 'LOW';

        return `
            <div class="finding-item severity-${this.confidenceToSeverity(confidence)}" 
                 data-finding-id="${this.escapeHtml(finding.finding_id || '')}">
                <div class="finding-header">
                    <span class="finding-type">${this.escapeHtml(finding.finding_type)}</span>
                    <span class="confidence-badge severity-${this.confidenceToSeverity(confidence)}">${confidence}</span>
                </div>
                
                ${hasOffset ? `
                    <div class="finding-offset" 
                         data-offset="${finding.byte_offset_start}"
                         data-offset-end="${finding.byte_offset_end || finding.byte_offset_start}"
                         title="Click to jump to offset">
                        Offset: 0x${finding.byte_offset_start.toString(16).toUpperCase()} 
                        (${finding.byte_offset_start})
                        ${finding.byte_offset_end && finding.byte_offset_end !== finding.byte_offset_start 
                            ? ` - 0x${finding.byte_offset_end.toString(16).toUpperCase()}` 
                            : ''}
                    </div>
                ` : ''}

                ${finding.extracted_value !== null && finding.extracted_value !== undefined ? `
                    <div class="finding-value">
                        ${this.renderExtractedValue(finding.extracted_value)}
                    </div>
                ` : ''}

                <div class="finding-meta">
                    <span>ID: ${this.escapeHtml(finding.finding_id || 'N/A')}</span>
                    <span>Type: ${this.escapeHtml(finding.semantic_file_type || 'N/A')}</span>
                </div>
            </div>
        `;
    }

    /**
     * Render extracted value based on type
     */
    renderExtractedValue(value) {
        if (value === null || value === undefined) {
            return '<span class="not-present">NOT_PRESENT</span>';
        }

        if (typeof value === 'object') {
            return `<pre>${this.escapeHtml(JSON.stringify(value, null, 2))}</pre>`;
        }

        // Truncate long values
        const strValue = String(value);
        if (strValue.length > 500) {
            return `${this.escapeHtml(strValue.substring(0, 500))}... (truncated)`;
        }

        return this.escapeHtml(strValue);
    }

    /**
     * Map confidence to severity class
     */
    confidenceToSeverity(confidence) {
        const map = {
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        };
        return map[confidence] || 'informational';
    }

    /**
     * Setup click handlers for offset navigation
     */
    setupOffsetClickHandlers() {
        const offsetElements = this.container.querySelectorAll('.finding-offset');
        offsetElements.forEach(el => {
            el.addEventListener('click', () => {
                const offset = parseInt(el.dataset.offset, 10);
                const offsetEnd = parseInt(el.dataset.offsetEnd, 10);
                if (this.onOffsetClick && !isNaN(offset)) {
                    this.onOffsetClick(offset, offsetEnd);
                }
            });
        });
    }

    /**
     * Set callback for offset clicks (for hex viewer navigation)
     */
    setOffsetClickHandler(callback) {
        this.onOffsetClick = callback;
    }

    /**
     * Render empty state
     */
    renderEmpty() {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No findings</p>
                <p class="hint">No findings available for this file</p>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Findings</div>
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
window.FindingsListComponent = FindingsListComponent;
