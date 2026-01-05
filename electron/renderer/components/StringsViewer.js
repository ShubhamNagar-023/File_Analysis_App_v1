/**
 * PART 5: Strings Viewer Component
 * 
 * Displays classified strings (URLs, IPs, emails, paths, commands) from PART 2.
 * Offset navigation to hex viewer.
 * 
 * Data Sources:
 * - part2.universal findings for string data
 * - list_findings IPC with type filters
 */

class StringsViewerComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.strings = [];
        this.filter = 'all';
        this.onOffsetClick = null;
    }

    /**
     * Render strings viewer
     * @param {array} findings - Findings array from list_findings IPC
     */
    render(findings) {
        if (!findings || findings.length === 0) {
            this.renderEmpty();
            return;
        }

        // Filter to string-type findings
        this.strings = this.extractStrings(findings);

        if (this.strings.length === 0) {
            this.renderEmpty();
            return;
        }

        // Group by classification
        const groups = this.groupByClassification(this.strings);

        const html = `
            <div class="strings-viewer">
                <div class="strings-toolbar">
                    <label>Filter:</label>
                    <select id="strings-filter" class="toolbar-select">
                        <option value="all">All (${this.strings.length})</option>
                        ${Object.entries(groups).map(([type, items]) => 
                            `<option value="${this.escapeHtml(type)}">${this.escapeHtml(type)} (${items.length})</option>`
                        ).join('')}
                    </select>
                </div>

                <div class="strings-content" id="strings-content">
                    ${this.renderStrings(this.strings)}
                </div>
            </div>
        `;

        this.container.innerHTML = html;
        this.setupEventHandlers();
    }

    /**
     * Extract string findings
     */
    extractStrings(findings) {
        // Filter findings that have string-like extracted values
        return findings.filter(f => {
            const value = f.extracted_value;
            return typeof value === 'string' && value.length > 0;
        }).map(f => ({
            findingId: f.finding_id,
            type: f.finding_type,
            classification: this.classifyString(f),
            value: f.extracted_value,
            offset: f.byte_offset_start,
            offsetEnd: f.byte_offset_end,
            confidence: f.confidence
        }));
    }

    /**
     * Classify a string finding
     */
    classifyString(finding) {
        const type = (finding.finding_type || '').toLowerCase();
        const value = String(finding.extracted_value || '');

        // URL patterns
        if (type.includes('url') || /^https?:\/\//i.test(value)) {
            return 'URL';
        }

        // IP address patterns
        if (type.includes('ip') || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(value)) {
            return 'IP Address';
        }

        // Email patterns
        if (type.includes('email') || /@[\w.-]+\.\w+/.test(value)) {
            return 'Email';
        }

        // Path patterns
        if (type.includes('path') || /^[\/\\]|^[A-Z]:\\/.test(value)) {
            return 'Path';
        }

        // Command patterns
        if (type.includes('command') || type.includes('shell')) {
            return 'Command';
        }

        // Hash patterns
        if (/^[a-f0-9]{32}$/i.test(value) || /^[a-f0-9]{40}$/i.test(value) || /^[a-f0-9]{64}$/i.test(value)) {
            return 'Hash';
        }

        return 'Other';
    }

    /**
     * Group strings by classification
     */
    groupByClassification(strings) {
        const groups = {};
        for (const s of strings) {
            if (!groups[s.classification]) {
                groups[s.classification] = [];
            }
            groups[s.classification].push(s);
        }
        return groups;
    }

    /**
     * Render strings list
     */
    renderStrings(strings) {
        if (strings.length === 0) {
            return '<div class="empty-state"><p>No strings found</p></div>';
        }

        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Classification</th>
                        <th>Value</th>
                        <th>Offset</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    ${strings.map(s => `
                        <tr data-finding-id="${this.escapeHtml(s.findingId || '')}"
                            data-classification="${this.escapeHtml(s.classification)}">
                            <td>
                                <span class="classification-badge ${this.getClassificationClass(s.classification)}">
                                    ${this.escapeHtml(s.classification)}
                                </span>
                            </td>
                            <td class="value-cell">${this.formatValue(s.value)}</td>
                            <td>
                                ${s.offset !== null && s.offset !== undefined ? `
                                    <span class="finding-offset" 
                                          data-offset="${s.offset}"
                                          title="Click to jump to offset">
                                        0x${s.offset.toString(16).toUpperCase()}
                                    </span>
                                ` : '<span class="not-present">N/A</span>'}
                            </td>
                            <td>
                                <span class="confidence-badge severity-${this.confidenceToSeverity(s.confidence)}">
                                    ${this.escapeHtml(s.confidence || 'N/A')}
                                </span>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    /**
     * Get classification CSS class
     */
    getClassificationClass(classification) {
        const classes = {
            'URL': 'severity-medium',
            'IP Address': 'severity-high',
            'Email': 'severity-medium',
            'Path': 'severity-low',
            'Command': 'severity-high',
            'Hash': 'severity-low',
            'Other': 'severity-informational'
        };
        return classes[classification] || 'severity-informational';
    }

    /**
     * Format value for display
     */
    formatValue(value) {
        if (!value) return '<span class="not-present">NOT_PRESENT</span>';
        
        const str = String(value);
        if (str.length > 100) {
            return this.escapeHtml(str.substring(0, 100)) + '...';
        }
        return this.escapeHtml(str);
    }

    /**
     * Map confidence to severity
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
     * Setup event handlers
     */
    setupEventHandlers() {
        // Filter dropdown
        const filterSelect = document.getElementById('strings-filter');
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                this.filter = e.target.value;
                this.applyFilter();
            });
        }

        // Offset click handlers
        const offsetElements = this.container.querySelectorAll('.finding-offset');
        offsetElements.forEach(el => {
            el.addEventListener('click', () => {
                const offset = parseInt(el.dataset.offset, 10);
                if (this.onOffsetClick && !isNaN(offset)) {
                    this.onOffsetClick(offset);
                }
            });
        });
    }

    /**
     * Apply filter to visible rows
     */
    applyFilter() {
        const rows = this.container.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (this.filter === 'all' || row.dataset.classification === this.filter) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    /**
     * Set callback for offset clicks
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
                <p>No strings found</p>
                <p class="hint">No string findings available for this file</p>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Strings</div>
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
window.StringsViewerComponent = StringsViewerComponent;
