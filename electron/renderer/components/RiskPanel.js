/**
 * PART 5: Risk Panel Component
 * 
 * Displays risk score and severity from PART 3 analysis.
 * All data must come from IPC - no fabrication or inference.
 * 
 * Data Sources:
 * - record.risk_score (normalized 0-100)
 * - record.severity (INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL)
 * - part3.risk_score.score_contributions
 * - part3.risk_score.explanation
 */

class RiskPanelComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.currentRecord = null;
    }

    /**
     * Render risk panel from record data
     * @param {object} record - Full analysis record from get_record IPC
     */
    render(record) {
        if (!record) {
            this.renderEmpty();
            return;
        }

        this.currentRecord = record;

        const part3 = record.part3 || {};
        const riskScore = part3.risk_score || {};
        const heuristics = part3.heuristics || {};

        const score = record.risk_score;
        const severity = record.severity || 'informational';
        const explanation = riskScore.explanation || '';
        const contributions = riskScore.score_contributions || [];

        const html = `
            <div class="risk-panel">
                <section class="overview-section">
                    <h3>Risk Assessment</h3>
                    
                    <div class="risk-score-display">
                        <div class="risk-score-value ${severity}">${this.formatScore(score)}</div>
                        <div class="risk-score-meta">
                            <span class="severity-badge ${severity}">${this.escapeHtml(severity.toUpperCase())}</span>
                            <span class="text-muted">/100</span>
                        </div>
                    </div>

                    <div class="risk-score-bar">
                        <div class="risk-score-fill bg-severity-${severity}" 
                             style="width: ${Math.min(100, Math.max(0, score || 0))}%"></div>
                    </div>

                    ${explanation ? `
                        <div class="risk-explanation">
                            <h4>Explanation</h4>
                            <p>${this.escapeHtml(explanation)}</p>
                        </div>
                    ` : ''}
                </section>

                <section class="overview-section">
                    <h3>Score Contributions</h3>
                    ${this.renderContributions(contributions)}
                </section>

                <section class="overview-section">
                    <h3>Heuristics Summary</h3>
                    ${this.renderHeuristicsSummary(heuristics)}
                </section>

                <section class="overview-section">
                    <h3>Analysis Summary</h3>
                    ${this.renderSummary(part3.summary)}
                </section>
            </div>
        `;

        this.container.innerHTML = html;
    }

    /**
     * Render score contributions table
     */
    renderContributions(contributions) {
        if (!contributions || contributions.length === 0) {
            return `<div class="empty-state"><p>No score contributions</p></div>`;
        }

        const rows = contributions.map(c => `
            <tr>
                <td>${this.escapeHtml(c.source_name || c.source_id || 'Unknown')}</td>
                <td>${this.escapeHtml(c.source_type || 'Unknown')}</td>
                <td>${this.formatNumber(c.weighted_score)}</td>
                <td><span class="severity-badge ${c.severity || 'informational'}">${this.escapeHtml((c.severity || 'info').toUpperCase())}</span></td>
            </tr>
        `).join('');

        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Type</th>
                        <th>Score</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;
    }

    /**
     * Render heuristics summary from PART 3
     */
    renderHeuristicsSummary(heuristics) {
        const triggered = heuristics.triggered_heuristics || [];
        const failed = heuristics.failed_heuristics || [];

        return `
            <div class="kv-list">
                <span class="kv-key">Total Evaluated</span>
                <span class="kv-value">${(heuristics.total_evaluated !== undefined) ? heuristics.total_evaluated : this.renderMissing('total_evaluated')}</span>
                
                <span class="kv-key">Triggered</span>
                <span class="kv-value severity-${triggered.length > 0 ? 'high' : 'low'}">${triggered.length}</span>
                
                <span class="kv-key">Not Triggered</span>
                <span class="kv-value">${failed.length}</span>
            </div>

            ${triggered.length > 0 ? `
                <h4 style="margin-top: 16px;">Triggered Heuristics</h4>
                <ul class="triggered-list">
                    ${triggered.map(h => `
                        <li class="finding-item severity-${h.severity || 'medium'}">
                            <div class="finding-header">
                                <span class="finding-type">${this.escapeHtml(h.name || h.heuristic_key)}</span>
                                <span class="severity-badge ${h.severity || 'medium'}">${this.escapeHtml((h.severity || 'medium').toUpperCase())}</span>
                            </div>
                            <div class="finding-value">${this.escapeHtml(h.explanation || h.description || '')}</div>
                        </li>
                    `).join('')}
                </ul>
            ` : ''}
        `;
    }

    /**
     * Render analysis summary from PART 3
     */
    renderSummary(summary) {
        if (!summary) {
            return `<div class="empty-state"><p>No summary available</p></div>`;
        }

        return `
            <div class="kv-list">
                <span class="kv-key">Recommendation</span>
                <span class="kv-value">${this.escapeHtml(summary.recommendation) || this.renderNotPresent()}</span>
                
                <span class="kv-key">Total Findings</span>
                <span class="kv-value">${summary.total_findings !== undefined ? summary.total_findings : this.renderMissing('total_findings')}</span>
                
                <span class="kv-key">YARA Matches</span>
                <span class="kv-value">${summary.yara_matches !== undefined ? summary.yara_matches : this.renderMissing('yara_matches')}</span>
                
                <span class="kv-key">Heuristics Triggered</span>
                <span class="kv-value">${summary.heuristics_triggered !== undefined ? summary.heuristics_triggered : this.renderMissing('heuristics_triggered')}</span>
                
                <span class="kv-key">Analysis Complete</span>
                <span class="kv-value">${summary.analysis_complete !== undefined ? (summary.analysis_complete ? 'Yes' : 'No') : this.renderMissing('analysis_complete')}</span>
            </div>
        `;
    }

    /**
     * Format score value
     */
    formatScore(score) {
        if (score === undefined || score === null) {
            return '--';
        }
        return Number(score).toFixed(1);
    }

    /**
     * Format number
     */
    formatNumber(num) {
        if (num === undefined || num === null) return '--';
        return Number(num).toFixed(2);
    }

    /**
     * Render empty state
     */
    renderEmpty() {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No file selected</p>
                <p class="hint">Select a record to view risk assessment</p>
            </div>
        `;
    }

    /**
     * Render error state - errors must be visible
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Risk Data</div>
                <div class="error-state-message">${this.escapeHtml(message)}</div>
            </div>
        `;
    }

    /**
     * Render missing field indicator
     */
    renderMissing(fieldName) {
        return `<span class="kv-value missing">Missing: ${this.escapeHtml(fieldName)}</span>`;
    }

    /**
     * Render not present indicator
     */
    renderNotPresent() {
        return `<span class="kv-value not-present">NOT_PRESENT</span>`;
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
window.RiskPanelComponent = RiskPanelComponent;
