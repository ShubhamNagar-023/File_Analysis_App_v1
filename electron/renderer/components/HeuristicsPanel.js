/**
 * PART 5: Heuristics Panel Component
 * 
 * Displays PART 3 heuristic results with explanations.
 * All data must come from IPC - no fabrication or inference.
 * 
 * Data Sources:
 * - list_heuristics IPC endpoint
 * - heuristic.name, triggered, severity, confidence
 * - heuristic.weight, explanation
 */

class HeuristicsPanelComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.heuristics = [];
        this.showTriggeredOnly = false;
    }

    /**
     * Render heuristics panel
     * @param {array} heuristics - Array of heuristics from list_heuristics IPC
     */
    render(heuristics) {
        if (!heuristics || heuristics.length === 0) {
            this.renderEmpty();
            return;
        }

        this.heuristics = heuristics;

        const triggered = heuristics.filter(h => h.triggered);
        const notTriggered = heuristics.filter(h => !h.triggered);

        const html = `
            <div class="heuristics-panel">
                <div class="heuristics-header">
                    <h3>Heuristics</h3>
                    <div class="heuristics-stats">
                        <span class="severity-high">${triggered.length} triggered</span>
                        <span class="text-muted">${notTriggered.length} not triggered</span>
                    </div>
                </div>
                
                <div class="heuristics-filter">
                    <label>
                        <input type="checkbox" id="triggered-only-checkbox" 
                               ${this.showTriggeredOnly ? 'checked' : ''}>
                        Show triggered only
                    </label>
                </div>

                <div class="heuristics-content">
                    ${triggered.length > 0 ? `
                        <div class="heuristics-group">
                            <h4 class="heuristics-group-title severity-high">Triggered (${triggered.length})</h4>
                            ${triggered.map(h => this.renderHeuristic(h)).join('')}
                        </div>
                    ` : ''}

                    <div class="heuristics-group not-triggered-group" 
                         style="${this.showTriggeredOnly ? 'display: none;' : ''}">
                        <h4 class="heuristics-group-title">Not Triggered (${notTriggered.length})</h4>
                        ${notTriggered.map(h => this.renderHeuristic(h)).join('')}
                    </div>
                </div>
            </div>
        `;

        this.container.innerHTML = html;

        // Setup filter handler
        const checkbox = document.getElementById('triggered-only-checkbox');
        if (checkbox) {
            checkbox.addEventListener('change', (e) => {
                this.showTriggeredOnly = e.target.checked;
                const notTriggeredGroup = this.container.querySelector('.not-triggered-group');
                if (notTriggeredGroup) {
                    notTriggeredGroup.style.display = this.showTriggeredOnly ? 'none' : '';
                }
            });
        }
    }

    /**
     * Render individual heuristic
     */
    renderHeuristic(heuristic) {
        const triggered = heuristic.triggered;
        const severity = heuristic.severity || 'informational';

        return `
            <div class="heuristic-item ${triggered ? 'triggered' : 'not-triggered'}"
                 data-heuristic-id="${this.escapeHtml(heuristic.heuristic_id || '')}">
                <div class="heuristic-name">
                    ${this.escapeHtml(heuristic.name || heuristic.heuristic_key || 'Unknown')}
                </div>
                
                <div class="heuristic-meta">
                    <span class="severity-badge ${severity}">${severity.toUpperCase()}</span>
                    <span title="Confidence">${this.escapeHtml(heuristic.confidence || 'N/A')}</span>
                    <span title="Weight">Weight: ${heuristic.weight !== undefined ? heuristic.weight : 'N/A'}</span>
                </div>

                ${heuristic.explanation ? `
                    <div class="heuristic-explanation">
                        ${this.escapeHtml(heuristic.explanation)}
                    </div>
                ` : ''}

                ${heuristic.trigger_conditions && heuristic.trigger_conditions.length > 0 ? `
                    <div class="heuristic-conditions">
                        <strong>Conditions:</strong>
                        <ul>
                            ${heuristic.trigger_conditions.map(c => `<li>${this.escapeHtml(c)}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}

                ${heuristic.evidence_references && heuristic.evidence_references.length > 0 ? `
                    <div class="heuristic-evidence">
                        <strong>Evidence:</strong>
                        <ul>
                            ${heuristic.evidence_references.map(e => `<li>${this.escapeHtml(e)}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
    }

    /**
     * Render empty state
     */
    renderEmpty() {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No heuristics</p>
                <p class="hint">No heuristic results available</p>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Heuristics</div>
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
window.HeuristicsPanelComponent = HeuristicsPanelComponent;
