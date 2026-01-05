/**
 * PART 5: Hex Viewer Component
 * 
 * Displays file content in hexadecimal format with byte-accurate offsets.
 * Synchronized ASCII view with jump-to-offset from findings.
 * 
 * Note: This component displays byte data from persisted analysis.
 * It does NOT read files directly - all data via IPC.
 * 
 * Data Sources:
 * - part2.universal findings with byte offsets
 * - Highlighting based on finding.byte_offset_start/end
 */

class HexViewerComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.hexData = null;
        this.currentOffset = 0;
        this.highlightRanges = [];
        this.bytesPerRow = 16;
    }

    /**
     * Render hex viewer with sample data
     * Note: In a real implementation, byte data would come from IPC
     * For now, we display findings with their byte offsets
     * 
     * @param {object} record - Full analysis record
     * @param {array} findings - Findings with byte offsets
     */
    render(record, findings) {
        if (!record) {
            this.renderEmpty();
            return;
        }

        // Extract byte offset information from findings
        this.highlightRanges = this.extractHighlightRanges(findings || []);

        const html = `
            <div class="hex-viewer">
                <div class="hex-toolbar">
                    <div class="hex-nav">
                        <label>Jump to offset:</label>
                        <input type="text" id="hex-offset-input" 
                               placeholder="0x0000 or decimal" 
                               class="toolbar-select"
                               style="width: 120px;">
                        <button id="hex-jump-btn" class="toolbar-btn">Go</button>
                    </div>
                    <div class="hex-info">
                        <span>File Size: ${this.formatSize(record.file_size)}</span>
                    </div>
                </div>

                <div class="hex-content">
                    ${this.renderHexInfo(record, findings)}
                </div>

                ${this.highlightRanges.length > 0 ? `
                    <div class="hex-highlights">
                        <h4>Findings with Byte Offsets</h4>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Finding</th>
                                    <th>Offset Start</th>
                                    <th>Offset End</th>
                                    <th>Length</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${this.highlightRanges.map(r => `
                                    <tr class="clickable-row" data-offset="${r.start}">
                                        <td>${this.escapeHtml(r.type)}</td>
                                        <td class="value-cell">0x${r.start.toString(16).toUpperCase()}</td>
                                        <td class="value-cell">0x${r.end.toString(16).toUpperCase()}</td>
                                        <td class="value-cell">${r.end - r.start + 1}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                ` : ''}
            </div>
        `;

        this.container.innerHTML = html;
        this.setupEventHandlers();
    }

    /**
     * Render hex information panel
     * Note: Full hex dump requires actual file bytes via IPC
     */
    renderHexInfo(record, findings) {
        // Since we don't have direct file access, show what byte info is available
        const part1 = record.part1 || {};
        const part2 = record.part2 || {};

        // Get string findings with offsets
        const stringFindings = (findings || []).filter(f => 
            f.byte_offset_start !== null && f.byte_offset_start !== undefined
        );

        return `
            <div class="hex-info-panel">
                <div class="info-section">
                    <h4>File Byte Information</h4>
                    <div class="kv-list">
                        <span class="kv-key">Total Bytes</span>
                        <span class="kv-value">${record.file_size !== undefined ? record.file_size.toLocaleString() : 'N/A'}</span>
                        
                        <span class="kv-key">Findings with Offsets</span>
                        <span class="kv-value">${stringFindings.length}</span>
                    </div>
                </div>

                ${stringFindings.length > 0 ? `
                    <div class="info-section">
                        <h4>Sample Findings at Byte Offsets</h4>
                        <div class="hex-sample-list">
                            ${stringFindings.slice(0, 20).map(f => this.renderFindingHex(f)).join('')}
                        </div>
                        ${stringFindings.length > 20 ? `
                            <p class="text-muted">... and ${stringFindings.length - 20} more findings</p>
                        ` : ''}
                    </div>
                ` : `
                    <div class="info-section">
                        <p class="text-muted">No findings with byte offset information available.</p>
                        <p class="hint">Hex viewer displays byte data from persisted findings.</p>
                    </div>
                `}
            </div>
        `;
    }

    /**
     * Render a finding with hex-like display
     */
    renderFindingHex(finding) {
        const offset = finding.byte_offset_start;
        const offsetHex = offset.toString(16).toUpperCase().padStart(8, '0');
        const value = finding.extracted_value;

        // Convert value to hex if it's a string
        let hexDisplay = '';
        let asciiDisplay = '';
        
        if (typeof value === 'string') {
            const bytes = [];
            const ascii = [];
            for (let i = 0; i < Math.min(value.length, 16); i++) {
                const byte = value.charCodeAt(i);
                bytes.push(byte.toString(16).toUpperCase().padStart(2, '0'));
                ascii.push(byte >= 32 && byte < 127 ? value[i] : '.');
            }
            hexDisplay = bytes.join(' ');
            asciiDisplay = ascii.join('');
            if (value.length > 16) {
                hexDisplay += ' ...';
                asciiDisplay += '...';
            }
        }

        return `
            <div class="hex-row">
                <span class="hex-offset">${offsetHex}</span>
                <span class="hex-bytes">${hexDisplay || 'N/A'}</span>
                <span class="hex-ascii">${this.escapeHtml(asciiDisplay) || ''}</span>
            </div>
        `;
    }

    /**
     * Extract highlight ranges from findings
     */
    extractHighlightRanges(findings) {
        return findings
            .filter(f => f.byte_offset_start !== null && f.byte_offset_start !== undefined)
            .map(f => ({
                start: f.byte_offset_start,
                end: f.byte_offset_end || f.byte_offset_start,
                type: f.finding_type,
                findingId: f.finding_id
            }))
            .sort((a, b) => a.start - b.start);
    }

    /**
     * Jump to specific offset
     */
    jumpToOffset(offset) {
        this.currentOffset = offset;
        // In a full implementation, this would scroll to and highlight the offset
        console.log(`Jumping to offset: 0x${offset.toString(16)}`);
    }

    /**
     * Setup event handlers
     */
    setupEventHandlers() {
        const jumpBtn = document.getElementById('hex-jump-btn');
        const offsetInput = document.getElementById('hex-offset-input');

        if (jumpBtn && offsetInput) {
            jumpBtn.addEventListener('click', () => {
                const value = offsetInput.value.trim();
                let offset;
                
                if (value.startsWith('0x') || value.startsWith('0X')) {
                    offset = parseInt(value, 16);
                } else {
                    offset = parseInt(value, 10);
                }

                if (!isNaN(offset)) {
                    this.jumpToOffset(offset);
                }
            });

            offsetInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    jumpBtn.click();
                }
            });
        }

        // Clickable rows in highlight table
        const rows = this.container.querySelectorAll('.clickable-row');
        rows.forEach(row => {
            row.addEventListener('click', () => {
                const offset = parseInt(row.dataset.offset, 10);
                if (!isNaN(offset)) {
                    this.jumpToOffset(offset);
                }
            });
        });
    }

    /**
     * Format file size
     */
    formatSize(bytes) {
        if (bytes === undefined || bytes === null) return 'N/A';
        if (bytes === 0) return '0 bytes';
        
        const units = ['bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 2 : 0)} ${units[i]}`;
    }

    /**
     * Render empty state
     */
    renderEmpty() {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No file selected</p>
                <p class="hint">Select a record to view hex data</p>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Hex Data</div>
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
window.HexViewerComponent = HexViewerComponent;
