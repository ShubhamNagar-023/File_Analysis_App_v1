/**
 * PART 5: Metadata Explorer Component
 * 
 * Displays file metadata from PART 1 analysis.
 * Renders only file-type-valid metadata with clear indication
 * of NOT_PRESENT vs UNSUPPORTED.
 * 
 * Data Sources:
 * - part1.filesystem_metadata
 * - part1.extension_analysis
 * - part1.magic_detection
 * - part1.advanced_checks
 */

class MetadataExplorerComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.currentRecord = null;
        this.searchTerm = '';
    }

    /**
     * Render metadata explorer from record data
     * @param {object} record - Full analysis record from get_record IPC
     */
    render(record) {
        if (!record) {
            this.renderEmpty();
            return;
        }

        this.currentRecord = record;

        const part1 = record.part1 || {};
        const fsMetadata = part1.filesystem_metadata || {};
        const extAnalysis = part1.extension_analysis || {};
        const magicDetection = part1.magic_detection || {};
        const advancedChecks = part1.advanced_checks || {};
        const ingestion = part1.ingestion || {};

        const html = `
            <div class="metadata-explorer">
                <div class="metadata-search">
                    <input type="text" 
                           id="metadata-search-input" 
                           placeholder="Filter metadata..." 
                           class="toolbar-select"
                           aria-label="Filter metadata fields">
                </div>

                <div class="metadata-sections" id="metadata-sections">
                    ${this.renderFilesystemMetadata(fsMetadata)}
                    ${this.renderExtensionAnalysis(extAnalysis)}
                    ${this.renderMagicDetection(magicDetection)}
                    ${this.renderIngestion(ingestion)}
                    ${this.renderAdvancedChecks(advancedChecks)}
                </div>
            </div>
        `;

        this.container.innerHTML = html;

        // Setup search filter
        const searchInput = document.getElementById('metadata-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filterMetadata(e.target.value);
            });
        }
    }

    /**
     * Render filesystem metadata section
     */
    renderFilesystemMetadata(fsMetadata) {
        const output = fsMetadata.output_value || {};
        const timestamps = output.timestamps || {};

        return `
            <section class="metadata-section" data-section="filesystem">
                <h3>Filesystem Metadata</h3>
                <div class="kv-list">
                    ${this.renderKVPair('Modified', timestamps.modified)}
                    ${this.renderKVPair('Accessed', timestamps.accessed)}
                    ${this.renderKVPair('Created/Changed', timestamps.created_or_changed)}
                    ${this.renderKVPair('Permissions (Octal)', output.permissions?.mode_octal)}
                    ${this.renderKVPair('Is Readable', output.permissions?.is_readable)}
                    ${this.renderKVPair('Is Writable', output.permissions?.is_writable)}
                    ${this.renderKVPair('Is Executable', output.permissions?.is_executable)}
                    ${this.renderKVPair('Owner UID', output.ownership?.uid)}
                    ${this.renderKVPair('Owner GID', output.ownership?.gid)}
                    ${this.renderKVPair('Owner Name', output.ownership?.user_name)}
                    ${this.renderKVPair('Group Name', output.ownership?.group_name)}
                    ${this.renderKVPair('NTFS ADS Status', output.ntfs_alternate_data_streams?.status)}
                </div>
            </section>
        `;
    }

    /**
     * Render extension analysis section
     */
    renderExtensionAnalysis(extAnalysis) {
        const output = extAnalysis.output_value || {};
        const extensionChain = output.extension_chain || [];
        const unicodeDeception = output.unicode_deception || [];

        return `
            <section class="metadata-section" data-section="extension">
                <h3>Extension Analysis</h3>
                <div class="kv-list">
                    ${this.renderKVPair('Raw Filename', output.raw_filename)}
                    ${this.renderKVPair('Primary Extension', output.primary_extension)}
                    ${this.renderKVPair('Extension Chain', extensionChain.join(' → ') || 'None')}
                    ${this.renderKVPair('Has Double Extension', output.has_double_extension)}
                    ${this.renderKVPair('Extension Mismatch', output.extension_mismatch)}
                    ${this.renderKVPair('Expected Extensions', (output.expected_extensions || []).join(', ') || 'N/A')}
                </div>

                ${unicodeDeception.length > 0 ? `
                    <h4>Unicode Deception Detected</h4>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Character</th>
                                <th>Codepoint</th>
                                <th>Description</th>
                                <th>Byte Offset</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${unicodeDeception.map(d => `
                                <tr>
                                    <td class="value-cell">${this.escapeHtml(d.character)}</td>
                                    <td class="value-cell">${this.escapeHtml(d.codepoint)}</td>
                                    <td>${this.escapeHtml(d.description)}</td>
                                    <td class="value-cell">${d.byte_offset}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : ''}
            </section>
        `;
    }

    /**
     * Render magic detection section
     */
    renderMagicDetection(magicDetection) {
        const output = magicDetection.output_value || {};
        const signatures = output.signatures || [];
        const scanCoverage = output.scan_coverage || {};

        return `
            <section class="metadata-section" data-section="magic">
                <h3>Magic Byte Detection</h3>
                <div class="kv-list">
                    ${this.renderKVPair('Python-Magic MIME', output.python_magic_mime)}
                    ${this.renderKVPair('Python-Magic Type', output.python_magic_type)}
                    ${this.renderKVPair('Signatures Found', signatures.length)}
                    ${this.renderKVPair('Polyglot Indicators', (output.polyglot_indicators || []).length > 0 ? 'Yes' : 'No')}
                    ${this.renderKVPair('Scan Strategy', scanCoverage.scan_strategy)}
                    ${this.renderKVPair('Offsets Scanned', scanCoverage.total_offsets_scanned)}
                    ${this.renderKVPair('Coverage %', scanCoverage.coverage_percentage)}
                </div>

                ${signatures.length > 0 ? `
                    <h4>Detected Signatures</h4>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Signature Type</th>
                                <th>Offset</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${signatures.map(s => `
                                <tr>
                                    <td>${this.escapeHtml(s.signature_type)}</td>
                                    <td class="value-cell">${s.offset}</td>
                                    <td>${this.escapeHtml(s.description)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : ''}
            </section>
        `;
    }

    /**
     * Render ingestion section
     */
    renderIngestion(ingestion) {
        const output = ingestion.output_value || {};

        return `
            <section class="metadata-section" data-section="ingestion">
                <h3>File Ingestion</h3>
                <div class="kv-list">
                    ${this.renderKVPair('Status', output.status)}
                    ${this.renderKVPair('Expected Size', output.expected_size_bytes)}
                    ${this.renderKVPair('Actual Size', output.actual_size_bytes)}
                    ${this.renderKVPair('Size Match', output.size_match)}
                    ${this.renderKVPair('Is Truncated', output.is_truncated)}
                    ${this.renderKVPair('Is Symlink', output.is_symlink)}
                    ${this.renderKVPair('Is Hard Linked', output.is_hard_linked)}
                    ${this.renderKVPair('Hard Link Count', output.hard_link_count)}
                    ${this.renderKVPair('Is Sparse', output.is_sparse)}
                </div>
            </section>
        `;
    }

    /**
     * Render advanced checks section
     */
    renderAdvancedChecks(advancedChecks) {
        const output = advancedChecks.output_value || {};
        const checks = output.checks || [];

        return `
            <section class="metadata-section" data-section="advanced">
                <h3>Advanced Checks</h3>
                ${checks.length > 0 ? `
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Check</th>
                                <th>Result</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${checks.map(c => `
                                <tr>
                                    <td>${this.escapeHtml(c.check_name)}</td>
                                    <td class="${c.passed ? 'severity-low' : 'severity-high'}">${c.passed ? 'PASS' : 'FAIL'}</td>
                                    <td>${this.escapeHtml(c.details || c.message || '')}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : '<div class="empty-state"><p>No advanced checks available</p></div>'}
            </section>
        `;
    }

    /**
     * Render key-value pair with proper handling of missing/undefined
     */
    renderKVPair(key, value) {
        let displayValue;
        
        if (value === undefined) {
            displayValue = '<span class="kv-value not-present">NOT_PRESENT</span>';
        } else if (value === null) {
            displayValue = '<span class="kv-value not-present">null</span>';
        } else if (typeof value === 'boolean') {
            displayValue = value ? 'Yes' : 'No';
        } else {
            displayValue = this.escapeHtml(String(value));
        }

        return `
            <span class="kv-key" data-key="${this.escapeHtml(key.toLowerCase())}">${this.escapeHtml(key)}</span>
            <span class="kv-value">${displayValue}</span>
        `;
    }

    /**
     * Filter metadata by search term
     */
    filterMetadata(searchTerm) {
        this.searchTerm = searchTerm.toLowerCase();
        const sections = document.getElementById('metadata-sections');
        if (!sections) return;

        const kvPairs = sections.querySelectorAll('.kv-key');
        kvPairs.forEach(key => {
            const keyText = key.textContent.toLowerCase();
            const valueEl = key.nextElementSibling;
            const valueText = valueEl ? valueEl.textContent.toLowerCase() : '';
            
            const visible = !this.searchTerm || 
                           keyText.includes(this.searchTerm) || 
                           valueText.includes(this.searchTerm);
            
            key.style.display = visible ? '' : 'none';
            if (valueEl) valueEl.style.display = visible ? '' : 'none';
        });
    }

    /**
     * Render empty state
     */
    renderEmpty() {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No file selected</p>
                <p class="hint">Select a record to view metadata</p>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Metadata</div>
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
window.MetadataExplorerComponent = MetadataExplorerComponent;
