/**
 * PART 5: Archive Tree Component
 * 
 * Displays hierarchical structure of archive/container files.
 * Nested containers with depth limiting.
 * 
 * Data Sources:
 * - part2.container_level findings
 * - Container entry list from analysis
 */

class ArchiveTreeComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.entries = [];
        this.expandedNodes = new Set();
    }

    /**
     * Render archive tree from record data
     * @param {object} record - Full analysis record
     */
    render(record) {
        if (!record) {
            this.renderEmpty();
            return;
        }

        const part2 = record.part2 || {};
        const containerLevel = part2.container_level || [];
        
        // Extract container entries
        this.entries = this.extractContainerEntries(containerLevel);

        if (this.entries.length === 0) {
            this.renderNoContainer(record);
            return;
        }

        const html = `
            <div class="archive-tree">
                <div class="archive-header">
                    <h3>Container Contents</h3>
                    <div class="archive-stats">
                        <span>${this.entries.length} entries</span>
                    </div>
                </div>
                <div class="tree-view">
                    ${this.renderTreeNodes(this.entries)}
                </div>
            </div>
        `;

        this.container.innerHTML = html;
        this.setupEventHandlers();
    }

    /**
     * Extract container entries from PART 2 findings
     */
    extractContainerEntries(containerLevel) {
        const entries = [];

        for (const finding of containerLevel) {
            const extracted = finding.extracted_value;
            
            if (finding.finding_type === 'zip_contents' && extracted?.entries) {
                for (const entry of extracted.entries) {
                    entries.push({
                        type: 'zip',
                        name: entry.filename,
                        size: entry.file_size,
                        compressedSize: entry.compress_size,
                        isDir: entry.filename.endsWith('/'),
                        path: entry.filename
                    });
                }
            } else if (finding.finding_type === 'ole_streams' && extracted?.streams) {
                for (const stream of extracted.streams) {
                    entries.push({
                        type: 'ole',
                        name: stream.name,
                        size: stream.size,
                        isDir: false,
                        path: stream.name
                    });
                }
            } else if (finding.finding_type === 'ole_metadata' && extracted) {
                // OLE metadata is a single entry
                entries.push({
                    type: 'ole_meta',
                    name: 'OLE Metadata',
                    metadata: extracted,
                    isDir: false,
                    path: '_metadata'
                });
            }
        }

        return entries;
    }

    /**
     * Build tree structure from flat entries
     */
    buildTree(entries) {
        const root = { name: 'root', children: {}, entries: [] };

        for (const entry of entries) {
            const parts = entry.path.split(/[\/\\]/).filter(p => p);
            let current = root;

            for (let i = 0; i < parts.length; i++) {
                const part = parts[i];
                const isLast = i === parts.length - 1;

                if (!current.children[part]) {
                    current.children[part] = {
                        name: part,
                        children: {},
                        entries: [],
                        isDir: !isLast || entry.isDir
                    };
                }

                if (isLast && !entry.isDir) {
                    current.children[part].entry = entry;
                }

                current = current.children[part];
            }
        }

        return root;
    }

    /**
     * Render tree nodes
     */
    renderTreeNodes(entries) {
        if (entries.length === 0) {
            return '<div class="empty-state"><p>No entries</p></div>';
        }

        // Build and render tree
        const tree = this.buildTree(entries);
        return this.renderNode(tree, 0);
    }

    /**
     * Render a single tree node
     */
    renderNode(node, depth) {
        if (depth > 10) {
            return '<div class="text-muted">... (depth limit reached)</div>';
        }

        const children = Object.values(node.children);
        if (children.length === 0 && !node.entry) {
            return '';
        }

        let html = '';

        for (const child of children) {
            const hasChildren = Object.keys(child.children).length > 0;
            const isExpanded = this.expandedNodes.has(child.name);
            const icon = child.isDir ? '📁' : this.getFileIcon(child.name);

            html += `
                <div class="tree-item" data-path="${this.escapeHtml(child.name)}" data-depth="${depth}">
                    <div class="tree-item-row">
                        <span class="tree-toggle">${hasChildren ? (isExpanded ? '▼' : '▶') : ''}</span>
                        <span class="tree-icon">${icon}</span>
                        <span class="tree-label">${this.escapeHtml(child.name)}</span>
                        ${child.entry ? `
                            <span class="tree-size">${this.formatSize(child.entry.size)}</span>
                        ` : ''}
                    </div>
                    ${hasChildren ? `
                        <div class="tree-children" style="${isExpanded ? '' : 'display: none;'}">
                            ${this.renderNode(child, depth + 1)}
                        </div>
                    ` : ''}
                </div>
            `;
        }

        return html;
    }

    /**
     * Get icon for file type
     */
    getFileIcon(filename) {
        const ext = (filename.split('.').pop() || '').toLowerCase();
        const icons = {
            'txt': '📄',
            'xml': '📋',
            'json': '📋',
            'bin': '💾',
            'exe': '⚙️',
            'dll': '⚙️',
            'py': '🐍',
            'js': '📜',
            'vba': '📜',
            'doc': '📝',
            'docx': '📝',
            'xls': '📊',
            'xlsx': '📊',
            'pdf': '📕',
            'png': '🖼️',
            'jpg': '🖼️',
            'jpeg': '🖼️',
            'gif': '🖼️',
            'zip': '📦',
            'rar': '📦'
        };
        return icons[ext] || '📄';
    }

    /**
     * Format file size
     */
    formatSize(bytes) {
        if (bytes === undefined || bytes === null) return '';
        if (bytes === 0) return '0 B';
        
        const units = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
    }

    /**
     * Setup event handlers
     */
    setupEventHandlers() {
        const toggles = this.container.querySelectorAll('.tree-toggle');
        toggles.forEach(toggle => {
            toggle.addEventListener('click', (e) => {
                const item = e.target.closest('.tree-item');
                const children = item.querySelector('.tree-children');
                const path = item.dataset.path;

                if (children) {
                    const isVisible = children.style.display !== 'none';
                    children.style.display = isVisible ? 'none' : '';
                    e.target.textContent = isVisible ? '▶' : '▼';

                    if (isVisible) {
                        this.expandedNodes.delete(path);
                    } else {
                        this.expandedNodes.add(path);
                    }
                }
            });
        });
    }

    /**
     * Render state for non-container file
     */
    renderNoContainer(record) {
        const semanticType = record.semantic_file_type || 'Unknown';
        
        this.container.innerHTML = `
            <div class="empty-state">
                <p>Not a container file</p>
                <p class="hint">File type: ${this.escapeHtml(semanticType)}</p>
                <p class="text-muted">This view is for archive and container formats (ZIP, OLE, etc.)</p>
            </div>
        `;
    }

    /**
     * Render empty state
     */
    renderEmpty() {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No file selected</p>
                <p class="hint">Select a container file to view its structure</p>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Container</div>
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
window.ArchiveTreeComponent = ArchiveTreeComponent;
