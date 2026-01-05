/**
 * PART 5: Timeline Component
 * 
 * Displays filesystem timestamps and analysis timeline.
 * All data must come from IPC - no fabrication.
 * 
 * Data Sources:
 * - get_timeline IPC endpoint
 * - part1.filesystem_metadata.timestamps
 * - Analysis event timestamps from records
 */

class TimelineComponent {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.events = [];
    }

    /**
     * Render timeline from record and timeline data
     * @param {object} record - Full analysis record
     * @param {array} timeline - Timeline events from get_timeline IPC
     */
    render(record, timeline) {
        if (!record) {
            this.renderEmpty();
            return;
        }

        // Combine filesystem timestamps with analysis timeline
        this.events = this.buildTimeline(record, timeline || []);

        if (this.events.length === 0) {
            this.renderNoEvents(record);
            return;
        }

        const html = `
            <div class="timeline-viewer">
                <div class="timeline-header">
                    <h3>Timeline</h3>
                    <div class="timeline-stats">
                        <span>${this.events.length} events</span>
                    </div>
                </div>
                <div class="timeline">
                    ${this.events.map(e => this.renderEvent(e)).join('')}
                </div>
            </div>
        `;

        this.container.innerHTML = html;
    }

    /**
     * Build timeline from record and IPC data
     */
    buildTimeline(record, timeline) {
        const events = [];

        // Add filesystem timestamps from PART 1
        const part1 = record.part1 || {};
        const fsMetadata = part1.filesystem_metadata || {};
        const timestamps = fsMetadata.output_value?.timestamps || {};

        if (timestamps.created_or_changed) {
            events.push({
                timestamp: timestamps.created_or_changed,
                type: 'filesystem',
                event: 'File Created/Changed',
                details: 'Filesystem timestamp (ctime)',
                source: 'PART 1'
            });
        }

        if (timestamps.modified) {
            events.push({
                timestamp: timestamps.modified,
                type: 'filesystem',
                event: 'File Modified',
                details: 'Filesystem timestamp (mtime)',
                source: 'PART 1'
            });
        }

        if (timestamps.accessed) {
            events.push({
                timestamp: timestamps.accessed,
                type: 'filesystem',
                event: 'File Accessed',
                details: 'Filesystem timestamp (atime)',
                source: 'PART 1'
            });
        }

        // Add analysis event
        if (record.created_at) {
            events.push({
                timestamp: record.created_at,
                type: 'analysis',
                event: 'Analysis Performed',
                details: `Record ID: ${record.record_id}`,
                source: 'PART 4'
            });
        }

        // Add timeline events from IPC
        for (const event of timeline) {
            events.push({
                timestamp: event.timestamp,
                type: event.event_type || 'timeline',
                event: event.event || 'Event',
                details: event.details || '',
                source: 'IPC'
            });
        }

        // Sort by timestamp
        events.sort((a, b) => {
            const dateA = new Date(a.timestamp);
            const dateB = new Date(b.timestamp);
            return dateA - dateB;
        });

        return events;
    }

    /**
     * Render a single timeline event
     */
    renderEvent(event) {
        const typeClass = this.getEventTypeClass(event.type);
        const formattedTime = this.formatTimestamp(event.timestamp);

        return `
            <div class="timeline-item ${typeClass}">
                <div class="timeline-timestamp">${formattedTime}</div>
                <div class="timeline-content">
                    <div class="timeline-event-title">
                        <span class="timeline-event-icon">${this.getEventIcon(event.type)}</span>
                        <strong>${this.escapeHtml(event.event)}</strong>
                    </div>
                    ${event.details ? `
                        <div class="timeline-event-details">${this.escapeHtml(event.details)}</div>
                    ` : ''}
                    <div class="timeline-event-source text-muted">Source: ${this.escapeHtml(event.source)}</div>
                </div>
            </div>
        `;
    }

    /**
     * Get CSS class for event type
     */
    getEventTypeClass(type) {
        const classes = {
            'filesystem': 'timeline-fs',
            'analysis': 'timeline-analysis',
            'detection': 'timeline-detection',
            'timeline': 'timeline-default'
        };
        return classes[type] || 'timeline-default';
    }

    /**
     * Get icon for event type
     */
    getEventIcon(type) {
        const icons = {
            'filesystem': '📁',
            'analysis': '🔍',
            'detection': '⚠️',
            'timeline': '📅'
        };
        return icons[type] || '📌';
    }

    /**
     * Format timestamp for display
     */
    formatTimestamp(timestamp) {
        if (!timestamp) return 'Unknown';
        
        try {
            const date = new Date(timestamp);
            if (isNaN(date.getTime())) {
                return this.escapeHtml(timestamp);
            }
            
            return date.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            });
        } catch (e) {
            return this.escapeHtml(timestamp);
        }
    }

    /**
     * Render state when no events available
     */
    renderNoEvents(record) {
        this.container.innerHTML = `
            <div class="empty-state">
                <p>No timeline events</p>
                <p class="hint">No timestamp information available for this file</p>
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
                <p class="hint">Select a record to view timeline</p>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        this.container.innerHTML = `
            <div class="error-state">
                <div class="error-state-title">Error Loading Timeline</div>
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
window.TimelineComponent = TimelineComponent;
