/**
 * PART 5: Status Bar Component
 * 
 * Displays data load state, errors/warnings, and case/session context.
 * All state must reflect actual backend status via IPC.
 * 
 * Data Sources:
 * - App state from main process
 * - IPC responses for error tracking
 */

class StatusBarComponent {
    constructor() {
        this.dataLoadState = document.getElementById('data-load-state');
        this.statusErrors = document.getElementById('status-errors');
        this.statusWarnings = document.getElementById('status-warnings');
        this.caseContext = document.getElementById('case-context');
        this.sessionContext = document.getElementById('session-context');
        this.schemaVersion = document.getElementById('schema-version');
        
        this.errors = [];
        this.warnings = [];
    }

    /**
     * Update data load state
     * @param {string} state - 'idle', 'loading', 'ready', 'error'
     * @param {string} message - Status message
     */
    setLoadState(state, message) {
        if (!this.dataLoadState) return;

        this.dataLoadState.dataset.state = state;
        
        const icon = this.dataLoadState.querySelector('.status-icon');
        const text = this.dataLoadState.querySelector('.status-text');
        
        if (text) {
            text.textContent = message || this.getDefaultMessage(state);
        }

        // Update icon color via CSS class
        this.dataLoadState.className = `status-item state-${state}`;
    }

    /**
     * Get default message for state
     */
    getDefaultMessage(state) {
        const messages = {
            'idle': 'Ready',
            'loading': 'Loading...',
            'ready': 'Data loaded',
            'error': 'Error'
        };
        return messages[state] || 'Unknown';
    }

    /**
     * Set case context
     * @param {string} caseId - Current case ID or null
     * @param {string} caseName - Case name for display
     */
    setCaseContext(caseId, caseName) {
        if (!this.caseContext) return;

        const idSpan = this.caseContext.querySelector('.case-id');
        if (idSpan) {
            if (caseId) {
                idSpan.textContent = caseName || caseId;
                idSpan.title = caseId;
            } else {
                idSpan.textContent = 'None';
                idSpan.title = '';
            }
        }
    }

    /**
     * Set session context
     * @param {string} sessionId - Current session ID or null
     * @param {string} sessionName - Session name for display
     */
    setSessionContext(sessionId, sessionName) {
        if (!this.sessionContext) return;

        const idSpan = this.sessionContext.querySelector('.session-id');
        if (idSpan) {
            if (sessionId) {
                idSpan.textContent = sessionName || sessionId;
                idSpan.title = sessionId;
            } else {
                idSpan.textContent = 'None';
                idSpan.title = '';
            }
        }
    }

    /**
     * Set schema version
     * @param {string} version - Schema version string
     */
    setSchemaVersion(version) {
        if (!this.schemaVersion) return;
        this.schemaVersion.textContent = `Schema: v${version || '?.?.?'}`;
    }

    /**
     * Add error
     * @param {string} message - Error message
     * @param {string} code - Error code
     */
    addError(message, code) {
        this.errors.push({
            message,
            code,
            timestamp: new Date().toISOString()
        });
        this.updateErrorCount();
    }

    /**
     * Add warning
     * @param {string} message - Warning message
     */
    addWarning(message) {
        this.warnings.push({
            message,
            timestamp: new Date().toISOString()
        });
        this.updateWarningCount();
    }

    /**
     * Clear all errors
     */
    clearErrors() {
        this.errors = [];
        this.updateErrorCount();
    }

    /**
     * Clear all warnings
     */
    clearWarnings() {
        this.warnings = [];
        this.updateWarningCount();
    }

    /**
     * Update error count display
     */
    updateErrorCount() {
        if (!this.statusErrors) return;

        const count = this.errors.length;
        const countSpan = this.statusErrors.querySelector('.error-count');
        
        if (countSpan) {
            countSpan.textContent = count;
        }

        this.statusErrors.hidden = count === 0;
    }

    /**
     * Update warning count display
     */
    updateWarningCount() {
        if (!this.statusWarnings) return;

        const count = this.warnings.length;
        const countSpan = this.statusWarnings.querySelector('.warning-count');
        
        if (countSpan) {
            countSpan.textContent = count;
        }

        this.statusWarnings.hidden = count === 0;
    }

    /**
     * Get all errors
     * @returns {array} Array of error objects
     */
    getErrors() {
        return [...this.errors];
    }

    /**
     * Get all warnings
     * @returns {array} Array of warning objects
     */
    getWarnings() {
        return [...this.warnings];
    }

    /**
     * Show error details in console/modal
     */
    showErrorDetails() {
        if (this.errors.length === 0) {
            console.log('No errors');
            return;
        }

        console.group('Error Details');
        this.errors.forEach((err, i) => {
            console.log(`${i + 1}. [${err.code || 'ERROR'}] ${err.message} (${err.timestamp})`);
        });
        console.groupEnd();
    }
}

// Export for use in main app
window.StatusBarComponent = StatusBarComponent;
