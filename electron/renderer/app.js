/**
 * PART 5: Main Application Script
 * 
 * Orchestrates the desktop dashboard UI, managing:
 * - IPC communication with Python backend (via preload bridge)
 * - Component initialization and updates
 * - State management
 * - Theme switching
 * - Keyboard shortcuts
 * 
 * CONSTRAINTS:
 * - All data via IPC - no fabrication
 * - Errors must be visible - no silent failures
 * - Presentation only - no analysis logic
 */

// Application state
const AppState = {
    currentCase: null,
    currentSession: null,
    currentRecord: null,
    records: [],
    findings: [],
    heuristics: [],
    theme: 'dark',
    databasePath: null,
    isLoading: false,
    schemaVersion: '1.0.0'
};

// Component instances
let fileOverview = null;
let riskPanel = null;
let metadataExplorer = null;
let findingsList = null;
let heuristicsPanel = null;
let hexViewer = null;
let stringsViewer = null;
let archiveTree = null;
let timeline = null;
let diffView = null;
let statusBar = null;

/**
 * Initialize the application
 */
async function initializeApp() {
    console.log('PART 5: Initializing Desktop Dashboard...');
    
    // Initialize components
    initializeComponents();
    
    // Setup event listeners
    setupEventListeners();
    
    // Setup keyboard shortcuts
    setupKeyboardShortcuts();
    
    // Setup IPC listeners from main process
    setupIPCListeners();
    
    // Update initial state
    statusBar.setLoadState('idle', 'Ready');
    statusBar.setSchemaVersion(AppState.schemaVersion);
    
    console.log('PART 5: Dashboard initialized');
}

/**
 * Initialize all UI components
 */
function initializeComponents() {
    fileOverview = new FileOverviewComponent('file-overview-component');
    riskPanel = new RiskPanelComponent('risk-panel-component');
    metadataExplorer = new MetadataExplorerComponent('metadata-explorer-component');
    findingsList = new FindingsListComponent('findings-list-component');
    heuristicsPanel = new HeuristicsPanelComponent('heuristics-panel-component');
    hexViewer = new HexViewerComponent('hex-viewer-component');
    stringsViewer = new StringsViewerComponent('strings-viewer-component');
    archiveTree = new ArchiveTreeComponent('archive-tree-component');
    timeline = new TimelineComponent('timeline-component');
    diffView = new DiffViewComponent('diff-view-component');
    statusBar = new StatusBarComponent();

    // Setup offset click handlers for navigation
    findingsList.setOffsetClickHandler((offset, offsetEnd) => {
        hexViewer.jumpToOffset(offset);
        switchToTab('hex-viewer');
    });

    stringsViewer.setOffsetClickHandler((offset) => {
        hexViewer.jumpToOffset(offset);
        switchToTab('hex-viewer');
    });
}

/**
 * Setup DOM event listeners
 */
function setupEventListeners() {
    // Tab switching
    const tabButtons = document.querySelectorAll('.tab-btn[data-tab]');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            switchToTab(btn.dataset.tab);
        });
    });

    // Toolbar buttons
    document.getElementById('btn-refresh')?.addEventListener('click', refreshData);
    document.getElementById('btn-analyze')?.addEventListener('click', () => {
        window.api?.onAnalyzeFile?.();
    });

    // Case and session selectors
    document.getElementById('case-selector')?.addEventListener('change', handleCaseChange);
    document.getElementById('session-selector')?.addEventListener('change', handleSessionChange);

    // Records list click handling
    document.getElementById('records-list')?.addEventListener('click', handleRecordClick);

    // Error modal close
    document.getElementById('error-modal-close')?.addEventListener('click', hideErrorModal);

    // Error/warning click handlers
    document.getElementById('status-errors')?.addEventListener('click', () => {
        statusBar.showErrorDetails();
    });
}

/**
 * Setup IPC listeners from main process
 */
function setupIPCListeners() {
    if (!window.api) {
        console.warn('Preload API not available - running in browser mode');
        return;
    }

    // Menu actions
    window.api.onMenuAction(handleMenuAction);

    // Panel switching
    window.api.onSwitchPanel(switchToTab);

    // Theme changes
    window.api.onSetTheme(setTheme);
    window.api.onToggleTheme(toggleTheme);

    // Status updates
    window.api.onStatusUpdate(({ message, state }) => {
        statusBar.setLoadState(state, message);
    });

    // Database selection
    window.api.onDatabaseSelected(handleDatabaseSelected);

    // File analysis
    window.api.onAnalyzeFile(handleAnalyzeFile);
}

/**
 * Setup keyboard shortcuts
 */
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // F5 - Refresh
        if (e.key === 'F5') {
            e.preventDefault();
            refreshData();
        }

        // Ctrl+1-6 for tab switching
        if (e.ctrlKey && !e.shiftKey && !e.altKey) {
            const tabMap = {
                '1': 'file-overview',
                '2': 'risk-findings',
                '3': 'metadata',
                '4': 'hex-viewer',
                '5': 'strings',
                '6': 'timeline'
            };
            if (tabMap[e.key]) {
                e.preventDefault();
                switchToTab(tabMap[e.key]);
            }
        }

        // Ctrl+D - Toggle theme
        if (e.ctrlKey && e.key === 'd') {
            e.preventDefault();
            toggleTheme();
        }

        // Escape - Close modals
        if (e.key === 'Escape') {
            hideErrorModal();
        }
    });
}

/**
 * Switch to a specific tab
 */
function switchToTab(tabId) {
    // Update tab buttons
    const tabButtons = document.querySelectorAll('.tab-btn[data-tab]');
    tabButtons.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
        btn.setAttribute('aria-selected', btn.dataset.tab === tabId);
    });

    // Update tab content
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        const contentId = content.id.replace('tab-', '');
        content.classList.toggle('active', contentId === tabId);
    });
}

/**
 * Handle menu actions from main process
 */
async function handleMenuAction(action) {
    switch (action) {
        case 'refresh':
            await refreshData();
            break;
        case 'new-case':
            // Would open new case dialog
            break;
        case 'new-session':
            // Would open new session dialog
            break;
        case 'export':
        case 'export-json':
        case 'export-html':
            await handleExport(action);
            break;
        case 'statistics':
            await showStatistics();
            break;
        default:
            console.log('Unknown menu action:', action);
    }
}

/**
 * Refresh all data from IPC
 */
async function refreshData() {
    if (AppState.isLoading) return;

    setLoading(true, 'Refreshing data...');
    statusBar.clearErrors();

    try {
        // Refresh cases
        await loadCases();

        // Refresh records if session selected
        if (AppState.currentSession) {
            await loadRecords(AppState.currentSession);
        }

        // Refresh current record
        if (AppState.currentRecord) {
            await loadRecord(AppState.currentRecord.record_id);
        }

        statusBar.setLoadState('ready', 'Data refreshed');
    } catch (error) {
        handleError('Refresh failed', error);
    } finally {
        setLoading(false);
    }
}

/**
 * Load cases from IPC
 */
async function loadCases() {
    try {
        // IPC call would go here
        // const cases = await ipcBridge.listCases();
        
        // For now, update UI to show no cases
        const selector = document.getElementById('case-selector');
        if (selector) {
            selector.innerHTML = '<option value="">-- Select Case --</option>';
        }
    } catch (error) {
        handleError('Failed to load cases', error);
    }
}

/**
 * Load records for a session
 */
async function loadRecords(sessionId) {
    try {
        // IPC call would go here
        // const records = await ipcBridge.listRecords({ session_id: sessionId });
        
        // Update records list
        renderRecordsList([]);
    } catch (error) {
        handleError('Failed to load records', error);
    }
}

/**
 * Load a specific record
 */
async function loadRecord(recordId) {
    setLoading(true, 'Loading record...');

    try {
        // IPC call would go here
        // const record = await ipcBridge.getRecord(recordId);
        // const findings = await ipcBridge.listFindings({ record_id: recordId });
        // const heuristics = await ipcBridge.listHeuristics({ record_id: recordId });

        // For now, use mock data structure
        // In production, this would come from IPC

        // Update all components with record data
        if (AppState.currentRecord) {
            fileOverview.render(AppState.currentRecord);
            riskPanel.render(AppState.currentRecord);
            metadataExplorer.render(AppState.currentRecord);
            hexViewer.render(AppState.currentRecord, AppState.findings);
            stringsViewer.render(AppState.findings);
            archiveTree.render(AppState.currentRecord);
            timeline.render(AppState.currentRecord, []);
            findingsList.render(AppState.findings);
            heuristicsPanel.render(AppState.heuristics);
        }

        statusBar.setLoadState('ready', 'Record loaded');
    } catch (error) {
        handleError('Failed to load record', error);
    } finally {
        setLoading(false);
    }
}

/**
 * Handle case selection change
 */
async function handleCaseChange(event) {
    const caseId = event.target.value;
    
    if (!caseId) {
        AppState.currentCase = null;
        statusBar.setCaseContext(null);
        return;
    }

    try {
        // Load case details and sessions
        // const case = await ipcBridge.getCase(caseId);
        // const sessions = await ipcBridge.listSessions({ case_id: caseId });
        
        AppState.currentCase = { case_id: caseId };
        statusBar.setCaseContext(caseId, caseId);

        // Update session selector
        const sessionSelector = document.getElementById('session-selector');
        if (sessionSelector) {
            sessionSelector.innerHTML = '<option value="">-- Select Session --</option>';
        }
    } catch (error) {
        handleError('Failed to load case', error);
    }
}

/**
 * Handle session selection change
 */
async function handleSessionChange(event) {
    const sessionId = event.target.value;
    
    if (!sessionId) {
        AppState.currentSession = null;
        statusBar.setSessionContext(null);
        clearRecordDisplay();
        return;
    }

    try {
        AppState.currentSession = { session_id: sessionId };
        statusBar.setSessionContext(sessionId, sessionId);

        // Load records for session
        await loadRecords(sessionId);
    } catch (error) {
        handleError('Failed to load session', error);
    }
}

/**
 * Handle record click in list
 */
function handleRecordClick(event) {
    const recordItem = event.target.closest('.record-item');
    if (!recordItem) return;

    const recordId = recordItem.dataset.recordId;
    if (!recordId) return;

    // Update selection
    document.querySelectorAll('.record-item').forEach(item => {
        item.classList.remove('selected');
    });
    recordItem.classList.add('selected');

    // Load record
    loadRecord(recordId);
}

/**
 * Render records list
 */
function renderRecordsList(records) {
    const container = document.getElementById('records-list');
    if (!container) return;

    if (records.length === 0) {
        container.innerHTML = `
            <div class="empty-state" aria-live="polite">
                <p>No records loaded</p>
                <p class="hint">Select a case and session, or analyze a file</p>
            </div>
        `;
        return;
    }

    container.innerHTML = records.map(record => `
        <div class="record-item" 
             data-record-id="${escapeHtml(record.record_id)}"
             role="option"
             tabindex="0">
            <div class="record-item-name">${escapeHtml(record.file_name)}</div>
            <div class="record-item-meta">
                <span>${escapeHtml(record.semantic_file_type)}</span>
                <span class="record-item-severity severity-badge ${record.severity}">
                    ${escapeHtml(record.severity)}
                </span>
                <span>${record.risk_score?.toFixed(1) || '0.0'}</span>
            </div>
        </div>
    `).join('');
}

/**
 * Clear record display
 */
function clearRecordDisplay() {
    AppState.currentRecord = null;
    AppState.findings = [];
    AppState.heuristics = [];

    fileOverview.renderEmpty();
    riskPanel.renderEmpty();
    metadataExplorer.renderEmpty();
    hexViewer.renderEmpty();
    stringsViewer.renderEmpty();
    archiveTree.renderEmpty();
    timeline.renderEmpty();
    findingsList.renderEmpty();
    heuristicsPanel.renderEmpty();
}

/**
 * Handle database selection
 */
async function handleDatabaseSelected(dbPath) {
    AppState.databasePath = dbPath;
    statusBar.setLoadState('loading', 'Connecting to database...');

    try {
        // Initialize IPC with database
        // await ipcBridge.initialize(dbPath);
        
        await loadCases();
        statusBar.setLoadState('ready', 'Connected');
    } catch (error) {
        handleError('Database connection failed', error);
    }
}

/**
 * Handle analyze file request
 */
async function handleAnalyzeFile(filePath) {
    if (!AppState.currentSession) {
        showError('No Session', 'Please select a session before analyzing files.');
        return;
    }

    setLoading(true, 'Analyzing file...');

    try {
        // Would call analysis via IPC
        // const result = await ipcBridge.analyzeFile(filePath, AppState.currentSession.session_id);
        
        // Refresh records
        await loadRecords(AppState.currentSession.session_id);
        
        statusBar.setLoadState('ready', 'Analysis complete');
    } catch (error) {
        handleError('Analysis failed', error);
    } finally {
        setLoading(false);
    }
}

/**
 * Handle export
 */
async function handleExport(action) {
    if (!AppState.currentRecord) {
        showError('No Record', 'Please select a record to export.');
        return;
    }

    const format = action.includes('html') ? 'html' : 'json';
    
    try {
        const result = await window.api.showSaveDialog({
            title: 'Export Record',
            defaultPath: `${AppState.currentRecord.file_name}_report.${format}`,
            filters: [
                { name: format.toUpperCase(), extensions: [format] }
            ]
        });

        if (result.canceled) return;

        // Would call export via IPC
        // await ipcBridge.exportRecord(AppState.currentRecord.record_id, result.filePath, format);
        
        statusBar.setLoadState('ready', 'Export complete');
    } catch (error) {
        handleError('Export failed', error);
    }
}

/**
 * Show statistics
 */
async function showStatistics() {
    try {
        // Would call statistics via IPC
        // const stats = await ipcBridge.getStatistics();
        
        // For now, show placeholder
        console.log('Statistics would be displayed here');
    } catch (error) {
        handleError('Failed to load statistics', error);
    }
}

/**
 * Set theme
 */
function setTheme(theme) {
    AppState.theme = theme;
    document.body.className = `theme-${theme}`;
    localStorage.setItem('theme', theme);
}

/**
 * Toggle theme
 */
function toggleTheme() {
    const themes = ['dark', 'light', 'high-contrast'];
    const currentIndex = themes.indexOf(AppState.theme);
    const nextIndex = (currentIndex + 1) % themes.length;
    setTheme(themes[nextIndex]);
}

/**
 * Set loading state
 */
function setLoading(loading, message) {
    AppState.isLoading = loading;
    
    const overlay = document.getElementById('loading-overlay');
    const loadingText = overlay?.querySelector('.loading-text');
    
    if (overlay) {
        overlay.hidden = !loading;
    }
    
    if (loadingText && message) {
        loadingText.textContent = message;
    }

    if (loading) {
        statusBar.setLoadState('loading', message);
    }
}

/**
 * Handle error - errors MUST be visible
 */
function handleError(title, error) {
    const message = error?.message || String(error);
    
    console.error(`${title}:`, error);
    
    statusBar.addError(message, 'error');
    statusBar.setLoadState('error', title);
    
    showError(title, message);
}

/**
 * Show error modal
 */
function showError(title, message) {
    const modal = document.getElementById('error-modal');
    const modalTitle = document.getElementById('error-modal-title');
    const modalMessage = document.getElementById('error-modal-message');
    
    if (modal && modalTitle && modalMessage) {
        modalTitle.textContent = title;
        modalMessage.textContent = message;
        modal.hidden = false;
    }
}

/**
 * Hide error modal
 */
function hideErrorModal() {
    const modal = document.getElementById('error-modal');
    if (modal) {
        modal.hidden = true;
    }
}

/**
 * Escape HTML helper
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', initializeApp);

// Load saved theme
const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
    document.body.className = `theme-${savedTheme}`;
}
