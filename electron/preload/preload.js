/**
 * PART 5: Preload Script
 * 
 * This script runs in a sandboxed context and exposes a safe API
 * to the renderer process via contextBridge.
 * 
 * CONSTRAINTS:
 * - Context isolation enabled
 * - No direct node access in renderer
 * - All IPC via contextBridge
 */

const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods to renderer via window.api
contextBridge.exposeInMainWorld('api', {
    // =========================================================================
    // Application State
    // =========================================================================
    
    getAppState: () => ipcRenderer.invoke('get-app-state'),
    updateStatus: (message, state) => ipcRenderer.invoke('update-status', { message, state }),
    showError: (title, message) => ipcRenderer.invoke('show-error', { title, message }),
    showSaveDialog: (options) => ipcRenderer.invoke('show-save-dialog', options),

    // =========================================================================
    // IPC Communication with Python Backend
    // =========================================================================

    // Send IPC request
    sendIPC: (method, params) => ipcRenderer.invoke('ipc-request', { method, params }),

    // =========================================================================
    // Event Listeners
    // =========================================================================

    // Menu actions
    onMenuAction: (callback) => {
        ipcRenderer.on('menu-action', (event, action) => callback(action));
    },

    // Panel switching
    onSwitchPanel: (callback) => {
        ipcRenderer.on('switch-panel', (event, panel) => callback(panel));
    },

    // Theme changes
    onSetTheme: (callback) => {
        ipcRenderer.on('set-theme', (event, theme) => callback(theme));
    },

    onToggleTheme: (callback) => {
        ipcRenderer.on('toggle-theme', () => callback());
    },

    // Status updates
    onStatusUpdate: (callback) => {
        ipcRenderer.on('status-update', (event, data) => callback(data));
    },

    // Database selection
    onDatabaseSelected: (callback) => {
        ipcRenderer.on('database-selected', (event, path) => callback(path));
    },

    // File analysis
    onAnalyzeFile: (callback) => {
        ipcRenderer.on('analyze-file', (event, path) => callback(path));
    },

    // Config changes
    onConfigDatabase: (callback) => {
        ipcRenderer.on('config-database', (event, path) => callback(path));
    },

    // IPC responses
    onIPCResponse: (callback) => {
        ipcRenderer.on('ipc-response', (event, response) => callback(response));
    },

    // =========================================================================
    // Cleanup
    // =========================================================================

    removeAllListeners: (channel) => {
        ipcRenderer.removeAllListeners(channel);
    }
});

// Log that preload is ready
console.log('Preload script initialized - PART 5 Desktop Dashboard');
