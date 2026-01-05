/**
 * PART 5: Electron Main Process
 * 
 * This is the main entry point for the Electron desktop application.
 * It handles window creation, menu setup, and IPC bridge to Python backend.
 * 
 * CONSTRAINTS:
 * - No analysis logic
 * - No scoring or heuristics
 * - No direct file parsing
 * - Offline-first behavior
 * - All data via validated IPC only
 */

const { app, BrowserWindow, Menu, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

// Python backend process
let pythonProcess = null;
let mainWindow = null;

// Application state
const appState = {
    dataLoadState: 'idle',
    currentCase: null,
    currentSession: null,
    errors: [],
    warnings: []
};

/**
 * Create the main application window
 */
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1024,
        minHeight: 768,
        title: 'File Analysis Dashboard',
        webPreferences: {
            preload: path.join(__dirname, '..', 'preload', 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true
        },
        backgroundColor: '#1e1e1e',
        show: false
    });

    // Load the main HTML file
    mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

    // Show window when ready
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
        updateStatusBar('Ready', 'idle');
    });

    // Handle window close
    mainWindow.on('closed', () => {
        mainWindow = null;
        stopPythonBackend();
    });

    // Create application menu
    createApplicationMenu();
}

/**
 * Create application menu bar
 * Required: File, View, Analysis, Reports, Settings, Help
 */
function createApplicationMenu() {
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'Open Database...',
                    accelerator: 'CmdOrCtrl+O',
                    click: () => openDatabaseDialog()
                },
                { type: 'separator' },
                {
                    label: 'New Case',
                    accelerator: 'CmdOrCtrl+N',
                    click: () => mainWindow.webContents.send('menu-action', 'new-case')
                },
                {
                    label: 'New Session',
                    accelerator: 'CmdOrCtrl+Shift+N',
                    click: () => mainWindow.webContents.send('menu-action', 'new-session')
                },
                { type: 'separator' },
                {
                    label: 'Export...',
                    accelerator: 'CmdOrCtrl+E',
                    click: () => mainWindow.webContents.send('menu-action', 'export')
                },
                { type: 'separator' },
                {
                    label: 'Exit',
                    accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Alt+F4',
                    click: () => app.quit()
                }
            ]
        },
        {
            label: 'View',
            submenu: [
                {
                    label: 'File Overview',
                    accelerator: 'CmdOrCtrl+1',
                    click: () => mainWindow.webContents.send('switch-panel', 'file-overview')
                },
                {
                    label: 'Risk & Findings',
                    accelerator: 'CmdOrCtrl+2',
                    click: () => mainWindow.webContents.send('switch-panel', 'risk-findings')
                },
                {
                    label: 'Metadata Explorer',
                    accelerator: 'CmdOrCtrl+3',
                    click: () => mainWindow.webContents.send('switch-panel', 'metadata')
                },
                { type: 'separator' },
                {
                    label: 'Hex Viewer',
                    accelerator: 'CmdOrCtrl+H',
                    click: () => mainWindow.webContents.send('switch-panel', 'hex-viewer')
                },
                {
                    label: 'Strings Viewer',
                    accelerator: 'CmdOrCtrl+S',
                    click: () => mainWindow.webContents.send('switch-panel', 'strings')
                },
                {
                    label: 'Timeline',
                    accelerator: 'CmdOrCtrl+T',
                    click: () => mainWindow.webContents.send('switch-panel', 'timeline')
                },
                { type: 'separator' },
                {
                    label: 'Toggle Dark Mode',
                    accelerator: 'CmdOrCtrl+D',
                    click: () => mainWindow.webContents.send('toggle-theme')
                },
                { type: 'separator' },
                {
                    label: 'Reload',
                    accelerator: 'CmdOrCtrl+R',
                    click: () => mainWindow.webContents.reload()
                },
                {
                    label: 'Toggle Developer Tools',
                    accelerator: process.platform === 'darwin' ? 'Alt+Cmd+I' : 'Ctrl+Shift+I',
                    click: () => mainWindow.webContents.toggleDevTools()
                }
            ]
        },
        {
            label: 'Analysis',
            submenu: [
                {
                    label: 'Analyze File...',
                    accelerator: 'CmdOrCtrl+A',
                    click: () => analyzeFileDialog()
                },
                { type: 'separator' },
                {
                    label: 'Refresh Data',
                    accelerator: 'F5',
                    click: () => mainWindow.webContents.send('menu-action', 'refresh')
                },
                { type: 'separator' },
                {
                    label: 'View Statistics',
                    click: () => mainWindow.webContents.send('menu-action', 'statistics')
                }
            ]
        },
        {
            label: 'Reports',
            submenu: [
                {
                    label: 'Export Record to JSON',
                    click: () => mainWindow.webContents.send('menu-action', 'export-json')
                },
                {
                    label: 'Export Record to HTML',
                    click: () => mainWindow.webContents.send('menu-action', 'export-html')
                },
                {
                    label: 'Export Session Report',
                    click: () => mainWindow.webContents.send('menu-action', 'export-session')
                },
                {
                    label: 'Export Case Report',
                    click: () => mainWindow.webContents.send('menu-action', 'export-case')
                }
            ]
        },
        {
            label: 'Settings',
            submenu: [
                {
                    label: 'Theme',
                    submenu: [
                        {
                            label: 'Dark',
                            type: 'radio',
                            checked: true,
                            click: () => mainWindow.webContents.send('set-theme', 'dark')
                        },
                        {
                            label: 'Light',
                            type: 'radio',
                            click: () => mainWindow.webContents.send('set-theme', 'light')
                        },
                        {
                            label: 'High Contrast',
                            type: 'radio',
                            click: () => mainWindow.webContents.send('set-theme', 'high-contrast')
                        }
                    ]
                },
                { type: 'separator' },
                {
                    label: 'Database Path...',
                    click: () => configureDatabasePath()
                }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'Documentation',
                    click: () => shell.openExternal('file://' + path.join(__dirname, '..', '..', 'README.md'))
                },
                {
                    label: 'Testing Guide',
                    click: () => shell.openExternal('file://' + path.join(__dirname, '..', '..', 'TESTING_GUIDE.md'))
                },
                { type: 'separator' },
                {
                    label: 'About',
                    click: () => showAboutDialog()
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

/**
 * Open database file dialog
 */
async function openDatabaseDialog() {
    const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Open Analysis Database',
        filters: [
            { name: 'SQLite Database', extensions: ['db', 'sqlite', 'sqlite3'] }
        ],
        properties: ['openFile']
    });

    if (!result.canceled && result.filePaths.length > 0) {
        mainWindow.webContents.send('database-selected', result.filePaths[0]);
    }
}

/**
 * Analyze file dialog
 */
async function analyzeFileDialog() {
    const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Select File to Analyze',
        properties: ['openFile']
    });

    if (!result.canceled && result.filePaths.length > 0) {
        mainWindow.webContents.send('analyze-file', result.filePaths[0]);
    }
}

/**
 * Configure database path
 */
async function configureDatabasePath() {
    const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Select Database File',
        filters: [
            { name: 'SQLite Database', extensions: ['db', 'sqlite', 'sqlite3'] }
        ],
        properties: ['openFile', 'createDirectory']
    });

    if (!result.canceled && result.filePaths.length > 0) {
        mainWindow.webContents.send('config-database', result.filePaths[0]);
    }
}

/**
 * Show about dialog
 */
function showAboutDialog() {
    dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'About File Analysis Dashboard',
        message: 'File Analysis Dashboard',
        detail: `PART 5: Desktop Dashboard UI & Visualization

Version: 1.0.0
Schema Version: 1.0.0

A presentation-only layer for the File Analysis Application.
All data is retrieved via validated IPC from PART 4 backend.

No analysis logic, no scoring, no direct file parsing.
Offline-first, desktop-only application.`
    });
}

/**
 * Update status bar in renderer
 */
function updateStatusBar(message, state) {
    if (mainWindow && mainWindow.webContents) {
        mainWindow.webContents.send('status-update', { message, state });
    }
}

/**
 * Start Python backend process for IPC
 */
function startPythonBackend(dbPath) {
    if (pythonProcess) {
        stopPythonBackend();
    }

    const pythonScript = path.join(__dirname, '..', '..', 'src', 'file_analyzer', 'part4', 'ipc_server.py');
    
    pythonProcess = spawn('python', [pythonScript, '--database', dbPath || ''], {
        cwd: path.join(__dirname, '..', '..'),
        stdio: ['pipe', 'pipe', 'pipe']
    });

    pythonProcess.stdout.on('data', (data) => {
        handlePythonResponse(data.toString());
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error('Python backend error:', data.toString());
        updateStatusBar('Backend error: ' + data.toString().substring(0, 100), 'error');
    });

    pythonProcess.on('close', (code) => {
        console.log('Python backend exited with code:', code);
        pythonProcess = null;
    });
}

/**
 * Stop Python backend process
 */
function stopPythonBackend() {
    if (pythonProcess) {
        pythonProcess.kill();
        pythonProcess = null;
    }
}

/**
 * Send request to Python backend
 */
function sendToPythonBackend(request) {
    return new Promise((resolve, reject) => {
        if (!pythonProcess) {
            reject(new Error('Python backend not running'));
            return;
        }

        pythonProcess.stdin.write(JSON.stringify(request) + '\n');
        
        // For simplicity, we'll use the IPC bridge approach instead
        // This is a placeholder for the actual implementation
        setTimeout(() => {
            resolve({ success: true, data: null });
        }, 100);
    });
}

/**
 * Handle Python backend response
 */
function handlePythonResponse(data) {
    try {
        const response = JSON.parse(data);
        if (mainWindow && mainWindow.webContents) {
            mainWindow.webContents.send('ipc-response', response);
        }
    } catch (e) {
        console.error('Failed to parse Python response:', e);
    }
}

// IPC Handlers from renderer process
ipcMain.handle('get-app-state', () => {
    return appState;
});

ipcMain.handle('update-status', (event, { message, state }) => {
    appState.dataLoadState = state;
    updateStatusBar(message, state);
});

ipcMain.handle('show-error', (event, { title, message }) => {
    dialog.showErrorBox(title, message);
});

ipcMain.handle('show-save-dialog', async (event, options) => {
    const result = await dialog.showSaveDialog(mainWindow, options);
    return result;
});

// App lifecycle
app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    stopPythonBackend();
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('before-quit', () => {
    stopPythonBackend();
});

// Security: Disable navigation to external URLs
app.on('web-contents-created', (event, contents) => {
    contents.on('will-navigate', (event, navigationUrl) => {
        event.preventDefault();
    });
    
    contents.setWindowOpenHandler(() => {
        return { action: 'deny' };
    });
});

module.exports = { appState };
