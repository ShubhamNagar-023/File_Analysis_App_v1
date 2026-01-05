#!/usr/bin/env python3
"""
File Analysis Application - Production GUI
Full-featured desktop application for file analysis.

For law enforcement, SOC teams, enterprises, and security analysts.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QFileDialog, QTextEdit, QTableWidget,
        QTableWidgetItem, QTabWidget, QProgressBar, QMessageBox,
        QGroupBox, QGridLayout, QComboBox, QLineEdit, QSplitter,
        QHeaderView, QStatusBar, QMenuBar, QMenu, QToolBar
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QIcon, QFont, QColor, QAction
except ImportError:
    print("ERROR: PyQt6 not installed")
    print("\nInstall with: pip install PyQt6")
    sys.exit(1)

import json
from datetime import datetime
import threading

from src.file_analyzer.analyzer import analyze_file as analyze_part1
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3
from src.file_analyzer.part4.persistence import AnalysisDatabase
from src.file_analyzer.part4.exporter import Exporter, ExportFormat


class AnalysisWorker(QThread):
    """Background worker for file analysis"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, file_path, db, case_id, session_id):
        super().__init__()
        self.file_path = file_path
        self.db = db
        self.case_id = case_id
        self.session_id = session_id
    
    def run(self):
        try:
            # PART 1
            self.progress.emit("Running PART 1: File Ingestion & Type Resolution...")
            part1 = analyze_part1(self.file_path)
            
            # PART 2
            self.progress.emit("Running PART 2: Deep Static Analysis...")
            part2 = deep_analyze_file(self.file_path, part1)
            
            # PART 3
            self.progress.emit("Running PART 3: Risk Scoring...")
            part3 = analyze_part3(self.file_path, part1, part2)
            
            # Save to database
            self.progress.emit("Saving to database...")
            record_id = self.db.import_analysis(
                session_id=self.session_id,
                part1_results=part1,
                part2_results=part2,
                part3_results=part3
            )
            
            record = self.db.get_record(record_id)
            self.progress.emit("Analysis complete!")
            self.finished.emit(record)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.db = None
        self.current_case_id = None
        self.current_session_id = None
        self.exporter = None
        self.worker = None
        
        self.init_database()
        self.init_ui()
        self.setup_default_case()
    
    def init_database(self):
        """Initialize database"""
        exports_dir = Path("exports")
        exports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        db_path = exports_dir / timestamp / "analysis.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.db = AnalysisDatabase(str(db_path))
        self.exporter = Exporter(self.db)
        self.db_path = db_path
    
    def setup_default_case(self):
        """Create default case and session"""
        case_name = f"Analysis Session {datetime.now().strftime('%Y-%m-%d')}"
        self.current_case_id = self.db.create_case(
            name=case_name,
            description="Production analysis session"
        )
        
        session_name = f"Session {datetime.now().strftime('%H:%M:%S')}"
        self.current_session_id = self.db.create_session(
            case_id=self.current_case_id,
            name=session_name
        )
    
    def init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle("File Analysis Application - Production")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Top section: File selection and analysis
        top_section = self.create_top_section()
        main_layout.addWidget(top_section)
        
        # Middle section: Tabs for results
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, stretch=1)
        
        # Create tabs
        self.create_overview_tab()
        self.create_findings_tab()
        self.create_risk_tab()
        self.create_records_tab()
        
        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        
        # Apply styling
        self.apply_styling()
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        analyze_action = QAction("&Analyze File", self)
        analyze_action.setShortcut("Ctrl+O")
        analyze_action.triggered.connect(self.select_file)
        file_menu.addAction(analyze_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        refresh_action = QAction("&Refresh", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_records)
        view_menu.addAction(refresh_action)
        
        # Export menu
        export_menu = menubar.addMenu("&Export")
        
        export_json = QAction("Export as &JSON", self)
        export_json.triggered.connect(lambda: self.export_current("json"))
        export_menu.addAction(export_json)
        
        export_html = QAction("Export as &HTML", self)
        export_html.triggered.connect(lambda: self.export_current("html"))
        export_menu.addAction(export_html)
        
        export_pdf = QAction("Export as &PDF", self)
        export_pdf.triggered.connect(lambda: self.export_current("pdf"))
        export_menu.addAction(export_pdf)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        """Create toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        analyze_btn = QPushButton("📄 Analyze File")
        analyze_btn.clicked.connect(self.select_file)
        toolbar.addWidget(analyze_btn)
        
        toolbar.addSeparator()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_records)
        toolbar.addWidget(refresh_btn)
        
        toolbar.addSeparator()
        
        self.db_label = QLabel(f"Database: {self.db_path.name}")
        toolbar.addWidget(self.db_label)
    
    def create_top_section(self):
        """Create top section with file selection"""
        group = QGroupBox("File Analysis")
        layout = QGridLayout()
        
        # File selection
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("font-weight: bold; padding: 10px;")
        layout.addWidget(QLabel("Selected File:"), 0, 0)
        layout.addWidget(self.file_label, 0, 1, 1, 2)
        
        select_btn = QPushButton("Select File")
        select_btn.clicked.connect(self.select_file)
        layout.addWidget(select_btn, 0, 3)
        
        # Analysis button
        self.analyze_btn = QPushButton("🔍 Analyze")
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self.start_analysis)
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:disabled {
                background-color: #6c757d;
            }
        """)
        layout.addWidget(self.analyze_btn, 1, 0, 1, 4)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar, 2, 0, 1, 4)
        
        # Status label
        self.status_label = QLabel("")
        layout.addWidget(self.status_label, 3, 0, 1, 4)
        
        group.setLayout(layout)
        return group
    
    def create_overview_tab(self):
        """Create overview tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        self.overview_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.overview_text)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "📊 Overview")
    
    def create_findings_tab(self):
        """Create findings tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels([
            "Type", "Confidence", "Offset", "Description", "Value"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.findings_table)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "🔍 Findings")
    
    def create_risk_tab(self):
        """Create risk assessment tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Risk score display
        risk_group = QGroupBox("Risk Assessment")
        risk_layout = QGridLayout()
        
        self.risk_score_label = QLabel("N/A")
        self.risk_score_label.setFont(QFont("Arial", 32, QFont.Weight.Bold))
        risk_layout.addWidget(QLabel("Risk Score:"), 0, 0)
        risk_layout.addWidget(self.risk_score_label, 0, 1)
        
        self.severity_label = QLabel("N/A")
        self.severity_label.setFont(QFont("Arial", 24))
        risk_layout.addWidget(QLabel("Severity:"), 1, 0)
        risk_layout.addWidget(self.severity_label, 1, 1)
        
        risk_group.setLayout(risk_layout)
        layout.addWidget(risk_group)
        
        # Heuristics
        heur_group = QGroupBox("Triggered Heuristics")
        heur_layout = QVBoxLayout()
        
        self.heuristics_text = QTextEdit()
        self.heuristics_text.setReadOnly(True)
        heur_layout.addWidget(self.heuristics_text)
        
        heur_group.setLayout(heur_layout)
        layout.addWidget(heur_group)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "⚠️ Risk Assessment")
    
    def create_records_tab(self):
        """Create records history tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        self.records_table = QTableWidget()
        self.records_table.setColumnCount(6)
        self.records_table.setHorizontalHeaderLabels([
            "File Name", "Type", "Size", "Risk Score", "Severity", "Date"
        ])
        self.records_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.records_table.cellDoubleClicked.connect(self.load_record_from_table)
        layout.addWidget(self.records_table)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Records")
        refresh_btn.clicked.connect(self.refresh_records)
        layout.addWidget(refresh_btn)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "📁 Analysis History")
        
        # Load initial records
        self.refresh_records()
    
    def apply_styling(self):
        """Apply application styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QTableWidget {
                alternate-background-color: #f9f9f9;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                border-radius: 5px;
            }
        """)
    
    def select_file(self):
        """Open file selection dialog"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Analyze",
            "",
            "All Files (*.*)"
        )
        
        if file_path:
            self.current_file = file_path
            self.file_label.setText(Path(file_path).name)
            self.analyze_btn.setEnabled(True)
            self.statusBar.showMessage(f"File selected: {file_path}")
    
    def start_analysis(self):
        """Start file analysis"""
        if not hasattr(self, 'current_file'):
            QMessageBox.warning(self, "No File", "Please select a file first")
            return
        
        # Disable button and show progress
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText("Analyzing...")
        
        # Start worker thread
        self.worker = AnalysisWorker(
            self.current_file,
            self.db,
            self.current_case_id,
            self.current_session_id
        )
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_analysis_complete)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.start()
    
    def on_progress(self, message):
        """Handle progress updates"""
        self.status_label.setText(message)
        self.statusBar.showMessage(message)
    
    def on_analysis_complete(self, record):
        """Handle analysis completion"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.status_label.setText("Analysis complete!")
        self.statusBar.showMessage("Analysis complete")
        
        # Display results
        self.display_results(record)
        
        # Refresh records table
        self.refresh_records()
        
        # Show success message
        QMessageBox.information(
            self,
            "Analysis Complete",
            f"File: {record['file_name']}\n"
            f"Type: {record['semantic_file_type']}\n"
            f"Risk Score: {record['risk_score']:.1f}/100\n"
            f"Severity: {record['severity']}"
        )
    
    def on_analysis_error(self, error_msg):
        """Handle analysis error"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.status_label.setText("")
        self.statusBar.showMessage("Analysis failed")
        
        QMessageBox.critical(self, "Analysis Error", f"Error: {error_msg}")
    
    def display_results(self, record):
        """Display analysis results"""
        # Overview
        overview = f"""
File Analysis Results
{'='*60}

File Information:
  Name: {record['file_name']}
  Path: {record['file_path']}
  Size: {record['file_size']:,} bytes
  Type: {record['semantic_file_type']}
  SHA-256: {record['sha256_hash']}

Risk Assessment:
  Score: {record['risk_score']:.1f}/100
  Severity: {record['severity']}

Analysis Date: {record['created_at']}
Record ID: {record['record_id']}
"""
        self.overview_text.setPlainText(overview)
        
        # Risk score
        score = record['risk_score']
        self.risk_score_label.setText(f"{score:.1f}/100")
        
        severity = record['severity']
        self.severity_label.setText(severity)
        
        # Color code severity
        colors = {
            'INFORMATIONAL': '#17a2b8',
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
        color = colors.get(severity, '#6c757d')
        self.severity_label.setStyleSheet(f"color: {color};")
        
        # Heuristics
        part3 = record.get('part3', {})
        heuristics = part3.get('heuristics', {}).get('triggered_heuristics', [])
        
        if heuristics:
            heur_text = ""
            for h in heuristics:
                heur_text += f"• {h['name']} ({h['severity']})\n"
                heur_text += f"  {h['description']}\n\n"
            self.heuristics_text.setPlainText(heur_text)
        else:
            self.heuristics_text.setPlainText("No heuristics triggered")
        
        # Findings
        part2 = record.get('part2', {})
        all_findings = []
        all_findings.extend(part2.get('universal', []))
        all_findings.extend(part2.get('container_level', []))
        all_findings.extend(part2.get('file_type_specific', []))
        
        self.findings_table.setRowCount(len(all_findings))
        for i, finding in enumerate(all_findings):
            self.findings_table.setItem(i, 0, QTableWidgetItem(finding.get('finding_type', 'N/A')))
            self.findings_table.setItem(i, 1, QTableWidgetItem(finding.get('confidence', 'N/A')))
            offset = finding.get('byte_offset_start', 'N/A')
            self.findings_table.setItem(i, 2, QTableWidgetItem(str(offset)))
            
            value = finding.get('extracted_value', {})
            if isinstance(value, dict):
                desc = value.get('description', '')
                val = str(value.get('value', ''))[:50]
            else:
                desc = ""
                val = str(value)[:50]
            
            self.findings_table.setItem(i, 3, QTableWidgetItem(desc))
            self.findings_table.setItem(i, 4, QTableWidgetItem(val))
        
        self.current_record_id = record['record_id']
    
    def refresh_records(self):
        """Refresh records table"""
        try:
            records = self.db.query_records()
            
            self.records_table.setRowCount(len(records))
            for i, record in enumerate(records):
                self.records_table.setItem(i, 0, QTableWidgetItem(record['file_name']))
                self.records_table.setItem(i, 1, QTableWidgetItem(record['semantic_file_type']))
                self.records_table.setItem(i, 2, QTableWidgetItem(f"{record['file_size']:,}"))
                self.records_table.setItem(i, 3, QTableWidgetItem(f"{record['risk_score']:.1f}"))
                
                severity_item = QTableWidgetItem(record['severity'])
                colors = {
                    'INFORMATIONAL': QColor(23, 162, 184),
                    'LOW': QColor(40, 167, 69),
                    'MEDIUM': QColor(255, 193, 7),
                    'HIGH': QColor(253, 126, 20),
                    'CRITICAL': QColor(220, 53, 69)
                }
                if record['severity'] in colors:
                    severity_item.setForeground(colors[record['severity']])
                self.records_table.setItem(i, 4, severity_item)
                
                date = record['created_at'][:19]  # Remove microseconds
                self.records_table.setItem(i, 5, QTableWidgetItem(date))
                
                # Store record_id in item data
                self.records_table.item(i, 0).setData(Qt.ItemDataRole.UserRole, record['record_id'])
            
            self.statusBar.showMessage(f"Loaded {len(records)} records")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load records: {str(e)}")
    
    def load_record_from_table(self, row, col):
        """Load a record from the table"""
        record_id_item = self.records_table.item(row, 0)
        if record_id_item:
            record_id = record_id_item.data(Qt.ItemDataRole.UserRole)
            try:
                record = self.db.get_record(record_id)
                self.display_results(record)
                self.tabs.setCurrentIndex(0)  # Switch to overview tab
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to load record: {str(e)}")
    
    def export_current(self, format):
        """Export current record"""
        if not hasattr(self, 'current_record_id'):
            QMessageBox.warning(self, "No Record", "Please analyze a file first")
            return
        
        # Get save location
        file_filter = {
            'json': "JSON Files (*.json)",
            'html': "HTML Files (*.html)",
            'pdf': "PDF Files (*.pdf)"
        }[format]
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export as {format.upper()}",
            f"analysis_report.{format}",
            file_filter
        )
        
        if file_path:
            try:
                export_format = {
                    'json': ExportFormat.JSON,
                    'html': ExportFormat.HTML,
                    'pdf': ExportFormat.PDF
                }[format]
                
                self.exporter.export_record(self.current_record_id, file_path, export_format)
                QMessageBox.information(self, "Export Complete", f"Exported to {file_path}")
                self.statusBar.showMessage(f"Exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About File Analysis Application",
            "File Analysis Application v1.0\n\n"
            "Production-grade file analysis tool for:\n"
            "• Law enforcement agencies\n"
            "• Security Operations Centers (SOC)\n"
            "• Enterprise security teams\n"
            "• Digital forensics investigators\n\n"
            "Features:\n"
            "• Deep file type detection\n"
            "• Security analysis and risk scoring\n"
            "• Multi-format export (JSON/HTML/PDF)\n"
            "• Analysis history and case management\n\n"
            "© 2026 File Analysis Team"
        )
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.db:
            self.db.close()
        event.accept()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("File Analysis Application")
    app.setOrganizationName("File Analysis Team")
    
    # Set application font
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
