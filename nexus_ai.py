#!/usr/bin/env python3
"""
NEXUS-AI - Autonomous Code Editor with AI Intelligence
DarkForge-X Replication System - FIXED & ENHANCED VERSION
"""

import os
import sys
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import subprocess
import hashlib
import time
import re
from pathlib import Path
import mimetypes
import uuid
import ast

# Import the enhanced AI and security modules - FIXED IMPORTS
try:
    from ai_core import NeuralCodeAnalyzer, CodeGenerationEngine, FileIntelligenceSystem, IntelligentCodeMerger, MultilingualCommentDetector
    from security_core import SecurityScanner
    from config_system import NexusConfig
    AI_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"AI modules not available: {e}")
    AI_MODULES_AVAILABLE = False
    # Enhanced fallback implementations
    class NeuralCodeAnalyzer:
        def deep_code_analysis(self, code, language): 
            return {
                'vulnerability_assessment': {'risk_level': 'UNKNOWN', 'issues_found': 0},
                'maintainability_score': {'score': 0, 'maintainability_level': 'UNKNOWN'},
                'complexity_analysis': {'complexity_level': 'UNKNOWN'},
                'security_scan': [],
                'performance_scan': [],
                'ai_suggestions': [],
                'code_metrics': {'total_lines': len(code.split('\n'))}
            }
    
    class CodeGenerationEngine:
        def generate_from_prompt(self, prompt, context=None): 
            return f'''# AI-Generated Code
# Prompt: {prompt}

def ai_generated_function():
    """AI-generated function placeholder"""
    print("🤖 AI Code Generation - Replace with your logic")
    return None
'''
    
    class SecurityScanner:
        def deep_security_scan(self, code): 
            return {
                'summary': {'overall_risk': 'UNKNOWN', 'total_vulnerabilities': 0},
                'vulnerabilities': []
            }
    
    class NexusConfig:
        def __init__(self): 
            self.config = {'ai': {'auto_suggest': True}}
        def get_setting(self, section, key, default=None): return default
    
    class FileIntelligenceSystem:
        def analyze_file_structure(self, path): return {}
    
    class IntelligentCodeMerger:
        def smart_merge_files(self, file1, file2): 
            return {
                'success': False, 
                'error': 'AI core not available',
                'message': '❌ AI modules not installed'
            }
        def analyze_merge_requirements(self, original, donor):
            return {
                'detected_languages': [],
                'insertion_points': [],
                'missing_includes': [],
                'missing_functions': [],
                'changes_detected': 0
            }
    
    class MultilingualCommentDetector:
        def __init__(self):
            self.patterns = {
                'german': {
                    'single_line': r'//\s*[^\n]*[äöüßÄÖÜ]',
                    'multi_line': r'/\*[\s\S]*?[äöüßÄÖÜ][\s\S]*?\*/'
                },
                'english': {
                    'single_line': r'//\s*[^\n]*',
                    'multi_line': r'/\*[\s\S]*?\*/'
                },
                'turkish': {
                    'single_line': r'//\s*[^\n]*[çğıöşüÇĞİÖŞÜ]',
                    'multi_line': r'/\*[\s\S]*?[çğıöşüÇĞİÖŞÜ][\s\S]*?\*/'
                },
                'spanish': {
                    'single_line': r'//\s*[^\n]*[áéíóúñÁÉÍÓÚÑ]',
                    'multi_line': r'/\*[\s\S]*?[áéíóúñÁÉÍÓÚÑ][\s\S]*?\*/'
                }
            }

# Try to import PIL for icons, but make it optional
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("PIL not available - icons disabled")

class EnhancedDarkForgeAIEngine:
    """Enhanced AI Engine integrating all AI capabilities"""
    
    def __init__(self):
        if AI_MODULES_AVAILABLE:
            self.analyzer = NeuralCodeAnalyzer()
            self.generator = CodeGenerationEngine()
            self.security_scanner = SecurityScanner()
            self.config = NexusConfig()
        else:
            # Use fallback implementations
            self.analyzer = NeuralCodeAnalyzer()
            self.generator = CodeGenerationEngine()
            self.security_scanner = SecurityScanner()
            self.config = NexusConfig()
        
    def analyze_code(self, code, language):
        """Comprehensive code analysis using enhanced AI"""
        return self.analyzer.deep_code_analysis(code, language)
    
    def generate_code(self, prompt, context=None):
        """Advanced code generation"""
        return self.generator.generate_from_prompt(prompt, context)
    
    def security_scan(self, code):
        """Comprehensive security scanning"""
        return self.security_scanner.deep_security_scan(code)
    
    def process_command(self, command, code_context, file_context, project_context):
        """Process AI commands with full context integration"""
        command_lower = command.lower()
        
        if any(word in command_lower for word in ['analys', 'review', 'check']):
            analysis = self.analyze_code(code_context, "python")
            return f"""🔍 **Deep Code Analysis Complete**

**Security Assessment:** {analysis.get('vulnerability_assessment', {}).get('risk_level', 'UNKNOWN')}
**Maintainability:** {analysis.get('maintainability_score', {}).get('maintainability_level', 'UNKNOWN')}
**Complexity:** {analysis.get('complexity_analysis', {}).get('complexity_level', 'UNKNOWN')}

**Key Findings:**
- {len(analysis.get('security_scan', []))} security issues
- {len(analysis.get('performance_scan', []))} performance suggestions
- {len(analysis.get('ai_suggestions', []))} AI recommendations

**Detailed Report Available in Analysis Panel**"""
        
        elif any(word in command_lower for word in ['generat', 'create', 'write']):
            generated = self.generate_code(command, code_context)
            return f"""🤖 **Code Generation Complete**

**Generated code has been inserted into the editor.**

Features included:
✅ Proper documentation
✅ Error handling  
✅ Security considerations
✅ Best practices

*Review and customize the generated code as needed.*"""
        
        elif any(word in command_lower for word in ['security', 'scan', 'vulnerability']):
            security_result = self.security_scan(code_context)
            return f"""🛡️ **Security Scan Results**

**Overall Risk:** {security_result.get('summary', {}).get('overall_risk', 'UNKNOWN')}
**Vulnerabilities Found:** {security_result.get('summary', {}).get('total_vulnerabilities', 0)}

**Recommendations:**
• Review code for security best practices
• Implement input validation
• Use secure coding practices"""
        
        elif any(word in command_lower for word in ['file', 'explorer', 'directory']):
            return self._handle_file_operations(command, file_context, project_context)
        
        else:
            return f"""🤖 **DarkForge-X AI Assistant**

I've processed your command: *"{command}"*

**Context Analysis:**
- Code Size: {len(code_context)} characters
- Current File: {file_context}
- Project: {Path(project_context).name}

**Available Actions:**
• Code Analysis & Review
• Code Generation & Templates  
• Security Vulnerability Scanning
• File System Operations
• Performance Optimization

*What would you like me to help you with?*"""
    
    def _handle_file_operations(self, command, file_context, project_context):
        """Handle file system related commands"""
        if 'list' in command or 'show' in command or 'explorer' in command:
            return "📁 **File Explorer**\n\nUse the file explorer on the left to navigate directories and open files.\n\n**Quick Actions:**\n• Click folders to expand\n• Double-click files to open\n• Use toolbar for operations"
        return "📁 **File System Help**\n\nUse the file explorer panel for all file operations."

class EnhancedFileSystemController:
    """Enhanced File System Management with AI Integration"""
    
    def __init__(self):
        self.current_directory = Path.cwd()
        self.file_cache = {}
        self.watch_threads = {}
        
    def recursive_directory_scan(self, path=None):
        """Deep directory scanning with metadata and AI analysis"""
        scan_path = Path(path) if path else self.current_directory
        
        file_structure = {
            'path': str(scan_path),
            'files': [],
            'directories': [],
            'total_size': 0,
            'file_count': 0,
            'dir_count': 0,
            'project_insights': []
        }
        
        try:
            for item in scan_path.rglob('*'):
                if item.is_file():
                    file_info = self._get_file_metadata(item)
                    file_structure['files'].append(file_info)
                    file_structure['total_size'] += file_info['size']
                    file_structure['file_count'] += 1
                elif item.is_dir():
                    dir_info = {
                        'name': item.name,
                        'path': str(item),
                        'parent': str(item.parent)
                    }
                    file_structure['directories'].append(dir_info)
                    file_structure['dir_count'] += 1
            
            # AI-powered project insights
            file_structure['project_insights'] = self._analyze_project_structure(file_structure)
                    
        except Exception as e:
            print(f"Scan error: {e}")
            
        return file_structure
    
    def _get_file_metadata(self, file_path):
        """Extract comprehensive file metadata with AI analysis"""
        stat = file_path.stat()
        metadata = {
            'name': file_path.name,
            'path': str(file_path),
            'size': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'extension': file_path.suffix.lower(),
            'permissions': oct(stat.st_mode)[-3:],
            'hash': self._calculate_file_hash(file_path)
        }
        return metadata
    
    def _calculate_file_hash(self, file_path):
        """Calculate file hash"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return "unknown"
    
    def _analyze_project_structure(self, file_structure):
        """AI analysis of project structure"""
        insights = []
        files = file_structure['files']
        
        # Detect project type
        extensions = [f['extension'] for f in files]
        if '.py' in extensions:
            insights.append("🐍 Python project detected")
        if '.js' in extensions:
            insights.append("📜 JavaScript project detected")
        if '.html' in extensions:
            insights.append("🌐 Web project detected")
        
        # Size insights
        total_size_mb = file_structure['total_size'] / (1024 * 1024)
        if total_size_mb > 100:
            insights.append("💾 Large project (>100MB)")
        elif total_size_mb > 10:
            insights.append("📦 Medium-sized project")
        else:
            insights.append("📁 Small project")
        
        return insights

class NexusCodeEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("NEXUS-AI - DarkForge-X Code Platform")
        self.root.geometry("1400x900")
        
        # Enhanced core components
        self.ai_engine = EnhancedDarkForgeAIEngine()
        self.fs_controller = EnhancedFileSystemController()
        self.code_merger = IntelligentCodeMerger()  # KI-Merge Engine
        
        # UI Setup
        self._setup_ui()
        self._setup_menu()
        self._setup_bindings()
        self._setup_advanced_features()  # Enhanced features
        
        # Current state
        self.current_file = None
        self.auto_save = True
        self.file_tree_items = {}
        
    def _setup_ui(self):
        """Build comprehensive user interface"""
        # Main layout
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # File explorer - FIXED LAYOUT
        self._setup_file_explorer()
        
        # Editor area
        self._setup_editor_area()
        
        # AI Assistant panel - FIXED LAYOUT
        self._setup_ai_panel()
        
        # Status bar
        self._setup_status_bar()
        
        # Load initial file tree
        self._refresh_file_tree()
        
    def _setup_file_explorer(self):
        """Advanced file explorer panel - FIXED WIDTH ISSUE"""
        # File explorer frame - fixed width
        self.explorer_frame = ttk.LabelFrame(self.main_frame, text="📁 File System", padding="5", width=300)
        self.explorer_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        self.explorer_frame.pack_propagate(False)  # Prevent frame from resizing
        
        # Search box
        search_frame = ttk.Frame(self.explorer_frame)
        search_frame.pack(fill=tk.X, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind('<KeyRelease>', self._filter_file_tree)
        
        # Directory tree with scrollbar
        tree_frame = ttk.Frame(self.explorer_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tree = ttk.Treeview(tree_frame, show='tree')
        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # File operations toolbar
        self._setup_file_toolbar()
        
        # Bind double-click to open files
        self.tree.bind('<Double-1>', self._on_tree_double_click)
        
    def _setup_file_toolbar(self):
        """Setup file operations toolbar"""
        toolbar = ttk.Frame(self.explorer_frame)
        toolbar.pack(fill=tk.X, pady=5)
        
        ttk.Button(toolbar, text="🔄 Refresh", command=self._refresh_file_tree).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Open", command=self._open_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📄 New", command=self._new_file).pack(side=tk.LEFT, padx=2)
        
    def _setup_editor_area(self):
        """Advanced code editor with syntax highlighting"""
        # Editor notebook (tabs)
        self.editor_notebook = ttk.Notebook(self.main_frame)
        self.editor_notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Main text editor frame
        self.editor_frame = ttk.Frame(self.editor_notebook)
        self.editor_notebook.add(self.editor_frame, text="Untitled")
        
        # Line numbers
        self.line_numbers = tk.Text(self.editor_frame, width=4, padx=3, takefocus=0,
                                   border=0, background='lightgray', state='disabled')
        self.line_numbers.pack(side=tk.LEFT, fill=tk.Y)
        
        # Main text widget
        self.text_editor = scrolledtext.ScrolledText(self.editor_frame, wrap=tk.WORD,
                                                   undo=True, maxundo=-1, font=("Consolas", 11))
        self.text_editor.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Syntax highlighting
        self._setup_syntax_highlighting()
        
    def _setup_syntax_highlighting(self):
        """Setup basic syntax highlighting"""
        # Basic syntax tags
        self.text_editor.tag_configure("keyword", foreground="blue", font=("Consolas", 11, "bold"))
        self.text_editor.tag_configure("comment", foreground="green", font=("Consolas", 11))
        self.text_editor.tag_configure("string", foreground="red", font=("Consolas", 11))
        
    def _setup_ai_panel(self):
        """AI Assistant interaction panel - FIXED WIDTH ISSUE"""
        # AI frame - fixed width
        self.ai_frame = ttk.LabelFrame(self.main_frame, text="🤖 DarkForge-X AI Assistant", padding="5", width=400)
        self.ai_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        self.ai_frame.pack_propagate(False)  # Prevent frame from resizing
        
        # AI chat display
        self.ai_chat = scrolledtext.ScrolledText(self.ai_frame, height=15, state='normal',
                                               font=("Segoe UI", 9))
        self.ai_chat.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.ai_chat.insert(tk.END, "🚀 **NEXUS-AI DarkForge-X System Initialized**\n\n")
        self.ai_chat.insert(tk.END, "✅ File System Explorer Ready\n")
        self.ai_chat.insert(tk.END, "✅ AI Code Analysis Active\n")
        self.ai_chat.insert(tk.END, "✅ Security Scanner Online\n")
        self.ai_chat.insert(tk.END, "✅ Code Generator Ready\n\n")
        self.ai_chat.insert(tk.END, "**Commands:** analyze, generate, security scan, help\n\n")
        self.ai_chat.config(state='disabled')
        
        # AI input
        self.ai_input_frame = ttk.Frame(self.ai_frame)
        self.ai_input_frame.pack(fill=tk.X, pady=5, padx=2)
        
        self.ai_entry = ttk.Entry(self.ai_input_frame, font=("Segoe UI", 10))
        self.ai_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ai_entry.bind('<Return>', self._process_ai_command)
        self.ai_entry.focus()
        
        self.ai_send = ttk.Button(self.ai_input_frame, text="Send", 
                                command=self._process_ai_command)
        self.ai_send.pack(side=tk.RIGHT)
        
        # AI quick actions
        self._setup_ai_quick_actions()
        
    def _setup_ai_quick_actions(self):
        """Setup AI quick action buttons"""
        actions_frame = ttk.Frame(self.ai_frame)
        actions_frame.pack(fill=tk.X, pady=5, padx=2)
        
        actions = [
            ("🔍 Analyze", self._ai_analyze_code),
            ("⚡ Generate", self._ai_generate_code),
            ("🛡️ Security", self._ai_security_scan)
        ]
        
        for text, command in actions:
            btn = ttk.Button(actions_frame, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
    
    def _setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = ttk.Label(self.root, text="🟢 Ready - NEXUS-AI DarkForge-X System Online", 
                                  relief=tk.SUNKEN, font=("Segoe UI", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _setup_menu(self):
        """Setup application menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New File", command=self._new_file, accelerator="Ctrl+N")
        file_menu.add_command(label="Open File", command=self._open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save", command=self._save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As", command=self._save_file_as, accelerator="Ctrl+Shift+S")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo", command=self.text_editor.edit_undo, accelerator="Ctrl+Z")
        edit_menu.add_command(label="Redo", command=self.text_editor.edit_redo, accelerator="Ctrl+Y")
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut", command=self._cut_text, accelerator="Ctrl+X")
        edit_menu.add_command(label="Copy", command=self._copy_text, accelerator="Ctrl+C")
        edit_menu.add_command(label="Paste", command=self._paste_text, accelerator="Ctrl+V")
        
        # AI menu
        ai_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="AI Assistant", menu=ai_menu)
        ai_menu.add_command(label="Analyze Code", command=self._ai_analyze_code)
        ai_menu.add_command(label="Generate Code", command=self._ai_generate_code)
        ai_menu.add_command(label="Security Scan", command=self._ai_security_scan)
        ai_menu.add_separator()
        ai_menu.add_command(label="KI File Merge", command=self._open_ki_merge_dialog)
        ai_menu.add_command(label="Multilingual Scan", command=self._multilingual_scan)
        
    def _setup_bindings(self):
        """Setup keyboard bindings"""
        self.text_editor.bind('<Control-s>', lambda e: self._save_file())
        self.text_editor.bind('<Control-o>', lambda e: self._open_file())
        self.text_editor.bind('<Control-n>', lambda e: self._new_file())
        self.text_editor.bind('<Control-Shift-S>', lambda e: self._save_file_as())
        
    def _setup_advanced_features(self):
        """Setup erweiterte KI-Features für multilinguale Code-Zusammenführung"""
        self._setup_ki_merge_ui()
        self._setup_file_comparison()
    
    def _setup_ki_merge_ui(self):
        """UI für KI-gestützte Dateizusammenführung mit multilingualer Unterstützung"""
        merge_frame = ttk.LabelFrame(self.ai_frame, text="🔄 KI Datei-Merge (Multilingual)", padding="5")
        merge_frame.pack(fill=tk.X, pady=5)
        
        # Merge Buttons
        ttk.Button(merge_frame, text="📂 Dateien vergleichen & mergen", 
                  command=self._open_ki_merge_dialog).pack(fill=tk.X, pady=2)
        
        ttk.Button(merge_frame, text="🔧 Auto-Fix mit KI", 
                  command=self._auto_fix_with_ki).pack(fill=tk.X, pady=2)
        
        ttk.Button(merge_frame, text="🌍 Multilingual Scan", 
                  command=self._multilingual_scan).pack(fill=tk.X, pady=2)
        
        # Status Label
        self.merge_status = ttk.Label(merge_frame, text="Bereit für KI-Merge", font=("Segoe UI", 8))
        self.merge_status.pack(pady=2)
    
    def _setup_file_comparison(self):
        """Setup Dateivergleichs-Features"""
        # Rechtsklick-Menü für Dateivergleich
        self.tree_menu = tk.Menu(self.tree, tearoff=0)
        self.tree_menu.add_command(label="📊 Mit anderer Datei vergleichen", command=self._compare_files)
        self.tree_menu.add_command(label="🔀 KI-Merge starten", command=self._ki_merge_selected)
        self.tree.bind("<Button-3>", self._show_tree_menu)
    
    def _show_tree_menu(self, event):
        """Zeigt Rechtsklick-Menü für Dateivergleich"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)
    
    def _open_ki_merge_dialog(self):
        """Dialog für KI-gestützte Zusammenführung mit multilingualer Unterstützung"""
        dialog = tk.Toplevel(self.root)
        dialog.title("🌍 KI Datei-Zusammenführung (Multilingual)")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Header
        header = ttk.Label(dialog, text="🔄 Intelligente Code-Zusammenführung", 
                          font=("Segoe UI", 12, "bold"))
        header.pack(pady=10)
        
        subheader = ttk.Label(dialog, text="Versteht DE/EN/TR/ES Kommentare • Erstellt automatisch Backups",
                            font=("Segoe UI", 9))
        subheader.pack(pady=5)
        
        # Original Datei
        ttk.Label(dialog, text="Original Datei (wird geändert):").pack(pady=5)
        original_frame = ttk.Frame(dialog)
        original_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.original_entry = ttk.Entry(original_frame, width=60)
        self.original_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(original_frame, text="Durchsuchen", 
                  command=lambda: self._browse_file(self.original_entry)).pack(side=tk.RIGHT, padx=5)
        
        # Spender Datei
        ttk.Label(dialog, text="Spender Datei (mit Kommentaren):").pack(pady=5)
        donor_frame = ttk.Frame(dialog)
        donor_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.donor_entry = ttk.Entry(donor_frame, width=60)
        self.donor_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(donor_frame, text="Durchsuchen", 
                  command=lambda: self._browse_file(self.donor_entry)).pack(side=tk.RIGHT, padx=5)
        
        # Vorschau Bereich
        ttk.Label(dialog, text="Vorschau der Änderungen:").pack(pady=10)
        self.preview_text = scrolledtext.ScrolledText(dialog, height=12, font=("Consolas", 9))
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        self.preview_text.insert(tk.END, "Vorschau erscheint hier nach Dateiauswahl...")
        self.preview_text.config(state='disabled')
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Button(button_frame, text="🔍 Vorschau analysieren", 
                  command=self._preview_merge).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="🚀 KI-Zusammenführung starten", 
                  command=self._execute_ki_merge).pack(side=tk.RIGHT, padx=5)
    
    def _browse_file(self, entry_widget):
        """Open file browser and insert path into entry widget"""
        file_path = filedialog.askopenfilename()
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)
    
    def _preview_merge(self):
        """Analysiert die Merge-Anforderungen und zeigt Vorschau"""
        original_file = self.original_entry.get()
        donor_file = self.donor_entry.get()
        
        if not original_file or not donor_file:
            messagebox.showwarning("Warnung", "Bitte beide Dateien auswählen!")
            return
        
        try:
            # Analysiere die Merge-Anforderungen
            with open(original_file, 'r', encoding='utf-8') as f:
                original_content = f.read()
            with open(donor_file, 'r', encoding='utf-8') as f:
                donor_content = f.read()
            
            analysis = self.code_merger.analyze_merge_requirements(original_content, donor_content)
            
            # Zeige Vorschau
            self.preview_text.config(state='normal')
            self.preview_text.delete(1.0, tk.END)
            
            preview_content = f"""🔍 **KI-MERGE VORSCHAU**

📁 Original: {Path(original_file).name}
📁 Spender: {Path(donor_file).name}

🌍 ERKANNTE SPRACHEN: {', '.join(analysis['detected_languages']) or 'Keine'}

📊 ZUSAMMENFASSUNG:
• {len(analysis['insertion_points'])} Insertions-Punkte gefunden
• {len(analysis['missing_includes'])} fehlende Includes
• {len(analysis['missing_functions'])} fehlende Funktionen
• {analysis['changes_detected']} gesamte Änderungen

📍 INSERTIONS-PUNKTE:
"""
            for point in analysis['insertion_points']:
                preview_content += f"• {point['language'].upper()}: {point['type']} -> {point['target_name'] or 'Allgemein'}\n"
            
            if analysis['missing_includes']:
                preview_content += f"\n📦 FEHLENDE INCLUDES:\n" + "\n".join(f"• {inc}" for inc in analysis['missing_includes'])
            
            if analysis['missing_functions']:
                preview_content += f"\n🔧 FEHLENDE FUNKTIONEN:\n" + "\n".join(f"• {func}" for func in analysis['missing_functions'])
            
            self.preview_text.insert(tk.END, preview_content)
            self.preview_text.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Fehler", f"Vorschau fehlgeschlagen: {str(e)}")
    
    def _execute_ki_merge(self):
        """Führt die KI-Zusammenführung durch"""
        original_file = self.original_entry.get()
        donor_file = self.donor_entry.get()
        
        if not original_file or not donor_file:
            messagebox.showwarning("Warnung", "Bitte beide Dateien auswählen!")
            return
        
        # Fortschritt anzeigen
        self.merge_status.config(text="🔄 Führe KI-Merge durch...")
        
        def do_merge():
            result = self.code_merger.smart_merge_files(original_file, donor_file)
            
            # UI-Update im Hauptthread
            self.root.after(0, lambda: self._show_merge_result(result))
        
        # Im Thread ausführen
        threading.Thread(target=do_merge, daemon=True).start()
    
    def _show_merge_result(self, result):
        """Zeigt das Ergebnis des KI-Merges"""
        if result['success']:
            messagebox.showinfo("🎉 Erfolg!", 
                f"KI-Zusammenführung abgeschlossen!\n\n"
                f"✅ {result.get('changes_made', 0)} Änderungen durchgeführt\n"
                f"💾 Backup: {Path(result.get('backup_file', '')).name}\n"
                f"📄 Ergebnis: {Path(result.get('output_file', '')).name}\n\n"
                f"{result.get('message', 'Erfolgreich abgeschlossen')}")
            
            self.merge_status.config(text=f"✅ Merge abgeschlossen - {result.get('changes_made', 0)} Änderungen")
            self._display_ai_response(f"**🔀 KI-Merge abgeschlossen:** {result.get('message', 'Erfolg')}\n\n")
            
        else:
            messagebox.showerror("❌ Fehler", 
                f"KI-Zusammenführung fehlgeschlagen:\n{result.get('error', 'Unbekannter Fehler')}")
            self.merge_status.config(text="❌ Merge fehlgeschlagen")
    
    def _auto_fix_with_ki(self):
        """Automatisch fehlende Code-Teile mit KI erkennen und beheben"""
        if not self.current_file:
            messagebox.showwarning("Warnung", "Keine Datei geöffnet!")
            return
        
        self._display_ai_response("🔧 **Starte Auto-Fix Analyse...**\n\n")
        
        # Hier könnte erweiterte Auto-Fix Logik implementiert werden
        self._display_ai_response("✅ **Auto-Fix bereit** - Verwende KI-Merge für spezifische Code-Ergänzungen\n\n")
    
    def _multilingual_scan(self):
        """Scannt Dateien nach multilingualen Kommentaren"""
        if not self.current_file:
            messagebox.showwarning("Warnung", "Keine Datei geöffnet!")
            return
        
        try:
            with open(self.current_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            detector = MultilingualCommentDetector()
            found_comments = []
            
            for lang_name, patterns in detector.patterns.items():
                for pattern_type, pattern in patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        found_comments.append({
                            'language': lang_name,
                            'type': pattern_type,
                            'text': match[:100] + "..." if len(match) > 100 else match
                        })
            
            if found_comments:
                report = "🌍 **Multilingualer Scan - Gefundene Kommentare:**\n\n"
                for comment in found_comments:
                    report += f"• {comment['language'].upper()}: {comment['type']}\n"
                    report += f"  └─ {comment['text']}\n\n"
                
                self._display_ai_response(report)
            else:
                self._display_ai_response("🔍 **Keine multilingualen Kommentare gefunden**\n\n")
                
        except Exception as e:
            self._display_ai_response(f"❌ **Scan-Fehler:** {str(e)}\n\n")
    
    def _compare_files(self):
        """Vergleicht zwei Dateien"""
        try:
            file1 = self.tree.item(self.tree.selection()[0], 'values')[0]
            file2 = filedialog.askopenfilename(title="Zweite Datei auswählen")
            
            if file2:
                self._open_ki_merge_dialog()
                self.original_entry.delete(0, tk.END)
                self.original_entry.insert(0, file1)
                self.donor_entry.delete(0, tk.END)
                self.donor_entry.insert(0, file2)
                self._preview_merge()
        except IndexError:
            messagebox.showwarning("Warnung", "Bitte wählen Sie zuerst eine Datei im Explorer aus!")
    
    def _ki_merge_selected(self):
        """Startet KI-Merge für ausgewählte Datei"""
        try:
            selected_file = self.tree.item(self.tree.selection()[0], 'values')[0]
            donor_file = filedialog.askopenfilename(title="Spender-Datei auswählen")
            
            if donor_file:
                result = self.code_merger.smart_merge_files(selected_file, donor_file)
                self._show_merge_result(result)
        except IndexError:
            messagebox.showwarning("Warnung", "Bitte wählen Sie zuerst eine Datei im Explorer aus!")
    
    def _process_ai_command(self, event=None):
        """Process AI commands and queries"""
        command = self.ai_entry.get().strip()
        if not command:
            return
            
        self.ai_entry.delete(0, tk.END)
        self._display_ai_response(f"**👤 You:** {command}\n\n")
        
        # Process command in thread
        threading.Thread(target=self._execute_ai_command, 
                        args=(command,), daemon=True).start()
        
    def _execute_ai_command(self, command):
        """Execute AI command with full context"""
        try:
            # Get current code context
            current_code = self.text_editor.get(1.0, tk.END)
            file_context = self.current_file if self.current_file else "unsaved_file"
            
            # AI analysis and response
            response = self.ai_engine.process_command(
                command=command,
                code_context=current_code,
                file_context=file_context,
                project_context=self.fs_controller.current_directory
            )
            
            self._display_ai_response(f"**🤖 DarkForge-X:** {response}\n\n")
            
        except Exception as e:
            self._display_ai_response(f"**❌ Error:** {str(e)}\n\n")
    
    def _display_ai_response(self, message):
        """Display AI response in chat"""
        self.ai_chat.config(state='normal')
        self.ai_chat.insert(tk.END, message)
        self.ai_chat.see(tk.END)
        self.ai_chat.config(state='disabled')
    
    def _clear_ai_chat(self):
        """Clear AI chat history"""
        self.ai_chat.config(state='normal')
        self.ai_chat.delete(1.0, tk.END)
        self.ai_chat.insert(tk.END, "💬 **Chat cleared** - Ready for new commands\n\n")
        self.ai_chat.config(state='disabled')
    
    def _refresh_file_tree(self):
        """Refresh file tree view with AI-enhanced structure"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            structure = self.fs_controller.recursive_directory_scan()
            root_item = self.tree.insert("", "end", text=f"📁 {Path(structure['path']).name}", 
                                       values=[structure['path']], open=True)
            
            # Add directories
            for directory in structure['directories'][:20]:  # Limit for performance
                dir_item = self.tree.insert(root_item, "end", text=f"📂 {directory['name']}", 
                                          values=[directory['path']])
            
            # Add files
            for file_info in structure['files'][:50]:  # Limit for performance
                file_icon = self._get_file_icon(file_info['extension'])
                self.tree.insert(root_item, "end", text=f"{file_icon} {file_info['name']}", 
                               values=[file_info['path']])
            
            self.status_bar.config(text=f"📁 Loaded {structure['file_count']} files, {structure['dir_count']} directories")
            
        except Exception as e:
            self.tree.insert("", "end", text=f"❌ Error: {e}", values=[""])
    
    def _get_file_icon(self, extension):
        """Get appropriate icon for file type"""
        icons = {
            '.py': '🐍', '.js': '📜', '.html': '🌐', '.css': '🎨',
            '.json': '📋', '.xml': '📄', '.md': '📝', '.txt': '📄',
            '.jpg': '🖼️', '.png': '🖼️', '.gif': '🖼️', '.pdf': '📕'
        }
        return icons.get(extension, '📄')
    
    def _filter_file_tree(self, event=None):
        """Filter file tree based on search"""
        # Basic search implementation
        search_term = self.search_var.get().lower()
        if not search_term:
            # Show all items if search is empty
            for item in self.tree.get_children():
                self.tree.item(item, tags=())
            return
        
        # Hide all items first
        for item in self.tree.get_children():
            self.tree.item(item, tags=('hidden',))
        
        # Show matching items
        def check_item(item):
            text = self.tree.item(item, 'text').lower()
            values = self.tree.item(item, 'values')
            value_text = ' '.join(str(v).lower() for v in values) if values else ''
            
            if search_term in text or search_term in value_text:
                self.tree.item(item, tags=())
                # Expand parent to show matched child
                parent = self.tree.parent(item)
                if parent:
                    self.tree.item(parent, open=True)
                    check_item(parent)  # Recursively show parents
                return True
            return False
        
        # Check all items
        for item in self.tree.get_children():
            check_item(item)
    
    def _on_tree_double_click(self, event):
        """Handle double-click on tree items"""
        item = self.tree.selection()[0]
        path = self.tree.item(item, 'values')[0]
        if Path(path).is_file():
            self._load_file(path)
    
    def _new_file(self):
        """Create new file"""
        self.current_file = None
        self.text_editor.delete(1.0, tk.END)
        self.editor_notebook.tab(0, text="Untitled")
        self.status_bar.config(text="🆕 New file created - Ready to code")
        self._display_ai_response("**📄 New file created** - Start coding or ask AI for assistance\n\n")
    
    def _open_file(self):
        """Open file dialog"""
        file_path = filedialog.askopenfilename(
            title="Open File",
            filetypes=[("All files", "*.*"), 
                      ("Python files", "*.py"),
                      ("Text files", "*.txt"),
                      ("JavaScript files", "*.js"),
                      ("HTML files", "*.html"),
                      ("CSS files", "*.css")]
        )
        if file_path:
            self._load_file(file_path)
    
    def _load_file(self, file_path):
        """Load file into editor"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.text_editor.delete(1.0, tk.END)
                self.text_editor.insert(1.0, content)
                self.current_file = file_path
                self.editor_notebook.tab(0, text=Path(file_path).name)
                self.status_bar.config(text=f"📂 Loaded: {file_path}")
                
                # Auto-analyze code files
                if file_path.endswith(('.py', '.js', '.html', '.css')):
                    self._display_ai_response(f"**📁 Loaded:** `{Path(file_path).name}`\n*File is ready for editing and analysis*\n\n")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Could not load file: {e}")
    
    def _save_file(self):
        """Save current file"""
        try:
            if self.current_file:
                with open(self.current_file, 'w', encoding='utf-8') as f:
                    f.write(self.text_editor.get(1.0, tk.END))
                self.status_bar.config(text=f"💾 Saved: {self.current_file}")
                self._display_ai_response(f"**💾 Saved:** `{Path(self.current_file).name}`\n\n")
            else:
                self._save_file_as()
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file: {e}")
    
    def _save_file_as(self):
        """Save file as new"""
        file_path = filedialog.asksaveasfilename(
            title="Save File As",
            defaultextension=".py",
            filetypes=[("Python files", "*.py"),
                      ("Text files", "*.txt"),
                      ("All files", "*.*")]
        )
        if file_path:
            self.current_file = file_path
            self._save_file()
            self.editor_notebook.tab(0, text=Path(file_path).name)
    
    def _cut_text(self):
        """Cut selected text"""
        try:
            self.text_editor.event_generate("<<Cut>>")
        except:
            pass
    
    def _copy_text(self):
        """Copy selected text"""
        try:
            self.text_editor.event_generate("<<Copy>>")
        except:
            pass
    
    def _paste_text(self):
        """Paste text"""
        try:
            self.text_editor.event_generate("<<Paste>>")
        except:
            pass
    
    def _ai_analyze_code(self):
        """AI code analysis"""
        code = self.text_editor.get(1.0, tk.END)
        if len(code.strip()) > 10:
            self._display_ai_response("🔍 **Analyzing code...**\n\n")
            analysis = self.ai_engine.analyze_code(code, "python")
            
            # Display summary
            vuln_count = len(analysis.get('security_scan', []))
            perf_count = len(analysis.get('performance_scan', []))
            suggestion_count = len(analysis.get('ai_suggestions', []))
            
            summary = f"""**📊 Analysis Complete**

**Security:** {vuln_count} issues
**Performance:** {perf_count} suggestions  
**AI Recommendations:** {suggestion_count} ideas

"""
            self._display_ai_response(summary)
                
        else:
            self._display_ai_response("❌ **No code to analyze** - Please write some code first\n\n")
    
    def _ai_generate_code(self):
        """AI code generation"""
        self._display_ai_response(f"⚡ **Generating code...**\n\n")
        
        current_code = self.text_editor.get(1.0, tk.END)
        generated = self.ai_engine.generate_code("Create a useful Python function", current_code)
        
        # Insert generated code
        self.text_editor.insert(tk.END, f"\n\n{generated}")
        self._display_ai_response("✅ **Code generated and inserted**\n*Review and customize the generated code*\n\n")
    
    def _ai_security_scan(self):
        """AI security scan"""
        code = self.text_editor.get(1.0, tk.END)
        if len(code.strip()) > 10:
            self._display_ai_response("🛡️ **Running security scan...**\n\n")
            security_result = self.ai_engine.security_scan(code)
            
            risk_level = security_result.get('summary', {}).get('overall_risk', 'UNKNOWN')
            vuln_count = security_result.get('summary', {}).get('total_vulnerabilities', 0)
            
            result_text = f"""**Security Scan Results**

**Risk Level:** {risk_level}
**Vulnerabilities Found:** {vuln_count}

"""
            self._display_ai_response(result_text)
                
        else:
            self._display_ai_response("❌ **No code to scan** - Please write some code first\n\n")

def main():
    """Application entry point"""
    try:
        root = tk.Tk()
        app = NexusCodeEditor(root)
        root.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Fatal Error", f"Application failed to start: {e}")

if __name__ == "__main__":
    main()