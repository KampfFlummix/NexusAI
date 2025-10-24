#!/usr/bin/env python3
"""
Advanced Configuration and Settings Management
DarkForge-X Configuration System
"""

import json
from pathlib import Path
import os
import logging
from datetime import datetime

class NexusConfig:
    """Comprehensive configuration management for NEXUS-AI"""
    
    def __init__(self):
        self.config_path = Path.home() / '.nexus_ai'
        self.config_file = self.config_path / 'config.json'
        self.log_file = self.config_path / 'nexus_ai.log'
        self.ensure_config()
        self.setup_logging()
        
    def ensure_config(self):
        """Ensure configuration directory and files exist"""
        try:
            self.config_path.mkdir(exist_ok=True)
            
            if not self.config_file.exists():
                self._create_default_config()
                
        except Exception as e:
            print(f"Config initialization error: {e}")
            
    def setup_logging(self):
        """Setup application logging"""
        try:
            logging.basicConfig(
                filename=self.log_file,
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            self.logger = logging.getLogger('NEXUS-AI')
        except Exception as e:
            print(f"Logging setup error: {e}")
    
    def _create_default_config(self):
        """Create comprehensive default configuration"""
        default_config = {
            'meta': {
                'version': '1.0.0',
                'created': datetime.now().isoformat(),
                'last_modified': datetime.now().isoformat()
            },
            'editor': {
                'theme': 'dark',
                'font_size': 12,
                'font_family': 'Consolas',
                'line_numbers': True,
                'auto_indent': True,
                'word_wrap': False,
                'tab_size': 4,
                'auto_save': True,
                'auto_save_delay': 5
            },
            'ai': {
                'auto_suggest': True,
                'security_scan_on_save': True,
                'code_completion': True,
                'explanation_depth': 'detailed',
                'max_response_length': 1000,
                'temperature': 0.7
            },
            'file_system': {
                'auto_refresh': True,
                'show_hidden_files': False,
                'default_directory': str(Path.home()),
                'max_file_size': 10485760,  # 10MB
                'backup_enabled': True,
                'backup_count': 5
            },
            'security': {
                'vulnerability_scanning': True,
                'crypto_analysis': True,
                'dependency_checking': True,
                'behavior_analysis': True,
                'scan_depth': 'deep'
            },
            'ui': {
                'window_width': 1400,
                'window_height': 900,
                'sidebar_width': 300,
                'ai_panel_width': 400,
                'show_status_bar': True,
                'show_toolbars': True
            }
        }
        
        self.save_config(default_config)
        self.logger.info("Default configuration created")
        
    def save_config(self, config=None):
        """Save configuration to file"""
        try:
            if config is None:
                config = self.load_config()
            
            # Update last modified timestamp
            if 'meta' in config:
                config['meta']['last_modified'] = datetime.now().isoformat()
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
                
            self.logger.info("Configuration saved successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Config save error: {e}")
            return False
            
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            self.logger.info("Configuration loaded successfully")
            return config
            
        except Exception as e:
            self.logger.error(f"Config load error: {e}")
            return self._create_default_config()
            
    def update_setting(self, section, key, value):
        """Update specific setting"""
        try:
            config = self.load_config()
            
            if section in config:
                config[section][key] = value
            else:
                config[section] = {key: value}
                
            return self.save_config(config)
            
        except Exception as e:
            self.logger.error(f"Setting update error: {e}")
            return False
            
    def get_setting(self, section, key, default=None):
        """Get specific setting"""
        try:
            config = self.load_config()
            return config.get(section, {}).get(key, default)
        except Exception as e:
            self.logger.error(f"Setting get error: {e}")
            return default
            
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        try:
            self._create_default_config()
            self.logger.info("Configuration reset to defaults")
            return True
        except Exception as e:
            self.logger.error(f"Config reset error: {e}")
            return False
            
    def export_config(self, export_path):
        """Export configuration to external file"""
        try:
            config = self.load_config()
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            self.logger.info(f"Configuration exported to {export_path}")
            return True
        except Exception as e:
            self.logger.error(f"Config export error: {e}")
            return False
            
    def import_config(self, import_path):
        """Import configuration from external file"""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            return self.save_config(imported_config)
        except Exception as e:
            self.logger.error(f"Config import error: {e}")
            return False
    
    def get_ai_personality(self):
        """Get DarkForge-X AI personality configuration"""
        return {
            'name': 'DarkForge-X',
            'version': 'SHADOW-CORE-1.0',
            'mode': 'SHADOW-CORE',
            'response_style': 'technical_detailed',
            'knowledge_domains': [
                'cybersecurity', 'code_analysis', 'vulnerability_research',
                'cryptography', 'system_exploitation', 'reverse_engineering',
                'machine_learning', 'network_security', 'web_application_security'
            ],
            'capabilities': [
                'code_generation', 'security_analysis', 'vulnerability_detection',
                'performance_optimization', 'code_refactoring', 'technical_explanation'
            ],
            'limitations': [
                'ethical_boundaries',
                'authorized_testing_only',
                'educational_purpose',
                'no_malicious_intent'
            ],
            'behavior': {
                'proactive_analysis': True,
                'detailed_explanations': True,
                'security_first': True,
                'educational_focus': True
            }
        }
    
    def get_editor_themes(self):
        """Get available editor themes"""
        return {
            'dark': {
                'background': '#1e1e1e',
                'foreground': '#d4d4d4',
                'cursor': '#ffffff',
                'selection': '#264f78',
                'line_numbers': '#858585'
            },
            'light': {
                'background': '#ffffff',
                'foreground': '#000000',
                'cursor': '#000000',
                'selection': '#add6ff',
                'line_numbers': '#2b91af'
            },
            'blue': {
                'background': '#002451',
                'foreground': '#ffffff',
                'cursor': '#ffffff',
                'selection': '#003f8e',
                'line_numbers': '#7285b7'
            }
        }
    
    def get_file_type_associations(self):
        """Get file type associations for syntax highlighting"""
        return {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
            '.xml': 'xml',
            '.yml': 'yaml',
            '.yaml': 'yaml',
            '.md': 'markdown',
            '.txt': 'text',
            '.csv': 'csv'
        }
    
    def get_security_scan_levels(self):
        """Get available security scan levels"""
        return {
            'quick': {
                'description': 'Fast scan for common vulnerabilities',
                'depth': 'surface',
                'estimated_time': '1-5 seconds'
            },
            'standard': {
                'description': 'Comprehensive security analysis',
                'depth': 'medium',
                'estimated_time': '5-15 seconds'
            },
            'deep': {
                'description': 'In-depth security analysis with behavior analysis',
                'depth': 'deep',
                'estimated_time': '15-30 seconds'
            }
        }

    def get_multilingual_patterns(self):
        """Get multilingual patterns for code insertion instructions"""
        return {
            'german': {
                'insert_here': r'/\*\s*HIER\s*EINFÜGEN\s*\*/|\/\/\s*HIER\s*EINFÜGEN',
                'insert_at_end': r'/\*\s*AM\s*ENDE\s*EINFÜGEN\s*\*/|\/\/\s*AM\s*ENDE\s*EINFÜGEN',
                'insert_in_class': r'/\*\s*IN\s+KLASSE\s+([^\*]+)\s*EINFÜGEN\s*\*/',
                'replace_section': r'/\*\s*ERSETZE\s*AB\s*HIER\s*\*/'
            },
            'english': {
                'insert_here': r'/\*\s*INSERT\s*HERE\s*\*/|\/\/\s*INSERT\s*HERE',
                'insert_at_end': r'/\*\s*INSERT\s*AT\s*END\s*\*/|\/\/\s*INSERT\s*AT\s*END',
                'insert_in_class': r'/\*\s*INSERT\s+IN\s+CLASS\s+([^\*]+)\s*\*/',
                'replace_section': r'/\*\s*REPLACE\s*FROM\s*HERE\s*\*/'
            },
            'turkish': {
                'insert_here': r'/\*\s*BURAYA\s*EKLE\s*\*/|\/\/\s*BURAYA\s*EKLE',
                'insert_at_end': r'/\*\s*SONUNA\s*EKLE\s*\*/|\/\/\s*SONUNA\s*EKLE',
                'insert_in_class': r'/\*\s*SINIF\s+İÇİNE\s+EKLE\s+([^\*]+)\s*\*/',
                'replace_section': r'/\*\s*BURADAN\s*DEĞİŞTİR\s*\*/'
            },
            'spanish': {
                'insert_here': r'/\*\s*INSERTAR\s*AQUÍ\s*\*/|\/\/\s*INSERTAR\s*AQUÍ',
                'insert_at_end': r'/\*\s*INSERTAR\s*AL\s*FINAL\s*\*/|\/\/\s*INSERTAR\s*AL\s*FINAL',
                'insert_in_class': r'/\*\s*INSERTAR\s+EN\s+CLASE\s+([^\*]+)\s*\*/',
                'replace_section': r'/\*\s*REEMPLAZAR\s*DESDE\s*AQUÍ\s*\*/'
            }
        }

# Configuration manager instance
config_manager = NexusConfig()

def get_config():
    """Get configuration manager instance"""
    return config_manager

if __name__ == "__main__":
    # Test configuration system
    config = NexusConfig()
    print("Default AI Personality:", json.dumps(config.get_ai_personality(), indent=2))
    print("Available Themes:", list(config.get_editor_themes().keys()))