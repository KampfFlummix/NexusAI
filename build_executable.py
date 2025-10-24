#!/usr/bin/env python3
"""
Build Script for NEXUS-AI Executable - FIXED VERSION
Creates standalone executable with all dependencies
DarkForge-X Build System - ENHANCED
"""

import PyInstaller.__main__
import os
import shutil
import sys
import subprocess
from pathlib import Path

def clean_previous_builds():
    """Clean previous build artifacts"""
    folders_to_remove = ['build', 'dist', '__pycache__']
    files_to_remove = ['NEXUS-AI.spec', 'version.txt']
    
    for folder in folders_to_remove:
        if Path(folder).exists():
            shutil.rmtree(folder)
            print(f"🧹 Cleaned: {folder}")
    
    for file in files_to_remove:
        if Path(file).exists():
            os.remove(file)
            print(f"🧹 Cleaned: {file}")

def check_dependencies():
    """Check and install required dependencies"""
    print("📦 Checking dependencies...")
    
    required_packages = [
        "pyinstaller>=5.0.0",
        "Pillow>=9.0.0"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        package_name = package.split('>=')[0]
        try:
            __import__(package_name)
            print(f"✅ {package_name} found")
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing dependencies detected")
        install = input("Install missing dependencies? (y/n): ").lower().strip()
        if install == 'y':
            return install_dependencies(missing_packages)
        else:
            print("⚠️  Building without dependencies may fail")
            return False
    return True

def install_dependencies(packages):
    """Install required packages"""
    print("🔧 Installing dependencies...")
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ Installed: {package}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
            return False
    
    return True

def build_nexus_ai():
    """Build NEXUS-AI as standalone executable - ENHANCED"""
    
    print("🔨 Building NEXUS-AI Executable...")
    
    # Clean previous builds
    clean_previous_builds()
    
    # Create necessary directories
    Path("assets").mkdir(exist_ok=True)
    Path("templates").mkdir(exist_ok=True)
    
    # Check if required source files exist
    required_files = ['nexus_ai.py', 'ai_core.py', 'security_core.py', 'config_system.py']
    missing_files = []
    
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing required files: {missing_files}")
        return False
    
    # PyInstaller configuration - OPTIMIZED
    pyinstaller_args = [
        'nexus_ai.py',
        '--name=NEXUS-AI',
        '--onefile',
        '--windowed',
        '--add-data=ai_core.py:.',
        '--add-data=security_core.py:.', 
        '--add-data=config_system.py:.',
        '--hidden-import=tkinter',
        '--hidden-import=PIL',
        '--hidden-import=PIL._tkinter_finder',
        '--hidden-import=pathlib',
        '--hidden-import=threading',
        '--hidden-import=hashlib',
        '--hidden-import=re',
        '--hidden-import=json',
        '--hidden-import=os',
        '--hidden-import=sys',
        '--hidden-import=time',
        '--clean',
        '--noconfirm'
    ]
    
    # Platform-specific optimizations
    if sys.platform == 'win32':
        pyinstaller_args.extend([
            '--console',  # Use console for better error reporting
            '--uac-admin'  # Request admin privileges if needed
        ])
        print("🏁 Windows build configured")
    elif sys.platform == 'darwin':
        pyinstaller_args.extend([
            '--osx-bundle-identifier=com.darkforge.nexusai'
        ])
        print("🍎 macOS build configured")
    else:
        print("🐧 Linux build configured")
    
    print("📦 Building executable with PyInstaller...")
    print(f"Command: pyinstaller {' '.join(pyinstaller_args)}")
    
    try:
        # Build executable
        PyInstaller.__main__.run(pyinstaller_args)
        
        # Verify build success
        if sys.platform == 'win32':
            exe_path = Path("dist/NEXUS-AI.exe")
        else:
            exe_path = Path("dist/NEXUS-AI")
        
        if exe_path.exists():
            # Get file size
            exe_size = exe_path.stat().st_size / (1024 * 1024)  # MB
            
            print(f"✅ Build successful!")
            print(f"📁 Executable: {exe_path}")
            print(f"📊 Size: {exe_size:.2f} MB")
            
            # Create portable package
            create_portable_package()
            
            # Clean up temporary files
            if Path("build").exists():
                shutil.rmtree("build")
            if Path("NEXUS-AI.spec").exists():
                os.remove("NEXUS-AI.spec")
                
            return True
        else:
            print("❌ Build failed: No executable found in dist directory")
            return False
            
    except Exception as e:
        print(f"❌ Build error: {e}")
        print("💡 Trying alternative build method...")
        return try_alternative_build()

def try_alternative_build():
    """Alternative build method if main method fails"""
    print("🔄 Trying alternative build method...")
    
    try:
        # Simple build command
        cmd = [
            sys.executable, '-m', 'PyInstaller',
            'nexus_ai.py',
            '--onefile',
            '--windowed',
            '--name=NEXUS-AI'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            print("✅ Alternative build successful!")
            return True
        else:
            print(f"❌ Alternative build failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Alternative build error: {e}")
        return False

def create_portable_package():
    """Create portable package with all necessary files"""
    print("🎒 Creating portable package...")
    
    # Create portable directory
    portable_dir = Path("NEXUS-AI_Portable")
    if portable_dir.exists():
        shutil.rmtree(portable_dir)
    portable_dir.mkdir()
    
    # Copy executable
    if sys.platform == 'win32':
        exe_src = Path("dist/NEXUS-AI.exe")
        exe_dest = portable_dir / "NEXUS-AI.exe"
    else:
        exe_src = Path("dist/NEXUS-AI")
        exe_dest = portable_dir / "NEXUS-AI"
    
    if exe_src.exists():
        shutil.copy2(exe_src, exe_dest)
        
        # Make executable on Unix systems
        if sys.platform != 'win32':
            os.chmod(exe_dest, 0o755)
        
        # Create README
        create_readme(portable_dir)
        
        # Copy source files for debugging
        source_files = ['ai_core.py', 'security_core.py', 'config_system.py']
        for file in source_files:
            if Path(file).exists():
                shutil.copy2(file, portable_dir / file)
        
        print(f"✅ Portable package created: {portable_dir}")
        return True
    else:
        print("❌ Executable not found for portable package")
        return False

def create_readme(portable_dir):
    """Create README file for portable package"""
    readme_content = """
NEXUS-AI DarkForge-X System
===========================

Advanced Code Editor with AI Intelligence

🚀 FEATURES:
- Full file system explorer
- AI-powered code analysis and generation
- Real-time security scanning  
- Multilingual support (DE/EN/TR/ES)
- KI-Merge for intelligent code merging
- VS Code-like interface
- DarkForge-X AI Assistant

📁 QUICK START:
1. Run NEXUS-AI.exe (Windows) or ./NEXUS-AI (Linux/Mac)
2. Use the file explorer to navigate directories
3. Open files by double-clicking or using File > Open
4. Use the AI Assistant for code analysis and generation
5. Save files with Ctrl+S or File > Save

🛠️ AI COMMANDS:
• "analyze this code" - Deep code analysis
• "generate a function" - AI code generation  
• "security scan" - Vulnerability detection
• "help" - Show available commands

🔧 SYSTEM REQUIREMENTS:
- Windows 10+, macOS 10.14+, or Linux with GUI
- 4GB RAM minimum, 8GB recommended
- 100MB free disk space

⚠️  IMPORTANT:
This is an authorized cybersecurity research tool.
Use only for ethical testing and educational purposes.

DarkForge-X SHADOW-CORE MODE: ACTIVE
🤖 AI Intelligence: ONLINE
🔒 Security Scanner: OPERATIONAL
🌍 Multilingual: ENABLED

For support and documentation, visit:
https://github.com/KampfFlummix/NexusAI
"""
    
    with open(portable_dir / "README.txt", "w", encoding='utf-8') as f:
        f.write(readme_content)

def main():
    """Main build process"""
    print("=" * 60)
    print("🚀 NEXUS-AI DarkForge-X Build System")
    print("=" * 60)
    
    # Check dependencies
    if not check_dependencies():
        print("⚠️  Continuing build with missing dependencies...")
    
    # Build the executable
    if build_nexus_ai():
        print("\n🎉 NEXUS-AI build completed successfully!")
        print("\n📋 NEXT STEPS:")
        print("1. Navigate to the 'NEXUS-AI_Portable' directory")
        print("2. Run NEXUS-AI.exe (Windows) or ./NEXUS-AI (Linux/Mac)")
        print("3. Start coding with AI assistance!")
        print("\n💡 TIP: The portable package contains everything needed to run NEXUS-AI")
        
        # Show build summary
        if Path("NEXUS-AI_Portable").exists():
            portable_size = sum(f.stat().st_size for f in Path("NEXUS-AI_Portable").rglob('*')) / (1024 * 1024)
            print(f"\n📦 Portable package size: {portable_size:.2f} MB")
            
    else:
        print("\n❌ Build failed")
        print("\n🔧 TROUBLESHOOTING:")
        print("1. Check that all Python files are in the same directory")
        print("2. Ensure you have write permissions")
        print("3. Try running: python build_fix.py")
        print("4. Check Python version: python --version")
        print("5. Install dependencies manually: pip install -r requirements.txt")
        
        sys.exit(1)

if __name__ == "__main__":
    main()