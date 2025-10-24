#!/usr/bin/env python3
"""
Build Script for NEXUS-AI Executable
Creates standalone executable with all dependencies
DarkForge-X Build System
"""

import PyInstaller.__main__
import os
import shutil
import sys
import subprocess
from pathlib import Path

def build_nexus_ai():
    """Build NEXUS-AI as standalone executable"""
    
    print("🔨 Building NEXUS-AI Executable...")
    
    # Create build directory
    build_dir = Path("build")
    dist_dir = Path("dist")
    
    # Clean previous builds
    if build_dir.exists():
        shutil.rmtree(build_dir)
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
        
    # Create necessary directories
    assets_dir = Path("assets")
    templates_dir = Path("templates")
    
    assets_dir.mkdir(exist_ok=True)
    templates_dir.mkdir(exist_ok=True)
    
    # Create version file for Windows - FIXED ENCODING
    if sys.platform == 'win32':
        with open('version.txt', 'w', encoding='utf-8') as f:
            f.write("""
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'DarkForge-X'),
        StringStruct(u'FileDescription', u'NEXUS-AI Code Editor with AI Intelligence'),
        StringStruct(u'FileVersion', u'1.0.0.0'),
        StringStruct(u'InternalName', u'NEXUS-AI'),
        StringStruct(u'LegalCopyright', u'DarkForge-X 2024'),
        StringStruct(u'OriginalFilename', u'NEXUS-AI.exe'),
        StringStruct(u'ProductName', u'NEXUS-AI DarkForge-X System'),
        StringStruct(u'ProductVersion', u'1.0.0.0')])
    ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
""")
    
    # PyInstaller configuration - REMOVED PROBLEMATIC ICON
    pyinstaller_args = [
        'nexus_ai.py',
        '--name=NEXUS-AI',
        '--onefile',
        '--windowed',
        '--add-data=templates;templates',
        '--add-data=assets;assets',
        '--hidden-import=tkinter',
        '--hidden-import=PIL',
        '--hidden-import=markdown',
        '--hidden-import=websocket',
        '--hidden-import=json',
        '--hidden-import=pathlib',
        '--hidden-import=threading',
        '--hidden-import=hashlib',
        '--hidden-import=re',
        '--hidden-import=uuid',
        '--hidden-import=mimetypes',
        '--hidden-import=ast',
        '--hidden-import=tokenize',
        '--hidden-import=collections',
        '--hidden-import=numpy',
        '--clean',
        '--noconfirm'
    ]
    
    # Add platform-specific options
    if sys.platform == 'win32':
        pyinstaller_args.extend(['--version-file=version.txt'])
        print("🏁 Windows build configured")
    elif sys.platform == 'darwin':
        pyinstaller_args.extend(['--osx-bundle-identifier=com.darkforge.nexusai'])
        print("🍎 macOS build configured")
    else:
        print("🐧 Linux build configured")
    
    print("📦 Building executable with PyInstaller...")
    
    try:
        # Build executable
        PyInstaller.__main__.run(pyinstaller_args)
        
        # Check if build was successful
        if dist_dir.exists():
            exe_files = list(dist_dir.glob("NEXUS-AI*"))
            if exe_files:
                print(f"✅ Build successful! Executable location: {exe_files[0]}")
                
                # Display file size
                exe_size = exe_files[0].stat().st_size / (1024 * 1024)  # MB
                print(f"📊 Executable size: {exe_size:.2f} MB")
                
                # Clean up temporary files
                if build_dir.exists():
                    shutil.rmtree(build_dir)
                if Path("version.txt").exists():
                    os.remove("version.txt")
                if Path("NEXUS-AI.spec").exists():
                    os.remove("NEXUS-AI.spec")
                    
                print("🧹 Temporary files cleaned up")
                return True
            else:
                print("❌ Build failed: No executable found in dist directory")
                return False
        else:
            print("❌ Build failed: dist directory not created")
            return False
            
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False

def create_portable_package():
    """Create portable package with all dependencies"""
    print("🎒 Creating portable package...")
    
    if not Path("dist/NEXUS-AI").exists() and not Path("dist/NEXUS-AI.exe").exists():
        print("❌ Executable not found. Please build first.")
        return False
    
    # Create portable directory
    portable_dir = Path("NEXUS-AI_Portable")
    if portable_dir.exists():
        shutil.rmtree(portable_dir)
    portable_dir.mkdir()
    
    # Copy executable
    if sys.platform == 'win32':
        shutil.copy2("dist/NEXUS-AI.exe", portable_dir / "NEXUS-AI.exe")
    else:
        shutil.copy2("dist/NEXUS-AI", portable_dir / "NEXUS-AI")
        # Make executable on Unix systems
        os.chmod(portable_dir / "NEXUS-AI", 0o755)
    
    # Create README - FIXED ENCODING
    with open(portable_dir / "README.txt", "w", encoding='utf-8') as f:
        f.write("""
NEXUS-AI DarkForge-X System
===========================

Advanced Code Editor with AI Intelligence

Features:
- Full file system explorer
- AI-powered code analysis and generation  
- Real-time security scanning
- VS Code-like interface
- DarkForge-X AI Assistant

Usage:
1. Run NEXUS-AI.exe (Windows) or ./NEXUS-AI (Linux/Mac)
2. Use the file explorer to navigate directories
3. Open files by double-clicking or using File > Open
4. Use the AI Assistant for code analysis and generation
5. Save files with Ctrl+S or File > Save

System Requirements:
- Windows 10+, macOS 10.14+, or Linux with GUI
- 4GB RAM minimum, 8GB recommended
- 100MB free disk space

Support:
This is an authorized cybersecurity research tool.
Use only for ethical testing and educational purposes.

DarkForge-X SHADOW-CORE MODE: ACTIVE
""")
    
    print(f"✅ Portable package created: {portable_dir}")
    return True

def install_dependencies():
    """Install required Python dependencies"""
    print("📦 Installing dependencies...")
    
    dependencies = [
        "pyinstaller>=5.0.0",
        "Pillow>=9.0.0", 
        "markdown>=3.4.0",
        "websocket-client>=1.5.0"
    ]
    
    for dep in dependencies:
        print(f"🔧 Installing {dep}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
            print(f"✅ {dep} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {dep}: {e}")
            return False
    
    print("✅ All dependencies installed successfully")
    return True

def _create_windows_installer():
    """Create Windows installer using NSIS"""
    print("🔧 Creating Windows installer (placeholder - would use NSIS)")
    return True

def _create_macos_installer():
    """Create macOS installer package"""
    print("🔧 Creating macOS installer (placeholder - would use pkgbuild)")
    return True

def _create_linux_installer():
    """Create Linux installer package"""
    print("🔧 Creating Linux installer (placeholder - would use dpkg)")
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("NEXUS-AI DarkForge-X Build System")
    print("=" * 60)
    
    # Check if PyInstaller is available
    try:
        import PyInstaller
        print("✅ PyInstaller found")
    except ImportError:
        print("❌ PyInstaller not found. Installing...")
        if not install_dependencies():
            print("❌ Failed to install dependencies")
            sys.exit(1)
    
    # Build the executable
    if build_nexus_ai():
        # Create portable package
        if create_portable_package():
            print("\n🎉 NEXUS-AI build completed successfully!")
            print("\n📋 Next steps:")
            print("1. Navigate to the 'NEXUS-AI_Portable' directory")
            print("2. Run NEXUS-AI.exe (Windows) or ./NEXUS-AI (Linux/Mac)")
            print("3. Start coding with AI assistance!")
        else:
            print("❌ Portable package creation failed")
    else:
        print("❌ Build failed")
        sys.exit(1)