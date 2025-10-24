#!/usr/bin/env python3
"""
Alternative Build Script - FIXED & ENHANCED
Simplified build process for problematic environments
DarkForge-X Alternative Build System
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def clean_build_artifacts():
    """Clean all build artifacts"""
    print("🧹 Cleaning build artifacts...")
    
    # Remove build directories
    for dir_name in ['build', 'dist', '__pycache__']:
        if Path(dir_name).exists():
            shutil.rmtree(dir_name)
            print(f"✅ Removed: {dir_name}")
    
    # Remove build files
    for file_pattern in ['*.spec', 'version.txt']:
        for file in Path('.').glob(file_pattern):
            file.unlink()
            print(f"✅ Removed: {file}")
    
    # Remove portable directories
    for portable_dir in Path('.').glob('*Portable*'):
        if portable_dir.is_dir():
            shutil.rmtree(portable_dir)
            print(f"✅ Removed: {portable_dir}")

def check_python_environment():
    """Check Python environment and dependencies"""
    print("🔍 Checking Python environment...")
    
    # Check Python version
    python_version = sys.version_info
    print(f"✅ Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 7):
        print("❌ Python 3.7 or higher required")
        return False
    
    # Check required modules
    required_modules = ['tkinter', 'pathlib', 'hashlib', 'threading']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ Module: {module}")
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"❌ Missing required modules: {missing_modules}")
        return False
    
    return True

def simple_pyinstaller_build():
    """Simple PyInstaller build without complex options"""
    print("🔨 Starting simplified build process...")
    
    # Basic PyInstaller command
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        'nexus_ai.py',           # Main script
        '--name=NEXUS-AI',       # Output name
        '--onefile',             # Single executable
        '--windowed',            # No console window
        '--clean',               # Clean build cache
        '--noconfirm'           # Overwrite without confirmation
    ]
    
    print(f"📦 Build command: {' '.join(cmd)}")
    
    try:
        # Run build process
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', timeout=300)
        
        if result.returncode == 0:
            print("✅ Build process completed successfully")
            return True
        else:
            print(f"❌ Build failed with return code: {result.returncode}")
            if result.stdout:
                print(f"📋 Build output: {result.stdout[-500:]}")  # Last 500 chars
            if result.stderr:
                print(f"❌ Build errors: {result.stderr[-500:]}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Build timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"❌ Build exception: {e}")
        return False

def verify_build_result():
    """Verify that build was successful"""
    print("🔍 Verifying build result...")
    
    # Check for executable
    if sys.platform == 'win32':
        exe_path = Path("dist/NEXUS-AI.exe")
    else:
        exe_path = Path("dist/NEXUS-AI")
    
    if not exe_path.exists():
        print("❌ Executable not found in dist directory")
        return False
    
    # Check file size
    exe_size = exe_path.stat().st_size
    size_mb = exe_size / (1024 * 1024)
    
    print(f"✅ Executable found: {exe_path}")
    print(f"📊 File size: {size_mb:.2f} MB")
    
    if size_mb < 1:
        print("⚠️  Executable seems very small - might be incomplete")
        return False
    
    return True

def create_simple_portable():
    """Create simple portable package"""
    print("🎒 Creating simple portable package...")
    
    portable_dir = Path("NEXUS-AI_Simple_Portable")
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
        
        # Make executable on Unix
        if sys.platform != 'win32':
            os.chmod(exe_dest, 0o755)
        
        # Create simple README
        with open(portable_dir / "README.txt", "w", encoding='utf-8') as f:
            f.write("""NEXUS-AI - Simple Portable Version

Run NEXUS-AI.exe (Windows) or ./NEXUS-AI (Linux/Mac)

Features:
- Code Editor with AI Assistant
- File System Explorer
- Security Scanning
- Multilingual Support

For full features, ensure all .py files are in the same directory.
""")
        
        print(f"✅ Simple portable package created: {portable_dir}")
        return True
    else:
        print("❌ Could not create portable package - executable missing")
        return False

def manual_dependency_check():
    """Manual dependency check and installation"""
    print("🔧 Checking for PyInstaller...")
    
    try:
        import PyInstaller
        print("✅ PyInstaller is available")
        return True
    except ImportError:
        print("❌ PyInstaller not found")
        
        install = input("Install PyInstaller? (y/n): ").lower().strip()
        if install == 'y':
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
                print("✅ PyInstaller installed successfully")
                return True
            except subprocess.CalledProcessError:
                print("❌ Failed to install PyInstaller")
                return False
        else:
            print("⚠️  Cannot build without PyInstaller")
            return False

def main():
    """Main alternative build process"""
    print("=" * 60)
    print("🛠️  NEXUS-AI Alternative Build System")
    print("=" * 60)
    
    # Clean previous builds
    clean_build_artifacts()
    
    # Check environment
    if not check_python_environment():
        print("❌ Python environment check failed")
        sys.exit(1)
    
    # Check dependencies
    if not manual_dependency_check():
        print("❌ Dependency check failed")
        sys.exit(1)
    
    # Build executable
    if simple_pyinstaller_build():
        if verify_build_result():
            # Create portable package
            if create_simple_portable():
                print("\n🎉 Alternative build completed successfully!")
                print(f"📁 Your executable is in: {Path('NEXUS-AI_Simple_Portable')}")
                print("\n🚀 You can now run NEXUS-AI!")
            else:
                print("\n⚠️  Build completed but portable package creation failed")
                print("📁 Your executable is in: dist/ directory")
        else:
            print("\n❌ Build verification failed")
            sys.exit(1)
    else:
        print("\n❌ Alternative build failed")
        print("\n💡 TROUBLESHOOTING TIPS:")
        print("1. Run directly: python nexus_ai.py")
        print("2. Check file permissions")
        print("3. Try different Python version")
        print("4. Manual build: python -m PyInstaller nexus_ai.py --onefile --windowed")
        sys.exit(1)

if __name__ == "__main__":
    main()