#!/usr/bin/env python3
"""
Test runner script for ChromaDB Admin application.
Provides different test execution modes and configurations.
"""

import os
import sys
import subprocess
import argparse
from typing import List, Optional


def run_command(cmd: List[str], description: str) -> bool:
    """Run a command and return success status"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('='*60)
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed with exit code {e.returncode}")
        return False


def setup_test_environment():
    """Set up test environment variables"""
    os.environ.update({
        'TEST_MODE': '1',
        'SECRET_KEY': 'test-secret-key-for-testing-only',
        'DATABASE_URL': 'sqlite:///./test.db',
        'CREATE_INITIAL_ADMIN': 'false',
        'CHROMADB_HOST': 'localhost',
        'CHROMADB_PORT': '8000'
    })
    print("Test environment variables set")


def run_unit_tests(verbose: bool = False, coverage: bool = True) -> bool:
    """Run unit tests"""
    cmd = ['python', '-m', 'pytest', 'tests/', '-m', 'not integration and not slow']
    
    if verbose:
        cmd.extend(['-v', '-s'])
    
    if coverage:
        cmd.extend(['--cov=app', '--cov-report=term-missing'])
    
    return run_command(cmd, "Unit Tests")


def run_integration_tests(verbose: bool = False) -> bool:
    """Run integration tests"""
    cmd = ['python', '-m', 'pytest', 'tests/', '-m', 'integration']
    
    if verbose:
        cmd.extend(['-v', '-s'])
    
    return run_command(cmd, "Integration Tests")


def run_all_tests(verbose: bool = False, coverage: bool = True) -> bool:
    """Run all tests"""
    cmd = ['python', '-m', 'pytest', 'tests/']
    
    if verbose:
        cmd.extend(['-v', '-s'])
    
    if coverage:
        cmd.extend(['--cov=app', '--cov-report=html', '--cov-report=term-missing'])
    
    return run_command(cmd, "All Tests")


def run_specific_test_file(test_file: str, verbose: bool = False) -> bool:
    """Run tests from a specific file"""
    cmd = ['python', '-m', 'pytest', f'tests/{test_file}']
    
    if verbose:
        cmd.extend(['-v', '-s'])
    
    return run_command(cmd, f"Tests from {test_file}")


def run_tests_by_marker(marker: str, verbose: bool = False) -> bool:
    """Run tests with specific marker"""
    cmd = ['python', '-m', 'pytest', 'tests/', '-m', marker]
    
    if verbose:
        cmd.extend(['-v', '-s'])
    
    return run_command(cmd, f"Tests with marker: {marker}")


def run_linting() -> bool:
    """Run code linting"""
    success = True
    
    # Check if flake8 is available
    try:
        subprocess.run(['flake8', '--version'], check=True, capture_output=True)
        success &= run_command(['flake8', 'app/', 'tests/'], "Flake8 Linting")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  Flake8 not available, skipping linting")
    
    # Check if black is available
    try:
        subprocess.run(['black', '--version'], check=True, capture_output=True)
        success &= run_command(['black', '--check', '--diff', 'app/', 'tests/'], "Black Code Formatting Check")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  Black not available, skipping format check")
    
    return success


def run_type_checking() -> bool:
    """Run type checking with mypy"""
    try:
        subprocess.run(['mypy', '--version'], check=True, capture_output=True)
        return run_command(['mypy', 'app/'], "MyPy Type Checking")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  MyPy not available, skipping type checking")
        return True


def clean_test_artifacts():
    """Clean up test artifacts"""
    import shutil
    import glob
    
    artifacts = [
        'test.db',
        '.coverage',
        'htmlcov/',
        '.pytest_cache/',
        '**/__pycache__/',
        '**/*.pyc'
    ]
    
    for pattern in artifacts:
        for path in glob.glob(pattern, recursive=True):
            try:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
                print(f"Cleaned: {path}")
            except OSError:
                pass


def install_test_dependencies() -> bool:
    """Install test dependencies"""
    return run_command([
        'pip', 'install', '-r', 'requirements.txt'
    ], "Installing Test Dependencies")


def main():
    parser = argparse.ArgumentParser(description='ChromaDB Admin Test Runner')
    parser.add_argument('--mode', choices=['unit', 'integration', 'all', 'file', 'marker'], 
                       default='all', help='Test execution mode')
    parser.add_argument('--file', help='Specific test file to run (for file mode)')
    parser.add_argument('--marker', help='Test marker to filter by (for marker mode)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--no-coverage', action='store_true', help='Skip coverage reporting')
    parser.add_argument('--lint', action='store_true', help='Run linting')
    parser.add_argument('--type-check', action='store_true', help='Run type checking')
    parser.add_argument('--install-deps', action='store_true', help='Install dependencies first')
    parser.add_argument('--clean', action='store_true', help='Clean test artifacts before running')
    parser.add_argument('--ci', action='store_true', help='CI mode (install deps, run all checks, no interactive)')
    
    args = parser.parse_args()
    
    # Setup
    setup_test_environment()
    
    if args.clean:
        clean_test_artifacts()
    
    if args.install_deps or args.ci:
        if not install_test_dependencies():
            sys.exit(1)
    
    success = True
    
    # CI mode runs everything
    if args.ci:
        print("🚀 Running in CI mode - executing all checks")
        success &= run_linting()
        success &= run_type_checking()
        success &= run_all_tests(verbose=True, coverage=True)
    else:
        # Run linting if requested
        if args.lint:
            success &= run_linting()
        
        # Run type checking if requested
        if args.type_check:
            success &= run_type_checking()
        
        # Run tests based on mode
        coverage = not args.no_coverage
        
        if args.mode == 'unit':
            success &= run_unit_tests(args.verbose, coverage)
        elif args.mode == 'integration':
            success &= run_integration_tests(args.verbose)
        elif args.mode == 'all':
            success &= run_all_tests(args.verbose, coverage)
        elif args.mode == 'file':
            if not args.file:
                print("❌ --file argument required for file mode")
                sys.exit(1)
            success &= run_specific_test_file(args.file, args.verbose)
        elif args.mode == 'marker':
            if not args.marker:
                print("❌ --marker argument required for marker mode")
                sys.exit(1)
            success &= run_tests_by_marker(args.marker, args.verbose)
    
    # Summary
    print("\n" + "="*60)
    if success:
        print("🎉 All tests and checks completed successfully!")
        print("✅ Build is ready for deployment")
    else:
        print("💥 Some tests or checks failed!")
        print("❌ Please fix the issues before proceeding")
    print("="*60)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main() 