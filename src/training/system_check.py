#!/usr/bin/env python3
"""
System Resource Check for Ollama
Checks system resources that might affect Ollama performance
"""

import psutil
import platform
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_system_resources() -> Dict[str, Any]:
    """Check system resources"""
    logger.info("🔍 Checking system resources...")
    
    # CPU info
    cpu_count = psutil.cpu_count()
    cpu_percent = psutil.cpu_percent(interval=1)
    
    # Memory info
    memory = psutil.virtual_memory()
    memory_total_gb = memory.total / (1024**3)
    memory_available_gb = memory.available / (1024**3)
    memory_percent = memory.percent
    
    # Disk info
    disk = psutil.disk_usage('/')
    disk_total_gb = disk.total / (1024**3)
    disk_free_gb = disk.free / (1024**3)
    disk_percent = (disk.used / disk.total) * 100
    
    # System info
    system_info = {
        'platform': platform.system(),
        'platform_version': platform.version(),
        'architecture': platform.architecture()[0],
        'cpu_count': cpu_count,
        'cpu_percent': cpu_percent,
        'memory_total_gb': round(memory_total_gb, 2),
        'memory_available_gb': round(memory_available_gb, 2),
        'memory_percent': memory_percent,
        'disk_total_gb': round(disk_total_gb, 2),
        'disk_free_gb': round(disk_free_gb, 2),
        'disk_percent': round(disk_percent, 2)
    }
    
    logger.info("📊 System Resources:")
    logger.info(f"  Platform: {system_info['platform']} {system_info['platform_version']}")
    logger.info(f"  Architecture: {system_info['architecture']}")
    logger.info(f"  CPU: {system_info['cpu_count']} cores, {system_info['cpu_percent']}% usage")
    logger.info(f"  Memory: {system_info['memory_total_gb']} GB total, {system_info['memory_available_gb']} GB available ({system_info['memory_percent']}% used)")
    logger.info(f"  Disk: {system_info['disk_total_gb']} GB total, {system_info['disk_free_gb']} GB free ({system_info['disk_percent']}% used)")
    
    # Check for potential issues
    issues = []
    
    if memory_available_gb < 8:
        issues.append(f"⚠️ Low available memory: {memory_available_gb:.1f} GB (recommended: 8+ GB for 8B model)")
    
    if disk_free_gb < 10:
        issues.append(f"⚠️ Low disk space: {disk_free_gb:.1f} GB free")
    
    if cpu_percent > 90:
        issues.append(f"⚠️ High CPU usage: {cpu_percent}%")
    
    if issues:
        logger.warning("🚨 Potential resource issues detected:")
        for issue in issues:
            logger.warning(f"  {issue}")
    else:
        logger.info("✅ System resources look adequate for Ollama")
    
    return system_info

def check_ollama_processes() -> Dict[str, Any]:
    """Check for Ollama-related processes"""
    logger.info("🔍 Checking for Ollama processes...")
    
    ollama_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
        try:
            if 'ollama' in proc.info['name'].lower():
                ollama_processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'memory_mb': proc.info['memory_info'].rss / (1024**2),
                    'cpu_percent': proc.info['cpu_percent']
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    if ollama_processes:
        logger.info(f"✅ Found {len(ollama_processes)} Ollama processes:")
        total_memory = 0
        for proc in ollama_processes:
            logger.info(f"  PID {proc['pid']}: {proc['name']} - {proc['memory_mb']:.1f} MB RAM, {proc['cpu_percent']}% CPU")
            total_memory += proc['memory_mb']
        logger.info(f"  Total Ollama memory usage: {total_memory:.1f} MB")
    else:
        logger.warning("⚠️ No Ollama processes found")
    
    return {'ollama_processes': ollama_processes}

def main():
    """Main function"""
    logger.info("🚀 Starting system resource check...")
    
    # Check system resources
    system_info = check_system_resources()
    
    # Check Ollama processes
    process_info = check_ollama_processes()
    
    # Summary
    logger.info("\n📋 Summary:")
    logger.info(f"  System: {system_info['platform']} with {system_info['cpu_count']} cores")
    logger.info(f"  Memory: {system_info['memory_available_gb']:.1f} GB available")
    logger.info(f"  Ollama processes: {len(process_info['ollama_processes'])}")
    
    # Recommendations
    logger.info("\n💡 Recommendations:")
    if system_info['memory_available_gb'] < 8:
        logger.info("  - Close other applications to free up memory")
        logger.info("  - Consider using a smaller model (e.g., 3B instead of 8B)")
    
    if len(process_info['ollama_processes']) == 0:
        logger.info("  - Start Ollama: ollama serve")
    
    logger.info("  - For 8B models, ensure at least 8GB RAM is available")
    logger.info("  - Consider using GPU acceleration if available")

if __name__ == "__main__":
    main() 