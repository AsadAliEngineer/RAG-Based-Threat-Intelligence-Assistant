#!/usr/bin/env python3
"""
Quick Data Analysis Runner
Runs the comprehensive data analysis and provides immediate recommendations.
"""

import sys
import argparse
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from analyze_training_data import TrainingDataAnalyzer

def main():
    """Run data analysis and provide recommendations"""
    parser = argparse.ArgumentParser(description="Quick CVE Training Data Analysis")
    parser.add_argument("--dataset", default="data/training_datasets/enhanced_training_dataset_with_mitigations.json",
                       help="Path to training dataset")
    parser.add_argument("--sample-size", type=int, default=200,
                       help="Number of samples to analyze")
    parser.add_argument("--no-viz", action="store_true",
                       help="Skip visualization generation")
    
    args = parser.parse_args()
    
    print("🔍 CVE Training Data Analysis")
    print("=" * 50)
    
    # Check if dataset exists
    dataset_path = args.dataset
    if not Path(dataset_path).exists():
        print(f"❌ Dataset not found: {dataset_path}")
        print("Please run dataset_preparation.py first to create the training dataset")
        return False
    
    # Run analysis
    analyzer = TrainingDataAnalyzer(dataset_path)
    
    print("📊 Running comprehensive data analysis...")
    print("This will analyze:")
    print("  - Instruction diversity")
    print("  - Input diversity") 
    print("  - Output patterns")
    print("  - Duplicate detection")
    print("  - Data distribution")
    print()
    
    success = analyzer.run_full_analysis(sample_size=args.sample_size, generate_viz=not args.no_viz)
    
    if success:
        print("\n📁 Analysis results saved to 'data_analysis/' directory")
        print("📊 Check 'data_analysis_visualization.png' for visualizations")
        print("📝 Check 'data_analysis_report.md' for detailed report")
        
        # Provide immediate recommendations
        red_flag_count = sum(1 for results in analyzer.analysis_results.values() 
                           if 'red_flag' in results and results['red_flag'])
        
        print("\n🎯 IMMEDIATE RECOMMENDATIONS:")
        print("=" * 50)
        
        if red_flag_count > 2:
            print("❌ CRITICAL: Multiple data quality issues detected!")
            print("   → Fix data quality before training")
            print("   → Consider data augmentation")
            print("   → Remove duplicate examples")
            print("   → Increase validation set size")
        elif red_flag_count > 0:
            print("⚠️ WARNING: Some data quality issues detected")
            print("   → Use overfitting fixes in training pipeline")
            print("   → Start with small subsets (--subset 10)")
            print("   → Monitor training closely")
            print("   → Consider data cleaning")
        else:
            print("✅ GOOD: Data quality looks acceptable")
            print("   → Safe to proceed with training")
            print("   → Use standard training settings")
            print("   → Monitor for overfitting during training")
        
        print("\n🚀 NEXT STEPS:")
        print("1. Review the detailed report in data_analysis_report.md")
        print("2. Run training test: python test_overfitting_fixes.py")
        print("3. Start training: python src/training/fine_tuning_pipeline.py --subset 10")
        
        return True
    else:
        print("❌ Data analysis failed!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 