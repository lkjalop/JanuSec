#!/usr/bin/env python3
"""
Comprehensive JanuSec Pipeline Analysis
Processes files through the full 21-stage threat detection pipeline
Tracks exit points and generates detailed flow analysis
"""

import asyncio
import json
import logging
import pandas as pd
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

# Add src to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('pipeline_analysis.log', mode='w')
    ]
)

logger = logging.getLogger(__name__)

class ComprehensivePipelineAnalysis:
    """Analyzes file processing through the complete JanuSec pipeline"""

    def __init__(self):
        self.orchestrator = None
        self.results = []
        self.pipeline_stages = [
            'baseline', 'regex', 'parent_child', 'endpoint', 'auth_burst',
            'graph', 'adaptive_pre', 'packet_summary', 'sbom_exec', 'sbom_vuln',
            'beacon', 'egress', 'domain_novelty', 'rare_token', 'hunt_lanes',
            'correlation', 'quality_filter', 'mapping', 'cluster_dedupe',
            'coverage_tracker', 'embedding'
        ]
        self.heavy_stages = ['beacon', 'egress', 'domain_novelty']

    async def initialize(self):
        """Initialize the JanuSec orchestrator"""
        try:
            from main import SecurityOrchestrator

            # Use lightweight config for analysis
            config_path = "config/main.yaml"
            self.orchestrator = SecurityOrchestrator(config_path)
            await self.orchestrator.initialize()
            logger.info("JanuSec orchestrator initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            # Fallback to mock analysis
            logger.info("Proceeding with mock pipeline analysis")

    def convert_file_to_event(self, file_path: str, file_data: Dict) -> Dict[str, Any]:
        """Convert file data to JanuSec event format"""
        return {
            'id': f"file-{hash(file_path)}",
            'timestamp': time.time(),
            'event_type': 'file_analysis',
            'file_path': file_path,
            'file_name': file_data.get('name', Path(file_path).name),
            'file_size': file_data.get('size', 0),
            'file_hash': file_data.get('sha256', ''),
            'signed': file_data.get('signed', False),
            'threat_score': file_data.get('threatScore', 0),
            'av_positives': file_data.get('avPositives', 0),
            'av_total': file_data.get('avTotal', 0),
            'malicious': file_data.get('malicious', False),
            'suspicious': file_data.get('suspicious', False),
            'tenant_id': 'cyberstash_analysis'
        }

    async def analyze_single_file(self, file_path: str, file_data: Dict) -> Dict:
        """Process a single file through the complete pipeline"""

        event = self.convert_file_to_event(file_path, file_data)

        if self.orchestrator:
            try:
                # Process through actual JanuSec pipeline
                result = await self.orchestrator.process_event(event)

                return {
                    'file_path': file_path,
                    'file_name': file_data.get('name', Path(file_path).name),
                    'event_id': event['id'],
                    'pipeline_result': {
                        'verdict': result.verdict,
                        'confidence': result.confidence,
                        'processing_time_ms': result.processing_time_ms,
                        'factors': result.factors,
                        'stage_timings': result.stage_timings,
                        'exit_stage': self.determine_exit_stage(result),
                        'exit_reason': self.determine_exit_reason(result),
                        'stages_executed': self.extract_executed_stages(result),
                        'stages_skipped': getattr(result, 'skipped_stages', []),
                        'routing_path': self.determine_routing_path(result)
                    },
                    'input_metadata': {
                        'original_threat_score': file_data.get('threatScore', 0),
                        'original_flag': file_data.get('flagName', 'Unknown'),
                        'original_av_detections': file_data.get('avPositives', 0),
                        'file_size': file_data.get('size', 0),
                        'signed': file_data.get('signed', False)
                    }
                }

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
                return self.create_error_result(file_path, file_data, str(e))
        else:
            # Mock analysis based on original data
            return self.create_mock_analysis(file_path, file_data)

    def determine_exit_stage(self, result) -> str:
        """Determine which stage the pipeline exited at"""
        stage_timings = result.stage_timings or []
        if not stage_timings:
            return "pre_pipeline"

        # Check for terminal exit
        if hasattr(result, 'stage') and result.stage == 'terminal':
            return stage_timings[-1].get('name', 'unknown_terminal')

        # Return last executed stage
        return stage_timings[-1].get('name', 'complete')

    def determine_exit_reason(self, result) -> str:
        """Determine why the pipeline exited"""
        if hasattr(result, 'stage'):
            if result.stage == 'terminal':
                return "terminal_hit"
            elif result.stage == 'complete':
                return "pipeline_complete"

        if 'processing_timeout' in result.factors:
            return "timeout_fallback"
        elif 'processing_error' in result.factors:
            return "error_fallback"

        return "normal_completion"

    def determine_routing_path(self, result) -> str:
        """Determine which routing path was taken"""
        if result.verdict == 'benign' and result.confidence < 0.3:
            return "fast_benign_path"
        elif result.verdict == 'malicious' and result.confidence > 0.8:
            return "fast_malicious_path"
        else:
            return "deep_analysis_path"

    def extract_executed_stages(self, result) -> List[str]:
        """Extract list of stages that were actually executed"""
        stage_timings = result.stage_timings or []
        return [stage.get('name', 'unknown') for stage in stage_timings]

    def create_error_result(self, file_path: str, file_data: Dict, error: str) -> Dict:
        """Create result for files that failed processing"""
        return {
            'file_path': file_path,
            'file_name': file_data.get('name', Path(file_path).name),
            'event_id': f"error-{hash(file_path)}",
            'pipeline_result': {
                'verdict': 'error',
                'confidence': 0.0,
                'processing_time_ms': 0.0,
                'factors': ['processing_error'],
                'stage_timings': [],
                'exit_stage': 'error',
                'exit_reason': f"processing_error: {error}",
                'stages_executed': [],
                'stages_skipped': self.pipeline_stages,
                'routing_path': 'error_fallback'
            },
            'input_metadata': {
                'original_threat_score': file_data.get('threatScore', 0),
                'original_flag': file_data.get('flagName', 'Unknown'),
                'original_av_detections': file_data.get('avPositives', 0),
                'file_size': file_data.get('size', 0),
                'signed': file_data.get('signed', False)
            }
        }

    def create_mock_analysis(self, file_path: str, file_data: Dict) -> Dict:
        """Create mock pipeline analysis when orchestrator unavailable"""

        # Simulate pipeline processing based on original threat indicators
        original_score = file_data.get('threatScore', 0)
        av_detections = file_data.get('avPositives', 0)
        flag_name = file_data.get('flagName', 'Unknown')

        # Determine mock verdict
        if av_detections > 2 or original_score > 3:
            verdict = 'suspicious'
            confidence = min(0.8, (original_score / 10) + (av_detections / 10))
            exit_stage = 'hunt_lanes'
            routing_path = 'deep_analysis_path'
        elif flag_name == 'For Review':
            verdict = 'suspicious'
            confidence = 0.6
            exit_stage = 'quality_filter'
            routing_path = 'deep_analysis_path'
        elif flag_name in ['Probably Good', 'Verified Good']:
            verdict = 'benign'
            confidence = 0.2
            exit_stage = 'baseline'
            routing_path = 'fast_benign_path'
        else:
            verdict = 'unknown'
            confidence = 0.5
            exit_stage = 'correlation'
            routing_path = 'deep_analysis_path'

        # Mock stage execution based on exit point
        stage_index = self.pipeline_stages.index(exit_stage) if exit_stage in self.pipeline_stages else len(self.pipeline_stages) - 1
        executed_stages = self.pipeline_stages[:stage_index + 1]
        skipped_stages = self.pipeline_stages[stage_index + 1:] if confidence > 0.8 else []

        return {
            'file_path': file_path,
            'file_name': file_data.get('name', Path(file_path).name),
            'event_id': f"mock-{hash(file_path)}",
            'pipeline_result': {
                'verdict': verdict,
                'confidence': confidence,
                'processing_time_ms': len(executed_stages) * 5.0,  # Mock timing
                'factors': self.generate_mock_factors(file_data, executed_stages),
                'stage_timings': [{'name': stage, 'duration_ms': 5.0, 'confidence_after': confidence} for stage in executed_stages],
                'exit_stage': exit_stage,
                'exit_reason': 'mock_analysis_complete',
                'stages_executed': executed_stages,
                'stages_skipped': skipped_stages,
                'routing_path': routing_path
            },
            'input_metadata': {
                'original_threat_score': original_score,
                'original_flag': flag_name,
                'original_av_detections': av_detections,
                'file_size': file_data.get('size', 0),
                'signed': file_data.get('signed', False)
            }
        }

    def generate_mock_factors(self, file_data: Dict, executed_stages: List[str]) -> List[str]:
        """Generate mock factors based on file characteristics"""
        factors = []

        if file_data.get('signed', False):
            factors.append('digitally_signed')
        else:
            factors.append('unsigned_binary')

        if file_data.get('avPositives', 0) > 0:
            factors.append('av_detection')

        if file_data.get('threatScore', 0) > 2:
            factors.append('elevated_threat_score')

        if 'solarwinds' in file_data.get('name', '').lower():
            factors.append('supply_chain_risk')

        if any(tool in file_data.get('name', '').lower() for tool in ['putty', 'teamviewer', 'remote']):
            factors.append('remote_access_tool')

        # Add stage-specific factors
        if 'hunt_lanes' in executed_stages:
            factors.append('hunt_lane_processed')
        if 'correlation' in executed_stages:
            factors.append('correlation_analyzed')

        return factors[:10]  # Limit factors

    async def process_all_files(self):
        """Process all files through the pipeline"""
        logger.info("Starting comprehensive pipeline analysis...")

        # Load input data
        df = pd.read_excel(r'D:\AI\Threat_thy_sniffer\dump\Cyberstash_csv2.xlsx')
        paths_df = pd.read_excel(r'D:\AI\Threat_thy_sniffer\dump\cybstash csv1.xlsx')

        # Combine data
        combined_data = []
        for idx, row in df.iterrows():
            file_path = paths_df.iloc[idx]['path'] if idx < len(paths_df) else f"unknown_{idx}"
            combined_data.append((file_path, row.to_dict()))

        logger.info(f"Processing {len(combined_data)} files through JanuSec pipeline...")

        # Process files in batches to avoid overwhelming the system
        batch_size = 50
        for i in range(0, len(combined_data), batch_size):
            batch = combined_data[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(combined_data) + batch_size - 1)//batch_size}")

            batch_tasks = [
                self.analyze_single_file(file_path, file_data)
                for file_path, file_data in batch
            ]

            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Batch processing error: {result}")
                else:
                    self.results.append(result)

            # Small delay between batches
            await asyncio.sleep(0.1)

        logger.info(f"Completed processing {len(self.results)} files")

    async def generate_comprehensive_report(self):
        """Generate comprehensive pipeline flow analysis report"""

        # Analyze exit points
        exit_stages = {}
        exit_reasons = {}
        routing_paths = {}
        verdicts = {}

        for result in self.results:
            pipeline = result['pipeline_result']

            exit_stage = pipeline['exit_stage']
            exit_stages[exit_stage] = exit_stages.get(exit_stage, 0) + 1

            exit_reason = pipeline['exit_reason']
            exit_reasons[exit_reason] = exit_reasons.get(exit_reason, 0) + 1

            routing_path = pipeline['routing_path']
            routing_paths[routing_path] = routing_paths.get(routing_path, 0) + 1

            verdict = pipeline['verdict']
            verdicts[verdict] = verdicts.get(verdict, 0) + 1

        # Create comprehensive report
        report = {
            'analysis_summary': {
                'total_files_processed': len(self.results),
                'pipeline_stages': len(self.pipeline_stages),
                'heavy_stages': len(self.heavy_stages),
                'analysis_timestamp': time.time()
            },
            'pipeline_exit_analysis': {
                'exit_stage_distribution': exit_stages,
                'exit_reason_distribution': exit_reasons,
                'routing_path_distribution': routing_paths,
                'verdict_distribution': verdicts
            },
            'stage_performance': self.analyze_stage_performance(),
            'detailed_file_results': self.results
        }

        # Save detailed results
        with open('comprehensive_pipeline_analysis_results.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return report

    def analyze_stage_performance(self) -> Dict:
        """Analyze performance of each pipeline stage"""
        stage_stats = {}

        for result in self.results:
            executed_stages = result['pipeline_result']['stages_executed']
            skipped_stages = result['pipeline_result']['stages_skipped']

            for stage in executed_stages:
                if stage not in stage_stats:
                    stage_stats[stage] = {'executed': 0, 'skipped': 0}
                stage_stats[stage]['executed'] += 1

            for stage in skipped_stages:
                if stage not in stage_stats:
                    stage_stats[stage] = {'executed': 0, 'skipped': 0}
                stage_stats[stage]['skipped'] += 1

        return stage_stats

    async def shutdown(self):
        """Clean shutdown"""
        if self.orchestrator:
            await self.orchestrator.shutdown()


async def main():
    """Main analysis function"""
    analyzer = ComprehensivePipelineAnalysis()

    try:
        await analyzer.initialize()
        await analyzer.process_all_files()
        report = await analyzer.generate_comprehensive_report()

        print("\\n" + "="*80)
        print("JANUSEC COMPREHENSIVE PIPELINE ANALYSIS COMPLETE")
        print("="*80)

        print(f"\\nProcessed: {report['analysis_summary']['total_files_processed']} files")
        print(f"Pipeline Stages: {report['analysis_summary']['pipeline_stages']}")

        print("\\nVERDICT DISTRIBUTION:")
        for verdict, count in report['pipeline_exit_analysis']['verdict_distribution'].items():
            percentage = (count / len(analyzer.results)) * 100
            print(f"  {verdict}: {count} files ({percentage:.1f}%)")

        print("\\nROUTING PATH DISTRIBUTION:")
        for path, count in report['pipeline_exit_analysis']['routing_path_distribution'].items():
            percentage = (count / len(analyzer.results)) * 100
            print(f"  {path}: {count} files ({percentage:.1f}%)")

        print("\\nEXIT STAGE DISTRIBUTION:")
        for stage, count in sorted(report['pipeline_exit_analysis']['exit_stage_distribution'].items(),
                                 key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / len(analyzer.results)) * 100
            print(f"  {stage}: {count} files ({percentage:.1f}%)")

        print("\\nDetailed results saved to: comprehensive_pipeline_analysis_results.json")
        print("Pipeline analysis log: pipeline_analysis.log")

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
    finally:
        await analyzer.shutdown()


if __name__ == "__main__":
    asyncio.run(main())