"""Package Analyzer - Unified Interface for Package Malice Detection

Core workflow:
1. Scan package directory with prioritized file ordering
2. For each file: Slice -> Model -> Detect
3. Save comprehensive analysis results

Supports: PyPI (Python) and NPM (JavaScript) packages
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PYGUARD_ROOT)

from Configs.config import PyGuardConfig
from Core.RAG.rag_knowledge_builder import PatternKnowledge, CaseKnowledge, PromptManager
from Core.Detector.code_slicer import CodeSlicer, SliceOutput
from Core.Detector.api_extractor import APISequenceExtractor, APIModelOutput
from Core.Detector.malice_detector import MaliceDetector, DetectionOutput


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class FileAnalysisResult:
    """Analysis result for a single file"""
    file_path: str
    file_type: str
    priority: str  # "high" or "normal"
    
    # Slicing result
    slices: List[Dict[str, Any]]
    slice_count: int
    
    # Per-slice analysis
    slice_analyses: List[Dict[str, Any]]
    
    # File-level summary
    is_malicious: bool
    max_confidence: float
    max_risk_level: str
    malicious_slice_count: int
    
    analysis_time: float
    error: Optional[str] = None


@dataclass
class PackageAnalysisResult:
    """Complete analysis result for a package"""
    package_path: str
    package_manager: str
    analysis_timestamp: str
    
    total_files_found: int
    total_files_analyzed: int
    high_priority_files: int
    
    file_results: List[FileAnalysisResult]
    
    # Package-level summary
    is_package_malicious: bool
    malicious_file_count: int
    max_risk_level: str
    total_analysis_time: float

    configuration: Dict[str, Any] = None


def _analyze_file_core(
    file_path: Path,
    priority: str,
    slicer: CodeSlicer,
    extractor: APISequenceExtractor,
    detector: MaliceDetector,
    package_name: Optional[str] = None
) -> FileAnalysisResult:
    """
    Core implementation that performs slice -> model -> detect for a single file.
    Separated from PackageAnalyzer instance to enable multiprocessing execution.
    """
    start_time = datetime.now()
    file_path = Path(file_path)

    try:
        logger.info(f"Analyzing [{priority}] {file_path.name}")

        # Check if file is empty - skip analysis if so
        try:
            file_content = file_path.read_text(encoding='utf-8', errors='ignore')
            if not file_content.strip():
                logger.info(f"Skipping empty file: {file_path.name}")
                return FileAnalysisResult(
                    file_path=str(file_path),
                    file_type=file_path.suffix,
                    priority=priority,
                    slices=[],
                    slice_count=0,
                    slice_analyses=[],
                    is_malicious=False,
                    max_confidence=0.0,
                    max_risk_level="benign",
                    malicious_slice_count=0,
                    analysis_time=(datetime.now() - start_time).total_seconds()
                )
        except Exception as e:
            logger.warning(f"Failed to read file {file_path.name}: {e}")
            # Continue with analysis anyway

        # Step 1: Code Slicing
        slice_output: SliceOutput = slicer.slice(str(file_path))
        slices = slice_output.slices

        if not slices:
            logger.warning(f"No slices extracted from {file_path.name}")
            return FileAnalysisResult(
                file_path=str(file_path),
                file_type=file_path.suffix,
                priority=priority,
                slices=[],
                slice_count=0,
                slice_analyses=[],
                is_malicious=False,
                max_confidence=0.0,
                max_risk_level="benign",
                malicious_slice_count=0,
                analysis_time=(datetime.now() - start_time).total_seconds()
            )

        # Step 2 & 3: For each slice, Model API + Detect
        slice_analyses = []
        malicious_count = 0
        max_confidence = 0.0
        max_risk = "benign"

        risk_order = {"benign": 0, "low": 1, "medium": 2, "high": 3, "unknown": 0}

        for i, slice_item in enumerate(slices):
            code_context = slice_item.get("code", "")

            if not code_context.strip():
                continue

            # API Modeling
            api_output: APIModelOutput = extractor.extract(code_context)

            # Malice Detection - build additional context
            context_dict = {
                "file_path": str(file_path),
                "slice_id": slice_item.get("slice_id", f"slice_{i}"),
                "api_sequence": api_output.api_sequence,
                "object_sequence": api_output.object_sequence,
                "intention_sequence": api_output.intention_sequence
            }

            if package_name:
                context_dict["package_name"] = package_name

            detection_output: DetectionOutput = detector.detect(
                code_context=code_context,
                action_sequence=api_output.action_sequence,
                additional_context=context_dict
            )

            # Aggregate results
            if detection_output.is_malicious:
                malicious_count += 1

            if detection_output.confidence > max_confidence:
                max_confidence = detection_output.confidence

            if risk_order.get(detection_output.risk_level, 0) > risk_order.get(max_risk, 0):
                max_risk = detection_output.risk_level

            # Store slice analysis
            slice_analyses.append({
                "slice_id": slice_item.get("slice_id"),
                "slice_purpose": slice_item.get("purpose", ""),
                "code_snippet": code_context,
                "api_sequence": api_output.api_sequence,
                "action_sequence": api_output.action_sequence,
                "object_sequence": api_output.object_sequence,
                "intention_sequence": api_output.intention_sequence,
                "is_malicious": detection_output.is_malicious,
                "confidence": detection_output.confidence,
                "risk_level": detection_output.risk_level,
                "matched_patterns": detection_output.matched_patterns,
                "llm_reasoning": detection_output.llm_reasoning,
                "explanation": detection_output.explanation,
                "recommendation": detection_output.recommendation
            })

        analysis_time = (datetime.now() - start_time).total_seconds()

        return FileAnalysisResult(
            file_path=str(file_path),
            file_type=file_path.suffix,
            priority=priority,
            slices=[asdict(s) if hasattr(s, '__dict__') else s for s in slices],
            slice_count=len(slices),
            slice_analyses=slice_analyses,
            is_malicious=malicious_count > 0,
            max_confidence=max_confidence,
            max_risk_level=max_risk,
            malicious_slice_count=malicious_count,
            analysis_time=analysis_time
        )

    except Exception as e:
        logger.error(f"Error analyzing {file_path.name}: {e}")
        return FileAnalysisResult(
            file_path=str(file_path),
            file_type=file_path.suffix,
            priority=priority,
            slices=[],
            slice_count=0,
            slice_analyses=[],
            is_malicious=False,
            max_confidence=0.0,
            max_risk_level="unknown",
            malicious_slice_count=0,
            analysis_time=(datetime.now() - start_time).total_seconds(),
            error=str(e)
        )


def _multiprocess_file_runner(task: Dict[str, Any]) -> FileAnalysisResult:
    """Entry point for multiprocessing pool."""
    slicer = CodeSlicer()
    extractor = APISequenceExtractor()
    detector = MaliceDetector()
    return _analyze_file_core(
        file_path=Path(task["file_path"]),
        priority=task["priority"],
        slicer=slicer,
        extractor=extractor,
        detector=detector,
        package_name=task.get("package_name")
    )


def _build_error_result(file_path: str, priority: str, error: str) -> FileAnalysisResult:
    return FileAnalysisResult(
        file_path=file_path,
        file_type=Path(file_path).suffix,
        priority=priority,
        slices=[],
        slice_count=0,
        slice_analyses=[],
        is_malicious=False,
        max_confidence=0.0,
        max_risk_level="unknown",
        malicious_slice_count=0,
        analysis_time=0.0,
        error=error
    )


class PackageAnalyzer:
    """Unified package analysis interface"""
    
    # File priority definitions
    PYPI_HIGH_PRIORITY = ['setup.py', '__init__.py']
    NPM_HIGH_PRIORITY = ['index.js', 'package.json']
    
    # File extension definitions
    PYPI_EXTENSIONS = {'.py', '.sh'}
    NPM_EXTENSIONS = {'.js', '.json'}
    
    def __init__(
        self,
        slicer: Optional[CodeSlicer] = None,
        extractor: Optional[APISequenceExtractor] = None,
        detector: Optional[MaliceDetector] = None
    ):
        """
        Initialize package analyzer

        Args:
            slicer: Custom code slicer (optional)
            extractor: Custom API extractor (optional)
            detector: Custom malice detector (optional)
        """
        self.max_files = PyGuardConfig.MAX_ANALYSIS_FILES
        self.file_analysis_workers = PyGuardConfig.get_file_analysis_workers()
        self.slicer = slicer or CodeSlicer()
        self.extractor = extractor or APISequenceExtractor()
        self.detector = detector or MaliceDetector()
        logger.info(
            "PackageAnalyzer initialized with max_files=%s, file_analysis_workers=%s",
            self.max_files,
            self.file_analysis_workers
        )
    
    def _discover_files(
        self, 
        package_path: Path, 
        package_manager: str
    ) -> Tuple[List[Path], List[Path]]:
        """
        Discover and prioritize files in package
        
        Returns:
            (high_priority_files, normal_priority_files)
        """
        if package_manager.lower() == 'pypi':
            high_priority_names = self.PYPI_HIGH_PRIORITY
            extensions = self.PYPI_EXTENSIONS
        elif package_manager.lower() == 'npm':
            high_priority_names = self.NPM_HIGH_PRIORITY
            extensions = self.NPM_EXTENSIONS
        else:
            raise ValueError(f"Unsupported package manager: {package_manager}")
        
        high_priority_files = []
        normal_files = []
        
        # Walk through all files in package
        for file_path in package_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Check if file has target extension
            if file_path.suffix not in extensions:
                continue
            
            # Check priority
            if file_path.name in high_priority_names:
                high_priority_files.append(file_path)
            else:
                normal_files.append(file_path)
        
        # Sort by depth (shallower first) then by name for deterministic ordering
        # Depth is calculated by the number of path components relative to package_path
        def sort_key(file_path: Path) -> tuple:
            try:
                relative_path = file_path.relative_to(package_path)
                depth = len(relative_path.parts)
            except ValueError:
                depth = 999  # fallback for paths not relative to package_path
            return (depth, str(file_path))
        
        high_priority_files.sort(key=sort_key)
        normal_files.sort(key=sort_key)
        
        logger.info(
            f"Discovered {len(high_priority_files)} high-priority files, "
            f"{len(normal_files)} normal files"
        )
        
        return high_priority_files, normal_files
    
    def _execute_file_tasks(self, tasks: List[Dict[str, Any]]) -> List[FileAnalysisResult]:
        """Run file analysis tasks sequentially or in parallel based on configuration."""
        if not tasks:
            return []
        
        # Fallback to sequential execution when workers <= 1
        if self.file_analysis_workers <= 1 or len(tasks) == 1:
            results = []
            for task in tasks:
                results.append(self._analyze_file(
                    file_path=Path(task["file_path"]),
                    priority=task["priority"],
                    package_name=task.get("package_name")
                ))
            return results
        
        results: List[Optional[FileAnalysisResult]] = [None] * len(tasks)
        logger.info("Running file analysis with %s parallel workers", self.file_analysis_workers)
        
        with ProcessPoolExecutor(max_workers=self.file_analysis_workers) as executor:
            future_to_index = {}
            for idx, task in enumerate(tasks):
                future = executor.submit(_multiprocess_file_runner, task)
                future_to_index[future] = idx
            
            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                task = tasks[idx]
                try:
                    results[idx] = future.result()
                except Exception as exc:
                    logger.error(
                        "Parallel analysis failed for %s: %s",
                        task.get("file_path"),
                        exc
                    )
                    results[idx] = _build_error_result(task.get("file_path", ""), task.get("priority", "normal"), str(exc))
        
        # Filter out any None slots just in case
        return [res for res in results if res is not None]
    
    def _analyze_file(
        self,
        file_path: Path,
        priority: str,
        package_name: Optional[str] = None
    ) -> FileAnalysisResult:
        return _analyze_file_core(
            file_path=file_path,
            priority=priority,
            slicer=self.slicer,
            extractor=self.extractor,
            detector=self.detector,
            package_name=package_name
        )
    
    def analyze_package(
        self,
        package_path: str,
        package_manager: str,
        version: str = "unknown",
        output_path: Optional[str] = None
    ) -> PackageAnalysisResult:
        """
        Analyze a complete package
        
        Args:
            package_path: Path to extracted package directory
            package_manager: 'pypi' or 'npm'
            version: Package version (default: "unknown")
            output_path: Optional path to save results (JSON)
        
        Returns:
            PackageAnalysisResult with complete analysis
        """
        start_time = datetime.now()
        package_path = Path(package_path)
        
        if not package_path.exists():
            raise FileNotFoundError(f"Package path not found: {package_path}")
        
        logger.info(f"Starting package analysis: {package_path.name}")
        logger.info(f"Package manager: {package_manager}")

        # Step 1: Discover files
        high_priority_files, normal_files = self._discover_files(
            package_path, package_manager
        )
        
        # Early return if no relevant files found
        total_files = len(high_priority_files) + len(normal_files)
        if total_files == 0:
            logger.info(f"No relevant files found in package {package_path.name}, returning empty result")
            return PackageAnalysisResult(
                package_path=str(package_path),
                package_manager=package_manager,
                analysis_timestamp=datetime.now().isoformat(),
                total_files_found=0,
                total_files_analyzed=0,
                high_priority_files=0,
                file_results=[],
                is_package_malicious=False,
                malicious_file_count=0,
                max_risk_level="benign",
                total_analysis_time=0.0,
                configuration={
                    "max_files": self.max_files,
                    "package_manager": package_manager
                }
            )

        # Apply file limit to normal priority files
        if self.max_files is not None:
            normal_files = normal_files[:self.max_files]
            logger.info(f"Limited normal files to {len(normal_files)} (max_files={self.max_files})")
        
        # Step 2: Analyze all files
        file_tasks: List[Dict[str, Any]] = []

        for file_path in high_priority_files:
            file_tasks.append({
                "file_path": str(file_path),
                "priority": "high",
                "package_name": package_path.name
            })

        for file_path in normal_files:
            file_tasks.append({
                "file_path": str(file_path),
                "priority": "normal",
                "package_name": package_path.name
            })
        
        file_results = self._execute_file_tasks(file_tasks)
        
        # Aggregate package-level results
        malicious_file_count = sum(1 for r in file_results if r.is_malicious)
        is_package_malicious = malicious_file_count > 0
        
        max_risk = "benign"
        risk_order = {"benign": 0, "low": 1, "medium": 2, "high": 3, "unknown": 0}
        for result in file_results:
            if risk_order.get(result.max_risk_level, 0) > risk_order.get(max_risk, 0):
                max_risk = result.max_risk_level
        
        total_analysis_time = (datetime.now() - start_time).total_seconds()
        
        package_result = PackageAnalysisResult(
            package_path=str(package_path),
            package_manager=package_manager,
            analysis_timestamp=datetime.now().isoformat(),
            total_files_found=len(high_priority_files) + len(normal_files),
            total_files_analyzed=len(file_results),
            high_priority_files=len(high_priority_files),
            file_results=file_results,
            is_package_malicious=is_package_malicious,
            malicious_file_count=malicious_file_count,
            max_risk_level=max_risk,
            total_analysis_time=total_analysis_time,
            configuration={
                "max_files": self.max_files,
                "package_manager": package_manager
            }
        )
        
        # Save results if output path specified
        if output_path:
            self._save_results(package_result, output_path)
        
        logger.info(f"Package analysis complete: {package_path.name}")
        logger.info(f"Malicious: {is_package_malicious}, Risk: {max_risk}")
        logger.info(f"Total time: {total_analysis_time:.2f}s")
        
        return package_result
    
    def _save_results(self, result: PackageAnalysisResult, output_path: str):
        """Save analysis results to JSON file"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict for JSON serialization
        result_dict = asdict(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results saved to: {output_path}")
    
    def print_summary(self, result: PackageAnalysisResult):
        """Print a human-readable summary"""
        print("\n" + "=" * 80)
        print(f"Package Analysis Summary: {Path(result.package_path).name}")
        print("=" * 80)
        print(f"Package Manager: {result.package_manager}")
        print(f"Analysis Time: {result.analysis_timestamp}")
        print(f"Total Time: {result.total_analysis_time:.2f}s")
        print()
        print(f"Files Found: {result.total_files_found}")
        print(f"Files Analyzed: {result.total_files_analyzed}")
        print(f"  - High Priority: {result.high_priority_files}")
        print(f"  - Normal Priority: {result.total_files_analyzed - result.high_priority_files}")
        print()
        print(f"Malicious: {'YES' if result.is_package_malicious else 'NO'}")
        print(f"Risk Level: {result.max_risk_level.upper()}")
        print(f"Malicious Files: {result.malicious_file_count}/{result.total_files_analyzed}")
        print()
        
        if result.malicious_file_count > 0:
            print("Malicious Files Detected:")
            print("-" * 80)
            for file_result in result.file_results:
                if file_result.is_malicious:
                    print(f"  [{file_result.priority.upper()}] {Path(file_result.file_path).name}")
                    print(f"    Risk: {file_result.max_risk_level}, Confidence: {file_result.max_confidence:.2f}")
                    print(f"    Malicious Slices: {file_result.malicious_slice_count}/{file_result.slice_count}")
                    print()
        
        print("=" * 80)


# def main():
#     """Example usage"""
#     # Example: Analyze a PyPI package
#     analyzer = PackageAnalyzer()
    
#     result = analyzer.analyze_package(
#         package_path="/home2/wenbo/Documents/PyPIAgent/Dataset/2025/unzip_malware/ctftestsowwy#0.0.7",
#         package_manager="pypi",
#         version="1.8.0",
#         output_path="/home2/wenbo/Documents/PyPIAgent/PyGuard/Core/Detector/analysis_result.json"
#     )
    
#     analyzer.print_summary(result)


# if __name__ == "__main__":
#     main()

