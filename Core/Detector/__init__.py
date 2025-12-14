"""Core malware detection engine"""

from Core.Detector.code_slicer import CodeSlicer, SliceOutput
from Core.Detector.api_extractor import APISequenceExtractor, APIModelOutput
from Core.Detector.malice_detector import (
    MaliceDetector,
    DetectionOutput,
    PatternMatchingDetection,
    RAGBasedDetection,
    MatchResult
)
from Core.Detector.package_analyzer import PackageAnalyzer, PackageAnalysisResult, FileAnalysisResult

__all__ = [
    'CodeSlicer',
    'SliceOutput',
    'APISequenceExtractor',
    'APIModelOutput',
    'MaliceDetector',
    'DetectionOutput',
    'PatternMatchingDetection',
    'RAGBasedDetection',
    'MatchResult',
    'PackageAnalyzer',
    'PackageAnalysisResult',
    'FileAnalysisResult',
]

