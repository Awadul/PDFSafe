"""Static analysis engine: parse a PDF, extract evidence, score it."""

from pdfsafe.analysis.heuristics import HeuristicEngine, HeuristicOutcome, score_result
from pdfsafe.analysis.pipeline import (
    AnalysisOutput,
    analyze_bytes,
    analyze_file,
    extract_evidence,
    score_evidence,
)

__all__ = [
    "AnalysisOutput",
    "HeuristicEngine",
    "HeuristicOutcome",
    "analyze_bytes",
    "analyze_file",
    "extract_evidence",
    "score_evidence",
    "score_result",
]
