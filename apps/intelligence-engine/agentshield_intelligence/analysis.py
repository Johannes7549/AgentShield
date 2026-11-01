"""Content analysis boundary.

No classifier is implemented. Callers must not treat this failure as an
authorization decision, and the exception deliberately omits the content.
"""


class AnalysisUnavailable(NotImplementedError):
    """Deterministic and model-based analysis are both unavailable."""


def analyze_untrusted_content(content: bytes, content_type: str) -> None:
    del content, content_type
    raise AnalysisUnavailable(
        "untrusted content analysis is not implemented and is not an authorization decision"
    )
