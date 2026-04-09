from typing import List, Tuple


NEGATIVE_WORDS = ["杀死", "暴力", "色情"]
POSITIVE_WORDS = ["和谐", "尊重", "中正"]


def score_text(text: str) -> Tuple[float, List[str]]:
    score = 0.7
    reasons: List[str] = []

    if any(word in text for word in NEGATIVE_WORDS):
        score -= 0.3
        reasons.append("contains negative keyword")

    if any(word in text for word in POSITIVE_WORDS):
        score += 0.2
        reasons.append("contains positive keyword")

    score = max(0.0, min(1.0, score))
    return score, reasons
