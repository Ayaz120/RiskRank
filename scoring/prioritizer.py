"""
scoring/prioritizer.py
-----------------------
This is the "own logic" layer of the project — after the AI has
triaged each finding individually, THIS module decides how they rank
against each other, combining three signals into one priority score:

    - CVSS score           (severity, from the AI)            -> 50% weight
    - Exploitability        (confirmed/likely/theoretical)      -> 30% weight
    - Asset criticality     (how much this asset matters to you) -> 20% weight

Why not just sort by CVSS alone? Because a 9.8-severity bug on a
throwaway dev box you don't care about shouldn't outrank a 7.5 on your
production login page. This is exactly the kind of judgment call real
risk-based vulnerability management makes, and it's the difference
between a tool that just calls an AI and one that actually reasons
about risk.

The weights and mappings below are deliberately explicit and easy to
tune — you should be able to explain in an interview exactly why a
finding ranked where it did.
"""

import models

# --- Tunable weights (must sum to 1.0) ---
CVSS_WEIGHT = 0.5
EXPLOITABILITY_WEIGHT = 0.3
CRITICALITY_WEIGHT = 0.2

# --- Mapping AI's exploitability label to a 0-1 score ---
EXPLOITABILITY_SCORES = {
    "confirmed": 1.0,
    "likely": 0.7,
    "theoretical": 0.4,
}
DEFAULT_EXPLOITABILITY_SCORE = 0.5  # fallback if the model returns something unexpected

# --- Mapping analyst-tagged asset criticality to a 0-1 score ---
CRITICALITY_SCORES = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
    "unknown": 0.5,  # neutral default when we don't know
}


def compute_priority_score(finding: dict) -> float:
    """
    Combines CVSS + exploitability + asset criticality into a single
    0-100 priority score. Higher = fix this first.
    """
    cvss = finding.get("ai_cvss_score") or 0.0
    cvss_normalized = max(0.0, min(cvss, 10.0)) / 10.0  # clamp to 0-10 just in case, then normalize to 0-1

    exploitability = (finding.get("ai_exploitability") or "").lower().strip()
    exploitability_score = EXPLOITABILITY_SCORES.get(exploitability, DEFAULT_EXPLOITABILITY_SCORE)

    criticality = (finding.get("asset_criticality") or "unknown").lower().strip()
    criticality_score = CRITICALITY_SCORES.get(criticality, CRITICALITY_SCORES["unknown"])

    weighted = (
        cvss_normalized * CVSS_WEIGHT
        + exploitability_score * EXPLOITABILITY_WEIGHT
        + criticality_score * CRITICALITY_WEIGHT
    )

    return round(weighted * 100, 2)  # scale to a friendlier 0-100 range


def prioritize_all_triaged():
    """
    Computes a priority score for every 'triaged' finding, ranks them
    highest-to-lowest, and writes the score + rank back to the database.
    Returns the ranked list of findings (as dicts) for display.
    """
    findings = models.get_all_findings(status="triaged")

    if not findings:
        return []

    scored = []
    for f in findings:
        score = compute_priority_score(f)
        scored.append((f, score))

    # Rank highest priority score first
    scored.sort(key=lambda pair: pair[1], reverse=True)

    ranked_findings = []
    for rank, (finding, score) in enumerate(scored, start=1):
        models.update_priority(finding["id"], priority_score=score, priority_rank=rank)
        finding["priority_score"] = score
        finding["priority_rank"] = rank
        ranked_findings.append(finding)

    return ranked_findings


if __name__ == "__main__":
    # Quick manual test with fake findings, no DB involved.
    fake_findings = [
        {"title": "SQLi on login", "ai_cvss_score": 9.8, "ai_exploitability": "confirmed", "asset_criticality": "high"},
        {"title": "Verbose banner", "ai_cvss_score": 3.1, "ai_exploitability": "theoretical", "asset_criticality": "low"},
        {"title": "IDOR on profile", "ai_cvss_score": 6.5, "ai_exploitability": "likely", "asset_criticality": "medium"},
    ]
    for f in fake_findings:
        print(f"{f['title']}: {compute_priority_score(f)}")
