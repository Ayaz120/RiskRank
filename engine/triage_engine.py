"""
engine/triage_engine.py
------------------------
Sends each raw finding to a local LLM (via Ollama) and gets back a
structured triage assessment. Runs 100% locally and free.

Setup:
    1. Install Ollama:        https://ollama.com/download
    2. Pull a model:          ollama pull llama3.2:3b
    3. Ollama usually runs automatically after install, or: ollama serve
    4. pip install -r requirements.txt
"""

import os
import json
import requests

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.environ.get("TRIAGE_MODEL", "llama3.2:3b")

SYSTEM_PROMPT = """You are a senior application security analyst performing \
vulnerability triage. You will be given a single security finding and must \
assess it with the same rigor a human analyst would bring to a real \
penetration test report.

Respond with ONLY a valid JSON object, no markdown formatting, no code \
fences, no extra commentary before or after. The JSON must have exactly \
these keys:

{
  "explanation": "2-4 sentences explaining the vulnerability and its \
real-world impact in plain English, tailored to the specific context given.",
  "cvss_score": <float between 0.0 and 10.0>,
  "cvss_reasoning": "1-3 sentences justifying the score, referencing the \
specific factors that raised or lowered it (attack complexity, privileges \
required, scope, impact, asset criticality).",
  "exploitability": "theoretical" | "likely" | "confirmed",
  "remediation": "Specific, actionable remediation advice. Include a short \
code-level example if relevant to the vulnerability type."
}

Guidelines:
- Do not default to generic advice. Reference the specific asset, service, \
or code pattern described in the finding.
- If the finding is low-signal (e.g. informational, no real exploitability), \
score it accordingly and say so plainly rather than inflating severity.
- "exploitability" reflects how directly attackable this is AS DESCRIBED, \
not worst-case theoretical severity.
- Asset criticality provided in the input should influence your CVSS \
environmental scoring context, not just the base score.
- For cvss_reasoning: write it as PLAIN PROSE only. Do NOT invent numeric \
sub-scores, fractions, or ratios like "6/8" or "9/8" — there is no such \
thing as a score out of 8, and this is a common mistake. Simply describe \
in words which real CVSS factors (attack vector, attack complexity, \
privileges required, user interaction, scope, confidentiality/integrity/\
availability impact) push the score up or down, without assigning each \
one a fake number.
- Output ONLY the JSON object. Nothing else."""


def build_user_prompt(finding: dict) -> str:
    return f"""Finding to triage:

Title: {finding['title']}
Asset: {finding['asset']}
Asset criticality (as tagged by analyst): {finding.get('asset_criticality', 'unknown')}
Source: {finding['source']}
Description: {finding['description']}

Provide your triage assessment as the specified JSON object."""


def _extract_json(raw_text: str) -> dict:
    raw_text = raw_text.strip()

    if raw_text.startswith("```"):
        raw_text = raw_text.strip("`")
        if raw_text.startswith("json"):
            raw_text = raw_text[4:].strip()

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        pass

    start = raw_text.find("{")
    end = raw_text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object found in model output:\n{raw_text}")

    return json.loads(raw_text[start:end + 1])


def warm_up_model():
    try:
        requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": MODEL, "prompt": "Reply with just the word: ready", "stream": False},
            timeout=300,
        )
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Could not reach Ollama for warm-up: {e}")


def triage_finding(finding: dict, client=None) -> dict:
    payload = {
        "model": MODEL,
        "prompt": f"{SYSTEM_PROMPT}\n\n{build_user_prompt(finding)}",
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.2},
    }

    try:
        response = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, timeout=300)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Could not connect to Ollama. Is it running? "
            "Try: 'ollama serve' in another terminal. Also confirm the model "
            f"is pulled: 'ollama pull {MODEL}'"
        )
    except requests.exceptions.ReadTimeout:
        raise RuntimeError(
            f"Request timed out after 300s. Try a smaller model, e.g.: "
            "'ollama pull phi3:mini' then set TRIAGE_MODEL=phi3:mini"
        )

    raw_text = response.json().get("response", "")

    try:
        parsed = _extract_json(raw_text)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(
            f"Model did not return valid JSON for finding '{finding['title']}': {e}\n"
            f"Raw response: {raw_text}"
        )

    required_keys = {"explanation", "cvss_score", "cvss_reasoning", "exploitability", "remediation"}
    if not required_keys.issubset(parsed.keys()):
        raise ValueError(f"Model response missing keys: {required_keys - parsed.keys()}")

    return parsed


if __name__ == "__main__":
    sample = {
        "title": "SQL Injection in login form",
        "asset": "http://127.0.0.1:5000/login",
        "asset_criticality": "high",
        "source": "manual",
        "description": (
            "The username field is concatenated directly into the SQL "
            "query string instead of using parameterized queries, "
            "allowing authentication bypass with a payload like "
            "' OR '1'='1' -- "
        ),
    }
    print(json.dumps(triage_finding(sample), indent=2))
