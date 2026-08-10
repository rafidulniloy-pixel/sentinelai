# explain.py
# =============================================================================
# The ExplainabilityEngine (from our CO2 design report).
#
# PURPOSE:
#   Convert a technical alert into a plain-language explanation that a
#   non-expert can act on. This answers the user's question:
#   "Why is this alert High risk?"
#
# DESIGN DECISION (important for the report):
#   We use a DETERMINISTIC TEMPLATE generator, not an LLM API, because:
#     1. Our CO1 proposal flagged "LLM-dependency risk" (cost + availability)
#        and promised a template-based fallback. This IS that fallback.
#     2. It works offline, is free, is instant, and never fails.
#     3. It is reproducible - the same alert always gives the same wording,
#        which matters for a security audit trail.
#   An LLM can later be added ON TOP of this (see generate_explanation()).
#
# NOTE: explanations are generated ON READ (not stored in the database).
#   This keeps the database schema unchanged and guarantees the explanation
#   always matches the alert's current risk score.
# =============================================================================


# -----------------------------------------------------------------------------
# KNOWLEDGE BASE
# For each attack type we store the security knowledge a human analyst has:
#   - what the attacker is trying to achieve
#   - why it is dangerous (the business impact)
#   - how urgently it must be handled
# -----------------------------------------------------------------------------
ATTACK_KNOWLEDGE = {
    "Brute Force Attack": {
        "goal": "guess the password of a single account by trying many passwords very quickly",
        "danger": "if even one guess succeeds, the attacker gains full access to that account "
                  "and everything it can reach",
        "urgency": "Immediate",
    },
    "Credential Stuffing": {
        "goal": "test username and password pairs stolen from OTHER websites against our system",
        "danger": "many people reuse passwords, so stolen credentials often work here too - "
                  "and each success looks like a normal login",
        "urgency": "Immediate",
    },
    "Password Spraying": {
        "goal": "try ONE very common password (like '123456') against many different accounts",
        "danger": "it deliberately stays under the failed-login limit of each account, so it "
                  "avoids lockouts and is easy to miss without correlation across accounts",
        "urgency": "High",
    },
    "Impossible Travel": {
        "goal": "use a stolen session or password from a different part of the world",
        "danger": "one human cannot physically be in two distant countries minutes apart, so "
                  "at least one of these logins is not the real user",
        "urgency": "Immediate",
    },
    "Port Scanning": {
        "goal": "map which services and doors on our server are open",
        "danger": "this is reconnaissance - the information gathered is normally used to plan "
                  "a real attack shortly afterwards",
        "urgency": "Elevated",
    },
    "Anomalous Activity (AI)": {
        "goal": "unknown - this behaviour did not match any known attack rule",
        "danger": "the machine-learning model found this source statistically unusual compared "
                  "to all other traffic, which may indicate a NEW attack pattern",
        "urgency": "Investigate",
    },
}


def _risk_reason(alert) -> str:
    """
    Explain WHY the alert landed in its risk band.

    Our risk bands (from the CO2 design report):
        0-30   = Low
        31-70  = Medium
        71-100 = High
    """
    score = alert.risk_score
    if score >= 71:
        return (f"The final risk score is {score}/100, which falls in the HIGH band "
                f"(71-100). High-risk alerts should be actioned immediately.")
    if score >= 31:
        return (f"The final risk score is {score}/100, which falls in the MEDIUM band "
                f"(31-70). Medium-risk alerts should be reviewed, not ignored.")
    return (f"The final risk score is {score}/100, which falls in the LOW band "
            f"(0-30). This is likely routine activity worth monitoring.")


def _ai_reason(alert) -> str:
    """
    Explain what the Isolation Forest (our unsupervised ML model) contributed.

    We read the anomaly score that ai_engine.py appended to the evidence text
    in the format:  "... | AI anomaly score: 0.79"
    """
    evidence = alert.evidence or ""
    marker = "AI anomaly score:"

    # If the AI never scored this alert, say so honestly.
    if marker not in evidence:
        return ("The machine-learning layer did not contribute a score to this alert; "
                "the detection came from the rule engine alone.")

    # Pull the number out of the evidence string.
    try:
        score = float(evidence.split(marker)[1].strip().split()[0])
    except (IndexError, ValueError):
        return "The machine-learning anomaly score for this alert could not be read."

    # Translate the 0.00 - 1.00 number into plain language.
    if score >= 0.80:
        verdict = (f"The Isolation Forest model rated this source {score:.2f} out of 1.00 - "
                   f"extremely unusual compared with all other traffic. The rule engine and "
                   f"the AI strongly agree, so the risk score was escalated.")
    elif score >= 0.50:
        verdict = (f"The Isolation Forest model rated this source {score:.2f} out of 1.00, "
                   f"meaning its behaviour is noticeably different from normal traffic. "
                   f"This supports the rule-based detection.")
    else:
        verdict = (f"The Isolation Forest model rated this source only {score:.2f} out of 1.00, "
                   f"so on its own the AI did not find it unusual. IMPORTANT: this does not "
                   f"clear the alert. Our fusion policy is escalation-only - the AI may raise "
                   f"a risk score but can never overrule a confirmed rule detection. "
                   f"(Example: impossible travel is a per-USER anomaly, which a per-IP model "
                   f"cannot see.)")
    return verdict


def generate_explanation(alert) -> dict:
    """
    Build the full plain-language explanation for one alert.

    Returns a dictionary with five clearly separated parts so the frontend can
    display them nicely:
        headline   - one-line answer to "why is this flagged?"
        what       - what the attacker appears to be doing
        why_risky  - the business impact if ignored
        ai_view    - what the machine-learning model thought
        action     - the recommended response
        urgency    - how fast a human should react
    """
    # Look up what we know about this attack type. If the type is unknown,
    # fall back to safe generic wording instead of crashing.
    knowledge = ATTACK_KNOWLEDGE.get(alert.attack_type, {
        "goal": "perform suspicious activity against our systems",
        "danger": "the behaviour deviates from normal usage patterns",
        "urgency": "Review",
    })

    # Build a readable "target" phrase, e.g. "from 192.168.1.20 against account 'admin'".
    target = ""
    if alert.source_ip:
        target += f"from {alert.source_ip}"
    if alert.username:
        target += f" against the account '{alert.username}'"
    target = target.strip() or "in the analysed logs"

    return {
        "headline": (f"This is a {alert.risk_level.upper()} risk "
                     f"{alert.attack_type} detected {target}."),
        "what": f"The attacker appears to be trying to {knowledge['goal']}.",
        "why_risky": f"This matters because {knowledge['danger']}. {_risk_reason(alert)}",
        "ai_view": _ai_reason(alert),
        "action": alert.recommendation,
        "urgency": knowledge["urgency"],
    }