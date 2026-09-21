# explain.py
# =============================================================================
# The ExplainabilityEngine (from our CO2 design report).
#
# Converts a technical alert into a plain-language explanation that a
# non-expert can act on, answering: "Why is this alert High risk?"
#
# DESIGN DECISION: this is a DETERMINISTIC TEMPLATE generator, not an LLM.
#   Our CO1 proposal flagged "LLM-dependency risk" (cost + availability) and
#   promised a template-based fallback. This IS that fallback: offline, free,
#   instant, and reproducible - the same alert always gives the same wording,
#   which matters for a security audit trail.
#
# MITRE ATT&CK MAPPING: each attack type carries its official technique ID so
#   alerts can be cross-referenced with professional tooling and threat reports.
# =============================================================================


# -----------------------------------------------------------------------------
# MITRE ATT&CK technique mapping (verified against attack.mitre.org)
# -----------------------------------------------------------------------------
MITRE_MAP = {
    "Brute Force Attack": {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "Credential Stuffing": {
        "id": "T1110.004", "name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/004/",
    },
    "Password Spraying": {
        "id": "T1110.003", "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "Impossible Travel": {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "Port Scanning": {
        "id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    # Sub-threshold password guessing is still the Brute Force technique - it is
    # simply being attempted slowly enough to evade a naive detector.
    "Suspicious Failed Logins": {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    # Off-hours access is use of legitimate credentials, so it maps to Valid
    # Accounts. It is informational, not proof of compromise.
    "Off-Hours Login": {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    # "Anomalous Activity (AI)" is deliberately unmapped: it is a statistical
    # outlier, not a recognised adversary technique.
}


# -----------------------------------------------------------------------------
# Security knowledge base: what a human analyst knows about each finding.
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
    "Suspicious Failed Logins": {
        "goal": "sign in to an account without knowing the correct password",
        "danger": "this is most often a member of staff who has forgotten their password, but "
                  "it looks identical to a patient attacker deliberately guessing slowly to "
                  "stay beneath the brute-force alarm - which is exactly why it is worth a look "
                  "rather than being ignored",
        "urgency": "Review",
    },
    "Off-Hours Login": {
        "goal": "sign in using valid credentials outside normal working hours",
        "danger": "on its own this is NOT an attack - staff legitimately work late. It is "
                  "recorded because stolen credentials are frequently used at night when nobody "
                  "is watching, so it is useful context if other alerts appear for the same "
                  "account",
        "urgency": "Informational",
    },
    "Anomalous Activity (AI)": {
        "goal": "unknown - this behaviour did not match any known attack rule",
        "danger": "the machine-learning model found this source statistically unusual compared "
                  "to all other traffic, which may indicate a NEW attack pattern",
        "urgency": "Investigate",
    },
}

# Findings that are informational rather than adversarial. Their explanations
# must not accuse anyone of attacking, or the wording is simply wrong.
NON_ADVERSARIAL = {"Off-Hours Login"}


def _risk_reason(alert) -> str:
    """Explain WHY the alert landed in its band (0-30 Low, 31-70 Medium, 71-100 High)."""
    score = alert.risk_score
    if score >= 71:
        return (f"The final risk score is {score}/100, which falls in the HIGH band "
                f"(71-100). High-risk alerts should be actioned immediately.")
    if score >= 31:
        return (f"The final risk score is {score}/100, which falls in the MEDIUM band "
                f"(31-70). Medium-risk alerts should be reviewed, not ignored.")
    return (f"The final risk score is {score}/100, which falls in the LOW band "
            f"(0-30). This is informational: worth noting for context, but not alarming "
            f"on its own.")


def _ai_reason(alert) -> str:
    """
    Explain what the Isolation Forest contributed, including WHICH behaviours
    drove the decision (from SHAP attribution).
    """
    evidence = alert.evidence or ""
    marker = "AI anomaly score:"

    if marker not in evidence:
        return ("The machine-learning layer did not contribute a score to this alert; "
                "the detection came from the rule engine alone.")

    try:
        score = float(evidence.split(marker)[1].strip().split()[0])
    except (IndexError, ValueError):
        return "The machine-learning anomaly score for this alert could not be read."

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

    if "AI drivers:" in evidence:
        drivers = evidence.split("AI drivers:")[1].strip()
        verdict += f" The features that contributed most to this decision were: {drivers}."

    return verdict


def generate_explanation(alert) -> dict:
    """Build the full plain-language explanation for one alert."""
    knowledge = ATTACK_KNOWLEDGE.get(alert.attack_type, {
        "goal": "perform suspicious activity against our systems",
        "danger": "the behaviour deviates from normal usage patterns",
        "urgency": "Review",
    })

    # Readable target phrase, e.g. "from 192.168.1.20 against account 'admin'".
    target = ""
    if alert.source_ip:
        target += f"from {alert.source_ip}"
    if alert.username:
        target += f" against the account '{alert.username}'"
    target = target.strip() or "in the analysed logs"

    # Informational findings must not be described as an attack.
    if alert.attack_type in NON_ADVERSARIAL:
        headline = (f"This is a {alert.risk_level.upper()} risk "
                    f"{alert.attack_type} observed {target.replace('against the account', 'for the account')}.")
        what = f"A user appears to {knowledge['goal']}."
    else:
        headline = (f"This is a {alert.risk_level.upper()} risk "
                    f"{alert.attack_type} detected {target}.")
        what = f"The attacker appears to be trying to {knowledge['goal']}."

    return {
        "headline": headline,
        "what": what,
        "why_risky": f"This matters because {knowledge['danger']}. {_risk_reason(alert)}",
        "ai_view": _ai_reason(alert),
        "action": alert.recommendation,
        "urgency": knowledge["urgency"],
        "mitre": MITRE_MAP.get(alert.attack_type),
    }
