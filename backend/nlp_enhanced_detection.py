"""
Integration of NLP Log Analyzer with Live Detection System

This module shows how to enhance the existing detection pipeline with
NLP-based attack intent understanding.

Before: Log → Detector → Alert
After:  Log → NLP Analyzer → Enhanced Detector → Better Alert
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
from nlp_log_analyzer import NLPLogAnalyzer, EnhancedLogEntry


class NLPEnhancedDetector:
    """
    Wraps existing detectors with NLP understanding.

    Example:
    - Old: "5 failed logins" → Alert with risk=85
    - New: "5 failed logins" → NLP says "brute_force" → Alert risk=85 +
           "high confidence attack underway" + "recommended actions"
    """

    def __init__(self, nlp_analyzer: NLPLogAnalyzer = None):
        self.nlp_analyzer = nlp_analyzer or NLPLogAnalyzer(mode="fast")

    def enhance_alert(self, alert: Dict, raw_log_message: str) -> Dict:
        """
        Take existing alert and enhance it with NLP insights.

        Args:
            alert: Standard alert dict from live_detection.py
            raw_log_message: Original unparsed log line

        Returns:
            Enhanced alert with intent, confidence, actions
        """
        nlp_result = self.nlp_analyzer.analyze_log(raw_log_message)
        severity_map = self.nlp_analyzer.extract_severity(nlp_result['intent'])

        return {
            **alert,  # Keep all existing fields

            # NEW: NLP analysis
            "attack_intent": nlp_result['intent'],
            "intent_confidence": nlp_result['confidence'],
            "method": nlp_result.get('method', 'regex'),

            # NEW: Severity-based actions
            "recommended_actions": severity_map['actions'],
            "urgency": severity_map['severity'],

            # Boost risk score based on NLP confidence
            "nlp_adjusted_risk": self._adjust_risk_score(
                alert.get('risk_score', 50),
                nlp_result['confidence'],
                severity_map['severity']
            ),

            # NEW: Explainability
            "nlp_evidence": {
                "matched_patterns": nlp_result.get('matched_patterns'),
                "all_matches": nlp_result.get('all_matches', {}),
                "confidence_reason": self._explain_confidence(nlp_result)
            }
        }

    @staticmethod
    def _adjust_risk_score(base_score: float, confidence: float, severity: str) -> float:
        """Boost risk score based on NLP confidence and severity"""
        boost = confidence * 10  # Max +10 points from confidence

        severity_boost = {
            "CRITICAL": 15,
            "HIGH": 10,
            "MEDIUM": 5,
            "LOW": 0
        }

        adjusted = base_score + boost + severity_boost.get(severity, 0)
        return min(adjusted, 100)  # Cap at 100

    @staticmethod
    def _explain_confidence(nlp_result: Dict) -> str:
        """Human-readable explanation of confidence"""
        intent = nlp_result['intent']
        confidence = nlp_result['confidence']
        method = nlp_result.get('method', 'unknown')

        if confidence >= 0.8:
            return f"High confidence {intent} detected via {method}"
        elif confidence >= 0.6:
            return f"Moderate confidence {intent} detected via {method}"
        else:
            return f"Low confidence {intent} detected via {method}"


class NLPCorrelator:
    """
    Use NLP to better correlate attack chains.

    Example:
    - Log 1: "Failed password for admin" → Brute Force intent
    - Log 2: "SSH key added to root account" → Persistence intent
    - Correlation: Brute Force → Persistence = Account Compromise (HIGH)
    """

    def __init__(self, nlp_analyzer: NLPLogAnalyzer = None):
        self.nlp_analyzer = nlp_analyzer or NLPLogAnalyzer(mode="fast")
        self.intent_chains = self._define_attack_chains()

    @staticmethod
    def _define_attack_chains() -> Dict[tuple, Dict]:
        """Define suspicious sequences of attack intents"""
        return {
            # Typical APT progression
            ("reconnaissance", "credential_stuffing"): {
                "pattern": "Recon → Credential Attack",
                "severity": "HIGH",
                "confidence_boost": 0.15
            },
            ("credential_stuffing", "lateral_movement"): {
                "pattern": "Credential Theft → Lateral Movement",
                "severity": "CRITICAL",
                "confidence_boost": 0.20
            },
            ("lateral_movement", "persistence"): {
                "pattern": "Lateral Movement → Persistence",
                "severity": "CRITICAL",
                "confidence_boost": 0.25
            },
            ("privilege_escalation", "persistence"): {
                "pattern": "Privilege Escalation → Backdoor",
                "severity": "CRITICAL",
                "confidence_boost": 0.20
            },
            ("brute_force", "privilege_escalation"): {
                "pattern": "Brute Force → Privilege Escalation",
                "severity": "HIGH",
                "confidence_boost": 0.15
            },
            ("brute_force", "lateral_movement"): {
                "pattern": "Credential Compromise → Lateral Movement",
                "severity": "HIGH",
                "confidence_boost": 0.15
            },
        }

    def correlate_with_intent(
        self,
        recent_logs: List[Dict],
        time_window_seconds: int = 3600
    ) -> List[Dict]:
        """
        Correlate recent logs based on attack intent.

        Args:
            recent_logs: List of log entries with raw_message field
            time_window_seconds: Correlation window (default 1 hour)

        Returns:
            List of detected attack chains
        """
        if len(recent_logs) < 2:
            return []

        # Analyze each log for intent
        log_intents = []
        for log in recent_logs:
            nlp_result = self.nlp_analyzer.analyze_log(
                log.get("raw_message", "")
            )
            log_intents.append({
                "log": log,
                "intent": nlp_result['intent'],
                "confidence": nlp_result['confidence'],
                "timestamp": datetime.fromisoformat(
                    log['event_time'].replace('Z', '+00:00')
                )
            })

        # Sort by timestamp
        log_intents.sort(key=lambda x: x['timestamp'])

        # Find attack chains
        chains = []
        for i in range(len(log_intents) - 1):
            current = log_intents[i]
            next_entry = log_intents[i + 1]

            # Check if this is a suspicious sequence
            intent_pair = (current['intent'], next_entry['intent'])

            if intent_pair in self.intent_chains:
                chain_info = self.intent_chains[intent_pair]

                # Ensure chronological order and within time window
                time_diff = (next_entry['timestamp'] - current['timestamp']).total_seconds()
                if 0 < time_diff <= time_window_seconds:
                    chains.append({
                        "pattern": chain_info['pattern'],
                        "severity": chain_info['severity'],
                        "stage_1": {
                            "intent": current['intent'],
                            "confidence": current['confidence'],
                            "timestamp": current['timestamp'].isoformat()
                        },
                        "stage_2": {
                            "intent": next_entry['intent'],
                            "confidence": next_entry['confidence'],
                            "timestamp": next_entry['timestamp'].isoformat()
                        },
                        "time_between_stages_seconds": time_diff,
                        "combined_confidence": min(
                            (current['confidence'] + next_entry['confidence']) / 2 +
                            chain_info['confidence_boost'],
                            1.0
                        )
                    })

        return chains


class NLPExplainer:
    """
    Generate human-readable explanations for alerts using NLP results.

    Example output:
    "CRITICAL: Data exfiltration detected. Attacker likely stole sensitive
    data. Immediately isolate the compromised user and audit all file access."
    """

    def __init__(self):
        self.severity_descriptions = {
            "CRITICAL": {
                "urgency": "IMMEDIATE ACTION REQUIRED",
                "response_time": "<15 minutes"
            },
            "HIGH": {
                "urgency": "URGENT ACTION REQUIRED",
                "response_time": "<1 hour"
            },
            "MEDIUM": {
                "urgency": "ACTION REQUIRED",
                "response_time": "<4 hours"
            },
            "LOW": {
                "urgency": "MONITOR",
                "response_time": "<24 hours"
            }
        }

    def explain_attack(self, enhanced_alert: Dict) -> str:
        """Generate plain-English explanation of an attack"""
        intent = enhanced_alert.get('attack_intent', 'unknown')
        confidence = enhanced_alert.get('intent_confidence', 0)
        severity = enhanced_alert.get('urgency', 'MEDIUM')
        source_ip = enhanced_alert.get('source_ip', 'unknown')
        username = enhanced_alert.get('username', 'unknown')

        # Base explanation
        intent_descriptions = {
            "brute_force": "Attacker is attempting to guess passwords",
            "credential_stuffing": "Attacker is testing stolen credentials",
            "reconnaissance": "Attacker is scanning for vulnerabilities",
            "privilege_escalation": "Attacker is trying to gain admin access",
            "data_exfiltration": "Attacker is stealing sensitive data",
            "lateral_movement": "Attacker is moving through your network",
            "persistence": "Attacker is installing backdoors for long-term access",
            "denial_of_service": "Attacker is attempting to take down services",
            "malware_deployment": "Attacker is deploying malicious software",
        }

        base_desc = intent_descriptions.get(
            intent,
            "Unknown attack type detected"
        )

        explanation = f"""
ALERT: {severity} {intent.upper().replace('_', ' ')}

📊 ATTACK SUMMARY:
{base_desc}

🎯 TARGET:
  - User: {username}
  - Source IP: {source_ip}

📈 CONFIDENCE: {confidence:.0%}

⚡ URGENCY: {self.severity_descriptions[severity]['urgency']}
   Expected Response Time: {self.severity_descriptions[severity]['response_time']}

🛡️ IMMEDIATE ACTIONS:
"""

        # Add recommended actions
        actions = enhanced_alert.get('recommended_actions', [])
        for action in actions:
            explanation += f"  ☐ {action.replace('_', ' ').title()}\n"

        return explanation.strip()


# =============================================================================
# Integration Example with Live Detection
# =============================================================================

def enhance_live_detection_pipeline():
    """
    Shows how to integrate NLP analyzer into existing live_detection.py
    """

    code_snippet = """
# In live_detection.py, update LiveLogProcessor:

from nlp_log_analyzer import NLPLogAnalyzer
from nlp_enhanced_detection import NLPEnhancedDetector, NLPExplainer

class LiveLogProcessor:
    def __init__(self, user_id: int, db: Session):
        self.user_id = user_id
        self.db = db

        # NEW: Initialize NLP components
        self.nlp_analyzer = NLPLogAnalyzer(mode="fast")  # Fast mode for real-time
        self.nlp_detector = NLPEnhancedDetector(self.nlp_analyzer)
        self.nlp_explainer = NLPExplainer()

    def process_log_entry(self, log_dict: dict) -> dict:
        '''Process single log entry with NLP enhancement'''

        # 1. Parse log (existing code)
        parsed = self._parse_log(log_dict)

        # 2. Store raw message for NLP
        raw_message = log_dict.get('raw_message', '')

        # 3. Run existing detectors
        detected_alerts = self._run_detectors(parsed)

        # 4. NEW: Enhance alerts with NLP
        for alert in detected_alerts:
            alert = self.nlp_detector.enhance_alert(alert, raw_message)

            # 5. Generate human-readable explanation
            alert['explanation_text'] = self.nlp_explainer.explain_attack(alert)

            # 6. Store enhanced alert
            self._create_alert(alert)

        return detected_alerts
    """

    return code_snippet


# =============================================================================
# Testing
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("NLP ENHANCED DETECTION DEMO")
    print("=" * 70)

    # Initialize components
    nlp_analyzer = NLPLogAnalyzer(mode="fast")
    nlp_detector = NLPEnhancedDetector(nlp_analyzer)
    nlp_correlator = NLPCorrelator(nlp_analyzer)
    nlp_explainer = NLPExplainer()

    # Test alert from live_detection.py
    base_alert = {
        "id": 123,
        "attack_type": "Brute Force",
        "source_ip": "192.168.1.100",
        "username": "admin",
        "risk_level": "High",
        "risk_score": 85,
        "evidence": "5+ failed logins from same IP/account within 60s",
        "detected_at": datetime.utcnow().isoformat()
    }

    raw_log = "[sshd] Failed password for admin from 192.168.1.100 port 54321 ssh2"

    # Enhance the alert
    enhanced = nlp_detector.enhance_alert(base_alert, raw_log)

    print("\n📊 BEFORE (Standard Detection):")
    print(f"  Attack Type: {base_alert['attack_type']}")
    print(f"  Risk Score: {base_alert['risk_score']}/100")

    print("\n✨ AFTER (NLP Enhanced):")
    print(f"  Attack Intent: {enhanced['attack_intent']}")
    print(f"  Intent Confidence: {enhanced['intent_confidence']:.0%}")
    print(f"  NLP-Adjusted Risk: {enhanced['nlp_adjusted_risk']:.0f}/100")
    print(f"  Recommended Actions: {', '.join(enhanced['recommended_actions'])}")

    print("\n📝 HUMAN-READABLE EXPLANATION:")
    explanation = nlp_explainer.explain_attack(enhanced)
    print(explanation)

    # Test correlation
    print("\n\n" + "=" * 70)
    print("ATTACK CHAIN CORRELATION TEST")
    print("=" * 70)

    test_logs = [
        {
            "event_time": (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z",
            "raw_message": "Starting Nmap scan on 10.0.0.0/24",
            "source_ip": "203.0.113.45"
        },
        {
            "event_time": (datetime.utcnow() - timedelta(minutes=3)).isoformat() + "Z",
            "raw_message": "[sshd] Failed password for admin from 203.0.113.45",
            "source_ip": "203.0.113.45"
        },
        {
            "event_time": datetime.utcnow().isoformat() + "Z",
            "raw_message": "SSH key added to /root/.ssh/authorized_keys",
            "source_ip": "203.0.113.45"
        },
    ]

    chains = nlp_correlator.correlate_with_intent(test_logs)
    print(f"\n🔗 Detected {len(chains)} attack chains:\n")
    for chain in chains:
        print(f"Pattern: {chain['pattern']}")
        print(f"Severity: {chain['severity']}")
        print(f"Stage 1: {chain['stage_1']['intent']} ({chain['stage_1']['confidence']:.0%})")
        print(f"Stage 2: {chain['stage_2']['intent']} ({chain['stage_2']['confidence']:.0%})")
        print(f"Time Between: {chain['time_between_stages_seconds']}s")
        print(f"Combined Confidence: {chain['combined_confidence']:.0%}\n")

    print("=" * 70)
    print("✅ NLP Enhanced Detection ready for production!")
    print("=" * 70)
