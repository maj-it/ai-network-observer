"""
Keylogger Detection Module
Détecte les comportements suspects de keylogging dans le trafic réseau
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class KeyloggerSignature:
    """Signature de comportement keylogger"""
    name: str
    pattern: str
    risk_score: int
    description: str

class KeyloggerDetector:
    """
    Détecteur de keyloggers basé sur l'analyse du trafic réseau
    
    Détecte:
    - Exfiltration de données clavier
    - Communications C2 suspectes
    - Patterns de transmission périodique
    - Encodage suspect de données
    """
    
    def __init__(self):
        self.signatures = self._load_signatures()
        self.suspicious_domains = [
            'pastebin.com',
            'hastebin.com', 
            'discord.com/api/webhooks',
            'telegram.org/bot',
            'dropbox.com/upload',
            'transfer.sh'
        ]
        
    def _load_signatures(self) -> List[KeyloggerSignature]:
        """Charge les signatures de keyloggers connus"""
        return [
            KeyloggerSignature(
                name="Base64 Encoded Data",
                pattern=r"[A-Za-z0-9+/]{30,}={0,2}",  # Réduit à 30 caractères
                risk_score=7,
                description="Données encodées en base64 (possibles frappes clavier)"
            ),
            KeyloggerSignature(
                name="Hex Encoded Data",
                pattern=r"[0-9a-fA-F]{40,}",  # Données hexadécimales
                risk_score=6,
                description="Données encodées en hexadécimal"
            ),
            KeyloggerSignature(
                name="Keystroke Pattern",
                pattern=r"(key|stroke|press|input|char|keyboard).*data",
                risk_score=8,
                description="Référence explicite à des frappes clavier"
            ),
            KeyloggerSignature(
                name="Password Exfiltration",
                pattern=r"(password|passwd|pwd|credentials)[:=]",
                risk_score=9,
                description="Exfiltration possible de mots de passe"
            ),
            KeyloggerSignature(
                name="Periodic POST Request",
                pattern=r"POST.*\/(upload|log|send|data|collect)",
                risk_score=6,
                description="Requête POST vers endpoint suspect"
            ),
        ]
    
    def analyze_payload(self, payload: str) -> Dict:
        """
        Analyse un payload pour détecter des signes de keylogging
        
        Returns:
            Dict avec risk_score, matches, et description
        """
        matches = []
        total_risk = 0
        
        for signature in self.signatures:
            if re.search(signature.pattern, payload, re.IGNORECASE):
                matches.append({
                    'signature': signature.name,
                    'description': signature.description,
                    'risk_score': signature.risk_score
                })
                total_risk += signature.risk_score
        
        return {
            'risk_score': min(total_risk, 10),
            'matches': matches,
            'is_suspicious': total_risk >= 6
        }
    
    def check_domain(self, domain: str) -> bool:
        """Vérifie si un domaine est suspect pour keylogging"""
        return any(suspect in domain.lower() for suspect in self.suspicious_domains)
    
    def analyze_traffic_pattern(self, connections: List[Dict]) -> Dict:
        """
        Analyse les patterns de trafic pour détecter keylogging
        
        Args:
            connections: Liste de connexions avec timestamps
            
        Returns:
            Analyse des patterns suspects
        """
        if len(connections) < 3:
            return {'periodic': False, 'risk_score': 0}
        
        # Calculer les intervalles entre connexions
        intervals = []
        for i in range(1, len(connections)):
            delta = connections[i]['timestamp'] - connections[i-1]['timestamp']
            intervals.append(delta.total_seconds())
        
        # Détecter périodicité (keyloggers envoient souvent à intervalles réguliers)
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        
        is_periodic = variance < (avg_interval * 0.2)  # Variance < 20%
        
        return {
            'periodic': is_periodic,
            'avg_interval': avg_interval,
            'risk_score': 8 if is_periodic else 2,
            'description': 'Trafic périodique détecté (possible exfiltration automatique)' if is_periodic else 'Pas de périodicité détectée'
        }
    
    def generate_alert(self, analysis: Dict, source_ip: str = None, dest_domain: str = None) -> Dict:
        """Génère une alerte formatée"""
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'KEYLOGGER_DETECTED',
            'risk_score': analysis.get('risk_score', 0),
            'source_ip': source_ip or 'unknown',
            'destination': dest_domain or 'unknown',
            'signatures_matched': [m['signature'] for m in analysis.get('matches', [])],
            'recommendation': self._get_recommendation(analysis.get('risk_score', 0))
        }
    
    def _get_recommendation(self, risk_score: int) -> str:
        """Retourne une recommandation basée sur le score"""
        if risk_score >= 9:
            return "BLOCK_IMMEDIATELY"
        elif risk_score >= 7:
            return "BLOCK_AND_INVESTIGATE"
        elif risk_score >= 5:
            return "ALERT_AND_MONITOR"
        else:
            return "MONITOR"


if __name__ == "__main__":
    # Test amélioré
    detector = KeyloggerDetector()
    
    print("\n" + "="*60)
    print("🧪 TEST AMÉLIORÉ DU DÉTECTEUR")
    print("="*60 + "\n")
    
    # Test 1: Payload réaliste avec mot de passe
    print("━━━ TEST 1: PAYLOAD AVEC PASSWORD ━━━")
    payload1 = "POST /upload username=admin&password=Secret123&data=SGVsbG8="
    result1 = detector.analyze_payload(payload1)
    print(f"Payload: {payload1[:50]}...")
    print(f"Risk: {result1['risk_score']}/10 - Suspect: {result1['is_suspicious']}")
    print(f"Matches: {[m['signature'] for m in result1['matches']]}")
    
    # Test 2: Payload avec Base64
    print("\n━━━ TEST 2: PAYLOAD BASE64 ━━━")
    payload2 = "data=VXNlcm5hbWU6YWRtaW4gUGFzc3dvcmQ6MTIzNDU2"
    result2 = detector.analyze_payload(payload2)
    print(f"Payload: {payload2}")
    print(f"Risk: {result2['risk_score']}/10 - Suspect: {result2['is_suspicious']}")
    
    # Test 3: Alerte complète
    print("\n━━━ TEST 3: GÉNÉRATION D'ALERTE ━━━")
    alert = detector.generate_alert(result1, "192.168.1.100", "evil.pastebin.com")
    import json
    print(json.dumps(alert, indent=2))
    
    print("\n✅ Tests terminés !\n")
