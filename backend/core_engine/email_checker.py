# backend/core_engine/email_checker.py
import re
import json
import os
from urllib.parse import urlparse
from typing import Dict, List, Optional
import tldextract

# Load rules from JSON file
def load_email_rules() -> dict:
    """Load email rules from JSON file"""
    rules_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "..", "..", "rules", "email_rules.json"
    )
    try:
        with open(rules_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Fallback to default rules
        return {
            "dangerous_attachments": [".exe", ".zip", ".rar", ".7z", ".bat", ".scr", ".js", ".vbs", ".jar", ".pdf"],
            "urgent_phrases": ["urgent", "immediately", "your account will be closed", "last warning", "suspended", "final notice", "verify now", "action required", "unauthorized access", "security alert"],
            "info_request_phrases": ["password", "credit card", "debit card", "security code", "otp", "2fa", "pin", "verify your identity", "confirm your details"],
            "suspicious_sender_domains": ["outlook.com", "gmail.com", "yahoo.com", "hotmail.com"],
            "link_mismatch_detection": True
        }

# Configuration: weights for different checks
WEIGHTS = {
    "suspicious_sender_domain": 20,
    "sender_domain_mismatch": 25,
    "urgent_language": 20,
    "info_request": 25,
    "dangerous_attachment": 20,
    "suspicious_link": 15,
    "link_domain_mismatch": 20,
    "too_good_to_be_true": 25,
    "suspicious_subject": 10,
    "spelling_errors": 25,
    "generic_greeting": 5,
    "typosquatting": 55,  # High score to immediately flag as phishing
}

# Trusted brands to protect against typosquatting
TRUSTED_BRANDS = ["google", "support", "noreply", "github", "opay", "the5ers"]

# --- Helper functions ---
def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address"""
    if not email or "@" not in email:
        return ""
    return email.split("@")[-1].lower().strip()

def extract_links(text: str) -> List[str]:
    """Extract all URLs from text"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def check_domain_similarity(domain1: str, domain2: str) -> bool:
    """Check if two domains are similar (basic check)"""
    if not domain1 or not domain2:
        return False
    # Remove www. prefix
    d1 = domain1.replace("www.", "").lower()
    d2 = domain2.replace("www.", "").lower()
    return d1 == d2

def count_spelling_errors(text: str) -> int:
    """Simple heuristic to detect potential spelling errors"""
    # Look for repeated characters (e.g., "googIe" instead of "google")
    # Look for suspicious character substitutions
    suspicious_patterns = [
        r'[0-9]',  # Numbers in words
        r'[il1|][il1|][il1|]',  # Repeated i/l/1/|
    ]
    count = 0
    for pattern in suspicious_patterns:
        count += len(re.findall(pattern, text, re.IGNORECASE))
    return count

def is_generic_greeting(text: str) -> bool:
    """Check if email uses generic greeting"""
    generic_greetings = ["dear user", "dear customer", "dear sir/madam", "hello", "hi there"]
    text_lower = text.lower()
    return any(greeting in text_lower[:100] for greeting in generic_greetings)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein edit distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

# --- Main analysis function ---
def analyze_email(sender: Optional[str] = None, subject: Optional[str] = None, 
                  content: Optional[str] = None, attachments: Optional[List[str]] = None) -> dict:
    """
    Analyze an email and return a structured result:
    {
        "sender": "...",
        "subject": "...",
        "score": 0-100,
        "verdict": "safe" | "suspicious" | "phishing",
        "reasons": [...],
        "indicators": {flag: True/False, ...},
        "links_found": [...],
        "attachments_found": [...]
    }
    """
    reasons = []
    indicators = {}
    score = 0.0
    links_found = []
    attachments_found = attachments or []

    # Load rules
    rules = load_email_rules()

    # Normalize inputs
    sender = (sender or "").strip()
    subject = (subject or "").strip()
    content = (content or "").strip()
    full_text = f"{subject} {content}".lower()

    # --- Checks ---

    # 0) CRITICAL: Typosquatting / Brand Impersonation Check (User Priority)
    sender_domain = extract_domain_from_email(sender)
    if sender_domain:
        # Extract the Second Level Domain (SLD) e.g., 'google' from 'google.com'
        extracted = tldextract.extract(sender_domain)
        sld = extracted.domain.lower()
        
        # Check against trusted brands
        for brand in TRUSTED_BRANDS:
            # Exact match: Check if it's the official domain
            if sld == brand:
                # Basic check: if brand is the5ers, ensure complete domain match if needed
                # For now, we assume if the SLD matches exactly, it might be safe-ish, 
                # but we still run other checks.
                # However, if it is 'google.com', that's fine. 
                # If it is 'google.bad-site.com', tldextract handles subdomains separately.
                # We care about the root domain.
                pass 
            else:
                # Check for typosquatting (close distance)
                dist = levenshtein_distance(sld, brand)
                
                # Logic: If distance is small (1 or 2) AND it's not the brand itself -> Phishing
                # We normalize distance relative to length to avoid false positives on short words,
                # but for these specific brands, strict distance often works well.
                
                # Special handling for "the5ers" as requested
                is_typo = False
                if brand == "the5ers":
                     # "the5ers" specific logic if needed, but standard edit distance usually covers "the5erss"
                     if dist > 0 and dist <= 2:
                         is_typo = True
                else: 
                     # Standard check for google, github, etc.
                     if dist > 0 and dist <= 2:
                         is_typo = True
                
                # Also check for visual confusion (homoglyphs) if implemented, 
                # but Levenshtein handles "googie" (dist 1) vs "google".
                
                if is_typo:
                    reasons.append(f"Typosquatting detected: '{sender_domain}' mimics trusted brand '{brand}'")
                    # IMMEDIATELY SCORE HIGHER to ensure PHISHING verdict (Threshold is 65)
                    score += 75 
                    indicators["typosquatting"] = True
                    break # Stop checking other brands if one matches

    # 0.5) Local-Part Brand Impersonation Check (e.g. googlesecurity@gmail.com)
    # Check if a trusted brand appears in the local part (before @)
    local_part = sender.split("@")[0].lower() if "@" in sender else ""
    if local_part:
        for brand in TRUSTED_BRANDS:
            # Check if brand is in local part (e.g. "google" in "googlesecurity")
            # We skip "support" and "noreply" as they are common prefixes unless combined with a brand
            if brand in ["support", "noreply"]:
                continue
                
            if brand in local_part:
                # If the sender domain is NOT the official brand domain, flag it.
                # e.g. "google-support@gmail.com" -> Phishing
                # e.g. "support@google.com" -> Safe (captured by earlier logic, but here we check domain mismatch)
                
                # Check if the domain is actually the brand's domain
                sender_sld = tldextract.extract(sender_domain).domain.lower() if sender_domain else ""
                
                if sender_sld != brand:
                     # e.g. brand="google" found in "googlesecurity", but domain is "gmail" (or "yahoo", etc.)
                     reasons.append(f"Trusted brand '{brand}' found in local-part of email (potential impersonation)")
                     score += 55 
                     indicators["brand_impersonation_local"] = True
                     break

    suspicious_sender_flag = sender_domain in rules.get("suspicious_sender_domains", [])
    indicators["suspicious_sender_domain"] = suspicious_sender_flag
    if suspicious_sender_flag:
        reasons.append(f"Sender domain '{sender_domain}' is commonly used in phishing")
        score += WEIGHTS["suspicious_sender_domain"]

    # 2) Extract and analyze links
    links_found = extract_links(full_text)
    indicators["has_links"] = len(links_found) > 0
    
    if links_found:
        reasons.append(f"Found {len(links_found)} link(s) in email")
        score += WEIGHTS["suspicious_link"]

        # Check for link domain mismatch
        if sender_domain and rules.get("link_mismatch_detection", True):
            for link in links_found:
                try:
                    parsed_url = urlparse(link)
                    link_domain = parsed_url.netloc.lower()
                    # Remove www. for comparison
                    link_domain_clean = link_domain.replace("www.", "")
                    sender_domain_clean = sender_domain.replace("www.", "")
                    
                    if link_domain_clean and sender_domain_clean:
                        # Extract root domain using tldextract
                        link_extracted = tldextract.extract(link_domain)
                        sender_extracted = tldextract.extract(sender_domain)
                        
                        link_root = f"{link_extracted.domain}.{link_extracted.suffix}".lower()
                        sender_root = f"{sender_extracted.domain}.{sender_extracted.suffix}".lower()
                        
                        if link_root != sender_root and link_root:
                            indicators["link_domain_mismatch"] = True
                            reasons.append(f"Link domain '{link_root}' doesn't match sender domain '{sender_root}'")
                            score += WEIGHTS["link_domain_mismatch"]
                            break
                except Exception:
                    pass

    # 3) Urgent language / fear-based phrases
    urgent_phrases = rules.get("urgent_phrases", [])
    urgent_found = []
    for phrase in urgent_phrases:
        if phrase.lower() in full_text:
            urgent_found.append(phrase)
    
    indicators["urgent_language"] = len(urgent_found) > 0
    if urgent_found:
        reasons.append(f"Urgent/fear-based language detected: {', '.join(urgent_found[:3])}")
        score += WEIGHTS["urgent_language"]

    # 4) Information request phrases
    info_phrases = rules.get("info_request_phrases", [])
    info_found = []
    for phrase in info_phrases:
        if phrase.lower() in full_text:
            info_found.append(phrase)
    
    indicators["info_request"] = len(info_found) > 0
    if info_found:
        reasons.append(f"Requests sensitive information: {', '.join(info_found[:3])}")
        score += WEIGHTS["info_request"]

    # 5) Dangerous attachments
    dangerous_extensions = rules.get("dangerous_attachments", [])
    dangerous_attachments = []
    for att in attachments_found:
        for ext in dangerous_extensions:
            if att.lower().endswith(ext.lower()):
                dangerous_attachments.append(att)
                break
    
    indicators["dangerous_attachment"] = len(dangerous_attachments) > 0
    if dangerous_attachments:
        reasons.append(f"Dangerous attachment(s) detected: {', '.join(dangerous_attachments)}")
        score += WEIGHTS["dangerous_attachment"]
    
    # Also check if attachments are mentioned in content
    if any(ext.lower() in full_text for ext in dangerous_extensions):
        if not indicators["dangerous_attachment"]:
            reasons.append("Email mentions dangerous file types")
            score += WEIGHTS["dangerous_attachment"] * 0.5

    # 6) "Too good to be true" offers
    promo_keywords = ["won", "reward", "free", "congratulations", "gift", "prize", "bonus", "lottery"]
    promo_found = [kw for kw in promo_keywords if kw in full_text]
    indicators["too_good_to_be_true"] = len(promo_found) > 0
    if promo_found:
        reasons.append(f"Suspicious promotional language: {', '.join(promo_found[:3])}")
        score += WEIGHTS["too_good_to_be_true"]

    # 7) Suspicious subject line
    if subject:
        subject_lower = subject.lower()
        suspicious_subject_indicators = ["urgent", "action required", "verify", "suspended", "locked"]
        if any(indicator in subject_lower for indicator in suspicious_subject_indicators):
            indicators["suspicious_subject"] = True
            reasons.append("Suspicious subject line detected")
            score += WEIGHTS["suspicious_subject"]

    # 8) Spelling errors / typosquatting in sender
    if sender:
        spelling_errors = count_spelling_errors(sender)
        indicators["spelling_errors"] = spelling_errors > 0
        if spelling_errors > 0:
            reasons.append("Potential spelling errors or typosquatting in sender address")
            score += WEIGHTS["spelling_errors"]

    # 9) Generic greeting
    if is_generic_greeting(content):
        indicators["generic_greeting"] = True
        reasons.append("Uses generic greeting instead of personal name")
        score += WEIGHTS["generic_greeting"]

    # --- Final score normalization ---
    raw_score = max(0, score)
    mapped = int(min(max(raw_score, 0), 100))

    # Convert score to verdict thresholds
    if mapped >= 65:
        verdict = "phishing"
    elif mapped >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    result = {
        "sender": sender,
        "subject": subject,
        "score": mapped,
        "verdict": verdict,
        "reasons": reasons or ["No obvious automated red flags detected"],
        "indicators": indicators,
        "links_found": links_found,
        "attachments_found": attachments_found
    }

    return result

# Allow external import
__all__ = ["analyze_email"]

