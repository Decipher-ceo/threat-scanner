# backend/core_engine/sms_checker.py
import re
import json
import os
from urllib.parse import urlparse
from typing import Dict, List, Optional
import tldextract

# Load rules from JSON file
def load_sms_rules() -> dict:
    """Load SMS rules from JSON file"""
    rules_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "..", "..", "rules", "sms_rules.json"
    )
    try:
        with open(rules_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Fallback to default rules
        return {
            "suspicious_numbers": ["+000", "+999", "unknown", "private"],
            "urgent_phrases": ["urgent", "verify now", "your account is locked", "security alert", "click this link", "your bank account is blocked", "reset immediately"],
            "phishing_keywords": ["bank", "login", "verify", "password", "click", "promo", "free", "bonus", "gift"],
            "unexpected_action_phrases": ["send your details", "provide your otp", "confirm your password", "share your pin"]
        }

# Configuration: weights for different checks (loaded from JSON, fallback defaults)
def get_weights(rules: dict) -> dict:
    """Get weights from rules JSON, with fallback defaults"""
    return rules.get("weights", {
        "suspicious_sender_number": 25,
        "invalid_number_format": 10,
        "shortened_url": 30,
        "urgent_language": 20,
        "phishing_keywords": 15,
        "info_request": 30,
        "unexpected_action": 25,
        "too_good_to_be_true": 15,
        "suspicious_link": 25,
        "link_sender_mismatch": 30,
        "bank_mention_mismatch": 15,
        "suspicious_sender_name": 15,
        "no_contact_info": 5,
        "excessive_special_chars": 10,
        "excessive_caps": 10,
    })

# --- Helper functions ---
def is_suspicious_number(number: str) -> bool:
    """Check if phone number is suspicious"""
    if not number:
        return False
    number_lower = number.lower()
    suspicious_patterns = ["+000", "+999", "unknown", "private", "blocked", "anonymous"]
    return any(pattern in number_lower for pattern in suspicious_patterns)

def extract_links(text: str) -> List[str]:
    """Extract all URLs from text"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def is_shortened_url(url: str) -> bool:
    """Check if URL is a shortened URL service"""
    shortened_domains = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "short.link", "rebrand.ly", "cutt.ly", "buff.ly", "adf.ly",
        "tiny.cc", "shorturl.at", "rb.gy", "bit.do", "shorte.st"
    ]
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        return any(short_domain in domain for short_domain in shortened_domains)
    except:
        return False

def extract_domain_from_link(url: str) -> str:
    """Extract root domain from URL using tldextract"""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if not host:
            return ""
        extracted = tldextract.extract(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return host
    except:
        return ""

def check_sender_link_mismatch(sender: str, links: List[str]) -> bool:
    """Check if links in SMS don't match sender (if sender appears to be a service)"""
    if not sender or not links:
        return False
    
    sender_lower = sender.lower()
    # Check if sender name suggests a service/company
    service_keywords = ["bank", "paypal", "amazon", "apple", "google", "microsoft", "netflix", "pay"]
    
    if not any(kw in sender_lower for kw in service_keywords):
        return False
    
    # Extract domains from links
    link_domains = [extract_domain_from_link(link) for link in links if extract_domain_from_link(link)]
    
    # Check if any link domain contains the service name
    for link_domain in link_domains:
        if link_domain:
            # If sender mentions a service but link doesn't match, it's suspicious
            for kw in service_keywords:
                if kw in sender_lower and kw not in link_domain:
                    return True
    
    return False

def count_phishing_keywords(text: str, keywords: List[str]) -> int:
    """Count occurrences of phishing keywords"""
    text_lower = text.lower()
    count = 0
    for keyword in keywords:
        count += len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower))
    return count

# --- Main analysis function ---
def analyze_sms(sender: Optional[str] = None, number: Optional[str] = None, 
                content: Optional[str] = None) -> dict:
    """
    Analyze an SMS and return a structured result:
    {
        "sender": "...",
        "number": "...",
        "content": "...",
        "score": 0-100,
        "verdict": "safe" | "suspicious" | "phishing",
        "reasons": [...],
        "indicators": {flag: True/False, ...},
        "links_found": [...]
    }
    """
    reasons = []
    indicators = {}
    score = 0.0
    links_found = []

    # Load rules
    rules = load_sms_rules()
    
    # Load weights from rules JSON (strictly from JSON)
    WEIGHTS = get_weights(rules)

    # Normalize inputs
    sender = (sender or "").strip()
    number = (number or "").strip()
    content = (content or "").strip()
    full_text = content.lower()

    # --- Checks ---

    # 1) Suspicious sender number (from rules JSON)
    if number:
        suspicious_numbers = rules.get("suspicious_numbers", [])
        suspicious_number_flag = any(pattern.lower() in number.lower() for pattern in suspicious_numbers) or is_suspicious_number(number)
        indicators["suspicious_sender_number"] = suspicious_number_flag
        if suspicious_number_flag:
            reasons.append(f"Suspicious sender number: {number} (from sms_rules.json)")
            score += WEIGHTS["suspicious_sender_number"]
        
        # Check if number looks invalid
        if number and not re.match(r'^\+?[0-9\s\-\(\)]{7,}$', number):
            indicators["invalid_number_format"] = True
            reasons.append("Invalid or unusual phone number format")
            score += WEIGHTS["invalid_number_format"]

    # 2) Extract and analyze links
    links_found = extract_links(content)
    indicators["has_links"] = len(links_found) > 0
    
    if links_found:
        reasons.append(f"Found {len(links_found)} link(s) in SMS")
        score += WEIGHTS["suspicious_link"]

        # Check for shortened URLs (high risk in SMS)
        shortened_found = []
        for link in links_found:
            if is_shortened_url(link):
                shortened_found.append(link)
        
        if shortened_found:
            indicators["shortened_url"] = True
            reasons.append(f"Shortened URL(s) detected: {', '.join(shortened_found[:2])}")
            score += WEIGHTS["shortened_url"]
        
        # Check for link-sender mismatch (similar to email checker)
        if sender and check_sender_link_mismatch(sender, links_found):
            indicators["link_sender_mismatch"] = True
            reasons.append("Links in SMS don't match the claimed sender service")
            score += WEIGHTS["link_sender_mismatch"]

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

    # 4) Phishing keywords
    phishing_keywords = rules.get("phishing_keywords", [])
    keyword_count = count_phishing_keywords(full_text, phishing_keywords)
    indicators["phishing_keywords"] = keyword_count > 0
    
    if keyword_count > 0:
        reasons.append(f"Phishing-related keywords detected ({keyword_count} occurrences)")
        score += min(WEIGHTS["phishing_keywords"] * (keyword_count / 2), WEIGHTS["phishing_keywords"] * 2)

    # 5) Unexpected action phrases (requests for sensitive info)
    unexpected_phrases = rules.get("unexpected_action_phrases", [])
    unexpected_found = []
    for phrase in unexpected_phrases:
        if phrase.lower() in full_text:
            unexpected_found.append(phrase)
    
    indicators["unexpected_action"] = len(unexpected_found) > 0
    if unexpected_found:
        reasons.append(f"Requests unexpected action: {', '.join(unexpected_found[:2])}")
        score += WEIGHTS["unexpected_action"]

    # 6) Information request (OTP, PIN, password, etc.)
    info_keywords = ["otp", "pin", "password", "security code", "verification code", "2fa code"]
    info_found = [kw for kw in info_keywords if kw in full_text]
    indicators["info_request"] = len(info_found) > 0
    if info_found:
        reasons.append(f"Requests sensitive information: {', '.join(info_found)}")
        score += WEIGHTS["info_request"]

    # 7) "Too good to be true" offers
    promo_keywords = ["won", "reward", "free", "congratulations", "gift", "prize", "bonus", "lottery", "promo"]
    promo_found = [kw for kw in promo_keywords if kw in full_text]
    indicators["too_good_to_be_true"] = len(promo_found) > 0
    if promo_found:
        reasons.append(f"Suspicious promotional language: {', '.join(promo_found[:3])}")
        score += WEIGHTS["too_good_to_be_true"]

    # 8) Check for bank/financial institution mentions (common in SMS phishing)
    bank_keywords = ["bank", "account", "card", "payment", "transaction", "balance"]
    bank_mentions = [kw for kw in bank_keywords if kw in full_text]
    if bank_mentions and not any(kw in sender.lower() for kw in ["bank", "financial"]):
        indicators["bank_mention_without_legitimate_sender"] = True
        reasons.append("Mentions banking/financial terms but sender doesn't appear to be a bank")
        score += WEIGHTS["bank_mention_mismatch"]

    # 9) Missing contact information
    # Legitimate messages often include contact info or opt-out instructions
    has_contact_info = bool(re.search(r'(call|contact|reply|stop|unsubscribe)', full_text))
    indicators["no_contact_info"] = not has_contact_info
    if not has_contact_info and score > 20:
        # Only add this if already suspicious
        reasons.append("No contact information or opt-out instructions")
        score += WEIGHTS["no_contact_info"]

    # 10) Suspicious sender name
    if sender:
        sender_lower = sender.lower()
        # Check if sender name mimics legitimate services
        suspicious_sender_patterns = ["bank", "paypal", "amazon", "apple", "google", "microsoft", "netflix", "uber", "whatsapp"]
        if any(pattern in sender_lower for pattern in suspicious_sender_patterns):
            # But check if it's actually from that service (would need verification)
            indicators["suspicious_sender_name"] = True
            reasons.append("Sender name mimics well-known service")
            score += WEIGHTS["suspicious_sender_name"]
    
    # 11) Check for suspicious patterns in content (typos, unusual formatting)
    if content:
        # Check for excessive use of special characters (common in spam)
        special_char_ratio = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>?]', content)) / max(len(content), 1)
        if special_char_ratio > 0.15:  # More than 15% special characters
            indicators["excessive_special_chars"] = True
            reasons.append("Unusual formatting with excessive special characters")
            score += WEIGHTS.get("excessive_special_chars", 10)
        
        # Check for all caps (common in phishing)
        if len(content) > 10:
            caps_ratio = sum(1 for c in content if c.isupper()) / len(content)
            if caps_ratio > 0.5:  # More than 50% uppercase
                indicators["excessive_caps"] = True
                reasons.append("Message uses excessive capitalization")
                score += WEIGHTS.get("excessive_caps", 8)

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
        "number": number,
        "content": content,
        "score": mapped,
        "verdict": verdict,
        "reasons": reasons or ["No obvious automated red flags detected"],
        "indicators": indicators,
        "links_found": links_found
    }

    return result

# Allow external import
__all__ = ["analyze_sms"]

