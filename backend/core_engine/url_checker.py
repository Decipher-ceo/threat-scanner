# backend/core_engine/url_checker.py
import re
import math
import json
import os
from urllib.parse import urlparse, unquote
import tldextract

# Load rules from JSON file
def load_url_rules() -> dict:
    """Load URL rules from JSON file"""
    rules_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "..", "..", "rules", "url_rules.json"
    )
    try:
        with open(rules_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Fallback to default rules
        return {
            "suspicious_tlds": [".xyz", ".top", ".gq", ".tk", ".ml", ".ga", ".icu", ".buzz", ".rest", ".monster", ".zip", ".click", ".work", ".cn", ".ru"],
            "trusted_domains": ["google.com", "paypal.com", "facebook.com", "youtube.com", "amazon.com", "netflix.com", "microsoft.com", "apple.com", "github.com", "linkedin.com"],
            "phishing_keywords": ["login", "verify", "secure", "update", "unlock", "banking", "password", "confirm", "recovery", "account-security", "free-gift", "bonus", "promo", "alert", "suspend", "urgent", "auth", "2fa"],
            "detect_ip_urls": True
        }

# --- Configuration: weights loaded from JSON rules ---
def get_weights(rules: dict) -> dict:
    """Get weights from rules JSON, with fallback defaults"""
    return rules.get("weights", {
        "ip_in_host": 25,
        "suspicious_tld": 18,
        "long_url": 6,
        "many_subdomains": 8,
        "hyphen_in_domain": 6,
        "punycode": 20,
        "suspicious_chars": 6,
        "suspicious_path_tokens": 6,
        "url_length_entropy": 5,
        "known_whitelist": -40,
        "suspicious_domain_token_long": 6,
    })

# --- Helper utils ---
def is_ip(host: str) -> bool:
    # IPv4
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return True
    # IPv6 bracketed
    if host.startswith("[") and host.endswith("]"):
        return True
    return False

def contains_punycode(host: str) -> bool:
    return "xn--" in host.lower()

def entropy_score(s: str) -> float:
    # crude "entropy-ish" measure: character distribution variance
    if not s:
        return 0.0
    from collections import Counter
    cnt = Counter(s)
    probs = [v/len(s) for v in cnt.values()]
    import math
    ent = -sum(p * math.log2(p) for p in probs if p>0)
    # normalized roughly to [0,1] by dividing by log2(len(alphabet))
    # use 6 as rough normalizer
    return min(ent / 6.0, 1.0)

# --- Main analysis function ---
def analyze_url(url: str) -> dict:
    """
    Analyze a URL and return a structured result:
    {
        "url": "...",
        "score": 0-100,
        "verdict": "safe" | "suspicious" | "phishing",
        "reasons": [...],
        "indicators": {flag: True/False, ...},
        "parsed": {...}
    }
    """
    reasons = []
    indicators = {}
    score = 0.0

    # Load rules from JSON file
    rules = load_url_rules()
    
    # Load weights from rules JSON (strictly from JSON)
    WEIGHTS = get_weights(rules)
    
    # Extract rules from JSON
    SUSPICIOUS_TLDS = set([tld.replace(".", "") for tld in rules.get("suspicious_tlds", [])])
    ROOT_DOMAIN_WHITELIST = set(rules.get("trusted_domains", []))
    SUSPICIOUS_PATH_TOKENS = set(rules.get("phishing_keywords", []))
    DETECT_IP_URLS = rules.get("detect_ip_urls", True)

    if not url or not isinstance(url, str):
        return {
            "url": url,
            "score": 100,
            "verdict": "phishing",
            "reasons": ["No URL provided or wrong type"],
            "indicators": {"invalid_input": True},
            "parsed": {}
        }

    # Ensure we have a scheme for parsing
    original = url.strip()
    if "://" not in original:
        test_url = "http://" + original
    else:
        test_url = original

    parsed = urlparse(test_url)
    host = parsed.hostname or ""
    path = unquote(parsed.path or "")
    query = parsed.query or ""

    extracted = tldextract.extract(host)
    root_domain = ".".join(part for part in (extracted.domain, extracted.suffix) if part)
    subdomain = extracted.subdomain or ""

    parsed_info = {
        "scheme": parsed.scheme,
        "host": host,
        "root_domain": root_domain,
        "subdomain": subdomain,
        "path": path,
        "query": query,
        "port": parsed.port,
    }

    # --- Checks ---

    # 1) Host is an IP address (if enabled in rules)
    if DETECT_IP_URLS:
        ip_flag = is_ip(host)
        indicators["ip_in_host"] = ip_flag
        if ip_flag:
            reasons.append("Host is an IP address (not a domain) - from url_rules.json")
            score += WEIGHTS["ip_in_host"]

    # 2) Suspicious / rare / known-bad TLDs (from JSON rules)
    suffix_full = (extracted.suffix or "").lower()
    suffix_top = suffix_full.split(".")[-1]
    
    # Check for .gov or any country code TLD (usually 2 characters)
    is_gov_or_cctld = suffix_top == "gov" or len(suffix_top) == 2
    
    tld_flag = suffix_top in SUSPICIOUS_TLDS and not is_gov_or_cctld
    indicators["suspicious_tld"] = tld_flag
    
    if is_gov_or_cctld:
        reasons.append(f"Top-level domain '.{suffix_full}' is a trusted government or country-specific TLD")
        score += -20  # Reward trusted TLDs
    elif tld_flag:
        reasons.append(f"Top-level domain '{extracted.suffix}' is suspicious/unusual (from url_rules.json)")
        score += WEIGHTS["suspicious_tld"]

    # 3) Very long URL
    url_len = len(original)
    indicators["long_url"] = url_len > 100
    if url_len > 100:
        reasons.append(f"URL length is long ({url_len} characters)")
        score += WEIGHTS["long_url"]

    # 4) Many subdomains (e.g., a.b.c.d.example.com)
    # 162) Many subdomains (e.g., a.b.c.d.example.com)
    # Ignore "www" and "m" as they are standard subdomains
    clean_subdomain = ".".join([p for p in subdomain.split(".") if p not in ["www", "m", ""]])
    sub_count = clean_subdomain.count(".") + (1 if clean_subdomain else 0)
    
    # Only flag if it's not a trusted domain or gov/ccTLD
    many_subdomains_flag = sub_count >= 2 and not is_gov_or_cctld
    indicators["many_subdomains"] = many_subdomains_flag
    if many_subdomains_flag:
        reasons.append(f"Excessive subdomains detected ({sub_count})")
        score += WEIGHTS["many_subdomains"]

    # 5) Hyphen in domain (brand impersonation)
    # Only flag if not a trusted or gov/cc domain
    hyphen_flag = "-" in extracted.domain and not is_gov_or_cctld
    indicators["hyphen_in_domain"] = hyphen_flag
    if hyphen_flag:
        reasons.append("Hyphen found in root domain (unusual for official entities)")
        score += WEIGHTS["hyphen_in_domain"]

    # 6) Punycode (IDN homograph attacks)
    puny_flag = contains_punycode(host)
    indicators["punycode"] = puny_flag
    if puny_flag:
        reasons.append("Punycode found in host (possible homograph attack)")
        score += WEIGHTS["punycode"]

    # 7) Suspicious characters in path or host (many @, %, javascript:, data:)
    # Only flag if not trusted
    suspicious_chars = bool(re.search(r"[@\^\[\]\{\}\<\>\\\|]", original)) and not is_gov_or_cctld
    indicators["suspicious_chars"] = suspicious_chars
    if suspicious_chars:
        reasons.append("Suspicious characters detected in URL")
        score += WEIGHTS["suspicious_chars"]

    # 8) Suspicious path tokens (from JSON rules - phishing_keywords)
    path_tokens = set(re.findall(r"[A-Za-z0-9_-]+", path.lower()))
    suspicious_tokens_found = path_tokens.intersection(SUSPICIOUS_PATH_TOKENS)
    indicators["suspicious_path_tokens"] = list(suspicious_tokens_found)
    if suspicious_tokens_found:
        reasons.append(f"Suspicious path tokens found: {', '.join(sorted(suspicious_tokens_found))}")
        score += WEIGHTS["suspicious_path_tokens"]

    # 9) Entropy-ish check for path+query
    ent = entropy_score((path + " " + query).strip())
    indicators["entropy_score"] = ent
    if ent > 0.9 and not is_gov_or_cctld:
        reasons.append("High character entropy in path/query (random-looking)")
        score += WEIGHTS["url_length_entropy"]

    # 10) Whitelist and misspelling check
    def is_similar_to_whitelisted(domain, threshold=0.8):
        """Check if domain is a likely misspelling of a whitelisted domain"""
        from difflib import SequenceMatcher
        
        domain = domain.lower()
        for whitelisted in ROOT_DOMAIN_WHITELIST:
            if domain == whitelisted:
                return True, whitelisted
                
            # Check for common misspellings
            ratio = SequenceMatcher(None, domain, whitelisted).ratio()
            if ratio >= threshold:
                return False, whitelisted  # Likely a misspelling
                
            # Check for character insertions/deletions (e.g., gooogle.com)
            if abs(len(domain) - len(whitelisted)) == 1:
                if whitelisted in domain or domain in whitelisted:
                    return False, whitelisted
                    
            # Check for common typos (character swaps, missing/extra characters)
            if len(domain) > 5 and len(whitelisted) > 5:
                if domain[1:] == whitelisted[1:]:  # First character difference
                    return False, whitelisted
                if domain[:-1] == whitelisted[:-1]:  # Last character difference
                    return False, whitelisted
                    
        return False, None

    # Check if domain is in whitelist or a likely misspelling
    is_whitelisted, matched_whitelist = is_similar_to_whitelisted(root_domain)
    indicators["known_whitelist"] = is_whitelisted
    
    if is_whitelisted or is_gov_or_cctld:
        reasons.append(f"Trust verified: Result is within a secure/official name space ('{root_domain}')")
        score += -40  # Massive score reduction for trusted entities
    elif matched_whitelist:
        reasons.append(f"Alert: Domain '{root_domain}' mimics trusted brand '{matched_whitelist}'")
        score += 65  # Immediate suspicious/phishing for mimicry

    # 11) Additional checks for whitelisted domains
    if is_whitelisted or matched_whitelist:
        domain_tokens = re.split(r"[\-\.]", extracted.domain or "")
        
        # Check for suspicious patterns in domain tokens
        suspicious_patterns = [
            (r"(.)\1{2,}", "Repeated characters in domain"),  # e.g. gooogle.com
            (r"(\w)\1{2,}", "Repeated characters in domain"),  # e.g. gooogle.com (alternative pattern)
            (r"(\w{2,})\1", "Repeated sequence in domain"),  # e.g. googlegoogle.com
            (r"(\w{3,})(\d+)", "Numbers after brand name"),  # e.g. google123.com
            (r"(\d+)(\w{3,})", "Numbers before brand name"),  # e.g. 123google.com
            (r"(\w{3,})-?(?:\w+)?-?(\1)", "Repeated words with separators"),  # e.g. google-account-google.com
        ]
        
        for pattern, reason in suspicious_patterns:
            if any(re.search(pattern, token, re.IGNORECASE) for token in domain_tokens):
                reasons.append(f"Suspicious domain pattern detected: {reason}")
                score += 30
                break
        
        # Check for long tokens
        suspicious_token_flag = any(len(tok) > 20 for tok in domain_tokens)
        indicators["suspicious_domain_token_long"] = suspicious_token_flag
        if suspicious_token_flag:
            reasons.append("Unusually long token in domain name")
            score += WEIGHTS.get("suspicious_domain_token_long", 6)

    # --- Final score normalization ---
    # Clip score to [0, 100]
    raw_score = max(0, score)
    # If negative due to whitelist weight, allow it but clamp after mapping
    mapped = int(min(max(raw_score, 0), 100))

    # Convert score to verdict thresholds (tweakable)
    if mapped >= 65:
        verdict = "phishing"
    elif mapped >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    result = {
        "url": original,
        "score": mapped,
        "verdict": verdict,
        "reasons": reasons or ["No obvious automated red flags detected"],
        "indicators": indicators,
        "parsed": parsed_info
    }

    return result

# Allow external import name
__all__ = ["analyze_url"]

