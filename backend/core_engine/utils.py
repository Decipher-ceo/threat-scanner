import tldextract
from urllib.parse import urlparse

def extract_domain(url: str) -> str:
    """
    Extracts domain from a URL using tldextract.
    Returns only the registered domain (e.g., 'google.com')
    """
    if not url:
        return ""

    parsed = tldextract.extract(url)

    if parsed.domain and parsed.suffix:
        return f"{parsed.domain}.{parsed.suffix}"

    # fallback method
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc
    except:
        return ""
