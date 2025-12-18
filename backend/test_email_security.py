
import sys
import os

# Add the project root to the python path so imports work
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.core_engine.email_checker import analyze_email

def run_tests():
    cases = [
        # (Email, Expected Verdict, Description)
        ("security@google.com", "safe", "Exact match Google"),
        ("admin@googie.com", "phishing", "Typo Google (googie)"),
        ("support@the5ers.com", "safe", "Exact match The5ers"),
        ("alert@the5erss.com", "phishing", "Typo The5ers (the5erss)"),
        ("dev@github.com", "safe", "Exact match GitHub"),
        ("fake@githuub.com", "phishing", "Typo GitHub (githuub)"),
        ("user@opay.com", "safe", "Exact match OPay"),
        ("pay@0pay.com", "phishing", "Typo OPay (0pay)"),
        ("random@example.com", "safe", "Unrelated domain (should be safe unless other rules trigger)"),
        ("googlesecurity@gmail.com", "phishing", "Local-part impersonation (google in gmail)"),
        ("github-support@yahoo.com", "phishing", "Local-part impersonation (github in yahoo)"),
        ("my.name@gmail.com", "safe", "Generic gmail usage")
    ]

    print(f"{'Email':<30} | {'Expected':<10} | {'Actual':<10} | {'Score':<5} | {'Result':<10}")
    print("-" * 80)

    all_passed = True
    for email, expected, desc in cases:
        result = analyze_email(sender=email)
        actual = result['verdict']
        score = result['score']
        
        # We only care about the verdict matching the expectation
        # Note: "safe" might turn "suspicious" if other rules trigger, 
        # but for clean emails it should remain safe.
        # "phishing" must be "phishing".
        
        passed = (actual == expected) if expected == "phishing" else (actual != "phishing")
        # Refined check: trusted domains should ideally be safe, typos MUST be phishing
        
        if expected == "phishing" and actual != "phishing":
            passed = False
        
        status = "PASS" if passed else "FAIL"
        if not passed: all_passed = False
        
        print(f"{email:<30} | {expected:<10} | {actual:<10} | {score:<5} | {status}")
        if not passed:
            print(f"  -> Reasons: {result['reasons']}")

    if all_passed:
        print("\nAll security tests PASSED.")
    else:
        print("\nSome tests FAILED.")

if __name__ == "__main__":
    run_tests()
