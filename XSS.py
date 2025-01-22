import re

def detect_xss(input_string):
    # Common XSS patterns
    xss_patterns = [
        r"<script.*?>.*?</script>",  # Script tags
        r"javascript:",             # Inline JavaScript
        r"on\w+\s*=",               # Event handlers like onerror, onclick, etc.
        r"eval\(",                  # Eval function
        r"src\s*=\s*[\"'].*?[\"']", # src attributes with links
        r"<iframe.*?>.*?</iframe>", # iframe tags
        r"document\.cookie",        # Accessing cookies
        r"<img.*?on\w+\s*=.*?>",    # Malicious image tags
    ]

    # Check for matches against each pattern
    for pattern in xss_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return f"Potential XSS detected: {pattern}"
    
    return "Input is clean."

# Example usage
while True:
    user_input = input("Enter text to check for XSS: ")
    result = detect_xss(user_input)
    print(result)
