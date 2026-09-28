import re
import math
import secrets
import string

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "admin", "welcome",
    "password123", "letmein", "iloveyou", "abc123", "111111", "123123",
}

PATTERNS = [
    "123456", "234567", "345678", "abcdef", "bcdefg",
    "qwerty", "asdfgh", "zxcvbn", "111111", "aaaaaa",
]


def has_predictable_pattern(password):
    lowered = password.lower()
    return any(pattern in lowered for pattern in PATTERNS)


def has_excessive_repetition(password):
    return bool(re.search(r"(.)\1{2,}", password))


def analyze_password(password):
    report = []
    score = 0

    if password.lower() in COMMON_PASSWORDS:
        report.append(("warning", "This password is commonly used."))
    else:
        report.append(("ok", "Not found in common password list."))

    length = len(password)
    if length >= 12:
        score += 30
        report.append(("ok", f"Good length ({length} characters)."))
    elif length >= 8:
        score += 15
        report.append(("warning", f"Acceptable length ({length}), but 12+ is safer."))
    else:
        report.append(("bad", f"Password is too short ({length} characters)."))

    if re.search(r"[A-Z]", password):
        score += 15
        report.append(("ok", "Contains uppercase letters."))
    else:
        report.append(("bad", "No uppercase letters."))

    if re.search(r"[a-z]", password):
        score += 15
        report.append(("ok", "Contains lowercase letters."))
    else:
        report.append(("bad", "No lowercase letters."))

    if re.search(r"[0-9]", password):
        score += 15
        report.append(("ok", "Contains numbers."))
    else:
        report.append(("bad", "No numbers."))

    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\];'/\\+=~`]", password):
        score += 15
        report.append(("ok", "Contains special characters."))
    else:
        report.append(("bad", "No special character."))

    if has_predictable_pattern(password):
        score -= 15
        report.append(("warning", "Contains a common/predictable pattern."))

    if has_excessive_repetition(password):
        score -= 10
        report.append(("warning", "Contains excessive repeated characters."))

    score = max(0, min(100, score))
    entropy = estimate_entropy(password)

    return score, report, entropy


def get_strength_label(score):
    if score <= 30:
        return "Very Weak"
    elif score <= 50:
        return "Weak"
    elif score <= 70:
        return "Medium"
    elif score <= 85:
        return "Strong"
    else:
        return "Very Strong"


def print_progress_bar(score, width=25):
    filled = int(width * score / 100)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {score}/100"


def get_suggestions(password):
    suggestions = []
    if len(password) < 12:
        suggestions.append("Increase the password length (aim for 12+ characters).")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
        suggestions.append("Add both uppercase and lowercase characters.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add numbers.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\];'/\\+=~`]", password):
        suggestions.append("Add symbols/special characters.")
    if has_predictable_pattern(password) or has_excessive_repetition(password):
        suggestions.append("Avoid predictable patterns and repeated characters.")
    if password.lower() in COMMON_PASSWORDS:
        suggestions.append("Avoid commonly used passwords entirely.")
    return suggestions


def estimate_entropy(password):
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\];'/\\+=~`]", password):
        pool_size += 32

    if pool_size == 0 or len(password) == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 1)


def get_resistance_label(entropy):
    if entropy < 28:
        return "Very Low (crackable almost instantly)"
    elif entropy < 40:
        return "Low"
    elif entropy < 60:
        return "Moderate"
    elif entropy < 80:
        return "High"
    else:
        return "Very High"


def generate_strong_password(length=14):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+"

    all_chars = lower + upper + digits + symbols

    password_chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]

    password_chars += [secrets.choice(all_chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def print_report(password):
    score, report, entropy = analyze_password(password)
    label = get_strength_label(score)
    resistance = get_resistance_label(entropy)
    suggestions = get_suggestions(password)

    print(f"\nStrength: {label}")
    print(print_progress_bar(score))

    print("\nSecurity Report:")
    for tag, message in report:
        symbol = {"ok": "[OK]", "bad": "[X]", "warning": "[!]"}[tag]
        print(f"  {symbol} {message}")

    print(f"\nEstimated entropy: {entropy} bits")
    print(f"Estimated resistance: {resistance}")
    print("(Educational estimate only.)")

    if suggestions:
        print("\nSuggestions to improve:")
        for tip in suggestions:
            print(f"  - {tip}")
    else:
        print("\nNo improvements needed - excellent password!")

    print("\nYour password is analyzed locally. It is not stored or transmitted.")
    print("-" * 60)


def main():
    print("=" * 60)
    print("     PASSWORD STRENGTH ANALYZER - Advanced Edition")
    print("=" * 60)
    print("Commands:")
    print("  Type a password  -> analyze it")
    print("  'generate'        -> get a strong password suggestion")
    print("  'quit'            -> exit")
    print()

    while True:
        user_input = input("Enter password (or command): ").strip()

        if user_input.lower() == "quit":
            print("Goodbye!")
            break

        if user_input.lower() == "generate":
            new_password = generate_strong_password()
            print(f"\nGenerated password: {new_password}")
            print("(Generated locally using a cryptographically secure method.)\n")
            print_report(new_password)
            continue

        if user_input == "":
            print("Please enter something.\n")
            continue

        print_report(user_input)


if __name__ == "__main__":
    main()