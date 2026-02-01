print("""
=====================================
 Passive Web Security Analyzer
 Author: Salah Eddine
 Mode: Passive Scan Only
=====================================
""")


import requests, socket, ssl
from urllib.parse import urlparse

target = input("Enter target URL: ")
parsed = urlparse(target)
host = parsed.hostname

score = 100
issues = []

print(f"\n🔍 FULL PASSIVE SECURITY SCAN (A → Z)")
print(f"🎯 Target: {target}\n")

# ========================
# HTTP HEADERS
# ========================
print("📌 Security Headers:")
headers_required = {
    "Content-Security-Policy": 15,
    "Strict-Transport-Security": 15,
    "X-Frame-Options": 5,
    "X-Content-Type-Options": 5,
    "Referrer-Policy": 5,
    "Permissions-Policy": 5
}

try:
    r = requests.get(target, timeout=10)
    for h, penalty in headers_required.items():
        if h not in r.headers:
            print(f"⚠ {h}: Missing")
            score -= penalty
            issues.append(f"Missing {h}")
        else:
            print(f"✔ {h}: OK")

    server = r.headers.get("Server")
    if server:
        print(f"ℹ Server Disclosure: {server}")
        score -= 5
        issues.append("Server version disclosed")

except Exception as e:
    print("❌ HTTP Error:", e)

# ========================
# SSL / TLS
# ========================
print("\n📌 SSL / TLS:")
try:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            print("✔ HTTPS Enabled")
            print("TLS Version:", ssock.version())
            print("Valid Until:", cert['notAfter'])
except:
    print("❌ SSL issue")
    score -= 20
    issues.append("SSL problem")

# ========================
# HTTP METHODS
# ========================
print("\n📌 HTTP Methods:")
try:
    opt = requests.options(target)
    methods = opt.headers.get("Allow", "Unknown")
    print("Allowed:", methods)
    if "PUT" in methods or "DELETE" in methods:
        score -= 15
        issues.append("Dangerous HTTP methods enabled")
except:
    pass

# ========================
# CORS
# ========================
print("\n📌 CORS:")
cors = r.headers.get("Access-Control-Allow-Origin")
if cors == "*":
    print("⚠ Wildcard CORS detected")
    score -= 15
    issues.append("CORS wildcard")
else:
    print("✔ CORS safe")

# ========================
# Cookies
# ========================
print("\n📌 Cookies:")
if not r.cookies:
    print("✔ No cookies detected")
else:
    for c in r.cookies:
        print("Cookie:", c.name)

# ========================
# Sensitive Files (SAFE)
# ========================
print("\n📌 Sensitive Files:")
paths = ["/robots.txt", "/security.txt", "/.env", "/.git/HEAD"]
for p in paths:
    try:
        res = requests.head(target + p, timeout=5)
        if res.status_code == 200:
            print(f"⚠ Accessible: {p}")
            score -= 10
            issues.append(f"Sensitive file exposed: {p}")
        else:
            print(f"✔ {p} protected")
    except:
        pass

# ========================
# FINAL SCORE
# ========================
print("\n==============================")
score = max(score, 0)

if score >= 80:
    level = "🟢 GOOD"
elif score >= 65:
    level = "🟡 MEDIUM (Needs Hardening)"
elif score >= 50:
    level = "🟡 MEDIUM (Some Risks)"
else:
    level = "🔴 WEAK"

print(f"📊 Security Score: {score} / 100")
print(f"🔐 Security Level: {level}")

print("\n🧠 Professional Verdict:")
if score >= 65:
    print("✔ No critical vulnerabilities detected.")
    print("⚠ Some security headers hardening recommended.")
else:
    print("⚠ Multiple weaknesses detected.")
    print("❗ Does NOT mean hacked.")

print("\n📌 Findings:")
for i in issues:
    print("-", i)

print("\n✅ Full passive security scan completed")



# For educational and authorized testing only.
# Do NOT scan systems without permission.
