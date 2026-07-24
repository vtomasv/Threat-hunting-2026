/*
 * YARA Rules for Web Shell Detection
 * MAR404 - Cacería de Amenazas - Lab 20
 * 
 * Estas reglas detectan diferentes tipos de web shells PHP.
 * Los estudiantes deben crear reglas adicionales durante el laboratorio.
 */

rule china_chopper_oneliner {
    meta:
        description = "Detects China Chopper one-liner web shell"
        author = "MAR404 Lab"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $chopper1 = /@eval\s*\(\s*\$_(POST|REQUEST|GET)\s*\[/ ascii
        $chopper2 = /@assert\s*\(\s*\$_(POST|REQUEST|GET)\s*\[/ ascii
        $chopper3 = /eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|REQUEST|GET)/ ascii
    condition:
        any of them
}

rule php_webshell_generic {
    meta:
        description = "Generic PHP web shell detection"
        author = "MAR404 Lab"
        severity = "high"
    strings:
        $func1 = "system(" ascii
        $func2 = "shell_exec(" ascii
        $func3 = "passthru(" ascii
        $func4 = "exec(" ascii
        $input1 = "$_POST[" ascii
        $input2 = "$_GET[" ascii
        $input3 = "$_REQUEST[" ascii
    condition:
        any of ($func*) and any of ($input*)
}

rule obfuscated_webshell {
    meta:
        description = "Detects obfuscated web shells using encoding"
        author = "MAR404 Lab"
        severity = "high"
    strings:
        $obf1 = "str_rot13" ascii
        $obf2 = "base64_decode" ascii
        $obf3 = "gzinflate" ascii
        $obf4 = "gzuncompress" ascii
        $exec1 = "eval(" ascii
        $exec2 = "assert(" ascii
        $exec3 = "create_function(" ascii
    condition:
        any of ($obf*) and any of ($exec*)
}

rule webshell_in_image {
    meta:
        description = "Detects PHP code embedded in image files"
        author = "MAR404 Lab"
        severity = "critical"
    strings:
        $jpeg_magic = { FF D8 FF }
        $php_open = "<?php" ascii
        $func1 = "system(" ascii
        $func2 = "shell_exec(" ascii
        $func3 = "exec(" ascii
    condition:
        $jpeg_magic at 0 and $php_open and any of ($func*)
}

rule encrypted_webshell {
    meta:
        description = "Detects web shells using encryption for C2 communication"
        author = "MAR404 Lab"
        severity = "critical"
    strings:
        $crypto1 = "openssl_decrypt" ascii
        $crypto2 = "openssl_encrypt" ascii
        $crypto3 = "aes-256" ascii nocase
        $crypto4 = "mcrypt" ascii
        $exec1 = "exec(" ascii
        $exec2 = "system(" ascii
        $exec3 = "shell_exec(" ascii
        $cookie = "$_COOKIE[" ascii
    condition:
        any of ($crypto*) and (any of ($exec*) or $cookie)
}

rule htaccess_php_handler {
    meta:
        description = "Detects .htaccess files that enable PHP execution in non-standard extensions"
        author = "MAR404 Lab"
        severity = "high"
    strings:
        $handler1 = "AddHandler application/x-httpd-php" ascii nocase
        $handler2 = "SetHandler application/x-httpd-php" ascii nocase
        $ext1 = ".jpg" ascii
        $ext2 = ".png" ascii
        $ext3 = ".gif" ascii
    condition:
        any of ($handler*) and any of ($ext*)
}
