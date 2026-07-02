<?php
/**
 * Reyonic — security.php
 * -----------------------------------------------------------------------
 * Drop-in security hardening module for the seller marketplace prototype.
 * Include this file ONCE, right after $pdo is created, and BEFORE
 * session_start(). See PATCH_INSTRUCTIONS_KU.md for exact wiring steps.
 *
 * What this file adds:
 *  1) Hardened session cookie settings (httponly, samesite, secure-on-https)
 *  2) CSRF tokens for every state-changing form
 *  3) Login attempt tracking + automatic lockout (brute-force protection)
 *  4) A one-time "setup key" required to ever create the admin account
 *     (fixes a critical hole: previously, anyone who typed the admin
 *     email + any strong-enough password could instantly become admin)
 *  5) TOTP two-factor authentication (Google Authenticator / Authy
 *     compatible) required for the admin account
 *  6) Baseline security response headers
 *  7) Safe file-upload checks (real image validation)
 * -----------------------------------------------------------------------
 */

/* =========================================================================
   0) CONFIG — real values live in config.local.php (gitignored, never
   committed). Each deployment must have its own copy of that file.
   ========================================================================= */

if (file_exists(__DIR__ . '/config.local.php')) {
    require __DIR__ . '/config.local.php';
} else {
    error_log('SECURITY WARNING: config.local.php is missing — falling back to the default ADMIN_SETUP_KEY. Create config.local.php before deploying.');
}

// One-time secret required to ever bootstrap (create) the admin account.
// Set this to a long random string, deploy, create the admin account once,
// then you may delete/blank this constant again since it is never needed
// after the admin row already exists.
if (!defined('ADMIN_SETUP_KEY')) {
    define('ADMIN_SETUP_KEY', 'boma85@PESHaWA#3');
}

define('LOGIN_MAX_ATTEMPTS', 5);      // failed attempts allowed
define('LOGIN_LOCKOUT_MINUTES', 15);  // lockout window after max attempts
define('ADMIN_PASSWORD_MIN_LENGTH_STRICT', 16); // stronger than sellers/customers

/* =========================================================================
   1) SESSION HARDENING — call bootstrapSecureSession() BEFORE session_start()
   ========================================================================= */

function bootstrapSecureSession(): void {
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443')
        || ((strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https');

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Lax');
    ini_set('session.cookie_secure', $isHttps ? '1' : '0');
    ini_set('session.gc_maxlifetime', '3600');
    session_name('reyonic_sid');
}

/** Call once right after a successful login (any role) to stop session fixation. */
function regenerateSessionOnLogin(): void {
    session_regenerate_id(true);
}

/* =========================================================================
   2) CSRF PROTECTION
   ========================================================================= */

function csrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/** Echo this inside every <form method="post"> ... </form> block. */
function csrfField(): string {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') . '">';
}

/** Call at the very top of every POST handler. Returns true if the token is valid. */
function csrfVerify(): bool {
    $token = $_POST['csrf_token'] ?? '';
    return is_string($token) && $token !== '' && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/* =========================================================================
   3) LOGIN RATE LIMITING / LOCKOUT
   ========================================================================= */

function ensureSecurityTables(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        identifier VARCHAR(190) NOT NULL,
        ip_address VARCHAR(64) NOT NULL,
        attempted_at DATETIME NOT NULL,
        success TINYINT(1) NOT NULL DEFAULT 0,
        INDEX idx_identifier_time (identifier, attempted_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function ensureAdminSecurityColumns(PDO $pdo): void {
    $addColumn = function (string $table, string $column, string $definition) use ($pdo) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?");
        $stmt->execute([$table, $column]);
        if ((int) $stmt->fetchColumn() === 0) {
            $pdo->exec("ALTER TABLE `{$table}` ADD COLUMN `{$column}` {$definition}");
        }
    };
    $addColumn('users', 'totp_secret', 'VARCHAR(64) NULL');
    $addColumn('users', 'totp_enabled', 'TINYINT(1) NOT NULL DEFAULT 0');
    $addColumn('users', 'last_login_at', 'DATETIME NULL');
    $addColumn('users', 'last_login_ip', 'VARCHAR(64) NULL');
}

function recordLoginAttempt(PDO $pdo, string $identifier, bool $success): void {
    $stmt = $pdo->prepare("INSERT INTO login_attempts (identifier, ip_address, attempted_at, success) VALUES (?, ?, NOW(), ?)");
    $stmt->execute([strtolower($identifier), $_SERVER['REMOTE_ADDR'] ?? 'unknown', $success ? 1 : 0]);
}

/** True if this identifier (e.g. "admin:email") is currently locked out. */
function isLoginLocked(PDO $pdo, string $identifier): bool {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE identifier = ? AND success = 0 AND attempted_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)");
    $stmt->execute([strtolower($identifier), LOGIN_LOCKOUT_MINUTES]);
    return intval($stmt->fetchColumn()) >= LOGIN_MAX_ATTEMPTS;
}

/** Clears failed-attempt history after a successful login. */
function clearLoginAttempts(PDO $pdo, string $identifier): void {
    $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE identifier = ?");
    $stmt->execute([strtolower($identifier)]);
}

/* =========================================================================
   4) TOTP TWO-FACTOR AUTH (RFC 6238) — no external library required
   ========================================================================= */

function totpGenerateSecret(int $bytes = 20): string {
    $random = random_bytes($bytes);
    $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    $buffer = 0;
    $bitsLeft = 0;
    foreach (str_split($random) as $byte) {
        $buffer = ($buffer << 8) | ord($byte);
        $bitsLeft += 8;
        while ($bitsLeft >= 5) {
            $bitsLeft -= 5;
            $secret .= $base32Chars[($buffer >> $bitsLeft) & 31];
        }
    }
    if ($bitsLeft > 0) {
        $secret .= $base32Chars[($buffer << (5 - $bitsLeft)) & 31];
    }
    return $secret;
}

function totpBase32Decode(string $b32): string {
    $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
    $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $buffer = 0;
    $bitsLeft = 0;
    $output = '';
    foreach (str_split($b32) as $char) {
        $val = strpos($base32Chars, $char);
        if ($val === false) {
            continue;
        }
        $buffer = ($buffer << 5) | $val;
        $bitsLeft += 5;
        if ($bitsLeft >= 8) {
            $bitsLeft -= 8;
            $output .= chr(($buffer >> $bitsLeft) & 0xFF);
        }
    }
    return $output;
}

function totpCodeAt(string $secretBase32, int $timestamp, int $timeStep = 30, int $digits = 6): string {
    $key = totpBase32Decode($secretBase32);
    $counter = intdiv($timestamp, $timeStep);
    $binCounter = pack('N*', 0) . pack('N*', $counter); // 8-byte big-endian counter
    $hash = hash_hmac('sha1', $binCounter, $key, true);
    $offset = ord($hash[19]) & 0xF;
    $truncated = ((ord($hash[$offset]) & 0x7F) << 24)
        | ((ord($hash[$offset + 1]) & 0xFF) << 16)
        | ((ord($hash[$offset + 2]) & 0xFF) << 8)
        | (ord($hash[$offset + 3]) & 0xFF);
    $code = $truncated % (10 ** $digits);
    return str_pad((string) $code, $digits, '0', STR_PAD_LEFT);
}

/** Verifies a 6-digit code, allowing +-1 time step of clock drift. */
function totpVerify(string $secretBase32, string $code, int $window = 1, int $timeStep = 30): bool {
    $code = trim($code);
    if (!preg_match('/^\d{6}$/', $code)) {
        return false;
    }
    $now = time();
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(totpCodeAt($secretBase32, $now + ($i * $timeStep), $timeStep), $code)) {
            return true;
        }
    }
    return false;
}

function totpProvisioningUri(string $secretBase32, string $accountLabel, string $issuer = 'Reyonic Admin'): string {
    return 'otpauth://totp/' . rawurlencode($issuer . ':' . $accountLabel)
        . '?secret=' . rawurlencode($secretBase32)
        . '&issuer=' . rawurlencode($issuer)
        . '&algorithm=SHA1&digits=6&period=30';
}

/* =========================================================================
   5) SECURITY HEADERS — call once near the top of every request
   ========================================================================= */

function sendSecurityHeaders(): void {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header(
        "Content-Security-Policy: default-src 'self'; " .
        "img-src * data: blob:; " .
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; " .
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; " .
        "frame-src https://www.google.com;"
    );
}

/* =========================================================================
   6) SAFE FILE UPLOADS
   ========================================================================= */

/** Confirms the uploaded temp file is a genuine image (not just a renamed .php). */
function isGenuineImageUpload(string $tmpPath): bool {
    $info = @getimagesize($tmpPath);
    if ($info === false) {
        return false;
    }
    $allowed = [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF, IMAGETYPE_WEBP];
    return in_array($info[2], $allowed, true);
}

/** Writes a .htaccess into an uploads directory so PHP files there can never execute. */
function lockDownUploadsFolder(string $dir): void {
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
    if (!file_exists($htaccess)) {
        file_put_contents($htaccess, "php_flag engine off\n<FilesMatch \"\\.(php|phtml|php\\d|phar)\">\nRequire all denied\n</FilesMatch>\n");
    }
}
