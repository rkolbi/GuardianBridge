<?php
/**
 * GuardianBridge - A Meshtastic Gateway for Community Resilience
 * Copyright (C) 2025 Robert Kolbasowski
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// GuardianBridge - Admin Panel

// --- CONFIGURATION ---
$revision = 'v1.4.0 "Dispatch"';
require_once __DIR__ . '/db.php';
$base_dir = '/opt/GuardianBridge';
$env_file = $base_dir . '/.env';
$gb_page_perf_start = microtime(true);
register_shutdown_function(function () use ($gb_page_perf_start) {
    $elapsed_ms = (microtime(true) - $gb_page_perf_start) * 1000;
    if ($elapsed_ms >= 1500) {
        $is_ajax = (isset($_POST['ajax']) && $_POST['ajax'] === 'true') ? ':ajax' : '';
        error_log(sprintf('GuardianBridge Perf: map.php%s %.1fms', $is_ajax, $elapsed_ms));
    }
});

// --- AUTHENTICATION CONFIG ---
$admin_env = get_env_settings($env_file, ['ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH']);
$admin_username = trim((string)($admin_env['ADMIN_USERNAME'] ?: 'admin'));
if ($admin_username === '') {
    $admin_username = 'admin';
}
$admin_password_hash = trim((string)($admin_env['ADMIN_PASSWORD_HASH'] ?? ''));
$admin_hash_info = password_get_info($admin_password_hash);
$is_admin_hash_configured = ($admin_password_hash !== '' && !empty($admin_hash_info['algo']));

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
$cookie_params = session_get_cookie_params();
$secure_cookie = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => $cookie_params['path'],
    'domain' => $cookie_params['domain'],
    'secure' => $secure_cookie,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

// --- CSRF TOKEN GENERATION ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// --- LOGOUT LOGIC ---
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
    exit;
}

// --- LOGIN LOGIC ---
function map_get_client_ip() {
    $ip = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    if ($ip === '') {
        $ip = 'unknown';
    }
    return substr($ip, 0, 64);
}

$login_error = '';
$max_login_attempts = 5;
$login_lockout_seconds = 300;
$now_ts = time();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $principal = ($username !== '') ? $username : '__EMPTY__';
    $client_ip = map_get_client_ip();

    $principal_stats = gb_get_recent_login_failure_stats('map', $principal, $client_ip, $login_lockout_seconds);
    $ip_stats = gb_get_recent_login_failure_stats('map', '__ANY__', $client_ip, $login_lockout_seconds);

    $locked_out = ($principal_stats['count'] >= $max_login_attempts) || ($ip_stats['count'] >= $max_login_attempts);
    if ($locked_out) {
        $remaining_seconds = 0;
        if (!empty($principal_stats['oldest'])) {
            $remaining_seconds = max($remaining_seconds, ($principal_stats['oldest'] + $login_lockout_seconds) - $now_ts);
        }
        if (!empty($ip_stats['oldest'])) {
            $remaining_seconds = max($remaining_seconds, ($ip_stats['oldest'] + $login_lockout_seconds) - $now_ts);
        }
        $remaining = max(1, intval(ceil($remaining_seconds / 60)));
        $login_error = "Too many failed attempts. Try again in {$remaining} minute(s).";
    } elseif (!$is_admin_hash_configured) {
        $login_error = 'ADMIN_PASSWORD_HASH is not configured. Set it in .env before signing in.';
    } else {
        if ($username === $admin_username && $password !== '' && password_verify($password, $admin_password_hash)) {
            $_SESSION['map_loggedin'] = true;
            gb_clear_login_failures('map', $principal, $client_ip);
            gb_clear_login_failures('map', '__ANY__', $client_ip);
            gb_prune_login_failures();
            session_regenerate_id(true);
            header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
            exit;
        } else {
            $login_error = 'Invalid username or password.';
            gb_record_login_failure('map', $principal, $client_ip, $now_ts);
            gb_record_login_failure('map', '__ANY__', $client_ip, $now_ts);
            gb_prune_login_failures();
        }
    }
}

// --- AUTHENTICATION GATE ---
if (!isset($_SESSION['map_loggedin']) || $_SESSION['map_loggedin'] !== true) {
?>
<!DOCTYPE html>
<html lang="en" class="bg-[#131314]">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - GuardianBridge Control</title>
    <link rel="icon" type="image/x-icon" href="/map-items/map-logo.ico">
    <script src="/map-items/tailwindcss.js"></script>
    <link href="/map-items/inter-font.css" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #131314; }
        input[type="text"], input[type="password"] {
            background-color: #1E1F20; border: 1px solid #3C4043; color: #E3E3E3;
            padding: 0.6rem 0.85rem; border-radius: 0.5rem; width: 100%; transition: all 0.2s;
        }
        input:focus {
            outline: none; border-color: #89B3F8; box-shadow: 0 0 0 2px rgba(137, 179, 248, 0.3);
        }
        .btn-primary { background-color: #89B3F8; color: #131314; }
        .btn-primary:hover { background-color: #A58AFB; }
    </style>
</head>
<body class="text-slate-300">
    <div class="min-h-screen flex items-center justify-center">
        <div class="max-w-md w-full p-8">
            <header class="mb-8 text-center">
                <img src="/map-items/map-logo.png" alt="Gateway Logo" class="h-28 w-24 mx-auto mb-4">
                <h1 class="text-4xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-red-400 bg-clip-text text-transparent">
                    GuardianBridge Control
                </h1>
                <p class="text-slate-400 mt-1">Administrator Login</p>
            </header>

            <?php if (!$is_admin_hash_configured): ?>
                <div class="bg-red-500/10 border border-red-500/20 text-red-300 px-4 py-3 rounded-lg relative mb-6 text-center">
                    <strong>Admin login disabled:</strong> <code class="bg-red-500/20 text-red-200 px-1 py-0.5 rounded text-sm">ADMIN_PASSWORD_HASH</code> is missing or invalid in <code class="bg-red-500/20 text-red-200 px-1 py-0.5 rounded text-sm">.env</code>.
                </div>
            <?php endif; ?>
            
            <?php if ($login_error): ?>
                <div class="bg-red-500/10 border border-red-500/20 text-red-300 px-4 py-3 rounded-lg relative mb-6 text-center" role="alert">
                    <?= htmlspecialchars($login_error) ?>
                </div>
            <?php endif; ?>

            <div class="bg-slate-900/70 border border-slate-700 text-slate-300 px-4 py-3 rounded-lg relative mb-6 text-center">
                Admin credentials are configured in <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-sm">.env</code>
                using <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-sm">ADMIN_USERNAME</code> and
                <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-sm">ADMIN_PASSWORD_HASH</code>.
            </div>

            <?php $can_attempt_admin_login = $is_admin_hash_configured; ?>
            <form method="POST" class="space-y-6">
                <input type="hidden" name="action" value="login">
                <div>
                    <label for="username" class="block text-sm font-medium text-slate-400 mb-2">Username</label>
                    <input type="text" id="username" name="username" required <?= $can_attempt_admin_login ? '' : 'disabled' ?>>
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-slate-400 mb-2">Password</label>
                    <input type="password" id="password" name="password" required <?= $can_attempt_admin_login ? '' : 'disabled' ?>>
                </div>
                <div>
                    <button type="submit" class="w-full py-2.5 px-4 rounded-lg font-semibold btn-primary" <?= $can_attempt_admin_login ? '' : 'disabled' ?>>Sign In</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
<?php
    exit;
}

$audit_actor = trim((string)($admin_username ?: 'admin'));

// --- CONFIGURATION & FILE PATHS ---
$data_dir = $base_dir . '/data';
$node_db_status_file = $data_dir . '/node_status.json';
$subscribers_file = $data_dir . '/subscribers.json';
$dispatcher_file = $data_dir . '/dispatcher_jobs.json';
$weather_current_file = $data_dir . '/weather_current.json';
$weather_alerts_file = $data_dir . '/nws_alerts.json';
$outgoing_email_file = $data_dir . '/outgoing_emails.json';
$failed_dm_queue_file = $data_dir . '/failed_dm_queue.json';
$dispatcher_status_file = $data_dir . '/dispatcher_status.json';
$weather_fetcher_lastrun_file = $data_dir . '/weather_fetcher.lastrun';
$email_processor_lastrun_file = $data_dir . '/email_processor.lastrun';
$commands_dir = $base_dir . '/data/commands';
$sos_log_file = $data_dir . '/sos_log.json';
$sos_email_instructions_file = $data_dir . '/sos_email_instructions.txt';

$manageable_settings = [
    'LATITUDE', 'LONGITUDE', 'LOG_LEVEL', 'MESHTASTIC_PORT',
    'EMAIL_USER', 'EMAIL_PASS', 'SMTP_SERVER', 'SMTP_PORT', 'IMAP_SERVER', 'IMAP_PORT',
    'TRASH_FOLDER_NAME', 'MAX_EMAIL_BODY_LEN', 'STALE_NODE_MINUTES',
    'POLLING_INTERVAL_MS', 'CHAT_POLLING_INTERVAL_MS',
    'WEATHER_ALERT_INTERVAL_MINS', 'WEATHER_UPDATE_INTERVAL_MINS', 'WEATHER_DATA_MAX_AGE_MINUTES',
    'FORECAST_MORNING_SEND_TIME', 'FORECAST_AFTERNOON_SEND_TIME',
    // New SOS Settings
    'SOS_EMAIL_ENABLED', 'SOS_EMAIL_RECIPIENTS',
    'SOSM_EMAIL_ENABLED', 'SOSM_EMAIL_RECIPIENTS',
    'SOSF_EMAIL_ENABLED', 'SOSF_EMAIL_RECIPIENTS',
    'SOSP_EMAIL_ENABLED', 'SOSP_EMAIL_RECIPIENTS',
    'SOS_ACK_TIMEOUT_MINS', 'SOS_CHECKIN_INTERVAL_MINS', 'SOS_CHECKIN_MAX_ATTEMPTS', 'TEMP_GROUP_TTL_DAYS',
    'AUTO_BACKUP_INTERVAL_HOURS',
    // Rate limiting
    'COMMAND_BURST_LIMIT', 'COMMAND_BURST_WINDOW_SECONDS',
    'EMAIL_RATE_LIMIT_MAX', 'EMAIL_RATE_LIMIT_WINDOW_SECONDS',
    'OUTGOING_EMAIL_QUARANTINE_MAX',
    // Audit retention controls
    'AUDIT_RETENTION_DAYS', 'AUDIT_MAX_ROWS'
];

// --- HELPER FUNCTIONS ---

/**
 * [NEW] Safely reads and decodes a JSON file using a shared lock to prevent race conditions.
 *
 * @param string $file_path The path to the JSON file.
 * @param mixed $default_value The value to return on failure.
 * @return mixed The decoded JSON data as an associative array, or the default value.
 */
function get_locked_json_file($file_path, $default_value = []) {
    if (!is_readable($file_path)) {
        return $default_value;
    }

    $attempts = 3;
    for ($i = 0; $i < $attempts; $i++) {
        $fp = @fopen($file_path, 'r');
        if (!$fp) {
            return $default_value;
        }

        $data = $default_value;
        if (flock($fp, LOCK_SH)) {
            $content = stream_get_contents($fp);
            flock($fp, LOCK_UN);
            if ($content !== false && !empty(trim($content))) {
                $decoded = json_decode($content, true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    fclose($fp);
                    return $decoded;
                }
            } else {
                fclose($fp);
                return $default_value;
            }
        }
        fclose($fp);
        usleep(50000);
    }

    return $default_value;
}

function get_iso_age_seconds($iso_value, $fallback_path = null) {
    if (is_string($iso_value) && $iso_value !== '') {
        try {
            $dt = new DateTime($iso_value);
            return time() - $dt->getTimestamp();
        } catch (Exception $e) {
            // fall through to file mtime
        }
    }
    if ($fallback_path && file_exists($fallback_path)) {
        return time() - filemtime($fallback_path);
    }
    return null;
}

function format_age_string($age_seconds) {
    if ($age_seconds === null) return 'Unknown';
    if ($age_seconds < 60) return $age_seconds . ' seconds ago';
    if ($age_seconds < 3600) return round($age_seconds / 60) . ' minutes ago';
    return round($age_seconds / 3600) . ' hours ago';
}

function legacy_json_count($file_path) {
    $data = get_locked_json_file($file_path, null);
    if ($data === null) {
        return null;
    }
    if (is_array($data) || is_countable($data)) {
        return count($data);
    }
    return null;
}

function write_json_atomic($file_path, $data) {
    $dir = dirname($file_path);
    if (!is_dir($dir)) {
        return false;
    }

    $temp_path = $file_path . '.' . uniqid('tmp', true);
    $bytes = file_put_contents($temp_path, json_encode($data));
    if ($bytes === false) {
        @unlink($temp_path);
        return false;
    }

    if (!rename($temp_path, $file_path)) {
        @unlink($temp_path);
        return false;
    }

    return true;
}

function gb_queue_dispatcher_command($commands_dir, array $command_data, &$queued_filename = '', &$command_id = '') {
    $queue_result = null;
    if (!gb_enqueue_command_job($command_data, 'map.php:webui', '', 5, $queue_result)) {
        return false;
    }
    $command_id = (string)($queue_result['command_id'] ?? '');
    $job_id = intval($queue_result['job_id'] ?? 0);
    $queued_filename = $job_id > 0 ? ('db_job_' . $job_id) : 'db_job';
    return true;
}

function gb_parse_coord($value, $min, $max) {
    $value = trim((string)$value);
    if ($value === '') {
        return null;
    }
    if (!is_numeric($value)) {
        return null;
    }
    $num = floatval($value);
    if ($num < $min || $num > $max) {
        return null;
    }
    return $num;
}

function get_subscribers($file_path) {
    return gb_load_subscribers();
}

function save_subscribers($file_path, $data) {
    ksort($data);
    gb_replace_subscribers($data);
    return true;
}

function get_dispatcher_jobs($file_path) {
    return gb_load_dispatcher_jobs();
}

function save_dispatcher_jobs($file_path, $jobs) {
    if (!is_array($jobs)) {
        $jobs = [];
    }
    gb_replace_dispatcher_jobs(array_values($jobs));
    return true;
}

function get_env_settings($file_path, $whitelist) {
    $env_values = [];
    if (is_readable($file_path)) {
        $lines = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            if (strpos($line, '=') === false) continue;
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            if (in_array($key, $whitelist)) {
                $env_values[$key] = trim($value);
            }
        }
    }
    foreach ($whitelist as $key) {
        if (!array_key_exists($key, $env_values)) {
            $env_values[$key] = '';
        }
    }
    return $env_values;
}
function save_env_settings($file_path, $new_settings, $whitelist) {
    if (!is_readable($file_path) || !is_writable($file_path)) {
        error_log("GuardianBridge Error: .env file is not readable or writable: " . $file_path);
        return false;
    }

    $lines = file($file_path, FILE_IGNORE_NEW_LINES);
    $updated_lines = [];
    $settings_to_update = $new_settings;

    foreach ($lines as $line) {
        $trimmed_line = trim($line);
        if (empty($trimmed_line) || $trimmed_line[0] === '#') {
            $updated_lines[] = $line;
            continue;
        }

        $parts = explode('=', $line, 2);
        $key = trim($parts[0]);

        if (in_array($key, $whitelist) && array_key_exists($key, $settings_to_update)) {
            // Update existing manageable setting
            $updated_lines[] = $key . '=' . $settings_to_update[$key];
            unset($settings_to_update[$key]); // Mark as updated
        } else {
            // Preserve non-manageable setting or comment
            $updated_lines[] = $line;
        }
    }

    // Add any new settings that were not found in the original file
    foreach ($settings_to_update as $key => $value) {
        if (in_array($key, $whitelist)) {
            $updated_lines[] = $key . '=' . $value;
        }
    }

    if (file_put_contents($file_path, implode("\n", $updated_lines)) === false) {
        error_log("GuardianBridge Error: Failed to write to .env file: " . $file_path);
        return false;
    }
    return true;
}
function get_file_age_string($file_path) {
    if (!file_exists($file_path)) return '<span class="text-slate-500">Unknown</span>';
    $age_seconds = time() - filemtime($file_path);
    if ($age_seconds < 60) return $age_seconds . ' seconds ago';
    if ($age_seconds < 3600) return round($age_seconds / 60) . ' minutes ago';
    return round($age_seconds / 3600) . ' hours ago';
}
function get_age_string_from_timestamp($timestamp) {
    if (empty($timestamp)) return '<span class="text-slate-500">Never</span>';
    $age_seconds = time() - $timestamp;
    
    if ($age_seconds < 60) return round($age_seconds) . 's ago';
    if ($age_seconds < 3600) return round($age_seconds / 60) . 'm ago';
    if ($age_seconds < 86400) return round($age_seconds / 3600) . 'h ago';
    return round($age_seconds / 86400) . 'd ago';
}

function gb_audit_map_log($action, $target = '', $details = []) {
    global $audit_actor;
    try {
        gb_log_audit($audit_actor, 'map', $action, $target, $details);
    } catch (Throwable $e) {
        error_log('GuardianBridge Warning: failed to write map audit log: ' . $e->getMessage());
    }
}

function gb_list_auto_backup_files($backup_dir) {
    $pattern = rtrim((string)$backup_dir, "/\\") . '/guardianbridge_db_*.db';
    $paths = glob($pattern);
    if (!is_array($paths) || count($paths) === 0) {
        return [];
    }

    $files = [];
    foreach ($paths as $path) {
        if (!is_file($path) || !is_readable($path)) {
            continue;
        }
        $name = basename((string)$path);
        if (!preg_match('/^guardianbridge_db_\d{8}_\d{6}\.db$/', $name)) {
            continue;
        }
        $files[] = [
            'name' => $name,
            'path' => (string)$path,
            'mtime' => intval(@filemtime($path) ?: 0),
            'size' => intval(@filesize($path) ?: 0),
        ];
    }

    usort($files, function ($a, $b) {
        $a_mtime = intval($a['mtime'] ?? 0);
        $b_mtime = intval($b['mtime'] ?? 0);
        if ($a_mtime === $b_mtime) {
            return strcmp((string)($b['name'] ?? ''), (string)($a['name'] ?? ''));
        }
        return $b_mtime <=> $a_mtime;
    });

    return $files;
}

function gb_find_latest_db_backup($backup_dir) {
    $files = gb_list_auto_backup_files($backup_dir);
    if (count($files) === 0) {
        return '';
    }
    return (string)($files[0]['path'] ?? '');
}

function gb_resolve_auto_backup_selection($backup_dir, $selected_name) {
    $selected_name = trim((string)$selected_name);
    if ($selected_name === '') {
        return '';
    }
    $backup_dir_real = realpath($backup_dir);
    if ($backup_dir_real === false) {
        return '';
    }

    $candidate = $backup_dir_real . DIRECTORY_SEPARATOR . basename($selected_name);
    $candidate_real = realpath($candidate);
    if ($candidate_real === false || !is_file($candidate_real) || !is_readable($candidate_real)) {
        return '';
    }

    $prefix = rtrim($backup_dir_real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if (strpos($candidate_real, $prefix) !== 0) {
        return '';
    }

    if (strtolower(pathinfo($candidate_real, PATHINFO_EXTENSION)) !== 'db') {
        return '';
    }
    return $candidate_real;
}

// --- FORM PROCESSING ---
$message = '';
$error = '';

if (isset($_POST['ajax']) && $_POST['ajax'] === 'true') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'Invalid action.'];

    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $response['message'] = 'Invalid security token.';
        echo json_encode($response);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = $_POST['action'] ?? '';
        if ($action === 'send_broadcast') {
            $text_to_send = $_POST['broadcast_text'] ?? '';
            $forced_target_group = strtoupper(trim((string)($_POST['target_group'] ?? '')));
            $command_data = [];
            $error_message = '';
            
            if (empty(trim($text_to_send))) {
                $error_message = 'Message text cannot be empty.';
            } elseif ($forced_target_group !== '') {
                $message_body = trim((string)$text_to_send);
                if (preg_match('/^@([^\s]+)\s*(.*)$/s', $message_body, $forced_match)) {
                    $forced_mention = strtoupper(trim((string)($forced_match[1] ?? '')));
                    if ($forced_mention === $forced_target_group) {
                        $message_body = (string)($forced_match[2] ?? '');
                    }
                }
                if (trim($message_body) === '') {
                    $error_message = "Direct message has no text. Format: @user/@tag/@all message";
                } else {
                    $command_data = ['command' => 'tagsend', 'tags' => $forced_target_group, 'text' => $message_body];
                }
            } else {
                if (strpos($text_to_send, '@') === 0) {
                    $parts = explode(' ', $text_to_send, 2);
                    $target_str = ltrim($parts[0], '@');
                    $message_body = $parts[1] ?? '';
                    if (empty(trim($message_body))) {
                        $error_message = "Direct message has no text. Format: @user/@tag/@all message";
                    } elseif (strcasecmp($target_str, 'all') === 0) {
                        $command_data = ['command' => 'broadcast_subscribers', 'text' => $message_body];
                    } else {
                        $subscribers = get_subscribers($subscribers_file);
                        $destination_id = null;
                        $target_tag = strtoupper($target_str);
                        $tag_found = false;
                        if (preg_match('/^![a-f0-9]{8}$/', $target_str)) {
                            $destination_id = $target_str;
                        } else {
                            foreach ($subscribers as $node_id => $user_data) {
                                if (isset($user_data['name']) && strcasecmp((string)$user_data['name'], $target_str) === 0) {
                                    $destination_id = $node_id;
                                    break;
                                }
                                $tags = $user_data['tags'] ?? [];
                                if (!$tag_found && is_array($tags)) {
                                    foreach ($tags as $tag) {
                                        if (strtoupper((string)$tag) === $target_tag) {
                                            $tag_found = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if ($destination_id) {
                            $command_data = ['command' => 'dm', 'destinationId' => $destination_id, 'text' => $message_body, 'recipient' => $target_str];
                        } else {
                            if (!$tag_found && gb_temp_group_exists($target_tag)) {
                                $tag_found = true;
                            }
                            if ($tag_found) {
                                $command_data = ['command' => 'tagsend', 'tags' => $target_tag, 'text' => $message_body];
                            } else {
                                $error_message = "User, tag, or node ID '{$target_str}' not found.";
                            }
                        }
                    }
                } else {
                    $command_data = ['command' => 'broadcast', 'text' => $text_to_send];
                }
            }

            if (!empty($command_data)) {
                $queued_file = '';
                $command_id = '';
                if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                    $response['success'] = true;
                    $response['message'] = 'Message sent successfully.';
                    gb_audit_map_log(
                        'send_broadcast_ajax',
                        $command_data['command'] ?? '',
                        [
                            'command' => $command_data['command'] ?? '',
                            'destinationId' => $command_data['destinationId'] ?? '',
                            'recipient' => $command_data['recipient'] ?? '',
                            'tags' => $command_data['tags'] ?? '',
                            'text_len' => strlen((string)($command_data['text'] ?? '')),
                        ]
                    );
                } else {
                    $response['message'] = 'Failed to queue command. Check server logs.';
                    error_log('GuardianBridge Error: Failed to queue command in DB from map send_broadcast.');
                }
            } elseif (!empty($error_message)) {
                $response['message'] = $error_message;
            }
        } elseif ($action === 'get_user') {
            $node_id = trim((string)($_POST['node_id'] ?? ''));
            if ($node_id === '') {
                $response['message'] = 'Node ID is required.';
            } else {
                $subscribers = get_subscribers($subscribers_file);
                if (!isset($subscribers[$node_id])) {
                    $response['success'] = true;
                    $response['exists'] = false;
                    $response['user'] = null;
                    $response['message'] = 'User not found.';
                } else {
                    $user = $subscribers[$node_id];
                    if (is_array($user) && isset($user['password_hash'])) {
                        unset($user['password_hash']);
                    }
                    $response['success'] = true;
                    $response['exists'] = true;
                    $response['user'] = array_merge(['node_id' => $node_id], is_array($user) ? $user : []);
                    $response['message'] = 'User loaded.';
                }
            }
        } elseif ($action === 'update_ops_notes') {
            $node_id = trim((string)($_POST['node_id'] ?? ''));
            if ($node_id === '') {
                $response['message'] = 'Node ID is required.';
            } else {
                $subscribers = get_subscribers($subscribers_file);
                if (!isset($subscribers[$node_id])) {
                    $response['message'] = 'User not found.';
                } else {
                    $ops_notes = trim(strip_tags((string)($_POST['ops_notes'] ?? '')));
                    $subscribers[$node_id]['ops_notes'] = $ops_notes;
                    if (save_subscribers($subscribers_file, $subscribers)) {
                        $response['success'] = true;
                        $response['message'] = 'Ops Notes updated.';
                        $response['ops_notes'] = $ops_notes;
                        gb_audit_map_log(
                            'update_ops_notes_ajax',
                            $node_id,
                            ['ops_notes_len' => strlen($ops_notes)]
                        );
                    } else {
                        $response['message'] = 'Failed to save Ops Notes. Please check server logs.';
                    }
                }
            }
        }
    }
    echo json_encode($response);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['ajax'])) {
    // 1. VERIFY CSRF TOKEN
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Invalid security token. Please refresh the page and try again.";
    } else {
        // 2. Process Actions
        $action = $_POST['action'] ?? '';

        if ($action === 'clear_chat_history') {
            try {
                gb_clear_chat_log();
                $message = "Message history has been cleared successfully.";
            } catch (Throwable $e) {
                $error = "Failed to clear chat history. Please check server logs.";
                error_log("GuardianBridge Error: Failed to clear chat log: " . $e->getMessage());
            }
        }

        if ($action === 'clear_sos_log') {
            try {
                gb_clear_sos_logs();
                $message = "SOS Alert Log has been cleared.";
            } catch (Throwable $e) {
                $error = "Failed to clear SOS log. Please check server logs.";
                error_log("GuardianBridge Error: Failed to clear SOS log: " . $e->getMessage());
            }
        }
        
        if ($action === 'update_sos_instructions') {
            $instructions_content = $_POST['sos_instructions_content'] ?? '';
                if (@file_put_contents($sos_email_instructions_file, $instructions_content) !== false) {
                    $message = "SOS email instructions updated successfully.";
                } else {
                    $error = "Failed to update SOS instructions file. Please check file permissions on the /opt/GuardianBridge/data/ 
directory.";
                    error_log("GuardianBridge Error: Failed to write to " . $sos_email_instructions_file);
                }
        }

        if ($action === 'admin_clear_sos') {
            $node_id_to_clear = $_POST['node_id'] ?? null;
            if ($node_id_to_clear) {
                $command_data = [
                    'command' => 'admin_clear_sos',
                    'node_id' => $node_id_to_clear
                ];
                $queued_file = '';
                $command_id = '';
                if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                    $message = "Admin command to clear SOS for node " . htmlspecialchars($node_id_to_clear) . " has been queued.";
                } else {
                    $error = 'Failed to queue admin clear command. Please check server logs.';
                    error_log('GuardianBridge Error: Failed to queue admin_clear_sos in DB from map.');
                }
            } else {
                $error = "No active SOS node ID was provided for the admin clear command.";
            }
        }

        if ($action === 'update_user') {
            $node_id = $_POST['node_id'];
            $subscribers = get_subscribers($subscribers_file);
            if (isset($subscribers[$node_id])) {
                $subscribers[$node_id]['name'] = trim(strip_tags($_POST['name']));
                $subscribers[$node_id]['full_name'] = trim(strip_tags($_POST['full_name']));
                $subscribers[$node_id]['role'] = trim(strip_tags($_POST['role']));
                $subscribers[$node_id]['email'] = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
                $subscribers[$node_id]['phone_1'] = trim(strip_tags($_POST['phone_1']));
                $subscribers[$node_id]['phone_2'] = trim(strip_tags($_POST['phone_2']));
                $subscribers[$node_id]['notes'] = trim(strip_tags($_POST['notes']));
                $subscribers[$node_id]['ops_notes'] = trim(strip_tags($_POST['ops_notes'] ?? ''));
                $subscribers[$node_id]['poc_info'] = trim(strip_tags($_POST['poc_info']));
                $subscribers[$node_id]['sos_notify'] = trim(strip_tags($_POST['sos_notify']));

                if (!isset($subscribers[$node_id]['address']) || !is_array($subscribers[$node_id]['address'])) {
                    $subscribers[$node_id]['address'] = [];
                }
                $subscribers[$node_id]['address']['street'] = trim(strip_tags($_POST['address_street']));
                $subscribers[$node_id]['address']['city'] = trim(strip_tags($_POST['address_city']));
                $subscribers[$node_id]['address']['state'] = trim(strip_tags($_POST['address_state']));
                $subscribers[$node_id]['address']['zip'] = trim(strip_tags($_POST['address_zip']));
                $address_lat = gb_parse_coord($_POST['address_lat'] ?? '', -90, 90);
                $address_lon = gb_parse_coord($_POST['address_lon'] ?? '', -180, 180);
                $subscribers[$node_id]['address_lat'] = $address_lat !== null ? $address_lat : '';
                $subscribers[$node_id]['address_lon'] = $address_lon !== null ? $address_lon : '';
                $subscribers[$node_id]['use_address_coords'] = isset($_POST['use_address_coords']) && $address_lat !== null && $address_lon !== null;

                if (isset($_POST['tags'])) {
                    $tags_raw = trim(strip_tags($_POST['tags']));
                    $tags_array = array_filter(array_map('trim', explode(',', $tags_raw)));
                    $subscribers[$node_id]['tags'] = array_values(array_unique(array_map('strtoupper', $tags_array)));
                    sort($subscribers[$node_id]['tags']);
                } else {
                    $subscribers[$node_id]['tags'] = [];
                }

                $subscribers[$node_id]['alerts'] = isset($_POST['alerts']);
                $subscribers[$node_id]['weather'] = isset($_POST['weather']);
                $subscribers[$node_id]['scheduled_daily_forecast'] = isset($_POST['scheduled_daily_forecast']);
                $subscribers[$node_id]['email_send'] = isset($_POST['email_send']);
                $subscribers[$node_id]['email_receive'] = isset($_POST['email_receive']);
                $subscribers[$node_id]['emailbroadcast'] = isset($_POST['emailbroadcast']);
                $subscribers[$node_id]['node_tag_send'] = isset($_POST['node_tag_send']);
                $subscribers[$node_id]['blocked'] = isset($_POST['blocked']); 
                $password = $_POST['password'] ?? '';
                $password_confirm = $_POST['password_confirm'] ?? '';
                if ($password !== '' || $password_confirm !== '') {
                    if ($password !== $password_confirm) {
                        $error = 'Passwords do not match.';
                    } else {
                        $subscribers[$node_id]['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
                    }
                }

                if (!$error) {
                    if (save_subscribers($subscribers_file, $subscribers)) {
                        $message = "User '" . htmlspecialchars($subscribers[$node_id]['name']) . "' updated successfully.";
                    } else {
                        $error = "Failed to update user. Please check server logs.";
                    }
                }
            }
        }

        if ($action === 'add_user') {
            $node_id = trim($_POST['new_node_id']);
            if (preg_match('/^![a-f0-9]{8}$/', $node_id)) {
                $subscribers = get_subscribers($subscribers_file);
                if (!isset($subscribers[$node_id])) {
                    $password = $_POST['new_password'] ?? '';
                    $password_confirm = $_POST['new_password_confirm'] ?? '';
                    if ($password === '' || $password_confirm === '') {
                        $error = "Password is required for new users.";
                    } elseif ($password !== $password_confirm) {
                        $error = "Passwords do not match.";
                    } else {
                        $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    }
                    if ($error) {
                        // stop processing
                    } else {
                    $subscribers[$node_id] = [
                        "name" => trim(strip_tags($_POST['new_name'])),
                        "full_name" => "", "role" => "", "email" => "",
                        "address" => ["street" => "", "city" => "", "state" => "", "zip" => ""],
                        "address_lat" => "", "address_lon" => "", "use_address_coords" => false,
                        "phone_1" => "", "phone_2" => "", "notes" => "", "ops_notes" => "",
                        "poc_info" => "", "sos_notify" => "", // <-- ADD THIS LINE
                        "alerts" => true, "weather" => true, "scheduled_daily_forecast" => true,
                        "email_send" => false, "email_receive" => false, "emailbroadcast" => false,
                        "node_tag_send" => false, "blocked" => false, "tags" => [],
                        "password_hash" => $password_hash
                    ];
                    if (save_subscribers($subscribers_file, $subscribers)) {
                        $message = "User '$node_id' added successfully.";
                    } else {
                        $error = "Failed to add user. Please check server logs.";
                    }
                    }
                } else {
                    $error = "User '$node_id' already exists.";
                }
            } else {
                $error = "Invalid Node ID format. Must be like '!a1b2c3d4'.";
            }
        }

        if ($action === 'clear_user_password') {
            $node_id = $_POST['node_id'] ?? '';
            $subscribers = get_subscribers($subscribers_file);
            if (isset($subscribers[$node_id])) {
                $subscribers[$node_id]['password_hash'] = '';
                if (save_subscribers($subscribers_file, $subscribers)) {
                    $message = "Password cleared for '$node_id'.";
                } else {
                    $error = "Failed to clear user password. Please check server logs.";
                }
            } else {
                $error = "User '$node_id' not found.";
            }
        }

        if ($action === 'delete_user') {
            $node_id = $_POST['node_id'];
            $subscribers = get_subscribers($subscribers_file);
            if (isset($subscribers[$node_id])) {
                unset($subscribers[$node_id]);
                if (save_subscribers($subscribers_file, $subscribers)) {
                    $message = "User '$node_id' deleted successfully.";
                } else {
                    $error = "Failed to delete user. Please check server logs.";
                }
            }
        }

        if ($action === 'save_broadcast_job') {
            $jobs = get_dispatcher_jobs($dispatcher_file);
            $job_index = $_POST['job_index'];

            if (isset($jobs[$job_index])) {
                $content = trim(strip_tags($_POST['content']));
                if (isset($_POST['with_bell']) && $_POST['with_bell'] === 'true') {
                    $content = "\x07" . $content;
                }

                $new_job = [
                    'name' => trim(strip_tags($_POST['name'])),
                    'content' => $content,
                    'interval_mins' => max(1, (int)$_POST['interval_mins']),
                    'enabled' => isset($_POST['enabled']) 
                ];

                $job_type = $_POST['job_type'] ?? 'recurring';
                if ($job_type === 'recurring') {
                    $new_job['days'] = $_POST['days'] ?? [];
                    $new_job['start_time'] = trim(strip_tags($_POST['start_time']));
                    $new_job['stop_time'] = trim(strip_tags($_POST['stop_time']));
                } else { // event
                    $new_job['start_datetime'] = trim(strip_tags($_POST['start_datetime']));
                    $new_job['stop_datetime'] = trim(strip_tags($_POST['stop_datetime']));
                }

                if (isset($jobs[$job_index]['last_sent'])) {
                    $new_job['last_sent'] = $jobs[$job_index]['last_sent'];
                }

                $jobs[$job_index] = $new_job;
                
                if (save_dispatcher_jobs($dispatcher_file, $jobs)) {
                    $message = "Broadcast job '" . htmlspecialchars($new_job['name']) . "' updated successfully.";
                } else {
                    $error = "Failed to save broadcast jobs. Please check server logs.";
                }
            } else {
                $error = "Invalid job index for update.";
            }
        }

        if ($action === 'add_broadcast_job') {
            $jobs = get_dispatcher_jobs($dispatcher_file);
            $new_job_name = trim(strip_tags($_POST['new_broadcast_name']));
            if (!empty($new_job_name)) {
                $name_exists = false;
                foreach ($jobs as $job) {
                    if (isset($job['name']) && strtolower($job['name']) === strtolower($new_job_name)) {
                        $name_exists = true;
                        break;
                    }
                }

                if (!$name_exists) {
                    $jobs[] = [
                        "name" => $new_job_name,
                        "content" => "Default content for {$new_job_name}. Please edit.",
                        "interval_mins" => 60,
                        "days" => ["MON", "TUE", "WED", "THU", "FRI"],
                        "start_time" => "08:00", "stop_time" => "17:00", "last_sent" => null,
                        "enabled" => false
                    ];
                    if (save_dispatcher_jobs($dispatcher_file, $jobs)) {
                        $message = "Broadcast job '" . htmlspecialchars($new_job_name) . "' added. Click 'More...' to edit details.";                    } else {
                        $error = "Failed to add broadcast job. Please check server logs.";
                    }
                } else {
                    $error = "A broadcast job with that name already exists.";
                }
            } else {
                $error = "Broadcast name cannot be empty.";
            }
        }

        if ($action === 'delete_broadcast_job') {
            $jobs = get_dispatcher_jobs($dispatcher_file);
            $job_index = $_POST['job_index'];
            if (isset($jobs[$job_index])) {
                $job_name = $jobs[$job_index]['name'] ?? 'Untitled Job';
                unset($jobs[$job_index]);
                if (save_dispatcher_jobs($dispatcher_file, $jobs)) {
                    $message = "Broadcast job '" . htmlspecialchars($job_name) . "' deleted successfully.";
                } else {
                    $error = "Failed to delete broadcast job. Please check server logs.";
                }
            } else {
                $error = "Invalid job index for deletion.";
            }
        }

        if ($action === 'update_settings') {
            $new_settings = $_POST['settings'] ?? []; // Default to empty array

            $checkbox_keys = ['SOS_EMAIL_ENABLED', 'SOSM_EMAIL_ENABLED', 'SOSF_EMAIL_ENABLED', 'SOSP_EMAIL_ENABLED'];
            foreach ($checkbox_keys as $key) {
                if (!isset($new_settings[$key])) {
                    $new_settings[$key] = 'False';
                }
            }

            if (isset($new_settings['EMAIL_PASS']) && $new_settings['EMAIL_PASS'] === '********') {
                $current_settings = get_env_settings($env_file, $manageable_settings);
                $new_settings['EMAIL_PASS'] = $current_settings['EMAIL_PASS'];
            }

            if (save_env_settings($env_file, $new_settings, $manageable_settings)) {
                $prune_note = 'Audit retention apply was skipped due to an internal error.';
                try {
                    $retention_days = isset($new_settings['AUDIT_RETENTION_DAYS']) ? max(0, intval($new_settings['AUDIT_RETENTION_DAYS'])) : null;
                    $max_rows = isset($new_settings['AUDIT_MAX_ROWS']) ? max(0, intval($new_settings['AUDIT_MAX_ROWS'])) : null;
                    $prune_result = gb_prune_audit_logs($retention_days, $max_rows);
                    $prune_note = "Audit retention applied (age-pruned: "
                        . intval($prune_result['deleted_by_age'] ?? 0)
                        . ", count-pruned: " . intval($prune_result['deleted_by_count'] ?? 0)
                        . ", remaining: " . intval($prune_result['remaining'] ?? 0)
                        . ").";
                } catch (Throwable $e) {
                    error_log("GuardianBridge Warning: post-settings audit prune failed: " . $e->getMessage());
                }

                $message = "Settings updated successfully. " . $prune_note . " You must restart the dispatcher service from the terminal for changes to take effect.";
            } else {
                $error = "Failed to save settings. Please check server logs.";
            }
        }

        if ($action === 'update_auto_backup_interval') {
            $interval_raw = trim((string)($_POST['auto_backup_interval_hours'] ?? ''));
            if ($interval_raw === '' || !preg_match('/^\d+$/', $interval_raw)) {
                $error = "Auto backup interval must be a whole number of hours (0 or greater).";
            } else {
                $interval_hours = max(0, intval($interval_raw));
                if (save_env_settings($env_file, ['AUTO_BACKUP_INTERVAL_HOURS' => (string)$interval_hours], ['AUTO_BACKUP_INTERVAL_HOURS'])) {
                    $message = "Auto backup interval updated to {$interval_hours} hour(s). Set to 0 to disable scheduled auto backup. Restart dispatcher for changes to take effect.";
                } else {
                    $error = "Failed to update auto backup interval. Please check server logs.";
                }
            }
        }

        if ($action === 'run_weather_fetcher') {
            $queued_file = '';
            $command_id = '';
            $command_data = [
                'command' => 'run_weather_fetcher',
                'requested_by_panel' => 'map',
                'requested_by_actor' => $audit_actor,
                'requested_at' => gmdate('c'),
            ];
            if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                $message = "Weather fetcher command queued as " . htmlspecialchars($queued_file) . " (ID: " . htmlspecialchars($command_id) . ").";
            } else {
                $error = "Failed to queue weather fetcher command.";
            }
        }

        if ($action === 'run_email_processor') {
            $queued_file = '';
            $command_id = '';
            $command_data = [
                'command' => 'run_email_processor',
                'requested_by_panel' => 'map',
                'requested_by_actor' => $audit_actor,
                'requested_at' => gmdate('c'),
            ];
            if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                $message = "Email processor command queued as " . htmlspecialchars($queued_file) . " (ID: " . htmlspecialchars($command_id) . ").";
            } else {
                $error = "Failed to queue email processor command.";
            }
        }

        if ($action === 'clear_email_queue') {
            try {
                gb_clear_outgoing_emails();
                $message = "Outgoing email queue has been cleared.";
            } catch (Throwable $e) {
                $error = "Failed to clear email queue. Please check server logs.";
                error_log("GuardianBridge Error: Failed to clear outgoing emails: " . $e->getMessage());
            }
        }

        if ($action === 'clear_email_quarantine') {
            try {
                gb_clear_outgoing_emails_quarantine();
                $message = "Outgoing email quarantine has been cleared.";
            } catch (Throwable $e) {
                $error = "Failed to clear email quarantine. Please check server logs.";
                error_log("GuardianBridge Error: Failed to clear outgoing email quarantine: " . $e->getMessage());
            }
        }

        if ($action === 'requeue_dead_letter_command') {
            $dead_letter_id = intval($_POST['dead_letter_id'] ?? 0);
            if ($dead_letter_id <= 0) {
                $error = "No dead-letter item selected for requeue.";
            } else {
                $result = null;
                if (gb_requeue_command_dead_letter($dead_letter_id, $commands_dir, $result)) {
                    $queued_file = htmlspecialchars((string)($result['queued_file'] ?? 'unknown'));
                    $message = "Dead-letter command requeued as {$queued_file}.";
                } else {
                    $why = htmlspecialchars((string)($result['error'] ?? 'unknown error'));
                    $error = "Failed to requeue dead-letter command: {$why}";
                }
            }
        }

        if ($action === 'delete_dead_letter_command') {
            $dead_letter_id = intval($_POST['dead_letter_id'] ?? 0);
            if ($dead_letter_id <= 0) {
                $error = "No dead-letter item selected for deletion.";
            } else {
                $result = null;
                if (gb_delete_command_dead_letter_with_file($dead_letter_id, $commands_dir, $result)) {
                    $message = "Dead-letter command deleted.";
                } else {
                    $why = htmlspecialchars((string)($result['error'] ?? 'unknown error'));
                    $error = "Failed to delete dead-letter command: {$why}";
                }
            }
        }

        if ($action === 'clear_dead_letter_commands') {
            try {
                gb_clear_command_dead_letters();
                $message = "Dead-letter queue table has been cleared.";
            } catch (Throwable $e) {
                $error = "Failed to clear dead-letter queue.";
                error_log("GuardianBridge Error: Failed to clear dead-letter queue: " . $e->getMessage());
            }
        }

        if ($action === 'export_email_quarantine') {
            try {
                $export_data = gb_export_outgoing_emails_quarantine();
                gb_audit_map_log('export_email_quarantine', 'outgoing_email_quarantine', ['count' => count($export_data)]);
                header('Content-Type: application/json');
                header('Content-Disposition: attachment; filename="outgoing_email_quarantine.json"');
                echo json_encode($export_data, JSON_PRETTY_PRINT);
                exit;
            } catch (Throwable $e) {
                $error = "Failed to export email quarantine. Please check server logs.";
                error_log("GuardianBridge Error: Failed to export outgoing email quarantine: " . $e->getMessage());
            }
        }

        if ($action === 'export_audit_log_json' || $action === 'export_audit_log_csv') {
            try {
                $requested_panel = strtolower(trim((string)($_POST['audit_panel'] ?? '')));
                $panel_filter = ($requested_panel === 'map' || $requested_panel === 'mop') ? $requested_panel : '';
                $limit = max(1, min(10000, intval($_POST['audit_limit'] ?? 2000)));
                $export_rows = gb_export_audit_logs($limit, $panel_filter, '');
                $target = ($panel_filter !== '') ? $panel_filter : 'all';

                gb_audit_map_log(
                    'export_audit_log',
                    $target,
                    ['format' => ($action === 'export_audit_log_csv' ? 'csv' : 'json'), 'count' => count($export_rows), 'limit' => $limit]
                );

                if ($action === 'export_audit_log_csv') {
                    header('Content-Type: text/csv');
                    header('Content-Disposition: attachment; filename="guardianbridge_audit_log.csv"');
                    $out = fopen('php://output', 'w');
                    fputcsv($out, ['id', 'created_at_unix', 'created_at_iso', 'actor', 'panel', 'action', 'target', 'details_json']);
                    foreach ($export_rows as $row) {
                        fputcsv($out, [
                            intval($row['id'] ?? 0),
                            intval($row['created_at'] ?? 0),
                            (string)($row['created_at_iso'] ?? ''),
                            (string)($row['actor'] ?? ''),
                            (string)($row['panel'] ?? ''),
                            (string)($row['action'] ?? ''),
                            (string)($row['target'] ?? ''),
                            json_encode($row['details'] ?? [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                        ]);
                    }
                    fclose($out);
                } else {
                    header('Content-Type: application/json');
                    header('Content-Disposition: attachment; filename="guardianbridge_audit_log.json"');
                    echo json_encode($export_rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                }
                exit;
            } catch (Throwable $e) {
                $error = "Failed to export audit log. Please check server logs.";
                error_log("GuardianBridge Error: Failed to export audit log: " . $e->getMessage());
            }
        }

        if ($action === 'db_maintenance') {
            $task = $_POST['maintenance_action'] ?? '';
            try {
                if ($task === 'integrity_check') {
                    $result = gb_db_integrity_check();
                    $message = "SQLite integrity check result: " . htmlspecialchars($result);
                } elseif ($task === 'wal_checkpoint') {
                    $result = gb_db_wal_checkpoint();
                    $message = "SQLite WAL checkpoint complete (" . htmlspecialchars($result) . ").";
                } elseif ($task === 'audit_prune') {
                    $prune_result = gb_prune_audit_logs();
                    $message = "Audit retention prune complete (age-pruned: "
                        . intval($prune_result['deleted_by_age'] ?? 0)
                        . ", count-pruned: " . intval($prune_result['deleted_by_count'] ?? 0)
                        . ", remaining: " . intval($prune_result['remaining'] ?? 0) . ").";
                } elseif ($task === 'backup_db') {
                    $backup_dir = $base_dir . '/AutoBackUp';
                    if (!is_dir($backup_dir) && !@mkdir($backup_dir, 0775, true)) {
                        $error = "Could not create AutoBackUp directory at " . htmlspecialchars($backup_dir) . ".";
                    } else {
                        $queued_file = '';
                        $command_id = '';
                        $command_data = [
                            'command' => 'maintenance_backup_db',
                            'requested_by_panel' => 'map',
                            'requested_by_actor' => $audit_actor,
                            'requested_at' => gmdate('c'),
                        ];
                        if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                            $message = "Database backup command queued as " . htmlspecialchars($queued_file) . " (ID: " . htmlspecialchars($command_id) . ").";
                        } else {
                            $error = "Failed to queue database backup command.";
                        }
                    }
                } elseif ($task === 'restore_db') {
                    $backup_dir = $base_dir . '/AutoBackUp';
                    if (!is_dir($backup_dir) && !@mkdir($backup_dir, 0775, true)) {
                        $error = "Could not create AutoBackUp directory at " . htmlspecialchars($backup_dir) . ".";
                    } else {
                        $selected_backup_name = trim((string)($_POST['restore_backup_file'] ?? ''));
                        $selected_backup_path = gb_resolve_auto_backup_selection($backup_dir, $selected_backup_name);
                        $uploaded_backup_path = '';

                        if (isset($_FILES['restore_backup_upload']) && is_array($_FILES['restore_backup_upload'])) {
                            $upload_error = intval($_FILES['restore_backup_upload']['error'] ?? UPLOAD_ERR_NO_FILE);
                            if ($upload_error !== UPLOAD_ERR_NO_FILE) {
                                if ($upload_error !== UPLOAD_ERR_OK) {
                                    $error = "Uploaded restore file failed to upload (error code {$upload_error}).";
                                } else {
                                    $upload_name = basename((string)($_FILES['restore_backup_upload']['name'] ?? 'uploaded.db'));
                                    $upload_ext = strtolower(pathinfo($upload_name, PATHINFO_EXTENSION));
                                    if ($upload_ext !== 'db') {
                                        $error = "Uploaded restore file must be a .db file.";
                                    } else {
                                        $target_name = 'uploaded_restore_' . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.db';
                                        $target_path = rtrim($backup_dir, "/\\") . '/' . $target_name;
                                        if (!@move_uploaded_file((string)($_FILES['restore_backup_upload']['tmp_name'] ?? ''), $target_path)) {
                                            $error = "Failed to store uploaded restore file on the server.";
                                        } else {
                                            $uploaded_backup_path = $target_path;
                                        }
                                    }
                                }
                            }
                        }

                        $restore_source = $uploaded_backup_path !== '' ? $uploaded_backup_path : $selected_backup_path;
                        if ($restore_source === '') {
                            $restore_source = gb_find_latest_db_backup($backup_dir);
                        }
                        if ($restore_source === '') {
                            $error = "No DB backups found in " . htmlspecialchars($backup_dir) . ". Create an AutoBackUp backup first or upload a local .db file.";
                        }
                    }

                    if ($error === '') {
                        $queued_file = '';
                        $command_id = '';
                        $source_name = basename($restore_source);
                        $cleanup_source = (strpos($source_name, 'uploaded_restore_') === 0);
                        $command_data = [
                            'command' => 'maintenance_restore_db',
                            'source_db_path' => $restore_source,
                            'cleanup_source' => $cleanup_source,
                            'requested_by_panel' => 'map',
                            'requested_by_actor' => $audit_actor,
                            'requested_at' => gmdate('c'),
                        ];
                        if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                            $message = "Database restore command queued from " . htmlspecialchars($source_name) . " as " . htmlspecialchars($queued_file) . " (ID: " . htmlspecialchars($command_id) . ").";
                        } else {
                            $error = "Failed to queue database restore command.";
                        }
                    }
                } elseif ($task === 'vacuum') {
                    $queued_file = '';
                    $command_id = '';
                    $command_data = [
                        'command' => 'maintenance_vacuum_db',
                        'requested_by_panel' => 'map',
                        'requested_by_actor' => $audit_actor,
                        'requested_at' => gmdate('c'),
                    ];
                    if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                        $message = "SQLite VACUUM command queued as " . htmlspecialchars($queued_file) . " (ID: " . htmlspecialchars($command_id) . ").";
                    } else {
                        $error = "Failed to queue SQLite VACUUM command.";
                    }
                } else {
                    $error = "Unknown maintenance action requested.";
                }
            } catch (Throwable $e) {
                $error = "Database maintenance failed. Please check server logs.";
                error_log("GuardianBridge Error: DB maintenance failed: " . $e->getMessage());
            }
        }

        if (empty($error) && $action !== '') {
            $target = '';
            $details = [];
            if ($action === 'update_user' || $action === 'clear_user_password' || $action === 'delete_user') {
                $target = (string)($_POST['node_id'] ?? '');
            } elseif ($action === 'add_user') {
                $target = (string)($_POST['new_node_id'] ?? '');
            } elseif ($action === 'admin_clear_sos') {
                $target = (string)($_POST['node_id'] ?? '');
            } elseif ($action === 'save_broadcast_job' || $action === 'delete_broadcast_job') {
                $target = (string)($_POST['job_index'] ?? '');
            } elseif ($action === 'add_broadcast_job') {
                $target = (string)($_POST['new_broadcast_name'] ?? '');
            } elseif ($action === 'db_maintenance') {
                $target = (string)($_POST['maintenance_action'] ?? '');
            } elseif ($action === 'requeue_dead_letter_command' || $action === 'delete_dead_letter_command') {
                $target = (string)($_POST['dead_letter_id'] ?? '');
            } elseif ($action === 'clear_dead_letter_commands') {
                $target = 'all';
            } elseif ($action === 'update_auto_backup_interval') {
                $target = (string)($_POST['auto_backup_interval_hours'] ?? '');
            }
            if ($action === 'update_settings') {
                $details['settings_count'] = count($_POST['settings'] ?? []);
            }
            gb_audit_map_log($action, $target, $details);
        }
    }
}


// --- DATA FOR DISPLAY ---
$queue_preview_limit = 25;
$dead_letter_preview_limit = 25;
$audit_preview_limit = 30;
$settings = get_env_settings($env_file, $manageable_settings);
$auto_backup_dir = $base_dir . '/AutoBackUp';
$auto_backup_files = gb_list_auto_backup_files($auto_backup_dir);
$gateway_lat = $settings['LATITUDE'] ?? 30.0000;
$gateway_lon = $settings['LONGITUDE'] ?? -90.0000;
$node_statuses = [];
$subscribers = [];
$dispatcher_jobs = get_dispatcher_jobs($dispatcher_file);
$weather_current = get_locked_json_file($weather_current_file, []);
$weather_alerts = get_locked_json_file($weather_alerts_file, []);
$outgoing_emails = gb_load_outgoing_emails($queue_preview_limit);
$outgoing_quarantine = gb_load_outgoing_emails_quarantine($queue_preview_limit);
$failed_dms = gb_load_failed_dm_queue($queue_preview_limit);
$command_dead_letters = gb_load_command_dead_letters($dead_letter_preview_limit);
$recent_audit_entries = gb_load_audit_logs($audit_preview_limit);
$outgoing_email_count = count($outgoing_emails);
$outgoing_quarantine_count = count($outgoing_quarantine);
$failed_dm_count = count($failed_dms);
$command_dead_letter_count = count($command_dead_letters);
$dispatcher_status = get_locked_json_file($dispatcher_status_file, null);
$dispatcher_status = is_array($dispatcher_status) ? $dispatcher_status : [];
$dispatcher_metrics = is_array($dispatcher_status['metrics'] ?? null) ? $dispatcher_status['metrics'] : [];
$weather_data_max_age_minutes = intval($settings['WEATHER_DATA_MAX_AGE_MINUTES'] ?? 120);
$weather_age_seconds = get_iso_age_seconds($weather_current['timestamp'] ?? null, $weather_current_file);
$weather_is_stale = $weather_age_seconds !== null && $weather_age_seconds > ($weather_data_max_age_minutes * 60);
$weather_age_label = format_age_string($weather_age_seconds);
$weather_station_id = $weather_current['station_id'] ?? null;
$legacy_counts = [
    'dispatcher_jobs.json' => legacy_json_count($dispatcher_file),
    'outgoing_emails.json' => legacy_json_count($outgoing_email_file),
    'failed_dm_queue.json' => legacy_json_count($failed_dm_queue_file),
];
$db_counts = [
    'dispatcher_jobs' => count($dispatcher_jobs),
    'outgoing_emails' => count($outgoing_emails),
    'failed_dm_queue' => count($failed_dms),
];
$legacy_files_exist = false;
$legacy_present = false;
foreach ($legacy_counts as $count) {
    if ($count !== null) {
        $legacy_files_exist = true;
    }
    if (is_int($count) && $count > 0) {
        $legacy_present = true;
    }
}
$db_has_data = ($db_counts['dispatcher_jobs'] > 0) || ($db_counts['outgoing_emails'] > 0) || ($db_counts['failed_dm_queue'] > 0);
$migration_ok = $legacy_present ? $db_has_data : true;
$days_of_week = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
$sos_instructions_content = is_readable($sos_email_instructions_file) ? file_get_contents($sos_email_instructions_file) : '';
$active_sos_node_id = null;

$setting_descriptions = [
    'LATITUDE' => 'The geographical latitude of the gateway (e.g., 40.7128). Required for fetching accurate local weather data.',
    'LONGITUDE' => 'The geographical longitude of the gateway (e.g., -74.0060). Required for fetching accurate local weather data.',
    'LOG_LEVEL' => 'Controls logging detail. Recommended: INFO, DEBUG, WARNING, or ERROR. DEBUG is most verbose.',
    'SERVER_NAME' => 'Server identity shown by the mesh hello/hi command response.',
    'SERVER_VERSION' => 'Server software version shown by the mesh hello/hi command response.',
    'MESHTASTIC_PORT' => "Device path for the Meshtastic radio (e.g., /dev/ttyUSB0). Set to 'None' for auto-detection.",
    'EMAIL_USER' => 'The full email address for the gateway (e.g., your-gateway@gmail.com).',
    'EMAIL_PASS' => 'The 16-character "App Password" for the email account, not your main password.',
    'SMTP_SERVER' => 'SMTP server for outgoing emails (e.g., smtp.gmail.com).',
    'SMTP_PORT' => 'SMTP server port, typically 587 (STARTTLS).',
    'IMAP_SERVER' => 'IMAP server for incoming emails (e.g., imap.gmail.com).',
    'IMAP_PORT' => 'IMAP server port, almost always 993 for SSL/TLS.',
    'TRASH_FOLDER_NAME' => 'The exact name of the trash folder on your email server (e.g., "[Gmail]/Trash").',
    'MAX_EMAIL_BODY_LEN' => 'Max characters for an email body sent from the mesh. Recommended: ~180.',
    'STALE_NODE_MINUTES' => 'Minutes before a node is marked stale in the Live Node List.',
    'POLLING_INTERVAL_MS' => 'Status/map polling interval in milliseconds. Recommended: 5000+.',
    'CHAT_POLLING_INTERVAL_MS' => 'Chat polling interval in milliseconds. Recommended: 1000+.',
    'WEATHER_ALERT_INTERVAL_MINS' => 'How often, in minutes, to re-broadcast an ongoing NWS alert. Recommended: 15-30.',
    'WEATHER_UPDATE_INTERVAL_MINS' => 'How often, in minutes, to broadcast current weather conditions. Recommended: 30-60.',
    'WEATHER_DATA_MAX_AGE_MINUTES' => 'Max age (minutes) before weather data is marked stale or skipped.',
    'FORECAST_MORNING_SEND_TIME' => 'Time to broadcast the morning forecast (24-hour format, e.g., 07:00).',
    'FORECAST_AFTERNOON_SEND_TIME' => 'Time to broadcast the afternoon forecast (24-hour format, e.g., 16:30).',
    'COMMAND_BURST_LIMIT' => 'Max commands per sender within the burst window. Set to 0 to disable burst limiting.',
    'COMMAND_BURST_WINDOW_SECONDS' => 'Burst window size in seconds for command limiting.',
    'COMMAND_FILE_READ_ATTEMPTS' => 'How many times to retry parsing queued command JSON files before dead-letter quarantine.',
    'COMMAND_FILE_READ_BASE_DELAY_MS' => 'Initial retry delay in milliseconds for command-file JSON parse backoff.',
    'COMMAND_FILE_READ_MAX_DELAY_MS' => 'Maximum retry delay in milliseconds for command-file JSON parse backoff.',
    'COMMAND_RECEIPT_TTL_HOURS' => 'Hours to retain processed command receipts for duplicate suppression. Older receipts are pruned.',
    'EMAIL_RATE_LIMIT_MAX' => 'Max inbound emails per sender within the email window. Set to 0 to disable email limiting.',
    'EMAIL_RATE_LIMIT_WINDOW_SECONDS' => 'Email rate limit window size in seconds.',
    'OUTGOING_EMAIL_QUARANTINE_MAX' => 'Max rows retained in the outgoing email quarantine table (invalid email rows).',
    'AUDIT_RETENTION_DAYS' => 'Delete audit rows older than this many days. Set to 0 to disable age-based pruning.',
    'AUDIT_MAX_ROWS' => 'Hard cap for audit rows. Oldest rows are removed when exceeded. Set to 0 to disable count-based pruning.',
    // New SOS Descriptions
    'SOS_EMAIL_ENABLED' => 'Enable email notifications for general (SOS) alerts.',
    'SOS_EMAIL_RECIPIENTS' => 'Comma-separated list of emails to receive general SOS alerts.',
    'SOSM_EMAIL_ENABLED' => 'Enable email notifications for Medical (SOSM) alerts.',
    'SOSM_EMAIL_RECIPIENTS' => 'Comma-separated list of emails to receive Medical SOS alerts.',
    'SOSF_EMAIL_ENABLED' => 'Enable email notifications for Fire (SOSF) alerts.',
    'SOSF_EMAIL_RECIPIENTS' => 'Comma-separated list of emails to receive Fire SOS alerts.',
    'SOSP_EMAIL_ENABLED' => 'Enable email notifications for Police (SOSP) alerts.',
    'SOSP_EMAIL_RECIPIENTS' => 'Comma-separated list of emails to receive Police SOS alerts.',
    'SOS_ACK_TIMEOUT_MINS' => 'Minutes to wait for a responder ACK before broadcasting an SOS alert network-wide.',
    'SOS_CHECKIN_INTERVAL_MINS' => 'Minutes between automated check-in pings to a user in an active SOS.',
    'SOS_CHECKIN_MAX_ATTEMPTS' => 'Number of unanswered check-in pings before escalating an SOS to "UNRESPONSIVE".',
    'TEMP_GROUP_TTL_DAYS' => 'Temporary group expiry window in days since last activity (join/leave/send). Default: 14.',
    'AUTO_BACKUP_INTERVAL_HOURS' => 'How many hours between automatic DB backups to /opt/GuardianBridge/AutoBackUp. Set to 0 to disable.'
];
?>
<!DOCTYPE html>
<html lang="en" class="bg-[#131314]">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GuardianBridge Admin Panel</title>
    <link rel="icon" type="image/x-icon" href="/map-items/map-logo.ico">
    <script src="/map-items/tailwindcss.js"></script>
    <link href="/map-items/inter-font.css" rel="stylesheet">
    <link rel="stylesheet" href="/map-items/leaflet.css"/>
    <script src="/map-items/leaflet.js"></script>    
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #131314; }
        .tab-button { position: relative; transition: color 0.2s; cursor: pointer; }
        .tab-button.active { color: #E3E3E3; }
        .tab-button:not(.active) { color: #8E918F; }
        .tab-button.active::after { content: ''; position: absolute; bottom: -1px; left: 0; right: 0; height: 3px; background-image: 
linear-gradient(to right, #89B3F8, #A58AFB, #F485A5); }
        input[type="text"], input[type="email"], input[type="number"], input[type="time"], input[type="datetime-local"], input[type="password"], select, textarea { background-color: #1E1F20; border: 1px solid #3C4043; color: #E3E3E3; padding: 0.6rem 0.85rem; border-radius: 0.5rem; width: 100%; transition: all 0.2s; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: #89B3F8; box-shadow: 0 0 0 2px rgba(137, 179, 248, 0.3); }
        input::placeholder, textarea::placeholder { color: #8E918F; }
        input[type="checkbox"] { background-color: #3C4043; border-color: #8E918F; border-radius: 4px; }
        input[type="checkbox"]:checked { background-image: linear-gradient(to right, #89B3F8, #A58AFB); border-color: transparent; }
        .btn { padding: 9px 18px; border-radius: 8px; font-weight: 600; transition: all 0.2s; cursor: pointer; border: 1px solid transparent; }
        .btn-sm { padding: 5px 10px; font-size: 0.875rem; }
        .btn-primary { background-color: #89B3F8; color: #131314; }
        .btn-primary:hover { background-color: #A58AFB; }
        .btn-secondary { background-color: #3C4043; color: #E3E3E3; }
        .btn-secondary:hover { background-color: #525355; }
        .btn-red { background-color: #F28B82; color: #131314; }
        .btn-red:hover { background-color: #F485A5; }
        .btn-green { background-color: #81C995; color: #131314; }
        .btn-green:hover { background-color: #A5D6A7; }
        .status-ok { color: #81C995; }
        .status-fail { color: #F28B82; }
        .status-warn { color: #FDD663; }
        .card { background-color: #1E1F20; border-radius: 0.75rem; border: 1px solid #3C4043; }
        
        /* Modal z-index fix */
        #dm-chat-modal, #user-edit-modal, #broadcast-edit-modal, #confirm-action-modal { z-index: 1050; }

        #map { height: 500px; border-radius: 0.75rem; border: 1px solid #3C4043; background-color: #3C4043; }
        .leaflet-popup-content-wrapper, .leaflet-popup-tip { background: #1E1F20; color: #E3E3E3; border: 1px solid #525355; box-shadow: 0 3px 14px rgba(0,0,0,0.4); }
        .leaflet-tile-pane { filter: none; }
        .map-node-label { background-color: rgba(30, 31, 32, 0.8); color: #E3E3E3; border: 1px solid #525355; padding: 2px 5px; border-radius: 4px; white-space: nowrap; }
        .popup-hr { border-color: #3C4043; margin-top: 6px; margin-bottom: 6px; }
        .ops-notes-editor { margin-top: 8px; }
        .ops-notes-input {
            width: 100%;
            min-height: 78px;
            resize: vertical;
            background-color: #131314;
            border: 1px solid #3C4043;
            color: #E3E3E3;
            border-radius: 6px;
            padding: 0.5rem 0.6rem;
            font-size: 0.8rem;
            line-height: 1.35;
        }
        .ops-notes-input:focus {
            outline: none;
            border-color: #89B3F8;
            box-shadow: 0 0 0 2px rgba(137, 179, 248, 0.2);
        }
        .ops-notes-actions {
            margin-top: 6px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .ops-notes-save-btn {
            border: 1px solid #3C4043;
            background: #2a2b2d;
            color: #E3E3E3;
            border-radius: 6px;
            padding: 0.25rem 0.6rem;
            font-size: 0.75rem;
            cursor: pointer;
        }
        .ops-notes-save-btn:hover { background: #34363a; }
        .ops-notes-save-btn:disabled { opacity: 0.65; cursor: default; }
        .ops-notes-status { font-size: 0.75rem; color: #8E918F; }
        .ops-notes-status.ok { color: #81C995; }
        .ops-notes-status.err { color: #F28B82; }

        /* --- Chat Theme (Restored) --- */
        #chat-messages-container, #dm-chat-messages-container { display: flex; flex-direction: column; gap: 0.75rem; }
        .message { max-width: 80%; padding: 0.35rem 1rem; border-radius: 0.75rem; position: relative; border: 1px solid transparent; 
}
        .message-incoming { align-self: flex-start; border-top-left-radius: 0; border-left: 3px solid #89B3F8; background: linear-gradient(135deg, rgba(137, 179, 248, 0.1), rgba(137, 179, 248, 0.03)); border-color: rgba(137, 179, 248, 0.15); }
        .message-outgoing { align-self: flex-end; border-bottom-right-radius: 0; border-right: 3px solid #A58AFB; background: linear-gradient(135deg, rgba(165, 138, 251, 0.1), rgba(165, 138, 251, 0.03)); border-color: rgba(165, 138, 251, 0.15); }
        .message-system { align-self: center; max-width: 90%; text-align: center; background: rgba(227, 227, 227, 0.05); border: 1px 
dashed #525355; color: #8E918F; font-size: 0.9rem; font-style: italic; padding: 0.5rem 1rem; }
        .message-content { word-break: break-word; white-space: pre-wrap; line-height: 1.3; }
        .message-meta { font-size: 0.75rem; line-height: 1.1; color: #8E918F; margin-top: 0.2rem; }
        .message-username { font-weight: 600; line-height: 1.1; margin-bottom: 0.2rem; }
        .message-incoming .message-username { color: #89B3F8; }
        .message-outgoing .message-username { color: #A58AFB; }

        /* --- SOS BANNER --- */
        @keyframes flash-red { 0%, 100% { background-color: #dc2626; } 50% { background-color: #ef4444; } }
        #sos-banner { animation: flash-red 1s infinite; }
        /* Styles for content loaded from help.html */
        .help-content h2 { font-size: 1.5rem; font-weight: bold; color: #E3E3E3; border-bottom: 1px solid #3C4043; padding-bottom: 0.5rem; margin-top: 2rem; }
        .help-content h3 { font-size: 1.25rem; font-weight: bold; color: #E3E3E3; margin-top: 1.5rem; }
        .help-content h4 { font-size: 1.1rem; font-weight: bold; color: #89B3F8; margin-top: 1.5rem; }
        .help-content ul { list-style-type: disc; padding-left: 2rem; }
        .help-content ol { list-style-type: decimal; padding-left: 2rem; }
        .help-content li { margin-bottom: 0.5rem; }
        .help-content code { background-color: #3C4043; color: #F485A5; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; }
        .help-content pre { background-color: #131314; border: 1px solid #3C4043; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
        .help-content pre code { background-color: transparent; padding: 0; }
        .help-content table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        .help-content th, .help-content td { border: 1px solid #3C4043; padding: 0.75rem; text-align: left; }
        .help-content th { background-color: #2a2b2d; }
        .help-content a { color: #89B3F8; text-decoration: none; }
        .help-content a:hover { text-decoration: underline; }
    </style>
</head>
<body class="text-slate-300 p-4 md:p-8">
    <?php if ($is_default_admin_password): ?>
        <div class="bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 px-4 py-3 rounded-lg mb-6 text-center">
            <strong>Security warning:</strong> The admin password is still the default. Update it in <code class="bg-yellow-400/10 text-yellow-200 px-1 py-0.5 rounded text-sm">.env</code>.
        </div>
    <?php endif; ?>
    <div id="sos-banner" style="display: none;" class="fixed top-0 left-0 w-full text-white text-center p-3 z-[1100] font-bold text-lg flex justify-between items-center">
        <span id="sos-banner-text" class="flex-grow text-center"></span>
        <button id="sos-banner-close" class="text-white text-3xl font-bold px-4 leading-none">&times;</button>
    </div>
    
    <div class="max-w-7xl mx-auto">
        <header class="mb-10 flex justify-between items-center">
            <div class="flex items-center gap-4">
                <img src="/map-items/map-logo.png" alt="Gateway Logo" class="h-14 w-12">
                <div>
                    <h1 class="text-4xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-red-400 bg-clip-text text-transparent">GuardianBridge Control</h1>
                    <p class="text-slate-400 mt-1">Administrator Panel for GuardianBridge</p>
                </div>
            </div>
            <div><a href="?logout=true" class="btn btn-secondary">Logout</a></div>
        </header>

        <?php if ($message): ?>
            <div class="bg-green-500/10 border border-green-500/20 text-green-300 px-4 py-3 rounded-lg relative mb-6 flex justify-between items-start" role="alert">
                <div><?= $message ?></div>
                <button class="ml-4 -mt-1 -mr-1 text-2xl text-green-300/60 hover:text-green-300" onclick="this.parentElement.style.display='none'">&times;</button>
            </div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="bg-red-500/10 border border-red-500/20 text-red-300 px-4 py-3 rounded-lg relative mb-6 flex justify-between items-start" role="alert">
                <div><?= htmlspecialchars($error) ?></div>
                <button class="ml-4 -mt-1 -mr-1 text-2xl text-red-300/60 hover:text-red-300" onclick="this.parentElement.style.display='none'">&times;</button>
            </div>
        <?php endif; ?>

        <div class="flex border-b border-slate-700/50 mb-6">
            <a data-tab="status" class="tab-button py-3 px-6 font-medium active">Status</a>
            <a data-tab="chat" class="tab-button py-3 px-6 font-medium">Chat</a>
            <a data-tab="actions" class="tab-button py-3 px-6 font-medium">Actions</a>
            <a data-tab="broadcasts" class="tab-button py-3 px-6 font-medium">Broadcasts</a>
            <a data-tab="users" class="tab-button py-3 px-6 font-medium">Users</a>
            <a data-tab="settings" class="tab-button py-3 px-6 font-medium">Settings</a>
            <a data-tab="help" class="tab-button py-3 px-6 font-medium">Help/About</a>
        </div>

        <main>
            <div id="status-content" class="tab-content">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="card p-6" id="system-health-card">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">System Health</h2>
                        <div class="space-y-4 text-slate-300" id="system-health-body">
                            <?php
                                $status_age_seconds = get_iso_age_seconds($dispatcher_status['last_update'] ?? null, $dispatcher_status_file);
                                $dispatcher_live = ($status_age_seconds !== null && $status_age_seconds <= 120);
                                if ($dispatcher_live) {
                                    echo '<p class="flex items-center"><span class="font-bold status-ok mr-3 text-lg">●</span> Dispatcher Service is ACTIVE</p>';
                                } else {
                                    echo '<p class="flex items-center"><span class="font-bold status-fail mr-3 text-lg">●</span> Dispatcher Service is INACTIVE or 
FAILED</p>';
                                }
                                $dispatcher_restart_count = intval($dispatcher_metrics['service_restart_count'] ?? 0);
                                $dispatcher_result = trim((string)($dispatcher_metrics['service_result'] ?? 'unknown'));
                                $dispatcher_sub_state = trim((string)($dispatcher_metrics['service_sub_state'] ?? 'unknown'));
                                $dispatcher_exec_code = trim((string)($dispatcher_metrics['service_exec_code'] ?? 'n/a'));
                                $dispatcher_exec_status = trim((string)($dispatcher_metrics['service_exec_status'] ?? 'n/a'));
                                $service_meta_available = (
                                    $dispatcher_restart_count > 0 ||
                                    $dispatcher_result !== 'unknown' ||
                                    $dispatcher_sub_state !== 'unknown' ||
                                    $dispatcher_exec_code !== 'n/a' ||
                                    $dispatcher_exec_status !== 'n/a'
                                );
                                if ($service_meta_available) {
                                    $restart_class = ($dispatcher_restart_count > 0) ? 'status-warn' : 'status-ok';
                                    $exec_class = ($dispatcher_exec_code === '0') ? 'status-ok' : 'status-warn';
                                    echo '<p class="flex items-center"><span class="font-bold ' . $restart_class . ' mr-3 text-lg">&#9679;</span> Restarts: '
                                        . $dispatcher_restart_count . ' | Result: ' . htmlspecialchars($dispatcher_result)
                                        . ' | SubState: ' . htmlspecialchars($dispatcher_sub_state) . '</p>';
                                    echo '<p class="flex items-center"><span class="font-bold ' . $exec_class . ' mr-3 text-lg">&#9679;</span> Exec: code='
                                        . htmlspecialchars($dispatcher_exec_code) . ' status=' . htmlspecialchars($dispatcher_exec_status) . '</p>';
                                }
                                $radio_ok = $dispatcher_status['radio_connected'] ?? false;
                                echo '<p class="flex items-center"><span class="font-bold ' . ($radio_ok ? 'status-ok' : 'status-fail') . ' mr-3 text-lg">●</span> 
Radio Connection Status</p>';
                                $weather_lastrun_age = file_exists($weather_fetcher_lastrun_file) ? time() - filemtime($weather_fetcher_lastrun_file) : 9999;
                                echo '<p class="flex items-center"><span class="font-bold ' . ($weather_lastrun_age < 1800 ? 'status-ok' : 'status-warn') . ' mr-3 
text-lg">●</span> Weather Fetcher Cron (Last run: ' . get_file_age_string($weather_fetcher_lastrun_file) . ')</p>';
                                $email_lastrun_age = file_exists($email_processor_lastrun_file) ? time() - filemtime($email_processor_lastrun_file) : 9999;
                                echo '<p class="flex items-center"><span class="font-bold ' . ($email_lastrun_age < 600 ? 'status-ok' : 'status-warn') . ' mr-3 text-lg">●</span> Email Processor Cron (Last run: ' . get_file_age_string($email_processor_lastrun_file) . ')</p>';
                            ?>
                        </div>
                    </div>
                    <div class="card p-6" id="weather-card">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Weather & Alerts</h2>
                        <div>
                            <h3 class="font-semibold text-lg text-blue-400">Current Weather</h3>
                            <p class="text-slate-300 mt-1">
                                Temp: <span class="font-medium text-slate-100"><?= htmlspecialchars($weather_current['temperature_f'] ?? 'N/A') ?>°F</span>,
                                Humidity: <span class="font-medium text-slate-100"><?= htmlspecialchars($weather_current['humidity'] ?? 'N/A') ?>% RH</span>
                            </p>
                            <p class="text-xs mt-2 <?= $weather_is_stale ? 'text-red-400' : 'text-slate-500' ?>">
                                Updated: <?= htmlspecialchars($weather_age_label) ?>
                                <?php if ($weather_station_id): ?>
                                    <span class="text-slate-600">· Station <?= htmlspecialchars($weather_station_id) ?></span>
                                <?php endif; ?>
                                <?php if ($weather_is_stale): ?>
                                    <span class="ml-2 font-semibold">STALE</span>
                                <?php endif; ?>
                            </p>
                        </div>
                        <div class="mt-4">
                            <h3 class="font-semibold text-lg text-yellow-400">Active NWS Alerts</h3>
                            <?php if (!empty($weather_alerts)): ?>
                                <p class="text-slate-300 mt-1"><?= htmlspecialchars($weather_alerts[0]['headline'] ?? 'N/A') ?></p>
                            <?php else: ?>
                                <p class="text-slate-500 mt-1">No active alerts.</p>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <div id="map" class="mt-6"></div>

                <div class="card p-6 mt-6">
                    <h2 class="text-2xl font-bold mb-4 text-slate-100">Live Node List (<span id="node-list-count">...</span>)</h2>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left min-w-[600px]">
                            <thead class="bg-black/20 border-b-2 border-slate-700/50">
                                <tr>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Node ID / Name</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Last Contact</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">SNR</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Hops</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Role</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Position</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="node-list-body" class="divide-y divide-slate-700/50">
                                <tr><td colspan="7" class="p-8 text-center text-slate-500">Loading live node data...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div id="chat-content" class="tab-content" style="display: none;">
                <div class="card flex flex-col h-[70vh]">
                    <h2 class="text-2xl font-bold text-slate-100 p-6 border-b border-slate-700/50 flex justify-between items-center">                        <span>Channel Traffic</span>
                        <div class="flex items-center gap-4">
                            <div class="flex items-center gap-x-3 text-sm text-slate-400">
                                <label class="flex items-center gap-2 cursor-pointer"><input type="checkbox" id="show-dms-checkbox" class="filter-checkbox h-4 w-4"> DMs</label>
                                <label class="flex items-center gap-2 cursor-pointer"><input type="checkbox" id="show-sms-checkbox" class="filter-checkbox h-4 w-4"> Server Msgs</label>
                            </div>
                        </div>
                    </h2>
                    <div class="px-6 pt-4 pb-2 border-b border-slate-700/50 bg-black/10">
                        <div id="chat-group-tabs" class="flex flex-wrap gap-2"></div>
                        <p id="chat-group-caption" class="mt-2 text-xs text-slate-500">Manual `@user`, `@tag`, or `@all` still overrides the selected group.</p>
                    </div>
                    <div id="chat-window" class="flex-grow p-6 overflow-y-auto">
                        <div class="space-y-4" id="chat-messages-container">
                            <div class="text-center text-slate-500 py-16"><p>Loading messages...</p></div>
                        </div>
                    </div>
                    <div class="p-4 border-t border-slate-700/50">
                        <div id="chat-form" class="flex items-center gap-2">
                            <textarea id="main-chat-textarea" rows="2" placeholder="Type message, @user, or @all ..." class="flex-grow resize-none"></textarea>
                            <button type="button" id="main-chat-bell-btn" class="btn btn-secondary">Bell</button>
                            <button type="button" id="main-chat-send-btn" class="btn btn-primary">Send</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="actions-content" class="tab-content" style="display: none;">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="card p-6">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Manual Actions</h2>
                        <div class="flex flex-col sm:flex-row gap-4">
                            <form method="POST"><input type="hidden" name="action" value="run_weather_fetcher"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>"><button type="submit" class="btn btn-secondary w-full sm:w-auto">Fetch 
Weather Now</button></form>
                            <form method="POST"><input type="hidden" name="action" value="run_email_processor"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>"><button type="submit" class="btn btn-secondary w-full sm:w-auto">Process Emails Now</button></form>
                            <form method="POST" id="clear-chat-history-form">
                                <input type="hidden" name="action" value="clear_chat_history">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red w-full sm:w-auto">Clear Message History</button>
                            </form>
                        </div>
                    </div>
                    <div class="card p-6">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Outgoing Email Queue (<?= intval($outgoing_email_count) ?>)</h2>                        <?php if (!empty($outgoing_emails)): ?>
                            <?php if (count($outgoing_emails) >= $queue_preview_limit): ?>
                                <p class="text-slate-500 text-xs mb-2">Showing latest <?= count($outgoing_emails) ?> entries for fast page load.</p>
                            <?php endif; ?>
                            <div class="space-y-2 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                                <?php foreach($outgoing_emails as $email): ?>
                                    <div class="bg-black/20 p-3 rounded text-sm">
                                        <span class="font-medium text-slate-300">To:</span> <span class="text-slate-400"><?= htmlspecialchars($email['recipient']) 
?></span><br>
                                        <span class="font-medium text-slate-300">Subject:</span> <span class="text-slate-400"><?= htmlspecialchars($email['subject']) 
?></span>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <form method="POST" class="mt-4" id="clear-email-queue-form">
                                <input type="hidden" name="action" value="clear_email_queue">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red">Clear Queue</button>
                            </form>
                        <?php else: ?>
                            <p class="text-slate-500">The outgoing email queue is empty.</p>
                        <?php endif; ?>
                    </div>
                    <div class="card p-6 md:col-span-2">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Outgoing Email Quarantine (<?= intval($outgoing_quarantine_count) ?>)</h2>
                        <?php if (!empty($outgoing_quarantine)): ?>
                            <?php if (count($outgoing_quarantine) >= $queue_preview_limit): ?>
                                <p class="text-slate-500 text-xs mb-2">Showing latest <?= count($outgoing_quarantine) ?> entries for fast page load.</p>
                            <?php endif; ?>
                            <div class="space-y-2 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                                <?php foreach($outgoing_quarantine as $email): ?>
                                    <div class="bg-black/20 p-3 rounded text-sm">
                                        <span class="font-medium text-slate-300">Reason:</span> <span class="text-slate-400"><?= htmlspecialchars($email['reason'] ?? 'unknown') ?></span><br>
                                        <span class="font-medium text-slate-300">Queued:</span> <span class="text-slate-400"><?= htmlspecialchars(date("Y-m-d H:i:s", $email['created_at'] ?? time())) ?></span><br>
                                        <span class="font-medium text-slate-300">To:</span> <span class="text-slate-400"><?= htmlspecialchars($email['recipient'] ?? '') ?></span><br>
                                        <span class="font-medium text-slate-300">Subject:</span> <span class="text-slate-400"><?= htmlspecialchars($email['subject'] ?? '') ?></span>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <form method="POST" class="mt-4" id="clear-email-quarantine-form">
                                <input type="hidden" name="action" value="clear_email_quarantine">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red">Clear Quarantine</button>
                            </form>
                            <form method="POST" class="mt-2" id="export-email-quarantine-form">
                                <input type="hidden" name="action" value="export_email_quarantine">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-secondary">Export Quarantine JSON</button>
                            </form>
                            <p class="text-slate-500 text-xs mt-2">Export includes recipient addresses and message metadata.</p>
                        <?php else: ?>
                            <p class="text-slate-500">The quarantine is empty.</p>
                        <?php endif; ?>
                    </div>
                    <div class="card p-6 md:col-span-2">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Queued Direct Messages (<?= intval($failed_dm_count) ?>)</h2>
                        <?php if (!empty($failed_dms)): ?>
                            <?php if (count($failed_dms) >= $queue_preview_limit): ?>
                                <p class="text-slate-500 text-xs mb-2">Showing latest <?= count($failed_dms) ?> entries for fast page load.</p>
                            <?php endif; ?>
                            <div class="space-y-2 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                                <?php foreach($failed_dms as $dm): ?>
                                    <div class="bg-black/20 p-3 rounded text-sm">
                                        <span class="font-medium text-slate-300">To:</span> <span class="text-slate-400 font-mono"><?= htmlspecialchars($dm['destination_id']) ?></span><br>
                                        <span class="font-medium text-slate-300">Queued:</span> <span class="text-slate-400"><?= htmlspecialchars(date("Y-m-d H:i:s",
strtotime($dm['timestamp']))) ?></span><br>
                                        <span class="font-medium text-slate-300">Text:</span> <span class="text-slate-400"><?= htmlspecialchars($dm['text']) ?></span>                       
            </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <p class="text-slate-500">The direct message queue is empty.</p>
                        <?php endif; ?>
                    </div>
                    <div class="card p-6 md:col-span-2">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Command Dead-Letter Queue (<?= intval($command_dead_letter_count) ?>)</h2>
                        <?php if (!empty($command_dead_letters)): ?>
                            <?php if (count($command_dead_letters) >= $dead_letter_preview_limit): ?>
                                <p class="text-slate-500 text-xs mb-2">Showing latest <?= count($command_dead_letters) ?> entries for fast page load.</p>
                            <?php endif; ?>
                            <div class="space-y-2 max-h-72 overflow-y-auto border border-slate-700 rounded-md p-3">
                                <?php foreach($command_dead_letters as $row): ?>
                                    <?php
                                        $details = is_array($row['details'] ?? null) ? $row['details'] : [];
                                        $detail_parts = [];
                                        foreach ($details as $k => $v) {
                                            if (!is_scalar($v) || $v === '') { continue; }
                                            $detail_parts[] = $k . '=' . $v;
                                            if (count($detail_parts) >= 4) { break; }
                                        }
                                    ?>
                                    <div class="bg-black/20 p-3 rounded text-xs">
                                        <div class="text-slate-300">
                                            <span class="font-mono text-slate-400"><?= htmlspecialchars(date('Y-m-d H:i:s', intval($row['created_at'] ?? 0))) ?></span>
                                            <span class="mx-2 text-slate-500">|</span>
                                            <span class="font-semibold"><?= htmlspecialchars($row['reason'] ?? 'unknown') ?></span>
                                        </div>
                                        <div class="text-slate-400 mt-1">
                                            Source: <span class="font-mono"><?= htmlspecialchars($row['source_file'] ?? '') ?></span>
                                            <span class="mx-1 text-slate-500">|</span>
                                            ID: <span class="font-mono"><?= htmlspecialchars($row['command_id'] ?? '') ?></span>
                                        </div>
                                        <?php if (!empty($detail_parts)): ?>
                                            <div class="text-slate-500 mt-1"><?= htmlspecialchars(implode(' | ', $detail_parts)) ?></div>
                                        <?php endif; ?>
                                        <div class="flex gap-2 mt-2">
                                            <form method="POST">
                                                <input type="hidden" name="action" value="requeue_dead_letter_command">
                                                <input type="hidden" name="dead_letter_id" value="<?= intval($row['id'] ?? 0) ?>">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                                <button type="submit" class="btn btn-secondary btn-sm">Requeue</button>
                                            </form>
                                            <form method="POST">
                                                <input type="hidden" name="action" value="delete_dead_letter_command">
                                                <input type="hidden" name="dead_letter_id" value="<?= intval($row['id'] ?? 0) ?>">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                                <button type="submit" class="btn btn-red btn-sm">Delete</button>
                                            </form>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <form method="POST" class="mt-4" id="clear-dead-letter-queue-form">
                                <input type="hidden" name="action" value="clear_dead_letter_commands">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red">Clear Dead-Letter Table</button>
                            </form>
                            <p class="text-slate-500 text-xs mt-2">Requeue creates a new queued command with a fresh command ID so duplicate suppression does not block retries.</p>
                        <?php else: ?>
                            <p class="text-slate-500">No dead-letter command rows.</p>
                        <?php endif; ?>
                    </div>
                    <div class="card p-6 md:col-span-2">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Blocked Email Senders</h2>
                        <div id="blocklist-container" class="space-y-2 mb-4 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                            <p class="text-slate-500">Loading blocklist...</p>
                        </div>
                        <form id="add-to-blocklist-form" class="flex items-center gap-4">
                            <input type="email" id="new-blocked-email" placeholder="email-to-block@example.com" required class="flex-grow">
                            <button type="submit" class="btn btn-primary">Add to Blocklist</button>
                        </form>
                    </div>
                    <div class="card p-6 md:col-span-2">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Recent Audit Activity (<?= count($recent_audit_entries) ?>)</h2>
                        <?php if (count($recent_audit_entries) >= $audit_preview_limit): ?>
                            <p class="text-slate-500 text-xs mb-2">Showing latest <?= count($recent_audit_entries) ?> entries for fast page load.</p>
                        <?php endif; ?>
                        <p class="text-slate-400 text-sm mb-3">Scope: all audit events.</p>
                        <div class="flex flex-wrap items-end gap-2 mb-4">
                            <form method="POST" class="flex flex-wrap items-end gap-2">
                                <input type="hidden" name="action" value="export_audit_log_json">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <label class="text-xs text-slate-400">
                                    Panel
                                    <select name="audit_panel" class="mt-1 min-w-[120px]">
                                        <option value="">All</option>
                                        <option value="map">MAP only</option>
                                        <option value="mop">MOP only</option>
                                    </select>
                                </label>
                                <label class="text-xs text-slate-400">
                                    Max rows
                                    <input type="number" name="audit_limit" value="2000" min="1" max="10000" class="mt-1 w-28">
                                </label>
                                <button type="submit" class="btn btn-secondary">Export JSON</button>
                            </form>
                            <form method="POST" class="flex flex-wrap items-end gap-2">
                                <input type="hidden" name="action" value="export_audit_log_csv">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <label class="text-xs text-slate-400">
                                    Panel
                                    <select name="audit_panel" class="mt-1 min-w-[120px]">
                                        <option value="">All</option>
                                        <option value="map">MAP only</option>
                                        <option value="mop">MOP only</option>
                                    </select>
                                </label>
                                <label class="text-xs text-slate-400">
                                    Max rows
                                    <input type="number" name="audit_limit" value="2000" min="1" max="10000" class="mt-1 w-28">
                                </label>
                                <button type="submit" class="btn btn-secondary">Export CSV</button>
                            </form>
                        </div>
                        <?php if (!empty($recent_audit_entries)): ?>
                            <div class="space-y-2 max-h-72 overflow-y-auto border border-slate-700 rounded-md p-3">
                                <?php foreach ($recent_audit_entries as $entry): ?>
                                    <?php
                                    $detail_parts = [];
                                    if (is_array($entry['details'] ?? null)) {
                                        foreach (($entry['details'] ?? []) as $k => $v) {
                                            if (!is_scalar($v) || $v === '') { continue; }
                                            $detail_parts[] = $k . '=' . $v;
                                            if (count($detail_parts) >= 4) { break; }
                                        }
                                    }
                                    ?>
                                    <div class="bg-black/20 p-3 rounded text-xs">
                                        <div class="text-slate-300">
                                            <span class="font-mono text-slate-400"><?= htmlspecialchars(date('Y-m-d H:i:s', intval($entry['created_at'] ?? 0))) ?></span>
                                            <span class="mx-2 text-slate-500">|</span>
                                            <span class="font-semibold"><?= htmlspecialchars($entry['actor'] ?? 'unknown') ?></span>
                                            <span class="mx-1 text-slate-500">[<?= htmlspecialchars($entry['panel'] ?? '-') ?>]</span>
                                            <span><?= htmlspecialchars($entry['action'] ?? '-') ?></span>
                                            <?php if (!empty($entry['target'])): ?>
                                                <span class="mx-1 text-slate-500">-&gt;</span><span class="font-mono"><?= htmlspecialchars($entry['target']) ?></span>
                                            <?php endif; ?>
                                        </div>
                                        <?php if (!empty($detail_parts)): ?>
                                            <div class="text-slate-500 mt-1"><?= htmlspecialchars(implode(' | ', $detail_parts)) ?></div>
                                        <?php endif; ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <p class="text-slate-500">No audit events recorded yet.</p>
                        <?php endif; ?>
                    </div>
                    <div class="card p-6 md:col-span-2">
                        <div class="flex justify-between items-center mb-4">
                            <h2 class="text-2xl font-bold text-red-400">SOS Incident Command</h2>
                             <div class="flex items-center gap-4">
                                <form method="POST" id="admin-clear-sos-form" class="inline-block">
                                    <input type="hidden" name="action" value="admin_clear_sos">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                    <input type="hidden" name="node_id" value="">
                                    <button type="submit" class="btn btn-secondary" disabled title="No active SOS detected.">Admin Clear Active SOS</button>
                                </form>
                                <a href="/map-items/api_download_sos_log.php" class="btn btn-secondary" download>SOS Log Download</a>
                            </div>
                        </div>
                        <p class="text-slate-400 mb-4 text-sm">This is a live, filtered list of nodes actively sending or responding to an SOS event.</p>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left min-w-[600px]">
                                <thead class="bg-black/20 border-b-2 border-slate-700/50">
                                    <tr>
                                        <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Node ID / Name</th>
                                        <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Last Contact</th>
                                        <th class="p-3 font-semibold text-sm text-slate-400 uppercase">SNR</th>
                                        <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Hops</th>
                                        <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Role</th>
                                        <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Position</th>
                                        <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="sos-node-list-body" class="divide-y divide-slate-700/50">
                                    <tr><td colspan="7" class="p-8 text-center text-slate-500">Loading live SOS data...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <div id="broadcasts-content" class="tab-content" style="display: none;">
                <div class="card overflow-x-auto">
                    <div class="p-6"><h2 class="text-2xl font-bold text-slate-100">Manage Custom Broadcasts</h2></div>
                    <table class="w-full text-left min-w-[1000px]">
                        <thead class="bg-black/20 border-b-2 border-slate-700/50">
                            <tr>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Status</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Broadcast Name</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Active Days</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Interval</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Time / Date Window</th>                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-700/50">
                            <?php if (!empty($dispatcher_jobs)): foreach ($dispatcher_jobs as $index => $job): 
                                // Add index to job data for the modal
                                $job['job_index'] = $index;
                            ?>
                            <tr class="hover:bg-black/20">
                                <td class="p-4">
                                    <?php $enabled = $job['enabled'] ?? false; ?>
                                    <span class="flex items-center">
                                        <span class="font-bold <?= $enabled ? 'status-ok' : 'text-slate-500' ?> mr-2 text-lg">●</span>
                                        <?= $enabled ? 'Enabled' : 'Disabled' ?>
                                    </span>
                            </td>
                            <td class="p-4 font-medium"><?= htmlspecialchars($job['name'] ?? 'N/A') ?></td>
                                <td class="p-4 font-mono text-sm">
                                    <?php
                                    if (isset($job['days'])) {
                                        foreach ($days_of_week as $day) {
                                            $is_active = in_array($day, $job['days']);
                                            $char = substr($day, 0, 1);
                                            echo '<span class="' . ($is_active ? 'text-blue-400' : 'text-slate-600') . '">' . $char . '</span> ';
                                        }
                                    } else {
                                        echo '<span class="text-slate-500">Event</span>';
                                    }
                                    ?>
                                </td>
                                <td class="p-4"><?= htmlspecialchars($job['interval_mins'] ?? 'N/A') ?> mins</td>
                                <td class="p-4">
                                    <?php 
                                    if (isset($job['start_datetime'])) {
                                        echo htmlspecialchars($job['start_datetime']) . ' to ' . htmlspecialchars($job['stop_datetime']);
                                    } else {
                                        echo htmlspecialchars($job['start_time'] ?? 'N/A') . ' - ' . htmlspecialchars($job['stop_time'] ?? 'N/A');
                                    }
                                    ?>
                                </td>
                                <td class="p-4">
                                    <button type="button" class="btn btn-secondary text-sm open-broadcast-edit-modal" data-job-data="<?= htmlspecialchars(json_encode($job), ENT_QUOTES, 'UTF-8') ?>">
                                        More...
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; else: ?>
                                <tr><td colspan="5" class="p-8 text-center text-slate-500">No custom broadcast jobs found.</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                <div class="mt-8 pt-6 border-t border-slate-700/50">
                    <h3 class="text-xl font-bold mb-4 text-slate-100">Add New Broadcast</h3>
                    <form method="POST" class="card p-6 flex flex-wrap items-end gap-4">
                        <input type="hidden" name="action" value="add_broadcast_job">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <div class="flex-grow">
                            <label for="new_broadcast_name">New Broadcast Name</label>
                            <input type="text" id="new_broadcast_name" name="new_broadcast_name" placeholder="E.g., Daily Weather Summary" required>
                        </div>
                        <div>
                            <button type="submit" class="btn btn-primary">Add Broadcast</button>
                        </div>
                    </form>
                </div>
            </div>

            <div id="users-content" class="tab-content" style="display: none;">
                <div class="card overflow-x-auto">
                    <div class="p-6"><h2 class="text-2xl font-bold text-slate-100">Manage Subscribers</h2></div>
                    <table class="w-full text-left min-w-[1000px]">
                        <thead class="bg-black/20 border-b-2 border-slate-700/50">
                            <tr>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Node ID</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Username</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Role</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Full Name</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Phone 1</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Tags</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="map-users-table-body" class="divide-y divide-slate-700/50">
                            <tr><td colspan="7" class="p-8 text-center text-slate-500">Loading subscribers...</td></tr>
                        </tbody>
                    </table>
                </div>
                <div class="mt-8 pt-6 border-t border-slate-700/50">
                    <h3 class="text-xl font-bold mb-4 text-slate-100">Add New Subscriber</h3>
                    <form method="POST" class="card p-6 flex flex-wrap items-end gap-4">
                        <input type="hidden" name="action" value="add_user">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <div>
                            <label for="new_node_id">Node ID</label>
                            <input type="text" id="new_node_id" name="new_node_id" placeholder="!a1b2c3d4" required class="font-mono">
                        </div>
                        <div>
                            <label for="new_name">Username</label>
                            <input type="text" id="new_name" name="new_name" placeholder="New User" required>
                        </div>
                        <div>
                            <label for="new_password">Password</label>
                            <input type="password" id="new_password" name="new_password" required>
                        </div>
                        <div>
                            <label for="new_password_confirm">Confirm Password</label>
                            <input type="password" id="new_password_confirm" name="new_password_confirm" required>
                        </div>
                        <div>
                            <button type="submit" class="btn btn-primary">Add User</button>
                        </div>
                    </form>
                </div>
            </div>

            <div id="settings-content" class="tab-content" style="display: none;">
                <div class="card p-6 mb-6" id="metrics-card">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-2xl font-bold text-slate-100">System Metrics</h2>
                        <button type="button" class="btn btn-secondary btn-sm collapse-toggle" data-target="metrics-card-body" aria-expanded="true">Collapse</button>
                    </div>
                    <div class="space-y-2 text-slate-300" id="metrics-card-body">
                        <div id="metrics-body">
                            <p class="text-slate-500">Loading metrics...</p>
                        </div>
                    </div>
                </div>
                <div class="card p-6 mb-6" id="queue-status-card">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-2xl font-bold text-slate-100">Queue Status</h2>
                        <button type="button" class="btn btn-secondary btn-sm collapse-toggle" data-target="queue-status-card-body" aria-expanded="true">Collapse</button>
                    </div>
                    <div id="queue-status-card-body">
                        <div class="text-slate-300 space-y-2">
                            <div>DB `dispatcher_jobs`: <span class="font-semibold"><?= htmlspecialchars((string)$db_counts['dispatcher_jobs']) ?></span></div>
                            <div>DB `outgoing_emails`: <span class="font-semibold"><?= htmlspecialchars((string)$db_counts['outgoing_emails']) ?></span></div>
                            <div>DB `failed_dm_queue`: <span class="font-semibold"><?= htmlspecialchars((string)$db_counts['failed_dm_queue']) ?></span></div>
                        </div>

                        <?php if (!empty($dispatcher_jobs)): ?>
                            <div class="mt-4">
                                <h3 class="text-lg font-semibold text-slate-200 mb-2">Dispatcher Jobs</h3>
                                <div class="space-y-2 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                                    <?php foreach (array_slice($dispatcher_jobs, 0, 50) as $job): ?>
                                        <div class="bg-black/20 p-3 rounded text-sm">
                                            <div><span class="font-medium text-slate-300">Name:</span> <span class="text-slate-400"><?= htmlspecialchars($job['name'] ?? 'Untitled') ?></span></div>
                                            <div><span class="font-medium text-slate-300">Enabled:</span> <span class="text-slate-400"><?= !empty($job['enabled']) ? 'Yes' : 'No' ?></span></div>
                                            <div><span class="font-medium text-slate-300">Interval:</span> <span class="text-slate-400"><?= htmlspecialchars((string)($job['interval_mins'] ?? 'N/A')) ?> mins</span></div>
                                            <?php if (!empty($job['start_time']) || !empty($job['stop_time'])): ?>
                                                <div><span class="font-medium text-slate-300">Window:</span> <span class="text-slate-400"><?= htmlspecialchars($job['start_time'] ?? 'N/A') ?> - <?= htmlspecialchars($job['stop_time'] ?? 'N/A') ?></span></div>
                                            <?php elseif (!empty($job['start_datetime']) || !empty($job['stop_datetime'])): ?>
                                                <div><span class="font-medium text-slate-300">Window:</span> <span class="text-slate-400"><?= htmlspecialchars($job['start_datetime'] ?? 'N/A') ?> - <?= htmlspecialchars($job['stop_datetime'] ?? 'N/A') ?></span></div>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endif; ?>

                        <?php if (!empty($outgoing_emails)): ?>
                            <div class="mt-4">
                                <h3 class="text-lg font-semibold text-slate-200 mb-2">Outgoing Emails</h3>
                                <div class="space-y-2 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                                    <?php foreach (array_slice($outgoing_emails, 0, 50) as $email): ?>
                                        <div class="bg-black/20 p-3 rounded text-sm">
                                            <div><span class="font-medium text-slate-300">To:</span> <span class="text-slate-400"><?= htmlspecialchars($email['recipient'] ?? '') ?></span></div>
                                            <div><span class="font-medium text-slate-300">Subject:</span> <span class="text-slate-400"><?= htmlspecialchars($email['subject'] ?? '') ?></span></div>
                                            <div><span class="font-medium text-slate-300">Sender:</span> <span class="text-slate-400"><?= htmlspecialchars($email['sender_node'] ?? '') ?></span></div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endif; ?>

                        <?php if (!empty($failed_dms)): ?>
                            <div class="mt-4">
                                <h3 class="text-lg font-semibold text-slate-200 mb-2">Failed DM Queue</h3>
                                <div class="space-y-2 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                                    <?php foreach (array_slice($failed_dms, 0, 50) as $dm): ?>
                                        <div class="bg-black/20 p-3 rounded text-sm">
                                            <div><span class="font-medium text-slate-300">To:</span> <span class="text-slate-400"><?= htmlspecialchars($dm['destination_id'] ?? '') ?></span></div>
                                            <div><span class="font-medium text-slate-300">Text:</span> <span class="text-slate-400"><?= htmlspecialchars($dm['text'] ?? '') ?></span></div>
                                            <div><span class="font-medium text-slate-300">Timestamp:</span> <span class="text-slate-400"><?= htmlspecialchars($dm['timestamp'] ?? '') ?></span></div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                <?php if ($legacy_files_exist): ?>
                <div class="card p-6 mb-6" id="legacy-migration-card">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-2xl font-bold text-slate-100">Legacy Migration Status</h2>
                        <button type="button" class="btn btn-secondary btn-sm collapse-toggle" data-target="legacy-migration-card-body" aria-expanded="true">Collapse</button>
                    </div>
                    <div id="legacy-migration-card-body">
                        <p class="text-slate-400 text-sm mb-4 max-w-3xl">
                            SQLite is now the source of truth for queues and scheduled broadcasts. Legacy JSON files are read-only
                            and can be removed after migration.
                        </p>
                        <div class="text-slate-300 space-y-2">
                            <div>DB `dispatcher_jobs`: <span class="font-semibold"><?= htmlspecialchars((string)$db_counts['dispatcher_jobs']) ?></span></div>
                            <div>DB `outgoing_emails`: <span class="font-semibold"><?= htmlspecialchars((string)$db_counts['outgoing_emails']) ?></span></div>
                            <div>DB `failed_dm_queue`: <span class="font-semibold"><?= htmlspecialchars((string)$db_counts['failed_dm_queue']) ?></span></div>
                            <div>Legacy `dispatcher_jobs.json`: <span class="font-semibold"><?= htmlspecialchars($legacy_counts['dispatcher_jobs.json'] === null ? 'missing' : (string)$legacy_counts['dispatcher_jobs.json']) ?></span></div>
                            <div>Legacy `outgoing_emails.json`: <span class="font-semibold"><?= htmlspecialchars($legacy_counts['outgoing_emails.json'] === null ? 'missing' : (string)$legacy_counts['outgoing_emails.json']) ?></span></div>
                            <div>Legacy `failed_dm_queue.json`: <span class="font-semibold"><?= htmlspecialchars($legacy_counts['failed_dm_queue.json'] === null ? 'missing' : (string)$legacy_counts['failed_dm_queue.json']) ?></span></div>
                        </div>
                        <div class="mt-4">
                            <?php if ($migration_ok): ?>
                                <div class="bg-green-500/10 border border-green-500/20 text-green-300 px-4 py-2 rounded-lg">
                                    Migration OK. It is safe to remove legacy JSON files if desired.
                                </div>
                            <?php else: ?>
                                <div class="bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 px-4 py-2 rounded-lg">
                                    Migration not confirmed. Legacy JSON has data but DB tables are empty.
                                </div>
                            <?php endif; ?>
                        </div>
                        <div class="mt-4 text-slate-400 text-sm">
                            Cleanup script:
                            <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-sm">python3 /opt/GuardianBridge/scripts/cleanup_legacy_json.py --apply</code>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                <div class="card p-6 mb-6" id="db-maintenance-card">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-2xl font-bold text-slate-100">Database Maintenance</h2>
                        <button type="button" class="btn btn-secondary btn-sm collapse-toggle" data-target="db-maintenance-card-body" aria-expanded="true">Collapse</button>
                    </div>
                    <div id="db-maintenance-card-body">
                        <p class="text-slate-400 text-sm mb-4 max-w-3xl">
                            These actions run SQLite maintenance tasks on <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-sm">guardianbridge.db</code>.
                            Backup creates a timestamped DB snapshot in <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-sm">/opt/GuardianBridge/AutoBackUp</code>.
                            Restore can use a selected AutoBackUp file or an uploaded local <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-sm">.db</code> file.
                            Backup/Restore/VACUUM are queued for dispatcher-side execution.
                        </p>
                        <form method="POST" id="db-maintenance-form" class="flex flex-wrap gap-3" enctype="multipart/form-data">
                            <input type="hidden" name="action" value="db_maintenance">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                            <input type="hidden" name="maintenance_action" id="maintenance_action_input" value="">
                            <button type="button" data-action="integrity_check" data-confirm="Run SQLite integrity check? This will read the entire database and may briefly slow the system." class="btn btn-secondary db-maintenance-btn">Integrity Check</button>
                            <button type="button" data-action="wal_checkpoint" data-confirm="Run WAL checkpoint? This may briefly stall writes while the log is checkpointed." class="btn btn-secondary db-maintenance-btn">WAL Checkpoint</button>
                            <button type="button" data-action="audit_prune" data-confirm="Run audit-log retention prune now using current settings?" class="btn btn-secondary db-maintenance-btn">Prune Audit Log</button>
                            <button type="button" data-action="backup_db" data-confirm="Queue a DB backup now in /opt/GuardianBridge/AutoBackUp?" class="btn btn-secondary db-maintenance-btn">Backup DB</button>
                            <button type="button" data-action="restore_db" data-confirm="Queue restore from selected backup source? This overwrites the active database." class="btn btn-red db-maintenance-btn">Restore DB</button>
                            <button type="button" data-action="vacuum" data-confirm="Queue SQLite VACUUM now? Use during a maintenance window." class="btn btn-red db-maintenance-btn">Vacuum</button>
                            <div class="w-full border-t border-slate-700/60 pt-4 mt-1 space-y-3">
                                <div>
                                    <label for="restore_backup_file" class="block text-sm font-semibold text-slate-200 mb-2">Restore Source: AutoBackUp File</label>
                                    <select id="restore_backup_file" name="restore_backup_file" class="max-w-2xl">
                                        <option value="">Use newest available backup automatically</option>
                                        <?php foreach ($auto_backup_files as $backup_file): ?>
                                            <?php
                                                $backup_name = (string)($backup_file['name'] ?? '');
                                                $backup_mtime = intval($backup_file['mtime'] ?? 0);
                                                $backup_size_mb = number_format((intval($backup_file['size'] ?? 0) / 1048576), 2);
                                                $backup_label = $backup_name . ' | ' . ($backup_mtime > 0 ? date('Y-m-d H:i:s', $backup_mtime) : 'unknown time') . ' | ' . $backup_size_mb . ' MB';
                                            ?>
                                            <option value="<?= htmlspecialchars($backup_name) ?>"><?= htmlspecialchars($backup_label) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                    <?php if (empty($auto_backup_files)): ?>
                                        <p class="text-slate-500 text-xs mt-2">No AutoBackUp DB files found yet.</p>
                                    <?php endif; ?>
                                </div>
                                <div>
                                    <label for="restore_backup_upload" class="block text-sm font-semibold text-slate-200 mb-2">Or Upload Local Backup (.db)</label>
                                    <input type="file" id="restore_backup_upload" name="restore_backup_upload" accept=".db" class="max-w-2xl">
                                    <p class="text-slate-500 text-xs mt-2">If a local file is uploaded, it takes priority over the dropdown selection.</p>
                                </div>
                            </div>
                        </form>
                        <div class="mt-4 border-t border-slate-700/60 pt-4">
                            <h3 class="text-sm font-semibold text-slate-200 mb-2">Automatic Backup Interval</h3>
                            <p class="text-slate-400 text-xs mb-3">
                                Set hours between automatic DB backups in <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-xs">/opt/GuardianBridge/AutoBackUp</code>.
                                Set to <strong>0</strong> to disable auto backup.
                            </p>
                            <form method="POST" id="auto-backup-settings-form" class="flex flex-wrap items-end gap-3">
                                <input type="hidden" name="action" value="update_auto_backup_interval">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <div>
                                    <label for="auto_backup_interval_hours" class="block text-xs text-slate-400 mb-1">Hours</label>
                                    <input
                                        type="number"
                                        id="auto_backup_interval_hours"
                                        name="auto_backup_interval_hours"
                                        min="0"
                                        step="1"
                                        value="<?= htmlspecialchars((string)($settings['AUTO_BACKUP_INTERVAL_HOURS'] !== '' ? $settings['AUTO_BACKUP_INTERVAL_HOURS'] : '6')) ?>"
                                        class="max-w-[9rem]"
                                    >
                                </div>
                                <button type="submit" class="btn btn-secondary">Save AutoBackUp Interval</button>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="card p-6 mb-6" id="admin-auth-card">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-2xl font-bold text-slate-100">Admin Authentication</h2>
                        <button type="button" class="btn btn-secondary btn-sm collapse-toggle" data-target="admin-auth-card-body" aria-expanded="true">Collapse</button>
                    </div>
                    <div id="admin-auth-card-body">
                        <p class="text-slate-400 text-sm mb-4 max-w-3xl">
                            Admin login is configured via <code class="bg-slate-700/60 text-slate-200 px-1 py-0.5 rounded text-sm">.env</code>.
                            Set a username and a bcrypt hash for the password, then reload this page.
                        </p>
                        <div class="bg-slate-900/70 border border-slate-700 text-slate-300 p-4 rounded-lg mb-4">
                            <div><code>ADMIN_USERNAME=admin</code></div>
                            <div><code>ADMIN_PASSWORD_HASH=$2y$10$...</code></div>
                        </div>
                        <p class="text-slate-400 text-sm mb-2 max-w-3xl">Generate a bcrypt hash with:</p>
                        <pre class="bg-slate-900/70 border border-slate-700 text-slate-300 p-3 rounded-lg text-sm overflow-x-auto"><code class="language-sh">php -r "echo password_hash('YourStrongPasswordHere', PASSWORD_BCRYPT) . PHP_EOL;"</code></pre>
                    </div>
                </div>
                <div class="card p-6">
                    <h2 class="text-2xl font-bold mb-4 text-slate-100">Manageable Settings</h2>
                    <div class="bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 p-4 rounded-lg mb-6">
                        <strong>Important:</strong> After saving changes, you must restart the dispatcher service from the terminal for them to take effect.<br>
                        <code class="bg-yellow-400/10 text-yellow-200 px-1 py-0.5 rounded text-sm mt-1 inline-block">sudo systemctl restart guardianbridge.service</code>
                    </div>
                    <form method="POST" id="save-settings-form">
    <input type="hidden" name="action" value="update_settings">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
    
    <?php 
        $all_settings = get_env_settings($env_file, $manageable_settings);
        // --- FIX START: Separate simple settings for the loop ---
            $simple_settings = [
            'LATITUDE', 'LONGITUDE', 'LOG_LEVEL', 'MESHTASTIC_PORT', 'EMAIL_USER', 'EMAIL_PASS',
            'SMTP_SERVER', 'SMTP_PORT', 'IMAP_SERVER', 'IMAP_PORT', 'TRASH_FOLDER_NAME', 'MAX_EMAIL_BODY_LEN', 'STALE_NODE_MINUTES',
            'POLLING_INTERVAL_MS', 'CHAT_POLLING_INTERVAL_MS',
            'WEATHER_ALERT_INTERVAL_MINS', 'WEATHER_UPDATE_INTERVAL_MINS', 'WEATHER_DATA_MAX_AGE_MINUTES',
            'FORECAST_MORNING_SEND_TIME', 'FORECAST_AFTERNOON_SEND_TIME',
            'OUTGOING_EMAIL_QUARANTINE_MAX'
        ];
    ?>

    <div class="space-y-8">
        <?php foreach ($simple_settings as $key): 
            $value = $all_settings[$key] ?? '';
            $label = ucwords(strtolower(str_replace('_', ' ', $key)));
            $description = $setting_descriptions[$key] ?? 'No description available.';
            $input_type = ($key === 'EMAIL_PASS') ? 'password' : 'text';
            $display_value = $value;
            $placeholder = '';
            if ($key === 'EMAIL_PASS' && !empty($value)) {
                $display_value = '********';
                $placeholder = 'Leave unchanged to keep current password';
            }
        ?>
        <div class="border-b border-slate-700/50 pb-8 last:border-b-0">
            <label for="setting_<?= htmlspecialchars($key) ?>" class="text-base font-semibold text-slate-200"><?= htmlspecialchars($label) ?></label>
            <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl"><?= htmlspecialchars($description) ?></p>
            <input type="<?= $input_type ?>" id="setting_<?= htmlspecialchars($key) ?>" name="settings[<?= htmlspecialchars($key) ?>]" value="<?= htmlspecialchars($display_value) ?>" placeholder="<?= htmlspecialchars($placeholder) ?>" class="max-w-lg">
        </div>
        <?php endforeach; ?>
    </div>

    <div class="card p-6 mt-8">
        <h3 class="text-xl font-bold mb-4 text-slate-100">SOS Email Notifications</h3>
        <div class="space-y-6">
            <?php
            $sos_types = ['SOS' => 'General (SOS)', 'SOSM' => 'Medical (SOSM)', 'SOSF' => 'Fire (SOSF)', 'SOSP' => 'Police (SOSP)'];
            foreach ($sos_types as $key => $label):
                $enabled_key = $key . '_EMAIL_ENABLED';
                $recipients_key = $key . '_EMAIL_RECIPIENTS';
                $is_checked = (isset($all_settings[$enabled_key]) && $all_settings[$enabled_key] === 'True');
                $recipients_value = $all_settings[$recipients_key] ?? '';
            ?>
            <div class="border-t border-slate-700/50 pt-4 first:border-t-0">
                <label class="flex items-center gap-3 font-semibold text-slate-200 cursor-pointer">
                    <input type="checkbox" name="settings[<?= htmlspecialchars($enabled_key) ?>]" value="True" <?= $is_checked ? 'checked' : '' ?>>
                    <?= htmlspecialchars($label) ?>
                </label>
                <p class="text-slate-400 text-sm mt-2 mb-2 max-w-3xl pl-7">Recipient emails (comma-separated). Leave blank if none.</p>
                <div class="pl-7">
                    <input type="text" name="settings[<?= htmlspecialchars($recipients_key) ?>]" value="<?= htmlspecialchars($recipients_value) ?>" placeholder="e.g., user1@example.com, user2@example.com">
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="card p-6 mt-8">
        <h3 class="text-xl font-bold mb-4 text-slate-100">SOS Timers & Escalation</h3>
        <div class="space-y-6">
            <div>
                <label for="setting_SOS_ACK_TIMEOUT_MINS" class="text-base font-semibold text-slate-200">No-Acknowledgement Timeout (Minutes)</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Time to wait for a tagged responder to ACK an SOS before broadcasting the alert network-wide.</p>
                <input type="number" id="setting_SOS_ACK_TIMEOUT_MINS" name="settings[SOS_ACK_TIMEOUT_MINS]" value="<?= htmlspecialchars($all_settings['SOS_ACK_TIMEOUT_MINS'] ?? 5) ?>" class="max-w-xs">
            </div>
            <div>
                <label for="setting_SOS_CHECKIN_INTERVAL_MINS" class="text-base font-semibold text-slate-200">Active Check-in Interval (Minutes)</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">How often to send an automated "Are you OK?" ping to a user in 
an active SOS.</p>
                <input type="number" id="setting_SOS_CHECKIN_INTERVAL_MINS" name="settings[SOS_CHECKIN_INTERVAL_MINS]" value="<?= htmlspecialchars($all_settings['SOS_CHECKIN_INTERVAL_MINS'] ?? 5) ?>" class="max-w-xs">
            </div>
            <div>
                <label for="setting_SOS_CHECKIN_MAX_ATTEMPTS" class="text-base font-semibold text-slate-200">Max Check-in Attempts</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Number of unanswered check-in pings before escalating an SOS to "UNRESPONSIVE".</p>
                <input type="number" id="setting_SOS_CHECKIN_MAX_ATTEMPTS" name="settings[SOS_CHECKIN_MAX_ATTEMPTS]" value="<?= htmlspecialchars($all_settings['SOS_CHECKIN_MAX_ATTEMPTS'] ?? 3) ?>" class="max-w-xs">
            </div>
            <div>
                <label for="setting_TEMP_GROUP_TTL_DAYS" class="text-base font-semibold text-slate-200">Temporary Group Inactivity TTL (Days)</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Auto-close temporary groups after this many days of inactivity (join, leave, or group send).</p>
                <input type="number" id="setting_TEMP_GROUP_TTL_DAYS" name="settings[TEMP_GROUP_TTL_DAYS]" value="<?= htmlspecialchars($all_settings['TEMP_GROUP_TTL_DAYS'] ?? 14) ?>" class="max-w-xs" min="1">
            </div>
            <div>
                <label for="setting_AUTO_BACKUP_INTERVAL_HOURS" class="text-base font-semibold text-slate-200">Automatic DB Backup Interval (Hours)</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">How often the dispatcher should create DB backups in /opt/GuardianBridge/AutoBackUp. Set to 0 to disable scheduled backups.</p>
                <input type="number" id="setting_AUTO_BACKUP_INTERVAL_HOURS" name="settings[AUTO_BACKUP_INTERVAL_HOURS]" value="<?= htmlspecialchars($all_settings['AUTO_BACKUP_INTERVAL_HOURS'] ?? 6) ?>" class="max-w-xs" min="0">
            </div>
        </div>
    </div>
    <div class="card p-6 mt-8">
        <h3 class="text-xl font-bold mb-4 text-slate-100">Rate Limiting</h3>
        <div class="space-y-6">
            <div>
                <label for="setting_COMMAND_BURST_LIMIT" class="text-base font-semibold text-slate-200">Command Burst Limit</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Max commands per sender within the burst window. Set to 0 to disable.</p>
                <input type="number" id="setting_COMMAND_BURST_LIMIT" name="settings[COMMAND_BURST_LIMIT]" value="<?= htmlspecialchars($all_settings['COMMAND_BURST_LIMIT'] ?? 8) ?>" class="max-w-xs">
            </div>
            <div>
                <label for="setting_COMMAND_BURST_WINDOW_SECONDS" class="text-base font-semibold text-slate-200">Command Burst Window (Seconds)</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Rolling window size for command burst limiting.</p>
                <input type="number" id="setting_COMMAND_BURST_WINDOW_SECONDS" name="settings[COMMAND_BURST_WINDOW_SECONDS]" value="<?= htmlspecialchars($all_settings['COMMAND_BURST_WINDOW_SECONDS'] ?? 30) ?>" class="max-w-xs">
            </div>
            <div>
                <label for="setting_EMAIL_RATE_LIMIT_MAX" class="text-base font-semibold text-slate-200">Email Rate Limit (Max)</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Max inbound emails per sender within the email window. Set to 0 to disable.</p>
                <input type="number" id="setting_EMAIL_RATE_LIMIT_MAX" name="settings[EMAIL_RATE_LIMIT_MAX]" value="<?= htmlspecialchars($all_settings['EMAIL_RATE_LIMIT_MAX'] ?? 6) ?>" class="max-w-xs">
            </div>
            <div>
                <label for="setting_EMAIL_RATE_LIMIT_WINDOW_SECONDS" class="text-base font-semibold text-slate-200">Email Rate Limit Window (Seconds)</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Rolling window size for inbound email rate limiting.</p>
                <input type="number" id="setting_EMAIL_RATE_LIMIT_WINDOW_SECONDS" name="settings[EMAIL_RATE_LIMIT_WINDOW_SECONDS]" value="<?= htmlspecialchars($all_settings['EMAIL_RATE_LIMIT_WINDOW_SECONDS'] ?? 300) ?>" class="max-w-xs">
            </div>
        </div>
    </div>
    <div class="card p-6 mt-8">
        <h3 class="text-xl font-bold mb-4 text-slate-100">Audit Retention</h3>
        <div class="space-y-6">
            <div>
                <label for="setting_AUDIT_RETENTION_DAYS" class="text-base font-semibold text-slate-200">Audit Retention Days</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Delete audit rows older than this many days. Set to 0 to disable age-based pruning.</p>
                <input type="number" id="setting_AUDIT_RETENTION_DAYS" name="settings[AUDIT_RETENTION_DAYS]" value="<?= htmlspecialchars($all_settings['AUDIT_RETENTION_DAYS'] ?? 90) ?>" class="max-w-xs" min="0">
            </div>
            <div>
                <label for="setting_AUDIT_MAX_ROWS" class="text-base font-semibold text-slate-200">Audit Max Rows</label>
                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl">Maximum audit rows to keep. Oldest rows are pruned when this cap is exceeded. Set to 0 to disable count-based pruning.</p>
                <input type="number" id="setting_AUDIT_MAX_ROWS" name="settings[AUDIT_MAX_ROWS]" value="<?= htmlspecialchars($all_settings['AUDIT_MAX_ROWS'] ?? 50000) ?>" class="max-w-xs" min="0">
            </div>
        </div>
    </div>
    <div class="mt-8"><button type="submit" class="btn btn-primary">Save Settings</button></div>
</form>
    <div class="card p-6 mt-8">
    <h2 class="text-2xl font-bold mb-4 text-slate-100">SOS Email Instructions</h2>
    <p class="text-slate-400 text-sm mb-4">
        This content will be appended to the bottom of every SOS notification email. Use it for standard procedures, contact lists, or important reminders for email recipients.
    </p>
    <form method="POST">
        <input type="hidden" name="action" value="update_sos_instructions">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
        
        <div>
            <label for="sos_instructions_content" class="block text-sm font-medium text-slate-400 mb-2">Instructions Content</label>
            <textarea id="sos_instructions_content" name="sos_instructions_content" rows="10" class="font-mono text-sm" placeholder="Enter your canned SOS handling instructions here..."><?= htmlspecialchars($sos_instructions_content) ?></textarea>
        </div>
        
        <div class="mt-6">
            <button type="submit" class="btn btn-primary">Save Instructions</button>
        </div>
    </form>
</div>
                </div>
            </div>
            <div id="help-content" class="tab-content" style="display: none;">
                <div class="card p-6 md:p-8 text-slate-300 space-y-6 help-content">
                    <?php
                        $help_file = '/opt/GuardianBridge/Docs/help_about.html';
                        if (file_exists($help_file)) {
                            include($help_file);
                        } else {
                            echo '<p class="text-red-400">Error: help_about.html file not found at: /opt/GuardianBridge/Docs/help_about.html.</p>';
                        }
                    ?>
                </div>
            </div>
            
        </main>
        
        <footer class="mt-12 pt-6 border-t border-slate-700/50 text-center text-sm text-slate-500">
            <p>
                GuardianBridge Admin Panel | Revision: <?= htmlspecialchars($revision) ?>
            </p>
            <p class="mt-2">
                Copyright © <?php echo date('Y'); ?> Robert Kolbasowski. All Rights Reserved.
            </p>
        </footer>
    </div>

<div id="dm-chat-modal" class="fixed inset-0 bg-black/70 items-center justify-center" style="display: none;">
    <div class="card w-full max-w-2xl h-[80vh] flex flex-col mx-4">
        <h2 id="dm-chat-title" class="text-xl font-bold text-slate-100 p-4 border-b border-slate-700/50 flex justify-between items-center">
            <span class="font-mono">Direct Chat</span>
            <div class="flex items-center gap-2">
                <button type="button" id="dm-chat-user-btn" class="btn btn-secondary btn-sm" disabled>User</button>
                <button type="button" id="close-dm-modal-btn" class="text-slate-400 hover:text-white text-3xl leading-none">&times;</button>
            </div>
        </h2>
        <div id="dm-chat-window" class="flex-grow p-4 overflow-y-auto">
            <div class="space-y-4" id="dm-chat-messages-container">
            </div>
        </div>
        <div class="p-4 border-t border-slate-700/50">
            <form id="dm-chat-form" onsubmit="return false;">
                <input type="hidden" id="dm-target-node-id-input">
                <div class="flex items-center gap-2">
                    <textarea id="dm-chat-textarea" rows="2" placeholder="Send a direct message..." class="flex-grow resize-none"></textarea>
                    <button type="button" id="dm-chat-bell-btn" class="btn btn-secondary">Bell</button>
                    <button type="submit" id="dm-chat-send-btn" class="btn btn-primary">Send</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div id="user-edit-modal" class="fixed inset-0 bg-black/70 items-center justify-center" style="display: none;">
    <div class="card w-full max-w-4xl max-h-[90vh] flex flex-col mx-4">
        <h2 id="user-modal-title" class="text-xl font-bold text-slate-100 p-4 border-b border-slate-700/50 flex justify-between items-center">
            <span class="font-mono">Edit User</span>
            <button id="close-user-modal-btn" class="text-slate-400 hover:text-white text-3xl leading-none">&times;</button>
        </h2>
        <div class="p-6 overflow-y-auto">
            <form id="user-edit-form" method="POST">
                <input type="hidden" name="action" value="update_user">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                <input type="hidden" name="node_id" value="">
                
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-5">
                    <div>
                        <label for="name">Username</label>
                        <input type="text" name="name" id="name" required>
                    </div>
                    <div>
                        <label for="full_name">Full Name</label>
                        <input type="text" name="full_name" id="full_name">
                    </div>
                    <div>
                        <label for="user_role">Assigned Role</label>
                        <select name="role" id="user_role">
                            <option value="">Not Set</option>
                            <option value="CLIENT">CLIENT (Default Repeater)</option>
                            <option value="CLIENT_MUTE">CLIENT_MUTE (No Repeat)</option>
                            <option value="ROUTER">ROUTER (Fixed Repeater)</option>
                            <option value="REPEATER">REPEATER (Legacy Repeater)</option>
                        </select>
                    </div>
                    <div>
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email">
                    </div>
                    <div>
                        <label for="phone_1">Phone 1</label>
                        <input type="text" name="phone_1" id="phone_1">
                    </div>
                    <div>
                        <label for="phone_2">Phone 2</label>
                        <input type="text" name="phone_2" id="phone_2">
                    </div>
                    
                    <div class="lg:col-span-2"></div> 
                    <div class="lg:col-span-2">
                        <label for="address_street">Street Address</label>
                        <input type="text" name="address_street" id="address_street">
                    </div>
                    <div>
                        <label for="address_city">City</label>
                        <input type="text" name="address_city" id="address_city">
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label for="address_state">State</label>
                            <input type="text" name="address_state" id="address_state">
                        </div>
                        <div>
                            <label for="address_zip">Zip Code</label>
                            <input type="text" name="address_zip" id="address_zip">
                        </div>
                    </div>
                    <div>
                        <label for="address_lat">Address Lat</label>
                        <input type="text" name="address_lat" id="address_lat" class="font-mono text-sm" placeholder="e.g., 40.7128">
                    </div>
                    <div>
                        <label for="address_lon">Address Lon</label>
                        <input type="text" name="address_lon" id="address_lon" class="font-mono text-sm" placeholder="e.g., -74.0060">
                    </div>
                    <div class="lg:col-span-2 md:col-span-2">
                        <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer">
                            <input type="checkbox" name="use_address_coords" id="use_address_coords">
                            Use address coordinates for map display
                        </label>
                        <p id="address-coords-warning" class="text-xs text-slate-500 mt-1">Enter both address coordinates to enable.</p>
                    </div>
                    <div class="lg:col-span-2 md:col-span-2">
                        <label for="notes">Notes</label>
                        <textarea name="notes" id="notes" rows="4" class="font-mono text-sm"></textarea>
                    </div>
                    <div class="lg:col-span-2 md:col-span-2">
                        <label for="ops_notes">Ops Notes</label>
                        <textarea name="ops_notes" id="ops_notes" rows="4" class="font-mono text-sm"></textarea>
                    </div>
                    <div class="lg:col-span-2 md:col-span-2">
                        <label for="poc_info">Emergency Point of Contact / Next of Kin</label>
                        <textarea name="poc_info" id="poc_info" rows="4" class="font-mono text-sm"></textarea>
                    </div>
                    
                    <div class="lg:col-span-4 md:col-span-2">
                        <label for="tags">Tags (comma-separated)</label>
                        <input type="text" id="tags" name="tags" placeholder="CERT, MEDICAL, TEAMLEAD" class="font-mono text-sm">
                    </div>
                    
                    <div class="lg:col-span-4 md:col-span-2">
                        <label for="sos_notify">SOS Notify (comma-separated names, node IDs, or emails)</label>
                        <input type="text" id="sos_notify" name="sos_notify" placeholder="e.g., responder-team@example.com, !a1b2c3d4, Bob" class="font-mono text-sm">
                    </div>

                    <div class="lg:col-span-2 md:col-span-2">
                        <label for="password">Login Password (leave blank to keep)</label>
                        <input type="password" id="password" name="password">
                    </div>
                    <div class="lg:col-span-2 md:col-span-2">
                        <label for="password_confirm">Confirm Password</label>
                        <input type="password" id="password_confirm" name="password_confirm">
                    </div>
                    
                    <div class="lg:col-span-4 md:col-span-2">
                        <label>Subscriptions & Permissions</label>
                        <div class="flex flex-wrap gap-x-6 gap-y-2 mt-2 p-3 bg-black/20 rounded-md">
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="alerts"> NWS Alerts</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="weather"> Weather Reports</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="scheduled_daily_forecast"> Daily Forecast</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="email_send"> Email Send</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="email_receive"> Email Receive</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="emailbroadcast"> Email Broadcast</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="node_tag_send"> Node Tag Send</label>
                        </div>
                    </div>
                    
                    <div class="lg:col-span-4 md:col-span-2 pt-4 mt-4 border-t border-slate-700/50">
                        <label class="text-red-400 font-bold">Administrative Actions</label>
                        <div class="mt-2 p-3 bg-red-900/20 rounded-md">
                            <label class="flex items-center gap-2 font-normal text-red-300 cursor-pointer">
                                <input type="checkbox" name="blocked" class="h-4 w-4">
                                Block User (Ignore all commands from this node)
                            </label>
                        </div>
                    </div>
                </div>
            </form>
        </div>
            <div class="p-4 border-t border-slate-700/50 bg-slate-800/20 flex justify-between items-center">
                <button type="button" id="close-user-modal-btn-footer" class="btn btn-secondary">Close</button>
            <div class="flex items-center gap-4">
                <form id="user-modal-delete-form" method="POST">
                    <input type="hidden" name="action" value="delete_user">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                    <input type="hidden" name="node_id" value="">
                    <button type="submit" class="btn btn-red">Delete User</button>
                </form>
                <form id="clear-user-password-form" method="POST">
                    <input type="hidden" name="action" value="clear_user_password">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                    <input type="hidden" name="node_id" value="">
                    <button type="submit" class="btn btn-red">Clear Password</button>
                </form>
                <button type="submit" form="user-edit-form" class="btn btn-green">Save Changes</button>
            </div>
        </div>
    </div>
</div>

<div id="broadcast-edit-modal" class="fixed inset-0 bg-black/70 items-center justify-center" style="display: none;">
    <div class="card w-full max-w-4xl max-h-[90vh] flex flex-col mx-4">
        <h2 id="broadcast-modal-title" class="text-xl font-bold text-slate-100 p-4 border-b border-slate-700/50 flex justify-between 
items-center">
            <span>Edit Broadcast</span>
            <button id="close-broadcast-modal-btn" class="text-slate-400 hover:text-white text-3xl leading-none">&times;</button>
        </h2>
        <div class="p-6 overflow-y-auto">
            <form id="broadcast-edit-form" method="POST" class="space-y-4">
                <input type="hidden" name="action" value="save_broadcast_job">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                <input type="hidden" name="job_index" value="">
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label>Broadcast Name</label>
                        <input type="text" name="name" required>
                    </div>
                    <div>
                        <label>Interval (minutes)</label>
                        <input type="number" name="interval_mins" value="60" min="1" required>
                    </div>
                </div>
                
                <div>
                    <label>Broadcast Content</label>
                    <textarea name="content" rows="3" required></textarea>
                </div>

                <div class="pt-2">
                    <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer">
                        <input type="checkbox" name="with_bell" value="true" class="w-auto h-4 w-4">
                        Bell (Prepend alert with audible bell character)
                    </label>
                </div>

                <div class="pt-4 mt-4 border-t border-slate-700/50">
                    <label class="flex items-center gap-2 font-semibold text-slate-300 cursor-pointer">
                        <input type="checkbox" name="enabled" value="true" class="h-4 w-4">
                        Enable this broadcast job
                    </label>
                    <p class="text-sm text-slate-500 mt-1 pl-6">The dispatcher will ignore this job unless this box is checked.</p>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                    <div>
                        <label>Job Type</label>
                        <select name="job_type" class="job-type-selector">
                            <option value="recurring">Recurring Day/Time</option>
                            <option value="event">Specific Date/Time Event</option>
                        </select>
                    </div>
                </div>

                <div class="recurring-fields space-y-3">
                    <div>
                        <label>Days of Week</label>
                        <div class="flex flex-wrap gap-x-4 gap-y-2 mt-2 p-3 bg-black/20 rounded-md">
                        <?php foreach ($days_of_week as $day): ?>
                            <label class="flex items-center gap-2 font-normal text-slate-400"><input type="checkbox" name="days[]" value="<?= $day ?>" class="w-auto h-4 w-4"> <?= 
$day ?></label>
                        <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div><label>Start Time</label><input type="time" name="start_time"></div>
                        <div><label>Stop Time</label><input type="time" name="stop_time"></div>
                    </div>
                </div>

                <div class="event-fields space-y-2">
                    <div class="grid grid-cols-2 gap-4">
                        <div><label>Start Date & Time</label><input type="datetime-local" name="start_datetime"></div>
                        <div><label>Stop Date & Time</label><input type="datetime-local" name="stop_datetime"></div>
                    </div>
                </div>
            </form>
        </div>
        <div class="p-4 border-t border-slate-700/50 bg-slate-800/20 flex justify-between items-center">
            <button type="button" id="close-broadcast-modal-btn-footer" class="btn btn-secondary">Close</button>
            <div class="flex items-center gap-4">
                <form id="broadcast-modal-delete-form" method="POST">
                    <input type="hidden" name="action" value="delete_broadcast_job">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                    <input type="hidden" name="job_index" value="">
                    <button type="submit" class="btn btn-red">Delete Job</button>
                </form>
                <button type="submit" form="broadcast-edit-form" class="btn btn-green">Save Changes</button>
            </div>
        </div>
    </div>
</div>

<div id="confirm-action-modal" class="fixed inset-0 bg-black/70 items-center justify-center" style="display: none;">
    <div class="card w-full max-w-md mx-4">
        <div class="p-6">
            <h2 class="text-2xl font-bold text-slate-100 mb-4">Confirm Your Action</h2>
            <p id="confirm-modal-text" class="text-slate-300 mb-6">Are you sure you wish to proceed?</p>
        </div>
        <div class="p-4 border-t border-slate-700/50 bg-slate-800/20 flex justify-end items-center gap-4">
            <button type="button" id="confirm-modal-cancel-btn" class="btn btn-secondary">Cancel</button>
            <button type="button" id="confirm-modal-confirm-btn" class="btn btn-red">Confirm</button>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // --- GLOBAL STATE & CONFIG ---
        let isStatusTabInitialized = false, isChatTabInitialized = false, isPollingActive = false;
        let isStatusPolling = false, isChatPolling = false;
        
        let map;
        let nodeMarkers = {};
        let nodeMarkersMeta = {};
        let lastNodesSignature = '';
        let lastPositionsSignature = '';
        const acknowledgedSosNodes = new Set();
        let activeSosNodeId = null;
        let autoFitEnabled = true; // Flag to control map auto-zoom
        const POLLING_INTERVAL = <?= json_encode(max(1000, intval($all_settings['POLLING_INTERVAL_MS'] ?? 5000))) ?>;
        const csrfToken = '<?= htmlspecialchars($csrf_token) ?>';
        const CHAT_POLLING_INTERVAL = <?= json_encode(max(500, intval($all_settings['CHAT_POLLING_INTERVAL_MS'] ?? 1000))) ?>;
        const STALE_NODE_MINUTES = <?= json_encode(intval($all_settings['STALE_NODE_MINUTES'] ?? 120)) ?>;
        const STALE_NODE_SECONDS = Math.max(0, Number(STALE_NODE_MINUTES)) * 60;
        let chatCursor = 0;
        let subscribersMtime = 0;
        let chatSubscribersMtime = 0;
        let nodesEtag = '';
        let dashboardEtag = '';
        let chatEtag = '';
        let chatTempGroupsToken = '';
        let lastFetchedTempGroups = [];
        const CHAT_GROUP_CHANNEL = '__CHANNEL__';
        let selectedChatGroup = '';
        let chatGroupSignature = '';
        let chatStreamSource = null;
        let chatStreamRetryTimer = null;
        let chatStreamConnected = false;
        const CHAT_STREAM_ENABLED = false;
        const CHAT_STREAM_TIMEOUT_MS = 20000;
        const CHAT_STREAM_RETRY_MS = 1500;
        const MAX_BACKOFF_MS = 30000;
        let statusBackoffMs = 0;
        let chatBackoffMs = 0;
        let statusPollTimer = null;
        let chatPollTimer = null;
        let statusPollInFlight = false;
        let chatPollInFlight = false;
        let updatePageInFlight = null;
        let updateDashboardInFlight = null;
        let updateChatInFlight = null;
        let mapUsersTableEtag = '';
        let mapUsersFetchInFlight = null;
        const opsNotesDraftByNode = new Map();
        const GATEWAY_LAT = <?= json_encode($gateway_lat) ?>;
        const GATEWAY_LON = <?= json_encode($gateway_lon) ?>;
        L.Icon.Default.imagePath = '/map-items/';
        async function updateDashboardData() {
            if (updateDashboardInFlight) {
                return updateDashboardInFlight;
            }
            const requestPromise = (async () => {
                try {
                    const requestHeaders = {};
                    if (dashboardEtag) {
                        requestHeaders['If-None-Match'] = dashboardEtag;
                    }
                    const response = await fetch('/map-items/api_get_dashboard.php', { headers: requestHeaders });
                    const responseEtag = response.headers.get('ETag');
                    if (responseEtag) {
                        dashboardEtag = responseEtag;
                    }
                    if (response.status === 304) {
                        return true;
                    }
                    if (!response.ok) {
                        console.error('Failed to fetch dashboard data');
                        return false;
                    }
                    const data = await response.json();

                // 1. Update System Health Panel
                const healthContainer = document.getElementById('system-health-body');
                if (healthContainer) {
                    const health = data.system_health;
                    const restartCount = Number.isFinite(Number(health.dispatcher_restart_count))
                        ? Number(health.dispatcher_restart_count)
                        : 0;
                    const serviceResult = String(health.dispatcher_result || 'unknown');
                    const execCode = String(health.dispatcher_exec_code || 'n/a');
                    const execStatus = String(health.dispatcher_exec_status || 'n/a');
                    const subState = String(health.dispatcher_sub_state || 'unknown');
                    const serviceMetaAvailable = (
                        restartCount > 0 ||
                        serviceResult !== 'unknown' ||
                        subState !== 'unknown' ||
                        execCode !== 'n/a' ||
                        execStatus !== 'n/a'
                    );
                    const serviceMetaHtml = serviceMetaAvailable ? `
                        <p class="flex items-center"><span class="font-bold ${restartCount > 0 ? 'status-warn' : 'status-ok'} mr-3 text-lg">●</span> Restarts: ${restartCount} | Result: ${escapeHTML(serviceResult)} | SubState: ${escapeHTML(subState)}</p>
                        <p class="flex items-center"><span class="font-bold ${execCode === '0' ? 'status-ok' : 'status-warn'} mr-3 text-lg">●</span> Exec: code=${escapeHTML(execCode)} status=${escapeHTML(execStatus)}</p>
                    ` : '';
                    const lastException = String(health.dispatcher_last_exception || '');
                    const lastExceptionSource = String(health.dispatcher_last_exception_source || '');
                    const lastExceptionTime = String(health.dispatcher_last_exception_time || '');
                    const exceptionMeta = [lastExceptionSource, lastExceptionTime].filter(Boolean).join(' @ ');
                    const alerts = Array.isArray(health.alerts) ? health.alerts : [];
                    const alertsHtml = alerts.length
                        ? `<div class="mt-3 space-y-1">${alerts.map((alert) => {
                            const level = String((alert && alert.level) || 'warn').toLowerCase();
                            const levelClass = level === 'critical' ? 'text-red-300' : (level === 'warn' ? 'text-yellow-300' : 'text-blue-300');
                            const msg = escapeHTML(String((alert && alert.message) || ''));
                            const code = escapeHTML(String((alert && alert.code) || ''));
                            return `<p class="text-xs ${levelClass}">[${code}] ${msg}</p>`;
                        }).join('')}</div>`
                        : '<p class="text-xs text-slate-500 mt-2">No active dispatcher alerts.</p>';
                    healthContainer.innerHTML = `
                        <p class="flex items-center"><span class="font-bold ${health.dispatcher_active ? 'status-ok' : 'status-fail'} mr-3 text-lg">●</span> Dispatcher Service is ${health.dispatcher_active ? 'ACTIVE' : 'INACTIVE or FAILED'}</p>
                        ${serviceMetaHtml}
                        <p class="flex items-center"><span class="font-bold ${health.radio_connected ? 'status-ok' : 'status-fail'} mr-3 text-lg">●</span> Radio Connection Status</p>
                        <p class="flex items-center"><span class="font-bold ${health.weather_fetcher_ok ? 'status-ok' : 'status-warn'} mr-3 text-lg">●</span> Weather Fetcher Cron (Last run: ${health.weather_fetcher_last_run})</p>
                        <p class="flex items-center"><span class="font-bold ${health.email_processor_ok ? 'status-ok' : 'status-warn'} mr-3 text-lg">●</span> Email Processor Cron (Last run: ${health.email_processor_last_run})</p>
                        <p class="text-xs ${lastException ? 'text-yellow-300' : 'text-slate-500'}">Last exception: ${lastException ? escapeHTML(lastException) : 'none'}${exceptionMeta ? ` <span class="text-slate-500">(${escapeHTML(exceptionMeta)})</span>` : ''}</p>
                        ${alertsHtml}
                    `;
                }

                // 2. Update Weather & Alerts Panel
                const weatherContainer = document.getElementById('weather-card');
                if (weatherContainer) {
                    const weather = data.weather_info;
                    const stationLabel = weather.station_id ? `· Station ${escapeHTML(String(weather.station_id))}` : '';
                    const staleLabel = weather.stale ? '<span class="ml-2 font-semibold">STALE</span>' : '';
                    const updatedClass = weather.stale ? 'text-red-400' : 'text-slate-500';
                    weatherContainer.innerHTML = `
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Weather & Alerts</h2>
                        <div>
                            <h3 class="font-semibold text-lg text-blue-400">Current Weather</h3>
                            <p class="text-slate-300 mt-1">Temp: <span class="font-medium text-slate-100">${weather.temperature_f}°F</span>, Humidity: <span class="font-medium text-slate-100">${weather.humidity}% RH</span></p>
                            <p class="text-xs mt-2 ${updatedClass}">Updated: ${weather.last_update} ${stationLabel} ${staleLabel}</p>
                        </div>
                        <div class="mt-4">
                            <h3 class="font-semibold text-lg text-yellow-400">Active NWS Alerts</h3>
                            <p class="text-slate-300 mt-1">${weather.active_alert}</p>
                        </div>
                    `;
                }

                // 3. Update System Metrics Panel
                const metricsContainer = document.getElementById('metrics-body');
                if (metricsContainer) {
                    const metrics = data.metrics || {};
                    const ageSeconds = (typeof metrics.dispatcher_state_age_seconds === 'number')
                        ? `${metrics.dispatcher_state_age_seconds}s`
                        : 'N/A';
                    metricsContainer.innerHTML = `
                        <p>DB Size: <span class="font-medium text-slate-100">${formatBytes(metrics.db_total_bytes || 0)}</span></p>
                        <p>WAL/SHM: <span class="font-medium text-slate-100">${formatBytes(metrics.db_wal_bytes || 0)} / ${formatBytes(metrics.db_shm_bytes || 0)}</span></p>
                        <p>Outgoing Email Queue: <span class="font-medium text-slate-100">${metrics.outgoing_email_queue ?? 0}</span></p>
                        <p>Failed DM Queue: <span class="font-medium text-slate-100">${metrics.failed_dm_queue ?? 0}</span></p>
                        <p>Command Backlog: <span class="font-medium text-slate-100">${metrics.command_backlog_count ?? 0}</span></p>
                        <p>Oldest Command Age: <span class="font-medium text-slate-100">${typeof metrics.command_oldest_age_seconds === 'number' ? `${metrics.command_oldest_age_seconds}s` : 'N/A'}</span></p>
                        <p>Dead Letters: <span class="font-medium text-slate-100">${metrics.command_dead_letter_count ?? 0}</span></p>
                        <p>Queue Depths (send/cmd): <span class="font-medium text-slate-100">${metrics.send_queue_depth ?? 0} / ${metrics.command_queue_depth ?? 0}</span></p>
                        <p>Subscribers: <span class="font-medium text-slate-100">${metrics.subscribers_count ?? 0}</span></p>
                        <p>Active SOS: <span class="font-medium text-slate-100">${metrics.active_sos_count ?? 0}</span></p>
                        <p>Dispatcher State Age: <span class="font-medium text-slate-100">${ageSeconds}</span></p>
                    `;
                }

                // 4. Update SOS Alert Log Panel & Admin Clear Button
                const sosLogContainer = document.querySelector('#actions-content .card:nth-child(4)');
                if (sosLogContainer) {
                    const sosLogContent = sosLogContainer.querySelector('.space-y-3');
                    const sosLog = data.sos_log;

                    if (sosLogContent) {
                        if (sosLog.length > 0) {
                            let sosHtml = '';
                            sosLog.forEach(log => {
                                // This logic to build the log entries remains the same
                                const date = new Date(log.timestamp).toLocaleString();
                                const phoneHtml = (log.user_info && log.user_info.phone_1) ? `<p>Phone: ${escapeHTML(log.user_info.phone_1)}</p>` : '';
                                sosHtml += `
                                    <div class="bg-red-900/30 p-4 rounded-lg">
                                        <div class="flex justify-between items-center mb-2">
                                            <span class="font-bold text-lg text-red-300">SOS: ${escapeHTML(log.sos_type || 'GENERAL')}</span>
                                            <span class="text-sm text-slate-400">${date}</span>
                                        </div>
                                        <p class="font-mono text-sm">Node: ${escapeHTML(log.node_id)}</p>
                                        <p>User: <b>${escapeHTML(log.user_info.name || 'N/A')}</b> / ${escapeHTML(log.user_info.full_name || 'N/A')}</p>
                                        ${phoneHtml}
                                    </div>
                                `;
                            });
                            sosLogContent.innerHTML = sosHtml;
                        } else {
                            sosLogContent.innerHTML = '<p class="text-slate-500">The SOS log is empty.</p>';
                        }
                    }

                    // New logic to update the Admin Clear button dynamically
                    const adminClearForm = document.getElementById('admin-clear-sos-form');
                    if (adminClearForm) {
                        const clearButton = adminClearForm.querySelector('button');
                        const nodeIdInput = adminClearForm.querySelector('input[name="node_id"]');
                        if (data.active_sos_node_id) {
                            nodeIdInput.value = data.active_sos_node_id;
                            clearButton.disabled = false;
                            clearButton.classList.remove('btn-secondary');
                            clearButton.classList.add('btn-green');
                            clearButton.title = 'Triggers the full stand-down protocol for this SOS.';
                        } else {
                            nodeIdInput.value = '';
                            clearButton.disabled = true;
                            clearButton.classList.remove('btn-green');
                            clearButton.classList.add('btn-secondary');
                            clearButton.title = 'No active SOS detected.';
                        }
                    }
                }
                    return true;
                } catch (error) {
                    console.error('Error updating dashboard data:', error);
                    return false;
                }
            })();
            updateDashboardInFlight = requestPromise;
            try {
                return await requestPromise;
            } finally {
                if (updateDashboardInFlight === requestPromise) {
                    updateDashboardInFlight = null;
                }
            }
        }

        // --- ROBUST POLLING LOGIC ---
        function startStatusPolling() {
            if (isStatusPolling) return;
            isStatusPolling = true;
            statusBackoffMs = POLLING_INTERVAL;
            pollStatusData();
        }

        function startChatPolling() {
            if (isChatPolling) return;
            isChatPolling = true;
            chatBackoffMs = CHAT_POLLING_INTERVAL;
            if (CHAT_STREAM_ENABLED) {
                startChatStream();
            }
            pollChatData();
        }

        function stopStatusPolling() {
            isStatusPolling = false;
            if (statusPollTimer) {
                clearTimeout(statusPollTimer);
                statusPollTimer = null;
            }
        }

        function stopChatPolling() {
            isChatPolling = false;
            if (chatPollTimer) {
                clearTimeout(chatPollTimer);
                chatPollTimer = null;
            }
            stopChatStream();
        }

        function scheduleStatusPoll(delayMs) {
            const nextDelay = Math.max(POLLING_INTERVAL, Number(delayMs) || POLLING_INTERVAL);
            if (statusPollTimer) {
                clearTimeout(statusPollTimer);
            }
            statusPollTimer = setTimeout(pollStatusData, nextDelay);
        }

        function scheduleChatPoll(delayMs) {
            const nextDelay = Math.max(CHAT_POLLING_INTERVAL, Number(delayMs) || CHAT_POLLING_INTERVAL);
            if (chatPollTimer) {
                clearTimeout(chatPollTimer);
            }
            chatPollTimer = setTimeout(pollChatData, nextDelay);
        }

        async function pollStatusData() {
            if (!isPollingActive) {
                isStatusPolling = false;
                return;
            }
            if (statusPollInFlight) {
                scheduleStatusPoll(statusBackoffMs || POLLING_INTERVAL);
                return;
            }
            statusPollInFlight = true;
            let ok = false;
            try {
                const pageOk = await updatePageData();
                const dashOk = await updateDashboardData();
                ok = !!pageOk && !!dashOk;
            } catch (error) {
                console.error("Polling error:", error);
            } finally {
                statusPollInFlight = false;
                if (!isPollingActive || !isStatusPolling) {
                    return;
                }
                statusBackoffMs = ok
                    ? POLLING_INTERVAL
                    : Math.min(MAX_BACKOFF_MS, Math.max(POLLING_INTERVAL, (statusBackoffMs || POLLING_INTERVAL) * 2));
                scheduleStatusPoll(statusBackoffMs);
            }
        }

        async function pollChatData() {
            if (!isPollingActive) {
                isChatPolling = false;
                stopChatStream();
                return;
            }
            if (chatPollInFlight) {
                scheduleChatPoll(chatBackoffMs || CHAT_POLLING_INTERVAL);
                return;
            }
            chatPollInFlight = true;
            let ok = true;
            try {
                if (CHAT_STREAM_ENABLED) {
                    if (!chatStreamSource && !chatStreamRetryTimer) {
                        startChatStream();
                    }
                } else {
                    ok = await updateChat();
                }
            } catch (error) {
                console.error("Chat polling error:", error);
                ok = false;
            } finally {
                chatPollInFlight = false;
                if (!isPollingActive || !isChatPolling) {
                    return;
                }
                chatBackoffMs = ok
                    ? CHAT_POLLING_INTERVAL
                    : Math.min(MAX_BACKOFF_MS, Math.max(CHAT_POLLING_INTERVAL, (chatBackoffMs || CHAT_POLLING_INTERVAL) * 2));
                scheduleChatPoll(chatBackoffMs);
            }
        }

        // --- UTILITY FUNCTIONS ---
        function escapeHTML(str) {
            if (typeof str !== 'string') return '';
            return str.replace(/[&<>"']/g, tag => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            } [tag] || tag));
        }

        function normalizeOpsNotesValue(value) {
            if (value === null || value === undefined) return '';
            return String(value);
        }

        function getOpsNotesDraftValue(nodeId, fallbackValue) {
            const key = String(nodeId || '');
            if (key && opsNotesDraftByNode.has(key)) {
                return normalizeOpsNotesValue(opsNotesDraftByNode.get(key));
            }
            return normalizeOpsNotesValue(fallbackValue);
        }

        function renderOpsNotesEditorHtml(nodeId, currentValue) {
            const safeNode = String(nodeId || '');
            const value = getOpsNotesDraftValue(safeNode, currentValue);
            return `
                <div class="ops-notes-editor" data-node-id="${escapeHTML(safeNode)}">
                    <textarea class="ops-notes-input" rows="4" placeholder="Add or update Ops Notes...">${escapeHTML(value)}</textarea>
                    <div class="ops-notes-actions">
                        <button type="button" class="ops-notes-save-btn">Save Ops Notes</button>
                        <span class="ops-notes-status" aria-live="polite"></span>
                    </div>
                </div>
            `;
        }

        function selectorEscape(value) {
            const raw = String(value || '');
            if (typeof CSS !== 'undefined' && CSS && typeof CSS.escape === 'function') {
                return CSS.escape(raw);
            }
            return raw.replace(/[^a-zA-Z0-9_-]/g, '\\$&');
        }

        function setOpsNotesStatus(nodeId, statusClass, message) {
            const key = String(nodeId || '');
            if (!key) return;
            const selectorNode = selectorEscape(key);
            document.querySelectorAll(`.ops-notes-editor[data-node-id="${selectorNode}"] .ops-notes-status`).forEach((el) => {
                el.classList.remove('ok', 'err');
                if (statusClass) {
                    el.classList.add(statusClass);
                }
                el.textContent = message || '';
            });
        }

        function updateLocalOpsNotesCache(nodeId, value) {
            const key = String(nodeId || '');
            if (!key) return;
            const normalized = normalizeOpsNotesValue(value);
            opsNotesDraftByNode.delete(key);
            if (lastFetchedSubscribers[key] && typeof lastFetchedSubscribers[key] === 'object') {
                lastFetchedSubscribers[key].ops_notes = normalized;
            } else {
                lastFetchedSubscribers[key] = { ops_notes: normalized };
            }
            const selectorNode = selectorEscape(key);
            document.querySelectorAll(`.ops-notes-editor[data-node-id="${selectorNode}"] .ops-notes-input`).forEach((el) => {
                if (document.activeElement !== el) {
                    el.value = normalized;
                }
            });
        }

        async function saveOpsNotesForNode(nodeId, notesValue, buttonEl) {
            const key = String(nodeId || '').trim();
            if (!key) {
                return { success: false, message: 'Node ID is required.' };
            }
            const formData = new FormData();
            formData.append('ajax', 'true');
            formData.append('action', 'update_ops_notes');
            formData.append('node_id', key);
            formData.append('ops_notes', notesValue);
            formData.append('csrf_token', csrfToken);

            const originalText = buttonEl ? buttonEl.textContent : '';
            if (buttonEl) {
                buttonEl.disabled = true;
                buttonEl.textContent = 'Saving...';
            }

            try {
                const response = await fetch(window.location.href, { method: 'POST', body: formData });
                if (!response.ok) {
                    return { success: false, message: `Save failed (${response.status})` };
                }
                const payload = await response.json();
                if (!payload || !payload.success) {
                    return { success: false, message: (payload && payload.message) ? String(payload.message) : 'Save failed.' };
                }
                return {
                    success: true,
                    message: String(payload.message || 'Ops Notes saved.'),
                    ops_notes: normalizeOpsNotesValue(payload.ops_notes)
                };
            } catch (error) {
                console.error('Failed to save Ops Notes:', error);
                return { success: false, message: 'Network error while saving Ops Notes.' };
            } finally {
                if (buttonEl) {
                    buttonEl.disabled = false;
                    buttonEl.textContent = originalText || 'Save Ops Notes';
                }
            }
        }

        function formatBytes(bytes) {
            const value = Number(bytes);
            if (!Number.isFinite(value) || value <= 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const idx = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
            const size = value / Math.pow(1024, idx);
            return `${size.toFixed(size >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
        }

        function formatTimestamp(timestamp) {
            if (!timestamp) return '<span class="text-slate-500">Unknown</span>';
            const months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
            // The timestamp from PHP is in seconds, JavaScript Date needs milliseconds.
            const date = new Date(timestamp * 1000);
            const hours = String(date.getHours()).padStart(2, '0');
            const minutes = String(date.getMinutes()).padStart(2, '0');
            const day = String(date.getDate()).padStart(2, '0');
            const month = months[date.getMonth()];
            const year = String(date.getFullYear()).slice(-2);
            return `${hours}:${minutes} ${day}${month}${year}`;
        }

        function formatRelativeAge(timestamp) {
            if (!timestamp) return '';
            const ts = Number(timestamp);
            if (!Number.isFinite(ts)) return '';
            const now = Math.floor(Date.now() / 1000);
            const diff = Math.max(0, now - ts);
            if (diff < 60) return `${diff}s ago`;
            if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
            return `${Math.round(diff / 86400)}d ago`;
        }

        function parseCoord(value, min, max) {
            if (value === null || value === undefined) return null;
            const raw = String(value).trim();
            if (raw === '') return null;
            const num = Number(raw);
            if (!Number.isFinite(num) || num < min || num > max) return null;
            return num;
        }

        function formatCoord(value, min, max, digits = 5) {
            const num = parseCoord(value, min, max);
            return num === null ? '—' : num.toFixed(digits);
        }

        function getPreferredCoords(node) {
            if (!node || typeof node !== 'object') return null;
            const addrLat = parseCoord(node.address_lat, -90, 90);
            const addrLon = parseCoord(node.address_lon, -180, 180);
            const addrValid = addrLat !== null && addrLon !== null;
            const useAddr = !!node.use_address_coords;
            if (useAddr && addrValid) {
                return { lat: addrLat, lon: addrLon, source: 'address' };
            }
            const meshLat = parseCoord(node.latitude, -90, 90);
            const meshLon = parseCoord(node.longitude, -180, 180);
            const meshValid = meshLat !== null && meshLon !== null;
            if (meshValid) {
                return { lat: meshLat, lon: meshLon, source: 'mesh' };
            }
            if (addrValid) {
                return { lat: addrLat, lon: addrLon, source: 'address' };
            }
            return null;
        }

        function getStaleBadge(timestamp) {
            if (!timestamp) return '<span class="last-heard-stale ml-2 text-xs text-slate-500">unknown</span>';
            const ts = Number(timestamp);
            if (!Number.isFinite(ts)) return '';
            if (STALE_NODE_SECONDS <= 0) return '';
            const now = Math.floor(Date.now() / 1000);
            const diff = Math.max(0, now - ts);
            if (diff >= STALE_NODE_SECONDS) {
                return '<span class="last-heard-stale ml-2 text-xs text-red-300">stale</span>';
            }
            return '';
        }

        function getSosRoleDisplay(node) {
            if (!node || typeof node !== 'object') {
                return { text: '', badgeClass: '' };
            }
            if (node.sos_role === 'SENDER') {
                return { text: 'Awaiting Response', badgeClass: 'bg-red-500/30 text-red-100 border border-red-400/40' };
            }
            if (node.sos_role === 'RESPONDER') {
                return { text: 'Responding', badgeClass: 'bg-green-500/30 text-green-100 border border-green-400/40' };
            }
            if (node.sos_role === 'ACKNOWLEDGER') {
                return { text: 'Acknowledged', badgeClass: 'bg-yellow-500/30 text-yellow-100 border border-yellow-300/40' };
            }
            return { text: '', badgeClass: '' };
        }

        function buildNodesSignature(nodes) {
            if (!Array.isArray(nodes)) return '';
            const parts = nodes.map(n => [
                n.node_id || '',
                n.lastHeard || '',
                n.sos || '',
                n.sos_role || '',
                n.name || '',
                n.latitude || '',
                n.longitude || '',
                n.address_lat || '',
                n.address_lon || '',
                n.use_address_coords ? 1 : 0
            ].join('|'));
            parts.sort();
            return `${subscribersMtime}|${parts.join(';')}`;
        }

        function buildPositionsSignature(nodes) {
            if (!Array.isArray(nodes)) return '';
            const parts = [];
            for (const n of nodes) {
                const coords = getPreferredCoords(n);
                if (coords) {
                    const lat = coords.lat.toFixed(5);
                    const lon = coords.lon.toFixed(5);
                    parts.push(`${n.node_id || ''}:${lat},${lon}:${n.sos ? 1 : 0}`);
                }
            }
            parts.sort();
            return parts.join('|');
        }

        // --- MAP FUNCTIONS ---
        const TILE_RADIUS_MILES = 25;
        const EARTH_RADIUS_MILES = 3958.8;

        function getTileBounds(lat, lon, radiusMiles) {
            const latNum = Number(lat);
            const lonNum = Number(lon);
            const radiusNum = Number(radiusMiles);
            if (!Number.isFinite(latNum) || !Number.isFinite(lonNum) || !Number.isFinite(radiusNum) || radiusNum <= 0) {
                return null;
            }
            const latRad = latNum * Math.PI / 180;
            const angularRadius = radiusNum / EARTH_RADIUS_MILES;
            const latDelta = angularRadius * (180 / Math.PI);
            const lonDelta = angularRadius * (180 / Math.PI) / Math.cos(latRad);
            const south = latNum - latDelta;
            const north = latNum + latDelta;
            const west = lonNum - lonDelta;
            const east = lonNum + lonDelta;
            return L.latLngBounds([south, west], [north, east]);
        }
        const defaultIcon = new L.Icon.Default();
        const sosIcon = new L.Icon({
            iconUrl: '/map-items/marker-icon-red.png',
            shadowUrl: '/map-items/marker-shadow.png',
            iconSize: [25, 41],
            iconAnchor: [12, 41],
            popupAnchor: [1, -34],
            shadowSize: [41, 41]
        });

        // --- CORE LIVE DATA & UI UPDATE FUNCTIONS ---
        const sosBanner = document.getElementById('sos-banner');
        const sosBannerText = document.getElementById('sos-banner-text');

        async function updatePageData(forceFresh = false) {
            if (updatePageInFlight && !forceFresh) {
                return updatePageInFlight;
            }
            const requestPromise = (async () => {
                try {
                    const requestHeaders = {};
                    if (!forceFresh && nodesEtag) {
                        requestHeaders['If-None-Match'] = nodesEtag;
                    }
                    const response = await fetch('/map-items/api_get_nodes.php', { headers: requestHeaders });
                    const responseEtag = response.headers.get('ETag');
                    if (responseEtag) {
                        nodesEtag = responseEtag;
                    }
                    if (response.status === 304) {
                        return true;
                    }
                    if (!response.ok) {
                        console.error('Failed to fetch node data. Status:', response.status);
                        return false;
                    }
                    const payload = await response.json();
                    const nodes = payload && payload.nodes ? payload.nodes : payload;
                    if (!Array.isArray(nodes)) return false;
                    if (payload && typeof payload.subscribers_mtime === 'number') {
                        subscribersMtime = payload.subscribers_mtime;
                    }

                    const nodesSignature = buildNodesSignature(nodes);
                    if (nodesSignature === lastNodesSignature) {
                        if (map && Object.keys(nodeMarkers).length === 0 && nodes.length > 0) {
                            updateMapMarkers(nodes);
                        }
                        return true;
                    }
                    lastNodesSignature = nodesSignature;

                    const activeSosIds = new Set(nodes.filter(n => n.sos).map(n => n.node_id));
                    acknowledgedSosNodes.forEach(nodeId => {
                        if (!activeSosIds.has(nodeId)) {
                            acknowledgedSosNodes.delete(nodeId);
                        }
                    });

                    updateNodeList(nodes);
                    updateSosBanner(nodes);
                    updateMapMarkers(nodes);
                    return true;

                } catch (error) {
                    console.error('Error fetching node data:', error);
                    return false;
                }
            })();
            updatePageInFlight = requestPromise;
            try {
                return await requestPromise;
            } finally {
                if (updatePageInFlight === requestPromise) {
                    updatePageInFlight = null;
                }
            }
        }

        function updateNodeList(nodes) {
            const mainNodeListBody = document.getElementById('node-list-body');
            const mainNodeListCount = document.getElementById('node-list-count');
            const sosNodeListBody = document.getElementById('sos-node-list-body');

            // Update main list on Status tab
            if (mainNodeListBody && mainNodeListCount) {
                mainNodeListCount.textContent = nodes.length;
                renderHierarchicalList(mainNodeListBody, nodes);
            }

            // Update filtered list on Actions tab
            if (sosNodeListBody) {
                const sosInvolvedNodes = nodes.filter(n => n.sos_role !== 'NONE');
                renderHierarchicalList(sosNodeListBody, sosInvolvedNodes, true);
            }
        }

        function renderHierarchicalList(tbodyElement, nodes, isSosOnly = false) {
            if (!nodes || nodes.length === 0) {
                const message = isSosOnly ? 'No active SOS events or responders.' : 'No live node data available.';
                tbodyElement.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-slate-500">${message}</td></tr>`;
                return;
            }

            const rows = [];
            let sosSenders = nodes.filter(n => n.sos_role === 'SENDER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
            let otherNodes = nodes.filter(n => n.sos_role !== 'SENDER');

            if (sosSenders.length === 0) {
                // No active SOS, sort normally by lastHeard
                otherNodes.sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                otherNodes.forEach(node => rows.push(generateNodeRow(node)));
            } else {
                // Active SOS exists, render hierarchically
                const participantMap = new Map();
                otherNodes.forEach(node => {
                    if (node.sos_parent) {
                        if (!participantMap.has(node.sos_parent)) {
                            participantMap.set(node.sos_parent, []);
                        }
                        participantMap.get(node.sos_parent).push(node);
                    }
                });

                sosSenders.forEach(sender => {
                    rows.push(generateNodeRow(sender));
                    if (sender.sos_message_payload) {
                        rows.push(generateMessageRow(sender.sos_message_payload));
                    }

                    const participants = participantMap.get(sender.node_id) || [];
                    const responders = participants.filter(p => p.sos_role === 'RESPONDER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                    const ackers = participants.filter(p => p.sos_role === 'ACKNOWLEDGER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));

                    responders.forEach(r => rows.push(generateNodeRow(r, 'pl-8')));
                    ackers.forEach(a => rows.push(generateNodeRow(a, 'pl-8')));
                });

                // On the main list, also show nodes not involved in any SOS
                if (!isSosOnly) {
                    const nonParticipants = otherNodes.filter(n => !n.sos_parent).sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                    if (nonParticipants.length > 0 && sosSenders.length > 0) {
                        rows.push(`<tr><td colspan="7" class="p-2 border-t-2 border-slate-700"></td></tr>`);
                    }
                    nonParticipants.forEach(node => rows.push(generateNodeRow(node)));
                }
            }
            tbodyElement.innerHTML = rows.join('');
        }

        function generateNodeRow(node, indentClass = '') {
            let rowClass = 'hover:bg-black/20';
            if (node.sos_role === 'SENDER') rowClass = 'bg-red-900/50 font-bold';
            if (node.sos_role === 'RESPONDER') rowClass = 'bg-green-900/50';
            if (node.sos_role === 'ACKNOWLEDGER') rowClass = 'bg-yellow-900/50 text-slate-200';
            const sosRoleDisplay = getSosRoleDisplay(node);
            const sosRoleBadge = sosRoleDisplay.text
                ? `<span class="inline-block rounded-full px-2 py-0.5 text-xs font-semibold ml-2 ${sosRoleDisplay.badgeClass}">${escapeHTML(sosRoleDisplay.text)}</span>`
                : '';
            const lastHeardTs = node.lastHeard || '';
            const lastHeardAge = formatRelativeAge(lastHeardTs);
                if (lastHeardTs && STALE_NODE_SECONDS > 0) {
                    const now = Math.floor(Date.now() / 1000);
                    if ((now - Number(lastHeardTs)) >= STALE_NODE_SECONDS) {
                        rowClass += ' opacity-75';
                    }
                }
            let standDownForm = '';
            if (node.sos_role === 'SENDER') {
                standDownForm = `
                    <form method="POST" class="inline-block mr-2 stand-down-form">
                        <input type="hidden" name="csrf_token" value="${csrfToken}">
                        <input type="hidden" name="action" value="admin_clear_sos">
                        <input type="hidden" name="node_id" value="${escapeHTML(node.node_id)}">
                        <button type="submit" class="btn btn-red btn-sm" title="Clear this SOS alert.">STAND DOWN</button>
                    </form>
                `;
            }
            const sosIndicator = node.sos ? `<span class="inline-block bg-red-500 text-white font-bold rounded-full px-2 py-1 text-xs mr-2">🆘 ${escapeHTML(node.sos)}</span>` : '';
            const coords = getPreferredCoords(node);
            const hasPosition = !!coords;
            const locationButton = hasPosition ? `<button class="btn btn-secondary btn-sm location-btn" data-lat="${coords.lat}" data-lon="${coords.lon}">Map It</button>` : '';
            const position = hasPosition ? `${coords.lat.toFixed(4)}, ${coords.lon.toFixed(4)}` : '<span class="text-slate-600">N/A</span>';
            const staleBadge = getStaleBadge(lastHeardTs);
            return `
                <tr class="${rowClass}" data-last-heard="${escapeHTML(String(lastHeardTs))}">
                    <td class="p-3 font-mono ${indentClass}">${standDownForm}${sosIndicator}<button type="button" class="text-blue-400 hover:text-blue-300 open-dm-chat" data-node-id="${escapeHTML(node.node_id)}" data-node-name="${escapeHTML(node.name || node.node_id)}">${escapeHTML(node.node_id)}</button>${node.name ? `<span class="text-slate-400 font-sans ml-2">(${escapeHTML(node.name)})</span>` : ''}${sosRoleBadge}</td>
                    <td class="p-3 font-mono text-sm"><span class="last-heard" data-ts="${escapeHTML(String(lastHeardTs))}">${formatTimestamp(lastHeardTs)}</span><span class="last-heard-age ml-2 text-xs text-slate-400">${escapeHTML(lastHeardAge)}</span>${staleBadge}</td>
                    <td class="p-3">${escapeHTML(String(node.snr ?? ''))}</td>
                    <td class="p-3">${escapeHTML(String(node.hopsAway ?? ''))}</td>
                    <td class="p-3 font-mono text-xs p-1 rounded bg-slate-700 text-slate-300">${escapeHTML(node.role)}</td>
                    <td class="p-3 font-mono text-sm">${position}</td>
                    <td class="p-3">${locationButton}</td>
                </tr>`;
        }

        function generateMessageRow(message) {
            return `
                <tr class="bg-red-900/30">
                    <td colspan="7" class="p-3 text-red-200 text-left pl-8 text-sm border-t-2 border-red-500/50">
                        <strong>Message:</strong> ${escapeHTML(message)}
                    </td>
                </tr>`;
        }

        function updateSosBanner(nodes) {
            if (!sosBanner || !sosBannerText) return;
            activeSosNodeId = null; // Reset
            const activeSosNode = nodes.find(node => node.sos && !acknowledgedSosNodes.has(node.node_id));

            if (activeSosNode) {
                activeSosNodeId = activeSosNode.node_id;
                const name = activeSosNode.full_name || activeSosNode.name || activeSosNode.node_id;
                sosBannerText.textContent = `🚨 ACTIVE ALERT: ${escapeHTML(activeSosNode.sos)} from ${escapeHTML(name)} 🚨`;
                sosBanner.style.display = 'flex';
            } else {
                sosBanner.style.display = 'none';
            }
        }

        function updateMapMarkers(nodes) {
            if (!map) return;
            let nodesOnMap = new Set();
            let markersToBound = [];
            let positionsSignature = buildPositionsSignature(nodes);
            const positionsChanged = positionsSignature !== lastPositionsSignature;

            nodes.forEach(node => {
                const coords = getPreferredCoords(node);
                if (coords) {
                    const node_id = node.node_id;
                    const pos = [coords.lat, coords.lon];
                    nodesOnMap.add(node_id);
                    const sosRoleDisplay = getSosRoleDisplay(node);

                    if (autoFitEnabled) {
                        markersToBound.push(pos);
                    }

                    let addressHtml = '';
                    if (node.address && (node.address.street || node.address.city)) {
                        addressHtml = `<hr class="popup-hr"><strong>Address:</strong><br>${escapeHTML(node.address.street || '')}<br>${escapeHTML(node.address.city || '')}, ${escapeHTML(node.address.state || '')} ${escapeHTML(node.address.zip || '')}`;
                    }
                    const sosStatusHtml = sosRoleDisplay.text ? `<hr class="popup-hr"><strong>SOS Status:</strong> ${escapeHTML(sosRoleDisplay.text)}` : '';
                    const phones = [node.phone_1, node.phone_2].filter(Boolean).map(escapeHTML).join('<br>');
                    let phonesHtml = phones ? `<hr class="popup-hr"><strong>Phone:</strong><br>${phones}` : '';
                    let emailHtml = node.email ? `<hr class="popup-hr"><strong>Email:</strong> ${escapeHTML(node.email)}` : '';
                    let notesHtml = node.notes ? `<hr class="popup-hr"><strong>Notes:</strong><br><div style="max-height: 60px; overflow-y: auto;">${escapeHTML(node.notes)}</div>` : '';
                    const opsNotesHtml = `<hr class="popup-hr"><strong>Ops Notes:</strong>${renderOpsNotesEditorHtml(node.node_id, node.ops_notes)}`;

                    const popupContent = `
                        <div class="font-sans text-sm" style="max-width: 250px;">
                            <strong>${escapeHTML(node.node_id)} / ${escapeHTML(node.name || 'N/A')}</strong>
                            <hr class="popup-hr">
                            ${escapeHTML(node.full_name || 'No full name provided.')}
                            ${sosStatusHtml}
                            ${phonesHtml}
                            ${emailHtml}
                            ${addressHtml}
                            ${notesHtml}
                            ${opsNotesHtml}
                        </div>
                    `;

                    const icon = node.sos ? sosIcon : defaultIcon;
                    const baseLabel = escapeHTML(node.name || node.node_id);
                    const labelContent = sosRoleDisplay.text ? `${baseLabel} - ${escapeHTML(sosRoleDisplay.text)}` : baseLabel;
                    const normalTooltipOptions = { permanent: true, direction: 'top', className: 'map-node-label', offset: [-15, -5] };
                    const sosTooltipOptions = { permanent: true, direction: 'top', className: 'map-node-label', offset: [2, -33] };

                    if (nodeMarkers[node_id]) {
                        const marker = nodeMarkers[node_id];
                        const meta = nodeMarkersMeta[node_id] || {};
                        const iconChanged = meta.sos !== !!node.sos;
                        const posChanged = meta.lat !== coords.lat || meta.lon !== coords.lon;
                        const labelChanged = meta.label !== labelContent;

                        if (posChanged) {
                            marker.setLatLng(pos);
                        }
                        if (iconChanged) {
                            marker.setIcon(icon);
                        }
                        if (labelChanged) {
                            marker.unbindTooltip().bindTooltip(labelContent, node.sos ? sosTooltipOptions : normalTooltipOptions);
                        }
                        marker.setPopupContent(popupContent);
                    } else {
                        nodeMarkers[node_id] = L.marker(pos, { icon: icon }).addTo(map).bindPopup(popupContent).bindTooltip(labelContent, node.sos ? sosTooltipOptions : normalTooltipOptions)
                            .on('click', (e) => { autoFitEnabled = false; map.setView(e.latlng, map.getZoom()); })
                            .on('popupclose', () => { autoFitEnabled = true; });
                    }
                    nodeMarkersMeta[node_id] = { lat: coords.lat, lon: coords.lon, sos: !!node.sos, label: labelContent };
                }
            });

            for (const node_id in nodeMarkers) {
                if (!nodesOnMap.has(node_id)) {
                    map.removeLayer(nodeMarkers[node_id]);
                    delete nodeMarkers[node_id];
                    delete nodeMarkersMeta[node_id];
                }
            }

            if (autoFitEnabled && markersToBound.length > 0 && positionsChanged) {
                map.fitBounds(markersToBound, { padding: [50, 50], maxZoom: 16, animate: false });
            }
            lastPositionsSignature = positionsSignature;
        }
        
        // --- CHAT FUNCTIONS ---
        let lastFetchedMessages = [];
        let chatMessageKeys = new Set();
        let lastFetchedSubscribers = {};
        let subscriberNameTargets = new Set();
        let localUserDirectory = Object.create(null);
        let userEditButtonsByNodeId = Object.create(null);

        function getChatMessageKey(message) {
            if (!message || typeof message !== 'object') {
                return '';
            }
            if (message._optimistic_token) {
                return `optimistic:${String(message._optimistic_token)}`;
            }
            const numericId = Number(message.id);
            if (Number.isFinite(numericId) && numericId > 0) {
                return `id:${Math.trunc(numericId)}`;
            }
            const from = String(message.from || '');
            const text = String(message.text || '');
            const timestamp = String(message.timestamp || '');
            const isDm = !!message.is_dm ? '1' : '0';
            return `fallback:${from}|${timestamp}|${isDm}|${text}`;
        }

        function applyChatPayload(data, forceRender = false) {
            if (!data || typeof data !== 'object') return false;

            let messagesChanged = false;
            let subscribersChanged = false;
            let groupsChanged = false;

            const total = typeof data.total === 'number' ? data.total : chatCursor;
            if (total < chatCursor) {
                lastFetchedMessages = [];
                chatMessageKeys = new Set();
                chatCursor = 0;
                messagesChanged = true;
            }

            const messages = Array.isArray(data.messages) ? data.messages : [];
            if (messages.length > 0) {
                const incomingGatewayTexts = new Set(
                    messages
                        .filter((msg) => msg && msg.from === 'GATEWAY')
                        .map((msg) => String(msg.text || ''))
                );
                if (incomingGatewayTexts.size > 0) {
                    const beforeCount = lastFetchedMessages.length;
                    lastFetchedMessages = lastFetchedMessages.filter((msg) => {
                        if (!msg || !msg._optimistic || msg.from !== 'GATEWAY') return true;
                        return !incomingGatewayTexts.has(String(msg.text || ''));
                    });
                    if (lastFetchedMessages.length !== beforeCount) {
                        chatMessageKeys = new Set(lastFetchedMessages.map(getChatMessageKey).filter(Boolean));
                        messagesChanged = true;
                    }
                }
                const dedupedIncoming = [];
                for (const msg of messages) {
                    const key = getChatMessageKey(msg);
                    if (key && chatMessageKeys.has(key)) {
                        continue;
                    }
                    if (key) {
                        chatMessageKeys.add(key);
                    }
                    dedupedIncoming.push(msg);
                }
                if (dedupedIncoming.length > 0) {
                    lastFetchedMessages = lastFetchedMessages.concat(dedupedIncoming);
                    if (lastFetchedMessages.length > 200) {
                        lastFetchedMessages = lastFetchedMessages.slice(-200);
                        chatMessageKeys = new Set(lastFetchedMessages.map(getChatMessageKey).filter(Boolean));
                    }
                    messagesChanged = true;
                }
                chatCursor = total;
            }

            if (data.subscribers_included) {
                if (data.subscribers && typeof data.subscribers === 'object' && !Array.isArray(data.subscribers)) {
                    lastFetchedSubscribers = data.subscribers || {};
                } else {
                    lastFetchedSubscribers = {};
                }
                subscriberNameTargets = new Set(
                    Object.values(lastFetchedSubscribers || {})
                        .map((user) => normalizeTagName(user?.name))
                        .filter(Boolean)
                );
                subscribersChanged = true;
            }

            if (typeof data.subscribers_mtime === 'number') {
                chatSubscribersMtime = data.subscribers_mtime;
            }

            if (typeof data.temp_groups_token === 'string') {
                chatTempGroupsToken = data.temp_groups_token;
            }

            const groupsPayloadIncluded = data.temp_groups_included === true || (!('temp_groups_included' in data) && Array.isArray(data.temp_groups));
            if (groupsPayloadIncluded && Array.isArray(data.temp_groups)) {
                const nextSignature = JSON.stringify(data.temp_groups.map(group => [
                    String(group.group_name || '').toUpperCase(),
                    !!group.locked
                ]));
                if (nextSignature !== chatGroupSignature || forceRender) {
                    chatGroupSignature = nextSignature;
                    lastFetchedTempGroups = data.temp_groups;
                    groupsChanged = true;
                }
            }

            const shouldRender = forceRender || messagesChanged || subscribersChanged || groupsChanged;
            if (!shouldRender) {
                return false;
            }

            if (subscribersChanged || groupsChanged || forceRender) {
                renderChatGroupTabs();
            }
            renderAllChats();
            const chatWindow = document.getElementById('chat-window');
            if (chatWindow && (chatWindow.scrollHeight - chatWindow.clientHeight <= chatWindow.scrollTop + 50)) {
                chatWindow.scrollTop = chatWindow.scrollHeight;
            }
            return true;
        }

        function scheduleChatStreamRetry(delayMs = CHAT_STREAM_RETRY_MS) {
            if (!CHAT_STREAM_ENABLED) return;
            if (!isPollingActive || !isChatPolling) return;
            if (chatStreamRetryTimer) {
                clearTimeout(chatStreamRetryTimer);
            }
            chatStreamRetryTimer = setTimeout(() => {
                chatStreamRetryTimer = null;
                startChatStream();
            }, delayMs);
        }

        function stopChatStream() {
            if (chatStreamRetryTimer) {
                clearTimeout(chatStreamRetryTimer);
                chatStreamRetryTimer = null;
            }
            if (chatStreamSource) {
                chatStreamSource.close();
                chatStreamSource = null;
            }
            chatStreamConnected = false;
        }

        function startChatStream() {
            if (!CHAT_STREAM_ENABLED) return;
            if (!isPollingActive || !isChatPolling) return;
            if (chatStreamSource) return;

            const params = new URLSearchParams({
                after: String(chatCursor),
                with_subscribers: '1',
                subscribers_mtime: String(chatSubscribersMtime),
                temp_groups_token: String(chatTempGroupsToken),
                timeout_ms: String(CHAT_STREAM_TIMEOUT_MS)
            });
            const streamUrl = `/map-items/api_get_chat_stream.php?${params.toString()}`;
            const stream = new EventSource(streamUrl);
            chatStreamSource = stream;
            chatStreamConnected = false;

            const restartStream = (delayMs) => {
                if (chatStreamSource !== stream) return;
                stream.close();
                chatStreamSource = null;
                chatStreamConnected = false;
                scheduleChatStreamRetry(delayMs);
            };

            stream.onopen = () => {
                chatStreamConnected = true;
            };
            stream.addEventListener('chat', (event) => {
                try {
                    const data = JSON.parse(event.data || '{}');
                    applyChatPayload(data);
                } catch (error) {
                    console.error('Invalid SSE chat payload:', error);
                }
                restartStream(25);
            });
            stream.addEventListener('heartbeat', () => {
                restartStream(25);
            });
            stream.onerror = () => {
                restartStream(CHAT_STREAM_RETRY_MS);
            };
        }

        async function loadChatData() {
            try {
                const params = new URLSearchParams({
                    after: chatCursor,
                    with_subscribers: '1',
                    subscribers_mtime: String(chatSubscribersMtime),
                    temp_groups_token: String(chatTempGroupsToken)
                });
                const requestHeaders = {};
                if (chatEtag) {
                    requestHeaders['If-None-Match'] = chatEtag;
                }
                const response = await fetch(`/map-items/api_get_chat.php?${params.toString()}`, { headers: requestHeaders });
                const responseEtag = response.headers.get('ETag');
                if (responseEtag) {
                    chatEtag = responseEtag;
                }
                if (response.status === 304) {
                    renderAllChats();
                    return;
                }
                if (!response.ok) {
                    console.error('Failed to fetch chat data on demand. Status:', response.status);
                    dmChatContainer.innerHTML = `<div class="text-center text-red-400 py-16"><p>Error loading messages.</p></div>`;
                    return;
                }
                const data = await response.json();
                applyChatPayload(data, true);
            } catch (error) {
                console.error('Error in loadChatData:', error);
                dmChatContainer.innerHTML = `<div class="text-center text-red-400 py-16"><p>Error loading messages.</p></div>`;
            }
        }

        async function updateChat() {
            if (updateChatInFlight) {
                return updateChatInFlight;
            }
            const requestPromise = (async () => {
                try {
                    const params = new URLSearchParams({
                        after: chatCursor,
                        with_subscribers: '1',
                        subscribers_mtime: String(chatSubscribersMtime),
                        temp_groups_token: String(chatTempGroupsToken)
                    });
                    const requestHeaders = {};
                    if (chatEtag) {
                        requestHeaders['If-None-Match'] = chatEtag;
                    }
                    const response = await fetch(`/map-items/api_get_chat.php?${params.toString()}`, { headers: requestHeaders });
                    const responseEtag = response.headers.get('ETag');
                    if (responseEtag) {
                        chatEtag = responseEtag;
                    }
                    if (response.status === 304) {
                        return true;
                    }
                    if (!response.ok) {
                        console.error('Failed to fetch chat data. Status:', response.status);
                        return false;
                    }
                    const data = await response.json();
                    return applyChatPayload(data);
                } catch (error) {
                    console.error('Error updating chat:', error);
                    return false;
                }
            })();
            updateChatInFlight = requestPromise;
            try {
                return await requestPromise;
            } finally {
                if (updateChatInFlight === requestPromise) {
                    updateChatInFlight = null;
                }
            }
        }

        // --- "JUST IN TIME" INITIALIZATION & TAB LOGIC ---
        function initStatusTab() {
            if (!isStatusTabInitialized) {
                isStatusTabInitialized = true;
                if (document.getElementById('map') && !map) {
                    const tileBounds = getTileBounds(GATEWAY_LAT, GATEWAY_LON, TILE_RADIUS_MILES);
                    const mapOptions = { minZoom: 10 };
                    if (tileBounds) {
                        mapOptions.maxBounds = tileBounds;
                        mapOptions.maxBoundsViscosity = 1.0;
                    }
                    map = L.map('map', mapOptions).setView([GATEWAY_LAT, GATEWAY_LON], 13);
                    const tileUrl = '/map-items/map-tiles/{z}/{x}/{y}.png';
                    const errorTileUrl = '/map-items/missing_tile.png';
                    const tileLayerOptions = {
                        maxZoom: 18,
                        maxNativeZoom: 16,
                        minZoom: 10,
                        attribution: '&copy; OpenStreetMap',
                        errorTileUrl: errorTileUrl
                    };
                    if (tileBounds) {
                        tileLayerOptions.bounds = tileBounds;
                    }
                    const tileLayer = L.tileLayer(tileUrl, tileLayerOptions);
                    const applyBoundsMinZoom = () => {
                        if (!tileBounds) return;
                        const minBoundsZoom = map.getBoundsZoom(tileBounds, false);
                        const effectiveMinZoom = Math.max(10, minBoundsZoom);
                        map.setMinZoom(effectiveMinZoom);
                        if (map.getZoom() < effectiveMinZoom) {
                            map.setZoom(effectiveMinZoom);
                        }
                    };
                    applyBoundsMinZoom();
                    tileLayer.on('tileerror', (e) => {
                        const src = e && e.tile ? e.tile.src : 'unknown';
                        console.warn('Map tile failed to load:', src);
                    });
                    tileLayer.addTo(map);
                    setTimeout(() => {
                        map.invalidateSize();
                        applyBoundsMinZoom();
                        map.setView([GATEWAY_LAT, GATEWAY_LON], map.getZoom());
                    }, 150);
                }
                setInterval(refreshLastHeardAges, 30000);
            }
            isPollingActive = true;
            startStatusPolling();
        }

        function initChatTab() {
            if (!isChatTabInitialized) {
                isChatTabInitialized = true;
            }
            isPollingActive = true;
            renderChatGroupTabs();
            renderFilteredChat();
            void updateChat();
            startChatPolling();
        }

        const tabs = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');
        tabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                tabs.forEach(t => t.classList.remove('active'));
                tabContents.forEach(c => c.style.display = 'none');
                
                tab.classList.add('active');
                const contentId = tab.dataset.tab + '-content';
                document.getElementById(contentId).style.display = 'block';

                isPollingActive = false;
                stopStatusPolling();
                stopChatPolling();
                if (tab.dataset.tab === 'status') {
                initStatusTab();
                if(map) setTimeout(() => map.invalidateSize(), 10);
                } else if (tab.dataset.tab === 'chat') {
                    initChatTab();
                } else if (tab.dataset.tab === 'actions') {
                    // Fetch blocklist when the actions tab is viewed
                    fetchBlocklist();
                } else if (tab.dataset.tab === 'users') {
                    void ensureMapUsersTableLoaded(false);
                }
            });
        });

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                isPollingActive = false;
                stopStatusPolling();
                stopChatPolling();
                return;
            }
            const activeTab = document.querySelector('.tab-button.active')?.dataset?.tab || '';
            if (activeTab === 'status') {
                isPollingActive = true;
                startStatusPolling();
            } else if (activeTab === 'chat') {
                isPollingActive = true;
                startChatPolling();
            }
        });

        // --- NEW: Blocklist Management Functions ---
    const blocklistContainer = document.getElementById('blocklist-container');
    const addBlocklistForm = document.getElementById('add-to-blocklist-form');
    const newBlockedEmailInput = document.getElementById('new-blocked-email');

    async function fetchBlocklist() {
        try {
            const response = await fetch('/map-items/api_manage_blocklist.php?action=get_blocklist');
            if (!response.ok) {
                renderBlocklistError('Failed to fetch blocklist from server.');
                return;
            }
            const data = await response.json();
            if (data.success) {
                renderBlocklist(data.blocklist);
            } else {
                renderBlocklistError(data.message || 'An unknown error occurred.');
            }
        } catch (error) {
            renderBlocklistError('Error connecting to the server.');
            console.error('Fetch Blocklist Error:', error);
        }
    }

    function renderBlocklist(emails) {
        blocklistContainer.innerHTML = '';
        if (!emails || emails.length === 0) {
            blocklistContainer.innerHTML = '<p class="text-slate-500">The email blocklist is empty.</p>';
            return;
        }
        emails.forEach(email => {
            const emailEl = document.createElement('div');
            emailEl.className = 'bg-black/20 p-2 rounded text-sm flex justify-between items-center';
            emailEl.innerHTML = `
                <span class="font-mono text-slate-300">${escapeHTML(email)}</span>
                <button type="button" class="btn btn-red btn-sm remove-email-btn" data-email="${escapeHTML(email)}">Remove</button>
            `;
            blocklistContainer.appendChild(emailEl);
        });
    }

    function renderBlocklistError(message) {
        blocklistContainer.innerHTML = `<p class="text-red-400">${escapeHTML(message)}</p>`;
    }

    async function addBlockedEmail(email) {
        const formData = new FormData();
        formData.append('action', 'add_to_blocklist');
        formData.append('email', email);
        formData.append('csrf_token', csrfToken);

        try {
            const response = await fetch('/map-items/api_manage_blocklist.php', { method: 'POST', body: formData });
            const data = await response.json();
            if (!data.success) {
                alert('Error: ' + data.message);
            }
            fetchBlocklist(); // Refresh the list
        } catch (error) {
            alert('An error occurred while adding the email.');
            console.error('Add Email Error:', error);
        }
    }

    async function removeBlockedEmail(email) {
        const formData = new FormData();
        formData.append('action', 'remove_from_blocklist');
        formData.append('email', email);
        formData.append('csrf_token', csrfToken);

        try {
            const response = await fetch('/map-items/api_manage_blocklist.php', { method: 'POST', body: formData });
            const data = await response.json();
            if (!data.success) {
                alert('Error: ' + data.message);
            }
            fetchBlocklist(); // Refresh the list
        } catch (error) {
            alert('An error occurred while removing the email.');
            console.error('Remove Email Error:', error);
        }
    }

    addBlocklistForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const emailToAdd = newBlockedEmailInput.value.trim();
        if (emailToAdd) {
            addBlockedEmail(emailToAdd);
            newBlockedEmailInput.value = '';
        }
    });

    blocklistContainer.addEventListener('click', function(e) {
        if (e.target.classList.contains('remove-email-btn')) {
            const emailToRemove = e.target.dataset.email;
            if (emailToRemove && confirm(`Are you sure you want to unblock "${emailToRemove}"?`)) {
                removeBlockedEmail(emailToRemove);
            }
        }
    });

        initStatusTab();

        const sosBannerCloseBtn = document.getElementById('sos-banner-close');
        sosBannerCloseBtn?.addEventListener('click', () => {
            if (activeSosNodeId) {
                acknowledgedSosNodes.add(activeSosNodeId);
            }
            sosBanner.style.display = 'none';
        });

        const confirmModal = document.getElementById('confirm-action-modal');
        const confirmModalText = document.getElementById('confirm-modal-text');
        const confirmBtn = document.getElementById('confirm-modal-confirm-btn');
        const cancelBtn = document.getElementById('confirm-modal-cancel-btn');
        let formToSubmit = null;
        function showConfirmModal(message, formElement) {
            formToSubmit = formElement;
            confirmModalText.innerHTML = message;
            confirmModal.style.display = 'flex';
        }
        function hideConfirmModal() {
            confirmModal.style.display = 'none';
            formToSubmit = null;
        }
        confirmBtn.addEventListener('click', () => { if (formToSubmit) { formToSubmit.submit(); } hideConfirmModal(); });
        cancelBtn.addEventListener('click', hideConfirmModal);

        document.querySelectorAll('.collapse-toggle').forEach(btn => {
            btn.addEventListener('click', function() {
                const targetId = this.getAttribute('data-target');
                const target = document.getElementById(targetId);
                if (!target) {
                    return;
                }
                const isHidden = target.style.display === 'none';
                target.style.display = isHidden ? '' : 'none';
                this.textContent = isHidden ? 'Collapse' : 'Expand';
                this.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
            });
        });
        
        document.querySelectorAll('form[method="POST"]').forEach(form => {
            form.addEventListener('submit', function(e) {
                if (['clear-chat-history-form', 'broadcast-modal-delete-form', 'user-modal-delete-form', 'save-settings-form', 'clear-email-queue-form', 'clear-email-quarantine-form', 'clear-dead-letter-queue-form', 'export-email-quarantine-form', 'clear-sos-log-form', 'admin-clear-sos-form', 'db-maintenance-form', 'auto-backup-settings-form'].includes(form.id)) {
                    return;
                }
                let confirmationMessage = 'Are you sure you want to proceed?';
                if (form.querySelector('input[name="action"][value="delete_user"]')) {
                    confirmationMessage = 'Are you sure you want to permanently delete this user?';
                } else if (form.querySelector('input[name="action"][value="delete_dead_letter_command"]')) {
                    confirmationMessage = 'Delete this dead-letter row and remove its quarantined file (if found)?';
                } else if (form.querySelector('input[name="action"][value="requeue_dead_letter_command"]')) {
                    confirmationMessage = 'Requeue this dead-letter command for processing now?';
                }
                e.preventDefault();
                showConfirmModal(confirmationMessage, this);
            });
        });

        const clearChatForm = document.getElementById('clear-chat-history-form');
        if(clearChatForm) { clearChatForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to permanently delete the entire chat history? This cannot be undone.', this); }); }
        
        const clearEmailQueueForm = document.getElementById('clear-email-queue-form');
        if(clearEmailQueueForm) { clearEmailQueueForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to clear the outgoing email queue?', this); }); }
        const clearEmailQuarantineForm = document.getElementById('clear-email-quarantine-form');
        if(clearEmailQuarantineForm) { clearEmailQuarantineForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to clear the outgoing email quarantine?', this); }); }
        const clearDeadLetterQueueForm = document.getElementById('clear-dead-letter-queue-form');
        if(clearDeadLetterQueueForm) { clearDeadLetterQueueForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to clear all dead-letter DB rows? Quarantined files will remain on disk unless deleted individually.', this); }); }
        
        const clearSosForm = document.getElementById('clear-sos-log-form');
        if(clearSosForm) { clearSosForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to permanently delete the SOS log? This action cannot be undone.', this); }); }
        
        const adminClearSosForm = document.getElementById('admin-clear-sos-form');
        if(adminClearSosForm) { adminClearSosForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('This will trigger the full stand-down protocol for the active SOS. Proceed?', this); }); }

        const broadcastDeleteForm = document.getElementById('broadcast-modal-delete-form');
        if (broadcastDeleteForm) { broadcastDeleteForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to permanently delete this broadcast job?', this); }); }

        const userDeleteForm = document.getElementById('user-modal-delete-form');
        if (userDeleteForm) { userDeleteForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to permanently delete this user? This action cannot be undone.', this); }); }

        const dbMaintenanceForm = document.getElementById('db-maintenance-form');
        const dbMaintenanceButtons = document.querySelectorAll('.db-maintenance-btn');
        if (dbMaintenanceForm && dbMaintenanceButtons.length) {
            const maintenanceActionInput = document.getElementById('maintenance_action_input');
            dbMaintenanceButtons.forEach((btn) => {
                btn.addEventListener('click', function(e) {
                    e.preventDefault();
                    const action = this.getAttribute('data-action') || '';
                    const message = this.getAttribute('data-confirm') || 'Are you sure you want to proceed?';
                    if (maintenanceActionInput) {
                        maintenanceActionInput.value = action;
                    }
                    showConfirmModal(message, dbMaintenanceForm);
                });
            });
        }

        document.body.addEventListener('submit', function(e) {
            if (e.target.matches('.stand-down-form')) {
                e.preventDefault();
                showConfirmModal('Are you sure you want to stand down this SOS alert? This will clear the alert and notify all responders.', e.target);
            }
        });
        function toggleJobFields(form) {
            if (!form) return;
            const selector = form.querySelector('.job-type-selector');
            if (!selector) return;
            const type = selector.value;
            const recurringFields = form.querySelector('.recurring-fields');
            const eventFields = form.querySelector('.event-fields');
            if (!recurringFields || !eventFields) return;
            if (type === 'recurring') {
                recurringFields.style.display = 'block'; eventFields.style.display = 'none';
                recurringFields.querySelectorAll('input, select').forEach(el => el.disabled = false);
                eventFields.querySelectorAll('input, select').forEach(el => el.disabled = true);
                recurringFields.querySelectorAll('input[type="time"]').forEach(el => el.required = true);
                eventFields.querySelectorAll('input[type="datetime-local"]').forEach(el => el.required = false);
            } else {
                recurringFields.style.display = 'none'; eventFields.style.display = 'block';
                recurringFields.querySelectorAll('input, select').forEach(el => el.disabled = true);
                eventFields.querySelectorAll('input, select').forEach(el => el.disabled = false);
                recurringFields.querySelectorAll('input[type="time"]').forEach(el => el.required = false);
                eventFields.querySelectorAll('input[type="datetime-local"]').forEach(el => el.required = true);
            }
        }
        const broadcastEditForm = document.getElementById('broadcast-edit-form');
        if (broadcastEditForm) {
            toggleJobFields(broadcastEditForm);
            const selector = broadcastEditForm.querySelector('.job-type-selector');
            if (selector) { selector.addEventListener('change', () => toggleJobFields(broadcastEditForm)); }
        }

        const serverMessagePrefixes = ['☀️', '🔮', '⚡️', '🗓️', '📧', '🤖', '☁️', '🆘'];
        const mainChatTextarea = document.getElementById('main-chat-textarea');
        const mainChatSendBtn = document.getElementById('main-chat-send-btn');
        const mainChatBellBtn = document.getElementById('main-chat-bell-btn');
        const dmModal = document.getElementById('dm-chat-modal');
        const dmChatTitle = document.getElementById('dm-chat-title');
        const dmChatWindow = document.getElementById('dm-chat-window');
        const dmChatContainer = document.getElementById('dm-chat-messages-container');
        const dmChatForm = document.getElementById('dm-chat-form');
        const dmChatTextarea = document.getElementById('dm-chat-textarea');
        const dmChatSendBtn = document.getElementById('dm-chat-send-btn');
        const dmChatBellBtn = document.getElementById('dm-chat-bell-btn');
        const dmChatUserBtn = document.getElementById('dm-chat-user-btn');
        const dmTargetNodeIdInput = document.getElementById('dm-target-node-id-input');
        const closeDmModalBtn = document.getElementById('close-dm-modal-btn');
        const userEditModal = document.getElementById('user-edit-modal');
        const userEditForm = document.getElementById('user-edit-form');
        const closeUserModalBtnHeader = document.getElementById('close-user-modal-btn');
        const closeUserModalBtnFooter = document.getElementById('close-user-modal-btn-footer');
        const userModalTitle = document.getElementById('user-modal-title').querySelector('span');
        const broadcastEditModal = document.getElementById('broadcast-edit-modal');
        const closeBroadcastModalBtnHeader = document.getElementById('close-broadcast-modal-btn');
        const closeBroadcastModalBtnFooter = document.getElementById('close-broadcast-modal-btn-footer');
        const clearUserPasswordForm = document.getElementById('clear-user-password-form');
        
        // --- EVENT LISTENERS FOR CHAT FILTERS ---
        document.getElementById('show-dms-checkbox')?.addEventListener('change', renderFilteredChat);
        document.getElementById('show-sms-checkbox')?.addEventListener('change', renderFilteredChat);

        function normalizeTagName(value) {
            return String(value || '').trim().toUpperCase();
        }

        function buildChatGroupList() {
            const channelGroup = [{ name: CHAT_GROUP_CHANNEL, type: 'channel', locked: false }];
            const regularTags = new Set();
            Object.values(lastFetchedSubscribers || {}).forEach((userData) => {
                const tags = Array.isArray(userData?.tags) ? userData.tags : [];
                tags.forEach((tag) => {
                    const normalized = normalizeTagName(tag);
                    if (normalized && normalized !== CHAT_GROUP_CHANNEL) {
                        regularTags.add(normalized);
                    }
                });
            });

            const regularGroups = Array.from(regularTags)
                .sort((a, b) => a.localeCompare(b))
                .map((name) => ({ name, type: 'regular', locked: false }));

            const tempSeen = new Set();
            const temporaryGroups = (Array.isArray(lastFetchedTempGroups) ? lastFetchedTempGroups : [])
                .map((group) => ({
                    name: normalizeTagName(group?.group_name),
                    type: 'temporary',
                    locked: !!group?.locked
                }))
                .filter((group) => {
                    if (!group.name || group.name === CHAT_GROUP_CHANNEL || regularTags.has(group.name) || tempSeen.has(group.name)) {
                        return false;
                    }
                    tempSeen.add(group.name);
                    return true;
                })
                .sort((a, b) => a.name.localeCompare(b.name));

            return channelGroup.concat(regularGroups, temporaryGroups);
        }

        function renderChatGroupTabs() {
            const tabsContainer = document.getElementById('chat-group-tabs');
            const caption = document.getElementById('chat-group-caption');
            if (!tabsContainer) {
                return;
            }

            const groups = buildChatGroupList();
            const unlocked = groups.filter(group => !group.locked);
            const hasSelectedUnlocked = unlocked.some(group => group.name === selectedChatGroup);
            if (!hasSelectedUnlocked) {
                selectedChatGroup = unlocked.length > 0 ? unlocked[0].name : '';
            }

            if (groups.length === 0) {
                tabsContainer.innerHTML = '<span class="text-xs text-slate-500">No tag groups available.</span>';
                if (caption) {
                    caption.textContent = 'Manual @user, @tag, or @all still works when no group tabs are available.';
                }
                if (mainChatTextarea) {
                    mainChatTextarea.placeholder = 'Type message, @user, or @all ...';
                }
                return;
            }

            tabsContainer.innerHTML = groups.map((group) => {
                const isActive = group.name === selectedChatGroup;
                const isLocked = group.locked;
                const baseClass = 'text-xs font-semibold px-3 py-1.5 rounded-full border transition';
                const activeClass = isActive ? 'bg-blue-500/20 border-blue-400 text-blue-200' : 'bg-slate-800/60 border-slate-600 text-slate-300';
                const lockedClass = isLocked ? ' opacity-50 cursor-not-allowed' : ' hover:border-blue-300 hover:text-slate-100';
                const labelBase = group.type === 'channel' ? 'Channel' : `@${group.name}`;
                const labelSuffix = group.type === 'temporary' ? ' (temp)' : '';
                const lockSuffix = isLocked ? ' [LOCKED]' : '';
                return `<button type="button" class="${baseClass} ${activeClass}${lockedClass}" data-chat-group="${escapeHTML(group.name)}" ${isLocked ? 'disabled' : ''}>${escapeHTML(labelBase)}${labelSuffix}${lockSuffix}</button>`;
            }).join('');

            tabsContainer.querySelectorAll('[data-chat-group]').forEach((button) => {
                button.addEventListener('click', () => {
                    selectedChatGroup = String(button.dataset.chatGroup || '').toUpperCase();
                    renderChatGroupTabs();
                    renderFilteredChat();
                });
            });

            if (caption) {
                if (selectedChatGroup === CHAT_GROUP_CHANNEL) {
                    caption.textContent = 'Selected target: Channel broadcast. Manual @user, @tag, or @all overrides this selection.';
                } else if (selectedChatGroup) {
                    caption.textContent = `Selected group: @${selectedChatGroup}. Manual @user, @tag, or @all overrides this selection.`;
                } else {
                    caption.textContent = 'No unlocked groups are available. Use manual @user, @tag, or @all.';
                }
            }
            if (mainChatTextarea) {
                mainChatTextarea.placeholder = (selectedChatGroup && selectedChatGroup !== CHAT_GROUP_CHANNEL)
                    ? `Message to @${selectedChatGroup} ...`
                    : 'Type channel message, @user, @tag, or @all ...';
            }
        }

        function renderAllChats() { renderFilteredChat(); renderDmChat(); }

        function refreshLastHeardAges() {
            document.querySelectorAll('.last-heard').forEach(el => {
                const ts = Number(el.dataset.ts || 0);
                const ageEl = el.parentElement?.querySelector('.last-heard-age');
                const staleEl = el.parentElement?.querySelector('.last-heard-stale');
                const ageText = formatRelativeAge(ts);
                if (ageEl) {
                    ageEl.textContent = ageText;
                }
                if (staleEl) {
                    staleEl.remove();
                }
                const staleBadge = getStaleBadge(ts);
                if (staleBadge) {
                    el.parentElement?.insertAdjacentHTML('beforeend', staleBadge);
                }

                const row = el.closest('tr');
                if (row) {
                    const now = Math.floor(Date.now() / 1000);
                    if (Number.isFinite(ts) && ts > 0 && STALE_NODE_SECONDS > 0 && (now - ts) >= STALE_NODE_SECONDS) {
                        row.classList.add('opacity-75');
                    } else {
                        row.classList.remove('opacity-75');
                    }
                }
            });
        }

        function isOutgoingDirectMessage(text) {
            const clean = String(text || '').replace(/^\x07/, '').trim();
            if (!clean.startsWith('@')) {
                return false;
            }
            const target = normalizeTagName(clean.split(/\s+/, 1)[0].slice(1));
            if (!target || target === 'ALL') {
                return false;
            }
            if (/^![A-F0-9]{8}$/i.test(target)) {
                return true;
            }
            return subscriberNameTargets.has(target);
        }

        function getMessageMentionTarget(text) {
            const clean = String(text || '').replace(/^\x07/, '').trim();
            if (!clean.startsWith('@')) {
                return '';
            }
            return normalizeTagName(clean.split(/\s+/, 1)[0].slice(1));
        }

        function getMessageBracketGroupTarget(text) {
            const clean = String(text || '').replace(/^\x07/, '').trim();
            const match = clean.match(/^\[([^\]]+)\]/);
            if (!match) {
                return '';
            }
            return normalizeTagName(match[1]);
        }

        function findNodeIdByMentionTarget(target) {
            const normalizedTarget = normalizeTagName(target);
            if (!normalizedTarget) {
                return '';
            }
            const allCandidates = Object.assign({}, localUserDirectory || {}, lastFetchedSubscribers || {});
            for (const [nodeId, userData] of Object.entries(allCandidates)) {
                if (normalizeTagName(nodeId) === normalizedTarget) {
                    return nodeId;
                }
                if (normalizeTagName(userData?.name) === normalizedTarget) {
                    return nodeId;
                }
            }
            return '';
        }

        function nodeBelongsToChatGroup(nodeId, groupName) {
            const normalizedGroup = normalizeTagName(groupName);
            const rawNodeId = String(nodeId || '').trim();
            if (!normalizedGroup || !rawNodeId) {
                return false;
            }
            let targetNodeId = rawNodeId;
            let userData = lastFetchedSubscribers[targetNodeId] || getLocalUserRecord(targetNodeId) || null;
            if (!userData) {
                const normalizedNodeId = normalizeTagName(rawNodeId);
                const allCandidates = Object.assign({}, localUserDirectory || {}, lastFetchedSubscribers || {});
                const matchedNodeId = Object.keys(allCandidates).find((candidateId) => normalizeTagName(candidateId) === normalizedNodeId);
                if (matchedNodeId) {
                    targetNodeId = matchedNodeId;
                    userData = allCandidates[matchedNodeId] || null;
                }
            }
            userData = userData || {};
            const userTags = Array.isArray(userData.tags) ? userData.tags : [];
            if (userTags.some((tag) => normalizeTagName(tag) === normalizedGroup)) {
                return true;
            }
            const normalizedNode = normalizeTagName(targetNodeId);
            const normalizedName = normalizeTagName(userData?.name);
            for (const group of (Array.isArray(lastFetchedTempGroups) ? lastFetchedTempGroups : [])) {
                if (normalizeTagName(group?.group_name) !== normalizedGroup) {
                    continue;
                }
                const members = Array.isArray(group?.members) ? group.members : [];
                for (const member of members) {
                    const normalizedMember = normalizeTagName(member);
                    if (!normalizedMember) {
                        continue;
                    }
                    if (normalizedMember === normalizedNode || (normalizedName && normalizedMember === normalizedName)) {
                        return true;
                    }
                }
            }
            return false;
        }

        function messageBelongsToSelectedGroup(msg, groupName) {
            const normalizedGroup = normalizeTagName(groupName);
            if (!normalizedGroup || normalizedGroup === CHAT_GROUP_CHANNEL) {
                return true;
            }
            const text = String(msg?.text || '');
            const mentionTarget = getMessageMentionTarget(text);
            const bracketTarget = getMessageBracketGroupTarget(text);
            const fromId = String(msg?.from || '').trim();

            if (fromId === 'GATEWAY') {
                if (mentionTarget === normalizedGroup || bracketTarget === normalizedGroup) {
                    return true;
                }
                if (!mentionTarget) {
                    return false;
                }
                const targetNodeId = findNodeIdByMentionTarget(mentionTarget);
                return targetNodeId ? nodeBelongsToChatGroup(targetNodeId, normalizedGroup) : false;
            }

            if (mentionTarget === normalizedGroup || bracketTarget === normalizedGroup) {
                return true;
            }
            return nodeBelongsToChatGroup(fromId, normalizedGroup);
        }
        
        function renderFilteredChat() {
            const chatContainerElement = document.getElementById('chat-messages-container');
            const chatWindow = document.getElementById('chat-window');
            if (!chatContainerElement || !chatWindow) return;
            const showDMs = document.getElementById('show-dms-checkbox')?.checked ?? false;
            const showSMs = document.getElementById('show-sms-checkbox')?.checked ?? false;
            const activeGroup = normalizeTagName(selectedChatGroup);
            const enforceGroupFilter = !!activeGroup && activeGroup !== CHAT_GROUP_CHANNEL;
            const isScrolledToBottom = chatWindow.scrollHeight - chatWindow.clientHeight <= chatWindow.scrollTop + 10;
            const filteredMessages = lastFetchedMessages.filter(msg => {
                const text = (msg.text || '').trim();
                let isServerMessage = false;
                for (const prefix of serverMessagePrefixes) { if (text.replace(/^\x07/, '').startsWith(prefix)) { isServerMessage = true; break; } }
                if (isServerMessage) return showSMs; // Filter for server messages
                // A DM is either flagged with `is_dm` or is an outgoing gateway message targeting a specific user.
                let isConsideredDM = msg.is_dm || (msg.from === 'GATEWAY' && isOutgoingDirectMessage(text));
                if (enforceGroupFilter && !messageBelongsToSelectedGroup(msg, activeGroup)) return false;
                if (isConsideredDM) return showDMs;
                return true;
            });
            if (filteredMessages.length > 0) {
                chatContainerElement.innerHTML = filteredMessages.map((msg) => createMessageHTML(msg, lastFetchedSubscribers, false)).join('');
            } else {
                chatContainerElement.innerHTML = `<div class="text-center text-slate-500 py-16"><p>No messages to display with current filters.</p></div>`;
            }
            if (isScrolledToBottom) { chatWindow.scrollTop = chatWindow.scrollHeight; }
        }
        
        function renderDmChat() {
            if (!dmModal || dmModal.style.display === 'none' || !dmChatContainer) return;
            const targetNodeId = dmTargetNodeIdInput.value;
            if (!targetNodeId) { dmChatContainer.innerHTML = ''; updateDmChatActionButtons(''); return; };
            updateDmChatActionButtons(targetNodeId);
            const targetName = lastFetchedSubscribers[targetNodeId]?.name || targetNodeId;
            const filteredMessages = lastFetchedMessages.filter(msg => {
                const gatewayToUserRegex = new RegExp(`^@${escapeRegExp(targetName)}\\s`, 'i');
                const fromGatewayToUser = msg.from === 'GATEWAY' && gatewayToUserRegex.test((msg.text || '').replace(/^\x07/, ''));
                // A DM from a user to the gateway is identified by the sender's ID and the `is_dm` flag.
                const fromUserToGateway = msg.from === targetNodeId && msg.is_dm;
                return fromUserToGateway || fromGatewayToUser; // Show messages from the user to the gateway, or from the gateway to the user.
            });
            const isScrolledToBottom = dmChatWindow.scrollHeight - dmChatWindow.clientHeight <= dmChatWindow.scrollTop + 10;
            if (filteredMessages.length > 0) {
                dmChatContainer.innerHTML = filteredMessages.map((msg) => createMessageHTML(msg, lastFetchedSubscribers, true)).join('');
            } else {
                dmChatContainer.innerHTML = `<div class="text-center text-slate-500 py-16"><p>No direct messages with this user yet.</p></div>`;
            }
            if (isScrolledToBottom) { dmChatWindow.scrollTop = dmChatWindow.scrollHeight; }
        }

        function setLocalUserRecord(nodeId, userData) {
            const targetNodeId = String(nodeId || userData?.node_id || '').trim();
            if (!targetNodeId || !userData || typeof userData !== 'object' || Array.isArray(userData)) {
                return;
            }
            localUserDirectory[targetNodeId] = { ...userData, node_id: targetNodeId };
        }

        function renderMapUsersTable(usersPayload) {
            const tbody = document.getElementById('map-users-table-body');
            if (!tbody) {
                return;
            }
            const rows = Array.isArray(usersPayload?.rows) ? usersPayload.rows : [];
            if (rows.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="p-8 text-center text-slate-500">No subscribers found.</td></tr>';
                indexUserEditButtonsByNodeId();
                return;
            }
            tbody.innerHTML = rows.map((row) => {
                const nodeId = String(row?.node_id || '').trim();
                const name = String(row?.name || '');
                const fullName = String(row?.full_name || '');
                const phone1 = String(row?.phone_1 || '');
                const assignedRole = String(row?.assigned_role || '');
                const reportedRole = String(row?.reported_role || 'Unknown');
                const roleClass = reportedRole === 'Unknown'
                    ? 'text-slate-500'
                    : (row?.reported_role_matches ? 'text-green-400' : 'text-yellow-400');
                const tags = Array.isArray(row?.tags) ? row.tags.filter(Boolean) : [];
                const tagsHtml = tags.length
                    ? tags.map((tag) => `<span class="inline-block bg-slate-700 rounded-full px-2 py-1 font-semibold mr-1 mb-1">${escapeHTML(String(tag))}</span>`).join('')
                    : '';
                const displayName = name || nodeId;
                return `
                    <tr class="hover:bg-black/20">
                        <td class="p-4 font-mono">
                            <button type="button" class="text-blue-400 hover:text-blue-300 open-dm-chat" data-node-id="${escapeHTML(nodeId)}" data-node-name="${escapeHTML(displayName)}">${escapeHTML(nodeId)}</button>
                        </td>
                        <td class="p-4">${escapeHTML(name)}</td>
                        <td class="p-4">
                            <div class="flex items-center gap-2">
                                <span class="font-mono text-xs p-1 rounded bg-slate-700 ${roleClass}" title="This is the role being reported by the radio node right now. Green means it matches the assigned role.">${escapeHTML(reportedRole)}</span>
                                <span class="font-medium">${escapeHTML(assignedRole)}</span>
                            </div>
                        </td>
                        <td class="p-4">${escapeHTML(fullName)}</td>
                        <td class="p-4">${escapeHTML(phone1)}</td>
                        <td class="p-4 text-slate-400 text-xs">${tagsHtml}</td>
                        <td class="p-4"><button type="button" class="btn btn-secondary text-sm open-user-edit-modal" data-node-id="${escapeHTML(nodeId)}">More...</button></td>
                    </tr>
                `;
            }).join('');
            indexUserEditButtonsByNodeId();
        }

        async function fetchMapUsersTable(forceFresh = false) {
            const requestHeaders = {};
            if (!forceFresh && mapUsersTableEtag) {
                requestHeaders['If-None-Match'] = mapUsersTableEtag;
            }
            const response = await fetch('/map-items/api_get_admin_tables.php?scope=users', { headers: requestHeaders });
            const responseEtag = response.headers.get('ETag');
            if (responseEtag) {
                mapUsersTableEtag = responseEtag;
            }
            if (response.status === 304) {
                return true;
            }
            if (!response.ok) {
                const tbody = document.getElementById('map-users-table-body');
                if (tbody) {
                    tbody.innerHTML = '<tr><td colspan="7" class="p-8 text-center text-slate-500">Failed to load subscribers.</td></tr>';
                }
                return false;
            }
            const payload = await response.json();
            if (payload?.users?.directory && typeof payload.users.directory === 'object') {
                localUserDirectory = Object.assign(Object.create(null), localUserDirectory || {}, payload.users.directory || {});
            }
            renderMapUsersTable(payload?.users || null);
            return true;
        }

        function ensureMapUsersTableLoaded(forceFresh = false) {
            if (mapUsersFetchInFlight) {
                return mapUsersFetchInFlight;
            }
            const requestPromise = fetchMapUsersTable(forceFresh)
                .catch((error) => {
                    console.error('Failed to load users table:', error);
                    return false;
                })
                .finally(() => {
                    if (mapUsersFetchInFlight === requestPromise) {
                        mapUsersFetchInFlight = null;
                    }
                });
            mapUsersFetchInFlight = requestPromise;
            return requestPromise;
        }

        function getLocalUserRecord(nodeId) {
            const targetNodeId = String(nodeId || '').trim();
            if (!targetNodeId) {
                return null;
            }
            const local = localUserDirectory[targetNodeId];
            if (local && typeof local === 'object' && !Array.isArray(local)) {
                return { ...local, node_id: targetNodeId };
            }
            const button = userEditButtonsByNodeId[targetNodeId] || null;
            if (!button) {
                return null;
            }
            const serialized = String(button.dataset.userData || '').trim();
            if (!serialized) {
                return null;
            }
            try {
                const parsed = JSON.parse(serialized);
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                    const normalizedNodeId = String(parsed.node_id || targetNodeId).trim();
                    setLocalUserRecord(normalizedNodeId, parsed);
                    const cached = localUserDirectory[normalizedNodeId] || null;
                    if (cached && typeof cached === 'object' && !Array.isArray(cached)) {
                        return { ...cached, node_id: normalizedNodeId };
                    }
                }
            } catch (err) {
                return null;
            }
            return null;
        }

        function indexUserEditButtonsByNodeId() {
            userEditButtonsByNodeId = Object.create(null);
            document.querySelectorAll('.open-user-edit-modal').forEach((button) => {
                const nodeId = String(button.dataset.nodeId || '').trim();
                if (nodeId) {
                    userEditButtonsByNodeId[nodeId] = button;
                }
            });
        }

        function getDmSubscriberRecord(nodeId) {
            const targetNodeId = String(nodeId || '').trim();
            if (!targetNodeId) {
                return null;
            }
            const raw = lastFetchedSubscribers[targetNodeId];
            if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
                return { node_id: targetNodeId, ...raw };
            }
            return getLocalUserRecord(targetNodeId);
        }

        async function fetchUserRecord(nodeId) {
            const targetNodeId = String(nodeId || '').trim();
            if (!targetNodeId) {
                return null;
            }
            const formData = new FormData();
            formData.append('ajax', 'true');
            formData.append('action', 'get_user');
            formData.append('node_id', targetNodeId);
            formData.append('csrf_token', csrfToken);
            try {
                const response = await fetch(window.location.href, { method: 'POST', body: formData });
                if (!response.ok) {
                    return null;
                }
                const payload = await response.json();
                if (!payload || !payload.success || !payload.exists || !payload.user || typeof payload.user !== 'object') {
                    return null;
                }
                setLocalUserRecord(targetNodeId, payload.user);
                return getLocalUserRecord(targetNodeId);
            } catch (error) {
                console.error('Failed to load user record:', error);
                return null;
            }
        }

        async function ensureUserRecord(nodeId) {
            const targetNodeId = String(nodeId || '').trim();
            if (!targetNodeId) {
                return null;
            }
            const localRecord = getDmSubscriberRecord(targetNodeId);
            if (localRecord) {
                return localRecord;
            }
            return fetchUserRecord(targetNodeId);
        }

        function updateDmChatActionButtons(nodeId) {
            const targetNodeId = String(nodeId || '').trim();
            const hasTarget = targetNodeId !== '';
            const localRecord = getLocalUserRecord(targetNodeId);
            const fallbackName = String(
                lastFetchedSubscribers[targetNodeId]?.name ||
                localRecord?.name ||
                dmChatUserBtn?.dataset?.nodeName ||
                targetNodeId
            );

            if (dmChatUserBtn) {
                dmChatUserBtn.dataset.nodeId = hasTarget ? targetNodeId : '';
                dmChatUserBtn.dataset.nodeName = hasTarget ? fallbackName : '';
                dmChatUserBtn.disabled = !hasTarget;
            }
        }

        function openCreateUserFromDmTarget(nodeId) {
            const targetNodeId = String(nodeId || '').trim();
            if (!targetNodeId) {
                return;
            }
            const localRecord = getLocalUserRecord(targetNodeId);
            const targetName = String(
                lastFetchedSubscribers[targetNodeId]?.name ||
                localRecord?.name ||
                dmChatUserBtn?.dataset?.nodeName ||
                targetNodeId
            );
            const usersTabButton = document.querySelector('.tab-button[data-tab="users"]');
            usersTabButton?.click();
            const newNodeIdInput = document.getElementById('new_node_id');
            const newNameInput = document.getElementById('new_name');
            const newPasswordInput = document.getElementById('new_password');
            if (newNodeIdInput) {
                newNodeIdInput.value = targetNodeId;
            }
            if (newNameInput && !String(newNameInput.value || '').trim()) {
                newNameInput.value = targetName;
            }
            setTimeout(() => {
                if (newPasswordInput) {
                    newPasswordInput.focus();
                } else if (newNameInput) {
                    newNameInput.focus();
                } else if (newNodeIdInput) {
                    newNodeIdInput.focus();
                }
            }, 50);
        }

        function formatOptimisticChatTimestamp() {
            const now = new Date();
            const hh = String(now.getHours()).padStart(2, '0');
            const mm = String(now.getMinutes()).padStart(2, '0');
            const month = String(now.getMonth() + 1).padStart(2, '0');
            const day = String(now.getDate()).padStart(2, '0');
            return `${hh}:${mm} ${month}/${day}`;
        }

        function addOptimisticGatewayMessage(messageText) {
            const text = String(messageText || '');
            if (!text.trim()) return '';
            const optimisticToken = `gw-${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const optimisticMessage = {
                from: 'GATEWAY',
                text,
                timestamp: formatOptimisticChatTimestamp(),
                is_dm: false,
                _optimistic: true,
                _optimistic_token: optimisticToken
            };
            const key = getChatMessageKey(optimisticMessage);
            if (key) {
                chatMessageKeys.add(key);
            }
            lastFetchedMessages = lastFetchedMessages.concat(optimisticMessage);
            if (lastFetchedMessages.length > 200) {
                lastFetchedMessages = lastFetchedMessages.slice(-200);
                chatMessageKeys = new Set(lastFetchedMessages.map(getChatMessageKey).filter(Boolean));
            }
            renderAllChats();
            return optimisticToken;
        }

        function removeOptimisticGatewayMessage(optimisticToken) {
            const token = String(optimisticToken || '').trim();
            if (!token) return;
            const beforeCount = lastFetchedMessages.length;
            lastFetchedMessages = lastFetchedMessages.filter((msg) => String(msg?._optimistic_token || '') !== token);
            if (lastFetchedMessages.length !== beforeCount) {
                chatMessageKeys = new Set(lastFetchedMessages.map(getChatMessageKey).filter(Boolean));
                renderAllChats();
            }
        }
        
        function escapeRegExp(string) { return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
        
        function createMessageHTML(msg, subscribers, isDmContext = false) {
            const fromId = msg.from || 'Unknown';
            let text = (msg.text || '').trim();
            let messageType = '', fromName = 'Unknown', hasBell = false;
            let isSystemMessage = false;
            for (const prefix of serverMessagePrefixes) { if (text.replace(/^\x07/, '').startsWith(prefix)) { isSystemMessage = true; break; } }
            if (isSystemMessage) { messageType = 'system'; } 
            else if (fromId === 'GATEWAY') { messageType = 'outgoing'; fromName = 'You (Gateway)'; } 
            else { fromName = (subscribers[fromId] && subscribers[fromId].name) ? subscribers[fromId].name : fromId; messageType = 'incoming'; }
            if (messageType === 'outgoing' && isDmContext) { 
                const parts = text.split(/ (.*)/s); 
                if (parts.length > 1 && parts[0].startsWith('@')) { text = parts[1]; }
            }
            if (text.startsWith("\x07")) { hasBell = true; text = text.substring(1); }
            if (messageType === 'system') { return `<div class="message message-system"><div class="message-content">${escapeHTML(text)}</div></div>`; }
            const dmPrefix = (msg.is_dm && messageType === 'incoming' && !isDmContext) ? '<span class="font-bold text-yellow-400/80">DM: </span>' : '';
            const bellIndicator = hasBell ? '<span class="text-red-400 font-bold" title="Sent with Bell">🔔 </span>' : '';
            return `<div class="message message-${messageType}"><div class="message-username">${escapeHTML(fromName)}</div><div class="message-content">${bellIndicator}${dmPrefix}${escapeHTML(text)}</div><div class="message-meta"><span class="timestamp">${escapeHTML(msg.timestamp || '')}</span></div></div>`;
        }
        
        function sendAjaxMessage(text, button, isBell = false) {
            if (!text.trim() || button.disabled) return;
            const originalButtonText = button.textContent;
            let allButtons = [mainChatSendBtn, mainChatBellBtn, dmChatSendBtn, dmChatBellBtn].filter(b => b);
            allButtons.forEach(b => { b.disabled = true; });
            button.textContent = '...';
            const isDmContext = !!button.closest('#dm-chat-form');
            let routedText = text;
            const trimmed = text.trim();
            let forcedTargetGroup = '';
            if (!isDmContext && !trimmed.startsWith('@')) {
                if (selectedChatGroup && selectedChatGroup !== CHAT_GROUP_CHANNEL) {
                    forcedTargetGroup = normalizeTagName(selectedChatGroup);
                    routedText = `@${selectedChatGroup} ${trimmed}`;
                } else {
                    routedText = trimmed;
                }
            }
            const routedTrimmed = routedText.trim();
            if (routedTrimmed.toLowerCase().startsWith('@all ') || routedTrimmed.toLowerCase() === '@all') {
                const confirmed = confirm('Send this message to ALL subscribers? This may take time on large networks.');
                if (!confirmed) {
                    allButtons.forEach(b => { b.disabled = false; });
                    button.textContent = originalButtonText;
                    return;
                }
            }
            let messageToSend = routedText;
            if (isBell) {
                if (routedTrimmed.startsWith('@')) {
                    const parts = routedTrimmed.split(/ (.*)/s);
                    messageToSend = `${parts[0]} \x07${parts[1] || ''}`;
                } else {
                    messageToSend = `\x07${routedTrimmed}`;
                }
            }
            const optimisticToken = addOptimisticGatewayMessage(messageToSend);
            
            const csrfToken = document.querySelector('input[name="csrf_token"]').value;
            const formData = new FormData();
            formData.append('ajax', 'true');
            formData.append('action', 'send_broadcast');
            formData.append('broadcast_text', messageToSend);
            if (forcedTargetGroup) {
                formData.append('target_group', forcedTargetGroup);
            }
            formData.append('csrf_token', csrfToken);

            fetch(window.location.href, { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => {
                if (data.success) { 
                    if (button.closest('#dm-chat-form')) dmChatTextarea.value = ''; 
                    else mainChatTextarea.value = ''; 
                    void updateChat();
                } else {
                    removeOptimisticGatewayMessage(optimisticToken);
                    alert('Failed to send message: ' + data.message);
                }
            })
            .catch(error => {
                removeOptimisticGatewayMessage(optimisticToken);
                console.error('Error sending message:', error);
                alert('An error occurred while sending the message.');
            })
            .finally(() => { allButtons.forEach(b => { b.disabled = false; }); button.textContent = originalButtonText; });
        }

        document.body.addEventListener('input', (event) => {
            const inputEl = event.target && event.target.closest ? event.target.closest('.ops-notes-input') : null;
            if (!inputEl) return;
            const editorEl = inputEl.closest('.ops-notes-editor');
            const nodeId = String(editorEl?.dataset?.nodeId || '').trim();
            if (!nodeId) return;
            opsNotesDraftByNode.set(nodeId, inputEl.value);
            setOpsNotesStatus(nodeId, '', '');
        });

        document.body.addEventListener('click', async (event) => {
            const saveBtn = event.target && event.target.closest ? event.target.closest('.ops-notes-save-btn') : null;
            if (!saveBtn) return;
            event.preventDefault();
            const editorEl = saveBtn.closest('.ops-notes-editor');
            const nodeId = String(editorEl?.dataset?.nodeId || '').trim();
            const inputEl = editorEl ? editorEl.querySelector('.ops-notes-input') : null;
            const nextNotes = inputEl ? normalizeOpsNotesValue(inputEl.value) : '';
            if (!nodeId) {
                alert('Unable to save Ops Notes: missing Node ID.');
                return;
            }
            setOpsNotesStatus(nodeId, '', 'Saving...');
            const result = await saveOpsNotesForNode(nodeId, nextNotes, saveBtn);
            if (result.success) {
                updateLocalOpsNotesCache(nodeId, result.ops_notes);
                setOpsNotesStatus(nodeId, 'ok', result.message || 'Saved.');
            } else {
                setOpsNotesStatus(nodeId, 'err', result.message || 'Save failed.');
            }
        });
        
        mainChatSendBtn?.addEventListener('click', function() { sendAjaxMessage(mainChatTextarea.value, this, false); });
        mainChatBellBtn?.addEventListener('click', function() { sendAjaxMessage(mainChatTextarea.value, this, true); });
        mainChatTextarea?.addEventListener('keydown', function(event) { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); mainChatSendBtn.click(); } });
        renderChatGroupTabs();
        
        async function openDmChat(nodeId, nodeName) {
            if (!dmModal) return;
            dmChatTitle.querySelector('span').textContent = `${nodeId} / ${nodeName}`;
            dmTargetNodeIdInput.value = nodeId;
            if (dmChatUserBtn) {
                dmChatUserBtn.dataset.nodeName = String(nodeName || nodeId || '');
            }
            updateDmChatActionButtons(nodeId);
            dmChatContainer.innerHTML = `<div class="text-center text-slate-500 py-16"><p>Loading messages...</p></div>`;
            dmModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
            if (!isPollingActive) {
                isPollingActive = true;
            }
            if (!isChatPolling) {
                startChatPolling();
            }
            renderDmChat();
            setTimeout(() => {
                if (dmChatWindow) dmChatWindow.scrollTop = dmChatWindow.scrollHeight;
                if (dmChatTextarea) dmChatTextarea.focus();
            }, 100);
        }
        
        function closeDmChat() {
            if (!dmModal) return;
            dmModal.style.display = 'none';
            document.body.style.overflow = '';
            const activeTab = document.querySelector('.tab-button.active')?.dataset?.tab || '';
            if (activeTab !== 'chat') {
                stopChatPolling();
                if (activeTab === 'status') {
                    isPollingActive = true;
                    startStatusPolling();
                } else {
                    isPollingActive = false;
                    stopStatusPolling();
                }
            }
            dmTargetNodeIdInput.value = '';
            updateDmChatActionButtons('');
        }
        
        document.body.addEventListener('click', function(event) {
            if (event.target.matches('.open-dm-chat')) {
                openDmChat(event.target.dataset.nodeId, event.target.dataset.nodeName);
            }
            if (event.target.matches('.location-btn')) {
                const { lat, lon } = event.target.dataset;
                if (map && lat && lon) { map.setView([lat, lon], 15); }
            }
        });
        
        closeDmModalBtn?.addEventListener('click', closeDmChat);
        
        dmChatForm?.addEventListener('submit', function(e) { 
            e.preventDefault(); 
            const text = dmChatTextarea.value.trim();
            const target = lastFetchedSubscribers[dmTargetNodeIdInput.value]?.name || dmTargetNodeIdInput.value;
            const fullMessage = `@${target} ${text}`;
            sendAjaxMessage(fullMessage, dmChatSendBtn, false); 
        });
        
        dmChatBellBtn?.addEventListener('click', function() { 
            const text = dmChatTextarea.value.trim(); 
            const target = lastFetchedSubscribers[dmTargetNodeIdInput.value]?.name || dmTargetNodeIdInput.value;
            const fullMessage = `@${target} ${text}`;
            sendAjaxMessage(fullMessage, this, true);
        });

        dmChatUserBtn?.addEventListener('click', async function() {
            const nodeId = dmChatUserBtn.dataset.nodeId || dmTargetNodeIdInput.value || '';
            const userRecord = await ensureUserRecord(nodeId);
            closeDmChat();
            if (userRecord) {
                openUserEditModal(userRecord);
                return;
            }
            openCreateUserFromDmTarget(nodeId);
        });
        
        dmChatTextarea?.addEventListener('keydown', function(event) { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); dmChatSendBtn.click(); } });
        
        function updateAddressCoordToggle() {
            const form = document.getElementById('user-edit-form');
            if (!form) return;
            const latInput = form.querySelector('input[name="address_lat"]');
            const lonInput = form.querySelector('input[name="address_lon"]');
            const toggle = form.querySelector('input[name="use_address_coords"]');
            const warning = document.getElementById('address-coords-warning');
            if (!latInput || !lonInput || !toggle) return;
            const lat = parseCoord(latInput.value, -90, 90);
            const lon = parseCoord(lonInput.value, -180, 180);
            const valid = lat !== null && lon !== null;
            toggle.disabled = !valid;
            if (!valid) {
                toggle.checked = false;
            }
            if (warning) {
                warning.style.display = valid ? 'none' : 'block';
            }
        }

        function openUserEditModal(userData) {
            const userEditForm = document.getElementById('user-edit-form');
            if (!userEditModal || !userEditForm) return;
            setLocalUserRecord(userData?.node_id, userData);
            userModalTitle.textContent = `${userData.node_id} / ${userData.name}`;
            userEditForm.querySelector('input[name="node_id"]').value = userData.node_id;
            document.getElementById('user-modal-delete-form').querySelector('input[name="node_id"]').value = userData.node_id;
            userEditForm.querySelector('input[name="name"]').value = userData.name || '';
            userEditForm.querySelector('input[name="full_name"]').value = userData.full_name || '';
            userEditForm.querySelector('select[name="role"]').value = userData.role || '';
            userEditForm.querySelector('input[name="email"]').value = userData.email || '';
            userEditForm.querySelector('input[name="phone_1"]').value = userData.phone_1 || '';
            userEditForm.querySelector('input[name="phone_2"]').value = userData.phone_2 || '';
            userEditForm.querySelector('input[name="address_street"]').value = userData.address?.street || '';
            userEditForm.querySelector('input[name="address_city"]').value = userData.address?.city || '';
            userEditForm.querySelector('input[name="address_state"]').value = userData.address?.state || '';
            userEditForm.querySelector('input[name="address_zip"]').value = userData.address?.zip || '';
            userEditForm.querySelector('input[name="address_lat"]').value = userData.address_lat ?? '';
            userEditForm.querySelector('input[name="address_lon"]').value = userData.address_lon ?? '';
            userEditForm.querySelector('input[name="use_address_coords"]').checked = !!userData.use_address_coords;
            userEditForm.querySelector('textarea[name="notes"]').value = userData.notes || '';
            userEditForm.querySelector('textarea[name="ops_notes"]').value = userData.ops_notes || '';
            userEditForm.querySelector('input[name="tags"]').value = (userData.tags || []).join(', ');
            userEditForm.querySelector('textarea[name="poc_info"]').value = userData.poc_info || '';
            userEditForm.querySelector('input[name="sos_notify"]').value = userData.sos_notify || '';
            userEditForm.querySelector('input[name="alerts"]').checked = userData.alerts || false;
            userEditForm.querySelector('input[name="weather"]').checked = userData.weather || false;
            userEditForm.querySelector('input[name="scheduled_daily_forecast"]').checked = userData.scheduled_daily_forecast || false;
            userEditForm.querySelector('input[name="email_send"]').checked = userData.email_send || false;
            userEditForm.querySelector('input[name="email_receive"]').checked = userData.email_receive || false;
            userEditForm.querySelector('input[name="emailbroadcast"]').checked = userData.emailbroadcast || false;
            userEditForm.querySelector('input[name="node_tag_send"]').checked = userData.node_tag_send || false;
            userEditForm.querySelector('input[name="blocked"]').checked = userData.blocked || false;
            userEditForm.querySelector('input[name="password"]').value = '';
            userEditForm.querySelector('input[name="password_confirm"]').value = '';
            updateAddressCoordToggle();
            const clearForm = document.getElementById('clear-user-password-form');
            if (clearForm) {
                clearForm.querySelector('input[name="node_id"]').value = userData.node_id;
            }
            userEditModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
        
        function closeUserEditModal() { if (!userEditModal) return; userEditModal.style.display = 'none'; document.body.style.overflow = ''; }
        
        indexUserEditButtonsByNodeId();
        document.body.addEventListener('click', async (event) => {
            const button = event.target.closest('.open-user-edit-modal');
            if (!button) return;
            const nodeId = String(button.dataset.nodeId || '').trim();
            if (!nodeId) {
                return;
            }
            let userData = getLocalUserRecord(nodeId);
            if (!userData) {
                userData = await fetchUserRecord(nodeId);
            }
            if (!userData) {
                alert(`Unable to load user profile for ${nodeId}.`);
                return;
            }
            openUserEditModal(userData);
        });
        document.getElementById('address_lat')?.addEventListener('input', updateAddressCoordToggle);
        document.getElementById('address_lon')?.addEventListener('input', updateAddressCoordToggle);
        closeUserModalBtnHeader?.addEventListener('click', closeUserEditModal);
        closeUserModalBtnFooter?.addEventListener('click', closeUserEditModal);
        clearUserPasswordForm?.addEventListener('submit', (event) => {
            event.preventDefault();
            if (!confirm('Clear the login password for this user?')) return;
            clearUserPasswordForm.submit();
        });
        
        function openBroadcastEditModal(jobData) {
            const broadcastEditForm = document.getElementById('broadcast-edit-form');
            if (!broadcastEditModal || !broadcastEditForm) return;
            broadcastEditModal.querySelector('#broadcast-modal-title span').textContent = `Edit: ${jobData.name || 'Untitled Job'}`;
            broadcastEditForm.querySelector('input[name="job_index"]').value = jobData.job_index;
            document.getElementById('broadcast-modal-delete-form').querySelector('input[name="job_index"]').value = jobData.job_index;
            broadcastEditForm.querySelector('input[name="name"]').value = jobData.name || '';
            let content = jobData.content || '';
            const bellCheckbox = broadcastEditForm.querySelector('input[name="with_bell"]');
            if (content.startsWith("\x07")) { bellCheckbox.checked = true; content = content.substring(1); } else { bellCheckbox.checked = false; }
            broadcastEditForm.querySelector('textarea[name="content"]').value = content;
            broadcastEditForm.querySelector('input[name="enabled"]').checked = jobData.enabled || false;
            broadcastEditForm.querySelector('input[name="interval_mins"]').value = jobData.interval_mins || 60;
            const jobTypeSelector = broadcastEditForm.querySelector('.job-type-selector');
            if (jobData.days) {
                jobTypeSelector.value = 'recurring';
                broadcastEditForm.querySelectorAll('input[name="days[]"]').forEach(cb => { cb.checked = (jobData.days || []).includes(cb.value); });
                broadcastEditForm.querySelector('input[name="start_time"]').value = jobData.start_time || '';
                broadcastEditForm.querySelector('input[name="stop_time"]').value = jobData.stop_time || '';
            } else {
                jobTypeSelector.value = 'event';
                const formatForInput = (dt) => dt ? dt.replace(' ', 'T') : '';
                broadcastEditForm.querySelector('input[name="start_datetime"]').value = formatForInput(jobData.start_datetime);
                broadcastEditForm.querySelector('input[name="stop_datetime"]').value = formatForInput(jobData.stop_datetime);
            }
            toggleJobFields(broadcastEditForm);
            broadcastEditModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
        
        function closeBroadcastEditModal() { if (!broadcastEditModal) return; broadcastEditModal.style.display = 'none'; document.body.style.overflow = ''; }
        
        document.querySelectorAll('.open-broadcast-edit-modal').forEach(button => { button.addEventListener('click', function() { openBroadcastEditModal(JSON.parse(this.dataset.jobData)); }); });
        document.getElementById('close-broadcast-modal-btn')?.addEventListener('click', closeBroadcastEditModal);
        document.getElementById('close-broadcast-modal-btn-footer')?.addEventListener('click', closeBroadcastEditModal);
    });
</script>
</body>
</html>
