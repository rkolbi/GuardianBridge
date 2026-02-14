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

// GuardianBridge - Mesh Operator Panel (MOP)
// Key differences vs map.php: operator-focused UI, compact overlay layout, MOP-styled admin tools.

// --- CONFIGURATION ---
$revision = 'v1.4.0 "Dispatch"';
require_once __DIR__ . '/db.php';
$base_dir = '/opt/GuardianBridge';
$env_file = $base_dir . '/.env';
$commands_dir = $base_dir . '/data/commands';
$gb_page_perf_start = microtime(true);
register_shutdown_function(function () use ($gb_page_perf_start) {
    $elapsed_ms = (microtime(true) - $gb_page_perf_start) * 1000;
    if ($elapsed_ms >= 1500) {
        $is_ajax = (isset($_POST['ajax']) && $_POST['ajax'] === 'true') ? ':ajax' : '';
        error_log(sprintf('GuardianBridge Perf: mop.php%s %.1fms', $is_ajax, $elapsed_ms));
    }
});

// --- AUTHENTICATION CONFIG (operator selection) ---
function mop_load_operator_directory() {
    try {
        $pdo = gb_db();
        $stmt = $pdo->query("SELECT node_id, json_extract(data_json, '$.name') AS name, json_extract(data_json, '$.password_hash') AS password_hash, json_extract(data_json, '$.role') AS role, json_extract(data_json, '$.tags') AS tags_json FROM subscribers");
        $directory = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            $node_id = trim((string)($row['node_id'] ?? ''));
            if ($node_id === '') {
                continue;
            }
            $tags = [];
            $tags_json = $row['tags_json'] ?? null;
            if (is_string($tags_json) && $tags_json !== '') {
                $decoded_tags = json_decode($tags_json, true);
                if (is_array($decoded_tags)) {
                    $tags = $decoded_tags;
                }
            } elseif (is_array($tags_json)) {
                $tags = $tags_json;
            }
            $directory[$node_id] = [
                'name' => (string)($row['name'] ?? ''),
                'password_hash' => (string)($row['password_hash'] ?? ''),
                'role' => (string)($row['role'] ?? ''),
                'tags' => $tags,
            ];
        }
        return $directory;
    } catch (Throwable $e) {
        $fallback = gb_load_subscribers();
        $directory = [];
        foreach ($fallback as $node_id => $user) {
            if (!is_array($user)) {
                continue;
            }
            $directory[$node_id] = [
                'name' => (string)($user['name'] ?? ''),
                'password_hash' => (string)($user['password_hash'] ?? ''),
                'role' => (string)($user['role'] ?? ''),
                'tags' => is_array($user['tags'] ?? null) ? $user['tags'] : [],
            ];
        }
        return $directory;
    }
}

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
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

$operator_directory = [];
$available_users = [];
$needs_operator_directory = (
    !isset($_SESSION['mop_loggedin']) ||
    $_SESSION['mop_loggedin'] !== true ||
    ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login')
);
if ($needs_operator_directory) {
    $operator_directory = mop_load_operator_directory();
    $available_users = array_filter($operator_directory, function ($user) {
        $hash = $user['password_hash'] ?? '';
        return is_string($hash) && $hash !== '';
    });
    ksort($available_users);
}

// --- LOGIN LOGIC ---
function mop_get_client_ip() {
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
    $selected_user = trim($_POST['operator_user'] ?? '');
    $password = $_POST['password'] ?? '';
    $principal = ($selected_user !== '') ? $selected_user : '__EMPTY__';
    $client_ip = mop_get_client_ip();

    $principal_stats = gb_get_recent_login_failure_stats('mop', $principal, $client_ip, $login_lockout_seconds);
    $ip_stats = gb_get_recent_login_failure_stats('mop', '__ANY__', $client_ip, $login_lockout_seconds);

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
    } else {
        if ($selected_user === '') {
            $login_error = 'Please select an operator.';
        } elseif (!isset($available_users[$selected_user])) {
            $login_error = 'Selected operator is not available.';
        } elseif ($password === '') {
            $login_error = 'Password is required.';
        } else {
            $password_hash = $available_users[$selected_user]['password_hash'] ?? '';
            if ($password_hash === '') {
                $login_error = 'Password not set for this operator. Set it in map.php.';
            } elseif (!password_verify($password, $password_hash)) {
                $login_error = 'Invalid password.';
            } else {
                $_SESSION['mop_loggedin'] = true;
                $_SESSION['operator_user'] = $selected_user;
                $_SESSION['operator_name'] = $available_users[$selected_user]['name'] ?? $selected_user;
                gb_clear_login_failures('mop', $principal, $client_ip);
                gb_clear_login_failures('mop', '__ANY__', $client_ip);
                gb_prune_login_failures();
                session_regenerate_id(true);
                header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
                exit;
            }
        }
        if ($login_error !== '') {
            gb_record_login_failure('mop', $principal, $client_ip, $now_ts);
            gb_record_login_failure('mop', '__ANY__', $client_ip, $now_ts);
            gb_prune_login_failures();
        }
    }
}

// --- AUTHENTICATION GATE ---
if (!isset($_SESSION['mop_loggedin']) || $_SESSION['mop_loggedin'] !== true) {
?>
<!DOCTYPE html>
<html lang="en" class="bg-[#131314]">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Mesh Operator Panel</title>
    <link rel="icon" type="image/x-icon" href="/map-items/map-logo.ico">
    <script src="/map-items/tailwindcss.js"></script>
    <link href="/map-items/inter-font.css" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #131314; }
        select, input[type="password"] {
            background-color: #1E1F20; border: 1px solid #3C4043; color: #E3E3E3;
            padding: 0.6rem 0.85rem; border-radius: 0.5rem; width: 100%; transition: all 0.2s;
        }
        select:focus, input[type="password"]:focus {
            outline: none; border-color: #89B3F8; box-shadow: 0 0 0 2px rgba(137, 179, 248, 0.3);
        }
        select:disabled { opacity: 0.6; cursor: not-allowed; }
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
                    Mesh Operator Panel
                </h1>
                <p class="text-slate-400 mt-1">Operator Login</p>
            </header>

            <?php if ($login_error): ?>
                <div class="bg-red-500/10 border border-red-500/20 text-red-300 px-4 py-3 rounded-lg relative mb-6 text-center" role="alert">
                    <?= htmlspecialchars($login_error) ?>
                </div>
            <?php endif; ?>

            <?php $has_users = !empty($available_users); ?>
            <?php if (!$has_users): ?>
                <div class="bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 px-4 py-3 rounded-lg relative mb-6 text-center">
                    No operators are available yet. Add a user in the Users panel or subscribers list.
                </div>
            <?php endif; ?>

            <form method="POST" class="space-y-6">
                <input type="hidden" name="action" value="login">
                <div>
                    <label for="operator_user" class="block text-sm font-medium text-slate-400 mb-2">Operator</label>
                    <select id="operator_user" name="operator_user" required <?= $has_users ? '' : 'disabled' ?>>
                        <option value="">Select an operator</option>
                        <?php foreach ($available_users as $node_id => $user): ?>
                            <?php
                                $label = trim($user['name'] ?? '');
                                $display = $label !== '' ? ($label . ' (' . $node_id . ')') : $node_id;
                            ?>
                            <option value="<?= htmlspecialchars($node_id) ?>"><?= htmlspecialchars($display) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-slate-400 mb-2">Password</label>
                    <input type="password" id="password" name="password" required <?= $has_users ? '' : 'disabled' ?>>
                </div>
                <div>
                    <button type="submit" class="w-full py-2.5 px-4 rounded-lg font-semibold btn-primary" <?= $has_users ? '' : 'disabled' ?>>Enter Panel</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
<?php
    exit;
}

$audit_actor = trim((string)($_SESSION['operator_user'] ?? $_SESSION['operator_name'] ?? 'operator'));
$operator_user_id = trim((string)($_SESSION['operator_user'] ?? ''));
$operator_profile = (isset($operator_directory[$operator_user_id]) && is_array($operator_directory[$operator_user_id]))
    ? $operator_directory[$operator_user_id]
    : [];
$operator_tags = $operator_profile['tags'] ?? [];
$operator_tags_upper = [];
if (is_array($operator_tags)) {
    foreach ($operator_tags as $tag) {
        if (is_string($tag) && $tag !== '') {
            $operator_tags_upper[] = strtoupper(trim($tag));
        }
    }
}
$operator_role_upper = strtoupper(trim((string)($operator_profile['role'] ?? '')));
$audit_can_view_all = in_array('ADMIN', $operator_tags_upper, true) || in_array($operator_role_upper, ['ADMIN', 'ADMINISTRATOR'], true);
$audit_scope_panel = $audit_can_view_all ? '' : 'mop';
$audit_scope_actor = $audit_can_view_all ? '' : $audit_actor;
$audit_scope_label = $audit_can_view_all ? 'All operators/admins' : 'Your operator activity only';

// --- HELPER FUNCTIONS (minimal subset from map.php) ---
function get_env_settings($file_path, $whitelist) {
    $env_values = [];
    if (is_readable($file_path)) {
        $lines = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            if (strpos($line, '=') === false) continue;
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            if (in_array($key, $whitelist, true)) {
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
    if (!gb_enqueue_command_job($command_data, 'mop.php:webui', '', 5, $queue_result)) {
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

function gb_audit_mop_log($action, $target = '', $details = []) {
    global $audit_actor;
    try {
        gb_log_audit($audit_actor, 'mop', $action, $target, $details);
    } catch (Throwable $e) {
        error_log('GuardianBridge Warning: failed to write mop audit log: ' . $e->getMessage());
    }
}

// --- FORM PROCESSING ---
$message = '';
$error = '';

// --- OPERATOR-SCOPE ACTIONS (DM only) ---
if (isset($_POST['ajax']) && $_POST['ajax'] === 'true') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'Invalid action.'];

    if (!isset($_SESSION['mop_loggedin']) || $_SESSION['mop_loggedin'] !== true) {
        $response['message'] = 'Not authenticated.';
        echo json_encode($response);
        exit;
    }

    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $response['message'] = 'Invalid security token.';
        echo json_encode($response);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = $_POST['action'] ?? '';
        if ($action === 'send_dm') {
            $destination_id = trim($_POST['destination_id'] ?? '');
            $text_to_send = trim($_POST['message'] ?? '');
            if ($destination_id === '' || $text_to_send === '') {
                $response['message'] = 'Destination and message are required.';
            } else {
                $recipient_name = $destination_id;
                $subscribers = gb_load_subscribers();
                if (isset($subscribers[$destination_id]['name']) && $subscribers[$destination_id]['name']) {
                    $recipient_name = $subscribers[$destination_id]['name'];
                }
                $command_data = [
                    'command' => 'dm',
                    'destinationId' => $destination_id,
                    'text' => $text_to_send,
                    'recipient' => $recipient_name
                ];
                $queued_file = '';
                $command_id = '';
                if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                    $response['success'] = true;
                    $response['message'] = 'Message queued.';
                    gb_audit_mop_log(
                        'send_dm_ajax',
                        $destination_id,
                        ['recipient' => $recipient_name, 'text_len' => strlen($text_to_send)]
                    );
                } else {
                    $response['message'] = 'Failed to queue message.';
                }
            }
        } elseif ($action === 'send_broadcast') {
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
                    $error_message = 'Direct message has no text. Format: @user/@tag/@all message';
                } else {
                    $command_data = ['command' => 'tagsend', 'tags' => $forced_target_group, 'text' => $message_body];
                }
            } else {
                if (strpos($text_to_send, '@') === 0) {
                    $parts = explode(' ', $text_to_send, 2);
                    $target_str = ltrim($parts[0], '@');
                    $message_body = $parts[1] ?? '';
                    if (empty(trim($message_body))) {
                        $error_message = 'Direct message has no text. Format: @user/@tag/@all message';
                    } elseif (strcasecmp($target_str, 'all') === 0) {
                        $command_data = ['command' => 'broadcast_subscribers', 'text' => $message_body];
                    } else {
                        $subscribers = get_subscribers('');
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
                    gb_audit_mop_log(
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
                    error_log('GuardianBridge Error: Failed to queue command in DB from mop send_broadcast.');
                }
            } elseif (!empty($error_message)) {
                $response['message'] = $error_message;
            }
        } elseif ($action === 'get_user') {
            $node_id = trim((string)($_POST['node_id'] ?? ''));
            if ($node_id === '') {
                $response['message'] = 'Node ID is required.';
            } else {
                $subscribers = get_subscribers('');
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
            $ops_notes = trim(strip_tags((string)($_POST['ops_notes'] ?? '')));
            if ($node_id === '') {
                $response['message'] = 'Node ID is required.';
            } else {
                $subscribers = get_subscribers('');
                if (!isset($subscribers[$node_id])) {
                    $response['message'] = 'User not found.';
                } else {
                    $subscribers[$node_id]['ops_notes'] = $ops_notes;
                    if (save_subscribers('', $subscribers)) {
                        $response['success'] = true;
                        $response['message'] = 'Ops Notes saved.';
                        $response['ops_notes'] = $ops_notes;
                        gb_audit_mop_log(
                            'update_ops_notes_ajax',
                            $node_id,
                            ['ops_notes_len' => strlen($ops_notes)]
                        );
                    } else {
                        $response['message'] = 'Failed to save Ops Notes.';
                    }
                }
            }
        }
    }

    echo json_encode($response);
    exit;
}

// --- SETTINGS FOR UI ---
$settings = get_env_settings($env_file, [
    'LATITUDE',
    'LONGITUDE',
    'POLLING_INTERVAL_MS',
    'CHAT_POLLING_INTERVAL_MS',
    'STALE_NODE_MINUTES'
]);
$gateway_lat = $settings['LATITUDE'] !== '' ? floatval($settings['LATITUDE']) : 30.0000;
$gateway_lon = $settings['LONGITUDE'] !== '' ? floatval($settings['LONGITUDE']) : -90.0000;
$polling_interval = max(1000, intval($settings['POLLING_INTERVAL_MS'] ?? 5000));
$chat_polling_interval = max(500, intval($settings['CHAT_POLLING_INTERVAL_MS'] ?? 1000));
$stale_node_minutes = intval($settings['STALE_NODE_MINUTES'] ?? 120);
$days_of_week = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['ajax'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = 'Invalid security token. Please refresh and try again.';
    } else {
        $action = $_POST['action'] ?? '';
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
                    error_log('GuardianBridge Error: Failed to queue admin_clear_sos in DB from mop.');
                }
            } else {
                $error = 'No active SOS node ID was provided for the admin clear command.';
            }
        }

        if ($action === 'update_user') {
            $node_id = $_POST['node_id'] ?? '';
            $subscribers = get_subscribers('');
            if (isset($subscribers[$node_id])) {
                $subscribers[$node_id]['name'] = trim(strip_tags($_POST['name'] ?? ''));
                $subscribers[$node_id]['full_name'] = trim(strip_tags($_POST['full_name'] ?? ''));
                $subscribers[$node_id]['role'] = trim(strip_tags($_POST['role'] ?? ''));
                $subscribers[$node_id]['email'] = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
                $subscribers[$node_id]['phone_1'] = trim(strip_tags($_POST['phone_1'] ?? ''));
                $subscribers[$node_id]['phone_2'] = trim(strip_tags($_POST['phone_2'] ?? ''));
                $subscribers[$node_id]['notes'] = trim(strip_tags($_POST['notes'] ?? ''));
                $subscribers[$node_id]['ops_notes'] = trim(strip_tags($_POST['ops_notes'] ?? ''));
                $subscribers[$node_id]['poc_info'] = trim(strip_tags($_POST['poc_info'] ?? ''));
                $subscribers[$node_id]['sos_notify'] = trim(strip_tags($_POST['sos_notify'] ?? ''));

                if (!isset($subscribers[$node_id]['address']) || !is_array($subscribers[$node_id]['address'])) {
                    $subscribers[$node_id]['address'] = [];
                }
                $subscribers[$node_id]['address']['street'] = trim(strip_tags($_POST['address_street'] ?? ''));
                $subscribers[$node_id]['address']['city'] = trim(strip_tags($_POST['address_city'] ?? ''));
                $subscribers[$node_id]['address']['state'] = trim(strip_tags($_POST['address_state'] ?? ''));
                $subscribers[$node_id]['address']['zip'] = trim(strip_tags($_POST['address_zip'] ?? ''));
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

                if (save_subscribers('', $subscribers)) {
                    $message = "User '" . htmlspecialchars($subscribers[$node_id]['name']) . "' updated successfully.";
                } else {
                    $error = 'Failed to update user. Please check server logs.';
                }
            }
        }

        if ($action === 'add_user') {
            $node_id = trim($_POST['new_node_id'] ?? '');
            if (preg_match('/^![a-f0-9]{8}$/', $node_id)) {
                $subscribers = get_subscribers('');
                if (!isset($subscribers[$node_id])) {
                    $subscribers[$node_id] = [
                        'name' => trim(strip_tags($_POST['new_name'] ?? '')),
                        'full_name' => '', 'role' => '', 'email' => '',
                        'address' => ['street' => '', 'city' => '', 'state' => '', 'zip' => ''],
                        'address_lat' => '', 'address_lon' => '', 'use_address_coords' => false,
                        'phone_1' => '', 'phone_2' => '', 'notes' => '', 'ops_notes' => '',
                        'poc_info' => '', 'sos_notify' => '',
                        'alerts' => true, 'weather' => true, 'scheduled_daily_forecast' => true,
                        'email_send' => false, 'email_receive' => false, 'emailbroadcast' => false,
                        'node_tag_send' => false, 'blocked' => false, 'tags' => []
                    ];
                    if (save_subscribers('', $subscribers)) {
                        $message = "User '$node_id' added successfully.";
                    } else {
                        $error = 'Failed to add user. Please check server logs.';
                    }
                } else {
                    $error = "User '$node_id' already exists.";
                }
            } else {
                $error = "Invalid Node ID format. Must be like '!a1b2c3d4'.";
            }
        }

        if ($action === 'save_broadcast_job') {
            $jobs = get_dispatcher_jobs('');
            $job_index = $_POST['job_index'] ?? '';
            if (isset($jobs[$job_index])) {
                $content = trim(strip_tags($_POST['content'] ?? ''));
                if (isset($_POST['with_bell']) && $_POST['with_bell'] === 'true') {
                    $content = "\x07" . $content;
                }

                $new_job = [
                    'name' => trim(strip_tags($_POST['name'] ?? '')),
                    'content' => $content,
                    'interval_mins' => max(1, (int)($_POST['interval_mins'] ?? 60)),
                    'enabled' => isset($_POST['enabled'])
                ];

                $job_type = $_POST['job_type'] ?? 'recurring';
                if ($job_type === 'recurring') {
                    $new_job['days'] = $_POST['days'] ?? [];
                    $new_job['start_time'] = trim(strip_tags($_POST['start_time'] ?? ''));
                    $new_job['stop_time'] = trim(strip_tags($_POST['stop_time'] ?? ''));
                } else {
                    $new_job['start_datetime'] = trim(strip_tags($_POST['start_datetime'] ?? ''));
                    $new_job['stop_datetime'] = trim(strip_tags($_POST['stop_datetime'] ?? ''));
                }

                if (isset($jobs[$job_index]['last_sent'])) {
                    $new_job['last_sent'] = $jobs[$job_index]['last_sent'];
                }

                $jobs[$job_index] = $new_job;
                if (save_dispatcher_jobs('', $jobs)) {
                    $message = "Broadcast job '" . htmlspecialchars($new_job['name']) . "' updated successfully.";
                } else {
                    $error = 'Failed to save broadcast jobs. Please check server logs.';
                }
            } else {
                $error = 'Invalid job index for update.';
            }
        }

        if ($action === 'add_broadcast_job') {
            $jobs = get_dispatcher_jobs('');
            $new_job_name = trim(strip_tags($_POST['new_broadcast_name'] ?? ''));
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
                        'name' => $new_job_name,
                        'content' => "Default content for {$new_job_name}. Please edit.",
                        'interval_mins' => 60,
                        'days' => ['MON', 'TUE', 'WED', 'THU', 'FRI'],
                        'start_time' => '08:00',
                        'stop_time' => '17:00',
                        'last_sent' => null,
                        'enabled' => false
                    ];
                    if (save_dispatcher_jobs('', $jobs)) {
                        $message = "Broadcast job '" . htmlspecialchars($new_job_name) . "' added. Click 'More...' to edit details.";
                    } else {
                        $error = 'Failed to add broadcast job. Please check server logs.';
                    }
                } else {
                    $error = 'A broadcast job with that name already exists.';
                }
            } else {
                $error = 'Broadcast name cannot be empty.';
            }
        }

        if ($action === 'delete_broadcast_job') {
            $jobs = get_dispatcher_jobs('');
            $job_index = $_POST['job_index'] ?? '';
            if (isset($jobs[$job_index])) {
                $job_name = $jobs[$job_index]['name'] ?? 'Untitled Job';
                unset($jobs[$job_index]);
                if (save_dispatcher_jobs('', $jobs)) {
                    $message = "Broadcast job '" . htmlspecialchars($job_name) . "' deleted successfully.";
                } else {
                    $error = 'Failed to delete broadcast job. Please check server logs.';
                }
            } else {
                $error = 'Invalid job index for deletion.';
            }
        }

        if ($action === 'run_weather_fetcher') {
            $queued_file = '';
            $command_id = '';
            $command_data = [
                'command' => 'run_weather_fetcher',
                'requested_by_panel' => 'mop',
                'requested_by_actor' => $audit_actor,
                'requested_at' => gmdate('c'),
            ];
            if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                $message = 'Weather fetcher command queued as ' . htmlspecialchars($queued_file) . ' (ID: ' . htmlspecialchars($command_id) . ').';
            } else {
                $error = 'Failed to queue weather fetcher command.';
            }
        }

        if ($action === 'run_email_processor') {
            $queued_file = '';
            $command_id = '';
            $command_data = [
                'command' => 'run_email_processor',
                'requested_by_panel' => 'mop',
                'requested_by_actor' => $audit_actor,
                'requested_at' => gmdate('c'),
            ];
            if (gb_queue_dispatcher_command($commands_dir, $command_data, $queued_file, $command_id)) {
                $message = 'Email processor command queued as ' . htmlspecialchars($queued_file) . ' (ID: ' . htmlspecialchars($command_id) . ').';
            } else {
                $error = 'Failed to queue email processor command.';
            }
        }

        if ($action === 'clear_email_queue') {
            try {
                gb_clear_outgoing_emails();
                $message = 'Outgoing email queue has been cleared.';
            } catch (Throwable $e) {
                $error = 'Failed to clear email queue. Please check server logs.';
                error_log('GuardianBridge Error: Failed to clear outgoing emails: ' . $e->getMessage());
            }
        }

        if ($action === 'clear_email_quarantine') {
            try {
                gb_clear_outgoing_emails_quarantine();
                $message = 'Outgoing email quarantine has been cleared.';
            } catch (Throwable $e) {
                $error = 'Failed to clear email quarantine. Please check server logs.';
                error_log('GuardianBridge Error: Failed to clear outgoing email quarantine: ' . $e->getMessage());
            }
        }

        if ($action === 'requeue_dead_letter_command') {
            if (!$audit_can_view_all) {
                $error = 'Access denied. Admin role required.';
            } else {
                $dead_letter_id = intval($_POST['dead_letter_id'] ?? 0);
                if ($dead_letter_id <= 0) {
                    $error = 'No dead-letter item selected for requeue.';
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
        }

        if ($action === 'delete_dead_letter_command') {
            if (!$audit_can_view_all) {
                $error = 'Access denied. Admin role required.';
            } else {
                $dead_letter_id = intval($_POST['dead_letter_id'] ?? 0);
                if ($dead_letter_id <= 0) {
                    $error = 'No dead-letter item selected for deletion.';
                } else {
                    $result = null;
                    if (gb_delete_command_dead_letter_with_file($dead_letter_id, $commands_dir, $result)) {
                        $message = 'Dead-letter command deleted.';
                    } else {
                        $why = htmlspecialchars((string)($result['error'] ?? 'unknown error'));
                        $error = "Failed to delete dead-letter command: {$why}";
                    }
                }
            }
        }

        if ($action === 'clear_dead_letter_commands') {
            if (!$audit_can_view_all) {
                $error = 'Access denied. Admin role required.';
            } else {
                try {
                    gb_clear_command_dead_letters();
                    $message = 'Dead-letter queue table has been cleared.';
                } catch (Throwable $e) {
                    $error = 'Failed to clear dead-letter queue. Please check server logs.';
                    error_log('GuardianBridge Error: Failed to clear dead-letter queue: ' . $e->getMessage());
                }
            }
        }

        if ($action === 'export_email_quarantine') {
            try {
                $export_data = gb_export_outgoing_emails_quarantine();
                gb_audit_mop_log('export_email_quarantine', 'outgoing_email_quarantine', ['count' => count($export_data)]);
                header('Content-Type: application/json');
                header('Content-Disposition: attachment; filename="outgoing_email_quarantine.json"');
                echo json_encode($export_data, JSON_PRETTY_PRINT);
                exit;
            } catch (Throwable $e) {
                $error = 'Failed to export email quarantine. Please check server logs.';
                error_log('GuardianBridge Error: Failed to export outgoing email quarantine: ' . $e->getMessage());
            }
        }

        if ($action === 'export_audit_log_json' || $action === 'export_audit_log_csv') {
            try {
                $requested_panel = strtolower(trim((string)($_POST['audit_panel'] ?? '')));
                $panel_filter = '';
                if ($audit_can_view_all) {
                    $panel_filter = ($requested_panel === 'map' || $requested_panel === 'mop') ? $requested_panel : '';
                } else {
                    $panel_filter = 'mop';
                }
                $actor_filter = $audit_can_view_all ? '' : $audit_actor;
                $limit = max(1, min(10000, intval($_POST['audit_limit'] ?? 2000)));
                $export_rows = gb_export_audit_logs($limit, $panel_filter, $actor_filter);
                $target = $audit_can_view_all ? (($panel_filter !== '') ? $panel_filter : 'all') : 'self';

                gb_audit_mop_log(
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
                $error = 'Failed to export audit log. Please check server logs.';
                error_log('GuardianBridge Error: Failed to export audit log: ' . $e->getMessage());
            }
        }

        if (empty($error) && $action !== '') {
            $target = '';
            $details = [];
            if ($action === 'update_user' || $action === 'delete_user') {
                $target = (string)($_POST['node_id'] ?? '');
            } elseif ($action === 'add_user') {
                $target = (string)($_POST['new_node_id'] ?? '');
            } elseif ($action === 'admin_clear_sos') {
                $target = (string)($_POST['node_id'] ?? '');
            } elseif ($action === 'save_broadcast_job' || $action === 'delete_broadcast_job') {
                $target = (string)($_POST['job_index'] ?? '');
            } elseif ($action === 'add_broadcast_job') {
                $target = (string)($_POST['new_broadcast_name'] ?? '');
            } elseif ($action === 'requeue_dead_letter_command' || $action === 'delete_dead_letter_command') {
                $target = (string)($_POST['dead_letter_id'] ?? '');
            } elseif ($action === 'clear_dead_letter_commands') {
                $target = 'all';
            }
            gb_audit_mop_log($action, $target, $details);
        }
    }
}

$queue_preview_limit = 25;
$dead_letter_preview_limit = 25;
$audit_preview_limit = 30;
$dispatcher_jobs = [];
$subscribers = [];
$node_statuses = [];
$outgoing_emails = gb_load_outgoing_emails($queue_preview_limit);
$outgoing_quarantine = gb_load_outgoing_emails_quarantine($queue_preview_limit);
$failed_dms = gb_load_failed_dm_queue($queue_preview_limit);
$command_dead_letters = gb_load_command_dead_letters($dead_letter_preview_limit);
$outgoing_email_count = count($outgoing_emails);
$outgoing_quarantine_count = count($outgoing_quarantine);
$failed_dm_count = count($failed_dms);
$command_dead_letter_count = count($command_dead_letters);
$recent_audit_entries = gb_load_audit_logs($audit_preview_limit, $audit_scope_panel, $audit_scope_actor);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mesh Operator Panel</title>
    <link rel="icon" type="image/x-icon" href="/map-items/map-logo.ico">
    <link href="/map-items/inter-font.css" rel="stylesheet">
    <link rel="stylesheet" href="/map-items/leaflet.css">
    <script src="/map-items/leaflet.js"></script>
    <style>
        :root {
            color-scheme: dark;
            --panel-bg: rgba(17, 18, 20, 0.78);
            --panel-border: rgba(255, 255, 255, 0.08);
            --text: #e5e7eb;
            --muted: #a1a1aa;
            --accent: #60a5fa;
            --danger: #ef4444;
            --warn: #f59e0b;
            --ok: #10b981;
        }
        * { box-sizing: border-box; }
        html, body { height: 100%; margin: 0; font-family: 'Inter', sans-serif; background: #101112; color: var(--text); }
        #map { position: fixed; inset: 0; z-index: 1; background: #1f2937; }
        .panel {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 10px;
            backdrop-filter: blur(6px);
            color: var(--text);
        }
        #left-panel {
            position: fixed;
            top: 12px;
            left: 12px;
            width: clamp(180px, 16vw, 220px);
            max-height: calc(100% - 24px);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            z-index: 900;
        }
        .panel-controls {
            display: flex;
            gap: 6px;
            padding: 6px;
            border-bottom: 1px solid var(--panel-border);
            background: rgba(8, 9, 10, 0.55);
        }
        .operator-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 6px;
            padding: 6px 8px;
            border-bottom: 1px solid var(--panel-border);
            font-size: 0.72rem;
            color: var(--muted);
            background: rgba(8, 9, 10, 0.45);
        }
        .operator-name { color: var(--text); font-weight: 600; }
        .logout-btn {
            background: rgba(148, 163, 184, 0.12);
            border: 1px solid rgba(148, 163, 184, 0.35);
            color: var(--text);
            padding: 4px 8px;
            border-radius: 8px;
            font-size: 0.7rem;
            text-decoration: none;
        }
        .panel-btn {
            flex: 1;
            font-size: 0.72rem;
            color: var(--muted);
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 6px 4px;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s ease, color 0.2s ease, border-color 0.2s ease;
        }
        .panel-btn:hover {
            color: var(--text);
            border-color: rgba(96, 165, 250, 0.4);
            background: rgba(96, 165, 250, 0.08);
        }
        .panel-body { flex: 1; display: flex; flex-direction: column; gap: 6px; padding: 6px; min-height: 0; }
        .panel-title { font-size: 0.75rem; letter-spacing: 0.04em; text-transform: uppercase; color: var(--muted); display: flex; justify-content: space-between; align-items: center; }
        .node-list { overflow-y: auto; display: flex; flex-direction: column; gap: 6px; padding-right: 4px; }
        .node-item {
            display: flex;
            gap: 8px;
            padding: 6px;
            border-radius: 6px;
            cursor: pointer;
            background: rgba(0, 0, 0, 0.18);
            border: 1px solid rgba(255, 255, 255, 0.06);
            transition: background 0.2s ease, border-color 0.2s ease;
        }
        .node-item:hover { background: rgba(0, 0, 0, 0.3); border-color: rgba(255, 255, 255, 0.12); }
        .node-item-sender { background: rgba(239, 68, 68, 0.14); border-color: rgba(239, 68, 68, 0.35); }
        .node-item-responder { background: rgba(16, 185, 129, 0.12); border-color: rgba(16, 185, 129, 0.32); }
        .node-item-ack { background: rgba(245, 158, 11, 0.14); border-color: rgba(245, 158, 11, 0.34); }
        .node-item-indent { margin-left: 14px; }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-top: 4px;
            background: #6b7280;
            flex-shrink: 0;
        }
        .status-ok { background: var(--ok); }
        .status-warn { background: var(--warn); }
        .status-stale { background: var(--danger); }
        .status-sos { background: var(--danger); box-shadow: 0 0 6px rgba(239, 68, 68, 0.8); }
        .node-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
        .node-name { font-size: 0.8rem; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .node-meta { font-size: 0.7rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .node-role-sender { color: #fecaca; }
        .node-role-responder { color: #a7f3d0; }
        .node-role-ack { color: #fde68a; }
        .node-list-divider {
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #94a3b8;
            margin: 4px 0 2px;
            padding-top: 6px;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
        }
        .node-sos-message {
            margin-left: 14px;
            padding: 6px 8px;
            border-radius: 6px;
            border: 1px solid rgba(239, 68, 68, 0.28);
            background: rgba(239, 68, 68, 0.08);
            font-size: 0.7rem;
            color: #fecaca;
            line-height: 1.3;
        }
        .node-id { font-size: 0.7rem; color: #94a3b8; margin-left: 4px; }
        .font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
        .open-dm-chat {
            background: transparent;
            border: none;
            color: var(--accent);
            font-size: 0.78rem;
            cursor: pointer;
            padding: 0;
        }
        .open-dm-chat:hover { text-decoration: underline; }
        .card {
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 12px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .card-title {
            font-size: 0.75rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--muted);
        }
        .row {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }
        .row-between {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            justify-content: space-between;
        }
        .field {
            display: flex;
            flex-direction: column;
            gap: 4px;
            min-width: 160px;
        }
        .field.grow { flex: 1; }
        .grow { flex: 1; }
        label { font-size: 0.75rem; color: var(--muted); }
        input[type="text"],
        input[type="email"],
        input[type="password"],
        input[type="number"],
        input[type="time"],
        input[type="datetime-local"],
        textarea,
        select {
            background: rgba(15, 16, 18, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: var(--text);
            padding: 6px 8px;
            font-size: 0.8rem;
        }
        textarea { resize: vertical; min-height: 80px; }
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: rgba(96, 165, 250, 0.5);
            box-shadow: 0 0 0 2px rgba(96, 165, 250, 0.2);
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.78rem;
            padding: 6px 10px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            background: rgba(148, 163, 184, 0.12);
            color: var(--text);
            cursor: pointer;
        }
        .btn:hover { border-color: rgba(255, 255, 255, 0.2); }
        .btn-primary { background: rgba(96, 165, 250, 0.2); border-color: rgba(96, 165, 250, 0.5); }
        .btn-secondary { background: rgba(148, 163, 184, 0.12); border-color: rgba(148, 163, 184, 0.35); }
        .btn-red { background: rgba(239, 68, 68, 0.18); border-color: rgba(239, 68, 68, 0.45); color: #fecaca; }
        .btn-green { background: rgba(16, 185, 129, 0.2); border-color: rgba(16, 185, 129, 0.45); color: #d1fae5; }
        .btn-sm { padding: 4px 8px; font-size: 0.7rem; }
        .inline-block { display: inline-block; }
        .mr-2 { margin-right: 8px; }
        .alert {
            padding: 8px 10px;
            border-radius: 8px;
            border: 1px solid transparent;
            font-size: 0.78rem;
        }
        .alert.success {
            background: rgba(16, 185, 129, 0.15);
            border-color: rgba(16, 185, 129, 0.45);
            color: #d1fae5;
        }
        .alert.error {
            background: rgba(239, 68, 68, 0.15);
            border-color: rgba(239, 68, 68, 0.45);
            color: #fecaca;
        }
        .alert pre {
            margin: 6px 0 0;
            white-space: pre-wrap;
            font-size: 0.7rem;
        }
        .scroll-list {
            max-height: 200px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .list-item {
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 8px;
            font-size: 0.75rem;
        }
        .table-wrap {
            overflow-x: auto;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
        }
        .admin-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.78rem;
        }
        .admin-table th, .admin-table td {
            padding: 8px 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }
        .admin-table th {
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--muted);
            background: rgba(0, 0, 0, 0.2);
        }
        .admin-table tr:last-child td { border-bottom: none; }
        .role-pill {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 6px;
            font-size: 0.65rem;
            margin-bottom: 4px;
        }
        .role-pill.status-ok {
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid rgba(16, 185, 129, 0.4);
            color: #a7f3d0;
        }
        .role-pill.status-warn {
            background: rgba(245, 158, 11, 0.2);
            border: 1px solid rgba(245, 158, 11, 0.4);
            color: #fde68a;
        }
        .role-pill.status-muted {
            background: rgba(148, 163, 184, 0.12);
            border: 1px solid rgba(148, 163, 184, 0.3);
            color: var(--muted);
        }
        .pill-sos {
            display: inline-block;
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.45);
            color: #fecaca;
            border-radius: 999px;
            padding: 2px 6px;
            font-size: 0.65rem;
            margin-right: 6px;
        }
        .indent { padding-left: 16px; }
        .row-sos-sender { background: rgba(239, 68, 68, 0.12); }
        .row-sos-responder { background: rgba(16, 185, 129, 0.12); }
        .row-sos-ack { background: rgba(245, 158, 11, 0.12); }
        .row-sos-message td { background: rgba(239, 68, 68, 0.08); color: #fecaca; }
        .status-ok { color: #a7f3d0; }
        .status-warn { color: #fde68a; }
        .status-fail { color: #fecaca; }
        .status-muted { color: var(--muted); }
        .mt-2 { margin-top: 8px; }
        .placeholder {
            font-size: 0.75rem;
            color: var(--muted);
            padding: 10px 6px;
            border: 1px dashed rgba(255, 255, 255, 0.08);
            border-radius: 6px;
            background: rgba(0, 0, 0, 0.15);
        }
        #status-panel {
            position: fixed;
            right: 12px;
            bottom: 12px;
            width: clamp(220px, 22vw, 280px);
            max-width: calc(100% - 24px);
            padding: 8px 10px;
            z-index: 900;
            font-size: 0.72rem;
            line-height: 1.35;
        }
        #status-panel h3 {
            margin: 0 0 4px 0;
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--muted);
        }
        .status-line { display: flex; align-items: center; gap: 6px; }
        .status-pill { width: 7px; height: 7px; border-radius: 50%; background: #6b7280; display: inline-block; }
        .status-pill.ok { background: var(--ok); }
        .status-pill.fail { background: var(--danger); }
        .status-pill.warn { background: var(--warn); }
        .status-section { margin-bottom: 6px; }
        .status-section:last-child { margin-bottom: 0; }
        .status-muted { color: var(--muted); }

        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.72);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 980;
            padding: 16px;
        }
        #user-edit-modal,
        #broadcast-edit-modal { z-index: 1005; }
        #confirm-action-modal { z-index: 1100; }
        .modal-overlay.active { display: flex; }
        .modal-card {
            width: min(980px, 96vw);
            max-height: 90vh;
            display: flex;
            flex-direction: column;
            background: rgba(17, 18, 20, 0.97);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 18px 40px rgba(0, 0, 0, 0.4);
        }
        .modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }
        .modal-header h2 {
            margin: 0;
            font-size: 1.05rem;
        }
        .modal-close {
            background: transparent;
            border: none;
            color: var(--muted);
            font-size: 1.2rem;
            cursor: pointer;
        }
        .modal-body {
            padding: 14px 16px 18px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }
        .modal-footer {
            padding: 10px 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            background: rgba(10, 11, 12, 0.6);
        }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(1, minmax(0, 1fr));
            gap: 12px;
        }
        .form-grid.columns-2 {
            grid-template-columns: repeat(1, minmax(0, 1fr));
        }
        @media (min-width: 900px) {
            .form-grid.columns-2 {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        .form-grid .span-2 { grid-column: span 2; }
        .checkbox-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 8px 16px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            padding: 8px;
        }
        .danger-label { color: #fca5a5; font-weight: 600; }
        .admin-note { font-size: 0.72rem; color: var(--muted); }
        .modal-section h3 {
            margin: 0 0 6px 0;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--muted);
        }
        .modal-table-wrap {
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            overflow: hidden;
            background: rgba(0, 0, 0, 0.2);
        }
        .modal-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.78rem;
        }
        .modal-table th,
        .modal-table td {
            padding: 8px 10px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }
        .modal-table th {
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--muted);
            background: rgba(0, 0, 0, 0.2);
        }
        .modal-table tr:last-child td { border-bottom: none; }
        #dm-chat-modal {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.7);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        .chat-card {
            width: min(520px, 92vw);
            max-height: 85vh;
            display: flex;
            flex-direction: column;
            background: rgba(17, 18, 20, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            overflow: hidden;
        }
        .chat-header {
            padding: 10px 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            font-size: 0.9rem;
        }
        .chat-header-actions {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .chat-header button {
            background: transparent;
            border: none;
            color: var(--muted);
            font-size: 1.1rem;
            cursor: pointer;
        }
        .chat-map-btn {
            background: rgba(96, 165, 250, 0.15);
            color: var(--text);
            border: 1px solid rgba(96, 165, 250, 0.4);
            border-radius: 8px;
            padding: 4px 10px;
            font-size: 0.75rem;
            cursor: pointer;
        }
        .chat-map-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        #dm-chat-window { flex: 1; overflow-y: auto; padding: 10px; }
        #dm-chat-messages-container { display: flex; flex-direction: column; gap: 8px; }
        .message { max-width: 82%; padding: 0.35rem 0.75rem; border-radius: 0.7rem; border: 1px solid transparent; }
        .message-incoming { align-self: flex-start; border-top-left-radius: 0; border-left: 3px solid #60a5fa; background: rgba(96, 165, 250, 0.08); }
        .message-outgoing { align-self: flex-end; border-bottom-right-radius: 0; border-right: 3px solid #a78bfa; background: rgba(167, 139, 250, 0.08); }
        .message-system { align-self: center; max-width: 90%; background: rgba(148, 163, 184, 0.12); border: 1px dashed rgba(148, 163, 184, 0.35); }
        .message-username { font-size: 0.7rem; font-weight: 600; margin-bottom: 2px; }
        .message-content { font-size: 0.8rem; line-height: 1.3; white-space: pre-wrap; word-break: break-word; }
        .message-meta { font-size: 0.65rem; color: var(--muted); margin-top: 2px; }
        .bell-indicator { font-size: 0.65rem; color: #facc15; margin-right: 4px; }
        .dm-prefix { font-size: 0.7rem; font-weight: 600; color: #facc15; margin-right: 4px; }
        .chat-username {
            background: none;
            border: none;
            color: inherit;
            padding: 0;
            font-family: inherit;
            text-align: left;
            cursor: pointer;
        }
        .chat-username:hover {
            color: #93c5fd;
            text-decoration: underline;
        }
        .chat-title-button {
            font-size: inherit;
            font-weight: 600;
            color: var(--text);
        }
        .chat-title-button:disabled {
            cursor: default;
            color: var(--muted);
            text-decoration: none;
        }
        .chat-form {
            display: flex;
            gap: 6px;
            padding: 8px 10px 10px;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
            background: rgba(10, 11, 12, 0.6);
        }
        .chat-form textarea {
            flex: 1;
            resize: none;
            background: rgba(15, 16, 18, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            color: var(--text);
            font-size: 0.8rem;
            padding: 6px 8px;
            min-height: 42px;
        }
        .chat-form button {
            background: rgba(96, 165, 250, 0.15);
            color: var(--text);
            border: 1px solid rgba(96, 165, 250, 0.4);
            border-radius: 8px;
            padding: 6px 10px;
            font-size: 0.75rem;
            cursor: pointer;
        }
        .chat-form button.secondary {
            background: rgba(148, 163, 184, 0.08);
            border-color: rgba(148, 163, 184, 0.3);
        }
        .chat-form button:disabled { opacity: 0.5; cursor: not-allowed; }
        .chat-panel {
            display: flex;
            flex-direction: column;
            height: min(72vh, 620px);
            background: rgba(12, 13, 14, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            overflow: hidden;
        }
        .chat-panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 12px 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            font-size: 0.9rem;
        }
        .chat-filters {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.75rem;
            color: var(--muted);
        }
        .chat-filters label { display: flex; align-items: center; gap: 6px; cursor: pointer; }
        .filter-checkbox { accent-color: #60a5fa; }
        .chat-group-tabs-wrap {
            padding: 8px 12px 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            background: rgba(0, 0, 0, 0.2);
        }
        .chat-group-tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        .chat-group-tab {
            border: 1px solid rgba(148, 163, 184, 0.35);
            background: rgba(30, 41, 59, 0.55);
            color: var(--text);
            border-radius: 999px;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 4px 10px;
            cursor: pointer;
            transition: border-color 0.2s, background-color 0.2s, opacity 0.2s;
        }
        .chat-group-tab:hover {
            border-color: rgba(96, 165, 250, 0.9);
        }
        .chat-group-tab.active {
            border-color: rgba(96, 165, 250, 0.9);
            background: rgba(30, 64, 175, 0.35);
        }
        .chat-group-tab.locked {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .chat-group-caption {
            margin-top: 6px;
            font-size: 0.7rem;
            color: var(--muted);
        }
        #chat-window { flex: 1; overflow-y: auto; padding: 12px; }
        #chat-messages-container { display: flex; flex-direction: column; gap: 8px; }
        .user-info-popup {
            position: fixed;
            top: 18px;
            right: 18px;
            width: min(360px, 92vw);
            max-height: 80vh;
            display: none;
            flex-direction: column;
            background: rgba(15, 16, 18, 0.96);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.55);
            z-index: 1600;
        }
        .user-info-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            padding: 10px 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            font-size: 0.9rem;
        }
        .user-info-actions {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .user-info-close {
            background: transparent;
            border: none;
            color: var(--muted);
            font-size: 1.1rem;
            cursor: pointer;
            min-width: 24px;
            line-height: 1;
            text-align: center;
        }
        .user-info-popup.minimized { max-height: none; }
        .user-info-popup.minimized .user-info-body { display: none; }
        .user-info-body {
            padding: 12px;
            overflow-y: auto;
            font-size: 0.78rem;
            display: grid;
            gap: 8px;
        }
        .user-info-row {
            display: grid;
            grid-template-columns: 110px 1fr;
            gap: 8px;
            align-items: start;
        }
        .user-info-label { color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.62rem; }
        .user-info-value { color: var(--text); word-break: break-word; white-space: pre-wrap; }
        .ops-notes-editor {
            display: grid;
            gap: 6px;
            margin-top: 4px;
        }
        .ops-notes-input {
            width: 100%;
            min-height: 84px;
            resize: vertical;
            border-radius: 8px;
            border: 1px solid rgba(148, 163, 184, 0.35);
            background: rgba(15, 23, 42, 0.6);
            color: var(--text);
            padding: 8px 10px;
            font-size: 0.76rem;
            line-height: 1.35;
        }
        .ops-notes-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            justify-content: space-between;
        }
        .ops-notes-save-btn {
            border: 1px solid rgba(74, 222, 128, 0.55);
            background: rgba(22, 101, 52, 0.45);
            color: #dcfce7;
            border-radius: 999px;
            padding: 4px 12px;
            font-size: 0.68rem;
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            cursor: pointer;
        }
        .ops-notes-save-btn:disabled {
            opacity: 0.6;
            cursor: wait;
        }
        .ops-notes-status {
            font-size: 0.65rem;
            color: var(--muted);
            min-height: 1em;
        }
        .ops-notes-status.ok { color: #86efac; }
        .ops-notes-status.err { color: #fca5a5; }
        .sos-popup-container {
            position: fixed;
            right: 12px;
            bottom: 12px;
            width: min(380px, 94vw);
            display: none;
            flex-direction: column;
            gap: 8px;
            z-index: 1500;
            pointer-events: none;
        }
        .sos-popup {
            width: 100%;
            max-height: 70vh;
            display: flex;
            flex-direction: column;
            background: rgba(20, 10, 10, 0.96);
            border: 1px solid rgba(239, 68, 68, 0.45);
            border-left: 4px solid #ef4444;
            border-radius: 12px;
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.6);
            pointer-events: auto;
            overflow: hidden;
        }
        .sos-popup-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            padding: 10px 12px;
            border-bottom: 1px solid rgba(239, 68, 68, 0.25);
        }
        .sos-popup-actions {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-shrink: 0;
        }
        .sos-popup-map {
            background: rgba(239, 68, 68, 0.18);
            border: 1px solid rgba(239, 68, 68, 0.45);
            color: #fecaca;
            padding: 3px 10px;
            border-radius: 999px;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            cursor: pointer;
        }
        .sos-popup-map:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .sos-popup-title {
            flex: 1;
            min-width: 0;
            font-size: 0.85rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #fecaca;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .sos-popup-close {
            background: transparent;
            border: none;
            color: #fecaca;
            font-size: 1.2rem;
            cursor: pointer;
            min-width: 24px;
            line-height: 1;
            text-align: center;
        }
        .sos-popup.minimized {
            max-height: none;
        }
        .sos-popup.minimized .sos-popup-body { display: none; }
        .sos-popup-body {
            padding: 10px 12px 12px;
            overflow-y: auto;
            display: grid;
            gap: 10px;
            font-size: 0.78rem;
        }
        .sos-popup-section {
            font-size: 0.62rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--muted);
            margin-top: 2px;
        }
        .sos-popup-summary,
        .sos-popup-info {
            display: grid;
            gap: 8px;
        }
        .sos-popup .user-info-row { grid-template-columns: 90px 1fr; }

        .leaflet-popup-content-wrapper, .leaflet-popup-tip {
            background: rgba(17, 18, 20, 0.95);
            color: var(--text);
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 3px 14px rgba(0, 0, 0, 0.4);
        }
        @keyframes flash-red {
            0%, 100% { background-color: #dc2626; }
            50% { background-color: #ef4444; }
        }
        #sos-banner { animation: flash-red 1s infinite; }
        .sos-banner-content {
            display: flex;
            flex-direction: column;
            gap: 2px;
            text-align: left;
            flex: 1;
            min-width: 0;
        }
        .sos-banner-title {
            font-size: 1rem;
            font-weight: 700;
            line-height: 1.2;
        }
        .sos-banner-details {
            font-size: 0.85rem;
            font-weight: 500;
            opacity: 0.95;
            line-height: 1.2;
            word-break: break-word;
        }
        .sos-banner-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-left: 12px;
        }
        .sos-banner-btn {
            background: rgba(15, 16, 18, 0.28);
            border: 1px solid rgba(255, 255, 255, 0.35);
            color: #fff;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 0.75rem;
            cursor: pointer;
        }
        .sos-banner-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .leaflet-popup-content { margin: 10px 12px; }
        .leaflet-control-attribution { font-size: 0.65rem; }
        .leaflet-top.leaflet-left { margin-left: clamp(190px, 17vw, 230px); }
        @media (max-width: 720px) {
            #left-panel { width: clamp(160px, 36vw, 200px); }
            .leaflet-top.leaflet-left { margin-left: clamp(170px, 34vw, 210px); }
        }
</style>
</head>
<body>
    <div id="sos-banner" style="display: none;" class="fixed top-0 left-0 w-full text-white p-3 z-[1100] flex justify-between items-center">
        <div class="sos-banner-content">
            <div id="sos-banner-title" class="sos-banner-title"></div>
            <div id="sos-banner-details" class="sos-banner-details"></div>
            <span id="sos-banner-text" style="display: none;"></span>
        </div>
        <div class="sos-banner-actions">
            <button type="button" id="sos-banner-open-btn" class="sos-banner-btn">Actions</button>
            <button type="button" id="sos-banner-mute-btn" class="sos-banner-btn">Mute 5m</button>
            <button type="button" id="sos-banner-sound-btn" class="sos-banner-btn">Sound On</button>
            <button type="button" id="sos-banner-ack-btn" class="sos-banner-btn">Acknowledge</button>
        </div>
    </div>
    <div id="map"></div>

    <div id="left-panel" class="panel">
        <div class="panel-controls">
            <button class="panel-btn" data-admin-tab="chat">Chat</button>
            <button class="panel-btn" data-admin-tab="actions">Actions</button>
            <button class="panel-btn" data-admin-tab="broadcasts">Broadcasts</button>
            <button class="panel-btn" data-admin-tab="users">Users</button>
        </div>
        <div class="operator-bar">
            <span>Operator: <span class="operator-name"><?= htmlspecialchars($_SESSION['operator_name'] ?? 'Unknown') ?></span></span>
            <a href="?logout=true" class="logout-btn">Log Off</a>
        </div>
        <div class="panel-body">
            <div class="panel-title">
                <span>Nodes</span>
                <span id="node-count">0</span>
            </div>
            <div id="node-list" class="node-list">
                <div class="placeholder">Loading nodes...</div>
            </div>
        </div>
    </div>

    <div id="status-panel" class="panel">
        <div class="status-section">
            <h3>System Health</h3>
            <div id="system-health-body" class="status-muted">Loading health...</div>
        </div>
        <div class="status-section">
            <h3>Weather & Alerts</h3>
            <div id="weather-body" class="status-muted">Loading weather...</div>
        </div>
    </div>

    <div id="sos-popup-container" class="sos-popup-container" aria-live="assertive" aria-atomic="true"></div>

    <div id="user-info-popup" class="user-info-popup" aria-live="polite">
        <div class="user-info-header">
            <span id="user-info-title">INFO</span>
            <div class="user-info-actions">
                <button type="button" id="user-info-minimize" class="user-info-close" aria-label="Minimize Info panel" title="Minimize">-</button>
                <button type="button" id="user-info-close" class="user-info-close" aria-label="Close Info panel" title="Close">&times;</button>
            </div>
        </div>
        <div id="user-info-body" class="user-info-body"></div>
    </div>

    <div id="modal-chat" class="modal-overlay" data-admin-panel>
        <div class="modal-card" style="width: min(980px, 96vw);">
            <div class="modal-header">
                <h2>Chat</h2>
                <button type="button" class="modal-close" data-close>&times;</button>
            </div>
            <div class="modal-body">
                <div class="chat-panel">
                    <div class="chat-panel-header">
                        <span>Channel Traffic</span>
                        <div class="chat-filters">
                            <label><input type="checkbox" id="show-dms-checkbox" class="filter-checkbox"> DMs</label>
                            <label><input type="checkbox" id="show-sms-checkbox" class="filter-checkbox"> Server Msgs</label>
                        </div>
                    </div>
                    <div class="chat-group-tabs-wrap">
                        <div id="chat-group-tabs" class="chat-group-tabs"></div>
                        <div id="chat-group-caption" class="chat-group-caption">Manual @user, @tag, or @all still overrides the selected group.</div>
                    </div>
                    <div id="chat-window">
                        <div id="chat-messages-container">
                            <div class="placeholder">Loading messages...</div>
                        </div>
                    </div>
                    <div id="main-chat-form" class="chat-form">
                        <textarea id="main-chat-textarea" rows="2" placeholder="Type message, @user, or @all ..."></textarea>
                        <button type="button" id="main-chat-bell-btn" class="secondary">Bell</button>
                        <button type="button" id="main-chat-send-btn">Send</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="modal-actions" class="modal-overlay" data-admin-panel>
        <div class="modal-card">
            <div class="modal-header">
                <h2>Actions</h2>
                <button type="button" class="modal-close" data-close>&times;</button>
            </div>
            <div class="modal-body">
                <?php if (!empty($message)): ?>
                    <div class="alert success"><?= $message ?></div>
                <?php endif; ?>
                <?php if (!empty($error)): ?>
                    <div class="alert error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-title">Manual Actions</div>
                    <div class="row">
                        <form method="POST">
                            <input type="hidden" name="action" value="run_weather_fetcher">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                            <button type="submit" class="btn btn-secondary">Fetch Weather Now</button>
                        </form>
                        <form method="POST">
                            <input type="hidden" name="action" value="run_email_processor">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                            <button type="submit" class="btn btn-secondary">Process Emails Now</button>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">Outgoing Email Queue (<?= intval($outgoing_email_count) ?>)</div>
                    <?php if (!empty($outgoing_emails)): ?>
                        <?php if (count($outgoing_emails) >= $queue_preview_limit): ?>
                            <div class="status-muted">Showing latest <?= count($outgoing_emails) ?> entries for fast page load.</div>
                        <?php endif; ?>
                        <div class="scroll-list">
                            <?php foreach ($outgoing_emails as $email): ?>
                                <div class="list-item">
                                    <div><strong>To:</strong> <?= htmlspecialchars($email['recipient'] ?? '') ?></div>
                                    <div><strong>Subject:</strong> <?= htmlspecialchars($email['subject'] ?? '') ?></div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <form method="POST" class="mt-2" id="clear-email-queue-form">
                            <input type="hidden" name="action" value="clear_email_queue">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                            <button type="submit" class="btn btn-red">Clear Queue</button>
                        </form>
                    <?php else: ?>
                        <div class="status-muted">The outgoing email queue is empty.</div>
                    <?php endif; ?>
                </div>

                <div class="card">
                    <div class="card-title">Outgoing Email Quarantine (<?= intval($outgoing_quarantine_count) ?>)</div>
                    <?php if (!empty($outgoing_quarantine)): ?>
                        <?php if (count($outgoing_quarantine) >= $queue_preview_limit): ?>
                            <div class="status-muted">Showing latest <?= count($outgoing_quarantine) ?> entries for fast page load.</div>
                        <?php endif; ?>
                        <div class="scroll-list">
                            <?php foreach ($outgoing_quarantine as $email): ?>
                                <div class="list-item">
                                    <div><strong>Reason:</strong> <?= htmlspecialchars($email['reason'] ?? 'unknown') ?></div>
                                    <div><strong>Queued:</strong> <?= htmlspecialchars(date('Y-m-d H:i:s', $email['created_at'] ?? time())) ?></div>
                                    <div><strong>To:</strong> <?= htmlspecialchars($email['recipient'] ?? '') ?></div>
                                    <div><strong>Subject:</strong> <?= htmlspecialchars($email['subject'] ?? '') ?></div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <div class="row mt-2">
                            <form method="POST" id="clear-email-quarantine-form">
                                <input type="hidden" name="action" value="clear_email_quarantine">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red">Clear Quarantine</button>
                            </form>
                            <form method="POST" id="export-email-quarantine-form">
                                <input type="hidden" name="action" value="export_email_quarantine">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-secondary">Export Quarantine JSON</button>
                            </form>
                        </div>
                        <div class="status-muted">Export includes recipient addresses and message metadata.</div>
                    <?php else: ?>
                        <div class="status-muted">The quarantine is empty.</div>
                    <?php endif; ?>
                </div>

                <div class="card">
                    <div class="card-title">Queued Direct Messages (<?= intval($failed_dm_count) ?>)</div>
                    <?php if (!empty($failed_dms)): ?>
                        <?php if (count($failed_dms) >= $queue_preview_limit): ?>
                            <div class="status-muted">Showing latest <?= count($failed_dms) ?> entries for fast page load.</div>
                        <?php endif; ?>
                        <div class="scroll-list">
                            <?php foreach ($failed_dms as $dm): ?>
                                <div class="list-item">
                                    <div><strong>To:</strong> <?= htmlspecialchars($dm['destination_id'] ?? '') ?></div>
                                    <div><strong>Queued:</strong> <?= htmlspecialchars($dm['timestamp'] ?? '') ?></div>
                                    <div><strong>Text:</strong> <?= htmlspecialchars($dm['text'] ?? '') ?></div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="status-muted">The direct message queue is empty.</div>
                    <?php endif; ?>
                </div>

                <div class="card">
                    <div class="card-title">Command Dead-Letter Queue (<?= intval($command_dead_letter_count) ?>)</div>
                    <?php if (!empty($command_dead_letters)): ?>
                        <?php if (count($command_dead_letters) >= $dead_letter_preview_limit): ?>
                            <div class="status-muted">Showing latest <?= count($command_dead_letters) ?> entries for fast page load.</div>
                        <?php endif; ?>
                        <div class="scroll-list">
                            <?php foreach ($command_dead_letters as $row): ?>
                                <?php
                                $details = is_array($row['details'] ?? null) ? $row['details'] : [];
                                $detail_parts = [];
                                foreach ($details as $k => $v) {
                                    if (!is_scalar($v) || $v === '') { continue; }
                                    $detail_parts[] = $k . '=' . $v;
                                    if (count($detail_parts) >= 4) { break; }
                                }
                                ?>
                                <div class="list-item">
                                    <div><strong><?= htmlspecialchars(date('Y-m-d H:i:s', intval($row['created_at'] ?? 0))) ?></strong></div>
                                    <div><strong>Reason:</strong> <?= htmlspecialchars($row['reason'] ?? 'unknown') ?></div>
                                    <div><strong>Source:</strong> <span class="font-mono"><?= htmlspecialchars($row['source_file'] ?? '') ?></span></div>
                                    <div><strong>ID:</strong> <span class="font-mono"><?= htmlspecialchars($row['command_id'] ?? '') ?></span></div>
                                    <?php if (!empty($detail_parts)): ?>
                                        <div class="status-muted"><?= htmlspecialchars(implode(' | ', $detail_parts)) ?></div>
                                    <?php endif; ?>
                                    <?php if ($audit_can_view_all): ?>
                                        <div class="row mt-2">
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
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <?php if ($audit_can_view_all): ?>
                            <form method="POST" class="mt-2" id="clear-dead-letter-queue-form">
                                <input type="hidden" name="action" value="clear_dead_letter_commands">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red">Clear Dead-Letter Table</button>
                            </form>
                        <?php else: ?>
                            <div class="status-muted">Admin role required for dead-letter requeue/delete actions.</div>
                        <?php endif; ?>
                        <div class="status-muted">Requeue creates a new queued command with a fresh command ID so duplicate suppression does not block retries.</div>
                    <?php else: ?>
                        <div class="status-muted">No dead-letter command rows.</div>
                    <?php endif; ?>
                </div>

                <div class="card">
                    <div class="card-title">Blocked Email Senders</div>
                    <div id="blocklist-container" class="scroll-list">
                        <div class="status-muted">Loading blocklist...</div>
                    </div>
                    <form id="add-to-blocklist-form" class="row mt-2">
                        <input type="email" id="new-blocked-email" placeholder="email-to-block@example.com" required>
                        <button type="submit" class="btn btn-primary">Add to Blocklist</button>
                    </form>
                </div>

                <div class="card">
                    <div class="card-title">Recent Audit Activity (<?= count($recent_audit_entries) ?>)</div>
                    <div class="status-muted">Scope: <?= htmlspecialchars($audit_scope_label) ?>. Showing latest <?= count($recent_audit_entries) ?> entries for fast page load.</div>
                    <div class="row mt-2">
                        <form method="POST" class="row">
                            <input type="hidden" name="action" value="export_audit_log_json">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                            <?php if ($audit_can_view_all): ?>
                                <select name="audit_panel">
                                    <option value="">All panels</option>
                                    <option value="mop">MOP only</option>
                                    <option value="map">MAP only</option>
                                </select>
                            <?php else: ?>
                                <input type="hidden" name="audit_panel" value="mop">
                            <?php endif; ?>
                            <input type="number" name="audit_limit" value="2000" min="1" max="10000" style="max-width: 6rem;">
                            <button type="submit" class="btn btn-secondary">Export JSON</button>
                        </form>
                        <form method="POST" class="row">
                            <input type="hidden" name="action" value="export_audit_log_csv">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                            <input type="hidden" name="audit_panel" value="<?= $audit_can_view_all ? '' : 'mop' ?>">
                            <input type="hidden" name="audit_limit" value="2000">
                            <button type="submit" class="btn btn-secondary">Export CSV</button>
                        </form>
                    </div>
                    <?php if (!empty($recent_audit_entries)): ?>
                        <div class="scroll-list">
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
                                <div class="list-item">
                                    <div><strong><?= htmlspecialchars(date('Y-m-d H:i:s', intval($entry['created_at'] ?? 0))) ?></strong></div>
                                    <div><?= htmlspecialchars($entry['actor'] ?? 'unknown') ?> [<?= htmlspecialchars($entry['panel'] ?? '-') ?>] <?= htmlspecialchars($entry['action'] ?? '-') ?><?php if (!empty($entry['target'])): ?> -> <?= htmlspecialchars($entry['target']) ?><?php endif; ?></div>
                                    <?php if (!empty($detail_parts)): ?>
                                        <div class="status-muted"><?= htmlspecialchars(implode(' | ', $detail_parts)) ?></div>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="status-muted">No audit events recorded yet.</div>
                    <?php endif; ?>
                </div>

                <div class="card">
                    <div class="row-between">
                        <div class="card-title">SOS Incident Command</div>
                        <div class="row">
                            <form method="POST" id="admin-clear-sos-form">
                                <input type="hidden" name="action" value="admin_clear_sos">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <input type="hidden" name="node_id" value="">
                                <button type="submit" class="btn btn-secondary" disabled title="No active SOS detected.">Admin Clear Active SOS</button>
                            </form>
                            <a href="/map-items/api_download_sos_log.php" class="btn btn-secondary" download>SOS Log Download</a>
                        </div>
                    </div>
                    <div class="status-muted">Live list of nodes actively sending or responding to SOS events.</div>
                    <div class="table-wrap">
                        <table class="admin-table">
                            <thead>
                                <tr>
                                    <th>Node ID / Name</th>
                                    <th>Last Contact</th>
                                    <th>SNR</th>
                                    <th>Hops</th>
                                    <th>Role</th>
                                    <th>Position</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="admin-sos-node-list-body">
                                <tr><td colspan="7" class="status-muted">Loading live SOS data...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="modal-broadcasts" class="modal-overlay" data-admin-panel>
        <div class="modal-card">
            <div class="modal-header">
                <h2>Broadcasts</h2>
                <button type="button" class="modal-close" data-close>&times;</button>
            </div>
            <div class="modal-body">
                <?php if (!empty($message)): ?>
                    <div class="alert success"><?= $message ?></div>
                <?php endif; ?>
                <?php if (!empty($error)): ?>
                    <div class="alert error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-title">Manage Custom Broadcasts</div>
                    <div class="table-wrap">
                        <table class="admin-table">
                            <thead>
                                <tr>
                                    <th>Status</th>
                                    <th>Broadcast Name</th>
                                    <th>Active Days</th>
                                    <th>Interval</th>
                                    <th>Time / Date Window</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="mop-broadcasts-table-body">
                                <tr><td colspan="6" class="status-muted">Loading broadcasts...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">Add New Broadcast</div>
                    <form method="POST" class="row">
                        <input type="hidden" name="action" value="add_broadcast_job">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <div class="field grow">
                            <label for="new_broadcast_name">New Broadcast Name</label>
                            <input type="text" id="new_broadcast_name" name="new_broadcast_name" placeholder="E.g., Daily Weather Summary" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Add Broadcast</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <div id="modal-users" class="modal-overlay" data-admin-panel>
        <div class="modal-card">
            <div class="modal-header">
                <h2>Users</h2>
                <button type="button" class="modal-close" data-close>&times;</button>
            </div>
            <div class="modal-body">
                <?php if (!empty($message)): ?>
                    <div class="alert success"><?= $message ?></div>
                <?php endif; ?>
                <?php if (!empty($error)): ?>
                    <div class="alert error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-title">Manage Subscribers</div>
                    <div class="table-wrap">
                        <table class="admin-table">
                            <thead>
                                <tr>
                                    <th>Node ID</th>
                                    <th>Username</th>
                                    <th>Role</th>
                                    <th>Full Name</th>
                                    <th>Phone 1</th>
                                    <th>Tags</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="mop-users-table-body">
                                <tr><td colspan="7" class="status-muted">Loading subscribers...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">Add New Subscriber</div>
                    <form method="POST" class="row">
                        <input type="hidden" name="action" value="add_user">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <div class="field">
                            <label for="new_node_id">Node ID</label>
                            <input type="text" id="new_node_id" name="new_node_id" placeholder="!a1b2c3d4" required class="font-mono">
                        </div>
                        <div class="field grow">
                            <label for="new_name">Username</label>
                            <input type="text" id="new_name" name="new_name" placeholder="New User" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Add User</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <div id="user-edit-modal" class="modal-overlay" style="display: none;">
        <div class="modal-card" style="width: min(980px, 96vw);">
            <div class="modal-header">
                <h2 id="user-modal-title"><span>Edit User</span></h2>
                <button type="button" id="close-user-modal-btn" class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <form id="user-edit-form" method="POST" class="form-grid columns-2">
                    <input type="hidden" name="action" value="update_user">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                    <input type="hidden" name="node_id" value="">

                    <div class="field">
                        <label for="name">Username</label>
                        <input type="text" name="name" id="name" required>
                    </div>
                    <div class="field">
                        <label for="full_name">Full Name</label>
                        <input type="text" name="full_name" id="full_name">
                    </div>
                    <div class="field">
                        <label for="user_role">Assigned Role</label>
                        <select name="role" id="user_role">
                            <option value="">Not Set</option>
                            <option value="CLIENT">CLIENT (Default Repeater)</option>
                            <option value="CLIENT_MUTE">CLIENT_MUTE (No Repeat)</option>
                            <option value="ROUTER">ROUTER (Fixed Repeater)</option>
                            <option value="REPEATER">REPEATER (Legacy Repeater)</option>
                        </select>
                    </div>
                    <div class="field">
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email">
                    </div>
                    <div class="field">
                        <label for="phone_1">Phone 1</label>
                        <input type="text" name="phone_1" id="phone_1">
                    </div>
                    <div class="field">
                        <label for="phone_2">Phone 2</label>
                        <input type="text" name="phone_2" id="phone_2">
                    </div>
                    <div class="field span-2">
                        <label for="address_street">Street Address</label>
                        <input type="text" name="address_street" id="address_street">
                    </div>
                    <div class="field">
                        <label for="address_city">City</label>
                        <input type="text" name="address_city" id="address_city">
                    </div>
                    <div class="field">
                        <label for="address_state">State</label>
                        <input type="text" name="address_state" id="address_state">
                    </div>
                    <div class="field">
                        <label for="address_zip">Zip Code</label>
                        <input type="text" name="address_zip" id="address_zip">
                    </div>
                    <div class="span-2">
                        <div class="row">
                            <div class="field grow">
                                <label for="address_lat">Address Lat</label>
                                <input type="text" name="address_lat" id="address_lat" class="font-mono" placeholder="e.g., 40.7128">
                            </div>
                            <div class="field grow">
                                <label for="address_lon">Address Lon</label>
                                <input type="text" name="address_lon" id="address_lon" class="font-mono" placeholder="e.g., -74.0060">
                            </div>
                        </div>
                    </div>
                    <div class="field span-2">
                        <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer">
                            <input type="checkbox" name="use_address_coords" id="use_address_coords">
                            Use address coordinates for map display
                        </label>
                        <div id="address-coords-warning" class="text-xs text-slate-500 mt-1">Enter both address coordinates to enable.</div>
                    </div>
                    <div class="field span-2">
                        <label for="notes">Notes</label>
                        <textarea name="notes" id="notes" rows="4"></textarea>
                    </div>
                    <div class="field span-2">
                        <label for="ops_notes">Ops Notes</label>
                        <textarea name="ops_notes" id="ops_notes" rows="4"></textarea>
                    </div>
                    <div class="field span-2">
                        <label for="poc_info">Emergency Point of Contact / Next of Kin</label>
                        <textarea name="poc_info" id="poc_info" rows="4"></textarea>
                    </div>
                    <div class="field span-2">
                        <label for="tags">Tags (comma-separated)</label>
                        <input type="text" id="tags" name="tags" placeholder="CERT, MEDICAL, TEAMLEAD" class="font-mono">
                    </div>
                    <div class="field span-2">
                        <label for="sos_notify">SOS Notify (comma-separated names, node IDs, or emails)</label>
                        <input type="text" id="sos_notify" name="sos_notify" placeholder="e.g., responder-team@example.com, !a1b2c3d4, Bob" class="font-mono">
                    </div>
                    <div class="field span-2">
                        <label>Subscriptions & Permissions</label>
                        <div class="checkbox-grid">
                            <label><input type="checkbox" name="alerts"> NWS Alerts</label>
                            <label><input type="checkbox" name="weather"> Weather Reports</label>
                            <label><input type="checkbox" name="scheduled_daily_forecast"> Daily Forecast</label>
                            <label><input type="checkbox" name="email_send"> Email Send</label>
                            <label><input type="checkbox" name="email_receive"> Email Receive</label>
                            <label><input type="checkbox" name="emailbroadcast"> Email Broadcast</label>
                            <label><input type="checkbox" name="node_tag_send"> Node Tag Send</label>
                        </div>
                    </div>
                    <div class="field span-2">
                        <label class="danger-label">Administrative Actions</label>
                        <div class="checkbox-grid">
                            <label class="danger-label"><input type="checkbox" name="blocked"> Block User (Ignore all commands from this node)</label>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" id="close-user-modal-btn-footer" class="btn btn-secondary">Close</button>
                <div class="row">
                    <button type="submit" form="user-edit-form" class="btn btn-green">Save Changes</button>
                </div>
            </div>
        </div>
    </div>

    <div id="broadcast-edit-modal" class="modal-overlay" style="display: none;">
        <div class="modal-card" style="width: min(980px, 96vw);">
            <div class="modal-header">
                <h2 id="broadcast-modal-title"><span>Edit Broadcast</span></h2>
                <button type="button" id="close-broadcast-modal-btn" class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <form id="broadcast-edit-form" method="POST" class="form-grid columns-2">
                    <input type="hidden" name="action" value="save_broadcast_job">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                    <input type="hidden" name="job_index" value="">

                    <div class="field">
                        <label>Broadcast Name</label>
                        <input type="text" name="name" required>
                    </div>
                    <div class="field">
                        <label>Interval (minutes)</label>
                        <input type="number" name="interval_mins" value="60" min="1" required>
                    </div>
                    <div class="field span-2">
                        <label>Broadcast Content</label>
                        <textarea name="content" rows="3" required></textarea>
                    </div>
                    <div class="field span-2">
                        <label><input type="checkbox" name="with_bell" value="true"> Bell (prepend alert with audible bell)</label>
                    </div>
                    <div class="field span-2">
                        <label><input type="checkbox" name="enabled" value="true"> Enable this broadcast job</label>
                        <div class="admin-note">The dispatcher will ignore this job unless this box is checked.</div>
                    </div>
                    <div class="field">
                        <label>Job Type</label>
                        <select name="job_type" class="job-type-selector">
                            <option value="recurring">Recurring Day/Time</option>
                            <option value="event">Specific Date/Time Event</option>
                        </select>
                    </div>
                    <div class="field"></div>

                    <div class="recurring-fields span-2">
                        <div class="field">
                            <label>Days of Week</label>
                            <div class="checkbox-grid">
                                <?php foreach ($days_of_week as $day): ?>
                                    <label><input type="checkbox" name="days[]" value="<?= $day ?>"> <?= $day ?></label>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <div class="form-grid columns-2">
                            <div class="field">
                                <label>Start Time</label>
                                <input type="time" name="start_time">
                            </div>
                            <div class="field">
                                <label>Stop Time</label>
                                <input type="time" name="stop_time">
                            </div>
                        </div>
                    </div>

                    <div class="event-fields span-2">
                        <div class="form-grid columns-2">
                            <div class="field">
                                <label>Start Date & Time</label>
                                <input type="datetime-local" name="start_datetime">
                            </div>
                            <div class="field">
                                <label>Stop Date & Time</label>
                                <input type="datetime-local" name="stop_datetime">
                            </div>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" id="close-broadcast-modal-btn-footer" class="btn btn-secondary">Close</button>
                <div class="row">
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

    <div id="confirm-action-modal" class="modal-overlay" style="display: none;">
        <div class="modal-card" style="width: min(420px, 92vw);">
            <div class="modal-header">
                <h2>Confirm Action</h2>
                <button type="button" id="confirm-modal-close-btn" class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <p id="confirm-modal-text">Are you sure you wish to proceed?</p>
            </div>
            <div class="modal-footer">
                <button type="button" id="confirm-modal-cancel-btn" class="btn btn-secondary">Cancel</button>
                <button type="button" id="confirm-modal-confirm-btn" class="btn btn-red">Confirm</button>
            </div>
        </div>
    </div>

    <div id="dm-chat-modal">
        <div class="chat-card">
            <div class="chat-header" id="dm-chat-title">
                <button type="button" id="dm-chat-title-btn" class="chat-username chat-title-button" data-node-id="">Direct Message</button>
                <div class="chat-header-actions">
                    <button type="button" id="dm-chat-map-btn" class="chat-map-btn" disabled>Map</button>
                    <button type="button" id="dm-chat-info-btn" class="chat-map-btn" disabled>Info</button>
                    <button type="button" id="dm-chat-user-btn" class="chat-map-btn" disabled>User</button>
                    <button type="button" id="close-dm-modal-btn" aria-label="Close">&times;</button>
                </div>
            </div>
            <div id="dm-chat-window">
                <div id="dm-chat-messages-container"></div>
            </div>
            <form id="dm-chat-form" class="chat-form" onsubmit="return false;">
                <textarea id="dm-chat-textarea" rows="2" placeholder="Send a direct message..."></textarea>
                <button type="button" id="dm-chat-bell-btn" class="secondary">Bell</button>
                <button type="submit" id="dm-chat-send-btn">Send</button>
            </form>
        </div>
    </div>

    <input type="hidden" id="csrf-token" value="<?= htmlspecialchars($csrf_token) ?>">

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // --- GLOBAL STATE & CONFIG ---
            let map;
            let nodeMarkers = {};
            let nodeMarkersMeta = {};
            let lastNodesSignature = '';
            let lastPositionsSignature = '';
            let autoFitEnabled = true;
            let chatCursor = 0;
            let subscribersMtime = 0;
            let chatSubscribersMtime = 0;
            let nodesEtag = '';
            let dashboardEtag = '';
            let chatEtag = '';
            let chatTempGroupsToken = '';
            let lastFetchedMessages = [];
            let chatMessageKeys = new Set();
            let lastFetchedSubscribers = {};
            let subscriberNameTargets = new Set();
            let localUserDirectory = Object.create(null);
            let userEditButtonsByNodeId = Object.create(null);
            let lastFetchedTempGroups = [];
            const CHAT_GROUP_CHANNEL = '__CHANNEL__';
            let selectedChatGroup = '';
            let chatGroupSignature = '';
            let lastFetchedNodesById = {};
            let lastNodePositions = {};
            const sosPopupPanels = new Map();
            let sosPopupExpandedKey = null;
            let sosPopupOrderKeys = [];
            const opsNotesDraftByNode = new Map();
            let userInfoPopupMinimized = false;
            const acknowledgedSosNodes = new Set();
            let activeSosNodeId = null;
            let sosAudioEnabled = true;
            let sosMutedUntil = 0;
            let sosAudioInterval = null;
            let sosMuteCountdownTimer = null;
            let sosAudioContext = null;
            let isStatusPolling = false;
            let isChatPolling = false;
            let statusBackoffMs = 0;
            let chatBackoffMs = 0;
            let statusPollTimer = null;
            let chatPollTimer = null;
            let statusPollInFlight = false;
            let chatPollInFlight = false;
            let updatePageInFlight = null;
            let updateDashboardInFlight = null;
            let updateChatInFlight = null;
            let adminUsersTableEtag = '';
            let adminBroadcastsTableEtag = '';
            let adminUsersFetchInFlight = null;
            let adminBroadcastsFetchInFlight = null;
            let isPollingPaused = document.hidden;
            let chatStreamSource = null;
            let chatStreamRetryTimer = null;
            let chatStreamConnected = false;
            const MAX_BACKOFF_MS = 60000;
            const CHAT_STREAM_ENABLED = false;
            const CHAT_STREAM_TIMEOUT_MS = 20000;
            const CHAT_STREAM_RETRY_MS = 1500;
            const serverMessagePrefixes = [
                '\u2600\uFE0F',
                '\uD83D\uDD2E',
                '\u26A1\uFE0F',
                '\uD83D\uDDD3\uFE0F',
                '\uD83D\uDCE7',
                '\uD83E\uDD16',
                '\u2601\uFE0F',
                '\uD83C\uDD98'
            ];

            const POLLING_INTERVAL = <?= json_encode($polling_interval) ?>;
            const CHAT_POLLING_INTERVAL = <?= json_encode($chat_polling_interval) ?>;
            const STALE_NODE_MINUTES = <?= json_encode($stale_node_minutes) ?>;
            const STALE_NODE_SECONDS = Math.max(0, Number(STALE_NODE_MINUTES)) * 60;
            const GATEWAY_LAT = <?= json_encode($gateway_lat) ?>;
            const GATEWAY_LON = <?= json_encode($gateway_lon) ?>;
            const csrfToken = document.getElementById('csrf-token').value;
            L.Icon.Default.imagePath = '/map-items/';

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

            const sosIcon = new L.Icon({
                iconUrl: '/map-items/marker-icon-red.png',
                shadowUrl: '/map-items/marker-shadow.png',
                iconSize: [25, 41],
                iconAnchor: [12, 41],
                popupAnchor: [1, -34],
                shadowSize: [41, 41]
            });

            function escapeHTML(str) {
                if (str === null || str === undefined) return '';
                return String(str)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
            }

            function formatRelativeAge(timestamp) {
                if (!timestamp) return 'unknown';
                const ts = Number(timestamp);
                if (!Number.isFinite(ts)) return 'unknown';
                const now = Math.floor(Date.now() / 1000);
                const diff = Math.max(0, now - ts);
                if (diff < 60) return `${diff}s ago`;
                if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
                if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
                return `${Math.round(diff / 86400)}d ago`;
            }

            function formatTimestamp(timestamp) {
                if (!timestamp) return 'Unknown';
                const months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
                const date = new Date(Number(timestamp) * 1000);
                if (Number.isNaN(date.getTime())) return 'Unknown';
                const hours = String(date.getHours()).padStart(2, '0');
                const minutes = String(date.getMinutes()).padStart(2, '0');
                const day = String(date.getDate()).padStart(2, '0');
                const month = months[date.getMonth()];
                const year = String(date.getFullYear()).slice(-2);
                return `${hours}:${minutes} ${day}${month}${year}`;
            }

            function formatSosTimestamp(value) {
                if (!value) return 'Unknown';
                const num = Number(value);
                let date = null;
                if (Number.isFinite(num)) {
                    const ms = num > 1e12 ? num : num * 1000;
                    date = new Date(ms);
                } else {
                    const parsed = Date.parse(value);
                    if (!Number.isNaN(parsed)) {
                        date = new Date(parsed);
                    }
                }
                if (!date || Number.isNaN(date.getTime())) return 'Unknown';
                const options = { year: '2-digit', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' };
                return date.toLocaleString(undefined, options);
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

            function getSosTimestampMs(value) {
                if (!value) return 0;
                const num = Number(value);
                if (Number.isFinite(num)) {
                    return num > 1e12 ? num : num * 1000;
                }
                const parsed = Date.parse(value);
                return Number.isNaN(parsed) ? 0 : parsed;
            }

            function getStaleBadge(timestamp) {
                if (!timestamp) return '<span class="status-muted">unknown</span>';
                const ts = Number(timestamp);
                if (!Number.isFinite(ts)) return '';
                if (STALE_NODE_SECONDS <= 0) return '';
                const now = Math.floor(Date.now() / 1000);
                const diff = Math.max(0, now - ts);
                if (diff >= STALE_NODE_SECONDS) {
                    return '<span class="status-fail">stale</span>';
                }
                return '';
            }

            function getStatusClass(node) {
                if (node.sos) return 'status-sos';
                const ts = Number(node.lastHeard);
                if (!Number.isFinite(ts)) return 'status-warn';
                if (STALE_NODE_SECONDS > 0 && (Math.floor(Date.now() / 1000) - ts) >= STALE_NODE_SECONDS) {
                    return 'status-stale';
                }
                return 'status-ok';
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

            function buildNodesSignature(nodes) {
                if (!Array.isArray(nodes)) return '';
                const parts = nodes.map(n => [
                    n.node_id || '',
                    n.lastHeard || '',
                    n.sos || '',
                    n.sos_timestamp || '',
                    n.sos_role || '',
                    n.sos_parent || '',
                    n.sos_message_payload || '',
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
                        parts.push(`${n.node_id || ''}:${coords.lat.toFixed(5)},${coords.lon.toFixed(5)}`);
                    }
                }
                parts.sort();
                return parts.join('|');
            }

            function initMap() {
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
                map.on('dragstart', () => { autoFitEnabled = false; });
                map.on('zoomstart', () => { autoFitEnabled = false; });
                setTimeout(() => {
                    map.invalidateSize();
                    applyBoundsMinZoom();
                    map.setView([GATEWAY_LAT, GATEWAY_LON], map.getZoom());
                }, 150);
            }
            async function updatePageData() {
                if (updatePageInFlight) {
                    return updatePageInFlight;
                }
                const requestPromise = (async () => {
                    try {
                        const requestHeaders = {};
                        if (nodesEtag) {
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
                            return true;
                        }
                        lastNodesSignature = nodesSignature;

                        lastNodePositions = {};
                        lastFetchedNodesById = {};
                        nodes.forEach(node => {
                            if (node.node_id) {
                                lastFetchedNodesById[node.node_id] = node;
                            }
                            const coords = getPreferredCoords(node);
                            if (coords && node.node_id) {
                                lastNodePositions[node.node_id] = { lat: coords.lat, lon: coords.lon };
                            }
                        });

                        const activeSosIds = new Set(nodes.filter(n => n.sos).map(n => n.node_id));
                        acknowledgedSosNodes.forEach(nodeId => {
                            if (!activeSosIds.has(nodeId)) {
                                acknowledgedSosNodes.delete(nodeId);
                            }
                        });

                        updateNodeList(nodes);
                        updateAdminSosList(nodes);
                        updateSosBanner(nodes);
                        updateSosPopup(nodes);
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

            function getNodeListSosRole(node) {
                if (node.sos_role === 'SENDER') return { text: 'Awaiting Response', textClass: 'node-role-sender', itemClass: 'node-item-sender' };
                if (node.sos_role === 'RESPONDER') return { text: 'Responding', textClass: 'node-role-responder', itemClass: 'node-item-responder' };
                if (node.sos_role === 'ACKNOWLEDGER') return { text: 'Acknowledged', textClass: 'node-role-ack', itemClass: 'node-item-ack' };
                return { text: '', textClass: '', itemClass: '' };
            }

            function generateNodeListItem(node, isIndented = false) {
                const name = node.name || node.node_id || 'Unknown';
                const nodeId = node.node_id || '';
                const lastHeard = formatRelativeAge(node.lastHeard);
                const statusClass = getStatusClass(node);
                const coords = getPreferredCoords(node);
                const latAttr = coords ? String(coords.lat) : '';
                const lonAttr = coords ? String(coords.lon) : '';
                const sosBadge = node.sos ? '<span class="node-meta" style="color: var(--danger);">SOS</span>' : '';
                const roleMeta = getNodeListSosRole(node);
                const roleBadge = roleMeta.text ? `<span class="node-meta ${roleMeta.textClass}">${escapeHTML(roleMeta.text)}</span>` : '';
                const itemClasses = ['node-item'];
                if (roleMeta.itemClass) itemClasses.push(roleMeta.itemClass);
                if (isIndented) itemClasses.push('node-item-indent');

                return `
                    <div class="${itemClasses.join(' ')}" data-node-id="${escapeHTML(nodeId)}" data-node-name="${escapeHTML(name)}" data-lat="${escapeHTML(latAttr)}" data-lon="${escapeHTML(lonAttr)}" data-last-heard="${escapeHTML(String(node.lastHeard || ''))}">
                        <span class="status-dot ${statusClass}"></span>
                        <div class="node-text">
                            <div class="node-name">${escapeHTML(name)}${nodeId && name !== nodeId ? `<span class="node-id">${escapeHTML(nodeId)}</span>` : ''}</div>
                            <div class="node-meta">Last heard: <span class="node-age">${escapeHTML(lastHeard)}</span> ${sosBadge} ${roleBadge}</div>
                        </div>
                    </div>
                `;
            }

            function generateNodeListMessageItem(message) {
                return `
                    <div class="node-sos-message"><strong>Message:</strong> ${escapeHTML(message)}</div>
                `;
            }

            function updateNodeList(nodes) {
                const nodeList = document.getElementById('node-list');
                const nodeCount = document.getElementById('node-count');
                if (!nodeList) return;
                if (nodeCount) nodeCount.textContent = nodes.length;

                if (!nodes || nodes.length === 0) {
                    nodeList.innerHTML = '<div class="placeholder">No live node data available.</div>';
                    return;
                }

                const rows = [];
                const sosSenders = nodes.filter(n => n.sos_role === 'SENDER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                const otherNodes = nodes.filter(n => n.sos_role !== 'SENDER');

                if (sosSenders.length === 0) {
                    const sorted = [...nodes].sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                    sorted.forEach(node => rows.push(generateNodeListItem(node)));
                } else {
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
                        rows.push(generateNodeListItem(sender));
                        if (sender.sos_message_payload) {
                            rows.push(generateNodeListMessageItem(sender.sos_message_payload));
                        }

                        const participants = participantMap.get(sender.node_id) || [];
                        const responders = participants.filter(p => p.sos_role === 'RESPONDER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                        const ackers = participants.filter(p => p.sos_role === 'ACKNOWLEDGER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));

                        responders.forEach(r => rows.push(generateNodeListItem(r, true)));
                        ackers.forEach(a => rows.push(generateNodeListItem(a, true)));
                    });

                    const nonParticipants = otherNodes.filter(n => !n.sos_parent).sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                    if (nonParticipants.length > 0) {
                        rows.push('<div class="node-list-divider">Other Active Nodes</div>');
                        nonParticipants.forEach(node => rows.push(generateNodeListItem(node)));
                    }
                }

                nodeList.innerHTML = rows.join('');
            }

            function generateAdminNodeRow(node, indentClass = '') {
                let rowClass = '';
                if (node.sos_role === 'SENDER') rowClass = 'row-sos-sender';
                if (node.sos_role === 'RESPONDER') rowClass = 'row-sos-responder';
                if (node.sos_role === 'ACKNOWLEDGER') rowClass = 'row-sos-ack';

                const lastHeardTs = node.lastHeard || '';
                const lastHeardAge = formatRelativeAge(lastHeardTs);
                const staleBadge = getStaleBadge(lastHeardTs);
                const coords = getPreferredCoords(node);
                const hasPosition = !!coords;
                const locationButton = hasPosition ? `<button class="btn btn-secondary btn-sm location-btn" data-lat="${coords.lat}" data-lon="${coords.lon}">Map It</button>` : '';
                const position = hasPosition ? `${coords.lat.toFixed(4)}, ${coords.lon.toFixed(4)}` : '<span class="status-muted">N/A</span>';

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

                const sosIndicator = node.sos ? `<span class="pill-sos">SOS ${escapeHTML(node.sos)}</span>` : '';
                return `
                    <tr class="${rowClass}" data-last-heard="${escapeHTML(String(lastHeardTs))}">
                        <td class="${indentClass}">
                            ${standDownForm}
                            ${sosIndicator}
                            <button type="button" class="open-dm-chat" data-node-id="${escapeHTML(node.node_id)}" data-node-name="${escapeHTML(node.name || node.node_id)}">${escapeHTML(node.node_id)}</button>
                            ${node.name ? `<span class="status-muted"> (${escapeHTML(node.name)})</span>` : ''}
                        </td>
                        <td>
                            <span class="last-heard" data-ts="${escapeHTML(String(lastHeardTs))}">${formatTimestamp(lastHeardTs)}</span>
                            <span class="last-heard-age status-muted">${escapeHTML(lastHeardAge)}</span>
                            ${staleBadge}
                        </td>
                        <td>${escapeHTML(String(node.snr ?? ''))}</td>
                        <td>${escapeHTML(String(node.hopsAway ?? ''))}</td>
                        <td>${escapeHTML(String(node.role ?? ''))}</td>
                        <td>${position}</td>
                        <td>${locationButton}</td>
                    </tr>
                `;
            }

            function generateAdminMessageRow(message) {
                return `
                    <tr class="row-sos-message">
                        <td colspan="7"><strong>Message:</strong> ${escapeHTML(message)}</td>
                    </tr>
                `;
            }

            function updateAdminSosList(nodes) {
                const tbody = document.getElementById('admin-sos-node-list-body');
                if (!tbody) return;
                if (!nodes || nodes.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="status-muted">No live node data available.</td></tr>';
                    return;
                }

                const rows = [];
                const isSosNode = (n) => n.sos || (n.sos_role && n.sos_role !== 'NONE');
                const sosSenders = nodes.filter(n => n.sos_role === 'SENDER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                const otherNodes = nodes.filter(n => n.sos_role !== 'SENDER');

                if (sosSenders.length === 0) {
                    const sosNodes = nodes.filter(isSosNode);
                    sosNodes.sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                    if (sosNodes.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="7" class="status-muted">No active SOS events.</td></tr>';
                        return;
                    }
                    sosNodes.forEach(node => rows.push(generateAdminNodeRow(node)));
                } else {
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
                        rows.push(generateAdminNodeRow(sender));
                        if (sender.sos_message_payload) {
                            rows.push(generateAdminMessageRow(sender.sos_message_payload));
                        }

                        const participants = participantMap.get(sender.node_id) || [];
                        const responders = participants.filter(p => p.sos_role === 'RESPONDER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
                        const ackers = participants.filter(p => p.sos_role === 'ACKNOWLEDGER').sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));

                        responders.forEach(r => rows.push(generateAdminNodeRow(r, 'indent')));
                        ackers.forEach(a => rows.push(generateAdminNodeRow(a, 'indent')));
                    });
                }

                tbody.innerHTML = rows.join('');
            }

            function updateSosBanner(nodes) {
                const sosBanner = document.getElementById('sos-banner');
                const sosBannerTitle = document.getElementById('sos-banner-title');
                const sosBannerDetails = document.getElementById('sos-banner-details');
                const sosBannerText = document.getElementById('sos-banner-text');
                if (!sosBanner || (!sosBannerTitle || !sosBannerDetails) && !sosBannerText) return;
                activeSosNodeId = null;
                const activeSosNode = nodes.find(node => node.sos && !acknowledgedSosNodes.has(node.node_id));
                if (activeSosNode) {
                    activeSosNodeId = activeSosNode.node_id;
                    const name = activeSosNode.full_name || activeSosNode.name || activeSosNode.node_id;
                    const msg = (activeSosNode.sos_message_payload || '').trim();
                    const msgText = msg ? msg : 'none';
                    const timeText = formatSosTimestamp(activeSosNode.sos_timestamp);
                    if (sosBannerTitle && sosBannerDetails) {
                        sosBannerTitle.textContent = `🚨 ACTIVE SOS: ${activeSosNode.sos} from ${name}`;
                        sosBannerDetails.textContent = `Msg: ${msgText} • Time: ${timeText}`;
                    }
                    if (sosBannerText) {
                        sosBannerText.textContent = `🚨 ACTIVE ALERT: ${activeSosNode.sos} from ${name} • Msg: ${msgText} • Time: ${timeText}`;
                    }
                    sosBanner.style.display = 'flex';
                } else {
                    sosBanner.style.display = 'none';
                }
                updateSosAudioState();
                updateSosButtons();
            }

            function buildSosEventKey(node) {
                return [
                    node.node_id || '',
                    node.sos || '',
                    node.sos_timestamp || '',
                    node.sos_message_payload || ''
                ].join('|');
            }

            function getSosDisplayName(node) {
                return node.full_name || node.name || node.node_id || 'Unknown';
            }

            function positionSosPopup() {
                if (!sosPopupContainer) return;
                const statusPanel = document.getElementById('status-panel');
                if (statusPanel) {
                    const height = statusPanel.offsetHeight || 0;
                    sosPopupContainer.style.bottom = `${height + 24}px`;
                } else {
                    sosPopupContainer.style.bottom = '12px';
                }
                layoutSosPopupPanels();
            }

            function setSosPanelMinimized(panelEl, minimized) {
                if (!panelEl) return;
                const isMinimized = !!minimized;
                panelEl.classList.toggle('minimized', isMinimized);
                panelEl.dataset.minimized = isMinimized ? '1' : '0';
                const minimizeBtn = panelEl.querySelector('.sos-popup-minimize');
                if (minimizeBtn) {
                    minimizeBtn.textContent = isMinimized ? '+' : '-';
                    minimizeBtn.setAttribute('aria-label', isMinimized ? 'Expand SOS panel' : 'Minimize SOS panel');
                    minimizeBtn.title = isMinimized ? 'Expand' : 'Minimize';
                }
            }

            function layoutSosPopupPanels() {
                if (!sosPopupContainer) return;
                const panels = Array.from(sosPopupContainer.querySelectorAll('.sos-popup'));
                if (panels.length === 0) return;

                const bottomPx = parseInt(String(sosPopupContainer.style.bottom || '12'), 10) || 12;
                const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 800;
                const topMargin = 8;
                const gap = 8;

                let minimizedHeightTotal = 0;
                let expandedPanel = null;
                panels.forEach((panelEl) => {
                    if (panelEl.dataset.minimized === '1') {
                        panelEl.style.maxHeight = 'none';
                        minimizedHeightTotal += panelEl.offsetHeight;
                    } else if (!expandedPanel) {
                        expandedPanel = panelEl;
                    }
                });
                if (!expandedPanel) return;

                const available = Math.max(220, viewportHeight - bottomPx - topMargin - minimizedHeightTotal - (gap * Math.max(0, panels.length - 1)));
                expandedPanel.style.maxHeight = `${available}px`;
            }

            function applySosPanelPresentation() {
                if (!sosPopupContainer) return;
                const preferredOrder = (Array.isArray(sosPopupOrderKeys) && sosPopupOrderKeys.length > 0)
                    ? sosPopupOrderKeys
                    : Array.from(sosPopupPanels.keys());
                const orderedKeys = [];

                if (sosPopupExpandedKey && sosPopupPanels.has(sosPopupExpandedKey)) {
                    preferredOrder.forEach((key) => {
                        if (key !== sosPopupExpandedKey && sosPopupPanels.has(key)) {
                            orderedKeys.push(key);
                        }
                    });
                    orderedKeys.push(sosPopupExpandedKey);
                } else {
                    preferredOrder.forEach((key) => {
                        if (sosPopupPanels.has(key)) {
                            orderedKeys.push(key);
                        }
                    });
                }

                orderedKeys.forEach((key) => {
                    const entry = sosPopupPanels.get(key);
                    if (!entry || !entry.element) return;
                    const isExpanded = !!(sosPopupExpandedKey && key === sosPopupExpandedKey);
                    setSosPanelMinimized(entry.element, !isExpanded);
                    sosPopupContainer.appendChild(entry.element);
                });

                layoutSosPopupPanels();
            }

            function createSosPopupPanel(key) {
                if (!sosPopupContainer) return null;
                const panel = document.createElement('div');
                panel.className = 'sos-popup minimized';
                panel.dataset.key = key;
                panel.dataset.minimized = '1';
                panel.innerHTML = `
                    <div class="sos-popup-header">
                        <span class="sos-popup-title">SOS Received</span>
                        <div class="sos-popup-actions">
                            <button type="button" class="sos-popup-map" disabled>Map</button>
                            <button type="button" class="sos-popup-close sos-popup-minimize" aria-label="Expand SOS panel" title="Expand">+</button>
                        </div>
                    </div>
                    <div class="sos-popup-body">
                        <div class="sos-popup-summary"></div>
                        <div class="sos-popup-section">Person Information</div>
                        <div class="sos-popup-info"></div>
                        <div class="sos-popup-section">Ops Notes</div>
                        <div class="sos-popup-ops-notes"></div>
                    </div>
                `;

                const headerEl = panel.querySelector('.sos-popup-header');
                const mapBtn = panel.querySelector('.sos-popup-map');
                const minimizeBtn = panel.querySelector('.sos-popup-minimize');

                headerEl?.addEventListener('click', (event) => {
                    if (event.target && event.target.closest('.sos-popup-map, .sos-popup-minimize')) {
                        return;
                    }
                    sosPopupExpandedKey = key;
                    applySosPanelPresentation();
                });

                minimizeBtn?.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    const currentlyMinimized = panel.dataset.minimized === '1';
                    if (currentlyMinimized) {
                        sosPopupExpandedKey = key;
                        applySosPanelPresentation();
                    } else {
                        sosPopupExpandedKey = null;
                        applySosPanelPresentation();
                    }
                });

                mapBtn?.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    if (!mapBtn || mapBtn.disabled) return;
                    const lat = Number(mapBtn.dataset.lat);
                    const lon = Number(mapBtn.dataset.lon);
                    if (map && Number.isFinite(lat) && Number.isFinite(lon)) {
                        map.setView([lat, lon], Math.max(map.getZoom(), 15));
                        autoFitEnabled = false;
                    }
                });

                return panel;
            }

            function renderSosPopup(panelEl, node) {
                if (!panelEl) return;
                const titleEl = panelEl.querySelector('.sos-popup-title');
                const summaryEl = panelEl.querySelector('.sos-popup-summary');
                const infoEl = panelEl.querySelector('.sos-popup-info');
                const opsNotesEl = panelEl.querySelector('.sos-popup-ops-notes');
                const mapBtn = panelEl.querySelector('.sos-popup-map');
                if (!summaryEl || !infoEl || !opsNotesEl) return;
                const subscriber = lastFetchedSubscribers[node.node_id] || {};
                const user = { ...subscriber, ...node };
                const displayName = getSosDisplayName(user);
                const msg = (user.sos_message_payload || '').trim();
                const msgText = msg ? msg : '—';
                const timeText = formatSosTimestamp(user.sos_timestamp);
                if (titleEl) {
                    const sosType = String(user.sos || 'SOS').trim().toUpperCase();
                    const titleNodeId = String(user.node_id || 'Unknown');
                    const titleUsername = String(user.name || user.full_name || 'Unknown');
                    titleEl.textContent = `${sosType}: ${titleNodeId}/${titleUsername}`;
                }

                const summaryRows = [
                    ['Type', user.sos || 'SOS'],
                    ['From', `${displayName} (${user.node_id || 'Unknown'})`],
                    ['Time', timeText],
                    ['Message', msgText]
                ];

                summaryEl.innerHTML = summaryRows.map(([label, value]) => `
                    <div class="user-info-row">
                        <div class="user-info-label">${escapeHTML(label)}</div>
                        <div class="user-info-value">${escapeHTML(formatValue(value))}</div>
                    </div>
                `).join('');

                const meshLat = formatCoord(user.latitude, -90, 90);
                const meshLon = formatCoord(user.longitude, -180, 180);
                const addrLat = formatCoord(user.address_lat, -90, 90);
                const addrLon = formatCoord(user.address_lon, -180, 180);
                const preferredCoords = getPreferredCoords(user);
                if (mapBtn) {
                    if (preferredCoords) {
                        mapBtn.disabled = false;
                        mapBtn.dataset.lat = String(preferredCoords.lat);
                        mapBtn.dataset.lon = String(preferredCoords.lon);
                    } else {
                        mapBtn.disabled = true;
                        mapBtn.dataset.lat = '';
                        mapBtn.dataset.lon = '';
                    }
                }

                const infoRows = [
                    ['Node ID', user.node_id],
                    ['Username', user.name],
                    ['Full Name', user.full_name],
                    ['Role', user.role],
                    ['Email', user.email],
                    ['Phone 1', user.phone_1],
                    ['Phone 2', user.phone_2],
                    ['Address', formatAddress(user.address)],
                    ['Mesh Lat', meshLat],
                    ['Mesh Lon', meshLon],
                    ['Address Lat', addrLat],
                    ['Address Lon', addrLon],
                    ['Use Address Coords', user.use_address_coords],
                    ['Tags', user.tags],
                    ['SOS Notify', user.sos_notify],
                    ['POC / NOK', user.poc_info],
                    ['Notes', user.notes]
                ];

                infoEl.innerHTML = infoRows.map(([label, value]) => `
                    <div class="user-info-row">
                        <div class="user-info-label">${escapeHTML(label)}</div>
                        <div class="user-info-value">${escapeHTML(formatValue(value))}</div>
                    </div>
                `).join('');
                opsNotesEl.innerHTML = renderOpsNotesEditorHtml(user.node_id, user.ops_notes, 'sos');
            }

            function updateSosPopup(nodes) {
                if (!sosPopupContainer || !Array.isArray(nodes)) return;
                const activeSosSenders = nodes.filter(node => node.sos && (!node.sos_role || node.sos_role === 'SENDER' || node.sos_role === 'NONE'));
                if (activeSosSenders.length === 0) {
                    sosPopupPanels.forEach((entry) => {
                        if (entry?.element) entry.element.remove();
                    });
                    sosPopupPanels.clear();
                    sosPopupExpandedKey = null;
                    sosPopupOrderKeys = [];
                    sosPopupContainer.style.display = 'none';
                    return;
                }

                activeSosSenders.sort((a, b) => getSosTimestampMs(b.sos_timestamp) - getSosTimestampMs(a.sos_timestamp));
                sosPopupOrderKeys = activeSosSenders.map((node) => buildSosEventKey(node));
                const activeKeys = new Set(activeSosSenders.map((node) => buildSosEventKey(node)));

                Array.from(sosPopupPanels.keys()).forEach((key) => {
                    if (!activeKeys.has(key)) {
                        const entry = sosPopupPanels.get(key);
                        if (entry?.element) {
                            entry.element.remove();
                        }
                        sosPopupPanels.delete(key);
                        if (sosPopupExpandedKey === key) {
                            sosPopupExpandedKey = null;
                        }
                    }
                });

                activeSosSenders.forEach((node) => {
                    const key = buildSosEventKey(node);
                    let entry = sosPopupPanels.get(key);
                    if (!entry || !entry.element) {
                        const panelEl = createSosPopupPanel(key);
                        if (!panelEl) return;
                        entry = { element: panelEl };
                        sosPopupPanels.set(key, entry);
                    }
                    renderSosPopup(entry.element, node);
                });

                sosPopupContainer.style.display = 'flex';
                if (!(sosPopupExpandedKey && sosPopupPanels.has(sosPopupExpandedKey))) {
                    sosPopupExpandedKey = null;
                }
                applySosPanelPresentation();

                positionSosPopup();
            }

            function ensureSosAudioContext() {
                if (!sosAudioContext) {
                    const AudioCtx = window.AudioContext || window.webkitAudioContext;
                    if (AudioCtx) {
                        sosAudioContext = new AudioCtx();
                    }
                }
                if (sosAudioContext && sosAudioContext.state === 'suspended') {
                    sosAudioContext.resume().catch(() => {});
                }
            }

            function playSosBeep() {
                if (!activeSosNodeId || !sosAudioEnabled || Date.now() < sosMutedUntil) return;
                ensureSosAudioContext();
                if (!sosAudioContext) return;
                const oscillator = sosAudioContext.createOscillator();
                const gain = sosAudioContext.createGain();
                oscillator.type = 'sine';
                oscillator.frequency.value = 880;
                gain.gain.value = 0.08;
                oscillator.connect(gain);
                gain.connect(sosAudioContext.destination);
                oscillator.start();
                oscillator.stop(sosAudioContext.currentTime + 0.4);
                oscillator.onended = () => {
                    oscillator.disconnect();
                    gain.disconnect();
                };
            }

            function startSosAudioLoop() {
                if (sosAudioInterval) return;
                playSosBeep();
                sosAudioInterval = setInterval(playSosBeep, 5000);
            }

            function stopSosAudioLoop() {
                if (!sosAudioInterval) return;
                clearInterval(sosAudioInterval);
                sosAudioInterval = null;
            }

            function updateSosAudioState() {
                if (!activeSosNodeId || !sosAudioEnabled || Date.now() < sosMutedUntil) {
                    stopSosAudioLoop();
                } else {
                    startSosAudioLoop();
                }
            }

            function updateSosButtons() {
                const muteBtn = document.getElementById('sos-banner-mute-btn');
                const soundBtn = document.getElementById('sos-banner-sound-btn');
                if (soundBtn) {
                    soundBtn.textContent = sosAudioEnabled ? 'Sound On' : 'Sound Off';
                }
                if (muteBtn) {
                    if (Date.now() < sosMutedUntil) {
                        const remainingMs = Math.max(0, sosMutedUntil - Date.now());
                        const mins = Math.max(1, Math.ceil(remainingMs / 60000));
                        muteBtn.textContent = `Muted ${mins}m`;
                    } else {
                        muteBtn.textContent = 'Mute 5m';
                    }
                }
            }

            function scheduleMuteCountdown() {
                if (sosMuteCountdownTimer) {
                    clearInterval(sosMuteCountdownTimer);
                    sosMuteCountdownTimer = null;
                }
                if (Date.now() < sosMutedUntil) {
                    sosMuteCountdownTimer = setInterval(() => {
                        if (Date.now() >= sosMutedUntil) {
                            clearInterval(sosMuteCountdownTimer);
                            sosMuteCountdownTimer = null;
                            updateSosButtons();
                            updateSosAudioState();
                            return;
                        }
                        updateSosButtons();
                    }, 1000);
                }
            }

            function refreshNodeAges() {
                document.querySelectorAll('.node-item').forEach(item => {
                    const ts = Number(item.dataset.lastHeard || 0);
                    const ageEl = item.querySelector('.node-age');
                    if (ageEl) {
                        ageEl.textContent = formatRelativeAge(ts);
                    }
                });
                document.querySelectorAll('.last-heard').forEach(el => {
                    const ts = Number(el.dataset.ts || 0);
                    const ageEl = el.parentElement?.querySelector('.last-heard-age');
                    if (ageEl) {
                        ageEl.textContent = formatRelativeAge(ts);
                    }
                });
            }

            function updateMapMarkers(nodes) {
                if (!map) return;
                const nodesOnMap = new Set();
                const markersToBound = [];
                const positionsSignature = buildPositionsSignature(nodes);
                const positionsChanged = positionsSignature !== lastPositionsSignature;

                nodes.forEach(node => {
                    const coords = getPreferredCoords(node);
                    if (!coords) return;

                    const node_id = node.node_id;
                    const pos = [coords.lat, coords.lon];
                    nodesOnMap.add(node_id);
                    if (autoFitEnabled) {
                        markersToBound.push(pos);
                    }

                    const labelName = node.name || node.node_id || 'Node';
                    const popupContent = `
                        <div style="font-size: 0.8rem; line-height: 1.3;">
                            <strong>${escapeHTML(node.node_id || 'Unknown')}</strong><br>
                            ${escapeHTML(node.name || 'N/A')}<br>
                            <span style="color: #9ca3af;">Last heard: ${escapeHTML(formatRelativeAge(node.lastHeard))}</span>
                        </div>
                    `;

                    const icon = node.sos ? sosIcon : new L.Icon.Default();
                    if (nodeMarkers[node_id]) {
                        const marker = nodeMarkers[node_id];
                        marker.setLatLng(pos);
                        marker.setPopupContent(popupContent);
                        marker.setTooltipContent(labelName);
                        marker.setIcon(icon);
                    } else {
                        nodeMarkers[node_id] = L.marker(pos, { icon: icon })
                            .addTo(map)
                            .bindPopup(popupContent)
                            .bindTooltip(labelName, { direction: 'top', offset: [0, -10] })
                            .on('click', () => {
                                openDmChat(node_id, labelName);
                                map.setView(pos, Math.max(map.getZoom(), 15));
                            });
                    }
                    nodeMarkersMeta[node_id] = { lat: coords.lat, lon: coords.lon, name: labelName };
                });

                for (const node_id in nodeMarkers) {
                    if (!nodesOnMap.has(node_id)) {
                        map.removeLayer(nodeMarkers[node_id]);
                        delete nodeMarkers[node_id];
                        delete nodeMarkersMeta[node_id];
                    }
                }

                if (autoFitEnabled && markersToBound.length > 0 && positionsChanged) {
                    map.fitBounds(markersToBound, { padding: [40, 40], maxZoom: 16, animate: false });
                }
                lastPositionsSignature = positionsSignature;
            }

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
                    const health = data.system_health || {};
                    const weather = data.weather_info || {};

                    const healthContainer = document.getElementById('system-health-body');
                    if (healthContainer) {
                        const dispatcherOk = !!health.dispatcher_active;
                        const radioOk = !!health.radio_connected;
                        const weatherOk = !!health.weather_fetcher_ok;
                        const emailOk = !!health.email_processor_ok;
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
                            <div class="status-line"><span class="status-pill ${restartCount > 0 ? 'warn' : 'ok'}"></span> Restarts ${escapeHTML(String(restartCount))} / result ${escapeHTML(serviceResult)} / substate ${escapeHTML(subState)}</div>
                            <div class="status-line"><span class="status-pill ${execCode === '0' ? 'ok' : 'warn'}"></span> Exec code ${escapeHTML(execCode)} status ${escapeHTML(execStatus)}</div>
                        ` : '';
                        const lastException = String(health.dispatcher_last_exception || '');
                        const exceptionSource = String(health.dispatcher_last_exception_source || '');
                        const exceptionTime = String(health.dispatcher_last_exception_time || '');
                        const exceptionMeta = [exceptionSource, exceptionTime].filter(Boolean).join(' @ ');
                        const alerts = Array.isArray(health.alerts) ? health.alerts : [];
                        const alertsHtml = alerts.length
                            ? `<div class="status-muted" style="margin-top:4px;">${alerts.map((alert) => {
                                const level = String((alert && alert.level) || 'warn').toLowerCase();
                                const levelTag = level === 'critical' ? 'CRIT' : (level === 'warn' ? 'WARN' : 'INFO');
                                const msg = escapeHTML(String((alert && alert.message) || ''));
                                return `<div>[${levelTag}] ${msg}</div>`;
                            }).join('')}</div>`
                            : '<div class="status-muted">No active dispatcher alerts.</div>';
                        healthContainer.innerHTML = `
                            <div class="status-line"><span class="status-pill ${dispatcherOk ? 'ok' : 'fail'}"></span> Dispatcher ${dispatcherOk ? 'active' : 'inactive'}</div>
                            ${serviceMetaHtml}
                            <div class="status-line"><span class="status-pill ${radioOk ? 'ok' : 'fail'}"></span> Radio ${radioOk ? 'connected' : 'disconnected'}</div>
                            <div class="status-line"><span class="status-pill ${weatherOk ? 'ok' : 'warn'}"></span> Weather ${escapeHTML(String(health.weather_fetcher_last_run || 'n/a'))}</div>
                            <div class="status-line"><span class="status-pill ${emailOk ? 'ok' : 'warn'}"></span> Email ${escapeHTML(String(health.email_processor_last_run || 'n/a'))}</div>
                            <div class="status-muted">Last exception: ${lastException ? escapeHTML(lastException) : 'none'}${exceptionMeta ? ` (${escapeHTML(exceptionMeta)})` : ''}</div>
                            ${alertsHtml}
                        `;
                    }

                    const weatherContainer = document.getElementById('weather-body');
                    if (weatherContainer) {
                        const staleLabel = weather.stale ? 'stale' : 'current';
                        const alertText = weather.active_alert || 'No active alerts.';
                        const stationLabel = weather.station_id ? `Station ${weather.station_id}` : '';
                        weatherContainer.innerHTML = `
                            <div>Temp ${escapeHTML(String(weather.temperature_f ?? 'n/a'))} F, Humidity ${escapeHTML(String(weather.humidity ?? 'n/a'))}%</div>
                            <div class="status-muted">Updated ${escapeHTML(String(weather.last_update || 'n/a'))} ${escapeHTML(String(stationLabel))} (${staleLabel})</div>
                            <div>${escapeHTML(String(alertText))}</div>
                        `;
                    }

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
                        positionSosPopup();
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
                return true;
            }

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

            function scheduleChatStreamRetry(delayMs = CHAT_STREAM_RETRY_MS) {
                if (!CHAT_STREAM_ENABLED) return;
                if (!isChatPolling || isPollingPaused) return;
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
                if (!isChatPolling || isPollingPaused) return;
                if (chatStreamSource) return;

                const params = new URLSearchParams({
                    after: String(chatCursor),
                    with_subscribers: '1',
                    subscribers_mtime: String(chatSubscribersMtime),
                    temp_groups_token: String(chatTempGroupsToken),
                    timeout_ms: String(CHAT_STREAM_TIMEOUT_MS)
                });
                const stream = new EventSource(`/map-items/api_get_chat_stream.php?${params.toString()}`);
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

            // --- Blocklist Management (Admin Actions) ---
            const blocklistContainer = document.getElementById('blocklist-container');
            const addBlocklistForm = document.getElementById('add-to-blocklist-form');
            const newBlockedEmailInput = document.getElementById('new-blocked-email');

            async function fetchBlocklist() {
                if (!blocklistContainer) return;
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
                if (!blocklistContainer) return;
                blocklistContainer.innerHTML = '';
                if (!emails || emails.length === 0) {
                    blocklistContainer.innerHTML = '<div class="status-muted">The email blocklist is empty.</div>';
                    return;
                }
                emails.forEach(email => {
                    const emailEl = document.createElement('div');
                    emailEl.className = 'list-item row-between';
                    emailEl.innerHTML = `
                        <span class="font-mono">${escapeHTML(email)}</span>
                        <button type="button" class="btn btn-red btn-sm remove-email-btn" data-email="${escapeHTML(email)}">Remove</button>
                    `;
                    blocklistContainer.appendChild(emailEl);
                });
            }

            function renderBlocklistError(message) {
                if (!blocklistContainer) return;
                blocklistContainer.innerHTML = `<div class="status-fail">${escapeHTML(message)}</div>`;
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
                    fetchBlocklist();
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
                    fetchBlocklist();
                } catch (error) {
                    alert('An error occurred while removing the email.');
                    console.error('Remove Email Error:', error);
                }
            }

            addBlocklistForm?.addEventListener('submit', function(e) {
                e.preventDefault();
                const emailToAdd = newBlockedEmailInput.value.trim();
                if (emailToAdd) {
                    addBlockedEmail(emailToAdd);
                    newBlockedEmailInput.value = '';
                }
            });

            blocklistContainer?.addEventListener('click', function(e) {
                const target = e.target;
                if (target.classList.contains('remove-email-btn')) {
                    const emailToRemove = target.dataset.email;
                    if (emailToRemove && confirm(`Are you sure you want to unblock "${emailToRemove}"?`)) {
                        removeBlockedEmail(emailToRemove);
                    }
                }
            });

            function createMessageHTML(msg, subscribers, isDmContext = false) {
                const fromId = msg.from || 'Unknown';
                let text = (msg.text || '').trim();
                let messageType = '';
                let fromName = 'Unknown';
                let hasBell = false;
                let isSystemMessage = false;
                for (const prefix of serverMessagePrefixes) {
                    if (text.replace(/^\x07/, '').startsWith(prefix)) {
                        isSystemMessage = true;
                        break;
                    }
                }
                if (isSystemMessage) {
                    messageType = 'system';
                } else if (fromId === 'GATEWAY') {
                    messageType = 'outgoing';
                    fromName = 'You (Gateway)';
                } else {
                    messageType = 'incoming';
                    fromName = (subscribers[fromId] && subscribers[fromId].name ? subscribers[fromId].name : fromId);
                }

                if (messageType === 'outgoing' && isDmContext) {
                    const parts = text.split(/ (.*)/s);
                    if (parts.length > 1 && parts[0].startsWith('@')) {
                        text = parts[1];
                    }
                }

                if (text.startsWith("\x07")) {
                    hasBell = true;
                    text = text.substring(1);
                }

                if (messageType === 'system') {
                    return `
                        <div class="message message-system">
                            <div class="message-content">${escapeHTML(text)}</div>
                        </div>
                    `;
                }

                const dmPrefix = (msg.is_dm && messageType === 'incoming' && !isDmContext) ? '<span class="dm-prefix">DM:</span>' : '';
                const bellIndicator = hasBell ? '<span class="bell-indicator">BELL</span>' : '';
                const userData = subscribers[fromId] || null;
                const canShowProfile = messageType === 'incoming' && fromId && fromId !== 'Unknown' && hasUserInfo(userData);
                const usernameHtml = canShowProfile
                    ? `<button type="button" class="message-username chat-username" data-node-id="${escapeHTML(fromId)}" title="View details">${escapeHTML(fromName)}</button>`
                    : `<div class="message-username">${escapeHTML(fromName)}</div>`;

                return `
                    <div class="message message-${messageType}">
                        ${usernameHtml}
                        <div class="message-content">${bellIndicator}${dmPrefix}${escapeHTML(text)}</div>
                        <div class="message-meta">${escapeHTML(msg.timestamp || '')}</div>
                    </div>
                `;
            }

            function hasUserInfo(userData) {
                if (!userData || typeof userData !== 'object') return false;
                if (userData.name || userData.full_name || userData.role || userData.email || userData.phone_1 || userData.phone_2) return true;
                if (userData.notes || userData.ops_notes || userData.poc_info || userData.sos_notify) return true;
                if (userData.address_lat || userData.address_lon || userData.use_address_coords) return true;
                if (Array.isArray(userData.tags) && userData.tags.length > 0) return true;
                if (userData.blocked) return true;
                if (userData.alerts || userData.weather || userData.scheduled_daily_forecast || userData.email_send || userData.email_receive || userData.emailbroadcast || userData.node_tag_send) return true;
                const address = userData.address || {};
                if (address.street || address.city || address.state || address.zip) return true;
                return false;
            }

            function setLocalUserRecord(nodeId, userData) {
                const targetNodeId = String(nodeId || userData?.node_id || '').trim();
                if (!targetNodeId || !userData || typeof userData !== 'object' || Array.isArray(userData)) return;
                localUserDirectory[targetNodeId] = { ...userData, node_id: targetNodeId };
            }

            function getLocalUserRecord(nodeId) {
                const targetNodeId = String(nodeId || '').trim();
                if (!targetNodeId) return null;
                const local = localUserDirectory[targetNodeId];
                if (local && typeof local === 'object' && !Array.isArray(local)) return { ...local, node_id: targetNodeId };
                const button = userEditButtonsByNodeId[targetNodeId] || null;
                if (!button) return null;
                const serialized = String(button.dataset.userData || '').trim();
                if (!serialized) return null;
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

            function getSubscriberUserRecord(nodeId) {
                const targetNodeId = String(nodeId || '').trim();
                if (!targetNodeId) return null;
                const raw = lastFetchedSubscribers[targetNodeId];
                if (raw && typeof raw === 'object' && !Array.isArray(raw)) return { node_id: targetNodeId, ...raw };
                return getLocalUserRecord(targetNodeId);
            }

            async function fetchUserRecord(nodeId) {
                const targetNodeId = String(nodeId || '').trim();
                if (!targetNodeId) return null;
                const formData = new FormData();
                formData.append('ajax', 'true');
                formData.append('action', 'get_user');
                formData.append('node_id', targetNodeId);
                formData.append('csrf_token', csrfToken);
                try {
                    const response = await fetch(window.location.href, { method: 'POST', body: formData });
                    if (!response.ok) return null;
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
                if (!targetNodeId) return null;
                const localRecord = getSubscriberUserRecord(targetNodeId);
                if (localRecord) return localRecord;
                return fetchUserRecord(targetNodeId);
            }

            function openCreateUserFromDmTarget(nodeId) {
                const targetNodeId = String(nodeId || '').trim();
                if (!targetNodeId) return;
                const localRecord = getLocalUserRecord(targetNodeId);
                const targetName = String(
                    lastFetchedSubscribers[targetNodeId]?.name ||
                    localRecord?.name ||
                    lastFetchedNodesById[targetNodeId]?.name ||
                    dmChatUserBtn?.dataset?.nodeName ||
                    targetNodeId
                );
                openAdminPanel('users');
                const newNodeIdInput = document.getElementById('new_node_id');
                const newNameInput = document.getElementById('new_name');
                if (newNodeIdInput) {
                    newNodeIdInput.value = targetNodeId;
                }
                if (newNameInput && !String(newNameInput.value || '').trim()) {
                    newNameInput.value = targetName;
                }
                setTimeout(() => {
                    if (newNameInput) {
                        newNameInput.focus();
                    } else if (newNodeIdInput) {
                        newNodeIdInput.focus();
                    }
                }, 50);
            }

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
                if (!tabsContainer) return;

                const groups = buildChatGroupList();
                const unlocked = groups.filter(group => !group.locked);
                const hasSelectedUnlocked = unlocked.some(group => group.name === selectedChatGroup);
                if (!hasSelectedUnlocked) {
                    selectedChatGroup = unlocked.length > 0 ? unlocked[0].name : '';
                }

                if (groups.length === 0) {
                    tabsContainer.innerHTML = '<span class="status-muted">No tag groups available.</span>';
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
                    const activeClass = isActive ? ' active' : '';
                    const lockedClass = isLocked ? ' locked' : '';
                    const labelBase = group.type === 'channel' ? 'Channel' : `@${group.name}`;
                    const tempSuffix = group.type === 'temporary' ? ' (temp)' : '';
                    const lockSuffix = isLocked ? ' [LOCKED]' : '';
                    return `<button type="button" class="chat-group-tab${activeClass}${lockedClass}" data-chat-group="${escapeHTML(group.name)}" ${isLocked ? 'disabled' : ''}>${escapeHTML(labelBase)}${tempSuffix}${lockSuffix}</button>`;
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
                    for (const prefix of serverMessagePrefixes) {
                        if (text.replace(/^\x07/, '').startsWith(prefix)) {
                            isServerMessage = true;
                            break;
                        }
                    }
                    if (isServerMessage) return showSMs;
                    const isConsideredDM = msg.is_dm || (msg.from === 'GATEWAY' && isOutgoingDirectMessage(text));
                    if (enforceGroupFilter && !messageBelongsToSelectedGroup(msg, activeGroup)) return false;
                    if (isConsideredDM) return showDMs;
                    return true;
                });

                if (filteredMessages.length > 0) {
                    chatContainerElement.innerHTML = filteredMessages.map((msg) => createMessageHTML(msg, lastFetchedSubscribers, false)).join('');
                } else {
                    chatContainerElement.innerHTML = '<div class="placeholder">No messages to display with current filters.</div>';
                }
                if (isScrolledToBottom) {
                    chatWindow.scrollTop = chatWindow.scrollHeight;
                }
            }

            function renderDmChat() {
                const dmModal = document.getElementById('dm-chat-modal');
                const dmChatContainer = document.getElementById('dm-chat-messages-container');
                const dmChatWindow = document.getElementById('dm-chat-window');
                const dmTargetNodeIdInput = document.getElementById('dm-target-node-id-input');
                const dmChatTitleBtn = document.getElementById('dm-chat-title-btn');
                if (!dmModal || dmModal.style.display === 'none' || !dmChatContainer || !dmTargetNodeIdInput) return;
                const targetNodeId = dmTargetNodeIdInput.value;
                if (!targetNodeId) {
                    dmChatContainer.innerHTML = '';
                    if (dmChatInfoBtn) {
                        dmChatInfoBtn.dataset.nodeId = '';
                        dmChatInfoBtn.disabled = true;
                    }
                    if (dmChatUserBtn) {
                        dmChatUserBtn.dataset.nodeId = '';
                        dmChatUserBtn.disabled = true;
                    }
                    return;
                }
                if (dmChatTitleBtn) {
                    const userData = lastFetchedSubscribers[targetNodeId] || null;
                    if (hasUserInfo(userData)) {
                        dmChatTitleBtn.dataset.nodeId = targetNodeId;
                        dmChatTitleBtn.disabled = false;
                    } else {
                        dmChatTitleBtn.dataset.nodeId = '';
                        dmChatTitleBtn.disabled = true;
                    }
                }
                if (dmChatMapBtn) {
                    const pos = lastNodePositions[targetNodeId];
                    if (pos && Number.isFinite(pos.lat) && Number.isFinite(pos.lon)) {
                        dmChatMapBtn.dataset.lat = String(pos.lat);
                        dmChatMapBtn.dataset.lon = String(pos.lon);
                        dmChatMapBtn.disabled = false;
                    } else {
                        dmChatMapBtn.dataset.lat = '';
                        dmChatMapBtn.dataset.lon = '';
                        dmChatMapBtn.disabled = true;
                    }
                }
                if (dmChatInfoBtn) {
                    dmChatInfoBtn.dataset.nodeId = targetNodeId;
                    dmChatInfoBtn.disabled = false;
                }
                if (dmChatUserBtn) {
                    const fallbackName = String(
                        lastFetchedSubscribers[targetNodeId]?.name ||
                        lastFetchedNodesById[targetNodeId]?.name ||
                        targetNodeId
                    );
                    dmChatUserBtn.dataset.nodeId = targetNodeId;
                    dmChatUserBtn.dataset.nodeName = fallbackName;
                    dmChatUserBtn.disabled = false;
                }
                const targetName = lastFetchedSubscribers[targetNodeId]?.name || targetNodeId;
                const filteredMessages = lastFetchedMessages.filter(msg => {
                    const gatewayToUserRegex = new RegExp(`^@${escapeRegExp(targetName)}\\s`, 'i');
                    const fromGatewayToUser = msg.from === 'GATEWAY' && gatewayToUserRegex.test((msg.text || '').replace(/^\x07/, ''));
                    const fromUserToGateway = msg.from === targetNodeId && msg.is_dm;
                    return fromUserToGateway || fromGatewayToUser;
                });
                const isScrolledToBottom = dmChatWindow.scrollHeight - dmChatWindow.clientHeight <= dmChatWindow.scrollTop + 10;
                if (filteredMessages.length > 0) {
                    dmChatContainer.innerHTML = filteredMessages.map((msg) => createMessageHTML(msg, lastFetchedSubscribers, true)).join('');
                } else {
                    dmChatContainer.innerHTML = '<div class="placeholder">No direct messages with this user yet.</div>';
                }
                if (isScrolledToBottom) {
                    dmChatWindow.scrollTop = dmChatWindow.scrollHeight;
                }
            }

            function renderAllChats() {
                renderFilteredChat();
                renderDmChat();
            }

            function escapeRegExp(string) { return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

            function openDmChat(nodeId, nodeName) {
                const dmModal = document.getElementById('dm-chat-modal');
                const dmChatTitleBtn = document.getElementById('dm-chat-title-btn');
                const dmTargetNodeIdInput = document.getElementById('dm-target-node-id-input');
                const dmChatTextarea = document.getElementById('dm-chat-textarea');
                if (!dmModal || !dmChatTitleBtn || !dmTargetNodeIdInput) return;
                dmChatTitleBtn.textContent = `${nodeId} / ${nodeName}`;
                const userData = lastFetchedSubscribers[nodeId] || null;
                if (hasUserInfo(userData)) {
                    dmChatTitleBtn.dataset.nodeId = nodeId;
                    dmChatTitleBtn.disabled = false;
                } else {
                    dmChatTitleBtn.dataset.nodeId = '';
                    dmChatTitleBtn.disabled = true;
                }
                if (dmChatMapBtn) {
                    const pos = lastNodePositions[nodeId];
                    if (pos && Number.isFinite(pos.lat) && Number.isFinite(pos.lon)) {
                        dmChatMapBtn.dataset.lat = String(pos.lat);
                        dmChatMapBtn.dataset.lon = String(pos.lon);
                        dmChatMapBtn.disabled = false;
                    } else {
                        dmChatMapBtn.dataset.lat = '';
                        dmChatMapBtn.dataset.lon = '';
                        dmChatMapBtn.disabled = true;
                    }
                }
                if (dmChatInfoBtn) {
                    dmChatInfoBtn.dataset.nodeId = nodeId;
                    dmChatInfoBtn.disabled = false;
                }
                if (dmChatUserBtn) {
                    const fallbackName = String(
                        lastFetchedSubscribers[nodeId]?.name ||
                        lastFetchedNodesById[nodeId]?.name ||
                        nodeName ||
                        nodeId
                    );
                    dmChatUserBtn.dataset.nodeId = nodeId;
                    dmChatUserBtn.dataset.nodeName = fallbackName;
                    dmChatUserBtn.disabled = false;
                }
                dmTargetNodeIdInput.value = nodeId;
                dmModal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
                if (!isChatPolling) {
                    startChatPolling();
                }
                updateChat();
                renderDmChat();
                setTimeout(() => {
                    if (dmChatTextarea) dmChatTextarea.focus();
                }, 100);
            }

            function closeDmChat() {
                const dmModal = document.getElementById('dm-chat-modal');
                const dmTargetNodeIdInput = document.getElementById('dm-target-node-id-input');
                const dmChatTitleBtn = document.getElementById('dm-chat-title-btn');
                if (!dmModal) return;
                dmModal.style.display = 'none';
                restoreBodyOverflow();
                if (dmTargetNodeIdInput) dmTargetNodeIdInput.value = '';
                if (dmChatTitleBtn) {
                    dmChatTitleBtn.dataset.nodeId = '';
                    dmChatTitleBtn.disabled = true;
                }
                if (dmChatMapBtn) {
                    dmChatMapBtn.dataset.lat = '';
                    dmChatMapBtn.dataset.lon = '';
                    dmChatMapBtn.disabled = true;
                }
                if (dmChatInfoBtn) {
                    dmChatInfoBtn.dataset.nodeId = '';
                    dmChatInfoBtn.disabled = true;
                }
                if (dmChatUserBtn) {
                    dmChatUserBtn.dataset.nodeId = '';
                    dmChatUserBtn.dataset.nodeName = '';
                    dmChatUserBtn.disabled = true;
                }
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

            function sendAjaxMessage(text, button, isBell = false) {
                if (!text.trim() || button.disabled) return;
                const originalButtonText = button.textContent;
                const allButtons = [mainChatSendBtn, mainChatBellBtn, dmChatSendBtn, dmChatBellBtn].filter(b => b);
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
                            if (button.closest('#dm-chat-form')) {
                                dmChatTextarea.value = '';
                            } else {
                                mainChatTextarea.value = '';
                            }
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
                    .finally(() => {
                        allButtons.forEach(b => { b.disabled = false; });
                        button.textContent = originalButtonText;
                    });
            }

            function toggleJobFields(form) {
                if (!form) return;
                const typeSelector = form.querySelector('.job-type-selector');
                const type = typeSelector ? typeSelector.value : 'recurring';
                const recurringFields = form.querySelector('.recurring-fields');
                const eventFields = form.querySelector('.event-fields');
                if (recurringFields && eventFields) {
                    if (type === 'event') {
                        recurringFields.style.display = 'none';
                        eventFields.style.display = '';
                    } else {
                        recurringFields.style.display = '';
                        eventFields.style.display = 'none';
                    }
                }
            }

            function formatAddress(address) {
                if (!address || typeof address !== 'object') return '—';
                const parts = [address.street, address.city, address.state, address.zip].filter(Boolean);
                return parts.length > 0 ? parts.join(', ') : '—';
            }

            function formatValue(value) {
                if (value === null || value === undefined || value === '') return '—';
                if (Array.isArray(value)) return value.length ? value.join(', ') : '—';
                if (typeof value === 'boolean') return value ? 'Yes' : 'No';
                return String(value);
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

            function renderOpsNotesEditorHtml(nodeId, currentValue, contextLabel = '') {
                const safeNode = String(nodeId || '');
                const safeContext = String(contextLabel || '');
                const value = getOpsNotesDraftValue(safeNode, currentValue);
                return `
                    <div class="ops-notes-editor" data-node-id="${escapeHTML(safeNode)}" data-context="${escapeHTML(safeContext)}">
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
                if (lastFetchedNodesById[key] && typeof lastFetchedNodesById[key] === 'object') {
                    lastFetchedNodesById[key].ops_notes = normalized;
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

            function updateAddressCoordToggle() {
                if (!addressLatInput || !addressLonInput || !useAddressCoordsInput) return;
                const lat = parseCoord(addressLatInput.value, -90, 90);
                const lon = parseCoord(addressLonInput.value, -180, 180);
                const valid = lat !== null && lon !== null;
                useAddressCoordsInput.disabled = !valid;
                if (!valid) {
                    useAddressCoordsInput.checked = false;
                }
                if (addressCoordsWarning) {
                    addressCoordsWarning.style.display = valid ? 'none' : 'block';
                }
            }

            function setUserInfoPopupMinimized(minimized) {
                if (!userInfoPopup) return;
                userInfoPopupMinimized = !!minimized;
                userInfoPopup.classList.toggle('minimized', userInfoPopupMinimized);
                if (userInfoMinimizeBtn) {
                    userInfoMinimizeBtn.textContent = userInfoPopupMinimized ? '+' : '-';
                    userInfoMinimizeBtn.setAttribute('aria-label', userInfoPopupMinimized ? 'Expand Info panel' : 'Minimize Info panel');
                    userInfoMinimizeBtn.title = userInfoPopupMinimized ? 'Expand' : 'Minimize';
                }
            }

            function openUserInfoPopup(nodeId) {
                if (!nodeId) return;
                if (!userInfoPopup || !userInfoBody || !userInfoTitle) return;
                const user = lastFetchedSubscribers[nodeId] || {};
                const nodeData = lastFetchedNodesById[nodeId] || {};
                const merged = { ...user, ...nodeData };
                const displayName = merged.name || merged.full_name || nodeId;
                userInfoTitle.textContent = `INFO: ${nodeId}/${displayName}`;
                const meshLat = formatCoord(nodeData.latitude, -90, 90);
                const meshLon = formatCoord(nodeData.longitude, -180, 180);
                const addrLat = formatCoord(merged.address_lat, -90, 90);
                const addrLon = formatCoord(merged.address_lon, -180, 180);
                const lastHeard = formatRelativeAge(nodeData.lastHeard);

                const rows = [
                    ['Node ID', nodeId],
                    ['Username', merged.name],
                    ['Full Name', merged.full_name],
                    ['Role', merged.role],
                    ['Last Heard', lastHeard],
                    ['SOS', merged.sos],
                    ['Email', merged.email],
                    ['Phone 1', merged.phone_1],
                    ['Phone 2', merged.phone_2],
                    ['Address', formatAddress(merged.address)],
                    ['Mesh Lat', meshLat],
                    ['Mesh Lon', meshLon],
                    ['Address Lat', addrLat],
                    ['Address Lon', addrLon],
                    ['Use Address Coords', merged.use_address_coords],
                    ['Tags', merged.tags],
                    ['SOS Notify', merged.sos_notify],
                    ['Notes', merged.notes],
                    ['POC / NOK', merged.poc_info],
                    ['Alerts', merged.alerts],
                    ['Weather', merged.weather],
                    ['Daily Forecast', merged.scheduled_daily_forecast],
                    ['Email Send', merged.email_send],
                    ['Email Receive', merged.email_receive],
                    ['Email Broadcast', merged.emailbroadcast],
                    ['Node Tag Send', merged.node_tag_send],
                    ['Blocked', merged.blocked]
                ];

                userInfoBody.innerHTML = rows.map(([label, value]) => `
                    <div class="user-info-row">
                        <div class="user-info-label">${escapeHTML(label)}</div>
                        <div class="user-info-value">${escapeHTML(formatValue(value))}</div>
                    </div>
                `).join('') + `
                    <div class="sos-popup-section">Ops Notes</div>
                    ${renderOpsNotesEditorHtml(nodeId, merged.ops_notes, 'info')}
                `;

                setUserInfoPopupMinimized(false);
                userInfoPopup.style.display = 'flex';
            }

            function closeUserInfoPopup() {
                if (!userInfoPopup) return;
                userInfoPopup.style.display = 'none';
                setUserInfoPopupMinimized(false);
            }

            const dmModal = document.getElementById('dm-chat-modal');
            const dmChatTitleBtn = document.getElementById('dm-chat-title-btn');
            const dmChatWindow = document.getElementById('dm-chat-window');
            const dmChatContainer = document.getElementById('dm-chat-messages-container');
            const dmChatForm = document.getElementById('dm-chat-form');
            const dmChatTextarea = document.getElementById('dm-chat-textarea');
            const dmChatSendBtn = document.getElementById('dm-chat-send-btn');
            const dmChatBellBtn = document.getElementById('dm-chat-bell-btn');
            const dmChatMapBtn = document.getElementById('dm-chat-map-btn');
            const dmChatInfoBtn = document.getElementById('dm-chat-info-btn');
            const dmChatUserBtn = document.getElementById('dm-chat-user-btn');
            const mainChatTextarea = document.getElementById('main-chat-textarea');
            const mainChatSendBtn = document.getElementById('main-chat-send-btn');
            const mainChatBellBtn = document.getElementById('main-chat-bell-btn');
            const dmTargetNodeIdInput = document.getElementById('dm-target-node-id-input');
            const userInfoPopup = document.getElementById('user-info-popup');
            const userInfoTitle = document.getElementById('user-info-title');
            const userInfoBody = document.getElementById('user-info-body');
            const userInfoMinimizeBtn = document.getElementById('user-info-minimize');
            const userInfoCloseBtn = document.getElementById('user-info-close');
            const sosPopupContainer = document.getElementById('sos-popup-container');
            const userEditModal = document.getElementById('user-edit-modal');
            const userEditForm = document.getElementById('user-edit-form');
            const addressLatInput = userEditForm?.querySelector('input[name="address_lat"]');
            const addressLonInput = userEditForm?.querySelector('input[name="address_lon"]');
            const useAddressCoordsInput = userEditForm?.querySelector('input[name="use_address_coords"]');
            const addressCoordsWarning = document.getElementById('address-coords-warning');
            const closeUserModalBtnHeader = document.getElementById('close-user-modal-btn');
            const closeUserModalBtnFooter = document.getElementById('close-user-modal-btn-footer');
            const userModalTitle = document.getElementById('user-modal-title')?.querySelector('span');
            const broadcastEditModal = document.getElementById('broadcast-edit-modal');
            const closeBroadcastModalBtnHeader = document.getElementById('close-broadcast-modal-btn');
            const closeBroadcastModalBtnFooter = document.getElementById('close-broadcast-modal-btn-footer');

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

            function openUserEditModal(userData) {
                if (!userEditModal || !userEditForm) return;
                setLocalUserRecord(userData?.node_id, userData);
                if (userModalTitle) userModalTitle.textContent = `${userData.node_id} / ${userData.name || userData.node_id}`;
                userEditForm.querySelector('input[name="node_id"]').value = userData.node_id;
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
                userEditForm.querySelector('textarea[name="poc_info"]').value = userData.poc_info || '';
                userEditForm.querySelector('input[name="tags"]').value = (userData.tags || []).join(', ');
                userEditForm.querySelector('input[name="sos_notify"]').value = userData.sos_notify || '';
                userEditForm.querySelector('input[name="alerts"]').checked = userData.alerts || false;
                userEditForm.querySelector('input[name="weather"]').checked = userData.weather || false;
                userEditForm.querySelector('input[name="scheduled_daily_forecast"]').checked = userData.scheduled_daily_forecast || false;
                userEditForm.querySelector('input[name="email_send"]').checked = userData.email_send || false;
                userEditForm.querySelector('input[name="email_receive"]').checked = userData.email_receive || false;
                userEditForm.querySelector('input[name="emailbroadcast"]').checked = userData.emailbroadcast || false;
                userEditForm.querySelector('input[name="node_tag_send"]').checked = userData.node_tag_send || false;
                userEditForm.querySelector('input[name="blocked"]').checked = userData.blocked || false;
                updateAddressCoordToggle();
                userEditModal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
            }

            function closeUserEditModal() {
                if (!userEditModal) return;
                userEditModal.style.display = 'none';
                restoreBodyOverflow();
            }

            function openBroadcastEditModal(jobData) {
                const broadcastEditForm = document.getElementById('broadcast-edit-form');
                if (!broadcastEditModal || !broadcastEditForm) return;
                broadcastEditModal.querySelector('#broadcast-modal-title span').textContent = `Edit: ${jobData.name || 'Untitled Job'}`;
                broadcastEditForm.querySelector('input[name="job_index"]').value = jobData.job_index;
                document.getElementById('broadcast-modal-delete-form').querySelector('input[name="job_index"]').value = jobData.job_index;
                broadcastEditForm.querySelector('input[name="name"]').value = jobData.name || '';
                let content = jobData.content || '';
                const bellCheckbox = broadcastEditForm.querySelector('input[name="with_bell"]');
                if (content.startsWith("\x07")) {
                    bellCheckbox.checked = true;
                    content = content.substring(1);
                } else {
                    bellCheckbox.checked = false;
                }
                broadcastEditForm.querySelector('textarea[name="content"]').value = content;
                broadcastEditForm.querySelector('input[name="enabled"]').checked = jobData.enabled || false;
                broadcastEditForm.querySelector('input[name="interval_mins"]').value = jobData.interval_mins || 60;
                const jobTypeSelector = broadcastEditForm.querySelector('.job-type-selector');
                if (jobData.days) {
                    jobTypeSelector.value = 'recurring';
                    broadcastEditForm.querySelectorAll('input[name="days[]"]').forEach(cb => {
                        cb.checked = (jobData.days || []).includes(cb.value);
                    });
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

            function closeBroadcastEditModal() {
                if (!broadcastEditModal) return;
                broadcastEditModal.style.display = 'none';
                restoreBodyOverflow();
            }

            document.querySelectorAll('.job-type-selector').forEach(select => {
                select.addEventListener('change', function() {
                    toggleJobFields(this.closest('form'));
                });
            });
            toggleJobFields(document.getElementById('broadcast-edit-form'));

            // --- Confirm Modal ---
            const confirmModal = document.getElementById('confirm-action-modal');
            const confirmModalText = document.getElementById('confirm-modal-text');
            const confirmBtn = document.getElementById('confirm-modal-confirm-btn');
            const cancelBtn = document.getElementById('confirm-modal-cancel-btn');
            const confirmCloseBtn = document.getElementById('confirm-modal-close-btn');
            let formToSubmit = null;

            function showConfirmModal(message, formElement) {
                formToSubmit = formElement;
                confirmModalText.textContent = message;
                confirmModal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
            }

            function hideConfirmModal() {
                confirmModal.style.display = 'none';
                formToSubmit = null;
                restoreBodyOverflow();
            }

            confirmBtn?.addEventListener('click', () => {
                if (formToSubmit) {
                    formToSubmit.submit();
                }
                hideConfirmModal();
            });
            cancelBtn?.addEventListener('click', hideConfirmModal);
            confirmCloseBtn?.addEventListener('click', hideConfirmModal);

            document.body.addEventListener('submit', function(event) {
                const form = event.target;
                if (form && form.classList && form.classList.contains('stand-down-form')) {
                    event.preventDefault();
                    showConfirmModal('This will trigger the full stand-down protocol for this SOS. Proceed?', form);
                }
            });
            function closeAllModals() {
                document.querySelectorAll('.modal-overlay.active').forEach(modal => {
                    modal.classList.remove('active');
                });
                restoreBodyOverflow();
            }

            function openModal(modalId) {
                closeAllModals();
                const modal = document.getElementById(modalId);
                if (!modal) return;
                modal.classList.add('active');
                document.body.style.overflow = 'hidden';
            }

            function restoreBodyOverflow() {
                const hasActive = document.querySelector('.modal-overlay.active');
                const hasVisible =
                    (userEditModal && userEditModal.style.display === 'flex') ||
                    (broadcastEditModal && broadcastEditModal.style.display === 'flex') ||
                    (confirmModal && confirmModal.style.display === 'flex') ||
                    (dmModal && dmModal.style.display === 'flex');
                if (!hasActive && !hasVisible) {
                    document.body.style.overflow = '';
                }
            }

            function renderMopUsersTable(usersPayload) {
                const tbody = document.getElementById('mop-users-table-body');
                if (!tbody) return;
                const rows = Array.isArray(usersPayload?.rows) ? usersPayload.rows : [];
                if (rows.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="status-muted">No subscribers found.</td></tr>';
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
                        ? 'status-muted'
                        : (row?.reported_role_matches ? 'status-ok' : 'status-warn');
                    const tags = Array.isArray(row?.tags) ? row.tags.filter(Boolean).join(', ') : '';
                    const displayName = name || nodeId;
                    return `
                        <tr>
                            <td class="font-mono">
                                <button type="button" class="open-dm-chat" data-node-id="${escapeHTML(nodeId)}" data-node-name="${escapeHTML(displayName)}">${escapeHTML(nodeId)}</button>
                            </td>
                            <td>${escapeHTML(name)}</td>
                            <td>
                                <div class="role-pill ${roleClass}">${escapeHTML(reportedRole)}</div>
                                <div>${escapeHTML(assignedRole)}</div>
                            </td>
                            <td>${escapeHTML(fullName)}</td>
                            <td>${escapeHTML(phone1)}</td>
                            <td class="status-muted">${escapeHTML(tags || '\u2014')}</td>
                            <td><button type="button" class="btn btn-secondary open-user-edit-modal" data-node-id="${escapeHTML(nodeId)}">More...</button></td>
                        </tr>
                    `;
                }).join('');
                indexUserEditButtonsByNodeId();
            }

            function renderMopBroadcastsTable(broadcastPayload) {
                const tbody = document.getElementById('mop-broadcasts-table-body');
                if (!tbody) return;
                const jobs = Array.isArray(broadcastPayload?.jobs) ? broadcastPayload.jobs : [];
                if (jobs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="status-muted">No custom broadcast jobs found.</td></tr>';
                    return;
                }
                const dayOrder = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
                tbody.innerHTML = jobs.map((job) => {
                    const enabled = !!job?.enabled;
                    const name = String(job?.name || 'N/A');
                    const intervalMins = String(job?.interval_mins ?? 'N/A');
                    const days = Array.isArray(job?.days) ? job.days.map((d) => String(d || '').toUpperCase()) : null;
                    const daysHtml = Array.isArray(days)
                        ? dayOrder.map((day) => {
                            const isActive = days.includes(day);
                            return `<span style="color:${isActive ? '#60a5fa' : '#52525b'};">${day.slice(0, 1)}</span>`;
                        }).join(' ')
                        : '<span class="status-muted">Event</span>';
                    const windowText = (job?.start_datetime || job?.stop_datetime)
                        ? `${String(job?.start_datetime || '')} to ${String(job?.stop_datetime || '')}`
                        : `${String(job?.start_time || 'N/A')} - ${String(job?.stop_time || 'N/A')}`;
                    const serialized = escapeHTML(JSON.stringify(job || {}));
                    return `
                        <tr>
                            <td>${enabled ? 'Enabled' : 'Disabled'}</td>
                            <td>${escapeHTML(name)}</td>
                            <td>${daysHtml}</td>
                            <td>${escapeHTML(intervalMins)} mins</td>
                            <td>${escapeHTML(windowText)}</td>
                            <td><button type="button" class="btn btn-secondary open-broadcast-edit-modal" data-job-data="${serialized}">More...</button></td>
                        </tr>
                    `;
                }).join('');
            }

            async function fetchMopAdminTables(scope, forceFresh = false) {
                const normalizedScope = String(scope || '').trim().toLowerCase();
                if (normalizedScope !== 'users' && normalizedScope !== 'broadcasts') {
                    return false;
                }
                const etagRef = normalizedScope === 'users' ? adminUsersTableEtag : adminBroadcastsTableEtag;
                const requestHeaders = {};
                if (!forceFresh && etagRef) {
                    requestHeaders['If-None-Match'] = etagRef;
                }
                const response = await fetch(`/map-items/api_get_admin_tables.php?scope=${encodeURIComponent(normalizedScope)}`, { headers: requestHeaders });
                const responseEtag = response.headers.get('ETag');
                if (responseEtag) {
                    if (normalizedScope === 'users') {
                        adminUsersTableEtag = responseEtag;
                    } else {
                        adminBroadcastsTableEtag = responseEtag;
                    }
                }
                if (response.status === 304) {
                    return true;
                }
                if (!response.ok) {
                    if (normalizedScope === 'users') {
                        const tbody = document.getElementById('mop-users-table-body');
                        if (tbody) {
                            tbody.innerHTML = '<tr><td colspan="7" class="status-muted">Failed to load subscribers.</td></tr>';
                        }
                    } else {
                        const tbody = document.getElementById('mop-broadcasts-table-body');
                        if (tbody) {
                            tbody.innerHTML = '<tr><td colspan="6" class="status-muted">Failed to load broadcasts.</td></tr>';
                        }
                    }
                    return false;
                }
                const payload = await response.json();
                if (normalizedScope === 'users') {
                    if (payload?.users?.directory && typeof payload.users.directory === 'object') {
                        localUserDirectory = Object.assign(Object.create(null), localUserDirectory || {}, payload.users.directory || {});
                    }
                    renderMopUsersTable(payload?.users || null);
                } else {
                    renderMopBroadcastsTable(payload?.broadcasts || null);
                }
                return true;
            }

            function ensureMopUsersTableLoaded(forceFresh = false) {
                if (adminUsersFetchInFlight) {
                    return adminUsersFetchInFlight;
                }
                const requestPromise = fetchMopAdminTables('users', forceFresh)
                    .catch((error) => {
                        console.error('Failed to load users table:', error);
                        return false;
                    })
                    .finally(() => {
                        if (adminUsersFetchInFlight === requestPromise) {
                            adminUsersFetchInFlight = null;
                        }
                    });
                adminUsersFetchInFlight = requestPromise;
                return requestPromise;
            }

            function ensureMopBroadcastsTableLoaded(forceFresh = false) {
                if (adminBroadcastsFetchInFlight) {
                    return adminBroadcastsFetchInFlight;
                }
                const requestPromise = fetchMopAdminTables('broadcasts', forceFresh)
                    .catch((error) => {
                        console.error('Failed to load broadcasts table:', error);
                        return false;
                    })
                    .finally(() => {
                        if (adminBroadcastsFetchInFlight === requestPromise) {
                            adminBroadcastsFetchInFlight = null;
                        }
                    });
                adminBroadcastsFetchInFlight = requestPromise;
                return requestPromise;
            }

            function openAdminPanel(tab) {
                const modalMap = {
                    chat: 'modal-chat',
                    actions: 'modal-actions',
                    broadcasts: 'modal-broadcasts',
                    users: 'modal-users'
                };
                const modalId = modalMap[tab] || 'modal-actions';
                openModal(modalId);
                if (tab === 'chat') {
                    if (!isChatPolling) {
                        startChatPolling();
                    }
                    renderChatGroupTabs();
                    renderFilteredChat();
                    updateChat();
                }
                if (tab === 'actions') {
                    fetchBlocklist();
                }
                if (tab === 'users') {
                    void ensureMopUsersTableLoaded(false);
                }
                if (tab === 'broadcasts') {
                    void ensureMopBroadcastsTableLoaded(false);
                }
            }

            function initModals() {
                document.querySelectorAll('.panel-btn').forEach(button => {
                    button.addEventListener('click', () => {
                        const tab = button.dataset.adminTab || '';
                        openAdminPanel(tab);
                    });
                });

                document.querySelectorAll('[data-close]').forEach(button => {
                    button.addEventListener('click', closeAllModals);
                });

                document.querySelectorAll('.modal-overlay').forEach(modal => {
                    modal.addEventListener('click', (event) => {
                        if (event.target !== modal) return;
                        if (modal.id === 'confirm-action-modal') {
                            hideConfirmModal();
                            return;
                        }
                        if (modal.id === 'user-edit-modal') {
                            closeUserEditModal();
                            return;
                        }
                        if (modal.id === 'broadcast-edit-modal') {
                            closeBroadcastEditModal();
                            return;
                        }
                        closeAllModals();
                    });
                });

                document.addEventListener('keydown', (event) => {
                    if (event.key !== 'Escape') return;
                    if (confirmModal && confirmModal.style.display === 'flex') {
                        hideConfirmModal();
                        return;
                    }
                    if (userEditModal && userEditModal.style.display === 'flex') {
                        closeUserEditModal();
                        return;
                    }
                    if (broadcastEditModal && broadcastEditModal.style.display === 'flex') {
                        closeBroadcastEditModal();
                        return;
                    }
                    closeAllModals();
                });

            }

            function startStatusPolling() {
                if (isStatusPolling) return;
                isStatusPolling = true;
                statusBackoffMs = POLLING_INTERVAL;
                runStatusPoll();
            }

            function startChatPolling() {
                if (isChatPolling) return;
                isChatPolling = true;
                chatBackoffMs = CHAT_POLLING_INTERVAL;
                if (CHAT_STREAM_ENABLED && !isPollingPaused) {
                    startChatStream();
                }
                runChatPoll();
            }

            function scheduleStatusPoll(delay) {
                if (statusPollTimer) clearTimeout(statusPollTimer);
                statusPollTimer = setTimeout(runStatusPoll, delay);
            }

            function scheduleChatPoll(delay) {
                if (chatPollTimer) clearTimeout(chatPollTimer);
                chatPollTimer = setTimeout(runChatPoll, delay);
            }

            async function runStatusPoll() {
                if (!isStatusPolling) return;
                if (isPollingPaused) {
                    scheduleStatusPoll(POLLING_INTERVAL);
                    return;
                }
                if (statusPollInFlight) {
                    scheduleStatusPoll(statusBackoffMs || POLLING_INTERVAL);
                    return;
                }
                statusPollInFlight = true;
                let okNodes = false;
                let okDash = false;
                try {
                    okNodes = await updatePageData();
                    okDash = await updateDashboardData();
                } finally {
                    statusPollInFlight = false;
                }
                if (okNodes && okDash) {
                    statusBackoffMs = POLLING_INTERVAL;
                } else {
                    statusBackoffMs = Math.min(MAX_BACKOFF_MS, Math.max(POLLING_INTERVAL, statusBackoffMs * 2));
                }
                if (!isStatusPolling) {
                    return;
                }
                scheduleStatusPoll(statusBackoffMs);
            }

            async function runChatPoll() {
                if (!isChatPolling) return;
                if (isPollingPaused) {
                    stopChatStream();
                    scheduleChatPoll(CHAT_POLLING_INTERVAL);
                    return;
                }
                if (chatPollInFlight) {
                    scheduleChatPoll(chatBackoffMs || CHAT_POLLING_INTERVAL);
                    return;
                }
                chatPollInFlight = true;
                let okChat = true;
                try {
                    if (CHAT_STREAM_ENABLED) {
                        if (!chatStreamSource && !chatStreamRetryTimer) {
                            startChatStream();
                        }
                        okChat = true;
                    } else {
                        okChat = await updateChat();
                    }
                } finally {
                    chatPollInFlight = false;
                }
                if (okChat) {
                    chatBackoffMs = CHAT_POLLING_INTERVAL;
                } else {
                    chatBackoffMs = Math.min(MAX_BACKOFF_MS, Math.max(CHAT_POLLING_INTERVAL, chatBackoffMs * 2));
                }
                if (!isChatPolling) {
                    return;
                }
                scheduleChatPoll(chatBackoffMs);
            }

            document.getElementById('node-list').addEventListener('click', function(event) {
                const item = event.target.closest('.node-item');
                if (!item) return;
                const nodeId = item.dataset.nodeId;
                const nodeName = item.dataset.nodeName || nodeId;
                openDmChat(nodeId, nodeName);
            });

            document.body.addEventListener('click', function(event) {
                const button = event.target.closest('.open-dm-chat');
                if (!button) return;
                const nodeId = button.dataset.nodeId;
                const nodeName = button.dataset.nodeName || nodeId;
                closeAllModals();
                closeUserEditModal();
                closeBroadcastEditModal();
                hideConfirmModal();
                openDmChat(nodeId, nodeName);
            });

            document.body.addEventListener('click', function(event) {
                const usernameButton = event.target.closest('.chat-username');
                if (!usernameButton) return;
                const nodeId = usernameButton.dataset.nodeId;
                if (!nodeId) return;
                openUserInfoPopup(nodeId);
            });

            document.body.addEventListener('click', function(event) {
                if (event.target.matches('.location-btn')) {
                    const { lat, lon } = event.target.dataset;
                    if (map && lat && lon) {
                        map.setView([lat, lon], Math.max(map.getZoom(), 15));
                        autoFitEnabled = false;
                    }
                }
            });

            indexUserEditButtonsByNodeId();
            document.body.addEventListener('click', async (event) => {
                const button = event.target.closest('.open-user-edit-modal');
                if (!button) return;
                const nodeId = String(button.dataset.nodeId || '').trim();
                if (!nodeId) return;
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
            addressLatInput?.addEventListener('input', updateAddressCoordToggle);
            addressLonInput?.addEventListener('input', updateAddressCoordToggle);
            closeUserModalBtnHeader?.addEventListener('click', closeUserEditModal);
            closeUserModalBtnFooter?.addEventListener('click', closeUserEditModal);

            document.body.addEventListener('click', (event) => {
                const button = event.target.closest('.open-broadcast-edit-modal');
                if (!button) return;
                try {
                    const jobData = JSON.parse(String(button.dataset.jobData || '{}'));
                    openBroadcastEditModal(jobData);
                } catch (error) {
                    console.error('Invalid broadcast job payload:', error);
                }
            });
            closeBroadcastModalBtnHeader?.addEventListener('click', closeBroadcastEditModal);
            closeBroadcastModalBtnFooter?.addEventListener('click', closeBroadcastEditModal);

            document.getElementById('show-dms-checkbox')?.addEventListener('change', renderFilteredChat);
            document.getElementById('show-sms-checkbox')?.addEventListener('change', renderFilteredChat);

            if (userInfoMinimizeBtn) {
                userInfoMinimizeBtn.textContent = '-';
                userInfoMinimizeBtn.setAttribute('aria-label', 'Minimize Info panel');
                userInfoMinimizeBtn.title = 'Minimize';
            }
            userInfoMinimizeBtn?.addEventListener('click', () => {
                setUserInfoPopupMinimized(!userInfoPopupMinimized);
            });
            userInfoCloseBtn?.addEventListener('click', closeUserInfoPopup);
            dmChatInfoBtn?.addEventListener('click', () => {
                const nodeId = dmChatInfoBtn.dataset.nodeId || dmTargetNodeIdInput?.value || '';
                if (!nodeId) return;
                openUserInfoPopup(nodeId);
            });
            dmChatUserBtn?.addEventListener('click', async () => {
                const nodeId = dmChatUserBtn.dataset.nodeId || dmTargetNodeIdInput?.value || '';
                const userRecord = await ensureUserRecord(nodeId);
                closeDmChat();
                if (userRecord) {
                    openUserEditModal(userRecord);
                    return;
                }
                openCreateUserFromDmTarget(nodeId);
            });

            const clearEmailQueueForm = document.getElementById('clear-email-queue-form');
            if (clearEmailQueueForm) {
                clearEmailQueueForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    showConfirmModal('Are you sure you want to clear the outgoing email queue?', this);
                });
            }

            const clearEmailQuarantineForm = document.getElementById('clear-email-quarantine-form');
            if (clearEmailQuarantineForm) {
                clearEmailQuarantineForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    showConfirmModal('Are you sure you want to clear the outgoing email quarantine?', this);
                });
            }

            const clearDeadLetterQueueForm = document.getElementById('clear-dead-letter-queue-form');
            if (clearDeadLetterQueueForm) {
                clearDeadLetterQueueForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    showConfirmModal('Are you sure you want to clear all dead-letter DB rows? Quarantined files remain unless deleted individually.', this);
                });
            }

            document.querySelectorAll('form input[name="action"][value="delete_dead_letter_command"]').forEach((input) => {
                const form = input.closest('form');
                if (!form) return;
                form.addEventListener('submit', function(e) {
                    e.preventDefault();
                    showConfirmModal('Delete this dead-letter row and remove its quarantined file (if found)?', this);
                });
            });

            document.querySelectorAll('form input[name="action"][value="requeue_dead_letter_command"]').forEach((input) => {
                const form = input.closest('form');
                if (!form) return;
                form.addEventListener('submit', function(e) {
                    e.preventDefault();
                    showConfirmModal('Requeue this dead-letter command for processing now?', this);
                });
            });

            const adminClearSosForm = document.getElementById('admin-clear-sos-form');
            if (adminClearSosForm) {
                adminClearSosForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    showConfirmModal('This will trigger the full stand-down protocol for the active SOS. Proceed?', this);
                });
            }

            const broadcastDeleteForm = document.getElementById('broadcast-modal-delete-form');
            if (broadcastDeleteForm) {
                broadcastDeleteForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    showConfirmModal('Are you sure you want to permanently delete this broadcast job?', this);
                });
            }

            document.getElementById('close-dm-modal-btn').addEventListener('click', closeDmChat);
            document.getElementById('dm-chat-form').addEventListener('submit', function(e) {
                e.preventDefault();
                const text = dmChatTextarea.value.trim();
                const target = lastFetchedSubscribers[dmTargetNodeIdInput.value]?.name || dmTargetNodeIdInput.value;
                const fullMessage = `@${target} ${text}`;
                sendAjaxMessage(fullMessage, document.getElementById('dm-chat-send-btn'), false);
            });
            document.getElementById('dm-chat-bell-btn').addEventListener('click', function() {
                const text = dmChatTextarea.value.trim();
                const target = lastFetchedSubscribers[dmTargetNodeIdInput.value]?.name || dmTargetNodeIdInput.value;
                const fullMessage = `@${target} ${text}`;
                sendAjaxMessage(fullMessage, this, true);
            });
            document.getElementById('dm-chat-textarea').addEventListener('keydown', function(event) {
                if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    document.getElementById('dm-chat-send-btn').click();
                }
            });

            dmChatMapBtn?.addEventListener('click', () => {
                if (!dmChatMapBtn || dmChatMapBtn.disabled) return;
                const lat = Number(dmChatMapBtn.dataset.lat);
                const lon = Number(dmChatMapBtn.dataset.lon);
                if (map && Number.isFinite(lat) && Number.isFinite(lon)) {
                    map.setView([lat, lon], Math.max(map.getZoom(), 15));
                    autoFitEnabled = false;
                }
            });

            mainChatSendBtn?.addEventListener('click', function() {
                sendAjaxMessage(mainChatTextarea.value, this, false);
            });
            mainChatBellBtn?.addEventListener('click', function() {
                sendAjaxMessage(mainChatTextarea.value, this, true);
            });
            mainChatTextarea?.addEventListener('keydown', function(event) {
                if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    mainChatSendBtn.click();
                }
            });
            renderChatGroupTabs();

            document.addEventListener('visibilitychange', () => {
                isPollingPaused = document.hidden;
                if (isPollingPaused) {
                    stopChatStream();
                }
                if (!isPollingPaused) {
                    statusBackoffMs = POLLING_INTERVAL;
                    chatBackoffMs = CHAT_POLLING_INTERVAL;
                    if (CHAT_STREAM_ENABLED) {
                        startChatStream();
                    }
                    runStatusPoll();
                    runChatPoll();
                }
            });

            const acknowledgeSosBanner = () => {
                if (activeSosNodeId) {
                    acknowledgedSosNodes.add(activeSosNodeId);
                }
                activeSosNodeId = null;
                const sosBanner = document.getElementById('sos-banner');
                if (sosBanner) {
                    sosBanner.style.display = 'none';
                }
                updateSosAudioState();
            };

            const sosBannerAckBtn = document.getElementById('sos-banner-ack-btn');
            sosBannerAckBtn?.addEventListener('click', acknowledgeSosBanner);

            const sosBannerCloseBtn = document.getElementById('sos-banner-close');
            sosBannerCloseBtn?.addEventListener('click', acknowledgeSosBanner);

            document.getElementById('sos-banner-open-btn')?.addEventListener('click', () => {
                openAdminPanel('actions');
            });

            document.getElementById('sos-banner-mute-btn')?.addEventListener('click', () => {
                sosMutedUntil = Date.now() + (5 * 60 * 1000);
                scheduleMuteCountdown();
                updateSosButtons();
                updateSosAudioState();
            });

            document.getElementById('sos-banner-sound-btn')?.addEventListener('click', () => {
                sosAudioEnabled = !sosAudioEnabled;
                ensureSosAudioContext();
                updateSosButtons();
                updateSosAudioState();
            });

            window.addEventListener('resize', positionSosPopup);

            const successAlerts = document.querySelectorAll('.alert.success');
            if (successAlerts.length) {
                setTimeout(() => {
                    successAlerts.forEach(alert => alert.remove());
                }, 8000);
            }

            initModals();
            initMap();
            startStatusPolling();
            setInterval(refreshNodeAges, 30000);
        });
    </script>

    <input type="hidden" id="dm-target-node-id-input" value="">
</body>
</html>
