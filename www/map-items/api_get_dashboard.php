<?php
// GuardianBridge - api_get_dashboard.php (v1.4.0)

header('Content-Type: application/json');
require_once __DIR__ . '/../db.php';
session_start();
$gb_perf_start = microtime(true);
register_shutdown_function(function () use ($gb_perf_start) {
    $elapsed_ms = (microtime(true) - $gb_perf_start) * 1000;
    if ($elapsed_ms >= 750) {
        error_log(sprintf('GuardianBridge Perf: api_get_dashboard %.1fms', $elapsed_ms));
    }
});

$is_map_admin = isset($_SESSION['map_loggedin']) && $_SESSION['map_loggedin'] === true;
$is_mop_operator = isset($_SESSION['mop_loggedin']) && $_SESSION['mop_loggedin'] === true;
if (!$is_map_admin && !$is_mop_operator) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['error' => 'Authentication required.']));
}

header('Cache-Control: private, no-cache, must-revalidate');
header('Vary: Cookie');
$if_none_match = trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''));
$cache_file = '/opt/GuardianBridge/data/api_dashboard_cache.json';
$cache_ttl_seconds = 2;

function gb_dashboard_api_read_cache($path, $ttl_seconds) {
    if (!is_readable($path)) {
        return null;
    }
    $mtime = @filemtime($path);
    if (!$mtime || (time() - intval($mtime)) > max(0, intval($ttl_seconds))) {
        return null;
    }
    $raw = @file_get_contents($path);
    if (!is_string($raw) || trim($raw) === '') {
        return null;
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return null;
    }
    $etag = trim((string)($decoded['etag'] ?? ''));
    $payload_json = $decoded['payload_json'] ?? null;
    if ($etag === '' || !is_string($payload_json) || $payload_json === '') {
        return null;
    }
    return [
        'etag' => $etag,
        'payload_json' => $payload_json,
    ];
}

function gb_dashboard_api_write_cache($path, $etag, $payload_json) {
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    if (!is_dir($dir)) {
        return;
    }
    $payload = [
        'etag' => (string)$etag,
        'payload_json' => (string)$payload_json,
        'created_at' => time(),
    ];
    try {
        $suffix = bin2hex(random_bytes(3));
    } catch (Throwable $e) {
        $suffix = substr(sha1(uniqid('', true) . microtime(true)), 0, 6);
    }
    $tmp = $path . '.tmp.' . getmypid() . '.' . $suffix;
    $ok = @file_put_contents($tmp, json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    if ($ok === false) {
        @unlink($tmp);
        return;
    }
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
    }
}

function gb_dashboard_api_etag_matches($if_none_match, $etag) {
    $raw = trim((string)$if_none_match);
    if ($raw === '') {
        return false;
    }
    if ($raw === '*') {
        return true;
    }
    $parts = explode(',', $raw);
    foreach ($parts as $part) {
        $candidate = trim($part);
        if ($candidate === $etag || $candidate === ('W/' . $etag)) {
            return true;
        }
    }
    return false;
}

$cached = gb_dashboard_api_read_cache($cache_file, $cache_ttl_seconds);
if (is_array($cached)) {
    header('ETag: ' . $cached['etag']);
    if (gb_dashboard_api_etag_matches($if_none_match, $cached['etag'])) {
        http_response_code(304);
        exit;
    }
    echo $cached['payload_json'];
    exit;
}

// --- CONFIGURATION & FILE PATHS ---
$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$dispatcher_status_file = $data_dir . '/dispatcher_status.json';
$weather_fetcher_lastrun_file = $data_dir . '/weather_fetcher.lastrun';
$email_processor_lastrun_file = $data_dir . '/email_processor.lastrun';
$weather_current_file = $data_dir . '/weather_current.json';
$weather_alerts_file = $data_dir . '/nws_alerts.json'; // Corrected filename
$env_file = $base_dir . '/.env';

// --- HELPER FUNCTIONS ---
function get_locked_json_file($file_path, $default_value = null) {
    if (!is_readable($file_path)) return $default_value;
    $fp = @fopen($file_path, 'r');
    if (!$fp) return $default_value;
    $data = $default_value;
    if (flock($fp, LOCK_SH)) {
        $content = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        if ($content !== false && !empty(trim($content))) {
            $decoded = json_decode($content, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $data = $decoded;
            }
        }
    }
    fclose($fp);
    return $data;
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

function get_env_value($file_path, $key, $default_value = null) {
    if (!is_readable($file_path)) return $default_value;
    $lines = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || (strlen($line) > 0 && $line[0] === '#')) continue;
        if (strpos($line, '=') === false) continue;
        [$k, $v] = explode('=', $line, 2);
        if (trim($k) === $key) {
            $v = trim($v);
            $v = trim($v, "\"'");
            return $v;
        }
    }
    return $default_value;
}

function get_file_age_string($file_path) {
    if (!file_exists($file_path)) return 'Never';
    $age_seconds = time() - filemtime($file_path);
    if ($age_seconds < 60) return $age_seconds . ' seconds ago';
    if ($age_seconds < 3600) return round($age_seconds / 60) . ' minutes ago';
    return round($age_seconds / 3600) . ' hours ago';
}

// --- DATA GATHERING ---
$dispatcher_status = get_locked_json_file(
    $dispatcher_status_file,
    ['radio_connected' => false, 'runtime' => [], 'metrics' => [], 'alerts' => []]
);
$last_update_iso = trim((string)($dispatcher_status['last_update'] ?? ''));
$last_update_age_seconds = get_iso_age_seconds($last_update_iso, $dispatcher_status_file);
$dispatcher_active = ($last_update_age_seconds !== null && $last_update_age_seconds <= 120);
$metrics = is_array($dispatcher_status['metrics'] ?? null) ? $dispatcher_status['metrics'] : [];
$status_alerts = is_array($dispatcher_status['alerts'] ?? null) ? $dispatcher_status['alerts'] : [];
$normalized_alerts = [];
foreach ($status_alerts as $entry) {
    if (!is_array($entry)) {
        continue;
    }
    $level = strtolower(trim((string)($entry['level'] ?? 'warn')));
    if ($level !== 'critical' && $level !== 'warn' && $level !== 'info') {
        $level = 'warn';
    }
    $code = trim((string)($entry['code'] ?? 'general'));
    $message = trim((string)($entry['message'] ?? ''));
    if ($message === '') {
        continue;
    }
    $normalized_alerts[] = [
        'level' => $level,
        'code' => $code,
        'message' => $message,
    ];
}
if (!$dispatcher_active) {
    $age_label = ($last_update_age_seconds === null) ? 'unknown' : (string)$last_update_age_seconds;
    $normalized_alerts[] = [
        'level' => 'critical',
        'code' => 'dispatcher_stale',
        'message' => "Dispatcher status is stale (age: {$age_label}s).",
    ];
}

$runtime_last_error = (is_array($dispatcher_status['runtime']['last_error'] ?? null))
    ? $dispatcher_status['runtime']['last_error']
    : null;
$latest_exception = '';
$latest_exception_source = '';
$latest_exception_timestamp = '';
if ($runtime_last_error) {
    $latest_exception = trim((string)($runtime_last_error['message'] ?? ''));
    $latest_exception_source = trim((string)($runtime_last_error['source'] ?? ''));
    $latest_exception_timestamp = trim((string)($runtime_last_error['timestamp'] ?? ''));
}
$weather_current = get_locked_json_file($weather_current_file, ['temperature_f' => 'N/A', 'humidity' => 'N/A']);
$weather_alerts = get_locked_json_file($weather_alerts_file, []);
$weather_data_max_age_minutes = intval(get_env_value($env_file, 'WEATHER_DATA_MAX_AGE_MINUTES', 120));
$weather_age_seconds = get_iso_age_seconds($weather_current['timestamp'] ?? null, $weather_current_file);
$weather_is_stale = $weather_age_seconds !== null && $weather_age_seconds > ($weather_data_max_age_minutes * 60);
$weather_age_label = format_age_string($weather_age_seconds);
$weather_station_id = $weather_current['station_id'] ?? null;
$sos_log = gb_load_recent_sos_logs(10);
$active_sos_entries = gb_load_active_sos_logs();

$active_sos_list = [];
foreach ($active_sos_entries as $entry) {
    if (!empty($entry['active'])) {
        $active_sos_list[] = [
            'node_id' => $entry['node_id'] ?? 'N/A',
            'sos_type' => $entry['sos_type'] ?? 'SOS',
            'user_name' => $entry['user_info']['name'] ?? 'Unknown',
            'timestamp' => $entry['timestamp'] ?? ''
        ];
    }
}
$active_sos_node_id = '';
if (!empty($active_sos_list)) {
    $active_sos_node_id = (string)($active_sos_list[0]['node_id'] ?? '');
}

// --- BUILD THE RESPONSE ARRAY ---
$response = [
    'system_health' => [
        'dispatcher_active' => $dispatcher_active,
        'radio_connected' => !empty($dispatcher_status['radio_connected']),
        'dispatcher_restart_count' => intval($metrics['service_restart_count'] ?? 0),
        'dispatcher_result' => trim((string)($metrics['service_result'] ?? 'unknown')),
        'dispatcher_exec_status' => trim((string)($metrics['service_exec_status'] ?? 'n/a')),
        'dispatcher_exec_code' => trim((string)($metrics['service_exec_code'] ?? 'n/a')),
        'dispatcher_sub_state' => trim((string)($metrics['service_sub_state'] ?? 'unknown')),
        'dispatcher_last_update_age_seconds' => $last_update_age_seconds,
        'dispatcher_last_exception' => $latest_exception,
        'dispatcher_last_exception_source' => $latest_exception_source,
        'dispatcher_last_exception_time' => $latest_exception_timestamp,
        'alerts' => $normalized_alerts,
        'weather_fetcher_ok' => (file_exists($weather_fetcher_lastrun_file) && (time() - filemtime($weather_fetcher_lastrun_file)) < 1800),
        'weather_fetcher_last_run' => get_file_age_string($weather_fetcher_lastrun_file),
        'email_processor_ok' => (file_exists($email_processor_lastrun_file) && (time() - filemtime($email_processor_lastrun_file)) < 600),
        'email_processor_last_run' => get_file_age_string($email_processor_lastrun_file),
    ],
    'weather_info' => [
        'temperature_f' => htmlspecialchars($weather_current['temperature_f'] ?? 'N/A'),
        'humidity' => htmlspecialchars($weather_current['humidity'] ?? 'N/A'),
        'active_alert' => !empty($weather_alerts) && isset($weather_alerts[0]['headline']) ? htmlspecialchars($weather_alerts[0]['headline']) : 'No active alerts.',
        'last_update' => $weather_age_label,
        'stale' => $weather_is_stale,
        'station_id' => $weather_station_id
    ],
    'sos_log' => array_slice($sos_log, 0, 10),
    'active_sos_list' => $active_sos_list,
    'active_sos_node_id' => $active_sos_node_id,
    'metrics' => $metrics,
];

// --- OUTPUT JSON ---
$response_json = json_encode($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
if (!is_string($response_json)) {
    $response_json = json_encode([
        'system_health' => [],
        'weather_info' => [],
        'sos_log' => [],
        'active_sos_list' => [],
        'active_sos_node_id' => '',
        'metrics' => [],
    ]);
}
$etag = '"' . sha1($response_json) . '"';
header('ETag: ' . $etag);
if (gb_dashboard_api_etag_matches($if_none_match, $etag)) {
    http_response_code(304);
    exit;
}
gb_dashboard_api_write_cache($cache_file, $etag, $response_json);
echo $response_json;
?>
