<?php
// Set the content type to application/json
header('Content-Type: application/json');

// --- CONFIGURATION & FILE PATHS ---
$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$dispatcher_status_file = $data_dir . '/dispatcher_status.json';
$weather_fetcher_lastrun_file = $data_dir . '/weather_fetcher.lastrun';
$email_processor_lastrun_file = $data_dir . '/email_processor.lastrun';
$weather_current_file = $data_dir . '/weather_current.json';
$weather_alerts_file = $data_dir . '/nws_alerts.txt'; // Assuming this is the correct path from your script
$sos_log_file = $data_dir . '/sos_log.json';

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

function get_file_age_string($file_path) {
    if (!file_exists($file_path)) return 'Never';
    $age_seconds = time() - filemtime($file_path);
    if ($age_seconds < 60) return $age_seconds . ' seconds ago';
    if ($age_seconds < 3600) return round($age_seconds / 60) . ' minutes ago';
    return round($age_seconds / 3600) . ' hours ago';
}

// --- DATA GATHERING ---
$service_status_raw = trim(shell_exec('systemctl is-active guardianbridge.service'));
$dispatcher_status = get_locked_json_file($dispatcher_status_file, ['radio_connected' => false]);
$weather_current = get_locked_json_file($weather_current_file, ['temperature_f' => 'N/A', 'humidity' => 'N/A']);
$weather_alerts = get_locked_json_file($weather_alerts_file, []);
$sos_log = array_reverse(get_locked_json_file($sos_log_file, [])); // Get latest first

// --- BUILD THE RESPONSE ARRAY ---
$response = [
    'system_health' => [
        'dispatcher_active' => ($service_status_raw === 'active'),
        'radio_connected' => $dispatcher_status['radio_connected'],
        'weather_fetcher_ok' => (file_exists($weather_fetcher_lastrun_file) && (time() - filemtime($weather_fetcher_lastrun_file)) < 1800),
        'weather_fetcher_last_run' => get_file_age_string($weather_fetcher_lastrun_file),
        'email_processor_ok' => (file_exists($email_processor_lastrun_file) && (time() - filemtime($email_processor_lastrun_file)) < 600),
        'email_processor_last_run' => get_file_age_string($email_processor_lastrun_file),
    ],
    'weather_info' => [
        'temperature_f' => htmlspecialchars($weather_current['temperature_f'] ?? 'N/A'),
        'humidity' => htmlspecialchars($weather_current['humidity'] ?? 'N/A'),
        'active_alert' => !empty($weather_alerts) ? htmlspecialchars($weather_alerts[0]['headline'] ?? 'N/A') : 'No active alerts.'
    ],
    'sos_log' => array_slice($sos_log, 0, 10) // Send the 10 most recent SOS logs
];

// --- OUTPUT JSON ---
echo json_encode($response);
