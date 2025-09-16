<?php
// GuardianBridge - api_download_sos_log.php (v1.0.0)

session_start();

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('HTTP/1.1 403 Forbidden');
    die('Authentication required.');
}

$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$sos_log_file = $data_dir . '/sos_log.json';
$subscribers_file = $data_dir . '/subscribers.json';

function get_locked_json_file($file_path, $default_value = []) {
    if (!is_readable($file_path)) return $default_value;
    $fp = @fopen($file_path, 'r');
    if (!$fp) return $default_value;
    $data = $default_value;
    if (flock($fp, LOCK_SH)) {
        $content = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        if ($content !== false && !empty(trim($content))) {
            $decoded = json_decode($content, true);
            if (json_last_error() === JSON_ERROR_NONE) { $data = $decoded; }
        }
    }
    fclose($fp);
    return $data;
}

$sos_log = get_locked_json_file($sos_log_file, []);
$subscribers = get_locked_json_file($subscribers_file, []);

header('Content-Type: text/plain');
header('Content-Disposition: attachment; filename="guardianbridge_sos_log_' . date('Y-m-d_H-i') . '.txt"');

if (empty($sos_log)) {
    echo "GuardianBridge SOS Log\n";
    echo "Generated: " . date('Y-m-d H:i:s T') . "\n\n";
    echo "No SOS events have been logged.";
    exit;
}

echo "GuardianBridge SOS Log\n";
echo "Generated: " . date('Y-m-d H:i:s T') . "\n";
echo "=================================================\n\n";

foreach (array_reverse($sos_log) as $entry) {
    $user_name = $entry['user_info']['name'] ?? 'N/A';
    $full_name = $entry['user_info']['full_name'] ?? 'N/A';
    $status = !empty($entry['active']) ? 'ACTIVE' : 'CLEARED';

    echo "--- EVENT [" . $status . "] ---\n";
    echo "Timestamp:         " . ($entry['timestamp'] ?? 'N/A') . "\n";
    echo "SOS Type:          " . ($entry['sos_type'] ?? 'N/A') . "\n";
    echo "Node ID:           " . ($entry['node_id'] ?? 'N/A') . "\n";
    echo "User / Full Name:  " . $user_name . " / " . $full_name . "\n";
    echo "Message Payload:   " . ($entry['message_payload'] ?? 'None') . "\n";
    echo "Last Known Lat/Lon: " . ($entry['latitude'] ?? 'N/A') . ", " . ($entry['longitude'] ?? 'N/A') . "\n";
    
    $acknowledged_by_names = [];
    foreach($entry['acknowledged_by'] ?? [] as $node_id) {
        $acknowledged_by_names[] = $subscribers[$node_id]['name'] ?? $node_id;
    }
    echo "Acknowledged By:   " . (empty($acknowledged_by_names) ? 'None' : implode(', ', $acknowledged_by_names)) . "\n";

    $responding_list_names = [];
    foreach($entry['responding_list'] ?? [] as $node_id) {
        $responding_list_names[] = $subscribers[$node_id]['name'] ?? $node_id;
    }
    echo "Responding Units:  " . (empty($responding_list_names) ? 'None' : implode(', ', $responding_list_names)) . "\n";
    echo "---------------------------------------------\n\n";
}

exit;
?>
