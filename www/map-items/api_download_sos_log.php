<?php
// GuardianBridge - api_download_sos_log.php (v1.0.0)

session_start();

$is_map_admin = isset($_SESSION['map_loggedin']) && $_SESSION['map_loggedin'] === true;
$is_mop_operator = isset($_SESSION['mop_loggedin']) && $_SESSION['mop_loggedin'] === true;
if (!$is_map_admin && !$is_mop_operator) {
    header('HTTP/1.1 403 Forbidden');
    die('Authentication required.');
}

require_once __DIR__ . '/../db.php';

$sos_log = gb_load_sos_logs(false);
$subscribers = gb_load_subscribers();

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
