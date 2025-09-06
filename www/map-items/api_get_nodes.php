<?php
ini_set('display_errors', 0); // Production should not display errors
error_reporting(0);

// api_get_nodes.php
// This secure API endpoint provides combined node status and subscriber data.

session_start();

// --- SECURITY CHECK ---
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['error' => 'Authentication required.']));
}

// --- CONFIGURATION ---
$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$node_status_file = $data_dir . '/node_status.json';
$subscribers_file = $data_dir . '/subscribers.json';

// --- HELPER FUNCTION ---
function load_json_data($file_path) {
    if (!is_readable($file_path)) return [];
    $content = @file_get_contents($file_path);
    if ($content === false) return [];
    return json_decode($content, true) ?? [];
}

// --- DATA RETRIEVAL & MERGING ---
$node_statuses = load_json_data($node_status_file);
$subscribers = load_json_data($subscribers_file);

$combined_data = [];

// Use the full subscriber list as the master list to include offline nodes
foreach ($subscribers as $node_id => $subscriber_info) {
    $status = $node_statuses[$node_id] ?? [];
    
    $combined_data[$node_id] = [
        // Core status info
        'node_id' => $node_id,
        'lastHeard' => $status['lastHeard'] ?? null,
        'snr' => $status['snr'] ?? 'N/A',
        'hopsAway' => $status['hopsAway'] ?? 'N/A',
        'role' => $status['role'] ?? 'OFFLINE',
        'latitude' => $status['latitude'] ?? null,
        'longitude' => $status['longitude'] ?? null,
        'sos' => $status['sos'] ?? null,
        
        // Subscriber info for popups
        'name' => $subscriber_info['name'] ?? null,
        'full_name' => $subscriber_info['full_name'] ?? null,
        'phone_1' => $subscriber_info['phone_1'] ?? null,
        'phone_2' => $subscriber_info['phone_2'] ?? null,
        'email' => $subscriber_info['email'] ?? null, 
        'address' => $subscriber_info['address'] ?? null,
        'notes' => $subscriber_info['notes'] ?? null,
    ];
}


// --- SEND RESPONSE ---
header('Content-Type: application/json');
echo json_encode(array_values($combined_data)); // Return as a simple array for easier JS iteration
exit;
