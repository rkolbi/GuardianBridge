<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

session_start();

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['error' => 'Authentication required.']));
}

header('Content-Type: application/json');

$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$channel0_log_file = $data_dir . '/channel0_log.json';
$subscribers_file = $data_dir . '/subscribers.json';

function load_json_data($file_path) {
    if (!is_readable($file_path)) return [];
    $content = file_get_contents($file_path);
    return json_decode($content, true) ?? [];
}

$messages = load_json_data($channel0_log_file);
$subscribers = load_json_data($subscribers_file);

echo json_encode([
    'messages' => $messages,
    'subscribers' => $subscribers
]);
exit;
?>
