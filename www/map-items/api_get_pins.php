<?php
// GuardianBridge - api_get_pins.php

header('Content-Type: application/json');
session_start();

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['error' => 'Authentication required.']));
}

$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$map_pins_file = $data_dir . '/map_pins.json';

function get_locked_json_file($file_path, $default_value = []) {
    if (!is_readable($file_path)) { return $default_value; }
    $fp = @fopen($file_path, 'r');
    if (!$fp) { return $default_value; }
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

$pins = get_locked_json_file($map_pins_file, []);

// Return pins as a simple array for easier JS processing
echo json_encode(array_values($pins));
?>