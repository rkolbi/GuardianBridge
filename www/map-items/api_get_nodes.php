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

// GuardianBridge - api_get_nodes.php (v1.3.0)

header('Content-Type: application/json');
session_start();

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['error' => 'Authentication required.']));
}

$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$node_status_file = $data_dir . '/node_status.json';
$subscribers_file = $data_dir . '/subscribers.json';
$sos_log_file = $data_dir . '/sos_log.json';

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
            if (json_last_error() === JSON_ERROR_NONE) {
                $data = $decoded;
            }
        }
    }
    fclose($fp);
    return $data;
}

$node_statuses = get_locked_json_file($node_status_file, []);
$subscribers = get_locked_json_file($subscribers_file, []);
$sos_log = get_locked_json_file($sos_log_file, []);

$active_sos_events = [];
if (is_array($sos_log)) {
    foreach ($sos_log as $entry) {
        if (!empty($entry['active'])) {
            $active_sos_events[] = $entry;
        }
    }
}

$output_nodes = [];
if (is_array($node_statuses)) {
    foreach ($node_statuses as $node_id => $status) {
        $user_data = $subscribers[$node_id] ?? [];
        
        $sos_role = 'NONE';
        $sos_parent = null;
        $sos_message_payload = '';

        foreach ($active_sos_events as $sos) {
            if ($node_id === ($sos['node_id'] ?? null)) {
                $sos_role = 'SENDER';
                $sos_message_payload = $sos['message_payload'] ?? '';
                break;
            }
            if (in_array($node_id, $sos['responding_list'] ?? [])) {
                $sos_role = 'RESPONDER';
                $sos_parent = $sos['node_id'];
                break;
            }
            if (in_array($node_id, $sos['acknowledged_by'] ?? [])) {
                $sos_role = 'ACKNOWLEDGER';
                $sos_parent = $sos['node_id'];
                break;
            }
        }

        $node_info = [
            'node_id' => $node_id,
            'name' => $user_data['name'] ?? null,
            'full_name' => $user_data['full_name'] ?? null,
            'lastHeard' => $status['lastHeard'] ?? null,
            'snr' => $status['snr'] ?? null,
            'hopsAway' => $status['hopsAway'] ?? null,
            'role' => $status['role'] ?? 'UNKNOWN',
            'latitude' => $status['latitude'] ?? null,
            'longitude' => $status['longitude'] ?? null,
            'sos' => $status['sos'] ?? null,
            'address' => $user_data['address'] ?? null,
            'phone_1' => $user_data['phone_1'] ?? null,
            'phone_2' => $user_data['phone_2'] ?? null,
            'email' => $user_data['email'] ?? null,
            'notes' => $user_data['notes'] ?? null,
            'poc_info' => $user_data['poc_info'] ?? null,
            'sos_notify' => $user_data['sos_notify'] ?? null,
            'sos_role' => $sos_role,
            'sos_parent' => $sos_parent,
            'sos_message_payload' => $sos_message_payload
        ];
        $output_nodes[] = $node_info;
    }
}

echo json_encode($output_nodes);
?>
