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
require_once __DIR__ . '/../db.php';
session_start();
$gb_perf_start = microtime(true);
register_shutdown_function(function () use ($gb_perf_start) {
    $elapsed_ms = (microtime(true) - $gb_perf_start) * 1000;
    if ($elapsed_ms >= 750) {
        error_log(sprintf('GuardianBridge Perf: api_get_nodes %.1fms', $elapsed_ms));
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

$cache_file = '/opt/GuardianBridge/data/api_nodes_cache.json';
$cache_ttl_seconds = 5;
$if_none_match = trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''));

function gb_nodes_api_read_cache($path, $ttl_seconds) {
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

function gb_nodes_api_write_cache($path, $etag, $payload_json) {
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

function gb_nodes_api_etag_matches($if_none_match, $etag) {
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

$cached = gb_nodes_api_read_cache($cache_file, $cache_ttl_seconds);
if (is_array($cached)) {
    header('ETag: ' . $cached['etag']);
    if (gb_nodes_api_etag_matches($if_none_match, $cached['etag'])) {
        http_response_code(304);
        exit;
    }
    echo $cached['payload_json'];
    exit;
}

$node_statuses = gb_load_node_statuses();
$active_sos_raw = gb_load_active_sos_logs();
$subscribers_mtime = gb_get_subscribers_mtime();

$required_subscriber_ids = [];
if (is_array($node_statuses)) {
    foreach ($node_statuses as $node_id => $_status_row) {
        $id = trim((string)$node_id);
        if ($id !== '') {
            $required_subscriber_ids[$id] = true;
        }
    }
}

$active_sos_events = [];
if (is_array($active_sos_raw)) {
    foreach ($active_sos_raw as $entry) {
        if (empty($entry['active'])) {
            continue;
        }
        $sos_node_id = trim((string)($entry['node_id'] ?? ''));
        $responding_list = [];
        foreach ((array)($entry['responding_list'] ?? []) as $responder_id) {
            $responder_key = trim((string)$responder_id);
            if ($responder_key === '') {
                continue;
            }
            $responding_list[] = $responder_key;
            $required_subscriber_ids[$responder_key] = true;
        }
        $acknowledged_by = [];
        foreach ((array)($entry['acknowledged_by'] ?? []) as $ack_id) {
            $ack_key = trim((string)$ack_id);
            if ($ack_key === '') {
                continue;
            }
            $acknowledged_by[] = $ack_key;
            $required_subscriber_ids[$ack_key] = true;
        }
        if ($sos_node_id !== '') {
            $required_subscriber_ids[$sos_node_id] = true;
        }
        $entry['node_id'] = $sos_node_id;
        $entry['responding_list'] = $responding_list;
        $entry['acknowledged_by'] = $acknowledged_by;
        $entry['responding_set'] = array_fill_keys($responding_list, true);
        $entry['acknowledged_set'] = array_fill_keys($acknowledged_by, true);
        $active_sos_events[] = $entry;
    }
}

$subscribers = gb_load_subscribers_by_ids(array_keys($required_subscriber_ids));

$output_nodes = [];
$seen_node_ids = [];
if (is_array($node_statuses)) {
    foreach ($node_statuses as $node_id => $status) {
        $user_data = $subscribers[$node_id] ?? [];
        
        $sos_role = 'NONE';
        $sos_parent = null;
        $sos_message_payload = '';
        $sos_from_log = null;
        $sos_timestamp = null;

        foreach ($active_sos_events as $sos) {
            if ($node_id === ($sos['node_id'] ?? null)) {
                $sos_role = 'SENDER';
                $sos_message_payload = $sos['message_payload'] ?? '';
                $sos_from_log = $sos['sos_type'] ?? null;
                $sos_timestamp = $sos['timestamp'] ?? null;
                break;
            }
            if (!empty($sos['responding_set'][$node_id])) {
                $sos_role = 'RESPONDER';
                $sos_parent = $sos['node_id'];
                break;
            }
            if (!empty($sos['acknowledged_set'][$node_id])) {
                $sos_role = 'ACKNOWLEDGER';
                $sos_parent = $sos['node_id'];
                break;
            }
        }

        $address = $user_data['address'] ?? null;
        if (is_string($address)) {
            $address = ['street' => $address, 'city' => '', 'state' => '', 'zip' => ''];
        }

        $sos_code = $status['sos'] ?? null;
        if (!$sos_code && $sos_role === 'SENDER') {
            $sos_code = $sos_from_log;
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
            'sos' => $sos_code,
            'sos_timestamp' => $sos_timestamp,
            'address' => $address,
            'address_lat' => $user_data['address_lat'] ?? null,
            'address_lon' => $user_data['address_lon'] ?? null,
            'use_address_coords' => !empty($user_data['use_address_coords']),
            'phone_1' => $user_data['phone_1'] ?? null,
            'phone_2' => $user_data['phone_2'] ?? null,
            'email' => $user_data['email'] ?? null,
            'notes' => $user_data['notes'] ?? null,
            'ops_notes' => $user_data['ops_notes'] ?? null,
            'poc_info' => $user_data['poc_info'] ?? null,
            'sos_notify' => $user_data['sos_notify'] ?? null,
            'sos_role' => $sos_role,
            'sos_parent' => $sos_parent,
            'sos_message_payload' => $sos_message_payload
        ];
        $output_nodes[] = $node_info;
        $seen_node_ids[$node_id] = true;
    }
}

// Ensure active SOS senders (and any missing participants) appear even if they have no node status row yet.
if (is_array($active_sos_events)) {
    foreach ($active_sos_events as $sos) {
        $sos_node_id = $sos['node_id'] ?? null;
        if ($sos_node_id && empty($seen_node_ids[$sos_node_id])) {
            $user_data = $subscribers[$sos_node_id] ?? [];
            $address = $user_data['address'] ?? null;
            if (is_string($address)) {
                $address = ['street' => $address, 'city' => '', 'state' => '', 'zip' => ''];
            }

            $last_heard = null;
            if (!empty($sos['timestamp'])) {
                $ts = strtotime($sos['timestamp']);
                if ($ts !== false) {
                    $last_heard = $ts;
                }
            }

            $output_nodes[] = [
                'node_id' => $sos_node_id,
                'name' => $user_data['name'] ?? null,
                'full_name' => $user_data['full_name'] ?? null,
                'lastHeard' => $last_heard,
                'snr' => null,
                'hopsAway' => null,
                'role' => 'UNKNOWN',
                'latitude' => $sos['latitude'] ?? null,
                'longitude' => $sos['longitude'] ?? null,
                'sos' => $sos['sos_type'] ?? 'SOS',
                'sos_timestamp' => $sos['timestamp'] ?? null,
                'address' => $address,
                'address_lat' => $user_data['address_lat'] ?? null,
                'address_lon' => $user_data['address_lon'] ?? null,
                'use_address_coords' => !empty($user_data['use_address_coords']),
                'phone_1' => $user_data['phone_1'] ?? null,
                'phone_2' => $user_data['phone_2'] ?? null,
                'email' => $user_data['email'] ?? null,
                'notes' => $user_data['notes'] ?? null,
                'ops_notes' => $user_data['ops_notes'] ?? null,
                'poc_info' => $user_data['poc_info'] ?? null,
                'sos_notify' => $user_data['sos_notify'] ?? null,
                'sos_role' => 'SENDER',
                'sos_parent' => null,
                'sos_message_payload' => $sos['message_payload'] ?? ''
            ];
            $seen_node_ids[$sos_node_id] = true;
        }

        foreach (($sos['responding_list'] ?? []) as $responder_id) {
            if (!$responder_id || !empty($seen_node_ids[$responder_id])) {
                continue;
            }
            $user_data = $subscribers[$responder_id] ?? [];
            $address = $user_data['address'] ?? null;
            if (is_string($address)) {
                $address = ['street' => $address, 'city' => '', 'state' => '', 'zip' => ''];
            }
            $output_nodes[] = [
                'node_id' => $responder_id,
                'name' => $user_data['name'] ?? null,
                'full_name' => $user_data['full_name'] ?? null,
                'lastHeard' => null,
                'snr' => null,
                'hopsAway' => null,
                'role' => 'UNKNOWN',
                'latitude' => null,
                'longitude' => null,
                'sos' => null,
                'sos_timestamp' => null,
                'address' => $address,
                'address_lat' => $user_data['address_lat'] ?? null,
                'address_lon' => $user_data['address_lon'] ?? null,
                'use_address_coords' => !empty($user_data['use_address_coords']),
                'phone_1' => $user_data['phone_1'] ?? null,
                'phone_2' => $user_data['phone_2'] ?? null,
                'email' => $user_data['email'] ?? null,
                'notes' => $user_data['notes'] ?? null,
                'ops_notes' => $user_data['ops_notes'] ?? null,
                'poc_info' => $user_data['poc_info'] ?? null,
                'sos_notify' => $user_data['sos_notify'] ?? null,
                'sos_role' => 'RESPONDER',
                'sos_parent' => $sos_node_id,
                'sos_message_payload' => ''
            ];
            $seen_node_ids[$responder_id] = true;
        }

        foreach (($sos['acknowledged_by'] ?? []) as $ack_id) {
            if (!$ack_id || !empty($seen_node_ids[$ack_id])) {
                continue;
            }
            $user_data = $subscribers[$ack_id] ?? [];
            $address = $user_data['address'] ?? null;
            if (is_string($address)) {
                $address = ['street' => $address, 'city' => '', 'state' => '', 'zip' => ''];
            }
            $output_nodes[] = [
                'node_id' => $ack_id,
                'name' => $user_data['name'] ?? null,
                'full_name' => $user_data['full_name'] ?? null,
                'lastHeard' => null,
                'snr' => null,
                'hopsAway' => null,
                'role' => 'UNKNOWN',
                'latitude' => null,
                'longitude' => null,
                'sos' => null,
                'sos_timestamp' => null,
                'address' => $address,
                'address_lat' => $user_data['address_lat'] ?? null,
                'address_lon' => $user_data['address_lon'] ?? null,
                'use_address_coords' => !empty($user_data['use_address_coords']),
                'phone_1' => $user_data['phone_1'] ?? null,
                'phone_2' => $user_data['phone_2'] ?? null,
                'email' => $user_data['email'] ?? null,
                'notes' => $user_data['notes'] ?? null,
                'ops_notes' => $user_data['ops_notes'] ?? null,
                'poc_info' => $user_data['poc_info'] ?? null,
                'sos_notify' => $user_data['sos_notify'] ?? null,
                'sos_role' => 'ACKNOWLEDGER',
                'sos_parent' => $sos_node_id,
                'sos_message_payload' => ''
            ];
            $seen_node_ids[$ack_id] = true;
        }
    }
}

$_response_payload = [
    'nodes' => $output_nodes,
    'subscribers_mtime' => $subscribers_mtime
];

$response_json = json_encode($_response_payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
if (!is_string($response_json)) {
    $response_json = json_encode(['nodes' => [], 'subscribers_mtime' => 0]);
}
$etag = '"' . sha1($response_json) . '"';
header('ETag: ' . $etag);
if (gb_nodes_api_etag_matches($if_none_match, $etag)) {
    http_response_code(304);
    exit;
}
gb_nodes_api_write_cache($cache_file, $etag, $response_json);
echo $response_json;
?>
