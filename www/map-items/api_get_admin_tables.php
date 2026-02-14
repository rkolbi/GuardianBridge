<?php
// GuardianBridge - api_get_admin_tables.php

header('Content-Type: application/json');
require_once __DIR__ . '/../db.php';
session_start();
$gb_perf_start = microtime(true);
register_shutdown_function(function () use ($gb_perf_start) {
    $elapsed_ms = (microtime(true) - $gb_perf_start) * 1000;
    if ($elapsed_ms >= 750) {
        error_log(sprintf('GuardianBridge Perf: api_get_admin_tables %.1fms', $elapsed_ms));
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

function gb_admin_tables_etag_matches($if_none_match, $etag) {
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

$scope_raw = trim((string)($_GET['scope'] ?? 'all'));
$scope_parts = array_filter(array_map('trim', explode(',', strtolower($scope_raw))));
$want_users = false;
$want_broadcasts = false;
if (empty($scope_parts) || in_array('all', $scope_parts, true)) {
    $want_users = true;
    $want_broadcasts = true;
} else {
    $want_users = in_array('users', $scope_parts, true);
    $want_broadcasts = in_array('broadcasts', $scope_parts, true);
}

$etag_basis = ['v1'];
if ($want_users) {
    $etag_basis[] = 'u:' . gb_get_subscribers_mtime() . ':' . gb_get_node_status_mtime();
}
if ($want_broadcasts) {
    $etag_basis[] = 'b:' . gb_get_dispatcher_jobs_mtime();
}
$etag = '"' . sha1(implode('|', $etag_basis)) . '"';
header('ETag: ' . $etag);
$if_none_match = trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''));
if (gb_admin_tables_etag_matches($if_none_match, $etag)) {
    http_response_code(304);
    exit;
}

$response = [
    'users' => null,
    'broadcasts' => null,
];

if ($want_users) {
    $subscribers = gb_load_subscribers();
    ksort($subscribers);
    $node_statuses = gb_load_node_statuses();
    $rows = [];
    $users = [];

    foreach ($subscribers as $node_id => $user_data) {
        if (!is_array($user_data)) {
            $user_data = [];
        }
        if (isset($user_data['password_hash'])) {
            unset($user_data['password_hash']);
        }
        $reported_role = 'Unknown';
        $reported_data = $node_statuses[$node_id] ?? null;
        if (is_array($reported_data) && isset($reported_data['role']) && $reported_data['role'] !== '') {
            $reported_role = (string)$reported_data['role'];
        }
        $assigned_role = (string)($user_data['role'] ?? '');
        $tags = [];
        if (is_array($user_data['tags'] ?? null)) {
            foreach ($user_data['tags'] as $tag) {
                $value = trim((string)$tag);
                if ($value !== '') {
                    $tags[] = strtoupper($value);
                }
            }
        }
        $users[$node_id] = array_merge($user_data, ['node_id' => $node_id]);
        $rows[] = [
            'node_id' => $node_id,
            'name' => (string)($user_data['name'] ?? ''),
            'full_name' => (string)($user_data['full_name'] ?? ''),
            'phone_1' => (string)($user_data['phone_1'] ?? ''),
            'tags' => $tags,
            'assigned_role' => $assigned_role,
            'reported_role' => $reported_role,
            'reported_role_matches' => ($reported_role !== 'Unknown' && strtoupper($assigned_role) === strtoupper($reported_role)),
        ];
    }

    $response['users'] = [
        'total' => count($rows),
        'rows' => $rows,
        'directory' => $users,
    ];
}

if ($want_broadcasts) {
    $jobs = gb_load_dispatcher_jobs();
    if (!is_array($jobs)) {
        $jobs = [];
    }
    $normalized_jobs = [];
    foreach ($jobs as $index => $job) {
        if (!is_array($job)) {
            $job = [];
        }
        $job['job_index'] = intval($index);
        $normalized_jobs[] = $job;
    }
    $response['broadcasts'] = [
        'total' => count($normalized_jobs),
        'jobs' => $normalized_jobs,
    ];
}

echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
exit;
?>
