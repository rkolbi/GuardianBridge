<?php

session_start();

$is_map_admin = isset($_SESSION['map_loggedin']) && $_SESSION['map_loggedin'] === true;
$is_mop_operator = isset($_SESSION['mop_loggedin']) && $_SESSION['mop_loggedin'] === true;
if (!$is_map_admin && !$is_mop_operator) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['error' => 'Authentication required.']));
}

header('Content-Type: application/json');
require_once __DIR__ . '/../db.php';
header('Cache-Control: private, no-cache, must-revalidate');
header('Vary: Cookie');
$if_none_match = trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''));

function gb_chat_api_etag_matches($if_none_match, $etag) {
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

$after = isset($_GET['after']) ? intval($_GET['after']) : 0;
$with_subscribers = isset($_GET['with_subscribers']) ? intval($_GET['with_subscribers']) : 1;
$client_subs_mtime = isset($_GET['subscribers_mtime']) ? intval($_GET['subscribers_mtime']) : 0;

$result = gb_load_chat_logs($after, 200);
$messages = $result[0];
$last_id = $result[1];

$subscribers = [];
$subs_mtime = gb_get_subscribers_mtime();
$include_subscribers = ($with_subscribers === 1) && ($client_subs_mtime !== $subs_mtime);
if ($include_subscribers) {
    $subscribers = gb_load_subscribers();
    foreach ($subscribers as $node_id => $user_data) {
        if (isset($subscribers[$node_id]['password_hash'])) {
            unset($subscribers[$node_id]['password_hash']);
        }
    }
}
$temp_groups = gb_load_temp_groups();

$_response_payload = [
    'messages' => $messages,
    'total' => $last_id,
    'subscribers' => $subscribers,
    'subscribers_included' => $include_subscribers,
    'subscribers_mtime' => $subs_mtime,
    'temp_groups' => $temp_groups
];
$response_json = json_encode($_response_payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
if (!is_string($response_json)) {
    $response_json = json_encode([
        'messages' => [],
        'total' => 0,
        'subscribers' => [],
        'subscribers_included' => false,
        'subscribers_mtime' => 0,
        'temp_groups' => []
    ]);
}
$etag = '"' . sha1($response_json) . '"';
header('ETag: ' . $etag);
if (gb_chat_api_etag_matches($if_none_match, $etag)) {
    http_response_code(304);
    exit;
}
echo $response_json;
exit;
?>
