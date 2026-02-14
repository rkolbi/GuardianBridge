<?php

session_start();

$is_map_admin = isset($_SESSION['map_loggedin']) && $_SESSION['map_loggedin'] === true;
$is_mop_operator = isset($_SESSION['mop_loggedin']) && $_SESSION['mop_loggedin'] === true;
if (!$is_map_admin && !$is_mop_operator) {
    header('HTTP/1.1 403 Forbidden');
    header('Content-Type: application/json');
    die(json_encode(['error' => 'Authentication required.']));
}

require_once __DIR__ . '/../db.php';

@ini_set('output_buffering', 'off');
@ini_set('zlib.output_compression', '0');
@ini_set('implicit_flush', '1');
while (ob_get_level() > 0) {
    @ob_end_flush();
}
ob_implicit_flush(true);

ignore_user_abort(true);
set_time_limit(0);

header('Content-Type: text/event-stream');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Connection: keep-alive');
header('X-Accel-Buffering: no');

function gb_emit_sse($event, $payload) {
    echo "event: " . $event . "\n";
    echo "data: " . json_encode($payload) . "\n\n";
    @flush();
}

function gb_temp_group_sig($groups) {
    if (!is_array($groups) || empty($groups)) {
        return '';
    }
    return hash('sha256', json_encode($groups));
}

$after = isset($_GET['after']) ? intval($_GET['after']) : 0;
if ($after < 0) {
    $after = 0;
}
$with_subscribers = isset($_GET['with_subscribers']) ? intval($_GET['with_subscribers']) : 1;
$client_subs_mtime = isset($_GET['subscribers_mtime']) ? intval($_GET['subscribers_mtime']) : 0;
$timeout_ms = isset($_GET['timeout_ms']) ? intval($_GET['timeout_ms']) : 20000;
$poll_ms = isset($_GET['poll_ms']) ? intval($_GET['poll_ms']) : 500;

$timeout_ms = max(3000, min(30000, $timeout_ms));
$poll_ms = max(150, min(2000, $poll_ms));

$started = microtime(true);
$baseline_group_sig = null;
$last_id = $after;
$subs_mtime = gb_get_subscribers_mtime();
$temp_groups = [];

while (true) {
    if (connection_aborted()) {
        exit;
    }

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
    $group_sig = gb_temp_group_sig($temp_groups);
    if ($baseline_group_sig === null) {
        $baseline_group_sig = $group_sig;
    }

    $groups_changed = ($group_sig !== $baseline_group_sig);
    $chat_reset = ($last_id < $after);
    $has_updates = (!empty($messages) || $include_subscribers || $groups_changed || $chat_reset);

    if ($has_updates) {
        gb_emit_sse('chat', [
            'messages' => $messages,
            'total' => $last_id,
            'subscribers' => $subscribers,
            'subscribers_included' => $include_subscribers,
            'subscribers_mtime' => $subs_mtime,
            'temp_groups' => $temp_groups
        ]);
        exit;
    }

    $elapsed_ms = (int)((microtime(true) - $started) * 1000);
    if ($elapsed_ms >= $timeout_ms) {
        break;
    }

    usleep($poll_ms * 1000);
}

gb_emit_sse('heartbeat', [
    'messages' => [],
    'total' => $last_id,
    'subscribers' => [],
    'subscribers_included' => false,
    'subscribers_mtime' => $subs_mtime,
    'temp_groups' => $temp_groups
]);
exit;

?>
