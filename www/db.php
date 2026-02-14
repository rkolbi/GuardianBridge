<?php
// Shared SQLite helpers for GuardianBridge

function gb_db_path() {
    return '/opt/GuardianBridge/data/guardianbridge.db';
}

function gb_db() {
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $pdo = new PDO('sqlite:' . gb_db_path());
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_TIMEOUT, 5);
    $pdo->exec('PRAGMA journal_mode=WAL;');
    $pdo->exec('PRAGMA busy_timeout=5000;');
    $pdo->exec('PRAGMA foreign_keys=ON;');
    gb_init_db($pdo);
    return $pdo;
}

function gb_init_db(PDO $pdo) {
    $pdo->exec('CREATE TABLE IF NOT EXISTS subscribers (node_id TEXT PRIMARY KEY, data_json TEXT NOT NULL, updated_at INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS node_status (node_id TEXT PRIMARY KEY, data_json TEXT NOT NULL, updated_at INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS chat_log (id INTEGER PRIMARY KEY AUTOINCREMENT, data_json TEXT NOT NULL, created_at INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS sos_log (id INTEGER PRIMARY KEY AUTOINCREMENT, data_json TEXT NOT NULL, created_at INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_sos_log_active ON sos_log(active)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS dispatcher_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, position INTEGER NOT NULL, data_json TEXT NOT NULL, updated_at INTEGER NOT NULL)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_dispatcher_jobs_position ON dispatcher_jobs(position)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS outgoing_emails (id INTEGER PRIMARY KEY AUTOINCREMENT, data_json TEXT NOT NULL, created_at INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS outgoing_emails_quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT, data_json TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS failed_dm_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, data_json TEXT NOT NULL, created_at INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS temp_groups (group_name TEXT PRIMARY KEY, members_json TEXT NOT NULL, created_at INTEGER NOT NULL, last_activity INTEGER NOT NULL, locked INTEGER NOT NULL DEFAULT 0)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_temp_groups_last_activity ON temp_groups(last_activity)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS command_receipts (command_id TEXT PRIMARY KEY, source_file TEXT NOT NULL, status TEXT NOT NULL, details_json TEXT NOT NULL, processed_at INTEGER NOT NULL)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_command_receipts_processed_at ON command_receipts(processed_at)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS command_dead_letters (id INTEGER PRIMARY KEY AUTOINCREMENT, command_id TEXT NOT NULL, source_file TEXT NOT NULL, reason TEXT NOT NULL, details_json TEXT NOT NULL, created_at INTEGER NOT NULL)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_command_dead_letters_created_at ON command_dead_letters(created_at)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS command_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, command_id TEXT NOT NULL UNIQUE, source_file TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 5, available_at INTEGER NOT NULL, lease_until INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT \'\', details_json TEXT NOT NULL DEFAULT \'{}\', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, completed_at INTEGER NOT NULL DEFAULT 0)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_command_jobs_status_available ON command_jobs(status, available_at, id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_command_jobs_lease_until ON command_jobs(lease_until)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_command_jobs_updated_at ON command_jobs(updated_at)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, actor TEXT NOT NULL, panel TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL DEFAULT \'\', details_json TEXT NOT NULL DEFAULT \'{}\')');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_log_panel_actor_id ON audit_log(panel, actor, id DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_log_panel_id ON audit_log(panel, id DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id ON audit_log(actor, id DESC)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS login_failures (id INTEGER PRIMARY KEY AUTOINCREMENT, panel TEXT NOT NULL, principal TEXT NOT NULL, remote_addr TEXT NOT NULL, created_at INTEGER NOT NULL)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_login_failures_lookup ON login_failures(panel, principal, remote_addr, created_at)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_login_failures_created_at ON login_failures(created_at)');
    $cols = $pdo->query('PRAGMA table_info(temp_groups)')->fetchAll(PDO::FETCH_ASSOC);
    $col_names = [];
    foreach ($cols as $col) {
        if (isset($col['name'])) {
            $col_names[$col['name']] = true;
        }
    }
    if (!isset($col_names['locked'])) {
        $pdo->exec('ALTER TABLE temp_groups ADD COLUMN locked INTEGER NOT NULL DEFAULT 0');
    }
}

function gb_load_subscribers() {
    $pdo = gb_db();
    $rows = $pdo->query('SELECT node_id, data_json FROM subscribers')->fetchAll(PDO::FETCH_ASSOC);
    $data = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        $data[$row['node_id']] = is_array($decoded) ? $decoded : [];
    }
    return $data;
}

function gb_load_subscribers_by_ids(array $node_ids) {
    $pdo = gb_db();
    $normalized = [];
    foreach ($node_ids as $node_id) {
        $key = trim((string)$node_id);
        if ($key !== '') {
            $normalized[$key] = true;
        }
    }
    $ids = array_keys($normalized);
    if (empty($ids)) {
        return [];
    }

    $data = [];
    $chunk_size = 500;
    for ($offset = 0; $offset < count($ids); $offset += $chunk_size) {
        $chunk = array_slice($ids, $offset, $chunk_size);
        if (empty($chunk)) {
            continue;
        }
        $placeholders = implode(',', array_fill(0, count($chunk), '?'));
        $stmt = $pdo->prepare('SELECT node_id, data_json FROM subscribers WHERE node_id IN (' . $placeholders . ')');
        $stmt->execute($chunk);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $row) {
            $decoded = json_decode($row['data_json'], true);
            $data[$row['node_id']] = is_array($decoded) ? $decoded : [];
        }
    }
    return $data;
}

function gb_replace_subscribers(array $subs) {
    $pdo = gb_db();
    $pdo->beginTransaction();
    $pdo->exec('DELETE FROM subscribers');
    $stmt = $pdo->prepare('INSERT OR REPLACE INTO subscribers (node_id, data_json, updated_at) VALUES (?, ?, ?)');
    $now = time();
    foreach ($subs as $node_id => $data) {
        $stmt->execute([$node_id, json_encode($data), $now]);
    }
    $pdo->commit();
}

function gb_delete_subscriber($node_id) {
    $pdo = gb_db();
    $stmt = $pdo->prepare('DELETE FROM subscribers WHERE node_id = ?');
    $stmt->execute([$node_id]);
}

function gb_get_subscribers_mtime() {
    $pdo = gb_db();
    $row = $pdo->query('SELECT MAX(updated_at) AS mtime FROM subscribers')->fetch(PDO::FETCH_ASSOC);
    return intval($row['mtime'] ?? 0);
}

function gb_get_node_status_mtime() {
    $pdo = gb_db();
    $row = $pdo->query('SELECT MAX(updated_at) AS mtime FROM node_status')->fetch(PDO::FETCH_ASSOC);
    return intval($row['mtime'] ?? 0);
}

function gb_load_node_statuses() {
    $pdo = gb_db();
    $rows = $pdo->query('SELECT node_id, data_json FROM node_status')->fetchAll(PDO::FETCH_ASSOC);
    $data = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        $data[$row['node_id']] = is_array($decoded) ? $decoded : [];
    }
    return $data;
}

function gb_load_chat_logs($after_id = 0, $limit = 200) {
    $pdo = gb_db();
    $last_row = $pdo->query('SELECT MAX(id) AS max_id FROM chat_log')->fetch(PDO::FETCH_ASSOC);
    $last_id = intval($last_row['max_id'] ?? 0);

    if ($after_id > 0) {
        if ($last_id <= $after_id) {
            return [[], $last_id];
        }
        $stmt = $pdo->prepare('SELECT id, data_json FROM chat_log WHERE id > ? ORDER BY id ASC');
        $stmt->execute([$after_id]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $stmt = $pdo->prepare('SELECT id, data_json FROM chat_log ORDER BY id DESC LIMIT ?');
        $stmt->execute([$limit]);
        $rows = array_reverse($stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    $messages = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        if (!is_array($decoded)) { $decoded = []; }
        $decoded['id'] = intval($row['id']);
        $messages[] = $decoded;
    }
    return [$messages, $last_id];
}

function gb_clear_chat_log() {
    $pdo = gb_db();
    $pdo->exec('DELETE FROM chat_log');
}

function gb_load_sos_logs($active_only = false) {
    $pdo = gb_db();
    if ($active_only) {
        $stmt = $pdo->prepare('SELECT id, data_json, active FROM sos_log WHERE active = 1 ORDER BY id ASC');
        $stmt->execute();
    } else {
        $stmt = $pdo->prepare('SELECT id, data_json, active FROM sos_log ORDER BY id ASC');
        $stmt->execute();
    }
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $entries = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        if (!is_array($decoded)) { $decoded = []; }
        $decoded['id'] = intval($row['id']);
        $decoded['active'] = !empty($row['active']);
        $entries[] = $decoded;
    }
    return $entries;
}

function gb_load_recent_sos_logs($limit = 10) {
    $pdo = gb_db();
    $limit_int = max(1, min(5000, intval($limit)));
    $stmt = $pdo->prepare('SELECT id, data_json, active FROM sos_log ORDER BY id DESC LIMIT ?');
    $stmt->bindValue(1, $limit_int, PDO::PARAM_INT);
    $stmt->execute();
    $rows = array_reverse($stmt->fetchAll(PDO::FETCH_ASSOC));
    $entries = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        if (!is_array($decoded)) { $decoded = []; }
        $decoded['id'] = intval($row['id']);
        $decoded['active'] = !empty($row['active']);
        $entries[] = $decoded;
    }
    return $entries;
}

function gb_load_active_sos_logs() {
    $pdo = gb_db();
    $stmt = $pdo->prepare('SELECT id, data_json, active FROM sos_log WHERE active = 1 ORDER BY id DESC');
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $entries = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        if (!is_array($decoded)) { $decoded = []; }
        $decoded['id'] = intval($row['id']);
        $decoded['active'] = true;
        $entries[] = $decoded;
    }
    return $entries;
}

function gb_clear_sos_logs() {
    $pdo = gb_db();
    $pdo->exec('DELETE FROM sos_log');
}

function gb_load_dispatcher_jobs() {
    $pdo = gb_db();
    $stmt = $pdo->query('SELECT position, data_json FROM dispatcher_jobs ORDER BY position ASC');
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $jobs = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        $jobs[] = is_array($decoded) ? $decoded : [];
    }
    return $jobs;
}

function gb_get_dispatcher_jobs_mtime() {
    $pdo = gb_db();
    $row = $pdo->query('SELECT MAX(updated_at) AS mtime FROM dispatcher_jobs')->fetch(PDO::FETCH_ASSOC);
    return intval($row['mtime'] ?? 0);
}

function gb_replace_dispatcher_jobs(array $jobs) {
    $pdo = gb_db();
    $pdo->beginTransaction();
    $pdo->exec('DELETE FROM dispatcher_jobs');
    $stmt = $pdo->prepare('INSERT INTO dispatcher_jobs (position, data_json, updated_at) VALUES (?, ?, ?)');
    $now = time();
    foreach ($jobs as $position => $job) {
        $stmt->execute([intval($position), json_encode($job), $now]);
    }
    $pdo->commit();
}

function gb_load_outgoing_emails($limit = null) {
    $pdo = gb_db();
    $rows = [];
    if ($limit === null) {
        $stmt = $pdo->query('SELECT id, data_json FROM outgoing_emails ORDER BY id ASC');
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $limit_int = max(1, min(5000, intval($limit)));
        $stmt = $pdo->prepare('SELECT id, data_json FROM outgoing_emails ORDER BY id DESC LIMIT ?');
        $stmt->bindValue(1, $limit_int, PDO::PARAM_INT);
        $stmt->execute();
        $rows = array_reverse($stmt->fetchAll(PDO::FETCH_ASSOC));
    }
    $messages = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        if (!is_array($decoded)) { $decoded = []; }
        $decoded['id'] = intval($row['id']);
        $messages[] = $decoded;
    }
    return $messages;
}

function gb_clear_outgoing_emails() {
    $pdo = gb_db();
    $pdo->exec('DELETE FROM outgoing_emails');
}

function gb_load_failed_dm_queue($limit = null) {
    $pdo = gb_db();
    $rows = [];
    if ($limit === null) {
        $stmt = $pdo->query('SELECT id, data_json FROM failed_dm_queue ORDER BY id ASC');
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $limit_int = max(1, min(5000, intval($limit)));
        $stmt = $pdo->prepare('SELECT id, data_json FROM failed_dm_queue ORDER BY id DESC LIMIT ?');
        $stmt->bindValue(1, $limit_int, PDO::PARAM_INT);
        $stmt->execute();
        $rows = array_reverse($stmt->fetchAll(PDO::FETCH_ASSOC));
    }
    $messages = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        if (!is_array($decoded)) { $decoded = []; }
        $decoded['id'] = intval($row['id']);
        $messages[] = $decoded;
    }
    return $messages;
}

function gb_load_command_dead_letters($limit = 100) {
    $pdo = gb_db();
    $limit = max(1, min(5000, intval($limit)));
    $stmt = $pdo->prepare('SELECT id, command_id, source_file, reason, details_json, created_at FROM command_dead_letters ORDER BY id DESC LIMIT ?');
    $stmt->bindValue(1, $limit, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $entries = [];
    foreach ($rows as $row) {
        $details = json_decode((string)($row['details_json'] ?? '{}'), true);
        if (!is_array($details)) {
            $details = [];
        }
        $entries[] = [
            'id' => intval($row['id'] ?? 0),
            'command_id' => (string)($row['command_id'] ?? ''),
            'source_file' => (string)($row['source_file'] ?? ''),
            'reason' => (string)($row['reason'] ?? ''),
            'details' => $details,
            'created_at' => intval($row['created_at'] ?? 0),
        ];
    }
    return $entries;
}

function gb_get_command_dead_letter($id) {
    $pdo = gb_db();
    $id_int = intval($id);
    if ($id_int <= 0) {
        return null;
    }
    $stmt = $pdo->prepare('SELECT id, command_id, source_file, reason, details_json, created_at FROM command_dead_letters WHERE id = ? LIMIT 1');
    $stmt->execute([$id_int]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        return null;
    }
    $details = json_decode((string)($row['details_json'] ?? '{}'), true);
    if (!is_array($details)) {
        $details = [];
    }
    return [
        'id' => intval($row['id'] ?? 0),
        'command_id' => (string)($row['command_id'] ?? ''),
        'source_file' => (string)($row['source_file'] ?? ''),
        'reason' => (string)($row['reason'] ?? ''),
        'details' => $details,
        'created_at' => intval($row['created_at'] ?? 0),
    ];
}

function gb_count_command_dead_letters() {
    $pdo = gb_db();
    $row = $pdo->query('SELECT COUNT(1) AS cnt FROM command_dead_letters')->fetch(PDO::FETCH_ASSOC);
    return intval($row['cnt'] ?? 0);
}

function gb_delete_command_dead_letter($id) {
    $pdo = gb_db();
    $id_int = intval($id);
    if ($id_int <= 0) {
        return false;
    }
    $stmt = $pdo->prepare('DELETE FROM command_dead_letters WHERE id = ?');
    $stmt->execute([$id_int]);
    return $stmt->rowCount() > 0;
}

function gb_clear_command_dead_letters() {
    $pdo = gb_db();
    $pdo->exec('DELETE FROM command_dead_letters');
}

function gb_random_hex($bytes = 3) {
    $len = max(1, intval($bytes));
    try {
        return bin2hex(random_bytes($len));
    } catch (Throwable $e) {
        return substr(sha1(uniqid('', true) . microtime(true)), 0, $len * 2);
    }
}

function gb_enqueue_command_job(array $command_data, $source_file = 'webui', $command_id = '', $max_attempts = 5, &$result = null) {
    $pdo = gb_db();
    $payload = $command_data;
    $existing_id = trim((string)$command_id);
    if ($existing_id === '') {
        $existing_id = trim((string)($payload['command_id'] ?? ''));
    }
    if ($existing_id === '') {
        try {
            $existing_id = 'webui-' . gmdate('YmdHis') . '-' . bin2hex(random_bytes(6));
        } catch (Throwable $e) {
            $existing_id = 'webui-' . gmdate('YmdHis') . '-' . gb_random_hex(6);
        }
    }
    $payload['command_id'] = $existing_id;

    $source = trim((string)$source_file);
    if ($source === '') {
        $source = 'webui';
    }
    $attempts = max(1, intval($max_attempts));
    $now = time();

    try {
        $stmt = $pdo->prepare(
            'INSERT OR IGNORE INTO command_jobs (command_id, source_file, payload_json, status, attempt_count, max_attempts, available_at, lease_until, last_error, details_json, created_at, updated_at, completed_at) VALUES (?, ?, ?, \'queued\', 0, ?, ?, 0, \'\', \'{}\', ?, ?, 0)'
        );
        $stmt->execute([
            $existing_id,
            $source,
            json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            $attempts,
            $now,
            $now,
            $now,
        ]);

        $inserted = ($stmt->rowCount() > 0);
        $job_id = 0;
        $status = '';
        if ($inserted) {
            $job_id = intval($pdo->lastInsertId());
            $status = 'queued';
        } else {
            $row = $pdo->prepare('SELECT id, status FROM command_jobs WHERE command_id = ? LIMIT 1');
            $row->execute([$existing_id]);
            $match = $row->fetch(PDO::FETCH_ASSOC);
            if ($match) {
                $job_id = intval($match['id'] ?? 0);
                $status = trim((string)($match['status'] ?? ''));
            }
        }

        $result = [
            'command_id' => $existing_id,
            'job_id' => $job_id,
            'status' => $status,
            'duplicate' => !$inserted,
        ];
        return true;
    } catch (Throwable $e) {
        error_log('GuardianBridge Error: gb_enqueue_command_job failed: ' . $e->getMessage());
        $result = ['error' => $e->getMessage()];
        return false;
    }
}

function gb_requeue_command_dead_letter($id, &$result = null) {
    $dead_letter = gb_get_command_dead_letter($id);
    if (!$dead_letter) {
        $result = ['error' => 'Dead-letter row not found.'];
        return false;
    }

    $payload = null;
    $details = is_array($dead_letter['details'] ?? null) ? $dead_letter['details'] : [];
    $payload = $details['payload'] ?? null;

    if (!is_array($payload)) {
        $result = ['error' => 'Unable to requeue: no valid command payload found in dead-letter record.'];
        return false;
    }

    $queue_result = null;
    $new_command_id = 'requeue:' . intval($dead_letter['id']) . ':' . time() . ':' . gb_random_hex(3);
    if (!gb_enqueue_command_job($payload, 'deadletter:' . intval($dead_letter['id']), $new_command_id, 5, $queue_result)) {
        $result = ['error' => 'Failed to enqueue dead-letter payload.'];
        return false;
    }

    gb_delete_command_dead_letter(intval($dead_letter['id']));

    $result = [
        'queued_file' => 'db_job_' . intval($queue_result['job_id'] ?? 0),
        'source_file' => $dead_letter['source_file'],
        'command_id' => (string)($queue_result['command_id'] ?? $new_command_id),
    ];
    return true;
}

function gb_delete_command_dead_letter_with_file($id, &$result = null) {
    $dead_letter = gb_get_command_dead_letter($id);
    if (!$dead_letter) {
        $result = ['error' => 'Dead-letter row not found.'];
        return false;
    }

    gb_delete_command_dead_letter(intval($dead_letter['id']));

    $result = [
        'source_file' => $dead_letter['source_file'],
        'command_id' => $dead_letter['command_id'],
    ];
    return true;
}

function gb_load_temp_groups() {
    $pdo = gb_db();
    $stmt = $pdo->query('SELECT group_name, members_json, created_at, last_activity, locked FROM temp_groups ORDER BY group_name ASC');
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $groups = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['members_json'], true);
        if (!is_array($decoded)) {
            $decoded = [];
        }
        $members = [];
        foreach ($decoded as $member) {
            if (is_string($member) && $member !== '') {
                $members[] = $member;
            }
        }
        $groups[] = [
            'group_name' => strtoupper((string)($row['group_name'] ?? '')),
            'members' => array_values(array_unique($members)),
            'created_at' => intval($row['created_at'] ?? 0),
            'last_activity' => intval($row['last_activity'] ?? 0),
            'locked' => !empty($row['locked']),
        ];
    }
    return $groups;
}

function gb_get_temp_groups_token() {
    $pdo = gb_db();
    $stmt = $pdo->query('SELECT COUNT(1) AS cnt, MAX(last_activity) AS max_last_activity, MAX(created_at) AS max_created_at, COALESCE(SUM(LENGTH(members_json)), 0) AS members_len_sum, COALESCE(SUM(CASE WHEN locked = 1 THEN 1 ELSE 0 END), 0) AS locked_count FROM temp_groups');
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $count = intval($row['cnt'] ?? 0);
    $max_last_activity = intval($row['max_last_activity'] ?? 0);
    $max_created_at = intval($row['max_created_at'] ?? 0);
    $members_len_sum = intval($row['members_len_sum'] ?? 0);
    $locked_count = intval($row['locked_count'] ?? 0);
    return $count . ':' . $max_last_activity . ':' . $max_created_at . ':' . $members_len_sum . ':' . $locked_count;
}

function gb_temp_group_exists($group_name) {
    $name = strtoupper(trim((string)$group_name));
    if ($name === '') {
        return false;
    }
    $pdo = gb_db();
    $stmt = $pdo->prepare('SELECT 1 FROM temp_groups WHERE UPPER(group_name) = ? LIMIT 1');
    $stmt->execute([$name]);
    return $stmt->fetchColumn() !== false;
}

function gb_clear_failed_dm_queue() {
    $pdo = gb_db();
    $pdo->exec('DELETE FROM failed_dm_queue');
}

function gb_load_outgoing_emails_quarantine($limit = 50) {
    $pdo = gb_db();
    $stmt = $pdo->prepare('SELECT id, data_json, reason, created_at FROM outgoing_emails_quarantine ORDER BY id DESC LIMIT ?');
    $stmt->bindValue(1, intval($limit), PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $messages = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        if (!is_array($decoded)) { $decoded = []; }
        $decoded['id'] = intval($row['id']);
        $decoded['reason'] = $row['reason'];
        $decoded['created_at'] = intval($row['created_at']);
        $messages[] = $decoded;
    }
    return $messages;
}

function gb_clear_outgoing_emails_quarantine() {
    $pdo = gb_db();
    $pdo->exec('DELETE FROM outgoing_emails_quarantine');
}

function gb_export_outgoing_emails_quarantine() {
    $pdo = gb_db();
    $stmt = $pdo->query('SELECT id, data_json, reason, created_at FROM outgoing_emails_quarantine ORDER BY id DESC');
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $messages = [];
    foreach ($rows as $row) {
        $decoded = json_decode($row['data_json'], true);
        if (!is_array($decoded)) { $decoded = []; }
        $decoded['id'] = intval($row['id']);
        $decoded['reason'] = $row['reason'];
        $decoded['created_at'] = intval($row['created_at']);
        $messages[] = $decoded;
    }
    return $messages;
}

function gb_db_integrity_check() {
    $pdo = gb_db();
    $stmt = $pdo->query('PRAGMA integrity_check');
    $row = $stmt->fetch(PDO::FETCH_NUM);
    return $row ? $row[0] : 'unknown';
}

function gb_db_wal_checkpoint() {
    $pdo = gb_db();
    $stmt = $pdo->query('PRAGMA wal_checkpoint(FULL)');
    $row = $stmt->fetch(PDO::FETCH_NUM);
    if (!$row) {
        return 'unknown';
    }
    return "busy={$row[0]}, log={$row[1]}, checkpointed={$row[2]}";
}

function gb_db_vacuum() {
    $pdo = gb_db();
    $pdo->exec('VACUUM');
    return true;
}

function gb_count_dispatcher_jobs() {
    $pdo = gb_db();
    $row = $pdo->query('SELECT COUNT(1) AS cnt FROM dispatcher_jobs')->fetch(PDO::FETCH_ASSOC);
    return intval($row['cnt'] ?? 0);
}

function gb_count_command_jobs($statuses = null) {
    $pdo = gb_db();
    if (!is_array($statuses) || count($statuses) === 0) {
        $row = $pdo->query('SELECT COUNT(1) AS cnt FROM command_jobs')->fetch(PDO::FETCH_ASSOC);
        return intval($row['cnt'] ?? 0);
    }
    $normalized = [];
    foreach ($statuses as $status) {
        $status_clean = strtolower(trim((string)$status));
        if ($status_clean !== '') {
            $normalized[$status_clean] = true;
        }
    }
    $status_values = array_keys($normalized);
    if (count($status_values) === 0) {
        $row = $pdo->query('SELECT COUNT(1) AS cnt FROM command_jobs')->fetch(PDO::FETCH_ASSOC);
        return intval($row['cnt'] ?? 0);
    }
    $placeholders = implode(',', array_fill(0, count($status_values), '?'));
    $stmt = $pdo->prepare("SELECT COUNT(1) AS cnt FROM command_jobs WHERE status IN ($placeholders)");
    $stmt->execute($status_values);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return intval($row['cnt'] ?? 0);
}

function gb_count_outgoing_emails() {
    $pdo = gb_db();
    $row = $pdo->query('SELECT COUNT(1) AS cnt FROM outgoing_emails')->fetch(PDO::FETCH_ASSOC);
    return intval($row['cnt'] ?? 0);
}

function gb_count_failed_dm_queue() {
    $pdo = gb_db();
    $row = $pdo->query('SELECT COUNT(1) AS cnt FROM failed_dm_queue')->fetch(PDO::FETCH_ASSOC);
    return intval($row['cnt'] ?? 0);
}

function gb_count_outgoing_emails_quarantine() {
    $pdo = gb_db();
    $row = $pdo->query('SELECT COUNT(1) AS cnt FROM outgoing_emails_quarantine')->fetch(PDO::FETCH_ASSOC);
    return intval($row['cnt'] ?? 0);
}

function gb_get_env_value($key, $default = '') {
    $key_clean = trim((string)$key);
    if ($key_clean === '') {
        return $default;
    }

    $env_path = '/opt/GuardianBridge/.env';
    if (!is_readable($env_path)) {
        return $default;
    }

    $lines = file($env_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return $default;
    }

    foreach ($lines as $line) {
        $trimmed = trim((string)$line);
        if ($trimmed === '' || strpos($trimmed, '#') === 0) {
            continue;
        }
        if (strpos($line, '=') === false) {
            continue;
        }
        list($k, $v) = explode('=', $line, 2);
        if (trim((string)$k) === $key_clean) {
            return trim((string)$v);
        }
    }
    return $default;
}

function gb_record_login_failure($panel, $principal, $remote_addr, $created_at = null) {
    $pdo = gb_db();
    $panel_clean = substr(trim((string)$panel), 0, 32);
    $principal_clean = substr(trim((string)$principal), 0, 128);
    $remote_addr_clean = substr(trim((string)$remote_addr), 0, 64);
    if ($panel_clean === '') { $panel_clean = 'unknown'; }
    if ($principal_clean === '') { $principal_clean = '__EMPTY__'; }
    if ($remote_addr_clean === '') { $remote_addr_clean = 'unknown'; }
    $created = ($created_at === null) ? time() : intval($created_at);

    $stmt = $pdo->prepare('INSERT INTO login_failures (panel, principal, remote_addr, created_at) VALUES (?, ?, ?, ?)');
    $stmt->execute([$panel_clean, $principal_clean, $remote_addr_clean, $created]);
}

function gb_get_recent_login_failure_stats($panel, $principal, $remote_addr, $window_seconds = 300) {
    $pdo = gb_db();
    $panel_clean = substr(trim((string)$panel), 0, 32);
    $principal_clean = substr(trim((string)$principal), 0, 128);
    $remote_addr_clean = substr(trim((string)$remote_addr), 0, 64);
    if ($panel_clean === '') { $panel_clean = 'unknown'; }
    if ($principal_clean === '') { $principal_clean = '__EMPTY__'; }
    if ($remote_addr_clean === '') { $remote_addr_clean = 'unknown'; }

    $window = max(1, intval($window_seconds));
    $cutoff = time() - $window;
    $stmt = $pdo->prepare('SELECT COUNT(1) AS cnt, MIN(created_at) AS oldest FROM login_failures WHERE panel = ? AND principal = ? AND remote_addr = ? AND created_at >= ?');
    $stmt->execute([$panel_clean, $principal_clean, $remote_addr_clean, $cutoff]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return [
        'count' => intval($row['cnt'] ?? 0),
        'oldest' => intval($row['oldest'] ?? 0),
    ];
}

function gb_clear_login_failures($panel, $principal, $remote_addr) {
    $pdo = gb_db();
    $panel_clean = substr(trim((string)$panel), 0, 32);
    $principal_clean = substr(trim((string)$principal), 0, 128);
    $remote_addr_clean = substr(trim((string)$remote_addr), 0, 64);
    if ($panel_clean === '') { $panel_clean = 'unknown'; }
    if ($principal_clean === '') { $principal_clean = '__EMPTY__'; }
    if ($remote_addr_clean === '') { $remote_addr_clean = 'unknown'; }
    $stmt = $pdo->prepare('DELETE FROM login_failures WHERE panel = ? AND principal = ? AND remote_addr = ?');
    $stmt->execute([$panel_clean, $principal_clean, $remote_addr_clean]);
}

function gb_prune_login_failures($retention_seconds = 86400) {
    $pdo = gb_db();
    $retention = max(60, intval($retention_seconds));
    $cutoff = time() - $retention;
    $stmt = $pdo->prepare('DELETE FROM login_failures WHERE created_at < ?');
    $stmt->execute([$cutoff]);
    return intval($stmt->rowCount());
}

function gb_get_audit_retention_settings() {
    $retention_days_raw = gb_get_env_value('AUDIT_RETENTION_DAYS', '');
    $max_rows_raw = gb_get_env_value('AUDIT_MAX_ROWS', '');

    $retention_days = (is_numeric($retention_days_raw) || $retention_days_raw === '0')
        ? max(0, intval($retention_days_raw))
        : 90;
    $max_rows = (is_numeric($max_rows_raw) || $max_rows_raw === '0')
        ? max(0, intval($max_rows_raw))
        : 50000;

    return [
        'retention_days' => $retention_days,
        'max_rows' => $max_rows,
    ];
}

function gb_count_audit_logs($panel = '', $actor = '') {
    $pdo = gb_db();
    $panel_clean = trim((string)$panel);
    $actor_clean = trim((string)$actor);

    if ($panel_clean !== '' && $actor_clean !== '') {
        $stmt = $pdo->prepare('SELECT COUNT(1) AS cnt FROM audit_log WHERE panel = ? AND actor = ?');
        $stmt->execute([$panel_clean, $actor_clean]);
    } elseif ($panel_clean !== '') {
        $stmt = $pdo->prepare('SELECT COUNT(1) AS cnt FROM audit_log WHERE panel = ?');
        $stmt->execute([$panel_clean]);
    } elseif ($actor_clean !== '') {
        $stmt = $pdo->prepare('SELECT COUNT(1) AS cnt FROM audit_log WHERE actor = ?');
        $stmt->execute([$actor_clean]);
    } else {
        $stmt = $pdo->query('SELECT COUNT(1) AS cnt FROM audit_log');
    }

    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return intval($row['cnt'] ?? 0);
}

function gb_log_audit($actor, $panel, $action, $target = '', $details = []) {
    $pdo = gb_db();
    $actor_clean = trim((string)$actor);
    if ($actor_clean === '') { $actor_clean = 'unknown'; }
    $panel_clean = trim((string)$panel);
    if ($panel_clean === '') { $panel_clean = 'unknown'; }
    $action_clean = trim((string)$action);
    if ($action_clean === '') { $action_clean = 'unknown'; }
    $target_clean = trim((string)$target);

    if (!is_array($details)) {
        $details = ['value' => (string)$details];
    }
    $details_json = json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($details_json) || $details_json === '') {
        $details_json = '{}';
    }

    $stmt = $pdo->prepare('INSERT INTO audit_log (created_at, actor, panel, action, target, details_json) VALUES (?, ?, ?, ?, ?, ?)');
    $stmt->execute([time(), $actor_clean, $panel_clean, $action_clean, $target_clean, $details_json]);

    // Keep audit storage bounded using configured retention controls.
    try {
        gb_prune_audit_logs();
    } catch (Throwable $e) {
        error_log('GuardianBridge Warning: audit retention prune failed: ' . $e->getMessage());
    }
}

function gb_load_audit_logs($limit = 100, $panel = '', $actor = '') {
    $pdo = gb_db();
    $limit = max(1, min(10000, intval($limit)));
    $panel_clean = trim((string)$panel);
    $actor_clean = trim((string)$actor);

    if ($panel_clean !== '' && $actor_clean !== '') {
        $stmt = $pdo->prepare('SELECT id, created_at, actor, panel, action, target, details_json FROM audit_log WHERE panel = ? AND actor = ? ORDER BY id DESC LIMIT ?');
        $stmt->bindValue(1, $panel_clean, PDO::PARAM_STR);
        $stmt->bindValue(2, $actor_clean, PDO::PARAM_STR);
        $stmt->bindValue(3, $limit, PDO::PARAM_INT);
        $stmt->execute();
    } elseif ($panel_clean !== '') {
        $stmt = $pdo->prepare('SELECT id, created_at, actor, panel, action, target, details_json FROM audit_log WHERE panel = ? ORDER BY id DESC LIMIT ?');
        $stmt->bindValue(1, $panel_clean, PDO::PARAM_STR);
        $stmt->bindValue(2, $limit, PDO::PARAM_INT);
        $stmt->execute();
    } elseif ($actor_clean !== '') {
        $stmt = $pdo->prepare('SELECT id, created_at, actor, panel, action, target, details_json FROM audit_log WHERE actor = ? ORDER BY id DESC LIMIT ?');
        $stmt->bindValue(1, $actor_clean, PDO::PARAM_STR);
        $stmt->bindValue(2, $limit, PDO::PARAM_INT);
        $stmt->execute();
    } else {
        $stmt = $pdo->prepare('SELECT id, created_at, actor, panel, action, target, details_json FROM audit_log ORDER BY id DESC LIMIT ?');
        $stmt->bindValue(1, $limit, PDO::PARAM_INT);
        $stmt->execute();
    }

    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $entries = [];
    foreach ($rows as $row) {
        $details = json_decode((string)($row['details_json'] ?? '{}'), true);
        if (!is_array($details)) {
            $details = [];
        }
        $entries[] = [
            'id' => intval($row['id'] ?? 0),
            'created_at' => intval($row['created_at'] ?? 0),
            'actor' => (string)($row['actor'] ?? ''),
            'panel' => (string)($row['panel'] ?? ''),
            'action' => (string)($row['action'] ?? ''),
            'target' => (string)($row['target'] ?? ''),
            'details' => $details,
        ];
    }
    return $entries;
}

function gb_export_audit_logs($limit = 2000, $panel = '', $actor = '') {
    $entries = gb_load_audit_logs(max(1, min(10000, intval($limit))), $panel, $actor);
    $rows = [];
    foreach ($entries as $entry) {
        $rows[] = [
            'id' => intval($entry['id'] ?? 0),
            'created_at' => intval($entry['created_at'] ?? 0),
            'created_at_iso' => gmdate('c', intval($entry['created_at'] ?? 0)),
            'actor' => (string)($entry['actor'] ?? ''),
            'panel' => (string)($entry['panel'] ?? ''),
            'action' => (string)($entry['action'] ?? ''),
            'target' => (string)($entry['target'] ?? ''),
            'details' => is_array($entry['details'] ?? null) ? $entry['details'] : [],
        ];
    }
    return $rows;
}

function gb_prune_audit_logs($retention_days = null, $max_rows = null) {
    $settings = gb_get_audit_retention_settings();
    $days = ($retention_days === null) ? intval($settings['retention_days'] ?? 90) : max(0, intval($retention_days));
    $rows_limit = ($max_rows === null) ? intval($settings['max_rows'] ?? 50000) : max(0, intval($max_rows));

    $pdo = gb_db();
    $deleted_by_age = 0;
    $deleted_by_count = 0;

    if ($days > 0) {
        $cutoff = time() - ($days * 86400);
        $stmt = $pdo->prepare('DELETE FROM audit_log WHERE created_at < ?');
        $stmt->execute([$cutoff]);
        $deleted_by_age = intval($stmt->rowCount());
    }

    if ($rows_limit > 0) {
        $total_count = gb_count_audit_logs();
        $overflow = $total_count - $rows_limit;
        if ($overflow > 0) {
            $stmt = $pdo->prepare('DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log ORDER BY id ASC LIMIT ?)');
            $stmt->bindValue(1, $overflow, PDO::PARAM_INT);
            $stmt->execute();
            $deleted_by_count = intval($stmt->rowCount());
        }
    }

    return [
        'deleted_by_age' => $deleted_by_age,
        'deleted_by_count' => $deleted_by_count,
        'remaining' => gb_count_audit_logs(),
        'retention_days' => $days,
        'max_rows' => $rows_limit,
    ];
}

?>
