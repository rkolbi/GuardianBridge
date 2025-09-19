<?php
// GuardianBridge - Admin Panel

// --- CONFIGURATION ---
$revision = 'v 1.1.0';

// --- AUTHENTICATION CONFIG ---
$admin_username = 'admin';
$admin_password_hash = '$2y$10$U7S57pL48AljscoTyeods.nMpGL5LU1GilDYO5ATJXpIM7aElvuUi'; // Example hash for password 'password'. REPLACE THIS.

session_start();

// --- CSRF TOKEN GENERATION ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// --- LOGOUT LOGIC ---
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
    exit;
}

// --- LOGIN LOGIC ---
$login_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    if ($username === $admin_username && password_verify($password, $admin_password_hash)) {
        $_SESSION['loggedin'] = true;
        session_regenerate_id(true);
        header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
        exit;
    } else {
        $login_error = 'Invalid username or password.';
    }
}

// --- AUTHENTICATION GATE ---
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
?>
<!DOCTYPE html>
<html lang="en" class="bg-[#131314]">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - GuardianBridge Control</title>
    <link rel="icon" type="image/x-icon" href="/map-items/map-logo.ico">
    <script src="/map-items/tailwindcss.js"></script>
    <link href="/map-items/inter-font.css" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #131314; }
        input[type="text"], input[type="password"] {
            background-color: #1E1F20; border: 1px solid #3C4043; color: #E3E3E3;
            padding: 0.6rem 0.85rem; border-radius: 0.5rem; width: 100%; transition: all 0.2s;
        }
        input:focus {
            outline: none; border-color: #89B3F8; box-shadow: 0 0 0 2px rgba(137, 179, 248, 0.3);
        }
        .btn-primary { background-color: #89B3F8; color: #131314; }
        .btn-primary:hover { background-color: #A58AFB; }
    </style>
</head>
<body class="text-slate-300">
    <div class="min-h-screen flex items-center justify-center">
        <div class="max-w-md w-full p-8">
            <header class="mb-8 text-center">
                <img src="/map-items/map-logo.png" alt="Gateway Logo" class="h-28 w-24 mx-auto mb-4">
                <h1 class="text-4xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-red-400 bg-clip-text text-transparent">
                    GuardianBridge Control
                </h1>
                <p class="text-slate-400 mt-1">Administrator Login</p>
            </header>
            
            <?php if ($login_error): ?>
                <div class="bg-red-500/10 border border-red-500/20 text-red-300 px-4 py-3 rounded-lg relative mb-6 text-center" role="alert">
                    <?= htmlspecialchars($login_error) ?>
                </div>
            <?php endif; ?>

            <form method="POST" class="space-y-6">
                <input type="hidden" name="action" value="login">
                <div>
                    <label for="username" class="block text-sm font-medium text-slate-400 mb-2">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-slate-400 mb-2">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div>
                    <button type="submit" class="w-full py-2.5 px-4 rounded-lg font-semibold btn-primary">Sign In</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
<?php
    exit;
}

// --- CONFIGURATION & FILE PATHS ---
$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$node_db_status_file = $data_dir . '/node_status.json';
$subscribers_file = $data_dir . '/subscribers.json';
$dispatcher_file = $base_dir . '/data/dispatcher.txt';
$env_file = $base_dir . '/.env';
$weather_current_file = $data_dir . '/weather_current.json';
$weather_alerts_file = $data_dir . '/nws_alerts.txt';
$outgoing_email_file = $data_dir . '/outgoing_emails.json';
$failed_dm_queue_file = $data_dir . '/failed_dm_queue.json';
$dispatcher_status_file = $data_dir . '/dispatcher_status.json';
$weather_fetcher_lastrun_file = $data_dir . '/weather_fetcher.lastrun';
$email_processor_lastrun_file = $data_dir . '/email_processor.lastrun';
$commands_dir = $base_dir . '/data/commands';
$channel0_log_file = $data_dir . '/channel0_log.json';
$sos_log_file = $data_dir . '/sos_log.json';

$manageable_settings = [
    'LATITUDE', 'LONGITUDE', 'LOG_LEVEL', 'MESHTASTIC_PORT',
    'EMAIL_USER', 'EMAIL_PASS', 'IMAP_SERVER', 'IMAP_PORT',
    'TRASH_FOLDER_NAME', 'MAX_EMAIL_BODY_LEN',
    'WEATHER_ALERT_INTERVAL_MINS', 'WEATHER_UPDATE_INTERVAL_MINS',
    'FORECAST_MORNING_SEND_TIME', 'FORECAST_AFTERNOON_SEND_TIME'
];

// --- HELPER FUNCTIONS ---

/**
 * [NEW] Safely reads and decodes a JSON file using a shared lock to prevent race conditions.
 *
 * @param string $file_path The path to the JSON file.
 * @param mixed $default_value The value to return on failure.
 * @return mixed The decoded JSON data as an associative array, or the default value.
 */
function get_locked_json_file($file_path, $default_value = []) {
    if (!is_readable($file_path)) {
        return $default_value;
    }

    $fp = @fopen($file_path, 'r');
    if (!$fp) {
        return $default_value;
    }

    $data = $default_value;
    if (flock($fp, LOCK_SH)) {
        $content = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        if ($content !== false && !empty(trim($content))) {
            $decoded = json_decode($content, true);
            // Check if json_decode was successful
            if (json_last_error() === JSON_ERROR_NONE) {
                $data = $decoded;
            }
        }
    }
    
    fclose($fp);
    return $data;
}

function get_subscribers($file_path) {
    return get_locked_json_file($file_path, []);
}

function save_subscribers($file_path, $data) {
    ksort($data);
    
    $fp = fopen($file_path, 'w');
    if (!$fp) {
        error_log("GuardianBridge Error: Cannot open for writing: " . $file_path);
        return false;
    }
    
    if (flock($fp, LOCK_EX)) {
        ftruncate($fp, 0);
        fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($fp);
        flock($fp, LOCK_UN);
    } else {
        fclose($fp);
        error_log("GuardianBridge Error: Cannot get exclusive lock on: " . $file_path);
        return false;
    }
    
    fclose($fp);
    return true;
}

function get_dispatcher_jobs($file_path) {
    return get_locked_json_file($file_path, []);
}

function save_dispatcher_jobs($file_path, $jobs) {
    if (!is_array($jobs)) {
        $jobs = [];
    }

    $fp = fopen($file_path, 'w');
    if (!$fp) {
        error_log("GuardianBridge Error: Cannot open for writing: " . $file_path);
        return false;
    }
    
    if (flock($fp, LOCK_EX)) {
        ftruncate($fp, 0);
        fwrite($fp, json_encode(array_values($jobs), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($fp);
        flock($fp, LOCK_UN);
    } else {
        fclose($fp);
        error_log("GuardianBridge Error: Cannot get exclusive lock on: " . $file_path);
        return false;
    }

    fclose($fp);
    return true;
}

function get_channel0_messages($file_path) {
    // [MODIFIED] Use the safe, locked file reading function.
    return get_locked_json_file($file_path, []);
}

function get_env_settings($file_path, $whitelist) {
    $env_values = [];
    if (is_readable($file_path)) {
        $lines = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            if (strpos($line, '=') === false) continue;
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            if (in_array($key, $whitelist)) {
                $env_values[$key] = trim($value);
            }
        }
    }
    foreach ($whitelist as $key) {
        if (!array_key_exists($key, $env_values)) {
            $env_values[$key] = '';
        }
    }
    return $env_values;
}
function save_env_settings($file_path, $new_settings, $whitelist) {
    if (!is_readable($file_path) || !is_writable($file_path)) {
        error_log("GuardianBridge Error: .env file is not readable or writable: " . $file_path);
        return false;
    }

    $lines = file($file_path, FILE_IGNORE_NEW_LINES);
    $updated_lines = [];
    $settings_to_update = $new_settings;

    foreach ($lines as $line) {
        $trimmed_line = trim($line);
        if (empty($trimmed_line) || $trimmed_line[0] === '#') {
            $updated_lines[] = $line;
            continue;
        }

        $parts = explode('=', $line, 2);
        $key = trim($parts[0]);

        if (in_array($key, $whitelist) && array_key_exists($key, $settings_to_update)) {
            // Update existing manageable setting
            $updated_lines[] = $key . '=' . $settings_to_update[$key];
            unset($settings_to_update[$key]); // Mark as updated
        } else {
            // Preserve non-manageable setting or comment
            $updated_lines[] = $line;
        }
    }

    // Add any new settings that were not found in the original file
    foreach ($settings_to_update as $key => $value) {
        if (in_array($key, $whitelist)) {
             $updated_lines[] = $key . '=' . $value;
        }
    }

    if (file_put_contents($file_path, implode("\n", $updated_lines)) === false) {
        error_log("GuardianBridge Error: Failed to write to .env file: " . $file_path);
        return false;
    }
    return true;
}
function get_file_age_string($file_path) {
    if (!file_exists($file_path)) return '<span class="text-slate-500">Never</span>';
    $age_seconds = time() - filemtime($file_path);
    if ($age_seconds < 60) return $age_seconds . ' seconds ago';
    if ($age_seconds < 3600) return round($age_seconds / 60) . ' minutes ago';
    return round($age_seconds / 3600) . ' hours ago';
}
function get_age_string_from_timestamp($timestamp) {
    if (empty($timestamp)) return '<span class="text-slate-500">Never</span>';
    $age_seconds = time() - $timestamp;
    
    if ($age_seconds < 60) return round($age_seconds) . 's ago';
    if ($age_seconds < 3600) return round($age_seconds / 60) . 'm ago';
    if ($age_seconds < 86400) return round($age_seconds / 3600) . 'h ago';
    return round($age_seconds / 86400) . 'd ago';
}

// --- FORM PROCESSING ---
$message = '';
$error = '';

// Handle AJAX requests separately to prevent full page reload
if (isset($_POST['ajax']) && $_POST['ajax'] === 'true') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'Invalid action.'];

    // RE-ENABLED CSRF PROTECTION FOR AJAX
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $response['message'] = 'Invalid security token.';
        echo json_encode($response);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = $_POST['action'] ?? '';
        if ($action === 'send_broadcast') {
            $text_to_send = $_POST['broadcast_text'] ?? '';
            $command_data = [];
            $error_message = ''; // Use a local variable for errors
            
            if (empty(trim($text_to_send))) {
                $error_message = 'Message text cannot be empty.';
            } else {
                if (strpos($text_to_send, '@') === 0) {
                    $parts = explode(' ', $text_to_send, 2);
                    $target_str = ltrim($parts[0], '@');
                    $message_body = $parts[1] ?? '';
                    if (empty($message_body)) {
                        $error_message = "Direct message has no text. Format: @user message";
                    } else {
                        $subscribers = get_subscribers($subscribers_file);
                        $destination_id = null;
                        if (preg_match('/^![a-f0-9]{8}$/', $target_str)) {
                            $destination_id = $target_str;
                        } else {
                            foreach ($subscribers as $node_id => $user_data) {
                                if (isset($user_data['name']) && strtolower($user_data['name']) === strtolower($target_str)) {
                                    $destination_id = $node_id;
                                    break;
                                }
                            }
                        }
                        if ($destination_id) {
                            $command_data = ['command' => 'dm', 'destinationId' => $destination_id, 'text' => $message_body, 'recipient' => $target_str];
                        } else {
                            $error_message = "User or Node ID '{$target_str}' not found in subscribers.";
                        }
                    }
                } else {
                    $command_data = ['command' => 'broadcast', 'text' => $text_to_send];
                }
            }

            if (!empty($command_data)) {
                $filename = 'webui_cmd_' . time() . '_' . rand(100,999) . '.json';
                if (@file_put_contents($commands_dir . '/' . $filename, json_encode($command_data))) {
                    $response['success'] = true;
                    $response['message'] = 'Message sent successfully.';
                } else {
                    $response['message'] = 'Failed to create command file. Check server logs.';
                    error_log("GuardianBridge Error: Failed to write command file to " . $commands_dir . "/" . $filename);
                }
            } elseif (!empty($error_message)) {
                $response['message'] = $error_message;
            }
        }
    }
    echo json_encode($response);
    exit;
}

// Main handler for non-AJAX form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['ajax'])) {
    // 1. VERIFY CSRF TOKEN
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Invalid security token. Please refresh the page and try again.";
    } else {
        // 2. Process Actions
        $action = $_POST['action'] ?? '';

        if ($action === 'clear_chat_history') {
            if (file_put_contents($channel0_log_file, '[]') !== false) {
                $message = "Message history has been cleared successfully.";
            } else {
                $error = "Failed to clear chat history. Please check server logs.";
                error_log("GuardianBridge Error: Failed to clear file " . $channel0_log_file);
            }
        }

        if ($action === 'clear_sos_log') {
            if (file_put_contents($sos_log_file, '[]') !== false) {
                $message = "SOS Alert Log has been cleared.";
            } else {
                $error = "Failed to clear SOS log. Please check server logs.";
                error_log("GuardianBridge Error: Failed to write to " . $sos_log_file);
            }
        }
        
        // --- MODIFIED: Handler for the new Admin Clear SOS command ---
        if ($action === 'admin_clear_sos') {
            $node_id_to_clear = $_POST['node_id'] ?? null;
            if ($node_id_to_clear) {
                $command_data = [
                    'command' => 'admin_clear_sos',
                    'node_id' => $node_id_to_clear
                ];
                $filename = 'webui_cmd_adminclear_' . time() . '_' . rand(100,999) . '.json';
                if (file_put_contents($commands_dir . '/' . $filename, json_encode($command_data))) {
                    $message = "Admin command to clear SOS for node " . htmlspecialchars($node_id_to_clear) . " has been queued.";
                } else {
                    $error = 'Failed to create admin clear command file. Please check server logs.';
                    error_log("GuardianBridge Error: Failed to write command file to " . $commands_dir);
                }
            } else {
                $error = "No active SOS node ID was provided for the admin clear command.";
            }
        }

        if ($action === 'update_user') {
            $node_id = $_POST['node_id'];
            $subscribers = get_subscribers($subscribers_file);
            if (isset($subscribers[$node_id])) {
                // VALIDATE AND CLEANSE INPUT
                $subscribers[$node_id]['name'] = trim(strip_tags($_POST['name']));
                $subscribers[$node_id]['full_name'] = trim(strip_tags($_POST['full_name']));
                $subscribers[$node_id]['role'] = trim(strip_tags($_POST['role']));
                $subscribers[$node_id]['email'] = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
                $subscribers[$node_id]['phone_1'] = trim(strip_tags($_POST['phone_1']));
                $subscribers[$node_id]['phone_2'] = trim(strip_tags($_POST['phone_2']));
                $subscribers[$node_id]['notes'] = trim(strip_tags($_POST['notes']));

                // Nested address object
                if (!isset($subscribers[$node_id]['address']) || !is_array($subscribers[$node_id]['address'])) {
                    $subscribers[$node_id]['address'] = [];
                }
                $subscribers[$node_id]['address']['street'] = trim(strip_tags($_POST['address_street']));
                $subscribers[$node_id]['address']['city'] = trim(strip_tags($_POST['address_city']));
                $subscribers[$node_id]['address']['state'] = trim(strip_tags($_POST['address_state']));
                $subscribers[$node_id]['address']['zip'] = trim(strip_tags($_POST['address_zip']));

                if (isset($_POST['tags'])) {
                    $tags_raw = trim(strip_tags($_POST['tags']));
                    $tags_array = array_filter(array_map('trim', explode(',', $tags_raw)));
                    $subscribers[$node_id]['tags'] = array_values(array_unique(array_map('strtoupper', $tags_array)));
                    sort($subscribers[$node_id]['tags']);
                } else {
                    $subscribers[$node_id]['tags'] = [];
                }

                // Checkbox/boolean fields
                $subscribers[$node_id]['alerts'] = isset($_POST['alerts']);
                $subscribers[$node_id]['weather'] = isset($_POST['weather']);
                $subscribers[$node_id]['scheduled_daily_forecast'] = isset($_POST['scheduled_daily_forecast']);
                $subscribers[$node_id]['email_send'] = isset($_POST['email_send']);
                $subscribers[$node_id]['email_receive'] = isset($_POST['email_receive']);
                $subscribers[$node_id]['emailbroadcast'] = isset($_POST['emailbroadcast']);
                $subscribers[$node_id]['node_tag_send'] = isset($_POST['node_tag_send']);
                $subscribers[$node_id]['blocked'] = isset($_POST['blocked']); 

                if (save_subscribers($subscribers_file, $subscribers)) {
                    $message = "User '" . htmlspecialchars($subscribers[$node_id]['name']) . "' updated successfully.";
                } else {
                    $error = "Failed to update user. Please check server logs.";
                }
            }
        }

        if ($action === 'add_user') {
            $node_id = trim($_POST['new_node_id']);
            // VALIDATE INPUT
            if (preg_match('/^![a-f0-9]{8}$/', $node_id)) {
                $subscribers = get_subscribers($subscribers_file);
                if (!isset($subscribers[$node_id])) {
                    $subscribers[$node_id] = [
                        "name" => trim(strip_tags($_POST['new_name'])), // Cleanse input
                        "full_name" => "", "role" => "", "email" => "",
                        "address" => ["street" => "", "city" => "", "state" => "", "zip" => ""],
                        "phone_1" => "", "phone_2" => "", "notes" => "",
                        "alerts" => true, "weather" => true, "scheduled_daily_forecast" => true,
                        "email_send" => false, "email_receive" => false, "emailbroadcast" => false,
                        "node_tag_send" => false, "blocked" => false, "tags" => []
                    ];
                    if (save_subscribers($subscribers_file, $subscribers)) {
                        $message = "User '$node_id' added successfully.";
                    } else {
                        $error = "Failed to add user. Please check server logs.";
                    }
                } else {
                    $error = "User '$node_id' already exists.";
                }
            } else {
                 $error = "Invalid Node ID format. Must be like '!a1b2c3d4'.";
            }
        }

        if ($action === 'delete_user') {
            $node_id = $_POST['node_id'];
            $subscribers = get_subscribers($subscribers_file);
            if (isset($subscribers[$node_id])) {
                unset($subscribers[$node_id]);
                if (save_subscribers($subscribers_file, $subscribers)) {
                    $message = "User '$node_id' deleted successfully.";
                } else {
                    $error = "Failed to delete user. Please check server logs.";
                }
            }
        }

        if ($action === 'save_broadcast_job') {
            $jobs = get_dispatcher_jobs($dispatcher_file);
            $job_index = $_POST['job_index'];

            if (isset($jobs[$job_index])) {
                // VALIDATE AND CLEANSE INPUT
                $content = trim(strip_tags($_POST['content']));
                if (isset($_POST['with_bell']) && $_POST['with_bell'] === 'true') {
                    $content = "\x07" . $content;
                }

                $new_job = [
                    'name' => trim(strip_tags($_POST['name'])),
                    'content' => $content,
                    'interval_mins' => max(1, (int)$_POST['interval_mins']), // Ensure at least 1
                    'enabled' => isset($_POST['enabled']) 
                ];

                $job_type = $_POST['job_type'] ?? 'recurring';
                if ($job_type === 'recurring') {
                    $new_job['days'] = $_POST['days'] ?? [];
                    $new_job['start_time'] = trim(strip_tags($_POST['start_time']));
                    $new_job['stop_time'] = trim(strip_tags($_POST['stop_time']));
                } else { // event
                    $new_job['start_datetime'] = trim(strip_tags($_POST['start_datetime']));
                    $new_job['stop_datetime'] = trim(strip_tags($_POST['stop_datetime']));
                }

                if (isset($jobs[$job_index]['last_sent'])) {
                    $new_job['last_sent'] = $jobs[$job_index]['last_sent'];
                }

                $jobs[$job_index] = $new_job;
                
                if (save_dispatcher_jobs($dispatcher_file, $jobs)) {
                     $message = "Broadcast job '" . htmlspecialchars($new_job['name']) . "' updated successfully.";
                } else {
                    $error = "Failed to save broadcast jobs. Please check server logs.";
                }
            } else {
                $error = "Invalid job index for update.";
            }
        }

        if ($action === 'add_broadcast_job') {
            $jobs = get_dispatcher_jobs($dispatcher_file);
            // VALIDATE AND CLEANSE INPUT
            $new_job_name = trim(strip_tags($_POST['new_broadcast_name']));
            if (!empty($new_job_name)) {
                $name_exists = false;
                foreach ($jobs as $job) {
                    if (isset($job['name']) && strtolower($job['name']) === strtolower($new_job_name)) {
                        $name_exists = true;
                        break;
                    }
                }

                if (!$name_exists) {
                    $jobs[] = [
                        "name" => $new_job_name,
                        "content" => "Default content for {$new_job_name}. Please edit.",
                        "interval_mins" => 60,
                        "days" => ["MON", "TUE", "WED", "THU", "FRI"],
                        "start_time" => "08:00", "stop_time" => "17:00", "last_sent" => null,
                        "enabled" => false // This job is disabled by default
                    ];
                    if (save_dispatcher_jobs($dispatcher_file, $jobs)) {
                        $message = "Broadcast job '" . htmlspecialchars($new_job_name) . "' added. Click 'More...' to edit details.";
                    } else {
                        $error = "Failed to add broadcast job. Please check server logs.";
                    }
                } else {
                    $error = "A broadcast job with that name already exists.";
                }
            } else {
                $error = "Broadcast name cannot be empty.";
            }
        }

        if ($action === 'delete_broadcast_job') {
            $jobs = get_dispatcher_jobs($dispatcher_file);
            $job_index = $_POST['job_index'];
            if (isset($jobs[$job_index])) {
                $job_name = $jobs[$job_index]['name'] ?? 'Untitled Job';
                unset($jobs[$job_index]);
                if (save_dispatcher_jobs($dispatcher_file, $jobs)) {
                    $message = "Broadcast job '" . htmlspecialchars($job_name) . "' deleted successfully.";
                } else {
                    $error = "Failed to delete broadcast job. Please check server logs.";
                }
            } else {
                $error = "Invalid job index for deletion.";
            }
        }

        if ($action === 'update_settings') {
            $new_settings = $_POST['settings'];
            if (isset($new_settings['EMAIL_PASS']) && $new_settings['EMAIL_PASS'] === '********') {
                $current_settings = get_env_settings($env_file, $manageable_settings);
                $new_settings['EMAIL_PASS'] = $current_settings['EMAIL_PASS'];
            }

            if (save_env_settings($env_file, $new_settings, $manageable_settings)) {
                $message = "Settings updated successfully. You must restart the dispatcher service from the terminal for changes to take effect.";
            } else {
                $error = "Failed to save settings. Please check server logs.";
            }
        }

        if ($action === 'run_weather_fetcher') {
            $output = shell_exec('python3 ' . escapeshellarg($base_dir . '/weather_fetcher.py') . ' 2>&1');
            $message = "Weather fetcher executed. Output: <pre class=\"text-xs bg-black/50 p-3 mt-2 border border-slate-700 rounded-md text-slate-300\">" . htmlspecialchars($output) 
. "</pre>";
        }

        if ($action === 'run_email_processor') {
            $output = shell_exec('python3 ' . escapeshellarg($base_dir . '/email_processor.py') . ' 2>&1');
            $message = "Email processor executed. Output: <pre class=\"text-xs bg-black/50 p-3 mt-2 border border-slate-700 rounded-md text-slate-300\">" . htmlspecialchars($output) 
. "</pre>";
        }

        if ($action === 'clear_email_queue') {
            if (file_put_contents($outgoing_email_file, '[]') !== false) {
                $message = "Outgoing email queue has been cleared.";
            } else {
                $error = "Failed to clear email queue. Please check server logs.";
                error_log("GuardianBridge Error: Failed to write to " . $outgoing_email_file);
            }
        }
    }
}


// --- DATA FOR DISPLAY ---
// [MODIFIED] All file_get_contents calls are replaced with the new safe helper function.
$settings = get_env_settings($env_file, $manageable_settings);
$gateway_lat = $settings['LATITUDE'] ?? 30.0000;
$gateway_lon = $settings['LONGITUDE'] ?? -90.0000;
$node_statuses = get_locked_json_file($node_db_status_file, []);
$subscribers = get_subscribers($subscribers_file);
$dispatcher_jobs = get_dispatcher_jobs($dispatcher_file);
$weather_current = get_locked_json_file($weather_current_file, null);
$weather_alerts = get_locked_json_file($weather_alerts_file, []);
$outgoing_emails = get_locked_json_file($outgoing_email_file, null);
$failed_dms = get_locked_json_file($failed_dm_queue_file, null);
$dispatcher_status = get_locked_json_file($dispatcher_status_file, null);
$channel0_messages = get_channel0_messages($channel0_log_file);
$sos_log = get_locked_json_file($sos_log_file, []);
$days_of_week = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];

$active_sos_node_id = null;
if (is_array($node_statuses)) {
    foreach ($node_statuses as $node_id => $status) {
        if (isset($status['sos']) && $status['sos']) {
            $active_sos_node_id = $node_id;
            break; 
        }
    }
}

$setting_descriptions = [
    'LATITUDE' => 'The geographical latitude of the gateway (e.g., 40.7128). This is required for fetching accurate local weather data from the National Weather Service (NWS) API.',
    'LONGITUDE' => 'The geographical longitude of the gateway (e.g., -74.0060). This is required for fetching accurate local weather data from the National Weather Service (NWS) API.',
    'LOG_LEVEL' => 'Controls the amount of detail logged by the backend scripts. Recommended values are INFO, DEBUG, WARNING, or ERROR. DEBUG is the most verbose and 
is useful for troubleshooting.',
    'MESHTASTIC_PORT' => "The system device path for the connected Meshtastic radio. On Linux, this is typically /dev/ttyUSB0. On Windows, it would be a COM port like COM3. Set to 'None' to enable auto-detection.",
    'EMAIL_USER' => 'The full email address of the account that will send and receive emails via the gateway (e.g., your-gateway@gmail.com).',
    'EMAIL_PASS' => 'The password for the email account. For services like Gmail, this must be a 16-character "App Password", not your main account password. This 
field is hidden for security.',
    'IMAP_SERVER' => 'The address of the IMAP server for reading incoming emails. Common examples: imap.gmail.com, outlook.office365.com, imap.mail.yahoo.com.',
    'IMAP_PORT' => 'The port for the IMAP server. This is almost always 993 for a standard SSL/TLS connection.',
    'TRASH_FOLDER_NAME' => 'The exact name of the folder on the email server where processed emails should be moved. Common names include "Trash", "Bin", or "[Gmail]/Trash".',
    'MAX_EMAIL_BODY_LEN' => 'The maximum number of characters allowed for an email body sent from the mesh network. This prevents messages from being split into too many parts. A value around 180 is recommended.',
    'WEATHER_ALERT_INTERVAL_MINS' => 'How often, in minutes, an ongoing NWS alert should be re-broadcast. New alerts are always sent immediately. A value of 15-30 
minutes is recommended to avoid excessive messages during a long-lasting alert.',
    'WEATHER_UPDATE_INTERVAL_MINS' => 'Controls how often, in minutes, the current weather conditions are broadcast to the network. The data itself is fetched separately in the background. A value of 30-60 minutes is recommended to reduce channel noise.',
    'FORECAST_MORNING_SEND_TIME' => 'The time of day to automatically broadcast the morning forecast to subscribed users. Use 24-hour format (e.g., 07:00 for 7:00 
AM).',
    'FORECAST_AFTERNOON_SEND_TIME' => 'The time of day to automatically broadcast the afternoon forecast to subscribed users. Use 24-hour format (e.g., 16:30 for 4:30 PM).'
];
?>
<!DOCTYPE html>
<html lang="en" class="bg-[#131314]">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GuardianBridge Admin Panel</title>
    <link rel="icon" type="image/x-icon" href="/map-items/map-logo.ico">
    <script src="/map-items/tailwindcss.js"></script>
    <link href="/map-items/inter-font.css" rel="stylesheet">
    <link rel="stylesheet" href="/map-items/leaflet.css"/>
    <script src="/map-items/leaflet.js"></script>    
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #131314; }
        .tab-button { position: relative; transition: color 0.2s; cursor: pointer; }
        .tab-button.active { color: #E3E3E3; }
        .tab-button:not(.active) { color: #8E918F; }
        .tab-button.active::after { content: ''; position: absolute; bottom: -1px; left: 0; right: 0; height: 3px; background-image: linear-gradient(to right, #89B3F8, #A58AFB, #F485A5); }
        input[type="text"], input[type="email"], input[type="number"], input[type="time"], input[type="datetime-local"], input[type="password"], select, textarea { background-color: #1E1F20; border: 1px solid #3C4043; color: #E3E3E3; padding: 0.6rem 0.85rem; border-radius: 0.5rem; width: 100%; transition: all 0.2s; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: #89B3F8; box-shadow: 0 0 0 2px rgba(137, 179, 248, 0.3); }
        input::placeholder, textarea::placeholder { color: #8E918F; }
        input[type="checkbox"] { background-color: #3C4043; border-color: #8E918F; border-radius: 4px; }
        input[type="checkbox"]:checked { background-image: linear-gradient(to right, #89B3F8, #A58AFB); border-color: transparent; }
        .btn { padding: 9px 18px; border-radius: 8px; font-weight: 600; transition: all 0.2s; cursor: pointer; border: 1px solid transparent; }
        .btn-sm { padding: 5px 10px; font-size: 0.875rem; }
        .btn-primary { background-color: #89B3F8; color: #131314; }
        .btn-primary:hover { background-color: #A58AFB; }
        .btn-secondary { background-color: #3C4043; color: #E3E3E3; }
        .btn-secondary:hover { background-color: #525355; }
        .btn-red { background-color: #F28B82; color: #131314; }
        .btn-red:hover { background-color: #F485A5; }
        .btn-green { background-color: #81C995; color: #131314; }
        .btn-green:hover { background-color: #A5D6A7; }
        .status-ok { color: #81C995; }
        .status-fail { color: #F28B82; }
        .status-warn { color: #FDD663; }
        .card { background-color: #1E1F20; border-radius: 0.75rem; border: 1px solid #3C4043; }
        
        /* Modal z-index fix */
        #dm-chat-modal, #user-edit-modal, #broadcast-edit-modal, #confirm-action-modal { z-index: 1050; }

        #map { height: 500px; border-radius: 0.75rem; border: 1px solid #3C4043; background-color: #3C4043; }
        .leaflet-popup-content-wrapper, .leaflet-popup-tip { background: #1E1F20; color: #E3E3E3; border: 1px solid #525355; box-shadow: 0 3px 14px rgba(0,0,0,0.4); }      .leaflet-tile-pane { filter: brightness(0.7) contrast(1.1) grayscale(0.2); }
        .map-node-label { background-color: rgba(30, 31, 32, 0.8); color: #E3E3E3; border: 1px solid #525355; padding: 2px 5px; border-radius: 4px; white-space: nowrap; }
        .popup-hr { border-color: #3C4043; margin-top: 6px; margin-bottom: 6px; }

        /* --- Chat Theme (Restored) --- */
        #chat-messages-container, #dm-chat-messages-container { display: flex; flex-direction: column; gap: 0.75rem; }
        .message { max-width: 80%; padding: 0.35rem 1rem; border-radius: 0.75rem; position: relative; border: 1px solid transparent; }
        .message-incoming { align-self: flex-start; border-top-left-radius: 0; border-left: 3px solid #89B3F8; background: linear-gradient(135deg, rgba(137, 179, 248, 0.1), rgba(137, 179, 248, 0.03)); border-color: rgba(137, 179, 248, 0.15); }
        .message-outgoing { align-self: flex-end; border-bottom-right-radius: 0; border-right: 3px solid #A58AFB; background: linear-gradient(135deg, rgba(165, 138, 251, 0.1), rgba(165, 138, 251, 0.03)); border-color: rgba(165, 138, 251, 0.15); }
        .message-system { align-self: center; max-width: 90%; text-align: center; background: rgba(227, 227, 227, 0.05); border: 1px dashed #525355; color: #8E918F; font-size: 0.9rem; font-style: italic; padding: 0.5rem 1rem; }
        .message-content { word-break: break-word; white-space: pre-wrap; line-height: 1.3; }
        .message-meta { font-size: 0.75rem; line-height: 1.1; color: #8E918F; margin-top: 0.2rem; }
        .message-username { font-weight: 600; line-height: 1.1; margin-bottom: 0.2rem; }
        .message-incoming .message-username { color: #89B3F8; }
        .message-outgoing .message-username { color: #A58AFB; }

        /* --- SOS BANNER --- */
        @keyframes flash-red { 0%, 100% { background-color: #dc2626; } 50% { background-color: #ef4444; } }
        #sos-banner { animation: flash-red 1s infinite; }
        /* Styles for content loaded from help.html */
        .help-content h2 { font-size: 1.5rem; font-weight: bold; color: #E3E3E3; border-bottom: 1px solid #3C4043; padding-bottom: 0.5rem; margin-top: 2rem; }
        .help-content h3 { font-size: 1.25rem; font-weight: bold; color: #E3E3E3; margin-top: 1.5rem; }
        .help-content h4 { font-size: 1.1rem; font-weight: bold; color: #89B3F8; margin-top: 1.5rem; }
        .help-content ul { list-style-type: disc; padding-left: 2rem; }
        .help-content ol { list-style-type: decimal; padding-left: 2rem; }
        .help-content li { margin-bottom: 0.5rem; }
        .help-content code { background-color: #3C4043; color: #F485A5; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; }
        .help-content pre { background-color: #131314; border: 1px solid #3C4043; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
        .help-content pre code { background-color: transparent; padding: 0; }
        .help-content table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        .help-content th, .help-content td { border: 1px solid #3C4043; padding: 0.75rem; text-align: left; }
        .help-content th { background-color: #2a2b2d; }
        .help-content a { color: #89B3F8; text-decoration: none; }
        .help-content a:hover { text-decoration: underline; }
    </style>
</head>
<body class="text-slate-300 p-4 md:p-8">
    <div id="sos-banner" style="display: none;" class="fixed top-0 left-0 w-full text-white text-center p-3 z-[1100] font-bold text-lg flex justify-between items-center">
        <span id="sos-banner-text" class="flex-grow text-center"></span>
        <button id="sos-banner-close" class="text-white text-3xl font-bold px-4 leading-none">×</button>
    </div>
    
    <div class="max-w-7xl mx-auto">
        <header class="mb-10 flex justify-between items-center">
            <div class="flex items-center gap-4">
                <img src="/map-items/map-logo.png" alt="Gateway Logo" class="h-14 w-12">
                <div>
                    <h1 class="text-4xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-red-400 bg-clip-text text-transparent">GuardianBridge Control</h1>
                    <p class="text-slate-400 mt-1">Administrator Panel for GuardianBridge</p>
                </div>
            </div>
            <div><a href="?logout=true" class="btn btn-secondary">Logout</a></div>
        </header>

        <?php if ($message): ?>
            <div class="bg-green-500/10 border border-green-500/20 text-green-300 px-4 py-3 rounded-lg relative mb-6" role="alert"><?= $message ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="bg-red-500/10 border border-red-500/20 text-red-300 px-4 py-3 rounded-lg relative mb-6" role="alert"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <div class="flex border-b border-slate-700/50 mb-6">
            <a data-tab="status" class="tab-button py-3 px-6 font-medium active">Status</a>
            <a data-tab="chat" class="tab-button py-3 px-6 font-medium">Chat</a>
            <a data-tab="actions" class="tab-button py-3 px-6 font-medium">Actions</a>
            <a data-tab="broadcasts" class="tab-button py-3 px-6 font-medium">Broadcasts</a>
            <a data-tab="users" class="tab-button py-3 px-6 font-medium">Users</a>
            <a data-tab="settings" class="tab-button py-3 px-6 font-medium">Settings</a>
            <a data-tab="help" class="tab-button py-3 px-6 font-medium">Help/About</a>
        </div>

        <main>
            <div id="status-content" class="tab-content">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="card p-6">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">System Health</h2>
                        <div class="space-y-4 text-slate-300">
                            <?php
                                $service_status_raw = trim(shell_exec('systemctl is-active guardianbridge.service'));
                                if ($service_status_raw === 'active') {
                                    echo '<p class="flex items-center"><span class="font-bold status-ok mr-3 text-lg">●</span> Dispatcher Service is ACTIVE</p>';
                                } else {
                                    echo '<p class="flex items-center"><span class="font-bold status-fail mr-3 text-lg">●</span> Dispatcher Service is INACTIVE or 
FAILED</p>';
                                }
                                $radio_ok = $dispatcher_status['radio_connected'] ?? false;
                                echo '<p class="flex items-center"><span class="font-bold ' . ($radio_ok ? 'status-ok' : 'status-fail') . ' mr-3 text-lg">●</span> 
Radio Connection Status</p>';
                                $weather_lastrun_age = file_exists($weather_fetcher_lastrun_file) ? time() - filemtime($weather_fetcher_lastrun_file) : 9999;
                                echo '<p class="flex items-center"><span class="font-bold ' . ($weather_lastrun_age < 1800 ? 'status-ok' : 'status-warn') . ' mr-3 
text-lg">●</span> Weather Fetcher Cron (Last run: ' . get_file_age_string($weather_fetcher_lastrun_file) . ')</p>';
                                $email_lastrun_age = file_exists($email_processor_lastrun_file) ? time() - filemtime($email_processor_lastrun_file) : 9999;
                                echo '<p class="flex items-center"><span class="font-bold ' . ($email_lastrun_age < 600 ? 'status-ok' : 'status-warn') . ' mr-3 text-lg">●</span> Email Processor Cron (Last run: ' . get_file_age_string($email_processor_lastrun_file) . ')</p>';
                            ?>
                        </div>
                    </div>
                    <div class="card p-6">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Weather & Alerts</h2>
                        <div>
                            <h3 class="font-semibold text-lg text-blue-400">Current Weather</h3>
                            <p class="text-slate-300 mt-1">Temp: <span class="font-medium text-slate-100"><?= htmlspecialchars($weather_current['temperature_f'] ?? 'N/A') ?>°F</span>, Humidity: <span class="font-medium text-slate-100"><?= htmlspecialchars($weather_current['humidity'] ?? 'N/A') ?>% RH</span></p>
                        </div>
                        <div class="mt-4">
                            <h3 class="font-semibold text-lg text-yellow-400">Active NWS Alerts</h3>
                            <?php if (!empty($weather_alerts)): ?>
                                <p class="text-slate-300 mt-1"><?= htmlspecialchars($weather_alerts[0]['headline'] ?? 'N/A') ?></p>
                            <?php else: ?>
                                <p class="text-slate-500 mt-1">No active alerts.</p>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <div id="map" class="mt-6"></div>

                <div class="card p-6 mt-6">
                    <h2 class="text-2xl font-bold mb-4 text-slate-100">Live Node List (<span id="node-list-count">...</span>)</h2>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left min-w-[600px]">
                            <thead class="bg-black/20 border-b-2 border-slate-700/50">
                                <tr>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Node ID / Name</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Last Contact</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">SNR</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Hops</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Role</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Position</th>
                                    <th class="p-3 font-semibold text-sm text-slate-400 uppercase">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="node-list-body" class="divide-y divide-slate-700/50">
                                <tr><td colspan="7" class="p-8 text-center text-slate-500">Loading live node data...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div id="chat-content" class="tab-content" style="display: none;">
                <div class="card flex flex-col h-[70vh]">
                    <h2 class="text-2xl font-bold text-slate-100 p-6 border-b border-slate-700/50 flex justify-between items-center">
                        <span>Channel Traffic</span>
                        <div class="flex items-center gap-4">
                            <div class="flex items-center gap-x-3 text-sm text-slate-400">
                                <label class="flex items-center gap-2 cursor-pointer"><input type="checkbox" id="show-dms-checkbox" class="filter-checkbox h-4 w-4"> DMs</label>
                                <label class="flex items-center gap-2 cursor-pointer"><input type="checkbox" id="show-sms-checkbox" class="filter-checkbox h-4 w-4"> Server Msgs</label>
                            </div>
                        </div>
                    </h2>
                    <div id="chat-window" class="flex-grow p-6 overflow-y-auto">
                        <div class="space-y-4" id="chat-messages-container">
                            <div class="text-center text-slate-500 py-16"><p>Loading messages...</p></div>
                        </div>
                    </div>
                    <div class="p-4 border-t border-slate-700/50">
                        <div id="chat-form" class="flex items-center gap-2">
                            <textarea id="main-chat-textarea" rows="2" placeholder="Type message or @user message..." class="flex-grow resize-none"></textarea>
                            <button type="button" id="main-chat-bell-btn" class="btn btn-secondary">Bell</button>
                            <button type="button" id="main-chat-send-btn" class="btn btn-primary">Send</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="actions-content" class="tab-content" style="display: none;">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="card p-6">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Manual Actions</h2>
                        <div class="flex flex-col sm:flex-row gap-4">
                            <form method="POST"><input type="hidden" name="action" value="run_weather_fetcher"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>"><button type="submit" class="btn btn-secondary w-full sm:w-auto">Fetch Weather Now</button></form>
                            <form method="POST"><input type="hidden" name="action" value="run_email_processor"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>"><button type="submit" class="btn btn-secondary w-full sm:w-auto">Process Emails Now</button></form>
                            <form method="POST" id="clear-chat-history-form">
                                <input type="hidden" name="action" value="clear_chat_history">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red w-full sm:w-auto">Clear Message History</button>
                            </form>
                        </div>
                    </div>
                     <div class="card p-6">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Outgoing Email Queue (<?= count($outgoing_emails) ?>)</h2>
                        <?php if (!empty($outgoing_emails)): ?>
                            <div class="space-y-2 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                                <?php foreach($outgoing_emails as $email): ?>
                                    <div class="bg-black/20 p-3 rounded text-sm">
                                        <span class="font-medium text-slate-300">To:</span> <span class="text-slate-400"><?= htmlspecialchars($email['recipient']) 
?></span><br>
                                        <span class="font-medium text-slate-300">Subject:</span> <span class="text-slate-400"><?= htmlspecialchars($email['subject']) 
?></span>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <form method="POST" class="mt-4" id="clear-email-queue-form">
                                <input type="hidden" name="action" value="clear_email_queue">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red">Clear Queue</button>
                            </form>
                        <?php else: ?>
                            <p class="text-slate-500">The outgoing email queue is empty.</p>
                        <?php endif; ?>
                    </div>
                    <div class="card p-6 md:col-span-2">
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Queued Direct Messages (<?= count($failed_dms) ?>)</h2>
                        <?php if (!empty($failed_dms)): ?>
                            <div class="space-y-2 max-h-60 overflow-y-auto border border-slate-700 rounded-md p-3">
                                <?php foreach($failed_dms as $dm): ?>
                                    <div class="bg-black/20 p-3 rounded text-sm">
                                        <span class="font-medium text-slate-300">To:</span> <span class="text-slate-400 font-mono"><?= htmlspecialchars($dm['destination_id']) ?></span><br>
                                        <span class="font-medium text-slate-300">Queued:</span> <span class="text-slate-400"><?= htmlspecialchars(date("Y-m-d H:i:s", 
strtotime($dm['timestamp']))) ?></span><br>
                                        <span class="font-medium text-slate-300">Text:</span> <span class="text-slate-400"><?= htmlspecialchars($dm['text']) ?></span>                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <p class="text-slate-500">The direct message queue is empty.</p>
                        <?php endif; ?>
                    </div>
                    <div class="card p-6 md:col-span-2">
                        <h2 class="text-2xl font-bold mb-4 text-red-400">SOS Alert Log</h2>
                        
                        <?php if (!empty($sos_log)): ?>
                            <div class="space-y-3 max-h-96 overflow-y-auto border border-slate-700 rounded-md p-3">
                                <?php foreach(array_reverse($sos_log) as $log): // Show most recent first ?>
                                    <div class="bg-red-900/30 p-4 rounded-lg">
                                        <div class="flex justify-between items-center mb-2">
                                            <span class="font-bold text-lg text-red-300">SOS: <?= htmlspecialchars($log['sos_type'] ?? 'GENERAL') ?></span>
                                            <span class="text-sm text-slate-400"><?= htmlspecialchars(date("Y-m-d H:i", strtotime($log['timestamp']))) ?></span>
                                        </div>
                                        <p class="font-mono text-sm">Node: <?= htmlspecialchars($log['node_id']) ?></p>
                                        <p>User: <b><?= htmlspecialchars($log['user_info']['name'] ?? 'N/A') ?></b> / <?= htmlspecialchars($log['user_info']['full_name'] ?? 'N/A') ?></p>
                                        <?php if(!empty($log['user_info']['phone_1'])): ?>
                                            <p>Phone: <?= htmlspecialchars($log['user_info']['phone_1']) ?></p>
                                        <?php endif; ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <p class="text-slate-500">The SOS log is empty.</p>
                        <?php endif; ?>

                        <div class="mt-4 flex flex-wrap gap-4 items-center">
                            <?php if ($active_sos_node_id): ?>
                                <form method="POST" id="admin-clear-sos-form">
                                    <input type="hidden" name="action" value="admin_clear_sos">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                    <input type="hidden" name="node_id" value="<?= htmlspecialchars($active_sos_node_id) ?>">
                                    <button type="submit" class="btn btn-green" title="Triggers the full stand-down protocol for this SOS.">Admin Clear SOS</button>
                                </form>
                            <?php else: ?>
                                <button class="btn btn-secondary" disabled title="No active SOS detected in node_status.json">Admin Clear SOS</button>
                            <?php endif; ?>

                            <form method="POST" id="clear-sos-log-form">
                                <input type="hidden" name="action" value="clear_sos_log">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                <button type="submit" class="btn btn-red">Clear SOS Log</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <div id="broadcasts-content" class="tab-content" style="display: none;">
                <div class="card overflow-x-auto">
                    <div class="p-6"><h2 class="text-2xl font-bold text-slate-100">Manage Custom Broadcasts</h2></div>
                    <table class="w-full text-left min-w-[1000px]">
                        <thead class="bg-black/20 border-b-2 border-slate-700/50">
                            <tr>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Status</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Broadcast Name</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Active Days</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Interval</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Time / Date Window</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-700/50">
                            <?php if (!empty($dispatcher_jobs)): foreach ($dispatcher_jobs as $index => $job): 
                                // Add index to job data for the modal
                                $job['job_index'] = $index;
                            ?>
                            <tr class="hover:bg-black/20">
                                <td class="p-4">
                                    <?php $enabled = $job['enabled'] ?? false; ?>
                                    <span class="flex items-center">
                                        <span class="font-bold <?= $enabled ? 'status-ok' : 'text-slate-500' ?> mr-2 text-lg">●</span>
                                        <?= $enabled ? 'Enabled' : 'Disabled' ?>
                                    </span>
                            </td>
                            <td class="p-4 font-medium"><?= htmlspecialchars($job['name'] ?? 'N/A') ?></td>
                                <td class="p-4 font-mono text-sm">
                                    <?php
                                    if (isset($job['days'])) {
                                        foreach ($days_of_week as $day) {
                                            $is_active = in_array($day, $job['days']);
                                            $char = substr($day, 0, 1);
                                            echo '<span class="' . ($is_active ? 'text-blue-400' : 'text-slate-600') . '">' . $char . '</span> ';
                                        }
                                    } else {
                                        echo '<span class="text-slate-500">Event</span>';
                                    }
                                    ?>
                                </td>
                                <td class="p-4"><?= htmlspecialchars($job['interval_mins'] ?? 'N/A') ?> mins</td>
                                <td class="p-4">
                                    <?php 
                                    if (isset($job['start_datetime'])) {
                                        echo htmlspecialchars($job['start_datetime']) . ' to ' . htmlspecialchars($job['stop_datetime']);
                                    } else {
                                        echo htmlspecialchars($job['start_time'] ?? 'N/A') . ' - ' . htmlspecialchars($job['stop_time'] ?? 'N/A');
                                    }
                                    ?>
                                </td>
                                <td class="p-4">
                                    <button type="button" class="btn btn-secondary text-sm open-broadcast-edit-modal" data-job-data="<?= htmlspecialchars(json_encode($job), ENT_QUOTES, 'UTF-8') ?>">
                                        More...
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; else: ?>
                                <tr><td colspan="5" class="p-8 text-center text-slate-500">No custom broadcast jobs found.</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                <div class="mt-8 pt-6 border-t border-slate-700/50">
                    <h3 class="text-xl font-bold mb-4 text-slate-100">Add New Broadcast</h3>
                    <form method="POST" class="card p-6 flex flex-wrap items-end gap-4">
                        <input type="hidden" name="action" value="add_broadcast_job">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <div class="flex-grow">
                            <label for="new_broadcast_name">New Broadcast Name</label>
                            <input type="text" id="new_broadcast_name" name="new_broadcast_name" placeholder="E.g., Daily Weather Summary" required>
                        </div>
                        <div>
                            <button type="submit" class="btn btn-primary">Add Broadcast</button>
                        </div>
                    </form>
                </div>
            </div>

            <div id="users-content" class="tab-content" style="display: none;">
                 <div class="card overflow-x-auto">
                    <div class="p-6"><h2 class="text-2xl font-bold text-slate-100">Manage Subscribers</h2></div>
                    <table class="w-full text-left min-w-[1000px]">
                        <thead class="bg-black/20 border-b-2 border-slate-700/50">
                            <tr>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Node ID</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Username</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Role</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Full Name</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Phone 1</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Tags</th>
                                <th class="p-4 font-semibold text-sm text-slate-400 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-700/50">
                            <?php if (!empty($subscribers)): foreach ($subscribers as $node_id => $user): 
                                // Ensure user data is consistent for the modal
                                $user['node_id'] = $node_id; 
                            ?>
                            <tr class="hover:bg-black/20">
                                <td class="p-4 font-mono">
                                    <button type="button" class="text-blue-400 hover:text-blue-300 open-dm-chat" 
                                            data-node-id="<?= htmlspecialchars($node_id) ?>" 
                                            data-node-name="<?= htmlspecialchars($user['name'] ?? $node_id) ?>">
                                        <?= htmlspecialchars($node_id) ?>
                                    </button>
                                </td>
                                <td class="p-4"><?= htmlspecialchars($user['name'] ?? '') ?></td>
                                <td class="p-4">
                                    <?php
                                        // Get the assigned and reported roles
                                        $assigned_role = $user['role'] ?? 'Not Set';
                                        $reported_role_data = $node_statuses[$node_id] ?? null;
                                        $reported_role = $reported_role_data ? htmlspecialchars($reported_role_data['role']) : 'Unknown';

                                        // Determine color based on match
                                        $is_match = (strtoupper($assigned_role) === strtoupper($reported_role));
                                        $color_class = $is_match ? 'text-green-400' : 'text-yellow-400';

                                        if ($reported_role === 'Unknown') {
                                            $color_class = 'text-slate-500';
                                        }
                                    ?>
                                    <div class="flex items-center gap-2">
                                        <span class="font-mono text-xs p-1 rounded bg-slate-700 <?= $color_class ?>" title="This is the role being reported by the 
radio node right now. Green means it matches the assigned role.">
                                            <?= $reported_role ?>
                                        </span>
                                        <span class="font-medium">
                                            <?= htmlspecialchars($assigned_role) ?>
                                        </span>
                                    </div>
                                </td>
                                <td class="p-4"><?= htmlspecialchars($user['full_name'] ?? '') ?></td>
                                <td class="p-4"><?= htmlspecialchars($user['phone_1'] ?? '') ?></td>
                                <td class="p-4 text-slate-400 text-xs">
                                    <?php
                                    if (!empty($user['tags']) && is_array($user['tags'])) {
                                        foreach ($user['tags'] as $tag) {
                                            echo '<span class="inline-block bg-slate-700 rounded-full px-2 py-1 font-semibold mr-1 mb-1">' . htmlspecialchars($tag) . 
'</span>';
                                        }
                                    }
                                    ?>
                                </td>
                                <td class="p-4">
                                    <button type="button" class="btn btn-secondary text-sm open-user-edit-modal" data-user-data="<?= htmlspecialchars(json_encode($user), ENT_QUOTES, 'UTF-8') ?>">
                                        More...
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; else: ?>
                                <tr><td colspan="7" class="p-8 text-center text-slate-500">Subscribers file is empty or not readable.</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                <div class="mt-8 pt-6 border-t border-slate-700/50">
                    <h3 class="text-xl font-bold mb-4 text-slate-100">Add New Subscriber</h3>
                    <form method="POST" class="card p-6 flex flex-wrap items-end gap-4">
                        <input type="hidden" name="action" value="add_user">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <div>
                            <label for="new_node_id">Node ID</label>
                            <input type="text" id="new_node_id" name="new_node_id" placeholder="!a1b2c3d4" required class="font-mono">
                        </div>
                        <div>
                            <label for="new_name">Username</label>
                            <input type="text" id="new_name" name="new_name" placeholder="New User" required>
                        </div>
                        <div>
                            <button type="submit" class="btn btn-primary">Add User</button>
                        </div>
                    </form>
                </div>
            </div>

            <div id="settings-content" class="tab-content" style="display: none;">
                <div class="card p-6">
                    <h2 class="text-2xl font-bold mb-4 text-slate-100">Manageable Settings</h2>
                     <div class="bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 p-4 rounded-lg mb-6">
                        <strong>Important:</strong> After saving changes, you must restart the dispatcher service from the terminal for them to take effect.<br>
                        <code class="bg-yellow-400/10 text-yellow-200 px-1 py-0.5 rounded text-sm mt-1 inline-block">sudo systemctl restart guardianbridge.service</code>
                    </div>
                    <form method="POST" id="save-settings-form">
                        <input type="hidden" name="action" value="update_settings">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <div class="space-y-8">
                            <?php 
                                $all_settings = get_env_settings($env_file, $manageable_settings);
                                foreach ($manageable_settings as $key): 
                                    $value = $all_settings[$key] ?? '';
                                    $label = ucwords(strtolower(str_replace('_', ' ', $key)));
                                    $description = $setting_descriptions[$key] ?? 'No description available.';

                                    $input_type = 'text';
                                    $display_value = $value;
                                    $placeholder = '';

                                    if ($key === 'EMAIL_PASS') {
                                        $input_type = 'password';
                                        if (!empty($value)) {
                                            $display_value = '********';
                                            $placeholder = 'Leave unchanged to keep current password';
                                        } else {
                                            $display_value = '';
                                            $placeholder = 'Enter email password or App Password';
                                        }
                                    }
                            ?>
                            <div class="border-b border-slate-700/50 pb-8 last:border-b-0">
                                <label for="setting_<?= htmlspecialchars($key) ?>" class="text-base font-semibold text-slate-200"><?= htmlspecialchars($label) ?></label>
                                <p class="text-slate-400 text-sm mt-1 mb-3 max-w-3xl"><?= htmlspecialchars($description) ?></p>
                                <input 
                                    type="<?= $input_type ?>" 
                                    id="setting_<?= htmlspecialchars($key) ?>" 
                                    name="settings[<?= htmlspecialchars($key) ?>]" 
                                    value="<?= htmlspecialchars($display_value) ?>" 
                                    placeholder="<?= htmlspecialchars($placeholder) ?>"
                                    class="max-w-lg">
                            </div>
                            <?php endforeach; ?>
                        </div>
                        <div class="mt-8"><button type="submit" class="btn btn-primary">Save Settings</button></div>
                    </form>
                </div>
            </div>
            <div id="help-content" class="tab-content" style="display: none;">
                <div class="card p-6 md:p-8 text-slate-300 space-y-6 help-content">
                    <?php
                        $help_file = '/opt/GuardianBridge/Docs/help_about.html';
                        if (file_exists($help_file)) {
                            include($help_file);
                        } else {
                            echo '<p class="text-red-400">Error: help_about.html file not found at: /opt/GuardianBridge/Docs/help_about.html.</p>';
                        }
                    ?>
                </div>
            </div>
            
        </main>
        
        <footer class="mt-12 pt-6 border-t border-slate-700/50 text-center text-sm text-slate-500">
            <p>
                GuardianBridge Admin Panel | Revision: <?= htmlspecialchars($revision) ?>
            </p>
            <p class="mt-2">
                Copyright © <?php echo date('Y'); ?> Robert Kolbasowski. All Rights Reserved.
            </p>
        </footer>
    </div>

<div id="dm-chat-modal" class="fixed inset-0 bg-black/70 items-center justify-center" style="display: none;">
    <div class="card w-full max-w-2xl h-[80vh] flex flex-col mx-4">
        <h2 id="dm-chat-title" class="text-xl font-bold text-slate-100 p-4 border-b border-slate-700/50 flex justify-between items-center">
            <span class="font-mono">Direct Chat</span>
            <button id="close-dm-modal-btn" class="text-slate-400 hover:text-white text-3xl leading-none">×</button>
        </h2>
        <div id="dm-chat-window" class="flex-grow p-4 overflow-y-auto">
            <div class="space-y-4" id="dm-chat-messages-container">
            </div>
        </div>
        <div class="p-4 border-t border-slate-700/50">
            <form id="dm-chat-form" onsubmit="return false;">
                <input type="hidden" id="dm-target-node-id-input">
                <div class="flex items-center gap-2">
                    <textarea id="dm-chat-textarea" rows="2" placeholder="Send a direct message..." class="flex-grow resize-none"></textarea>
                    <button type="button" id="dm-chat-bell-btn" class="btn btn-secondary">Bell</button>
                    <button type="submit" id="dm-chat-send-btn" class="btn btn-primary">Send</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div id="user-edit-modal" class="fixed inset-0 bg-black/70 items-center justify-center" style="display: none;">
    <div class="card w-full max-w-4xl max-h-[90vh] flex flex-col mx-4">
        <h2 id="user-modal-title" class="text-xl font-bold text-slate-100 p-4 border-b border-slate-700/50 flex justify-between items-center">
            <span class="font-mono">Edit User</span>
            <button id="close-user-modal-btn" class="text-slate-400 hover:text-white text-3xl leading-none">×</button>
        </h2>
        <div class="p-6 overflow-y-auto">
            <form id="user-edit-form" method="POST">
                <input type="hidden" name="action" value="update_user">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                <input type="hidden" name="node_id" value="">
                
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-5">
                    <div>
                        <label for="name">Username</label>
                        <input type="text" name="name" id="name" required>
                    </div>
                    <div>
                        <label for="full_name">Full Name</label>
                        <input type="text" name="full_name" id="full_name">
                    </div>
                    <div>
                        <label for="user_role">Assigned Role</label>
                        <select name="role" id="user_role">
                            <option value="">Not Set</option>
                            <option value="CLIENT">CLIENT (Default Repeater)</option>
                            <option value="CLIENT_MUTE">CLIENT_MUTE (No Repeat)</option>
                            <option value="ROUTER">ROUTER (Fixed Repeater)</option>
                            <option value="REPEATER">REPEATER (Legacy Repeater)</option>
                        </select>
                    </div>
                     <div>
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email">
                    </div>
                    <div>
                        <label for="phone_1">Phone 1</label>
                        <input type="text" name="phone_1" id="phone_1">
                    </div>
                    <div>
                        <label for="phone_2">Phone 2</label>
                        <input type="text" name="phone_2" id="phone_2">
                    </div>
                    
                    <div class="lg:col-span-2"></div> 
                    <div class="lg:col-span-2">
                        <label for="address_street">Street Address</label>
                        <input type="text" name="address_street" id="address_street">
                    </div>
                     <div>
                        <label for="address_city">City</label>
                        <input type="text" name="address_city" id="address_city">
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label for="address_state">State</label>
                            <input type="text" name="address_state" id="address_state">
                        </div>
                        <div>
                            <label for="address_zip">Zip Code</label>
                            <input type="text" name="address_zip" id="address_zip">
                        </div>
                    </div>

                    <div class="lg:col-span-4 md:col-span-2">
                        <label for="notes">Notes</label>
                        <textarea name="notes" id="notes" rows="4" class="font-mono text-sm"></textarea>
                    </div>
                    
                    <div class="lg:col-span-4 md:col-span-2">
                        <label for="tags">Tags (comma-separated)</label>
                        <input type="text" id="tags" name="tags" placeholder="CERT, MEDICAL, TEAMLEAD" class="font-mono text-sm">
                    </div>
                    
                    <div class="lg:col-span-4 md:col-span-2">
                        <label>Subscriptions & Permissions</label>
                        <div class="flex flex-wrap gap-x-6 gap-y-2 mt-2 p-3 bg-black/20 rounded-md">
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="alerts"> NWS Alerts</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="weather"> Weather Reports</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="scheduled_daily_forecast"> Daily Forecast</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="email_send"> Email Send</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="email_receive"> Email Receive</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="emailbroadcast"> Email Broadcast</label>
                            <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer"><input type="checkbox" name="node_tag_send"> Node Tag 
Send</label>
                        </div>
                    </div>
                    
                    <div class="lg:col-span-4 md:col-span-2 pt-4 mt-4 border-t border-slate-700/50">
                        <label class="text-red-400 font-bold">Administrative Actions</label>
                        <div class="mt-2 p-3 bg-red-900/20 rounded-md">
                            <label class="flex items-center gap-2 font-normal text-red-300 cursor-pointer">
                                <input type="checkbox" name="blocked" class="h-4 w-4">
                                Block User (Ignore all commands from this node)
                            </label>
                        </div>
                    </div>
                </div>
            </form>
        </div>
         <div class="p-4 border-t border-slate-700/50 bg-slate-800/20 flex justify-between items-center">
             <button type="button" id="close-user-modal-btn-footer" class="btn btn-secondary">Close</button>
            <div class="flex items-center gap-4">
                 <form id="user-modal-delete-form" method="POST">
                    <input type="hidden" name="action" value="delete_user">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                    <input type="hidden" name="node_id" value="">
                    <button type="submit" class="btn btn-red">Delete User</button>
                </form>
                <button type="submit" form="user-edit-form" class="btn btn-green">Save Changes</button>
            </div>
        </div>
    </div>
</div>

<div id="broadcast-edit-modal" class="fixed inset-0 bg-black/70 items-center justify-center" style="display: none;">
    <div class="card w-full max-w-4xl max-h-[90vh] flex flex-col mx-4">
        <h2 id="broadcast-modal-title" class="text-xl font-bold text-slate-100 p-4 border-b border-slate-700/50 flex justify-between items-center">
            <span>Edit Broadcast</span>
            <button id="close-broadcast-modal-btn" class="text-slate-400 hover:text-white text-3xl leading-none">×</button>
        </h2>
        <div class="p-6 overflow-y-auto">
            <form id="broadcast-edit-form" method="POST" class="space-y-4">
                <input type="hidden" name="action" value="save_broadcast_job">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                <input type="hidden" name="job_index" value="">
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label>Broadcast Name</label>
                        <input type="text" name="name" required>
                    </div>
                    <div>
                        <label>Interval (minutes)</label>
                        <input type="number" name="interval_mins" value="60" min="1" required>
                    </div>
                </div>
                
                <div>
                    <label>Broadcast Content</label>
                    <textarea name="content" rows="3" required></textarea>
                </div>

                <div class="pt-2">
                    <label class="flex items-center gap-2 font-normal text-slate-400 cursor-pointer">
                        <input type="checkbox" name="with_bell" value="true" class="w-auto h-4 w-4">
                        Bell (Prepend alert with audible bell character)
                    </label>
                </div>

                <div class="pt-4 mt-4 border-t border-slate-700/50">
                    <label class="flex items-center gap-2 font-semibold text-slate-300 cursor-pointer">
                        <input type="checkbox" name="enabled" value="true" class="h-4 w-4">
                        Enable this broadcast job
                    </label>
                    <p class="text-sm text-slate-500 mt-1 pl-6">The dispatcher will ignore this job unless this box is checked.</p>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                    <div>
                        <label>Job Type</label>
                        <select name="job_type" class="job-type-selector">
                            <option value="recurring">Recurring Day/Time</option>
                            <option value="event">Specific Date/Time Event</option>
                        </select>
                    </div>
                </div>

                <div class="recurring-fields space-y-3">
                    <div>
                        <label>Days of Week</label>
                        <div class="flex flex-wrap gap-x-4 gap-y-2 mt-2 p-3 bg-black/20 rounded-md">
                        <?php foreach ($days_of_week as $day): ?>
                            <label class="flex items-center gap-2 font-normal text-slate-400"><input type="checkbox" name="days[]" value="<?= $day ?>" class="w-auto h-4 w-4"> <?= 
$day ?></label>
                        <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div><label>Start Time</label><input type="time" name="start_time"></div>
                        <div><label>Stop Time</label><input type="time" name="stop_time"></div>
                    </div>
                </div>

                <div class="event-fields space-y-2">
                    <div class="grid grid-cols-2 gap-4">
                        <div><label>Start Date & Time</label><input type="datetime-local" name="start_datetime"></div>
                        <div><label>Stop Date & Time</label><input type="datetime-local" name="stop_datetime"></div>
                    </div>
                </div>
            </form>
        </div>
        <div class="p-4 border-t border-slate-700/50 bg-slate-800/20 flex justify-between items-center">
            <button type="button" id="close-broadcast-modal-btn-footer" class="btn btn-secondary">Close</button>
            <div class="flex items-center gap-4">
                <form id="broadcast-modal-delete-form" method="POST">
                    <input type="hidden" name="action" value="delete_broadcast_job">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                    <input type="hidden" name="job_index" value="">
                    <button type="submit" class="btn btn-red">Delete Job</button>
                </form>
                <button type="submit" form="broadcast-edit-form" class="btn btn-green">Save Changes</button>
            </div>
        </div>
    </div>
</div>

<div id="confirm-action-modal" class="fixed inset-0 bg-black/70 items-center justify-center" style="display: none;">
    <div class="card w-full max-w-md mx-4">
        <div class="p-6">
            <h2 class="text-2xl font-bold text-slate-100 mb-4">Confirm Your Action</h2>
            <p id="confirm-modal-text" class="text-slate-300 mb-6">Are you sure you wish to proceed?</p>
        </div>
        <div class="p-4 border-t border-slate-700/50 bg-slate-800/20 flex justify-end items-center gap-4">
            <button type="button" id="confirm-modal-cancel-btn" class="btn btn-secondary">Cancel</button>
            <button type="button" id="confirm-modal-confirm-btn" class="btn btn-red">Confirm</button>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // --- GLOBAL STATE & CONFIG ---
        let nodeDataInterval, chatUpdateInterval, dashboardUpdateInterval; // Added dashboardUpdateInterval
        let isStatusTabInitialized = false, isChatTabInitialized = false;
        
        let map;
        let nodeMarkers = {};
        const acknowledgedSosNodes = new Set();
        let activeSosNodeId = null;
        let autoFitEnabled = true; // Flag to control map auto-zoom
        const POLLING_INTERVAL = 5000;
        const CHAT_POLLING_INTERVAL = 4000;
        const GATEWAY_LAT = <?= json_encode($gateway_lat) ?>;
        const GATEWAY_LON = <?= json_encode($gateway_lon) ?>;
        L.Icon.Default.imagePath = '/map-items/';

        // --- NEW FUNCTION TO UPDATE DASHBOARD PANELS ---
        async function updateDashboardData() {
            try {
                const response = await fetch('/map-items/api_get_dashboard.php');
                if (!response.ok) {
                    console.error('Failed to fetch dashboard data');
                    return;
                }
                const data = await response.json();

                // 1. Update System Health Panel
                const healthContainer = document.querySelector('#status-content .card .space-y-4');
                if (healthContainer) {
                    const health = data.system_health;
                    healthContainer.innerHTML = `
                        <p class="flex items-center"><span class="font-bold ${health.dispatcher_active ? 'status-ok' : 'status-fail'} mr-3 text-lg">●</span> Dispatcher Service is ${health.dispatcher_active ? 'ACTIVE' : 'INACTIVE or FAILED'}</p>
                        <p class="flex items-center"><span class="font-bold ${health.radio_connected ? 'status-ok' : 'status-fail'} mr-3 text-lg">●</span> Radio Connection Status</p>
                        <p class="flex items-center"><span class="font-bold ${health.weather_fetcher_ok ? 'status-ok' : 'status-warn'} mr-3 text-lg">●</span> Weather Fetcher Cron (Last run: ${health.weather_fetcher_last_run})</p>
                        <p class="flex items-center"><span class="font-bold ${health.email_processor_ok ? 'status-ok' : 'status-warn'} mr-3 text-lg">●</span> Email Processor Cron (Last run: ${health.email_processor_last_run})</p>
                    `;
                }

                // 2. Update Weather & Alerts Panel
                const weatherContainer = document.querySelector('#status-content .grid > .card:nth-child(2)');
                if (weatherContainer) {
                    const weather = data.weather_info;
                    weatherContainer.innerHTML = `
                        <h2 class="text-2xl font-bold mb-4 text-slate-100">Weather & Alerts</h2>
                        <div>
                            <h3 class="font-semibold text-lg text-blue-400">Current Weather</h3>
                            <p class="text-slate-300 mt-1">Temp: <span class="font-medium text-slate-100">${weather.temperature_f}°F</span>, Humidity: <span class="font-medium text-slate-100">${weather.humidity}% RH</span></p>
                        </div>
                        <div class="mt-4">
                            <h3 class="font-semibold text-lg text-yellow-400">Active NWS Alerts</h3>
                            <p class="text-slate-300 mt-1">${weather.active_alert}</p>
                        </div>
                    `;
                }

                // 3. Update SOS Alert Log Panel
                const sosLogContainer = document.querySelector('#actions-content .card:nth-child(4)');
                if (sosLogContainer) {
                    const sosLogContent = sosLogContainer.querySelector('.space-y-3');
                    const sosLog = data.sos_log;
                    if (sosLogContent) {
                        if (sosLog.length > 0) {
                            let sosHtml = '';
                            sosLog.forEach(log => {
                                const date = new Date(log.timestamp).toLocaleString();
                                const phoneHtml = (log.user_info && log.user_info.phone_1) ? `<p>Phone: ${escapeHTML(log.user_info.phone_1)}</p>` : '';
                                sosHtml += `
                                    <div class="bg-red-900/30 p-4 rounded-lg">
                                        <div class="flex justify-between items-center mb-2">
                                            <span class="font-bold text-lg text-red-300">SOS: ${escapeHTML(log.sos_type || 'GENERAL')}</span>
                                            <span class="text-sm text-slate-400">${date}</span>
                                        </div>
                                        <p class="font-mono text-sm">Node: ${escapeHTML(log.node_id)}</p>
                                        <p>User: <b>${escapeHTML(log.user_info.name || 'N/A')}</b> / ${escapeHTML(log.user_info.full_name || 'N/A')}</p>
                                        ${phoneHtml}
                                    </div>
                                `;
                            });
                            sosLogContent.innerHTML = sosHtml;
                        } else {
                            sosLogContent.innerHTML = '<p class="text-slate-500">The SOS log is empty.</p>';
                        }
                    }
                }
            } catch (error) {
                console.error('Error updating dashboard data:', error);
            }
        }

        // --- UTILITY FUNCTIONS ---
        function escapeHTML(str) {
            if (typeof str !== 'string') return '';
            return str.replace(/[&<>"']/g, tag => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            } [tag] || tag));
        }

        function getAgeStringFromTimestamp(timestamp) {
            if (!timestamp) return '<span class="text-slate-500">Never</span>';
            const now = Math.floor(Date.now() / 1000);
            const ageSeconds = now - timestamp;
            if (ageSeconds < 60) return `${Math.round(ageSeconds)}s ago`;
            if (ageSeconds < 3600) return `${Math.round(ageSeconds / 60)}m ago`;
            if (ageSeconds < 86400) return `${Math.round(ageSeconds / 3600)}h ago`;
            return `${Math.round(ageSeconds / 86400)}d ago`;
        }

        // --- MAP FUNCTIONS ---
        const defaultIcon = new L.Icon.Default();
        const sosIcon = new L.Icon({
            iconUrl: '/map-items/marker-icon-red.png',
            shadowUrl: '/map-items/marker-shadow.png',
            iconSize: [25, 41],
            iconAnchor: [12, 41],
            popupAnchor: [1, -34],
            shadowSize: [41, 41]
        });

        // --- CORE LIVE DATA & UI UPDATE FUNCTIONS ---
        const sosBanner = document.getElementById('sos-banner');
        const sosBannerText = document.getElementById('sos-banner-text');

        async function updatePageData() {
            try {
                const response = await fetch('/map-items/api_get_nodes.php');
                if (!response.ok) {
                    console.error('Failed to fetch node data. Status:', response.status);
                    return;
                }
                const nodes = await response.json();
                if (!Array.isArray(nodes)) return;

                const activeSosIds = new Set(nodes.filter(n => n.sos).map(n => n.node_id));
                acknowledgedSosNodes.forEach(nodeId => {
                    if (!activeSosIds.has(nodeId)) {
                        acknowledgedSosNodes.delete(nodeId);
                    }
                });

                updateNodeList(nodes);
                updateSosBanner(nodes);
                updateMapMarkers(nodes);

            } catch (error) {
                console.error('Error fetching node data:', error);
            }
        }

        function updateNodeList(nodes) {
            const nodeListBody = document.getElementById('node-list-body');
            const nodeListCount = document.getElementById('node-list-count');
            if (!nodeListBody || !nodeListCount) return;
            nodes.sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0));
            nodeListCount.textContent = nodes.length;
            nodeListBody.innerHTML = '';
            if (nodes.length === 0) {
                nodeListBody.innerHTML = '<tr><td colspan="7" class="p-8 text-center text-slate-500">No live node data available.</td></tr>';
                return;
            }
            nodes.forEach(node => {
                const isSos = node.sos ? 'bg-red-900/50' : 'hover:bg-black/20';
                const sosIndicator = node.sos ? `<span class="inline-block bg-red-500 text-white font-bold rounded-full px-2 py-1 text-xs mr-2">🆘 ${escapeHTML(node.sos)}</span>` : '';
                const locationButton = (node.latitude && node.longitude) ? `<button class="btn btn-secondary btn-sm location-btn" data-lat="${node.latitude}" data-lon="${node.longitude}">Map It</button>` : '';
                const position = (node.latitude && node.longitude) ? `${Number(node.latitude).toFixed(4)}, ${Number(node.longitude).toFixed(4)}` : '<span class="text-slate-600">N/A</span>';
                const row = `<tr class="${isSos}">
                                <td class="p-3 font-mono">${sosIndicator}<button type="button" class="text-blue-400 hover:text-blue-300 open-dm-chat" data-node-id="${escapeHTML(node.node_id)}" data-node-name="${escapeHTML(node.name || node.node_id)}">${escapeHTML(node.node_id)}</button>${node.name ? `<span class="text-slate-400 font-sans ml-2">(${escapeHTML(node.name)})</span>` : ''}</td>
                                <td class="p-3">${getAgeStringFromTimestamp(node.lastHeard)}</td><td class="p-3">${escapeHTML(String(node.snr))}</td><td class="p-3">${escapeHTML(String(node.hopsAway))}</td>
                                <td class="p-3 font-mono text-xs p-1 rounded bg-slate-700 text-slate-300">${escapeHTML(node.role)}</td>
                                <td class="p-3 font-mono text-sm">${position}</td><td class="p-3">${locationButton}</td>
                            </tr>`;
                nodeListBody.innerHTML += row;
            });
        }

        function updateSosBanner(nodes) {
            if (!sosBanner || !sosBannerText) return;
            activeSosNodeId = null; // Reset
            const activeSosNode = nodes.find(node => node.sos && !acknowledgedSosNodes.has(node.node_id));

            if (activeSosNode) {
                activeSosNodeId = activeSosNode.node_id;
                const name = activeSosNode.full_name || activeSosNode.name || activeSosNode.node_id;
                sosBannerText.textContent = `🚨 ACTIVE ALERT: ${escapeHTML(activeSosNode.sos)} from ${escapeHTML(name)} 🚨`;
                sosBanner.style.display = 'flex';
            } else {
                sosBanner.style.display = 'none';
            }
        }

        function updateMapMarkers(nodes) {
            if (!map) return;
            let nodesOnMap = new Set();
            let markersToBound = [];

            nodes.forEach(node => {
                if (node.latitude && node.longitude) {
                    const node_id = node.node_id;
                    const pos = [node.latitude, node.longitude];
                    nodesOnMap.add(node_id);

                    if (autoFitEnabled) {
                        markersToBound.push(pos);
                    }

                    let addressHtml = '';
                    if (node.address && (node.address.street || node.address.city)) {
                        addressHtml = `<hr class="popup-hr"><strong>Address:</strong><br>${escapeHTML(node.address.street || '')}<br>${escapeHTML(node.address.city || '')}, ${escapeHTML(node.address.state || '')} ${escapeHTML(node.address.zip || '')}`;
                    }
                    const phones = [node.phone_1, node.phone_2].filter(Boolean).map(escapeHTML).join('<br>');
                    let phonesHtml = phones ? `<hr class="popup-hr"><strong>Phone:</strong><br>${phones}` : '';
                    let emailHtml = node.email ? `<hr class="popup-hr"><strong>Email:</strong> ${escapeHTML(node.email)}` : '';
                    let notesHtml = node.notes ? `<hr class="popup-hr"><strong>Notes:</strong><br><div style="max-height: 60px; overflow-y: auto;">${escapeHTML(node.notes)}</div>` : '';

                    const popupContent = `
                        <div class="font-sans text-sm" style="max-width: 250px;">
                            <strong>${escapeHTML(node.node_id)} / ${escapeHTML(node.name || 'N/A')}</strong>
                            <hr class="popup-hr">
                            ${escapeHTML(node.full_name || 'No full name provided.')}
                            ${phonesHtml}
                            ${emailHtml}
                            ${addressHtml}
                            ${notesHtml}
                        </div>
                    `;

                    const icon = node.sos ? sosIcon : defaultIcon;
                    const labelContent = escapeHTML(node.name || node.node_id);
                    const normalTooltipOptions = { permanent: true, direction: 'top', className: 'map-node-label', offset: [-15, -5] };
                    const sosTooltipOptions = { permanent: true, direction: 'top', className: 'map-node-label', offset: [2, -33] };

                    if (nodeMarkers[node_id]) {
                        nodeMarkers[node_id].setLatLng(pos).setIcon(icon).setPopupContent(popupContent).unbindTooltip().bindTooltip(labelContent, node.sos ? sosTooltipOptions : normalTooltipOptions);
                    } else {
                        nodeMarkers[node_id] = L.marker(pos, { icon: icon }).addTo(map).bindPopup(popupContent).bindTooltip(labelContent, node.sos ? sosTooltipOptions : normalTooltipOptions)
                            .on('click', (e) => { autoFitEnabled = false; map.setView(e.latlng, map.getZoom()); })
                            .on('popupclose', () => { autoFitEnabled = true; });
                    }
                }
            });

            for (const node_id in nodeMarkers) {
                if (!nodesOnMap.has(node_id)) {
                    map.removeLayer(nodeMarkers[node_id]);
                    delete nodeMarkers[node_id];
                }
            }

            if (autoFitEnabled && markersToBound.length > 0) {
                map.fitBounds(markersToBound, { padding: [50, 50], maxZoom: 16, animate: true });
            }
        }
        
        // --- CHAT FUNCTIONS ---
        async function loadChatData() {
            try {
                const response = await fetch('/map-items/api_get_chat.php');
                if (!response.ok) {
                    console.error('Failed to fetch chat data on demand. Status:', response.status);
                    dmChatContainer.innerHTML = `<div class="text-center text-red-400 py-16"><p>Error loading messages.</p></div>`;
                    return;
                }
                const data = await response.json();
                lastFetchedMessages = (data.messages || []);
                lastFetchedSubscribers = (data.subscribers || {});
            } catch (error) {
                console.error('Error in loadChatData:', error);
                dmChatContainer.innerHTML = `<div class="text-center text-red-400 py-16"><p>Error loading messages.</p></div>`;
            }
        }

        let lastFetchedMessages = [];
        let lastFetchedSubscribers = {};
        async function updateChat() {
            try {
                const response = await fetch('/map-items/api_get_chat.php');
                if (!response.ok) { console.error('Failed to fetch chat data. Status:', response.status); return; }
                const data = await response.json();
                lastFetchedMessages = (data.messages || []);
                lastFetchedSubscribers = data.subscribers || {};
                renderAllChats();
                const chatWindow = document.getElementById('chat-window');
                if (chatWindow && (chatWindow.scrollHeight - chatWindow.clientHeight <= chatWindow.scrollTop + 50)) {
                    chatWindow.scrollTop = chatWindow.scrollHeight;
                }
            } catch (error) { console.error('Error updating chat:', error); }
        }

        // --- "JUST IN TIME" INITIALIZATION & TAB LOGIC ---
        function initStatusTab() {
            if (isStatusTabInitialized) return;
            isStatusTabInitialized = true;
            console.log("Initializing Status Tab...");
            if (document.getElementById('map') && !map) {
                map = L.map('map').setView([GATEWAY_LAT, GATEWAY_LON], 13);
                L.tileLayer('/map-items/map-tiles/{z}/{x}/{y}.png', { maxZoom: 18, attribution: '© OpenStreetMap', errorTileUrl: '/map-items/missing_tile.png' }).addTo(map);
            }
            // Initial calls to populate data immediately
            updatePageData();
            updateDashboardData(); 
            // Start polling intervals
            nodeDataInterval = setInterval(updatePageData, POLLING_INTERVAL);
            dashboardUpdateInterval = setInterval(updateDashboardData, POLLING_INTERVAL + 500); // Poll slightly offset from node data
        }

        function initChatTab() {
            if (isChatTabInitialized) return;
            isChatTabInitialized = true;
            console.log("Initializing Chat Tab...");
            updateChat(true);
            chatUpdateInterval = setInterval(updateChat, CHAT_POLLING_INTERVAL);
        }

        const tabs = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');
        tabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                tabs.forEach(t => t.classList.remove('active'));
                tabContents.forEach(c => c.style.display = 'none');
                
                tab.classList.add('active');
                const contentId = tab.dataset.tab + '-content';
                document.getElementById(contentId).style.display = 'block';

                if (tab.dataset.tab === 'status') {
                    initStatusTab();
                    if(map) {
                        setTimeout(() => map.invalidateSize(), 10);
                    }
                } else if (tab.dataset.tab === 'chat') {
                    initChatTab();
                }
            });
        });

        // Initialize the default tab on page load
        initStatusTab();

        // --- OTHER EVENT LISTENERS AND MODAL/FORM FUNCTIONS ---
        // (This section includes all your original code for modals, forms, etc.)
        
        const sosBannerCloseBtn = document.getElementById('sos-banner-close');
        sosBannerCloseBtn?.addEventListener('click', () => {
            if (activeSosNodeId) {
                acknowledgedSosNodes.add(activeSosNodeId);
            }
            sosBanner.style.display = 'none';
        });

        const confirmModal = document.getElementById('confirm-action-modal');
        const confirmModalText = document.getElementById('confirm-modal-text');
        const confirmBtn = document.getElementById('confirm-modal-confirm-btn');
        const cancelBtn = document.getElementById('confirm-modal-cancel-btn');
        let formToSubmit = null;
        function showConfirmModal(message, formElement) {
            formToSubmit = formElement;
            confirmModalText.innerHTML = message;
            confirmModal.style.display = 'flex';
        }
        function hideConfirmModal() {
            confirmModal.style.display = 'none';
            formToSubmit = null;
        }
        confirmBtn.addEventListener('click', () => { if (formToSubmit) { formToSubmit.submit(); } hideConfirmModal(); });
        cancelBtn.addEventListener('click', hideConfirmModal);
        
        document.querySelectorAll('form[method="POST"]').forEach(form => {
            form.addEventListener('submit', function(e) {
                if (['clear-chat-history-form', 'broadcast-modal-delete-form', 'user-modal-delete-form', 'save-settings-form', 'clear-email-queue-form', 'clear-sos-log-form', 'admin-clear-sos-form'].includes(form.id)) {
                    return;
                }
                let confirmationMessage = 'Are you sure you want to proceed?';
                if (form.querySelector('input[name="action"][value="delete_user"]')) {
                    confirmationMessage = 'Are you sure you want to permanently delete this user?';
                }
                e.preventDefault();
                showConfirmModal(confirmationMessage, this);
            });
        });

        const clearChatForm = document.getElementById('clear-chat-history-form');
        if(clearChatForm) { clearChatForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to permanently delete the entire chat history? This cannot be undone.', this); }); }
        
        const clearEmailQueueForm = document.getElementById('clear-email-queue-form');
        if(clearEmailQueueForm) { clearEmailQueueForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to clear the outgoing email queue?', this); }); }
        
        const clearSosForm = document.getElementById('clear-sos-log-form');
        if(clearSosForm) { clearSosForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to permanently delete the SOS log? This action cannot be undone.', this); }); }
        
        const adminClearSosForm = document.getElementById('admin-clear-sos-form');
        if(adminClearSosForm) { adminClearSosForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('This will trigger the full stand-down protocol for the active SOS. Proceed?', this); }); }

        const broadcastDeleteForm = document.getElementById('broadcast-modal-delete-form');
        if (broadcastDeleteForm) { broadcastDeleteForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to permanently delete this broadcast job?', this); }); }

        const userDeleteForm = document.getElementById('user-modal-delete-form');
        if (userDeleteForm) { userDeleteForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Are you sure you want to permanently delete this user? This action cannot be undone.', this); }); }

        const saveSettingsForm = document.getElementById('save-settings-form');
        if (saveSettingsForm) { saveSettingsForm.addEventListener('submit', function(e) { e.preventDefault(); showConfirmModal('Settings will be saved, but you must restart the dispatcher service for changes to take effect.<br><br>Proceed with saving?', this); }); }
        
        function toggleJobFields(form) {
            if (!form) return;
            const selector = form.querySelector('.job-type-selector');
            if (!selector) return;
            const type = selector.value;
            const recurringFields = form.querySelector('.recurring-fields');
            const eventFields = form.querySelector('.event-fields');
            if (!recurringFields || !eventFields) return;
            if (type === 'recurring') {
                recurringFields.style.display = 'block'; eventFields.style.display = 'none';
                recurringFields.querySelectorAll('input, select').forEach(el => el.disabled = false);
                eventFields.querySelectorAll('input, select').forEach(el => el.disabled = true);
                recurringFields.querySelectorAll('input[type="time"]').forEach(el => el.required = true);
                eventFields.querySelectorAll('input[type="datetime-local"]').forEach(el => el.required = false);
            } else {
                recurringFields.style.display = 'none'; eventFields.style.display = 'block';
                recurringFields.querySelectorAll('input, select').forEach(el => el.disabled = true);
                eventFields.querySelectorAll('input, select').forEach(el => el.disabled = false);
                recurringFields.querySelectorAll('input[type="time"]').forEach(el => el.required = false);
                eventFields.querySelectorAll('input[type="datetime-local"]').forEach(el => el.required = true);
            }
        }
        const broadcastEditForm = document.getElementById('broadcast-edit-form');
        if (broadcastEditForm) {
            toggleJobFields(broadcastEditForm);
            const selector = broadcastEditForm.querySelector('.job-type-selector');
            if (selector) { selector.addEventListener('change', () => toggleJobFields(broadcastEditForm)); }
        }

        const serverMessagePrefixes = ['☀️', '🔮', '⚡️', '🗓️', '📧', '🤖', '☁️', '🆘'];
        const mainChatTextarea = document.getElementById('main-chat-textarea');
        const mainChatSendBtn = document.getElementById('main-chat-send-btn');
        const mainChatBellBtn = document.getElementById('main-chat-bell-btn');
        const dmModal = document.getElementById('dm-chat-modal');
        const dmChatTitle = document.getElementById('dm-chat-title');
        const dmChatWindow = document.getElementById('dm-chat-window');
        const dmChatContainer = document.getElementById('dm-chat-messages-container');
        const dmChatForm = document.getElementById('dm-chat-form');
        const dmChatTextarea = document.getElementById('dm-chat-textarea');
        const dmChatSendBtn = document.getElementById('dm-chat-send-btn');
        const dmChatBellBtn = document.getElementById('dm-chat-bell-btn');
        const dmTargetNodeIdInput = document.getElementById('dm-target-node-id-input');
        const closeDmModalBtn = document.getElementById('close-dm-modal-btn');
        const userEditModal = document.getElementById('user-edit-modal');
        const userEditForm = document.getElementById('user-edit-form');
        const closeUserModalBtnHeader = document.getElementById('close-user-modal-btn');
        const closeUserModalBtnFooter = document.getElementById('close-user-modal-btn-footer');
        const userModalTitle = document.getElementById('user-modal-title').querySelector('span');
        const broadcastEditModal = document.getElementById('broadcast-edit-modal');
        const closeBroadcastModalBtnHeader = document.getElementById('close-broadcast-modal-btn');
        const closeBroadcastModalBtnFooter = document.getElementById('close-broadcast-modal-btn-footer');
        
        function renderAllChats() { renderFilteredChat(); renderDmChat(); }
        
        function renderFilteredChat() {
            const chatContainerElement = document.getElementById('chat-messages-container');
            const chatWindow = document.getElementById('chat-window');
            if (!chatContainerElement || !chatWindow) return;
            const showDMs = document.getElementById('show-dms-checkbox')?.checked ?? false;
            const showSMs = document.getElementById('show-sms-checkbox')?.checked ?? false;
            const isScrolledToBottom = chatWindow.scrollHeight - chatWindow.clientHeight <= chatWindow.scrollTop + 10;
            const filteredMessages = lastFetchedMessages.filter(msg => {
                const text = (msg.text || '').trim();
                let isServerMessage = false;
                for (const prefix of serverMessagePrefixes) { if (text.replace(/^\x07/, '').startsWith(prefix)) { isServerMessage = true; break; } }
                if (isServerMessage) return showSMs;
                let isConsideredDM = msg.is_dm || false; 
                if (!isConsideredDM && msg.from === 'GATEWAY' && text.replace(/^\x07/, '').startsWith('@')) { isConsideredDM = true; }
                if (isConsideredDM) return showDMs;
                return true;
            });
            chatContainerElement.innerHTML = '';
            if (filteredMessages.length > 0) {
                filteredMessages.forEach(msg => { chatContainerElement.innerHTML += createMessageHTML(msg, lastFetchedSubscribers, false); });
            } else {
               chatContainerElement.innerHTML = `<div class="text-center text-slate-500 py-16"><p>No messages to display with current filters.</p></div>`;
            }
            if (isScrolledToBottom) { chatWindow.scrollTop = chatWindow.scrollHeight; }
        }
        
        function renderDmChat() {
            if (!dmModal || dmModal.style.display === 'none' || !dmChatContainer) return;
            const targetNodeId = dmTargetNodeIdInput.value;
            if (!targetNodeId) { dmChatContainer.innerHTML = ''; return; };
            const targetName = lastFetchedSubscribers[targetNodeId]?.name || targetNodeId;
            const filteredMessages = lastFetchedMessages.filter(msg => {
                if (!msg.is_dm) return false;
                const fromUserToGateway = msg.from === targetNodeId;
                const gatewayToUserRegex = new RegExp(`^@${escapeRegExp(targetName)}\\s`, 'i');
                const fromGatewayToUser = msg.from === 'GATEWAY' && gatewayToUserRegex.test((msg.text || '').replace(/^\x07/, ''));
                return fromUserToGateway || fromGatewayToUser;
            });
            const isScrolledToBottom = dmChatWindow.scrollHeight - dmChatWindow.clientHeight <= dmChatWindow.scrollTop + 10;
            dmChatContainer.innerHTML = '';
            if (filteredMessages.length > 0) {
                filteredMessages.forEach(msg => { dmChatContainer.innerHTML += createMessageHTML(msg, lastFetchedSubscribers, true); });
            } else {
                dmChatContainer.innerHTML = `<div class="text-center text-slate-500 py-16"><p>No direct messages with this user yet.</p></div>`;
            }
            if (isScrolledToBottom) { dmChatWindow.scrollTop = dmChatWindow.scrollHeight; }
        }
        
        function escapeRegExp(string) { return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
        
        function createMessageHTML(msg, subscribers, isDmContext = false) {
            const fromId = msg.from || 'Unknown';
            let text = (msg.text || '').trim();
            let messageType = '', fromName = 'Unknown', hasBell = false;
            let isSystemMessage = false;
            for (const prefix of serverMessagePrefixes) { if (text.replace(/^\x07/, '').startsWith(prefix)) { isSystemMessage = true; break; } }
            if (isSystemMessage) { messageType = 'system'; } 
            else if (fromId === 'GATEWAY') { messageType = 'outgoing'; fromName = 'You (Gateway)'; } 
            else { fromName = (subscribers[fromId] && subscribers[fromId].name) ? subscribers[fromId].name : fromId; messageType = 'incoming'; }
            if (messageType === 'outgoing' && isDmContext) { 
                const parts = text.split(/ (.*)/s); 
                if (parts.length > 1 && parts[0].startsWith('@')) { text = parts[1]; }
            }
            if (text.startsWith("\x07")) { hasBell = true; text = text.substring(1); }
            if (messageType === 'system') { return `<div class="message message-system"><div class="message-content">${escapeHTML(text)}</div></div>`; }
            const dmPrefix = (msg.is_dm && messageType === 'incoming' && !isDmContext) ? '<span class="font-bold text-yellow-400/80">DM: </span>' : '';
            const bellIndicator = hasBell ? '<span class="text-red-400 font-bold" title="Sent with Bell">🔔 </span>' : '';
            return `<div class="message message-${messageType}"><div class="message-username">${escapeHTML(fromName)}</div><div class="message-content">${bellIndicator}${dmPrefix}${escapeHTML(text)}</div><div class="message-meta"><span class="timestamp">${escapeHTML(msg.timestamp || '')}</span></div></div>`;
        }
        
        function sendAjaxMessage(text, button, isBell = false) {
            if (!text.trim() || button.disabled) return;
            const originalButtonText = button.textContent;
            let allButtons = [mainChatSendBtn, mainChatBellBtn, dmChatSendBtn, dmChatBellBtn].filter(b => b);
            allButtons.forEach(b => { b.disabled = true; });
            button.textContent = '...';
            let messageToSend = text;
            if (isBell) { if (text.startsWith('@')) { const parts = text.split(/ (.*)/s); messageToSend = `${parts[0]} \x07${parts[1] || ''}`; } else { messageToSend = `\x07${text}`; } }
            
            const csrfToken = document.querySelector('input[name="csrf_token"]').value;
            const formData = new FormData();
            formData.append('ajax', 'true');
            formData.append('action', 'send_broadcast');
            formData.append('broadcast_text', messageToSend);
            formData.append('csrf_token', csrfToken);

            fetch(window.location.href, { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => {
                if (data.success) { 
                    if (button.closest('#dm-chat-form')) dmChatTextarea.value = ''; 
                    else mainChatTextarea.value = ''; 
                    setTimeout(() => updateChat(false), 500);
                } else { alert('Failed to send message: ' + data.message); }
            })
            .catch(error => { console.error('Error sending message:', error); alert('An error occurred while sending the message.'); })
            .finally(() => { allButtons.forEach(b => { b.disabled = false; }); button.textContent = originalButtonText; });
        }
        
        mainChatSendBtn?.addEventListener('click', function() { sendAjaxMessage(mainChatTextarea.value, this, false); });
        mainChatBellBtn?.addEventListener('click', function() { sendAjaxMessage(mainChatTextarea.value, this, true); });
        mainChatTextarea?.addEventListener('keydown', function(event) { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); mainChatSendBtn.click(); } });
        
        async function openDmChat(nodeId, nodeName) {
            if (!dmModal) return;
            dmChatTitle.querySelector('span').textContent = `${nodeId} / ${nodeName}`;
            dmTargetNodeIdInput.value = nodeId;
            dmChatContainer.innerHTML = `<div class="text-center text-slate-500 py-16"><p>Loading messages...</p></div>`;
            dmModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
            if (!isChatTabInitialized) {
                await loadChatData();
            }
            renderDmChat();
            setTimeout(() => {
                if (dmChatWindow) dmChatWindow.scrollTop = dmChatWindow.scrollHeight;
                if (dmChatTextarea) dmChatTextarea.focus();
            }, 100);
        }
        
        function closeDmChat() {
            if (!dmModal) return;
            dmModal.style.display = 'none';
            document.body.style.overflow = '';
            dmTargetNodeIdInput.value = '';
        }
        
        document.body.addEventListener('click', function(event) {
            if (event.target.matches('.open-dm-chat')) {
                openDmChat(event.target.dataset.nodeId, event.target.dataset.nodeName);
            }
            if (event.target.matches('.location-btn')) {
                const { lat, lon } = event.target.dataset;
                if (map && lat && lon) { map.setView([lat, lon], 15); }
            }
        });
        
        closeDmModalBtn?.addEventListener('click', closeDmChat);
        
        dmChatForm?.addEventListener('submit', function(e) { 
            e.preventDefault(); 
            const text = dmChatTextarea.value.trim();
            const target = lastFetchedSubscribers[dmTargetNodeIdInput.value]?.name || dmTargetNodeIdInput.value;
            const fullMessage = `@${target} ${text}`;
            sendAjaxMessage(fullMessage, dmChatSendBtn, false); 
        });
        
        dmChatBellBtn?.addEventListener('click', function() { 
            const text = dmChatTextarea.value.trim(); 
            const target = lastFetchedSubscribers[dmTargetNodeIdInput.value]?.name || dmTargetNodeIdInput.value;
            const fullMessage = `@${target} ${text}`;
            sendAjaxMessage(fullMessage, this, true);
        });
        
        dmChatTextarea?.addEventListener('keydown', function(event) { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); dmChatSendBtn.click(); } });
        
        function openUserEditModal(userData) {
            const userEditForm = document.getElementById('user-edit-form');
            if (!userEditModal || !userEditForm) return;
            userModalTitle.textContent = `${userData.node_id} / ${userData.name}`;
            userEditForm.querySelector('input[name="node_id"]').value = userData.node_id;
            document.getElementById('user-modal-delete-form').querySelector('input[name="node_id"]').value = userData.node_id;
            userEditForm.querySelector('input[name="name"]').value = userData.name || '';
            userEditForm.querySelector('input[name="full_name"]').value = userData.full_name || '';
            userEditForm.querySelector('select[name="role"]').value = userData.role || '';
            userEditForm.querySelector('input[name="email"]').value = userData.email || '';
            userEditForm.querySelector('input[name="phone_1"]').value = userData.phone_1 || '';
            userEditForm.querySelector('input[name="phone_2"]').value = userData.phone_2 || '';
            userEditForm.querySelector('input[name="address_street"]').value = userData.address?.street || '';
            userEditForm.querySelector('input[name="address_city"]').value = userData.address?.city || '';
            userEditForm.querySelector('input[name="address_state"]').value = userData.address?.state || '';
            userEditForm.querySelector('input[name="address_zip"]').value = userData.address?.zip || '';
            userEditForm.querySelector('textarea[name="notes"]').value = userData.notes || '';
            userEditForm.querySelector('input[name="tags"]').value = (userData.tags || []).join(', ');
            userEditForm.querySelector('input[name="alerts"]').checked = userData.alerts || false;
            userEditForm.querySelector('input[name="weather"]').checked = userData.weather || false;
            userEditForm.querySelector('input[name="scheduled_daily_forecast"]').checked = userData.scheduled_daily_forecast || false;
            userEditForm.querySelector('input[name="email_send"]').checked = userData.email_send || false;
            userEditForm.querySelector('input[name="email_receive"]').checked = userData.email_receive || false;
            userEditForm.querySelector('input[name="emailbroadcast"]').checked = userData.emailbroadcast || false;
            userEditForm.querySelector('input[name="node_tag_send"]').checked = userData.node_tag_send || false;
            userEditForm.querySelector('input[name="blocked"]').checked = userData.blocked || false;
            userEditModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
        
        function closeUserEditModal() { if (!userEditModal) return; userEditModal.style.display = 'none'; document.body.style.overflow = ''; }
        
        document.querySelectorAll('.open-user-edit-modal').forEach(button => { button.addEventListener('click', function() { openUserEditModal(JSON.parse(this.dataset.userData)); }); });
        closeUserModalBtnHeader?.addEventListener('click', closeUserEditModal);
        closeUserModalBtnFooter?.addEventListener('click', closeUserEditModal);
        
        function openBroadcastEditModal(jobData) {
            const broadcastEditForm = document.getElementById('broadcast-edit-form');
            if (!broadcastEditModal || !broadcastEditForm) return;
            broadcastEditModal.querySelector('#broadcast-modal-title span').textContent = `Edit: ${jobData.name || 'Untitled Job'}`;
            broadcastEditForm.querySelector('input[name="job_index"]').value = jobData.job_index;
            document.getElementById('broadcast-modal-delete-form').querySelector('input[name="job_index"]').value = jobData.job_index;
            broadcastEditForm.querySelector('input[name="name"]').value = jobData.name || '';
            let content = jobData.content || '';
            const bellCheckbox = broadcastEditForm.querySelector('input[name="with_bell"]');
            if (content.startsWith("\x07")) { bellCheckbox.checked = true; content = content.substring(1); } else { bellCheckbox.checked = false; }
            broadcastEditForm.querySelector('textarea[name="content"]').value = content;
            broadcastEditForm.querySelector('input[name="enabled"]').checked = jobData.enabled || false;
            broadcastEditForm.querySelector('input[name="interval_mins"]').value = jobData.interval_mins || 60;
            const jobTypeSelector = broadcastEditForm.querySelector('.job-type-selector');
            if (jobData.days) {
                jobTypeSelector.value = 'recurring';
                broadcastEditForm.querySelectorAll('input[name="days[]"]').forEach(cb => { cb.checked = (jobData.days || []).includes(cb.value); });
                broadcastEditForm.querySelector('input[name="start_time"]').value = jobData.start_time || '';
                broadcastEditForm.querySelector('input[name="stop_time"]').value = jobData.stop_time || '';
            } else {
                jobTypeSelector.value = 'event';
                const formatForInput = (dt) => dt ? dt.replace(' ', 'T') : '';
                broadcastEditForm.querySelector('input[name="start_datetime"]').value = formatForInput(jobData.start_datetime);
                broadcastEditForm.querySelector('input[name="stop_datetime"]').value = formatForInput(jobData.stop_datetime);
            }
            toggleJobFields(broadcastEditForm);
            broadcastEditModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
        
        function closeBroadcastEditModal() { if (!broadcastEditModal) return; broadcastEditModal.style.display = 'none'; document.body.style.overflow = ''; }
        
        document.querySelectorAll('.open-broadcast-edit-modal').forEach(button => { button.addEventListener('click', function() { openBroadcastEditModal(JSON.parse(this.dataset.jobData)); }); });
        document.getElementById('close-broadcast-modal-btn')?.addEventListener('click', closeBroadcastEditModal);
        document.getElementById('close-broadcast-modal-btn-footer')?.addEventListener('click', closeBroadcastEditModal);
    });
</script>

</body>
</html>
