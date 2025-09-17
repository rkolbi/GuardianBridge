<?php
// GuardianBridge - api_manage_blocklist.php

session_start();
header('Content-Type: application/json');

// --- Security Gate ---
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['success' => false, 'message' => 'Authentication required.']));
}

// --- File Paths ---
$base_dir = '/opt/GuardianBridge';
$data_dir = $base_dir . '/data';
$blocklist_file = $data_dir . '/email_blocklist.json';

// --- Helper Functions ---
function get_blocklist($file_path) {
    if (!is_readable($file_path)) return [];
    $content = @file_get_contents($file_path);
    if ($content === false) return [];
    $data = json_decode($content, true);
    return (json_last_error() === JSON_ERROR_NONE && is_array($data)) ? $data : [];
}

function save_blocklist($file_path, $data) {
    if (!is_array($data)) return false;
    // Sort the list alphabetically for consistency
    sort($data);
    $json_data = json_encode(array_values($data), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    
    // Use a temporary file and atomic rename for safe writing
    $temp_file = $file_path . '.tmp';
    if (@file_put_contents($temp_file, $json_data) === false) {
        error_log("GuardianBridge Error: Failed to write to temporary blocklist file: " . $temp_file);
        return false;
    }
    if (!@rename($temp_file, $file_path)) {
        error_log("GuardianBridge Error: Failed to rename temporary blocklist file.");
        @unlink($temp_file);
        return false;
    }
    return true;
}

// --- Main Logic ---
$action = $_POST['action'] ?? $_GET['action'] ?? null;
$response = ['success' => false, 'message' => 'Invalid action specified.'];

switch ($action) {
    case 'get_blocklist':
        $response = [
            'success' => true,
            'blocklist' => get_blocklist($blocklist_file)
        ];
        break;

    case 'add_to_blocklist':
        // CSRF Protection for write actions
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
            $response['message'] = 'Invalid security token.';
            break;
        }
        $email = strtolower(trim($_POST['email'] ?? ''));
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $blocklist = get_blocklist($blocklist_file);
            if (!in_array($email, $blocklist)) {
                $blocklist[] = $email;
                if (save_blocklist($blocklist_file, $blocklist)) {
                    $response = ['success' => true, 'message' => 'Email added to blocklist.'];
                } else {
                    $response['message'] = 'Server error: Could not save blocklist file.';
                }
            } else {
                $response = ['success' => false, 'message' => 'Email is already on the blocklist.'];
            }
        } else {
            $response['message'] = 'Invalid email address format.';
        }
        break;

    case 'remove_from_blocklist':
        // CSRF Protection for write actions
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
            $response['message'] = 'Invalid security token.';
            break;
        }
        $email = strtolower(trim($_POST['email'] ?? ''));
        if (!empty($email)) {
            $blocklist = get_blocklist($blocklist_file);
            if (($key = array_search($email, $blocklist)) !== false) {
                unset($blocklist[$key]);
                if (save_blocklist($blocklist_file, $blocklist)) {
                    $response = ['success' => true, 'message' => 'Email removed from blocklist.'];
                } else {
                    $response['message'] = 'Server error: Could not save blocklist file.';
                }
            } else {
                $response = ['success' => false, 'message' => 'Email not found on the blocklist.'];
            }
        } else {
            $response['message'] = 'No email address provided.';
        }
        break;
}

echo json_encode($response);
exit;
