<?php
// api/auth.php

// 1. Response & CORS Headers
header('Content-Type: application/json');

// Handle preflight OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit();
}

require_once __DIR__ . '/../config/session.php';
startAppSession();
require_once __DIR__ . '/../config/db.php';

// Parse incoming JSON body safely using correct PHP input stream
$rawInput = file_get_contents('php://input');
$data = json_decode($rawInput, true) ?? $_POST ?? [];
$action = $_GET['action'] ?? $data['action'] ?? '';

// Route requests based on action
switch ($action) {
    case 'register':
        handleRegister($pdo, $data);
        break;
    case 'login':
        handleLogin($pdo, $data);
        break;
    case 'session':
        handleSession();
        break;
    case 'logout':
        handleLogout();
        break;
    case 'request_reset':
        handleRequestReset($pdo, $data);
        break;
    default:
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Invalid action requested.']);
        break;
}

// -----------------------------------------------------------------------------
// USER REGISTRATION
// -----------------------------------------------------------------------------
function handleRegister($pdo, $data) {
    $student_id = trim($data['student_id'] ?? '');
    $email      = trim($data['email'] ?? '');
    $password   = $data['password'] ?? '';

    if (empty($student_id) || empty($password) || empty($email)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Student ID, email, and password are required.']);
        return;
    }

    try {
        // Check for existing Student ID or Email
        $stmt = $pdo->prepare("SELECT id FROM users WHERE student_id = ? OR email = ?");
        $stmt->execute([$student_id, $email]);
        if ($stmt->fetch()) {
            http_response_code(409); // Conflict
            echo json_encode(['status' => 'error', 'message' => 'Student ID or Email is already registered.']);
            return;
        }

        // Securely hash password using Bcrypt
        $password_hash = password_hash($password, PASSWORD_BCRYPT);

        // Insert new user with email - Use transaction for safety
        $pdo->beginTransaction();
        
        $stmt = $pdo->prepare("INSERT INTO users (student_id, email, password) VALUES (?, ?, ?)");
        $success = $stmt->execute([$student_id, $email, $password_hash]);
        
        if (!$success) {
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(['status' => 'error', 'message' => 'Failed to insert user - execute failed']);
            return;
        }
        
        $userId = $pdo->lastInsertId();
        $pdo->commit();
        
        // Verify the user was actually inserted
        $verify = $pdo->prepare("SELECT id FROM users WHERE id = ?");
        $verify->execute([$userId]);
        $verifyResult = $verify->fetch();
        
        if ($verifyResult) {
            http_response_code(201);
            echo json_encode([
                'status' => 'success', 
                'message' => 'Account created successfully!',
                'user' => [
                    'id' => $userId,
                    'student_id' => $student_id
                ]
            ]);
        } else {
            http_response_code(500);
            echo json_encode(['status' => 'error', 'message' => 'Account was not saved. Please try again.']);
        }

    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        http_response_code(500);
        echo json_encode([
            'status' => 'error', 
            'message' => 'Registration failed: ' . $e->getMessage(),
            'error_code' => $e->getCode()
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'status' => 'error',
            'message' => 'Unexpected error: ' . $e->getMessage()
        ]);
    }
}


// USER LOGIN WITH 5-FAILED-ATTEMPTS LOCKOUT

function handleLogin($pdo, $data) {
    $student_id = trim($data['student_id'] ?? '');
    $password   = $data['password'] ?? '';

    if (empty($student_id) || empty($password)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Student ID and Password are required.']);
        return;
    }

    try {
        // Fetch user record
        $stmt = $pdo->prepare("SELECT * FROM users WHERE student_id = ?");
        $stmt->execute([$student_id]);
        $user = $stmt->fetch();

        // Generic error message to prevent account enumeration
        $genericError = 'Invalid Student ID or password.';

        if (!$user) {
            http_response_code(401);
            echo json_encode(['status' => 'error', 'message' => $genericError]);
            return;
        }

        $now = new DateTime();

        // 1. Check if user is currently locked out
        if ($user['lockout_until']) {
            $lockoutTime = new DateTime($user['lockout_until']);
            if ($now < $lockoutTime) {
                $remainingSeconds = $lockoutTime->getTimestamp() - $now->getTimestamp();
                $remainingMinutes = ceil($remainingSeconds / 60);

                http_response_code(429); // Too Many Requests
                echo json_encode([
                    'status' => 'error', 
                    'message' => "Account locked due to multiple failed attempts. Try again in {$remainingMinutes} minute(s)."
                ]);
                return;
            } else {
                // Lockout period expired; reset counters
                $resetStmt = $pdo->prepare("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?");
                $resetStmt->execute([$user['id']]);
                $user['failed_attempts'] = 0;
            }
        }

        // 2. Verify Password against the 'password' database field
        if (password_verify($password, $user['password'])) {
            // Password correct: clear failed attempts
            $successStmt = $pdo->prepare("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?");
            $successStmt->execute([$user['id']]);

            session_regenerate_id(true);
            $_SESSION['user'] = [
                'id' => (int) $user['id'],
                'student_id' => $user['student_id'],
            ];

            http_response_code(200);
            echo json_encode([
                'status' => 'success',
                'message' => 'Login successful.',
                'user' => [
                    'id' => $user['id'],
                    'student_id' => $user['student_id']
                ]
            ]);
        } else {
            // Password incorrect: increment failed attempts
            $failedAttempts = $user['failed_attempts'] + 1;
            $lockoutUntil = null;

            // Trigger 5-minute lockout if threshold reached
            if ($failedAttempts >= 5) {
                $lockoutTime = new DateTime();
                $lockoutTime->modify('+5 minutes');
                $lockoutUntil = $lockoutTime->format('Y-m-d H:i:s');
            }

            $failStmt = $pdo->prepare("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?");
            $failStmt->execute([$failedAttempts, $lockoutUntil, $user['id']]);

            http_response_code(401);

            if ($failedAttempts >= 5) {
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Too many failed login attempts. Your account has been locked for 5 minutes.'
                ]);
            } else {
                $attemptsLeft = 5 - $failedAttempts;
                echo json_encode([
                    'status' => 'error',
                    'message' => "Invalid Student ID or password. {$attemptsLeft} attempt(s) remaining before lockout."
                ]);
            }
        }

    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'An authentication error occurred.']);
    }
}


function handleSession() {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        http_response_code(405);
        echo json_encode(['status' => 'error', 'message' => 'Method not allowed.']);
        return;
    }

    if (empty($_SESSION['user']['id'])) {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'message' => 'Not authenticated.']);
        return;
    }

    echo json_encode(['status' => 'success', 'user' => $_SESSION['user']]);
}

function handleLogout() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['status' => 'error', 'message' => 'Method not allowed.']);
        return;
    }

    $_SESSION = [];
    $cookieParams = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $cookieParams['path'] ?: '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_destroy();

    echo json_encode(['status' => 'success', 'message' => 'Logged out.']);
}


// REQUEST PASSWORD RESET LINK

function handleRequestReset($pdo, $data) {
    $email = trim($data['email'] ?? '');

    if (empty($email)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Email address is required.']);
        return;
    }

    try {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        // Always respond with success to prevent email enumeration
        if (!$user) {
            http_response_code(200);
            echo json_encode([
                'status' => 'success',
                'message' => 'If an account exists for that email, a reset link has been sent.'
            ]);
            return;
        }

        $token = bin2hex(random_bytes(32));
        $expires = date('Y-m-d H:i:s', strtotime('+1 hour'));

        $updateStmt = $pdo->prepare("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?");
        $updateStmt->execute([$token, $expires, $user['id']]);

        // Construct full link
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $resetLink = "http://" . $host . "/class-scheduler/reset-password.php?token=" . $token;

        $subject = "Class Scheduler — Password Reset Request";
        $message = "Hello,\n\nYou requested a password reset for Class Scheduler.\n\nClick the link below to reset your password:\n" . $resetLink . "\n\nThis link expires in 1 hour.";
        $headers = "From: no-reply@" . $host . "\r\n" . "X-Mailer: PHP/" . phpversion();

        @mail($email, $subject, $message, $headers);

        http_response_code(200);
        echo json_encode([
            'status' => 'success',
            'message' => 'Reset link has been sent to your email.'
        ]);

    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Could not process reset request.']);
    }
}
?>