<?php
// api/schedule.php

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit();
}

require_once __DIR__ . '/../config/session.php';
startAppSession();

if (empty($_SESSION['user']['id'])) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Authentication required.']);
    exit();
}

require_once __DIR__ . '/../config/db.php';

$userId = (int) $_SESSION['user']['id'];
$method = $_SERVER['REQUEST_METHOD'];
$rawInput = file_get_contents('php://input');
$data = json_decode($rawInput, true) ?? [];
$action = $_GET['action'] ?? $data['action'] ?? '';

// Support DELETE method or POST overrides
$isDelete = ($method === 'DELETE') 
    || (isset($data['_method']) && strtoupper($data['_method']) === 'DELETE')
    || ($action === 'delete')
    || ($action === 'clear');

// Route requests
if ($method === 'GET') {
    getSchedules($pdo, $userId);
} elseif ($isDelete) {
    deleteSchedule($pdo, $data, $userId);
} elseif ($method === 'POST' || $method === 'PUT') {
    $hasId = isset($data['id']) && $data['id'] !== null && $data['id'] !== '' && intval($data['id']) > 0;
    if ($hasId) {
        updateSchedule($pdo, $data, $userId);
    } else {
        addSchedule($pdo, $data, $userId);
    }
} else {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed.']);
}

// FETCH ALL SCHEDULES FOR USER
function getSchedules($pdo, $userId) {
    try {
        $stmt = $pdo->prepare("SELECT id, subject_code, subject_title, day, start_time, end_time, professor, room FROM schedules WHERE user_id = ?");
        $stmt->execute([$userId]);
        $schedules = $stmt->fetchAll();
        echo json_encode(['status' => 'success', 'data' => $schedules]);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Failed to retrieve schedules: ' . $e->getMessage()]);
    }
}

// ADD NEW SCHEDULE
function addSchedule($pdo, $data, $userId) {
    $subject_code  = trim($data['subject_code'] ?? '');
    $subject_title = trim($data['subject_title'] ?? '');
    $day           = trim($data['day'] ?? '');
    $start_time    = trim($data['start_time'] ?? '');
    $end_time      = trim($data['end_time'] ?? '');
    $room          = trim($data['room'] ?? '');
    $professor     = trim($data['professor'] ?? '');

    if (empty($subject_title) || empty($day) || empty($start_time) || empty($end_time)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Missing required fields.']);
        return;
    }

    try {
        $stmt = $pdo->prepare("INSERT INTO schedules (user_id, subject_code, subject_title, day, start_time, end_time, room, professor) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$userId, $subject_code, $subject_title, $day, $start_time, $end_time, $room, $professor]);
        $newId = $pdo->lastInsertId();
        http_response_code(201);
        echo json_encode(['status' => 'success', 'message' => 'Schedule created successfully.', 'id' => $newId]);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

// UPDATE SCHEDULE
function updateSchedule($pdo, $data, $userId) {
    $id            = intval($data['id'] ?? 0);
    $subject_code  = trim($data['subject_code'] ?? '');
    $subject_title = trim($data['subject_title'] ?? '');
    $day           = trim($data['day'] ?? '');
    $start_time    = trim($data['start_time'] ?? '');
    $end_time      = trim($data['end_time'] ?? '');
    $room          = trim($data['room'] ?? '');
    $professor     = trim($data['professor'] ?? '');

    if ($id <= 0) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Valid Schedule ID is required for updates.']);
        return;
    }

    try {
        $stmt = $pdo->prepare("UPDATE schedules SET subject_code = ?, subject_title = ?, day = ?, start_time = ?, end_time = ?, room = ?, professor = ? WHERE id = ? AND user_id = ?");
        $stmt->execute([$subject_code, $subject_title, $day, $start_time, $end_time, $room, $professor, $id, $userId]);
        echo json_encode(['status' => 'success', 'message' => 'Schedule updated successfully.']);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

// DELETE SCHEDULE(S)
function deleteSchedule($pdo, $data, $userId) {
    $id      = intval($data['id'] ?? $_GET['id'] ?? 0);

    try {
        if ($id > 0) {
            $stmt = $pdo->prepare("DELETE FROM schedules WHERE id = ? AND user_id = ?");
            $stmt->execute([$id, $userId]);
        } else {
            $stmt = $pdo->prepare("DELETE FROM schedules WHERE user_id = ?");
            $stmt->execute([$userId]);
        }
        echo json_encode(['status' => 'success', 'message' => 'Schedule deleted successfully.']);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Failed to delete schedule: ' . $e->getMessage()]);
    }
}
?>