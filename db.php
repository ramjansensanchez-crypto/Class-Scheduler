<?php
// config/db.php

$dbDir  = dirname(__DIR__,) . '/database sqlite';
$dbPath = $dbDir . '/class_scheduler.sqlite';

if (!file_exists($dbDir)) {
    mkdir($dbDir, 0777, true);
}

$dsn = "sqlite:" . $dbPath;

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, null, null, $options);
    $pdo->setAttribute(PDO::ATTR_TIMEOUT, 30);  // Increased timeout
    
    // Use MEMORY journal for better reliability with SQLite
    $pdo->exec("PRAGMA journal_mode = MEMORY;");
    $pdo->exec("PRAGMA foreign_keys = ON;");
    $pdo->exec("PRAGMA synchronous = FULL;");  // Ensure all writes are committed
    
    // Auto-create users table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until TEXT DEFAULT NULL,
            reset_token TEXT DEFAULT NULL,
            reset_expires TEXT DEFAULT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ");

    // Auto-create schedules table matching api/schedule.php
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject_code TEXT,
            subject_title TEXT NOT NULL,
            day TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            room TEXT,
            professor TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ");

} catch (\PDOException $e) {
    header('Content-Type: application/json');
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Database connection failed: ' . $e->getMessage(), 'debug' => 'Path: ' . $dbPath]);
    exit;
}
?>