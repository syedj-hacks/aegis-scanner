<?php
/*
 * info.php — Aegis Scanner test-fixture companion script.
 *
 * NOT part of stock DVWA. Added because DVWA's own SQLi lab page
 * (vulnerabilities/sqli/index.php) sits behind a login wall, and Aegis's
 * sqlmap_wrap.py (as of this writing) has no session/cookie support, so
 * it can never reach that page through the scanner's normal unauthenticated
 * discovery flow (gobuster/dirb -> sqlmap). This page is a minimal,
 * intentionally-vulnerable, UNAUTHENTICATED stand-in that queries DVWA's
 * own MySQL `users` table (populated by DVWA's real setup.php) with the
 * `id` GET parameter concatenated directly into the SQL string — the same
 * class of vulnerability DVWA's own lab page demonstrates, just reachable
 * without a session. Local, isolated, authorized test target only.
 */

$id = isset($_GET['id']) ? $_GET['id'] : '1';

$conn = @new mysqli('127.0.0.1', 'app', 'vulnerables', 'dvwa');
if ($conn->connect_error) {
    echo "DB connection failed: " . $conn->connect_error;
    exit;
}

$query = "SELECT user, password FROM users WHERE user_id = '$id'";
$result = $conn->query($query);

if ($result) {
    while ($row = $result->fetch_assoc()) {
        echo htmlspecialchars($row['user']) . " - " . htmlspecialchars($row['password']) . "<br>";
    }
} else {
    echo "Query error: " . htmlspecialchars($conn->error);
}

$conn->close();
