<?php
// Database connection. Credentials are read from the environment (set in
// docker-compose.yml) with weak lab defaults. MySQL lives on the same host.
$DB_HOST = getenv('DB_HOST') ?: '127.0.0.1';
$DB_USER = getenv('DB_USER') ?: 'bloguser';
$DB_PASS = getenv('DB_PASS') ?: 'blogpass123';
$DB_NAME = getenv('DB_NAME') ?: 'blog';

$conn = @mysqli_connect($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if (!$conn) {
    // Verbose error on purpose — leaks backend details.
    http_response_code(500);
    die('Database connection failed: ' . mysqli_connect_error());
}
