<?php
// Shared connection helper. Credentials come from the environment (see compose).
function qd_db(): mysqli {
    $host = getenv('DB_HOST') ?: 'db';
    $name = getenv('DB_NAME') ?: 'quickdesk';
    $user = getenv('DB_USER') ?: 'quickdesk_app';
    $pass = getenv('DB_PASS') ?: 'app-db-pw-2024';
    $db = @new mysqli($host, $user, $pass, $name);
    if ($db->connect_errno) {
        http_response_code(503);
        exit('database unavailable');
    }
    return $db;
}
