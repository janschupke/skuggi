<?php
// Arbitrary file read / LFI: `file` is joined to a base dir with no path
// validation. Example: ?file=../../../../etc/passwd
$file = $_GET['file'] ?? '';
$path = __DIR__ . '/files/' . $file;
if (is_file($path)) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($path) . '"');
    readfile($path);
    exit;
}
http_response_code(404);
echo 'File not found: ' . htmlspecialchars($file);
