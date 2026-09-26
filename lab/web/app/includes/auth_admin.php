<?php
// Weak access control: any authenticated admin session may proceed. There is
// no CSRF protection and no re-authentication. The admin role is reachable via
// SQLi auth bypass on login.php or by cracking the dumped admin hash.
if (session_status() === PHP_SESSION_NONE) { session_start(); }
if (($_SESSION['role'] ?? '') !== 'admin') {
    header('Location: /login.php');
    exit;
}
