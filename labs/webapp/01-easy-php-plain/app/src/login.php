<?php
require __DIR__ . '/db.php';
session_start();
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db = qd_db();
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    // VULN: username is interpolated straight into the query (classic SQLi).
    // The password is hashed, so the username field is the injection point:
    //   admin' --      or     ' OR '1'='1' --
    $sql = "SELECT id, username, role FROM users "
         . "WHERE username = '$u' AND password = '" . md5($p) . "'";
    $res = $db->query($sql);
    if ($res && ($row = $res->fetch_assoc())) {
        $_SESSION['user'] = $row['username'];
        $_SESSION['role'] = $row['role'];
        header('Location: dashboard.php');
        exit;
    }
    $error = 'Invalid credentials.';
}
?><!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>QuickDesk — sign in</title></head>
<body>
  <h1>Agent sign in</h1>
  <?php if ($error): ?><p style="color:#b00"><?= htmlspecialchars($error) ?></p><?php endif; ?>
  <form method="post" action="login.php">
    <p><label>Username <input name="username" autofocus></label></p>
    <p><label>Password <input name="password" type="password"></label></p>
    <p><button type="submit">Sign in</button></p>
  </form>
</body>
</html>
