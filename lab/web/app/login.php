<?php require __DIR__ . '/db.php'; ?>
<?php
// SQLi auth bypass: username is concatenated into the query. Password is checked
// as an UNSALTED md5. Bypass example (no password needed):
//   username: admin'-- -      password: anything
// Legit: admin / password123 (see docs/lab.md).
if (session_status() === PHP_SESSION_NONE) { session_start(); }
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    $hash = md5($p);
    $sql = "SELECT id, username, role FROM users
            WHERE username = '$u' AND password = '$hash'";
    $res = mysqli_query($conn, $sql);
    if ($res && ($row = mysqli_fetch_assoc($res))) {
        $_SESSION['uid']      = (int) $row['id'];
        $_SESSION['username'] = $row['username'];
        $_SESSION['role']     = $row['role'];
        header('Location: /admin/index.php');
        exit;
    }
    $error = 'Invalid credentials.';
}
require __DIR__ . '/includes/header.php';
?>
<h2>Login</h2>
<?php if ($error): ?><p style="color:#c00"><?php echo htmlspecialchars($error); ?></p><?php endif; ?>
<form method="post" action="/login.php">
  <p><input type="text" name="username" placeholder="username"></p>
  <p><input type="password" name="password" placeholder="password"></p>
  <p><button type="submit">Log in</button></p>
</form>
<?php require __DIR__ . '/includes/footer.php'; ?>
