<?php require __DIR__ . '/../includes/auth_admin.php'; require __DIR__ . '/../includes/header.php'; ?>
<h2>Network tools</h2>
<form method="get" action="/admin/ping.php">
  <input type="text" name="host" value="<?php echo htmlspecialchars($_GET['host'] ?? ''); ?>" placeholder="host to ping">
  <button type="submit">Ping</button>
</form>
<?php
// Command injection: `host` is passed unsanitized to a shell. RCE example:
//   ?host=127.0.0.1;id      ?host=127.0.0.1;cat /etc/passwd
if (isset($_GET['host']) && $_GET['host'] !== '') {
    $host = $_GET['host'];
    $out = shell_exec('ping -c 1 ' . $host . ' 2>&1');
    echo '<h3>Result</h3><pre>' . htmlspecialchars((string) $out) . '</pre>';
}
?>
<?php require __DIR__ . '/../includes/footer.php'; ?>
