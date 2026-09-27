<?php require __DIR__ . '/../includes/auth_admin.php'; require __DIR__ . '/../includes/header.php'; ?>
<h2>Admin dashboard</h2>
<p>Logged in as <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong>
   (role: <?php echo htmlspecialchars($_SESSION['role']); ?>).</p>
<ul>
  <li><a href="/admin/ping.php">Network tools (ping)</a></li>
  <li><a href="/admin/upload.php">Upload media</a></li>
</ul>
<?php require __DIR__ . '/../includes/footer.php'; ?>
