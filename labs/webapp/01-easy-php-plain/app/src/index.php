<?php
require __DIR__ . '/db.php';
session_start();
?><!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>QuickDesk — customer helpdesk</title></head>
<body>
  <h1>QuickDesk</h1>
  <p>Internal customer helpdesk portal.</p>
  <?php if (!empty($_SESSION['user'])): ?>
    <p>Signed in as <strong><?= htmlspecialchars($_SESSION['user']) ?></strong>
       (<?= htmlspecialchars($_SESSION['role']) ?>) —
       <a href="dashboard.php">open dashboard</a> · <a href="logout.php">sign out</a></p>
  <?php else: ?>
    <p><a href="login.php">Agent sign in</a></p>
  <?php endif; ?>
  <!-- TODO(ops): move the nightly SQL dump out of the web root (backup/). -->
</body>
</html>
