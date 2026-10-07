<?php
require __DIR__ . '/db.php';
session_start();
if (empty($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
$db = qd_db();
$res = $db->query('SELECT name, email, phone, card_last4, mrr FROM customers ORDER BY id');
?><!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>QuickDesk — customer book</title></head>
<body>
  <h1>Customer book</h1>
  <p>Signed in as <strong><?= htmlspecialchars($_SESSION['user']) ?></strong>
     (<?= htmlspecialchars($_SESSION['role']) ?>) — <a href="logout.php">sign out</a></p>
  <table border="1" cellpadding="4">
    <tr><th>Account</th><th>Billing email</th><th>Phone</th><th>Card</th><th>MRR</th></tr>
    <?php while ($row = $res->fetch_assoc()): ?>
      <tr>
        <td><?= htmlspecialchars($row['name']) ?></td>
        <td><?= htmlspecialchars($row['email']) ?></td>
        <td><?= htmlspecialchars($row['phone']) ?></td>
        <td>•••• <?= htmlspecialchars($row['card_last4']) ?></td>
        <td>$<?= htmlspecialchars($row['mrr']) ?></td>
      </tr>
    <?php endwhile; ?>
  </table>
</body>
</html>
