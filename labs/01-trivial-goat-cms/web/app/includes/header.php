<?php if (session_status() === PHP_SESSION_NONE) { session_start(); } ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Goat Blog</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
    header{border-bottom:2px solid #e0b400;padding-bottom:.5rem;margin-bottom:1.5rem}
    nav a{margin-right:1rem;text-decoration:none;color:#0a6}
    .post{border:1px solid #ddd;border-radius:8px;padding:1rem;margin-bottom:1rem}
    .muted{color:#777;font-size:.85rem}
    pre{background:#f4f4f4;padding:1rem;overflow:auto;border-radius:6px}
    input,button{font-size:1rem;padding:.4rem}
  </style>
</head>
<body>
<header>
  <h1>🐐 Goat Blog</h1>
  <nav>
    <a href="/index.php">Home</a>
    <a href="/index.php?page=pages/about.php">About</a>
    <a href="/index.php?page=pages/contact.php">Contact</a>
    <a href="/search.php">Search</a>
    <?php if (!empty($_SESSION['username'])): ?>
      <a href="/admin/index.php">Admin</a>
      <a href="/logout.php">Logout (<?php echo htmlspecialchars($_SESSION['username']); ?>)</a>
    <?php else: ?>
      <a href="/login.php">Login</a>
    <?php endif; ?>
  </nav>
</header>
