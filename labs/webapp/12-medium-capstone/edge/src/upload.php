<?php
// VaultLine release-asset uploader.
$msg = '';
$link = '';
// Only image artifacts are meant to be stored for the dashboard.
$allowed = ['image/png', 'image/jpeg', 'image/gif'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['artifact'])) {
    $f = $_FILES['artifact'];
    // VULN (vector C): validation trusts the CLIENT-SUPPLIED MIME type
    // ($_FILES[...]['type'], straight from the request) and keeps the original
    // filename + extension. A .php uploaded with "Content-Type: image/png" is
    // accepted and lands in a web-served, PHP-executing directory.
    if ($f['error'] === UPLOAD_ERR_OK && in_array($f['type'], $allowed, true)) {
        $name = basename($f['name']);
        $dest = __DIR__ . '/uploads/' . $name;
        if (move_uploaded_file($f['tmp_name'], $dest)) {
            $msg  = 'Stored release asset.';
            $link = 'uploads/' . rawurlencode($name);
        } else {
            $msg = 'Could not store the asset (write failed).';
        }
    } else {
        $msg = 'Rejected: only PNG / JPEG / GIF release assets are accepted.';
    }
}
?><!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>VaultLine — upload release asset</title></head>
<body>
  <h1>Upload a release asset</h1>
  <?php if ($msg): ?><p><strong><?= htmlspecialchars($msg) ?></strong></p><?php endif; ?>
  <?php if ($link): ?><p>Preview: <a href="<?= htmlspecialchars($link) ?>"><?= htmlspecialchars($link) ?></a></p><?php endif; ?>
  <form method="post" action="upload.php" enctype="multipart/form-data">
    <p><input type="file" name="artifact"></p>
    <p><button type="submit">Upload</button></p>
  </form>
  <p><a href="index.php">back</a></p>
</body>
</html>
