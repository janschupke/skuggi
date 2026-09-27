<?php require __DIR__ . '/../includes/auth_admin.php'; require __DIR__ . '/../includes/header.php'; ?>
<h2>Upload media</h2>
<?php
// Unrestricted file upload: no extension/content-type/size checks and the target
// directory executes PHP. Upload shell.php then browse /uploads/shell.php?c=id
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $name = basename($_FILES['file']['name']);
    $dest = __DIR__ . '/../uploads/' . $name;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        $msg = 'Uploaded to /uploads/' . htmlspecialchars($name);
    } else {
        $msg = 'Upload failed.';
    }
}
?>
<?php if ($msg): ?><p><?php echo $msg; ?></p><?php endif; ?>
<form method="post" action="/admin/upload.php" enctype="multipart/form-data">
  <p><input type="file" name="file"></p>
  <p><button type="submit">Upload</button></p>
</form>
<?php require __DIR__ . '/../includes/footer.php'; ?>
