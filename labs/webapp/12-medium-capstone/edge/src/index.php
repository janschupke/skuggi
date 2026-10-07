<?php session_start(); ?><!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>VaultLine — Deployment Asset Portal</title></head>
<body>
  <h1>VaultLine</h1>
  <p>Deployment Asset Portal — upload and preview release artifacts (logos, banners,
     screenshots) for the VaultLine delivery dashboard.</p>
  <ul>
    <li><a href="upload.php">Upload a release asset</a></li>
    <li>Uploaded assets are served from <code>/uploads/</code>.</li>
  </ul>
  <!-- TODO(ops): the deploy agent still reads /opt/vaultline/deploy.conf at boot;
       rotate the svc password before the vault.vaultline.lab cutover. -->
  <hr>
  <p><small>VaultLine Inc. — internal tooling. Not for production exposure.</small></p>
</body>
</html>
