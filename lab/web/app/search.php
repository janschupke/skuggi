<?php require __DIR__ . '/db.php'; require __DIR__ . '/includes/header.php'; ?>
<h2>Search posts</h2>
<form method="get" action="/search.php">
  <input type="text" name="q" value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>" placeholder="keyword">
  <button type="submit">Search</button>
</form>
<?php
// SQLi (string context, 3 columns). UNION dump example:
//   ?q=zzz' UNION SELECT id,username,password FROM users-- -
if (isset($_GET['q'])) {
    $q = $_GET['q'];
    $sql = "SELECT id, title, body FROM posts
            WHERE status='published' AND title LIKE '%$q%'";
    $res = mysqli_query($conn, $sql);
    if (!$res) {
        echo '<pre>SQL error: ' . htmlspecialchars(mysqli_error($conn)) . '</pre>';
    } else {
        echo '<h3>Results</h3>';
        while ($row = mysqli_fetch_assoc($res)) {
            echo '<div class="post"><strong>' . htmlspecialchars($row['title']) . '</strong>';
            echo '<p>' . htmlspecialchars($row['body']) . '</p></div>';
        }
    }
}
?>
<?php require __DIR__ . '/includes/footer.php'; ?>
