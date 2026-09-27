<?php require __DIR__ . '/db.php'; require __DIR__ . '/includes/header.php'; ?>
<?php
// IDOR + SQLi: `id` is concatenated straight into the query (numeric context)
// and there is NO visibility check, so drafts and private posts are returned by
// simply enumerating ids. SQLi example (7 columns):
//   ?id=0 UNION SELECT 1,username,password,4,email,6,7 FROM users-- -
$id = $_GET['id'] ?? '1';
$sql = "SELECT p.id, p.title, p.body, p.created_at, u.username, p.status, p.is_private
        FROM posts p JOIN users u ON p.author_id = u.id
        WHERE p.id = $id";
$res = mysqli_query($conn, $sql);
if (!$res) {
    echo '<pre>SQL error: ' . htmlspecialchars(mysqli_error($conn)) . '</pre>';
} elseif ($row = mysqli_fetch_assoc($res)) {
    echo '<article class="post"><h2>' . htmlspecialchars($row['title']) . '</h2>';
    echo '<p class="muted">by ' . htmlspecialchars($row['username'])
        . ' · ' . htmlspecialchars((string) $row['created_at'])
        . ' · status=' . htmlspecialchars((string) $row['status'])
        . ' · private=' . htmlspecialchars((string) $row['is_private']) . '</p>';
    echo '<div>' . nl2br(htmlspecialchars($row['body'])) . '</div></article>';
} else {
    echo '<p>No such post.</p>';
}
?>
<?php require __DIR__ . '/includes/footer.php'; ?>
