<?php require __DIR__ . '/db.php'; require __DIR__ . '/includes/header.php'; ?>
<?php
// LFI: `page` is included with no sanitization and no extension appended, so any
// readable file works, e.g. ?page=../../../etc/passwd  (webroot is /var/www/html,
// so ../../../ reaches /). Also enables log poisoning:
//   ?page=../../../var/log/apache2/access.log  after seeding PHP in a User-Agent.
if (isset($_GET['page'])) {
    include __DIR__ . '/' . $_GET['page'];
    require __DIR__ . '/includes/footer.php';
    return;
}
?>
<h2>Latest posts</h2>
<?php
$res = mysqli_query($conn, "SELECT p.id, p.title, LEFT(p.body,120) AS teaser, u.id AS uid, u.username
                            FROM posts p JOIN users u ON p.author_id = u.id
                            WHERE p.status='published' AND p.is_private=0
                            ORDER BY p.id DESC");
while ($row = mysqli_fetch_assoc($res)) {
    $id = (int) $row['id'];
    $uid = (int) $row['uid'];
    echo '<div class="post"><h3><a href="/post.php?id=' . $id . '">'
        . htmlspecialchars($row['title']) . '</a></h3>';
    echo '<p>' . htmlspecialchars($row['teaser']) . '…</p>';
    echo '<p class="muted">by <a href="/profile.php?uid=' . $uid . '">'
        . htmlspecialchars($row['username']) . '</a></p></div>';
}
?>
<?php require __DIR__ . '/includes/footer.php'; ?>
