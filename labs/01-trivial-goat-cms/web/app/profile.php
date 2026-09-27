<?php require __DIR__ . '/db.php'; require __DIR__ . '/includes/header.php'; ?>
<?php
// IDOR: any user's profile (incl. email + role) is viewable by id, with no
// authentication and no ownership check. ?uid=1 exposes the admin.
$uid = (int) ($_GET['uid'] ?? 1);
$res = mysqli_query($conn, "SELECT id, username, email, role, created_at
                            FROM users WHERE id = $uid");
if ($row = mysqli_fetch_assoc($res)) {
    echo '<h2>' . htmlspecialchars($row['username']) . '</h2>';
    echo '<ul>';
    echo '<li>User ID: ' . (int) $row['id'] . '</li>';
    echo '<li>Email: ' . htmlspecialchars($row['email']) . '</li>';
    echo '<li>Role: ' . htmlspecialchars($row['role']) . '</li>';
    echo '<li>Joined: ' . htmlspecialchars((string) $row['created_at']) . '</li>';
    echo '</ul>';
} else {
    echo '<p>No such user.</p>';
}
?>
<?php require __DIR__ . '/includes/footer.php'; ?>
