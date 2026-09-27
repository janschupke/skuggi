-- Accounts. Passwords are UNSALTED md5 of intentionally weak values so they
-- crack instantly from a wordlist once dumped (SQLi or the leftover backup):
--   admin  : password123   (md5 482c811da5d5b4bc6d497ffa98491e38)
--   alice  : letmein       (md5 0d107d09f5bbe40cade3de5c71e9e9b7)
--   bob    : qwerty        (md5 d8578edf8458ce06fbc5bb76a58c5ca4)
--   carol  : iloveyou      (md5 f25a2fc72690b780b2a14e140ef6a9e0)
INSERT INTO users (id, username, password, email, role) VALUES
    (1, 'admin', '482c811da5d5b4bc6d497ffa98491e38', 'admin@web.lab',  'admin'),
    (2, 'alice', '0d107d09f5bbe40cade3de5c71e9e9b7', 'alice@web.lab',  'user'),
    (3, 'bob',   'd8578edf8458ce06fbc5bb76a58c5ca4', 'bob@web.lab',    'user'),
    (4, 'carol', 'f25a2fc72690b780b2a14e140ef6a9e0', 'carol@web.lab',  'user');

-- Posts: public, a draft, and a private one. IDOR/enumeration reveals the last two.
INSERT INTO posts (id, author_id, title, body, status, is_private) VALUES
    (1, 1, 'Welcome to Goat Blog',
        'This is our shiny new blog running on the Goat CMS. Look around!', 'published', 0),
    (2, 2, 'My first trip report',
        'Alice writes about hiking the northern trail last weekend.', 'published', 0),
    (3, 3, 'Coffee brewing notes',
        'Bob shares his pour-over ratios and grind sizes.', 'published', 0),
    (4, 1, 'DRAFT: site migration checklist',
        'Internal draft — remember to remove /backup/db_dump.sql before launch!', 'draft', 0),
    (5, 1, 'PRIVATE: infrastructure credentials',
        'Reminder to self: db user bloguser / blogpass123, and root / toor on MySQL. Rotate these!',
        'published', 1);

INSERT INTO comments (post_id, author, body) VALUES
    (1, 'alice', 'Great to see the blog up!'),
    (1, 'bob',   'Nice work.'),
    (2, 'carol', 'Sounds like a lovely hike.');

INSERT INTO messages (sender_id, recipient_id, body) VALUES
    (2, 1, 'Hi admin, can you review my draft?'),
    (1, 2, 'Sure Alice, looks good.');
