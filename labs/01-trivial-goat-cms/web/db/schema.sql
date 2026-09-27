-- skuggi practice lab — blog schema. Imported into database `blog` on first boot.
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(64)  NOT NULL UNIQUE,
    password   CHAR(32)     NOT NULL,           -- unsalted md5 (intentionally weak)
    email      VARCHAR(128) NOT NULL,
    role       VARCHAR(16)  NOT NULL DEFAULT 'user',
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    author_id  INT          NOT NULL,
    title      VARCHAR(200) NOT NULL,
    body       TEXT         NOT NULL,
    status     ENUM('published','draft') NOT NULL DEFAULT 'published',
    is_private TINYINT(1)   NOT NULL DEFAULT 0,   -- 1 = author-only (IDOR reveals it)
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE comments (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    post_id    INT          NOT NULL,
    author     VARCHAR(64)  NOT NULL,
    body       TEXT         NOT NULL,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE messages (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    sender_id    INT          NOT NULL,
    recipient_id INT          NOT NULL,
    body         TEXT         NOT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
