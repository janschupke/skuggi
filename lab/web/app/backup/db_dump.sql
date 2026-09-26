-- MySQL dump of the `blog` database — left behind in the webroot by mistake.
-- Directly downloadable at /backup/db_dump.sql (see the "site migration
-- checklist" draft). Contains every user's unsalted md5 password hash.
--
-- Host: localhost    Database: blog
-- ------------------------------------------------------

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password` char(32) NOT NULL,
  `email` varchar(128) NOT NULL,
  `role` varchar(16) NOT NULL DEFAULT 'user',
  PRIMARY KEY (`id`)
);

LOCK TABLES `users` WRITE;
INSERT INTO `users` VALUES
 (1,'admin','482c811da5d5b4bc6d497ffa98491e38','admin@web.lab','admin'),
 (2,'alice','0d107d09f5bbe40cade3de5c71e9e9b7','alice@web.lab','user'),
 (3,'bob','d8578edf8458ce06fbc5bb76a58c5ca4','bob@web.lab','user'),
 (4,'carol','f25a2fc72690b780b2a14e140ef6a9e0','carol@web.lab','user');
UNLOCK TABLES;

-- Note (ops): app DB account is bloguser / blogpass123; MySQL root / toor.
