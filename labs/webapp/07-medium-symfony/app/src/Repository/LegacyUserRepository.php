<?php

namespace App\Repository;

use Doctrine\DBAL\Connection;

/**
 * Pre-dates the ORM migration. Several methods still build SQL by string
 * concatenation. It was supposed to be retired — it was not.
 */
class LegacyUserRepository
{
    public function __construct(private readonly Connection $conn)
    {
    }

    /**
     * Authenticate a portal user.
     *
     * VULN (SQLi): $email is concatenated straight into the query. The password
     * is hashed before comparison, so the EMAIL field is the injection point:
     *     email = admin@cividoc.lab' --
     *     email = ' OR '1'='1' --
     * Either returns a row and logs the attacker in. A UNION on this same query
     * dumps every column of app_user (and, with care, other tables).
     */
    public function authenticate(string $email, string $password): ?array
    {
        $hash = hash('sha256', $password);

        $sql = "SELECT id, email, display_name, role, tenant_id "
             . "FROM app_user "
             . "WHERE email = '" . $email . "' "
             . "AND password_sha256 = '" . $hash . "'";

        // executeQuery runs the string verbatim — no bound parameters.
        $row = $this->conn->executeQuery($sql)->fetchAssociative();

        return $row ?: null;
    }
}
