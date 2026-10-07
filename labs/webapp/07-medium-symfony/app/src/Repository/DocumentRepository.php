<?php

namespace App\Repository;

use Doctrine\DBAL\Connection;

class DocumentRepository
{
    public function __construct(private readonly Connection $conn)
    {
    }

    public function find(int $id): ?array
    {
        $row = $this->conn->executeQuery(
            'SELECT id, tenant_id, title, filename, confidential '
            . 'FROM document WHERE id = :id',
            ['id' => $id],
        )->fetchAssociative();

        return $row ?: null;
    }

    public function findForTenant(int $tenantId): array
    {
        return $this->conn->executeQuery(
            'SELECT id, title, filename, confidential '
            . 'FROM document WHERE tenant_id = :t ORDER BY id',
            ['t' => $tenantId],
        )->fetchAllAssociative();
    }
}
