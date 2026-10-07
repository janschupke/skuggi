<?php

namespace App\Repository;

use Doctrine\DBAL\Connection;

class InvoiceRepository
{
    public function __construct(private readonly Connection $conn)
    {
    }

    /**
     * Fetch one invoice by id. This query IS parameterised (no SQLi here) — the
     * flaw is upstream: the controller never constrains the lookup to the
     * caller's own tenant, so any id is readable (IDOR).
     */
    public function find(int $id): ?array
    {
        $row = $this->conn->executeQuery(
            'SELECT id, tenant_id, number, customer_name, billing_email, '
            . 'amount_cents, status, issued_on '
            . 'FROM invoice WHERE id = :id',
            ['id' => $id],
        )->fetchAssociative();

        return $row ?: null;
    }

    public function findForTenant(int $tenantId): array
    {
        return $this->conn->executeQuery(
            'SELECT id, number, status, amount_cents, issued_on '
            . 'FROM invoice WHERE tenant_id = :t ORDER BY id',
            ['t' => $tenantId],
        )->fetchAllAssociative();
    }
}
