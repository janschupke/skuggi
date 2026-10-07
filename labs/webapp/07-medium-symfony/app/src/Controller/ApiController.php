<?php

namespace App\Controller;

use App\Repository\DocumentRepository;
use App\Repository\InvoiceRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

/**
 * The portal's JSON API. Every action resolves the caller's "current tenant"
 * from the session but then NEVER uses it to constrain the lookup — so any
 * authenticated-looking request can read any tenant's record (IDOR). The lab
 * seeds a browsing session (tenant 1) so the endpoints work straight from curl.
 */
class ApiController extends AbstractController
{
    #[Route('/api/invoices/{id}', name: 'api_invoice', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function invoice(int $id, Request $request, InvoiceRepository $invoices): JsonResponse
    {
        // The caller's own tenant — resolved, then ignored.
        $currentTenant = (int) $request->getSession()->get('tenant_id', 1);

        $invoice = $invoices->find($id);
        if ($invoice === null) {
            return new JsonResponse(['error' => 'not found'], JsonResponse::HTTP_NOT_FOUND);
        }

        // BUG: should be `if ($invoice['tenant_id'] !== $currentTenant) deny;`
        return new JsonResponse([
            'id' => (int) $invoice['id'],
            'tenant_id' => (int) $invoice['tenant_id'],
            'number' => $invoice['number'],
            'customer_name' => $invoice['customer_name'],
            'billing_email' => $invoice['billing_email'],
            'amount_cents' => (int) $invoice['amount_cents'],
            'status' => $invoice['status'],
            'issued_on' => $invoice['issued_on'],
            '_viewer_tenant' => $currentTenant,
        ]);
    }

    #[Route('/api/documents', name: 'api_document', methods: ['GET'])]
    public function document(Request $request, DocumentRepository $documents): JsonResponse
    {
        $id = $request->query->getInt('id');
        if ($id <= 0) {
            return new JsonResponse(['error' => 'id query parameter required'], JsonResponse::HTTP_BAD_REQUEST);
        }

        $currentTenant = (int) $request->getSession()->get('tenant_id', 1);

        $document = $documents->find($id);
        if ($document === null) {
            return new JsonResponse(['error' => 'not found'], JsonResponse::HTTP_NOT_FOUND);
        }

        // Same missing tenant check as the invoice endpoint.
        return new JsonResponse([
            'id' => (int) $document['id'],
            'tenant_id' => (int) $document['tenant_id'],
            'title' => $document['title'],
            'filename' => $document['filename'],
            'confidential' => (bool) $document['confidential'],
            '_viewer_tenant' => $currentTenant,
        ]);
    }
}
