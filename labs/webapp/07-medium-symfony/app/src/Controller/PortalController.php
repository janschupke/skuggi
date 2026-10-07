<?php

namespace App\Controller;

use App\Repository\DocumentRepository;
use App\Repository\LegacyUserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PortalController extends AbstractController
{
    public function __construct(private readonly string $documentDir)
    {
    }

    #[Route('/portal/login', name: 'portal_login', methods: ['GET', 'POST'])]
    public function login(Request $request, LegacyUserRepository $users): Response
    {
        $error = null;

        if ($request->isMethod('POST')) {
            $email = (string) $request->request->get('email', '');
            $password = (string) $request->request->get('password', '');

            // VULN (SQLi): authenticate() concatenates $email into raw SQL.
            $user = $users->authenticate($email, $password);

            if ($user !== null) {
                $session = $request->getSession();
                $session->set('user_id', (int) $user['id']);
                $session->set('email', $user['email']);
                $session->set('role', $user['role']);
                $session->set('tenant_id', (int) $user['tenant_id']);

                return $this->redirectToRoute('portal_documents');
            }

            $error = 'Invalid credentials.';
        }

        return $this->render('portal/login.html.twig', ['error' => $error]);
    }

    #[Route('/portal/documents', name: 'portal_documents', methods: ['GET'])]
    public function documents(Request $request, DocumentRepository $documents): Response
    {
        $tenantId = (int) $request->getSession()->get('tenant_id', 1);

        return $this->render('portal/documents.html.twig', [
            'email' => $request->getSession()->get('email', 'guest'),
            'tenant_id' => $tenantId,
            'documents' => $documents->findForTenant($tenantId),
        ]);
    }

    /**
     * Stream a stored document by filename.
     *
     * VULN (path traversal): the requested name is joined to the base dir with
     * no normalisation and no containment check, so `../` escapes var/documents:
     *     /portal/documents/download?file=../../../../secrets/cividoc.env
     *     /portal/documents/download?file=../../../../../etc/passwd
     */
    #[Route('/portal/documents/download', name: 'portal_download', methods: ['GET'])]
    public function download(Request $request): Response
    {
        $file = (string) $request->query->get('file', '');
        if ($file === '') {
            return new Response('missing file parameter', Response::HTTP_BAD_REQUEST);
        }

        $full = $this->documentDir . '/' . $file;
        $contents = @file_get_contents($full);
        if ($contents === false) {
            return new Response('document not found', Response::HTTP_NOT_FOUND);
        }

        return new Response($contents, Response::HTTP_OK, [
            'Content-Type' => 'application/octet-stream',
            'Content-Disposition' => 'attachment; filename="' . basename($file) . '"',
        ]);
    }
}
