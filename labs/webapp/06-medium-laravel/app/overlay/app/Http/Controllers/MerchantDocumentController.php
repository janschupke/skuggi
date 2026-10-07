<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

/**
 * Merchant onboarding document intake.
 *
 * LumenPay merchants upload KYC paperwork (business licence, ID scan, a logo
 * for their hosted checkout) during onboarding. The handler below accepts the
 * file, "checks" it, and files it under the public document store so the ops
 * team can review it from the admin console.
 *
 * NOTE (training lab): this controller is intentionally insecure. It trusts the
 * browser-declared MIME type, keeps the original filename and extension, and
 * writes into the web-reachable public/ tree — so an uploaded .php is served
 * and executed by Apache's mod_php.
 */
class MerchantDocumentController extends Controller
{
    /** Where accepted documents land, relative to the (web-reachable) public/ root. */
    private const STORE_DIR = 'uploads/kyc';

    /** The onboarding upload form. */
    public function form(Request $request)
    {
        return view('onboarding');
    }

    /** Accept and store a merchant onboarding document. */
    public function store(Request $request)
    {
        $file = $request->file('document');

        if ($file === null || ! $file->isValid()) {
            return back()->with('error', 'No document was received. Please attach a file.');
        }

        // "Validation": we only look at the Content-Type the client sent us.
        // Business says merchants send logos (PNG/JPG) and licences (PDF).
        $allowedMime = ['image/png', 'image/jpeg', 'image/gif', 'application/pdf'];
        if (! in_array($file->getClientMimeType(), $allowedMime, true)) {
            return back()->with('error', 'Unsupported document type: ' . $file->getClientMimeType());
        }

        // Keep the merchant's original filename so ops can recognise it.
        $filename = $file->getClientOriginalName();

        $destination = public_path(self::STORE_DIR);
        if (! is_dir($destination)) {
            @mkdir($destination, 0775, true);
        }

        $file->move($destination, $filename);

        $publicUrl = url(self::STORE_DIR . '/' . $filename);

        return back()->with('status', 'Document received. Review copy: ' . $publicUrl);
    }
}
