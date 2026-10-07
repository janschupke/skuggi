<?php

use App\Http\Controllers\MerchantDocumentController;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfTokens;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => view('welcome'));

// Merchant onboarding. The upload form is linked from the landing page, and the
// POST target is advertised in the form's action — discoverable from the app
// itself, not a stock wordlist path.
Route::get('/merchant/onboarding', [MerchantDocumentController::class, 'form'])
    ->name('onboarding.form');

// The intake endpoint is a machine-to-machine file drop, so it forgoes CSRF.
Route::post('/merchant/onboarding/document', [MerchantDocumentController::class, 'store'])
    ->withoutMiddleware([ValidateCsrfTokens::class])
    ->name('onboarding.store');

// Merchant directory — a thin DB-backed page for realism (and to prove the
// MySQL tier is wired). Degrades to a notice if the DB is not up yet.
Route::get('/merchant/directory', function () {
    try {
        $merchants = DB::table('merchants')->orderBy('name')->get();
    } catch (\Throwable $e) {
        $merchants = collect();
    }

    return view('directory', ['merchants' => $merchants]);
})->name('merchant.directory');
