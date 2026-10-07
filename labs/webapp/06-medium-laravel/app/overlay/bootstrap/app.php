<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // VULN: the merchant KYC document upload is exempted from CSRF
        // protection ("to let partner integrations POST documents"), so the
        // insufficiently-validated upload is reachable with a plain request.
        $middleware->validateCsrfTokens(except: [
            'merchant/onboarding/document',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
