<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>LumenPay — billing that just works</title>
    <style>
        :root { color-scheme: light dark; }
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
               margin: 0; background: #0f172a; color: #e2e8f0; }
        header { padding: 3rem 1.5rem 2rem; max-width: 60rem; margin: 0 auto; }
        .brand { font-size: 2.2rem; font-weight: 800; letter-spacing: -0.02em; }
        .brand span { color: #38bdf8; }
        .tag { color: #94a3b8; margin-top: .4rem; font-size: 1.1rem; }
        main { max-width: 60rem; margin: 0 auto; padding: 0 1.5rem 4rem; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
                padding: 1.5rem; margin: 1rem 0; }
        a.btn { display: inline-block; background: #38bdf8; color: #0f172a;
                font-weight: 600; text-decoration: none; padding: .6rem 1.1rem;
                border-radius: 8px; }
        a.link { color: #38bdf8; }
        footer { color: #64748b; font-size: .85rem; max-width: 60rem;
                 margin: 0 auto; padding: 1rem 1.5rem 3rem; }
    </style>
</head>
<body>
    <header>
        <div class="brand">Lumen<span>Pay</span></div>
        <div class="tag">Subscription billing &amp; merchant payouts for modern SaaS.</div>
    </header>
    <main>
        <div class="card">
            <h2>Become a LumenPay merchant</h2>
            <p>Start accepting recurring payments today. New merchants complete a short
               onboarding: tell us about your business and upload your verification
               documents (business licence, ID, and your checkout logo).</p>
            <p><a class="btn" href="/merchant/onboarding">Start merchant onboarding &rarr;</a></p>
        </div>
        <div class="card">
            <h2>Already onboarded?</h2>
            <p>Browse the <a class="link" href="/merchant/directory">merchant directory</a>
               or sign in to your dashboard to manage subscriptions and payouts.</p>
        </div>
    </main>
    <footer>
        &copy; LumenPay, Inc. &middot; This is an internal staging environment.
    </footer>
</body>
</html>
