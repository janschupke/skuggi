<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>LumenPay — merchant onboarding</title>
    <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
               margin: 0; background: #0f172a; color: #e2e8f0; }
        .wrap { max-width: 42rem; margin: 0 auto; padding: 2.5rem 1.5rem; }
        .brand { font-size: 1.6rem; font-weight: 800; }
        .brand span { color: #38bdf8; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
                padding: 1.5rem; margin: 1.25rem 0; }
        label { display: block; margin: .9rem 0 .3rem; font-weight: 600; }
        input[type=text], input[type=email], input[type=file] {
            width: 100%; padding: .55rem; border-radius: 8px; border: 1px solid #334155;
            background: #0f172a; color: #e2e8f0; box-sizing: border-box; }
        button { margin-top: 1.2rem; background: #38bdf8; color: #0f172a; border: 0;
                 font-weight: 700; padding: .65rem 1.2rem; border-radius: 8px; cursor: pointer; }
        .ok { background: #064e3b; border: 1px solid #10b981; color: #d1fae5;
              padding: .8rem; border-radius: 8px; }
        .err { background: #4c0519; border: 1px solid #f43f5e; color: #ffe4e6;
               padding: .8rem; border-radius: 8px; }
        .hint { color: #94a3b8; font-size: .9rem; }
        a { color: #38bdf8; }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="brand">Lumen<span>Pay</span> &middot; Merchant onboarding</div>

        @if (session('status'))
            <div class="card ok">{{ session('status') }}</div>
        @endif
        @if (session('error'))
            <div class="card err">{{ session('error') }}</div>
        @endif

        <form class="card" action="/merchant/onboarding/document" method="POST" enctype="multipart/form-data">
            @csrf
            <h2>Verification document</h2>
            <label for="business">Business name</label>
            <input type="text" id="business" name="business" placeholder="Acme Retail Ltd">

            <label for="contact">Billing contact email</label>
            <input type="email" id="contact" name="contact" placeholder="billing@acme.example">

            <label for="document">Document (logo, ID scan, or business licence)</label>
            <input type="file" id="document" name="document">
            <p class="hint">Accepted: PNG, JPG, GIF, or PDF. Files are filed to our
               document store for review by the onboarding team.</p>

            <button type="submit">Submit document</button>
        </form>

        <p><a href="/">&larr; Back to LumenPay</a></p>
    </div>
</body>
</html>
