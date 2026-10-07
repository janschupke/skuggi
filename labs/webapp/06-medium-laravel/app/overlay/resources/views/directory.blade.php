<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>LumenPay — merchant directory</title>
    <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
               margin: 0; background: #0f172a; color: #e2e8f0; }
        .wrap { max-width: 52rem; margin: 0 auto; padding: 2.5rem 1.5rem; }
        .brand { font-size: 1.6rem; font-weight: 800; }
        .brand span { color: #38bdf8; }
        table { width: 100%; border-collapse: collapse; margin-top: 1.25rem;
                background: #1e293b; border-radius: 12px; overflow: hidden; }
        th, td { text-align: left; padding: .65rem .8rem; border-bottom: 1px solid #334155; }
        th { background: #334155; }
        a { color: #38bdf8; }
        .muted { color: #94a3b8; }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="brand">Lumen<span>Pay</span> &middot; Merchant directory</div>
        @if ($merchants->isEmpty())
            <p class="muted">No merchants to display (the directory service may still be warming up).</p>
        @else
            <table>
                <thead><tr><th>Merchant</th><th>Billing contact</th><th>Plan</th><th>Status</th></tr></thead>
                <tbody>
                @foreach ($merchants as $m)
                    <tr>
                        <td>{{ $m->name }}</td>
                        <td>{{ $m->contact_email }}</td>
                        <td>{{ $m->plan }}</td>
                        <td>{{ $m->status }}</td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        @endif
        <p style="margin-top:1.5rem"><a href="/">&larr; Back to LumenPay</a></p>
    </div>
</body>
</html>
