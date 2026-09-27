// Ledgerline web console bootstrap.
// Endpoints are declared here and hydrated from the OpenAPI spec at load time.
const API = {
  session:  "/v1/session",     // POST {username,password} -> {token}
  customers:"/v1/customers",   // POST register
  me:       "/v1/me",
  transfer: "/v1/transfer",    // POST {from,to,amount}
  // The ops console pulls the full route table (incl. admin endpoints) from:
  spec:     "/v1/_internal/openapi.json"
};
// NOTE(dev): admin-only routes (/v1/ledger/contracts, /v1/ops/config) are
// gated on the JWT "role" claim; see the spec for the full list.
console.log("ledgerline console", API);
