// Bazaar storefront bootstrap.
const CONFIG = {
  // Link-preview widget: proxies a supplied URL through the edge API.
  previewEndpoint: "/api/fetch?url=",

  // Internal service mesh (NOT reachable from the edge; the API brokers calls).
  services: {
    // instance metadata / service-credential endpoint
    metadata: "http://metadata.internal/creds",
    // internal order-management API (needs the service token from metadata)
    orders:   "http://orders.internal/orders"
  }
};
// TODO(dev): the checkout page reads orders via CONFIG.services.orders using the
// token fetched from CONFIG.services.metadata. Do not expose these on the edge.
console.log("bazaar storefront", CONFIG);
