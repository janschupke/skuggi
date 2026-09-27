// Cirrus portal bootstrap.
const CONFIG = {
  // Profile avatar/link preview — proxied server-side by the app instance.
  avatarProxy: "/api/avatar?url=",
  // This instance runs in the cloud with an attached role. Standard metadata:
  imdsBase: "http://169.254.169.254/latest/meta-data/",
  // (dev) the app reaches AWS-compatible services at the internal gateway:
  cloudEndpoint: "http://cloud.cirrus.internal:4566"
};
console.log("cirrus portal", CONFIG);
