import createMDX from "@next/mdx";

const withMDX = createMDX();

const oldDocsSlugs = [
  "programmatic-api",
  "configuration",
  "nextjs",
  "vercel",
  "github",
  "google",
  "slack",
  "linear",
  "apple",
  "microsoft",
  "auth0",
  "aws",
  "okta",
  "mongoatlas",
  "resend",
  "stripe",
  "clerk",
  "agent-vault",
  "authentication",
  "architecture",
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  pageExtensions: ["ts", "tsx", "md", "mdx"],
  serverExternalPackages: ["just-bash", "bash-tool"],
  async redirects() {
    return oldDocsSlugs.map((slug) => ({
      source: `/${slug}`,
      destination: `/docs/${slug}`,
      permanent: true,
    }));
  },
};

export default withMDX(nextConfig);
