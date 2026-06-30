export const PAGE_TITLES: Record<string, string> = {
  "": "Local API Emulation\nfor CI and Sandboxes",
  "programmatic-api": "Programmatic API",
  configuration: "Configuration",
  nextjs: "Next.js Integration",
  vercel: "Vercel API",
  github: "GitHub API",
  google: "Google API",
  slack: "Slack API",
  linear: "Linear API",
  apple: "Apple Sign In",
  microsoft: "Microsoft Entra ID",
  auth0: "Auth0",
  aws: "AWS",
  "durable-streams": "Durable Streams",
  okta: "Okta",
  mongoatlas: "MongoDB Atlas",
  resend: "Resend",
  stripe: "Stripe",
  authentication: "Authentication",
  architecture: "Architecture",
};

export function getPageTitle(slug: string): string | null {
  return slug in PAGE_TITLES ? PAGE_TITLES[slug]! : null;
}
