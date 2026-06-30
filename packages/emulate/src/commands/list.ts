import { SERVICE_REGISTRY } from "../registry.js";

export function listCommand(): void {
  console.log("\nAvailable services:\n");
  const serviceNames = Object.keys(SERVICE_REGISTRY);
  const nameWidth = Math.max(...serviceNames.map((name) => name.length)) + 2;

  for (const [name, entry] of Object.entries(SERVICE_REGISTRY)) {
    console.log(`  ${name.padEnd(nameWidth)}${entry.label}`);
    console.log(`  ${" ".repeat(nameWidth)}Endpoints: ${entry.endpoints}`);
    console.log();
  }
}
