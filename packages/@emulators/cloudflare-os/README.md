# @emulators/cloudflare-os

This package runs the official open-source Cloudflare OS local runtime behind the
`emulate` CLI. It does not reimplement Cloudflare OS and it does not emulate the
separate `/v1/workspaces` sandbox-provider API used by Stream Slack's real-provider
capstone.

Configure it in the same seed file as the other emulators:

```yaml
cloudflare-os:
  port: 4102
  runtime:
    enabled: true
    source: ../cloudflare-os
    port: 8787
    startup_timeout_ms: 120000
```

The source must be an official Cloudflare OS checkout containing a
`package.json` named `cloudflare-os` with the `run-local` script. The launcher
executes `pnpm run-local -- --port <port>`, waits for the Wrangler server, and
proxies the official UI through the emulator service URL.

Useful endpoints on the proxy are `/_emulate/health` and `/_emulate/config`.
The latter reports launch configuration but never returns configured environment
values. Set `runtime.enabled: false` when the official checkout is not available;
the service then stays explicit and fail-closed instead of silently serving a fake
Cloudflare OS.

The local runtime is development infrastructure only. `make verify-E4-T08-real`
must continue to receive a real Cloudflare provider endpoint and credentials; this
package cannot satisfy that gate.
