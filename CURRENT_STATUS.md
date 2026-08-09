# Current Status

Date: 2026-08-09

## Repository

- Repo: `https://github.com/solitudecc/frida-ios-build.git`
- Branch: `main`
- Latest pushed commit: `16d8cd9 Fix workflow final artifact check syntax`

## Build

- Successful GitHub Actions run: `31320629355`
- Artifact: `frlda-server-ios-arm64`
- Local artifact path used for deployment:
  - `/tmp/frlda-artifact-31320629355/frlda-server-ios-arm64/frlda-server-ios-arm64`
  - `/tmp/frlda-artifact-31320629355/frlda-server-ios-arm64/frlda-agent.dylib`

Local byte-level verification passed for both files:

- `frida-agent.dylib`: `0`
- `frida-server`: `0`
- `re.frida.Server`: `0`
- `frida:rpc`: `0`
- `gum-js-loop`: `0`
- `gmain`: `0`
- `gdbus`: `0`
- `GumScript`: `0`
- `GDBusProxy`: `0`
- `GLib-GIO`: `0`
- `FridaScriptEngine`: `0`
- `frida` / `Frida` / `FRIDA`: `0`

## Device Deployment

- Device UDID: `73229a27f50bfc955dc8413725769effc49bc502`
- SSH forwarding: `iproxy 2222 22`
- Frida forwarding currently used: `iproxy 5200 51001`
- Deployed files:
  - `/usr/sbin/frlda-server`
  - `/usr/lib/frlda/frlda-agent.dylib`
- `51000` was still occupied by an older server process that could not be identified with the limited device shell tools, so the new `frlda-server` was started on device port `51001`.
- Host-side Frida connection through `127.0.0.1:5200` successfully enumerated processes after switching the forwarding to `51001`.

## Test Result

Test command:

```bash
cd /home/cc/桌面/rasp
./rf -f com.globetel.gcash -q -e "Process.id" -e "'alive'" -t 12
```

Observed result:

- Spawn succeeded.
- `"alive"` returned.
- User observed GCash UI exited quickly.
- After 60 seconds:
  - no GCash process in `frida-ps`
  - no GCash entry in `frida-ps -a`

Conclusion:

- Current `frlda-*` artifact removes obvious Frida strings and the known gum interceptor prologue patch is present, but GCash still detects/exits after spawn.
- Next work should continue modifying Frida internals beyond string/process-name cleanup.
