# Local Lab Checklist

## Intake

- Confirm the user owns the target or is explicitly authorized to assess it.
- Keep the target inside an isolated lab or disposable snapshot.
- Record the artifact hash, version string, platform, and acquisition source.
- Preserve original configs, manifests, and logs before making any changes.

## Evidence Collection

- List packages, services, ports, and bundled libraries.
- Collect manifests, lockfiles, SBOMs, container metadata, and build information.
- Identify management interfaces, admin paths, and default-exposed services.
- Capture vendor docs that describe defaults, requirements, and hardening guidance.

## Safe Validation

- Verify exact versions locally before mapping CVEs.
- Compare bundled component versions against vendor and CVE fixed versions.
- Inspect whether the vulnerable feature, module, or configuration is actually present.
- Use non-destructive requests and observations against the local lab instance only.
- Summarize exploit preconditions from advisories without reproducing exploit mechanics.

## Stop Conditions

- The user requests offensive use, payloads, or exploit code.
- The target is no longer local or no authorization is available.
- The version cannot be established with reasonable confidence.
- Sources materially conflict and the conflict cannot be resolved from primary evidence.
