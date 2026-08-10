Perform a release of freeswitch-sofia-trace-parser.

Optional override: $ARGUMENTS (format: vX.Y.Z). If provided, use that version.

## Version determination

1. Find the last release tag (`git tag --sort=-v:refname | head -1`).
2. Examine commits since that tag to classify the release type:
   - **Patch**: only bug fixes, dependency bumps, build changes, docs.
   - **Minor**: new features (`feat:`), new public API surface.
   - **Major**: breaking API changes, removed public items.
3. Bump the version accordingly. If **major**, stop and confirm before proceeding.

Pre-`1.0`, a breaking change is a minor bump (`0.7.x` → `0.8.0`) — `cargo semver-checks`
enforces that, so a red semver run on a patch bump means the bump was wrong.

## Pre-release checks

Run in sequence — stop and report on any failure:

```sh
cargo fmt
cargo clippy --fix --allow-dirty --features cli --all-targets --message-format=short
cargo check --no-default-features --message-format=short
cargo check --features cli --all-targets --message-format=short
cargo test --release --lib
cargo test --release --features cli --bin freeswitch-sofia-trace-parser
cargo semver-checks --baseline-rev <last-tag> --only-explicit-features
```

`--only-explicit-features` is required: the `pidf-test` feature pulls a git-only
dependency that a bare semver-checks run cannot resolve.

The `pre-commit` hook re-runs fmt, clippy, rustdoc coverage, tests and
semver-checks on the release commit, so it is the gate — the list above only
front-loads the failures.

Integration tests (`--test level{1,2,3}_samples`) need `samples/` and skip when it
is absent. Run them if the samples are present on this machine; their absence is
not a release blocker.

## Steps

1. Bump `version` in `Cargo.toml` — often already done, since a breaking change
   bumps it in its own commit. Then master needs no release commit and step 4
   skips it.

2. Run pre-release checks above.

3. Draft a changelog from `git log --oneline <last-tag>..HEAD`.

   **Rules:**
   - Group under: `New features:`, `Bug fixes:`, `Build:`, `Refactoring:` — omit empty sections.
   - Describe user-visible behavior, not implementation details.
   - Merge related commits for the same feature into one bullet.
   - No git hashes, no raw commit subjects, no co-author lines.

   Tag annotation format:
   ```
   vX.Y.Z

   New features:
   - what changed

   Bug fixes:
   - what was fixed

   Build:
   - what changed
   ```

4. Write the changelog sections (no version line) to `release-notes.txt`, then
   commit the bump and build the tag:

```sh
scripts/tag-release.sh vX.Y.Z release-notes.txt
rm release-notes.txt
```

   Nothing is pushed. The tag sits on a detached child commit that pins
   `Cargo.lock`, so the lock never lands on master while the tagged tree still
   builds from an exact dependency set. The script refuses to run unless it is
   on master with a clean tree or `Cargo.toml` as its only modification, the
   manifest version matches, and the tag does not exist yet; it aborts before
   staging the lock if the detach did not take.

   Never open-code these git commands instead — a chain rejected part-way
   (a hook, a denied permission) silently skips its untried half, and the
   failure mode is `Cargo.lock` committed onto master.

   Both commits run the `pre-commit` hook in full, so expect two clippy+test
   cycles. Back on master the working-tree `Cargo.lock` is untracked again; the
   next cargo command regenerates it.

5. Push master, wait for CI green:

```sh
git push
gh run watch "$(gh run list --workflow=ci.yml -b master -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

   No run within a couple of minutes: check the `Actions` component at
   `https://www.githubstatus.com/api/v2/components.json` — during an outage no
   run is created and missed events are never backfilled. Stop and report.

   Red: fix on master, rebuild the tag onto the new head, restart this step.

6. Push the tag:

```sh
git push origin vX.Y.Z
```

   CI does not run on tags and there is no release workflow — the tag is the
   release artifact. No GitHub release is created.

7. Report the tag, the changelog, and the CI run that gated it.

## Important

- **No `cargo publish`.** The crate is not currently publishable: the optional
  `eido` dependency is a git dependency with no crates.io version, which cargo
  refuses at publish time. See `CLAUDE.local.md`.
- **Never tag a commit CI has not run on.** If the tree changed after the checks
  — a rebase, a hand-resolved conflict, a dependency that resolved differently —
  the earlier green run does not cover it. Re-run the checks and go back to step 5.
- **Ask before pushing the tag when anything deviated from these steps.** An
  outage, a rebase, a skipped step, a red-then-fixed run: report the state and
  let me decide.
- **Cargo.lock never reaches master** — library crate, stays gitignored there. It
  exists only on the tag's own commit, so a tagged build is reproducible.
- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
