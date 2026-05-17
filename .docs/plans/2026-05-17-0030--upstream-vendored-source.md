# Upstream Vendored Source

- [x] Confirm the repository currently tracks `upstream` as a git submodule.
- [x] Verify Better Auth upstream tag `v1.6.9` resolves to commit `f484269228b7eb8df0e2325e7d264bb8d7796311`.
- [x] Remove the `upstream` gitlink from the parent repository index.
- [x] Replace the submodule checkout with a non-submodule source tree at `upstream/better-auth/1.6.9/`.
- [x] Update root agent instructions to point agents at the versioned upstream source tree.
- [x] Update package-level core agent instructions that referenced the old upstream path.
