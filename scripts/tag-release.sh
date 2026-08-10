#!/bin/bash
# Commit the version bump on master, then build the tag on a detached child
# commit that pins Cargo.lock. Nothing is pushed.
set -euo pipefail

usage() {
	cat >&2 <<-EOF
	usage: ${0##*/} vX.Y.Z CHANGELOG_FILE

	CHANGELOG_FILE holds the tag annotation body (the grouped sections only;
	the version line is prepended). Requires a clean tree on master with the
	Cargo.toml version already bumped to X.Y.Z and nothing else modified.
	EOF
	exit 2
}

[ $# -eq 2 ] || usage
version=$1
changelog=$2

[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a vX.Y.Z version: $version" >&2; exit 1; }
[ -s "$changelog" ] || { echo "changelog file is empty or missing: $changelog" >&2; exit 1; }

cd "$(git rev-parse --show-toplevel)"

branch=$(git symbolic-ref --short HEAD)
[ "$branch" = master ] || { echo "not on master (on $branch)" >&2; exit 1; }

if git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
	echo "tag $version already exists — tags are immutable, make a new patch release" >&2
	exit 1
fi

manifest_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ "v$manifest_version" = "$version" ] || {
	echo "Cargo.toml is at $manifest_version, releasing $version — bump it first" >&2
	exit 1
}

dirty=$(git status --porcelain --untracked-files=no)
case $dirty in
	"") ;;
	*) [ "${dirty#?? }" = Cargo.toml ] || {
		echo "working tree must be clean or have Cargo.toml as its only modification, got:" >&2
		echo "$dirty" >&2
		exit 1
	} ;;
esac

[ -f Cargo.lock ] || { echo "no Cargo.lock to pin — run a cargo command first" >&2; exit 1; }

# A breaking change bumps the version in its own commit, so by release time the
# manifest is often already correct and there is nothing to commit on master.
if [ -n "$dirty" ]; then
	git add Cargo.toml
	git commit -m "release: $version"
fi
release_commit=$(git rev-parse HEAD)

git checkout --detach
if git symbolic-ref -q HEAD >/dev/null; then
	echo "detach failed, HEAD still on a branch — refusing to stage Cargo.lock" >&2
	echo "master is at $release_commit with the bump committed; nothing else was done" >&2
	exit 1
fi

git add -f Cargo.lock
git commit -m "build: pin Cargo.lock for $version"
git tag -as "$version" -F - <<EOF
$version

$(cat "$changelog")
EOF

git switch master

cat <<-EOF

	$version tags $(git rev-parse --short "$version^{commit}") (Cargo.lock pinned),
	child of master at $(git rev-parse --short HEAD). Nothing pushed.
EOF
