#!/bin/sh
set -eu

repo="https://github.com/mozilla/nss"
api="https://api.github.com/repos/mozilla/nss"

find_latest_tag() {
	git ls-remote --tags "$repo" 2>/dev/null \
		| sed -n 's|.*refs/tags/\(NSS_[0-9_]*_RTM\)$|\1|p' \
		| sort -t_ -k2,2n -k3,3n -k4,4n \
		| tail -1
}

commit_date() {
	tag="$1"
	sha=$(curl -sL "$api/git/refs/tags/$tag" | sed -n 's/.*"sha": "\([a-f0-9]\{40\}\)".*/\1/p')
	curl -sL "$api/git/commits/$sha" | sed -n 's/.*"date": "\([0-9-]*\)T.*/\1/p' | head -1
}

if [ "${1:-}" = "--latest" ]; then
	nss_tag=$(find_latest_tag)
	echo "Latest: $nss_tag"
	sed -i "s/^NSS_VERSION := .*/NSS_VERSION := $nss_tag/" Makefile
else
	nss_tag=$(sed -n 's/^NSS_VERSION := //p' Makefile)
fi

date_str=$(commit_date "$nss_tag")
version=$(echo "$date_str" | tr -d '-')
echo "$version" > VERSION

echo "NSS_VERSION=$nss_tag"
echo "VERSION=$version ($date_str)"
