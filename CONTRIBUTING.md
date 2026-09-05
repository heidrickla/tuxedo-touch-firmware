# Conventions

## Writing

Concise. No fluff, prose, embellishment or emojis, in code comments,
documentation, commit messages or chat.

A comment states what the code does, or why a non-obvious choice was made.
Documentation states facts, addresses, measurements and procedures. Cut
adjectives, cut sentences restating the previous one, cut commentary on the work.

Keep the corrections. Where a claim was wrong, the retraction stays next to the
reasoning that produced it. That is content, not commentary.

## Commits

No `Co-Authored-By`, no "Generated with", no self-attribution. Enforced by
`ci/checks.sh`; the check inspects every ref, because trailers survive in
`refs/original/` left by `filter-branch` and in backup branches that
`git log --all` does not reach.

## Before pushing

    ci/checks.sh

Or install it as a hook once:

    ci/install-hooks.sh

## Claims

Mark statements `[CONFIRMED]` only after tracing every branch into and out of
the thing, not merely reading the instructions at the site. Both flash failures
in this repo came from reading a mechanism partly and describing it in the
register the resolved parts had earned.

Anything that must work at boot on the panel gets executed under `qemu-user` in
a chroot of the extracted rootfs before it is built into an image, with `/dev`
left exactly as the image ships it. Preparing the test environment to make the
subject work conceals the dependency that fails.
