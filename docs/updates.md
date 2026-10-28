# Updating the rules

> **In short:** tfpreflight's rules know specific AWS provider versions. When AWS releases a new provider version, run `tfpreflight update` to get rules for it. You don't need to reinstall tfpreflight.

## Update

```sh
tfpreflight update
```

You'll see something like:

```text
rules updated to 2026-10-27.1, covering AWS provider 5.98.0 to 6.70.0 (61 versions)
```

It exits `0` when you have the newest rules, and `2` if it couldn't download them. If it fails, your current rules stay as they are.

## Update right before a check

```sh
tfpreflight check --update --plan=tfplan
```

If the download fails, tfpreflight prints a warning and checks with the rules it already has. The failed download doesn't change the result.

## Is it safe?

Yes. Every rules download is signed by this project. tfpreflight has the matching public key built in, and checks the signature, the size, and the checksum of every file before using it. A download that fails any check is never used.

It keeps your newest download and the one before it, so a bad download can never leave you without rules.

## Where the rules come from

tfpreflight picks the first usable source:

1. A folder you choose with `--pack-dir` (for testing).
2. The newest rules you've downloaded.
3. The rules built into tfpreflight.

An older download never replaces newer rules that came with an upgraded tfpreflight.

Downloads are saved in your computer's user cache folder, under `tfpreflight/packs`. Set `TFPREFLIGHT_PACK_CACHE` to use another folder.

## Advanced: a different download location

By default, tfpreflight downloads from `https://packs.tfpreflight.dev/index.json`. To use your own location (for example, inside a company network):

```sh
tfpreflight update --index=https://example.com/index.json
```

Or set `TFPREFLIGHT_PACK_INDEX`.

Sometimes new rules need a newer tfpreflight. If that happens, it tells you to upgrade tfpreflight first.
