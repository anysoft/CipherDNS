#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027
readonly REPO_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
version=${VERSION:-0.2.0}
target=${TARGET:?Set TARGET, for example linux-arm64-musl-static}
binary=${BINARY:?Set BINARY}
output_dir=${OUTPUT_DIR:-"$REPO_ROOT/dist"}
stage=
lock_dir=
created_archive=
created_checksum=
committed=false
log() { printf '%s [%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" "$2" >&2; }
die() { log ERROR "$*"; exit 2; }
cleanup() {
  local status=$?
  trap - EXIT
  if [[ $committed != true ]]; then
    if [[ -n $created_checksum ]]; then rm -f -- "$created_checksum"; fi
    if [[ -n $created_archive ]]; then rm -f -- "$created_archive"; fi
  fi
  if [[ -n $stage && -d $stage && $stage == "$output_dir"/.cipherdns-package.* ]]; then rm -rf -- "$stage"; fi
  if [[ -n $lock_dir ]]; then rmdir -- "$lock_dir"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'status=$?; log ERROR "Packaging failed at line $LINENO"; exit "$status"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
sha256_file() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}
verify_binary() {
python3 - "$1" "$version" "$target" "${2:-$1.link-report.txt}" <<'PYVERIFY'
import hashlib, pathlib, sys
p = pathlib.Path(sys.argv[1])
report = pathlib.Path(sys.argv[4]).read_text()
digest = hashlib.sha256(p.read_bytes()).hexdigest()
if '\nverification: PASS\n' not in report or ('sha256: ' + digest + '\n') not in report:
    raise SystemExit('Binary report is incomplete or stale; rebuild before packaging')
if ('version: ' + sys.argv[2] + '\n') not in report:
    raise SystemExit('Package version differs from the verified binary version')
for mode in ('CLIENT', 'SERVER'):
    if ('build_mode: ' + mode + '\n') in report and mode not in sys.argv[3].split('-'):
        raise SystemExit('Non-default build mode must be included in TARGET')
PYVERIFY
}
[[ $version =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || die "Unsafe version"
[[ $target =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || die "Unsafe target"
[[ -f $binary && -f $binary.link-report.txt ]] || die "Binary and successful link report are required"
command -v python3 >/dev/null || die "python3 is required for deterministic packaging"
verify_binary "$binary"
[[ $output_dir = /* ]] || output_dir="$PWD/$output_dir"
[[ $output_dir != / && ! -L $output_dir ]] || die "Unsafe output directory"
mkdir -p -- "$output_dir"
output_dir=$(CDPATH='' cd -- "$output_dir" && pwd)
[[ $output_dir != / ]] || die "Refusing to package into /"
name="cipherdns-$version-$target"
lock_dir="$output_dir/.$name.lock"
if ! mkdir -- "$lock_dir"; then lock_dir=; die "Package is locked by another run"; fi
stage=$(mktemp -d "$output_dir/.cipherdns-package.XXXXXX")
mkdir -- "$stage/$name"
cp -- "$binary" "$stage/$name/"
cp -- "$binary.link-report.txt" "$stage/$name/link-report.txt"
# Check the copied pair as well in case another build replaced the source.
verify_binary "$stage/$name/$(basename -- "$binary")" "$stage/$name/link-report.txt"
cp -- "$REPO_ROOT/README.md" "$stage/$name/"
if [[ -f $REPO_ROOT/LICENSE ]]; then cp -- "$REPO_ROOT/LICENSE" "$stage/$name/"; fi
# Only public templates/documentation are shipped; local keys/configs are excluded.
mkdir -- "$stage/$name/examples" "$stage/$name/docs" "$stage/$name/examples/hooks"
for example in server.ini client.ini client-windows.ini cloudflare.ini aliyun.ini dnspod.ini server-aliyun.ini server-dnspod.ini ctunnel-hook.ini; do
  [[ -f $REPO_ROOT/examples/$example ]] || continue
  cp -- "$REPO_ROOT/examples/$example" "$stage/$name/examples/"
done
for hook in on-change.sh on-change.ps1 ctunnel-update.sh ctunnel-on-change.sh; do
  if [[ -f $REPO_ROOT/examples/hooks/$hook ]]; then cp -- "$REPO_ROOT/examples/hooks/$hook" "$stage/$name/examples/hooks/"; fi
done
for document in build.md provider-apis.md integration-tests.md embedded-builds.md troubleshooting.md validation.md validation-cross.json release-v0.2.0.md ctunnel-hook.md audit-v0.2.0.md validation-v0.1.0.md validation-cross-v0.1.0.json; do
  if [[ -f $REPO_ROOT/docs/$document ]]; then cp -- "$REPO_ROOT/docs/$document" "$stage/$name/docs/"; fi
done
mkdir -- "$stage/$name/scripts"
for script in soak-test.sh measure-resources.sh; do
  if [[ -f $REPO_ROOT/scripts/$script ]]; then cp -- "$REPO_ROOT/scripts/$script" "$stage/$name/scripts/"; fi
done
mkdir -- "$stage/$name/licenses"
for dependency in mbedtls inih jsmn; do
  for license in "$REPO_ROOT/third_party/$dependency"/LICENSE* "$REPO_ROOT/third_party/$dependency"/COPYING*; do
    [[ -f $license ]] || continue
    cp -- "$license" "$stage/$name/licenses/$dependency-$(basename -- "$license")"
  done
done
if [[ -f $REPO_ROOT/third_party/README.md ]]; then
  cp -- "$REPO_ROOT/third_party/README.md" "$stage/$name/licenses/SOURCES.md"
  mkdir -- "$stage/$name/third_party"
  cp -- "$REPO_ROOT/third_party/README.md" "$stage/$name/third_party/README.md"
fi
printf 'version=%s\ntarget=%s\n' "$version" "$target" > "$stage/$name/VERSION"
(cd "$stage/$name" && sha256_file "$(basename -- "$binary")" > SHA256SUMS)
# Normalize names, order, owners, modes, timestamps and gzip headers on every host.
case "$binary" in *.exe) extension=zip;; *) extension=tar.gz;; esac
python3 - "$stage" "$name" "$extension" <<'PYARCHIVE'
import gzip, pathlib, sys, tarfile, zipfile
stage, name, extension = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
root = stage / name
paths = [root] + sorted(root.rglob('*'))
if any(p.is_symlink() for p in paths):
    raise SystemExit('Package inputs must not contain symlinks')
def mode(p):
    return 0o755 if p.is_dir() or p.name in ('cipherdns', 'cipherdns.exe') or p.suffix == '.sh' else 0o644
if extension == 'zip':
    with zipfile.ZipFile(stage / (name + '.zip'), 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for p in paths:
            relative = p.relative_to(stage).as_posix() + ('/' if p.is_dir() else '')
            info = zipfile.ZipInfo(relative, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (mode(p) | (0o40000 if p.is_dir() else 0o100000)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, b'' if p.is_dir() else p.read_bytes())
else:
    with (stage / (name + '.tar.gz')).open('wb') as out:
        with gzip.GzipFile(filename='', mode='wb', fileobj=out, mtime=1577836800, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.GNU_FORMAT) as archive:
                for p in paths:
                    info = archive.gettarinfo(str(p), arcname=p.relative_to(stage).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mtime = 1577836800
                    info.mode = mode(p)
                    if p.is_dir():
                        archive.addfile(info)
                    else:
                        with p.open('rb') as data: archive.addfile(info, data)
PYARCHIVE
archive="$output_dir/$name.$extension"
(cd "$stage" && sha256_file "$name.$extension") > "$stage/checksum"
if [[ -e $archive ]]; then
  cmp -s "$stage/$name.$extension" "$archive" || die "Archive already exists with different content; choose another version or output directory"
  log INFO "Archive unchanged: $archive"
fi
if [[ -e $archive.sha256 ]]; then
  cmp -s "$stage/checksum" "$archive.sha256" || die "Checksum exists with different content"
fi
if [[ ! -e $archive ]]; then
  created_archive=$archive
  mv -- "$stage/$name.$extension" "$archive"
fi
if [[ ! -e $archive.sha256 ]]; then
  created_checksum=$archive.sha256
  mv -- "$stage/checksum" "$archive.sha256"
fi
committed=true
log INFO "Packaged: $archive"
