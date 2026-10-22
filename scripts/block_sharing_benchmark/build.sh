#!/usr/bin/env bash
set -euo pipefail
mkdir -p benchmark-bin
build_arm() {
  local arm="$1"
  cargo +1.95 test --locked -p starknet_os_flow_tests --lib --no-run --message-format=json > "benchmark-bin/$arm-build.jsonl"
  python3 - "$arm" <<'INNER'
import json,sys,shutil,pathlib
arm=sys.argv[1]
rows=[json.loads(line) for line in pathlib.Path(f'benchmark-bin/{arm}-build.jsonl').read_text().splitlines() if line.startswith('{')]
binary=[r['executable'] for r in rows if r.get('reason')=='compiler-artifact' and r.get('executable') and r['target']['name']=='starknet_os_flow_tests']
assert len(binary)==1,binary
shutil.copy2(binary[0],f'benchmark-bin/{arm}-flow-tests')
compiled=max(pathlib.Path('target/debug/build').glob('*/out/starknet_os_bytes'),key=lambda p:p.stat().st_mtime)
shutil.copy2(compiled,f'benchmark-bin/{arm}-os.json')
INNER
}
build_arm prototype
BASE=0da981c861f9078c13f7cddb89804c388ec9451d
for file in \
  crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/block_context.cairo \
  crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/committed_data.cairo \
  crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/syscall_impls.cairo \
  crates/starknet_os/src/hint_processor/snos_hint_processor.rs \
  crates/starknet_os/src/hints/enum_definition.rs \
  crates/starknet_os/src/hints/hint_implementation/committed_data.rs \
  crates/starknet_os/src/hints/vars.rs \
  crates/starknet_os_flow_tests/src/committed_data_batch_test.rs; do
  git show "$BASE:$file" > "$file"
done
build_arm current
# Preserve source provenance for both arms; restore prototype files before packaging.
git restore --worktree crates/apollo_starknet_os_program crates/starknet_os crates/starknet_os_flow_tests/src/committed_data_batch_test.rs
sha256sum benchmark-bin/*-flow-tests benchmark-bin/*-os.json > benchmark-bin/SHA256SUMS
