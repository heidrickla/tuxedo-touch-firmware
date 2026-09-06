# Building tuxweb

    ssh claude@203.0.113.40                      # key ~/.ssh/fwbuild_ed25519
    export RUSTUP_HOME=/build/rt/rustup CARGO_HOME=/build/rt/cargo
    export PATH=$CARGO_HOME/bin:$PATH
    export CC_arm_unknown_linux_musleabi=arm-linux-gnueabi-gcc
    export AR_arm_unknown_linux_musleabi=arm-linux-gnueabi-ar
    cargo build --release --target arm-unknown-linux-musleabi

**The target is `arm-unknown-linux-musleabi`.** `armv6-unknown-linux-musleabihf`
is not a rustc target — only `arm-*` and `armv7-*` exist.

**`ring` needs a cross C compiler**, unlike pure-Rust code. `cc-rs` looks for
`arm-linux-musleabi-gcc`, which does not exist on Ubuntu; point it at
`arm-linux-gnueabi-gcc` with the `CC_*`/`AR_*` variables above. Use the
**soft-float** `gnueabi` compiler, not `gnueabihf`, to match the `musleabi`
target. Linking is still `rust-lld` with `link-self-contained`, so the gnu
toolchain is only compiling ring's C — nothing gnu ends up linked in.

Output: `target/arm-unknown-linux-musleabi/release/tuxweb`, ~839 KB, `ELF 32-bit
LSB executable, ARM, EABI5, statically linked, stripped`.
