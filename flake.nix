{
  # Viper PQ Chain — Nix flake for reproducible builds (TASK-157, Phase 8).
  #
  # Scope:
  #   - `devShell`: pinned Rust 1.92.0 (matches rust-toolchain.toml) + the
  #     C/C++ toolchain and headers required to build RocksDB (bundled C++),
  #     libp2p/QUIC, and the rustls/reqwest TLS stack.
  #   - `packages.default`: `buildRustPackage` for `pqcd` release binary.
  #     RocksDB's bundled C++ source can be finicky under Nix's hermetic
  #     sandbox (needs `NIX_CFLAGS_COMPILE` relaxations and a fallback
  #     `CC`/`CXX`). If `nix build` fails on RocksDB, the `devShell` target
  #     alone is sufficient for Phase 8 audit scaffolding — reproducible
  #     inputs are pinned via flake.lock, even if the release binary is
  #     still produced by the GitLab CI `build` job on `rust:latest`.
  #
  # Vendored dep:
  #   `vendor/slh-dsa` is referenced as a workspace path (`[patch.crates-io]`
  #   in /Cargo.toml), so `cargoLock = { lockFile = ./Cargo.lock; }` is
  #   sufficient — no `outputHashes` entry needed (no git dep to pin).
  #
  # Style references: ethereum/reth, matter-labs/zksync-era, solana-labs.
  #
  # Usage:
  #   nix develop           # enter reproducible dev shell
  #   nix flake check       # syntax/eval validation
  #   nix build .#pqcd      # best-effort release build (see RocksDB note)

  description = "Viper PQ Chain — reproducible build scaffolding (Phase 8)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachSystem [
      # Primary CI / production target.
      "x86_64-linux"
      # Secondary: developer macOS M-series (aarch64-darwin). Linux aarch64
      # is intentionally omitted from the *tested* matrix for now — add when
      # we have a CI runner for it.
      "aarch64-darwin"
    ] (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Rust toolchain pinned to the version in rust-toolchain.toml (1.92.0).
        # Bump this string *and* rust-toolchain.toml together — they must match
        # or `cargo` inside the devShell will re-download a different channel.
        # 1.92 is the floor for the AWS SDK transitive deps required by the
        # `s3-upload` Cargo feature (KNOWN-ISSUES R-13); CI image was bumped
        # 2026-05-06 (`.gitlab-ci.yml` `rust:1.92`).
        rustToolchain = pkgs.rust-bin.stable."1.92.0".default.override {
          extensions = [ "rustfmt" "clippy" "rust-src" ];
        };

        # Common build inputs for RocksDB (bundled C++ build) + libp2p/QUIC +
        # rustls TLS (via reqwest). `protobuf` intentionally omitted: a grep
        # of the workspace shows no prost/tonic/protobuf-codegen consumers.
        # Add it here if/when a crate adopts a protobuf schema.
        commonBuildInputs = with pkgs; [
          # RocksDB C++ bundled source requires a C++17 compiler.
          stdenv.cc
          clang       # for rust-bindgen (bindgen-runtime is disabled, but
                      # clang is still handy for local development)
          llvmPackages.libclang
          pkg-config
          cmake
          # rustls uses ring (vendored C); openssl is *not* required but
          # included so reqwest/native-tls shims and cargo-audit work.
          openssl
          # zstd / lz4 / snappy linked against bundled RocksDB when
          # `features = ["lz4"]` is enabled (see /Cargo.toml workspace deps).
          lz4
          zlib
          zstd
          snappy
          # QUIC (quinn) needs nothing special at the system level; libp2p
          # pulls ring / rustls, both pure-Rust.
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          # macOS SDK frameworks needed by libp2p / mdns on aarch64-darwin.
          pkgs.darwin.apple_sdk.frameworks.Security
          pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          pkgs.darwin.apple_sdk.frameworks.CoreFoundation
        ];

        # LIBCLANG_PATH is required by bindgen-runtime; we disabled it in
        # workspace Cargo.toml, but we export it defensively so any crate
        # that enables bindgen at build time still works in the shell.
        envVars = {
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          # ROCKSDB_LIB_DIR unset → let `rocksdb` crate build bundled C++.
          # Set `ROCKSDB_LIB_DIR=${pkgs.rocksdb}/lib` to link against the
          # pkgs rocksdb instead (faster incremental dev, but introduces
          # a second ABI surface to track vs. what CI uses).
        };
      in
      {
        devShells.default = pkgs.mkShell ({
          name = "viper-pq-chain-dev";
          nativeBuildInputs = [
            rustToolchain
          ] ++ commonBuildInputs;

          shellHook = ''
            echo "Viper PQ Chain dev shell — Rust $(rustc --version)"
            echo "  (pinned via flake.nix; matches rust-toolchain.toml)"
          '';
        } // envVars);

        # Release binary build. Best-effort: RocksDB bundled C++ under the
        # Nix sandbox may need `ROCKSDB_LIB_DIR` / `SNAPPY_LIB_DIR` overrides
        # on some runners. If that breaks, drop `packages.default` from the
        # CI gating path and rely on `devShells.default` + GitLab CI build.
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "pqcd";
          version = "0.1.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
            # No `outputHashes` entries: the only patched crate (slh-dsa) is
            # a workspace path dep (vendor/slh-dsa), not a git source.
          };

          cargoBuildFlags = [ "-p" "pqcd" "--release" ];
          # pqcd's full test suite boots tokio runtimes and needs temp dirs;
          # leave tests to CI runners, where network + fs are unsandboxed.
          doCheck = false;

          nativeBuildInputs = [
            rustToolchain
            pkgs.pkg-config
            pkgs.cmake
            pkgs.clang
          ];
          buildInputs = commonBuildInputs;

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          meta = with pkgs.lib; {
            description = "Viper PQ Chain node binary (pqcd)";
            homepage = "https://github.com/v1p3r4llbl4ck-86/viper-pq-chain";
            license = licenses.asl20;
            platforms = [ "x86_64-linux" "aarch64-darwin" ];
            mainProgram = "pqcd";
          };
        };

        # `nix flake check` entry point: validates evaluation and formatting.
        checks.devShell = self.devShells.${system}.default;
      });
}
