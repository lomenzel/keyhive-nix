{
  description = "Pure Nix bindings for deterministic Keyhive identities";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    wechselbalg.url = "git+file:///home/leonard/Projekte/Gestalt/wechselbalg";
  };

  outputs = { self, nixpkgs, wechselbalg, ... }:
    let
      eachSystem = f: nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (system:
        f {
          inherit system;
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ wechselbalg.overlays.default self.overlays.default ];
          };
        });
    in {
      overlays.default = final: prev: {
        keyhive-wasm =
          (final.pkgsCross.wasi32.rustPlatform.buildRustPackage {
            pname = "keyhive-nix-wasm";
            version = "0.1.0";
            src = ./rust;
            cargoLock = {
              lockFile = ./rust/Cargo.lock;
              outputHashes = {
                "beekem-0.4.0" = "sha256-+AbPiOJQcLNIPT++Wwg3YH8gvAxm5qdpOBwcxQUmb9w=";
                "keyhive_core-0.6.0" = final.lib.fakeHash;
                "keyhive_crypto-0.2.1" = final.lib.fakeHash;
              };
            };
            nativeBuildInputs = [ final.lld ];
            RUSTFLAGS = "-C linker=wasm-ld -C link-arg=--export=malloc -C link-arg=--export=free";
            preConfigure = ''
              export CARGO_TARGET_WASM32_WASIP1_LINKER=wasm-ld
            '';
            installPhase = ''
              mkdir -p $out
              cp target/wasm32-wasip1/release/keyhive_nix_wasm.wasm $out/keyhive.wasm
              ${final.binaryen}/bin/wasm-opt -Oz $out/keyhive.wasm -o $out/keyhive.wasm
            '';
          });

        lib = (prev.lib or {}) // {
          keyhive =
            let
              wasm64 = builtins.readFile (final.runCommand "keyhive-wasm-base64" { }
                ''base64 -w0 "${final.keyhive-wasm}/keyhive.wasm" > $out'');
              callWasm = function: args:
                let
                  result = final.lib.wasm { bytecode = wasm64; inherit function; } args;
                  data = if result.success then result.data else throw "keyhive-nix [${function}]: ${result.error}";
                in
                  builtins.fromJSON (builtins.toJSON data);

              mkIdentity = entropy: result: {
                id = result.id;
                init = { operationEntropy }:
                  mkInstance entropy (callWasm "keyhive_init" {
                    identity = entropy;
                    entropy = operationEntropy;
                  });
                restore = { archive }:
                  mkInstance entropy (callWasm "keyhive_restore" {
                    identity = entropy;
                    inherit archive;
                  });
              };

              mkInstance = identityEntropy: result: {
                id = result.id;
                stats = result.stats;
                archive = _: result.state;

                expandPrekeys = { entropy }:
                  mkInstance identityEntropy
                  (callWasm "keyhive_expand_prekeys" {
                    identity = identityEntropy;
                    inherit entropy;
                    state = result.state;
                  });

                generateGroup = { entropy }:
                  let group = callWasm "keyhive_generate_group" {
                    identity = identityEntropy;
                    inherit entropy;
                    state = result.state;
                  }; in {
                    keyhive = mkInstance identityEntropy group;
                    group = { id = group.created; };
                  };

                generateDocument = { entropy }:
                  let document = callWasm "keyhive_generate_document" {
                    identity = identityEntropy;
                    inherit entropy;
                    state = result.state;
                  }; in {
                    keyhive = mkInstance identityEntropy document;
                    document = { id = document.created; };
                  };

                createInvite = { docId, to, rights ? [ "read" "write" ] }:
                  let res = callWasm "keyhive_create_invite" {
                    state = result.state;
                    identity = identityEntropy;
                    doc_id = docId;
                    inherit to rights;
                  }; in {
                    invite = res.invite;
                    keyhive = mkInstance identityEntropy res;
                  };

                acceptInvite = { invite }:
                  let res = callWasm "keyhive_accept_invite" {
                    state = result.state;
                    identity = identityEntropy;
                    inherit invite;
                  }; in
                  mkInstance identityEntropy res;

                seal = { docId, payload, entropy }:
                  callWasm "keyhive_seal" {
                    state = result.state;
                    identity = identityEntropy;
                    doc_id = docId;
                    inherit payload entropy;
                  };

                unseal = { packet }:
                  let res = callWasm "keyhive_unseal" {
                    state = result.state;
                    identity = identityEntropy;
                    inherit packet;
                  }; in {
                    docId = res.doc_id;
                    writer = res.writer;
                    plaintext = res.plaintext;
                    keyhive = mkInstance identityEntropy res;
                  };
              };
            in {
              identity = { entropy }:
                mkIdentity entropy (callWasm "keyhive_identity" { inherit entropy; });

              init = { identity, entropy }:
                identity.init { operationEntropy = entropy; };

              restore = { identity, archive }:
                identity.restore { inherit archive; };
            };
        };
      };

      packages = eachSystem ({ pkgs, ... }: { default = pkgs.keyhive-wasm; });
    };
}