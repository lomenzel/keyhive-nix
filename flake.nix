{
  description = "Pure Nix bindings for deterministic Keyhive identities";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    wechselbalg.url = "git+file:///home/leonard/Projekte/Gestalt/wechselbalg";
  };

  outputs =
    {
      self,
      nixpkgs,
      wechselbalg,
      ...
    }:
    let
      eachSystem =
        f:
        nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs {
              inherit system;
              overlays = [
                wechselbalg.overlays.default
                self.overlays.default
              ];
            };
          }
        );
    in
    {
      overlays.default = final: prev: {
        keyhive-wasm = (
          final.pkgsCross.wasi32.rustPlatform.buildRustPackage {
            pname = "keyhive-nix-wasm";
            version = "0.1.0";
            src = ./rust;
            cargoLock = {
              lockFile = ./rust/Cargo.lock;
              outputHashes = {
                "beekem-0.4.0" = "sha256-+AbPiOJQcLNIPT++Wwg3YH8gvAxm5qdpOBwcxQUmb9w=";
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
          }
        );

        lib =
          let
            wasm64 = builtins.readFile (
              final.runCommand "keyhive-wasm-base64" { }
                ''base64 -w0 "${final.keyhive-wasm}/keyhive.wasm" > $out''
            );

          in
          prev.lib.extend (
            lfinal: lprev: {
              keyhive =
                let

                  callWasm =
                    function: args:
                    let
                      result = final.lib.wasm {
                        bytecode = wasm64;
                        inherit function;
                      } args;
                      data = if result.success then result.data else throw "keyhive-nix [${function}]: ${result.error}";
                    in
                    builtins.fromJSON (builtins.toJSON data);

                  mkInstance = identityEntropy: result: {
                    id = result.id;
                    stats = result.stats;
                    archive = _: result.state;

                    # 1. Contact cards & Prekeys
                    contactCard = callWasm "keyhive_contact_card" {
                      identity = identityEntropy;
                      state = result.state;
                    };

                    receiveContactCard =
                      { contactCard }:
                      let
                        res = callWasm "keyhive_receive_contact_card" {
                          identity = identityEntropy;
                          state = result.state;
                          contact_card = contactCard; # only pass one
                        };
                      in
                      mkInstance identityEntropy res;
                    generateContactCard =
                      { entropy }:
                      let
                        res = callWasm "keyhive_generate_contact_card" {
                          identity = identityEntropy;
                          state = result.state;
                          inherit entropy;
                        };
                      in
                      {
                        contactCard = res.contact_card;
                        keyhive = mkInstance identityEntropy {
                          state = res.state;
                          id = result.id;
                          stats = result.stats;
                          created = null;
                        };
                      };

                    expandPrekeys =
                      { entropy }:
                      mkInstance identityEntropy (
                        callWasm "keyhive_expand_prekeys" {
                          identity = identityEntropy;
                          inherit entropy;
                          state = result.state;
                        }
                      );

                    # 2. Document & Group generation
                    generateGroup =
                      { entropy }:
                      let
                        group = callWasm "keyhive_generate_group" {
                          identity = identityEntropy;
                          inherit entropy;
                          state = result.state;
                        };
                      in
                      {
                        keyhive = mkInstance identityEntropy group;
                        group = {
                          id = group.created;
                        };
                      };

                    generateDocument =
                      { entropy }:
                      let
                        doc = callWasm "keyhive_generate_document" {
                          identity = identityEntropy;
                          inherit entropy;
                          state = result.state;
                        };
                      in
                      {
                        keyhive = mkInstance identityEntropy doc;
                        document = {
                          id = doc.created;
                        };
                      };

                    # 3. Access Control (Membership)
                    addMember =
                      {
                        resourceId,
                        memberId,
                        access ? "read",
                        isGroup ? false,
                        entropy,
                      }:
                      let
                        res = callWasm "keyhive_add_member" {
                          identity = identityEntropy;
                          state = result.state;
                          inherit entropy;
                          resource_id = resourceId;
                          member_id = memberId;
                          is_group = isGroup;
                          access = access;
                        };
                      in
                      mkInstance identityEntropy res;

                    # 4. Native Content Sealing & Unsealing
                    seal =
                      {
                        docId,
                        payload,
                        entropy,
                        predRefs ? [ ],
                        ...
                      }:
                      let
                        res = callWasm "keyhive_seal" {
                          identity = identityEntropy;
                          state = result.state;
                          doc_id = docId;
                          inherit payload entropy;
                          pred_refs = predRefs;
                        };
                      in
                      {
                        packet = res.packet;
                        docId = res.doc_id;
                        contentRef = res.content_ref;
                        keyhive = mkInstance identityEntropy {
                          state = res.state;
                          id = result.id;
                          stats = result.stats;
                          created = null;
                        };
                      };

                    unseal =
                      { packet, ... }:
                      let
                        actualPacket = if packet ? packet then packet.packet else packet;
                        res = callWasm "keyhive_unseal" {
                          identity = identityEntropy;
                          state = result.state;
                          packet = actualPacket;
                        };
                      in
                      {
                        docId = res.doc_id;
                        plaintext = res.plaintext;
                        keyhive = mkInstance identityEntropy {
                          state = res.state;
                          id = result.id;
                          stats = result.stats;
                          created = null;
                        };
                      };
                    exportEvents =
                      {
                        recipient,
                        have ? [ ],
                      }:
                      callWasm "keyhive_export_events" {
                        identity = identityEntropy;
                        state = result.state;
                        inherit recipient have;
                      };
                    ingestEvents =
                      { events, entropy }:
                      let
                        res = callWasm "keyhive_ingest_events" {
                          identity = identityEntropy;
                          state = result.state;
                          inherit events entropy;
                        };
                      in
                      (mkInstance identityEntropy res)
                      // {
                        pending = res.pending or 0;
                      };
                    # List all documents the active agent has access to: { [docId]: "edit", ... }
                    reachableDocs = callWasm "keyhive_reachable_docs" {
                      identity = identityEntropy;
                      state = result.state;
                    };

                    # List all transitive members of a document or group: { [memberId]: "edit", ... }
                    reachableMembers =
                      {
                        resourceId,
                        isGroup ? false,
                      }:
                      callWasm "keyhive_reachable_members" {
                        identity = identityEntropy;
                        state = result.state;
                        resource_id = resourceId;
                        is_group = isGroup;
                      };

                    # Revoke a member from a document or group
                    revokeMember =
                      {
                        resourceId,
                        memberId,
                        isGroup ? false,
                        retainAllOtherMembers ? true,
                        entropy,
                      }:
                      let
                        res = callWasm "keyhive_revoke_member" {
                          identity = identityEntropy;
                          state = result.state;
                          inherit entropy;
                          resource_id = resourceId;
                          member_id = memberId;
                          is_group = isGroup;
                          retain_all_other_members = retainAllOtherMembers;
                        };
                      in
                      mkInstance identityEntropy res;
                    # Export private prekey secrets as an opaque base64 blob for device backup
                    exportPrekeySecrets = callWasm "keyhive_export_prekey_secrets" {
                      identity = identityEntropy;
                      state = result.state;
                    };

                    # Import private prekey secrets onto another device
                    importPrekeySecrets =
                      {
                        secrets,
                        entropy ? identityEntropy,
                      }:
                      let
                        res = callWasm "keyhive_import_prekey_secrets" {
                          identity = identityEntropy;
                          state = result.state;
                          inherit secrets entropy;
                        };
                      in
                      mkInstance identityEntropy res;

                    accessForDoc =
                      { docId, memberId }:
                      callWasm "keyhive_access_for_doc" {
                        identity = identityEntropy;
                        state = result.state;
                        doc_id = docId;
                        member_id = memberId;
                      };

                    bestAccessForDoc =
                      { docId, memberId }:
                      callWasm "keyhive_best_access_for_doc" {
                        identity = identityEntropy;
                        state = result.state;
                        doc_id = docId;
                        member_id = memberId;
                      };

                    # --- 2. Entity Existence Checks ---
                    hasDocument =
                      docId:
                      callWasm "keyhive_has_document" {
                        identity = identityEntropy;
                        state = result.state;
                        id = docId;
                      };

                    hasGroup =
                      groupId:
                      callWasm "keyhive_has_group" {
                        identity = identityEntropy;
                        state = result.state;
                        id = groupId;
                      };

                    hasIndividual =
                      individualId:
                      callWasm "keyhive_has_individual" {
                        identity = identityEntropy;
                        state = result.state;
                        id = individualId;
                      };

                    # --- 3. Single-Pass Relay & Bulk Sync ---
                    allAgentEvents =
                      let
                        res = callWasm "keyhive_all_agent_events" {
                          identity = identityEntropy;
                          state = result.state;
                        };
                      in
                      {
                        events = res.events;
                        agentEvents = res.agentEvents or res.agent_events;
                        agentPayloads = res.agentPayloads or res.agent_payloads;
                      };
                    # --- 4. Causal DAG History Walk ---
                  };
                in
                {
                  # Root identity constructors
                  init =
                    { identity, entropy }:
                    mkInstance identity (
                      callWasm "keyhive_init" {
                        inherit identity entropy;
                      }
                    );
                  publicId = final.lib.trim (
                    builtins.readFile (
                      final.runCommand "keyhive-public-id" { nativeBuildInputs = [ final.nodejs ]; } ''
                        node -e '
                          const fs = require("fs");
                          const mod = new WebAssembly.Module(fs.readFileSync("${final.keyhive-wasm}/keyhive.wasm"));
                          const instance = new WebAssembly.Instance(mod, {
                            wasi_snapshot_preview1: new Proxy({}, { get: () => () => 0 }),
                            env: new Proxy({}, { get: () => () => 0 }),
                          });
                          const inBytes = Buffer.from("{}\0");
                          const inPtr = instance.exports.malloc(inBytes.length);
                          new Uint8Array(instance.exports.memory.buffer, inPtr, inBytes.length).set(inBytes);
                          const outPtr = instance.exports.keyhive_public_id(inPtr);
                          const mem = new Uint8Array(instance.exports.memory.buffer);
                          let end = outPtr;
                          while (mem[end] !== 0) end++;
                          const res = JSON.parse(new TextDecoder().decode(mem.subarray(outPtr, end)));
                          if (!res.success) throw new Error(res.error);
                          process.stdout.write(res.data);
                        ' > $out
                      ''
                    )
                  );
                  restore =
                    { identity, archive }:
                    mkInstance identity (
                      callWasm "keyhive_restore" {
                        inherit identity archive;
                      }
                    );

                };
            }
          );
      };

      packages = eachSystem ({ pkgs, ... }: { default = pkgs.keyhive-wasm; });
    };
}
