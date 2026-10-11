use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use beekem::{encrypted::EncryptedContent, operation::CgkaOperation};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::executor::block_on;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    archive::Archive,
    contact_card::ContactCard,
    event::static_event::StaticEvent,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{
        document::id::DocumentId,
        group::id::GroupId,
        identifier::Identifier,
        individual::id::IndividualId,
        individual::op::KeyOp,
        membered::id::MemberedId,
        public::Public,
    },
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{signed::Signed, signer::memory::MemorySigner};
use nonempty::nonempty;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    ffi::{c_char, CStr},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
    sync::Mutex as StdMutex,
};

const SEED_BYTES: usize = 32;

pub type Hive = Keyhive<
    future_form::Local,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    ChaCha20Rng,
>;

// --- Diagnostic Panic Hook & Safe Call Wrapper ---

static PANIC_INFO: StdMutex<Option<String>> = StdMutex::new(None);

fn init_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let msg = info.to_string();
            if let Ok(mut lock) = PANIC_INFO.lock() {
                *lock = Some(msg);
            }
        }));
    });
}


fn safe_call<T: Serialize>(f: impl FnOnce() -> Result<T, String>) -> *mut c_char {
    init_panic_hook();

    if let Ok(mut lock) = PANIC_INFO.lock() {
        *lock = None;
    }

    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => response(result),
        Err(_) => {
            let detail = PANIC_INFO
                .lock()
                .ok()
                .and_then(|mut lock| lock.take())
                .unwrap_or_else(|| "Unknown panic in WASM".to_string());
            response::<()>(Err(format!("Rust Panic: {detail}")))
        }
    }
}

// --- FFI Response Envelope & Memory Management ---

#[derive(Serialize)]
struct Response<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

extern "C" {
    fn malloc(size: usize) -> *mut u8;
}

fn response<T: Serialize>(value: Result<T, String>) -> *mut c_char {
    let output = match value {
        Ok(data) => match serde_json::to_string(&Response {
            success: true,
            data: Some(data),
            error: None,
        }) {
            Ok(json) => json,
            Err(e) => serde_json::to_string(&Response::<()> {
                success: false,
                data: None,
                error: Some(format!("Response JSON serialization error: {e}")),
            })
            .unwrap_or_else(|_| {
                "{\"success\":false,\"error\":\"fatal serialization error\"}".to_string()
            }),
        },
        Err(error) => serde_json::to_string(&Response::<()> {
            success: false,
            data: None,
            error: Some(error),
        })
        .unwrap_or_else(|_| {
            "{\"success\":false,\"error\":\"fatal serialization error\"}".to_string()
        }),
    };

    let bytes = output.as_bytes();
    unsafe {
        let ptr = malloc(bytes.len() + 1);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        *ptr.add(bytes.len()) = 0;
        ptr as *mut c_char
    }
}


// --- Cryptographic Determinism Helpers ---

fn seed_from_entropy(entropy: &[u8]) -> Result<[u8; SEED_BYTES], String> {
    if entropy.len() != SEED_BYTES {
        return Err("entropy must be exactly 32 bytes".to_string());
    }
    let mut seed = [0; SEED_BYTES];
    seed.copy_from_slice(entropy);
    Ok(seed)
}

fn rng_seed(entropy: &[u8; SEED_BYTES], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keyhive-nix/csprng/v2");
    hasher.update(domain);
    hasher.update(entropy);
    hasher.finalize().into()
}

fn signer_seed(seed: &[u8; SEED_BYTES]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keyhive-nix/ed25519/v1");
    hasher.update(seed);
    hasher.finalize().into()
}

fn identifier_from_bytes(bytes: [u8; 32]) -> Result<Identifier, String> {
    let vk = VerifyingKey::from_bytes(&bytes)
        .map_err(|e| format!("invalid verifying key: {e}"))?;
    Ok(Identifier::from(vk))
}

// --- Keyhive Lifecycle & Native Archive ---

fn make_hive(identity_seed: [u8; 32], operation_entropy: [u8; 32]) -> Result<Hive, String> {
    let signer = MemorySigner::from(SigningKey::from_bytes(&signer_seed(&identity_seed)));
    let rng = ChaCha20Rng::from_seed(rng_seed(&operation_entropy, b"init"));
    let store = MemoryCiphertextStore::new();
    block_on(Keyhive::generate(signer, store, NoListener, rng))
        .map_err(|e| e.to_string())
}

fn restore_hive(
    state_b64: &str,
    identity_seed: [u8; 32],
    operation_entropy: [u8; 32],
    operation: &[u8],
) -> Result<Hive, String> {
    let bytes = BASE64
        .decode(state_b64)
        .map_err(|e| format!("invalid state base64: {e}"))?;
    let archive: Archive<[u8; 32]> =
        bincode::deserialize(&bytes).map_err(|e| format!("archive deserialization failed: {e}"))?;
    let signer = MemorySigner::from(SigningKey::from_bytes(&signer_seed(&identity_seed)));
    let rng = ChaCha20Rng::from_seed(rng_seed(&operation_entropy, operation));
    let store = MemoryCiphertextStore::new();
    let hive = block_on(Keyhive::try_from_archive(
        &archive,
        signer,
        store,
        NoListener,
        Arc::new(Mutex::new(rng)),
    ))
    .map_err(|e| e.to_string())?;

    // --- RE-SEAT SECRETS INTO RESTORED DOCUMENTS ---
    // Exports the active prekey secrets already present in the archive
    // and re-imports them to trigger `adopt_all_leaf_secrets()` internally.
    let secrets = block_on(hive.export_prekey_secrets())
        .map_err(|e| format!("restore_hive: export_prekey_secrets failed: {e}"))?;
    let _ = block_on(hive.import_prekey_secrets(&secrets))
        .map_err(|e| format!("restore_hive: import_prekey_secrets failed: {e}"))?;

    Ok(hive)
}

fn archive_hive(hive: &Hive) -> Result<String, String> {
    let archive = block_on(hive.into_archive());
    bincode::serialize(&archive)
        .map(|bytes| BASE64.encode(bytes))
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct StateResult {
    pub state: String,
    pub id: String,
    pub stats: keyhive_core::stats::Stats,
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<usize>,
}

fn state_result(hive: &Hive, created: Option<String>) -> Result<StateResult, String> {
    Ok(StateResult {
        state: archive_hive(hive)?,
        id: BASE64.encode(hive.id().to_bytes()),
        stats: block_on(hive.stats()),
        created,
        pending: None,
    })
}
fn state_operation<F>(
    input: *const c_char,
    operation: F,
    domain: &'static [u8],
) -> *mut c_char
where
    F: FnOnce(&Hive, &[u8; 32], &[u8; 32]) -> Result<Option<String>, String>,
{
    safe_call(|| -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let state_str = payload
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| "state must be a base64 string".to_string())?;
        let id_str = payload
            .get("identity")
            .and_then(Value::as_str)
            .ok_or_else(|| "identity must be a base64 string".to_string())?;
        let entropy_str = payload
            .get("entropy")
            .and_then(Value::as_str)
            .ok_or_else(|| "entropy must be a base64 string".to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(id_str).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(entropy_str).map_err(|e| e.to_string())?)?;

        let hive = restore_hive(state_str, identity, entropy, domain)?;
        let created = operation(&hive, &identity, &entropy)?;

        state_result(&hive, created)
    })
}

// --- Baseline C-ABI Exports ---

#[no_mangle]
pub unsafe extern "C" fn keyhive_init(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        let id_raw = payload.get("identity").and_then(Value::as_str).unwrap_or("");
        let ent_raw = payload.get("entropy").and_then(Value::as_str).unwrap_or("");
        let identity = seed_from_entropy(&BASE64.decode(id_raw).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(ent_raw).map_err(|e| e.to_string())?)?;
        let hive = make_hive(identity, entropy)?;
        state_result(&hive, None)
    })
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_restore(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        let id_raw = payload.get("identity").and_then(Value::as_str).unwrap_or("");
        let archive_str = payload
            .get("archive")
            .and_then(Value::as_str)
            .ok_or_else(|| "archive must be a base64 string".to_string())?;
        let identity = seed_from_entropy(&BASE64.decode(id_raw).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(archive_str, identity, [0u8; 32], b"restore")?;
        state_result(&hive, None)
    })
}

// --- Prekeys, Groups, and Documents ---

#[no_mangle]
pub unsafe extern "C" fn keyhive_expand_prekeys(input: *const c_char) -> *mut c_char {
    state_operation(
        input,
        |hive, _, _| {
            block_on(hive.expand_prekeys())
                .map(|_| None)
                .map_err(|e| e.to_string())
        },
        b"expand-prekeys",
    )
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_generate_group(input: *const c_char) -> *mut c_char {
    state_operation(
        input,
        |hive, _, _| {
            block_on(hive.generate_group(vec![]))
                .map(|id| Some(BASE64.encode(id.to_bytes())))
                .map_err(|e| e.to_string())
        },
        b"generate-group",
    )
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_generate_document(input: *const c_char) -> *mut c_char {
    state_operation(
        input,
        |hive, _, entropy| {
            let app_key = rng_seed(entropy, b"keyhive/doc-app-key/v1");
            let doc_id = block_on(hive.generate_doc(vec![], nonempty![app_key]))
                .map_err(|e| e.to_string())?;
            Ok(Some(BASE64.encode(doc_id.to_bytes())))
        },
        b"generate-document",
    )
}

// --- Contact Cards & Membership Operations ---

#[derive(Deserialize)]
struct ReceiveContactCardPayload {
    state: String,
    identity: String,
    #[serde(alias = "contactCard")]
    contact_card: serde_json::Value,
}

#[derive(Deserialize)]
struct AddMemberPayload {
    state: String,
    identity: String,
    entropy: String,
    resource_id: String,
    is_group: bool,
    member_id: String,
    access: String,
}

#[derive(Serialize)]
struct GenerateContactCardResult {
    contact_card: ContactCard,
    state: String,
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_contact_card(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<ContactCard, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        let state_str = payload.get("state").and_then(Value::as_str).ok_or("missing state")?;
        let id_str = payload.get("identity").and_then(Value::as_str).ok_or("missing identity")?;

        let identity = seed_from_entropy(&BASE64.decode(id_str).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(state_str, identity, [0u8; 32], b"contact-card")?;

        let card = block_on(hive.get_existing_contact_card());
        Ok(card)
    })
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_generate_contact_card(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<GenerateContactCardResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        let state_str = payload.get("state").and_then(Value::as_str).ok_or("missing state")?;
        let id_str = payload.get("identity").and_then(Value::as_str).ok_or("missing identity")?;
        let entropy_str = payload.get("entropy").and_then(Value::as_str).unwrap_or(id_str);

        let identity = seed_from_entropy(&BASE64.decode(id_str).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(entropy_str).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(state_str, identity, entropy, b"gen-contact-card")?;

        let card = block_on(hive.generate_contact_card()).map_err(|e| e.to_string())?;
        let updated_state = archive_hive(&hive)?;

        Ok(GenerateContactCardResult {
            contact_card: card,
            state: updated_state,
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_receive_contact_card(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: ReceiveContactCardPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"receive-card")?;

        let card: ContactCard = if let Some(s) = payload.contact_card.as_str() {
            serde_json::from_str(s).map_err(|e| e.to_string())?
        } else {
            serde_json::from_value(payload.contact_card).map_err(|e| e.to_string())?
        };

        let peer_id = block_on(hive.receive_contact_card(&card)).map_err(|e| e.to_string())?;

        state_result(&hive, Some(BASE64.encode(peer_id.to_bytes())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_add_member(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: AddMemberPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(payload.entropy).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, entropy, b"add-member")?;

        let member_bytes: [u8; 32] = BASE64.decode(payload.member_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid member_id length")?;
        let member_id = identifier_from_bytes(member_bytes)?;

        let res_bytes: [u8; 32] = BASE64.decode(payload.resource_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid resource_id length")?;
        let res_id = identifier_from_bytes(res_bytes)?;

        let resource: MemberedId = if payload.is_group {
            MemberedId::GroupId(GroupId::new(res_id))
        } else {
            MemberedId::DocumentId(DocumentId::from(res_id))
        };

        let access = parse_access(&payload.access)?;

        block_on(hive.add_member(member_id, resource, access, &[]))
            .map_err(|e| e.to_string())?;

        state_result(&hive, None)
    })
}

// --- Content Sealing & Unsealing (BeeKEM Causal Encryption with Ratchet Envelope) ---

#[derive(Serialize, Deserialize, Clone)]
pub struct SealedPacket {
    pub doc_id: String,
    pub content_ref: String,
    pub encrypted: EncryptedContent<Vec<u8>, [u8; 32]>,
    #[serde(default)]
    pub update_op: Option<Signed<CgkaOperation>>,
}

#[derive(Deserialize)]
struct SealPayload {
    state: String,
    identity: String,
    entropy: String,
    doc_id: String,
    payload: String,
    #[serde(default)]
    pred_refs: Vec<String>,
}

#[derive(Serialize)]
struct UnsealResult {
    doc_id: String,
    plaintext: String,
    state: String,
}

#[derive(Serialize)]
struct SealResult {
    doc_id: String,
    content_ref: String,
    packet: String, // Base64 encoded bincode blob of SealedPacket
    state: String,
}

#[derive(Deserialize)]
struct UnsealPayload {
    state: String,
    identity: String,
    packet: String, // Base64 encoded bincode blob of SealedPacket
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_seal(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<SealResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: SealPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(payload.entropy).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, entropy, b"seal-content")?;

        let doc_bytes: [u8; 32] = BASE64.decode(&payload.doc_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid doc_id length")?;
        let doc_id = DocumentId::from(identifier_from_bytes(doc_bytes)?);

        let mut hasher = Sha256::new();
        hasher.update(payload.payload.as_bytes());
        let content_ref: [u8; 32] = hasher.finalize().into();

        let mut pred_refs: Vec<[u8; 32]> = Vec::new();
        for r_str in &payload.pred_refs {
            let bytes = BASE64.decode(r_str).map_err(|e| e.to_string())?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid pred_ref length")?;
            pred_refs.push(arr);
        }

        let encrypted_update = block_on(hive.try_encrypt_content(
            doc_id,
            &content_ref,
            &pred_refs,
            payload.payload.as_bytes(),
        ))
        .map_err(|e| e.to_string())?;

        let sealed_packet = SealedPacket {
            doc_id: payload.doc_id.clone(),
            content_ref: BASE64.encode(content_ref),
            encrypted: encrypted_update.encrypted_content().clone(),
            update_op: encrypted_update.update_op().cloned(),
        };

        let packet_bytes = bincode::serialize(&sealed_packet).map_err(|e| e.to_string())?;
        let updated_state = archive_hive(&hive)?;

        Ok(SealResult {
            doc_id: payload.doc_id,
            content_ref: BASE64.encode(content_ref),
            packet: BASE64.encode(packet_bytes),
            state: updated_state,
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_unseal(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<UnsealResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: UnsealPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"unseal-content")?;

        let packet_bytes = BASE64.decode(&payload.packet).map_err(|e| e.to_string())?;
        let p: SealedPacket = bincode::deserialize(&packet_bytes).map_err(|e| e.to_string())?;

        let doc_bytes: [u8; 32] = BASE64.decode(&p.doc_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid doc_id length")?;
        let doc_id = DocumentId::from(identifier_from_bytes(doc_bytes)?);


        // 1. Ratchet key tree if packet carries a CGKA update
        if let Some(op) = p.update_op {
            match block_on(hive.receive_cgka_op(op)) {
                Ok(()) => eprintln!(">>> [UNSEAL] receive_cgka_op: SUCCESS"),
                Err(e) => eprintln!(">>> [UNSEAL] receive_cgka_op ERROR: {:?}", e),
            }
        }

        // Diagnostic inspect of document's CGKA tree state
        let doc_handle = block_on(hive.get_document(doc_id));
        eprintln!(">>> [UNSEAL] Document in hive: {}", doc_handle.is_some());
        if let Some(doc) = doc_handle {
            let locked_doc = block_on(doc.lock());
            match locked_doc.cgka() {
                Ok(cgka) => {
                    eprintln!(">>> [UNSEAL] CGKA initialized: true");
                    eprintln!(">>> [UNSEAL] CGKA owner_leaf_key: {:?}", cgka.owner_leaf_key());
                    eprintln!(">>> [UNSEAL] CGKA owner_sks keys count: {}", cgka.owner_sks().len());
                }
                Err(e) => eprintln!(">>> [UNSEAL] CGKA initialized: false ({:?})", e),
            }
        }

        // 2. Decrypt with ratcheted key tree
        let plaintext_bytes = block_on(hive.try_decrypt_content(doc_id, &p.encrypted))
            .map_err(|e| format!("Keyhive decryption failed: {e}"))?;

        let plaintext = String::from_utf8(plaintext_bytes)
            .map_err(|e| format!("decrypted payload is not valid UTF-8: {e}"))?;

        let updated_state = archive_hive(&hive)?;

        Ok(UnsealResult {
            doc_id: p.doc_id,
            plaintext,
            state: updated_state,
        })
    })
}

#[derive(Deserialize)]
struct ExportEventsPayload {
    state: String,
    identity: String,
    recipient: String,
    #[serde(default)]
    have: Vec<String>, // Base64 digests the caller already possesses
}

#[derive(Deserialize)]
struct IngestEventsPayload {
    state: String,
    identity: String,
    entropy: String,
    events: String,
}


#[no_mangle]
pub unsafe extern "C" fn keyhive_export_events(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<String, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: ExportEventsPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"export-events")?;

        let rec_bytes: [u8; 32] = BASE64.decode(&payload.recipient)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid recipient identifier length")?;
        let recipient = identifier_from_bytes(rec_bytes)?;

        let have_set: HashSet<String> = payload.have.into_iter().collect();

        let events_map = block_on(hive.static_events_for_agent(recipient));
        let mut events: Vec<StaticEvent<[u8; 32]>> = events_map
            .into_iter()
            .filter(|(digest, _)| !have_set.contains(&BASE64.encode(digest.raw.as_bytes())))
            .map(|(_, ev)| ev)
            .collect();

        // Workaround for #206
        if let Some(agent) = block_on(hive.get_agent(recipient)) {
            let key_ops = block_on(agent.key_ops());
            for key_op in key_ops.values() {
                let ev = match key_op.as_ref() {
                    KeyOp::Add(add) => StaticEvent::PrekeysExpanded(Box::new((**add).clone())),
                    KeyOp::Rotate(rot) => StaticEvent::PrekeyRotated(Box::new((**rot).clone())),
                };
                events.push(ev);
            }
        }

        bincode::serialize(&events)
            .map(|b| BASE64.encode(b))
            .map_err(|e| e.to_string())
    })
}
#[no_mangle]
pub unsafe extern "C" fn keyhive_ingest_events(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: IngestEventsPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(payload.entropy).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, entropy, b"ingest-events")?;

        let event_bytes = BASE64.decode(&payload.events).map_err(|e| e.to_string())?;
        let events: Vec<StaticEvent<[u8; 32]>> = bincode::deserialize(&event_bytes).map_err(|e| e.to_string())?;

        // Ingest what we can; unresolved events are safely preserved in hive.pending_events
        let pending = block_on(hive.ingest_unsorted_static_events(events));
        let pending_count = pending.len();

        let mut res = state_result(&hive, None)?;
        res.pending = Some(pending_count);
        Ok(res)
    })
}

#[derive(Deserialize)]
struct AccessForDocPayload {
    state: String,
    identity: String,
    member_id: String,
    doc_id: String,
}

#[derive(Deserialize)]
struct ReachableMembersPayload {
    state: String,
    identity: String,
    resource_id: String,
    is_group: bool,
}

#[derive(Deserialize)]
struct RevokeMemberPayload {
    state: String,
    identity: String,
    entropy: String,
    resource_id: String,
    is_group: bool,
    member_id: String,
    #[serde(default = "default_retain")]
    retain_all_other_members: bool,
}

fn default_retain() -> bool {
    true
}

// 1. Query access level for a specific document
#[no_mangle]
pub unsafe extern "C" fn keyhive_access_for_doc(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<Option<String>, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: AccessForDocPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"access-query")?;

        let member_bytes: [u8; 32] = BASE64.decode(payload.member_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid member_id length")?;
        let who = identifier_from_bytes(member_bytes)?;

        let doc_bytes: [u8; 32] = BASE64.decode(payload.doc_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid doc_id length")?;
        let doc_id = DocumentId::from(identifier_from_bytes(doc_bytes)?);

        let access = block_on(hive.access_for_doc(who, doc_id));

        Ok(access.map(access_to_str).map(|s| s.to_string()))
    })
}

// 2. Query all documents accessible to the active identity
#[no_mangle]
pub unsafe extern "C" fn keyhive_reachable_docs(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<std::collections::HashMap<String, String>, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let state_str = payload.get("state").and_then(Value::as_str).ok_or("missing state")?;
        let id_str = payload.get("identity").and_then(Value::as_str).ok_or("missing identity")?;

        let identity = seed_from_entropy(&BASE64.decode(id_str).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(state_str, identity, [0u8; 32], b"reachable-docs")?;

        let docs = block_on(hive.reachable_docs());
        let mut result = std::collections::HashMap::new();
        for (doc_id, access) in docs {
            result.insert(
                BASE64.encode(doc_id.to_bytes()),
                access_to_str(access).to_string(),
            );
        }

        Ok(result)
    })
}

// 3. Query all members who reach a specific document or group
#[no_mangle]
pub unsafe extern "C" fn keyhive_reachable_members(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<std::collections::HashMap<String, String>, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: ReachableMembersPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"reachable-members")?;

        let res_bytes: [u8; 32] = BASE64.decode(payload.resource_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid resource_id length")?;
        let res_id = identifier_from_bytes(res_bytes)?;

        let resource: MemberedId = if payload.is_group {
            MemberedId::GroupId(GroupId::new(res_id))
        } else {
            MemberedId::DocumentId(DocumentId::from(res_id))
        };

        let members = block_on(hive.reachable_members(resource));
        let mut result = std::collections::HashMap::new();
        for (member_id, access) in members {
            result.insert(
                BASE64.encode(IndividualId::from(member_id).to_bytes()),
                access_to_str(access).to_string(),
            );
        }

        Ok(result)
    })
}

// 4. Revoke a member from a resource
#[no_mangle]
pub unsafe extern "C" fn keyhive_revoke_member(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: RevokeMemberPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(payload.entropy).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, entropy, b"revoke-member")?;

        let member_bytes: [u8; 32] = BASE64.decode(payload.member_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid member_id length")?;
        let to_revoke = identifier_from_bytes(member_bytes)?;

        let res_bytes: [u8; 32] = BASE64.decode(payload.resource_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid resource_id length")?;
        let res_id = identifier_from_bytes(res_bytes)?;

        let resource: MemberedId = if payload.is_group {
            MemberedId::GroupId(GroupId::new(res_id))
        } else {
            MemberedId::DocumentId(DocumentId::from(res_id))
        };

        block_on(hive.revoke_member(to_revoke, payload.retain_all_other_members, resource))
            .map_err(|e| e.to_string())?;

        state_result(&hive, None)
    })
}

fn access_to_str(access: Access) -> &'static str {
    match access {
        Access::Relay => "relay",
        Access::Read => "read",
        Access::Edit => "edit",
        Access::Admin => "admin",
    }
}

fn parse_access(s: &str) -> Result<Access, String> {
    match s.to_lowercase().as_str() {
        "relay" => Ok(Access::Relay),
        "read" => Ok(Access::Read),
        "edit" | "write" => Ok(Access::Edit),
        "admin" => Ok(Access::Admin),
        other => Err(format!(
            "unknown access level '{other}' (expected 'relay', 'read', 'edit', or 'admin')"
        )),
    }
}

// --- Prekey Secrets Export & Import (Multi-Device Migration) ---

#[derive(Deserialize)]
struct ImportPrekeySecretsPayload {
    state: String,
    identity: String,
    entropy: String,
    secrets: String, // Base64 encoded secret key material
}

// 1. Export private prekey secrets as an opaque base64 blob
#[no_mangle]
pub unsafe extern "C" fn keyhive_export_prekey_secrets(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<String, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let state_str = payload.get("state").and_then(Value::as_str).ok_or("missing state")?;
        let id_str = payload.get("identity").and_then(Value::as_str).ok_or("missing identity")?;

        let identity = seed_from_entropy(&BASE64.decode(id_str).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(state_str, identity, [0u8; 32], b"export-prekeys")?;

        let secrets_bytes = block_on(hive.export_prekey_secrets()).map_err(|e| e.to_string())?;

        Ok(BASE64.encode(secrets_bytes))
    })
}

// 2. Import private prekey secrets from a base64 blob onto a new device
#[no_mangle]
pub unsafe extern "C" fn keyhive_import_prekey_secrets(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: ImportPrekeySecretsPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(payload.entropy).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, entropy, b"import-prekeys")?;

        let secrets_bytes = BASE64.decode(&payload.secrets).map_err(|e| e.to_string())?;

        let unresolved = block_on(hive.import_prekey_secrets(&secrets_bytes))
            .map_err(|e| e.to_string())?;

        if !unresolved.is_empty() {
            return Err(format!(
                "import_prekey_secrets: {} pending events could not be resolved",
                unresolved.len()
            ));
        }

        state_result(&hive, None)
    })
}

// --- Effective & Public Access Evaluation ---

#[derive(Deserialize)]
struct BestAccessForDocPayload {
    state: String,
    identity: String,
    member_id: String,
    doc_id: String,
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_best_access_for_doc(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<Option<String>, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: BestAccessForDocPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"best-access")?;

        let member_bytes: [u8; 32] = BASE64.decode(payload.member_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid member_id length")?;
        let who = identifier_from_bytes(member_bytes)?;

        let doc_bytes: [u8; 32] = BASE64.decode(payload.doc_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid doc_id length")?;
        let doc_id = DocumentId::from(identifier_from_bytes(doc_bytes)?);

        let access = block_on(hive.best_access_for_doc(who, doc_id));
        Ok(access.map(access_to_str).map(|s| s.to_string()))
    })
}

// Well-known Public identifier
#[no_mangle]
pub unsafe extern "C" fn keyhive_public_id(_input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<String, String> {
        Ok(BASE64.encode(Public.id().to_bytes()))
    })
}

// --- Entity Existence Checks ---

#[derive(Deserialize)]
struct EntityCheckPayload {
    state: String,
    identity: String,
    id: String,
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_has_document(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<bool, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: EntityCheckPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"has-doc")?;

        let bytes: [u8; 32] = BASE64.decode(payload.id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid id length")?;
        let doc_id = DocumentId::from(identifier_from_bytes(bytes)?);

        Ok(block_on(hive.has_document(doc_id)))
    })
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_has_group(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<bool, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: EntityCheckPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"has-group")?;

        let bytes: [u8; 32] = BASE64.decode(payload.id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid id length")?;
        let group_id = GroupId::new(identifier_from_bytes(bytes)?);

        Ok(block_on(hive.has_group(group_id)))
    })
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_has_individual(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<bool, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: EntityCheckPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(&payload.state, identity, [0u8; 32], b"has-individual")?;

        let bytes: [u8; 32] = BASE64.decode(payload.id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "invalid id length")?;
        let indie_id = IndividualId::from(identifier_from_bytes(bytes)?);

        Ok(block_on(hive.has_individual(indie_id)))
    })
}

// --- Single-Pass Relay & Bulk Sync (`all_agent_events`) ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllAgentEventsResult {
    pub events: HashMap<String, String>,
    pub agent_events: HashMap<String, Vec<String>>,
    pub agent_payloads: HashMap<String, String>,
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_all_agent_events(input: *const c_char) -> *mut c_char {
    safe_call(|| -> Result<AllAgentEventsResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let state_str = payload.get("state").and_then(Value::as_str).ok_or("missing state")?;
        let id_str = payload.get("identity").and_then(Value::as_str).ok_or("missing identity")?;

        let identity = seed_from_entropy(&BASE64.decode(id_str).map_err(|e| e.to_string())?)?;
        let hive = restore_hive(state_str, identity, [0u8; 32], b"all-events")?;

        let all_events = block_on(hive.all_agent_events());

        // 1. Serialize all static events and collect by digest string (.raw.as_bytes())
        let mut static_events_by_digest: HashMap<String, (StaticEvent<[u8; 32]>, String)> = HashMap::new();
        for (digest, event) in all_events.events {
            let static_event: StaticEvent<[u8; 32]> = event.into();
            let bincode_bytes = bincode::serialize(&static_event).map_err(|e| e.to_string())?;
            let digest_b64 = BASE64.encode(digest.raw.as_bytes());
            let event_b64 = BASE64.encode(bincode_bytes);
            static_events_by_digest.insert(digest_b64, (static_event, event_b64));
        }

        // 2. Build per-agent index
        let public_id = Public.id();
        let mut all_agent_ids: HashSet<Identifier> = HashSet::new();
        all_agent_ids.extend(all_events.membership_index.keys());
        all_agent_ids.extend(all_events.prekey_index.keys());
        all_agent_ids.extend(all_events.cgka_index.keys());

        let mut agent_events: HashMap<String, Vec<String>> = HashMap::new();
        let mut agent_payloads: HashMap<String, String> = HashMap::new();

        for agent_id in all_agent_ids {
            let mut agent_digest_set: HashSet<String> = HashSet::new();
            let mut agent_static_events: Vec<StaticEvent<[u8; 32]>> = Vec::new();

            // Collect membership digests for this agent + Public
            if let Some(sources) = all_events.membership_index.get(&agent_id) {
                for src in sources {
                    if let Some(digests) = all_events.membership_sources.get(src) {
                        for d in digests {
                            agent_digest_set.insert(BASE64.encode(d.raw.as_bytes()));
                        }
                    }
                }
            }
            if agent_id != public_id {
                if let Some(pub_sources) = all_events.membership_index.get(&public_id) {
                    for src in pub_sources {
                        if let Some(digests) = all_events.membership_sources.get(src) {
                            for d in digests {
                                agent_digest_set.insert(BASE64.encode(d.raw.as_bytes()));
                            }
                        }
                    }
                }
            }

            // Collect prekey digests for this agent + Public
            if let Some(sources) = all_events.prekey_index.get(&agent_id) {
                for src in sources {
                    if let Some(digests) = all_events.prekey_sources.get(src) {
                        for d in digests {
                            agent_digest_set.insert(BASE64.encode(d.raw.as_bytes()));
                        }
                    }
                }
            }
            if agent_id != public_id {
                if let Some(pub_sources) = all_events.prekey_index.get(&public_id) {
                    for src in pub_sources {
                        if let Some(digests) = all_events.prekey_sources.get(src) {
                            for d in digests {
                                agent_digest_set.insert(BASE64.encode(d.raw.as_bytes()));
                            }
                        }
                    }
                }
            }

            // Collect CGKA digests for this agent + Public
            if let Some(sources) = all_events.cgka_index.get(&agent_id) {
                for src in sources {
                    if let Some(digests) = all_events.cgka_sources.get(src) {
                        for d in digests {
                            agent_digest_set.insert(BASE64.encode(d.raw.as_bytes()));
                        }
                    }
                }
            }
            if agent_id != public_id {
                if let Some(pub_sources) = all_events.cgka_index.get(&public_id) {
                    for src in pub_sources {
                        if let Some(digests) = all_events.cgka_sources.get(src) {
                            for d in digests {
                                agent_digest_set.insert(BASE64.encode(d.raw.as_bytes()));
                            }
                        }
                    }
                }
            }

            for d_str in &agent_digest_set {
                if let Some((ev, _)) = static_events_by_digest.get(d_str) {
                    agent_static_events.push(ev.clone());
                }
            }

            // Upstream #206 Workaround: Ensure recipient's contact card prekey op is present
            if let Some(agent) = block_on(hive.get_agent(agent_id)) {
                let key_ops = block_on(agent.key_ops());
                for key_op in key_ops.values() {
                    let ev = match key_op.as_ref() {
                        KeyOp::Add(add) => StaticEvent::PrekeysExpanded(Box::new((**add).clone())),
                        KeyOp::Rotate(rot) => StaticEvent::PrekeyRotated(Box::new((**rot).clone())),
                    };
                    agent_static_events.push(ev);
                }
            }

            let agent_id_b64 = BASE64.encode(agent_id.to_bytes());
            let payload_blob = bincode::serialize(&agent_static_events).map_err(|e| e.to_string())?;

            agent_events.insert(agent_id_b64.clone(), agent_digest_set.into_iter().collect());
            agent_payloads.insert(agent_id_b64, BASE64.encode(payload_blob));
        }

        let events_map = static_events_by_digest
            .into_iter()
            .map(|(k, (_, b64))| (k, b64))
            .collect();

        Ok(AllAgentEventsResult {
            events: events_map,
            agent_events,
            agent_payloads,
        })
    })
}