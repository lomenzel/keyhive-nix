use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::executor::block_on;
use futures::lock::Mutex;
use keyhive_core::{
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::signer::memory::MemorySigner;
use nonempty::nonempty;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::{c_char, CStr},
    sync::Arc,
};

const SEED_BYTES: usize = 32;

type Hive = Keyhive<
    future_form::Local,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    ChaCha20Rng,
>;

extern "C" {
    fn malloc(size: usize) -> *mut u8;
}

// --- Standard JSON Response Envelope ---

#[derive(Serialize)]
struct Response<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn response<T: Serialize>(value: Result<T, String>) -> *mut c_char {
    let output = match value {
        Ok(data) => serde_json::to_string(&Response {
            success: true,
            data: Some(data),
            error: None,
        }),
        Err(error) => serde_json::to_string(&Response::<()> {
            success: false,
            data: None,
            error: Some(error),
        }),
    }
    .expect("response serialization cannot fail");

    let bytes = output.as_bytes();
    unsafe {
        let ptr = malloc(bytes.len() + 1);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        *ptr.add(bytes.len()) = 0;
        ptr as *mut c_char
    }
}

// --- Cryptographic Helper Functions ---

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

fn derive_doc_cipher_key(secret_key: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keyhive-nix/doc-aead/v1");
    hasher.update(secret_key);
    hasher.update(nonce);
    hasher.finalize().into()
}

fn cipher_xor(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_seed(*key);
    let mut out = data.to_vec();
    for byte in out.iter_mut() {
        let mut k = [0u8; 1];
        rng.fill_bytes(&mut k);
        *byte ^= k[0];
    }
    out
}

// --- Capability Ticket, Invitations & State Envelope ---

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CapabilityTicket {
    pub doc_id: String,
    pub secret_key: String, // base64 encoded 32-byte secret key
    pub creator: String,    // base64 encoded creator verifying key
    pub authorized_writers: Vec<String>,
    pub creator_signature: String, // signature over (doc_id || secret_key || creator)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DelegationInvite {
    pub doc_id: String,
    pub recipient: String,       // Recipient's public verifying key
    pub secret_key: String,      // Document encryption key
    pub rights: Vec<String>,     // ["read", "write"]
    pub creator: String,        // Document creator's public verifying key
    pub delegation_sig: String, // Creator's signature over (doc_id || recipient || rights || secret_key)
}

#[derive(Serialize, Deserialize)]
struct StateEnvelope {
    archive: Vec<u8>,
    capabilities: HashMap<String, CapabilityTicket>,
}

fn make_hive(identity_seed: [u8; 32], operation_entropy: [u8; 32]) -> Result<Hive, String> {
    let signer = MemorySigner::from(SigningKey::from_bytes(&signer_seed(&identity_seed)));
    let rng = ChaCha20Rng::from_seed(rng_seed(&operation_entropy, b"init"));
    let store = MemoryCiphertextStore::new();
    block_on(Keyhive::generate(signer, store, NoListener, rng))
        .map_err(|error| error.to_string())
}

fn restore_hive(
    state: &str,
    identity_seed: [u8; 32],
    operation_entropy: [u8; 32],
    operation: &[u8],
) -> Result<(Hive, HashMap<String, CapabilityTicket>), String> {
    let bytes = BASE64
        .decode(state)
        .map_err(|error| format!("invalid state: {error}"))?;
    let envelope: StateEnvelope = bincode::deserialize(&bytes).map_err(|error| error.to_string())?;
    let archive = bincode::deserialize(&envelope.archive).map_err(|error| error.to_string())?;
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
    .map_err(|error| error.to_string())?;
    Ok((hive, envelope.capabilities))
}

fn archive(hive: &Hive, capabilities: HashMap<String, CapabilityTicket>) -> Result<String, String> {
    let archive = bincode::serialize(&block_on(hive.into_archive()))
        .map_err(|error| error.to_string())?;
    bincode::serialize(&StateEnvelope { archive, capabilities })
        .map(|bytes| BASE64.encode(bytes))
        .map_err(|error| error.to_string())
}

fn state_result(hive: &Hive, capabilities: HashMap<String, CapabilityTicket>) -> Result<StateResult, String> {
    Ok(StateResult {
        state: archive(hive, capabilities)?,
        id: BASE64.encode(hive.id().to_bytes()),
        stats: block_on(hive.stats()),
        created: None,
    })
}

// --- Payload Types ---

#[derive(Serialize)]
struct InitResult {
    state: String,
    id: String,
    stats: keyhive_core::stats::Stats,
}

#[derive(Serialize)]
struct IdentityResult {
    id: String,
}

#[derive(Serialize)]
struct StateResult {
    state: String,
    id: String,
    stats: keyhive_core::stats::Stats,
    created: Option<String>,
}

#[derive(Deserialize)]
struct GenDocPayload {
    state: String,
    identity: String,
    entropy: String,
}

#[derive(Deserialize)]
struct CreateInvitePayload {
    state: String,
    identity: String,
    doc_id: String,
    to: String,
    rights: Vec<String>,
}

#[derive(Serialize)]
struct CreateInviteResult {
    invite: DelegationInvite,
    state: String,
}

#[derive(Deserialize)]
struct AcceptInvitePayload {
    state: String,
    identity: String,
    invite: DelegationInvite,
}

#[derive(Deserialize)]
struct SealPayload {
    state: String,
    identity: String,
    doc_id: String,
    payload: String,
    entropy: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SealedPacket {
    pub doc_id: String,
    pub writer: String,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}

#[derive(Deserialize)]
struct UnsealPayload {
    state: String,
    identity: String,
    packet: SealedPacket,
}

#[derive(Serialize)]
struct UnsealResult {
    doc_id: String,
    writer: String,
    plaintext: String,
    state: String,
}

// --- C-ABI Export Implementations ---

#[no_mangle]
pub unsafe extern "C" fn keyhive_init(input: *const c_char) -> *mut c_char {
    let result = || -> Result<InitResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|error| error.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|error| error.to_string())?;
        let identity = BASE64
            .decode(payload.get("identity").and_then(Value::as_str).unwrap_or(""))
            .map_err(|error| format!("invalid identity: {error}"))?;
        let operation = BASE64
            .decode(payload.get("entropy").and_then(Value::as_str).unwrap_or(""))
            .map_err(|error| format!("invalid entropy: {error}"))?;
        let identity = seed_from_entropy(&identity)?;
        let operation = seed_from_entropy(&operation)?;
        let hive = make_hive(identity, operation)?;
        let result = state_result(&hive, HashMap::new())?;
        Ok(InitResult { state: result.state, id: result.id, stats: result.stats })
    }();
    response(result)
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_identity(input: *const c_char) -> *mut c_char {
    let result = || -> Result<IdentityResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|error| error.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|error| error.to_string())?;
        let entropy = BASE64
            .decode(payload.get("entropy").and_then(Value::as_str).unwrap_or(""))
            .map_err(|error| format!("invalid entropy: {error}"))?;
        let entropy = seed_from_entropy(&entropy)?;
        let key = SigningKey::from_bytes(&signer_seed(&entropy));
        Ok(IdentityResult { id: BASE64.encode(key.verifying_key().to_bytes()) })
    }();
    response(result)
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_restore(input: *const c_char) -> *mut c_char {
    let result = || -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|error| error.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|error| error.to_string())?;
        let identity = BASE64
            .decode(payload.get("identity").and_then(Value::as_str).unwrap_or(""))
            .map_err(|error| format!("invalid identity: {error}"))?;
        let identity = seed_from_entropy(&identity)?;
        let archive_str = payload
            .get("archive")
            .and_then(Value::as_str)
            .ok_or_else(|| "archive must be a base64 string".to_string())?;
        let (hive, capabilities) = restore_hive(archive_str, identity, [0u8; 32], b"restore")?;
        state_result(&hive, capabilities)
    }();
    response(result)
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_id(input: *const c_char) -> *mut c_char {
    let result = || -> Result<String, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|error| error.to_string())?;
        let bytes = BASE64
            .decode(raw)
            .map_err(|error| format!("invalid state: {error}"))?;
        let envelope: StateEnvelope =
            bincode::deserialize(&bytes).map_err(|error| error.to_string())?;
        let archive_obj: keyhive_core::archive::Archive<[u8; 32]> =
            bincode::deserialize(&envelope.archive).map_err(|error| error.to_string())?;
        Ok(BASE64.encode(archive_obj.id().to_bytes()))
    }();
    response(result)
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_stats(input: *const c_char) -> *mut c_char {
    let result = || -> Result<_, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|error| error.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|error| error.to_string())?;
        let state = payload.as_str().or_else(|| payload.get("state").and_then(Value::as_str))
            .ok_or_else(|| "state must be a base64 string or { state }".to_string())?;
        let identity = seed_from_entropy(
            &BASE64.decode(payload.get("entropy").and_then(Value::as_str).unwrap_or(""))
                .map_err(|error| format!("invalid entropy: {error}"))?,
        )?;
        let (hive, _) = restore_hive(state, identity, [0; 32], b"query")?;
        Ok(block_on(hive.stats()))
    }();
    response(result)
}

fn state_operation(
    input: *const c_char,
    operation: impl FnOnce(&Hive, &mut HashMap<String, CapabilityTicket>, &[u8; 32], &[u8; 32]) -> Result<Option<String>, String>,
    domain: &'static [u8],
) -> *mut c_char {
    let result = || -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|error| error.to_string())?;
        let payload: Value = serde_json::from_str(raw).map_err(|error| error.to_string())?;
        let state = payload.get("state").and_then(Value::as_str)
            .ok_or_else(|| "state must be a base64 string".to_string())?;
        let identity = payload.get("identity").and_then(Value::as_str)
            .ok_or_else(|| "identity must be a base64 string".to_string())?;
        let entropy = payload.get("entropy").and_then(Value::as_str)
            .ok_or_else(|| "entropy must be a base64 string".to_string())?;
        let identity = seed_from_entropy(&BASE64.decode(identity).map_err(|error| error.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(entropy).map_err(|error| error.to_string())?)?;
        let (hive, mut capabilities) = restore_hive(state, identity, entropy, domain)?;
        let created = operation(&hive, &mut capabilities, &identity, &entropy)?;
        let mut result = state_result(&hive, capabilities)?;
        result.created = created;
        Ok(result)
    }();
    response(result)
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_expand_prekeys(input: *const c_char) -> *mut c_char {
    state_operation(input, |hive, _, _, _| {
        block_on(hive.expand_prekeys()).map(|_| None).map_err(|error| error.to_string())
    }, b"expand-prekeys")
}

#[no_mangle]
pub unsafe extern "C" fn keyhive_generate_group(input: *const c_char) -> *mut c_char {
    state_operation(input, |hive, _, _, _| {
        block_on(hive.generate_group(vec![]))
            .map(|id| Some(BASE64.encode(id.to_bytes())))
            .map_err(|error| error.to_string())
    }, b"generate-group")
}

// 1. Creator creates doc alone (no need to foresee future collaborators)
#[no_mangle]
pub unsafe extern "C" fn keyhive_generate_document(input: *const c_char) -> *mut c_char {
    let result = || -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|error| error.to_string())?;
        let payload: GenDocPayload = serde_json::from_str(raw).map_err(|error| error.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let entropy = seed_from_entropy(&BASE64.decode(payload.entropy).map_err(|e| e.to_string())?)?;
        let (hive, mut capabilities) = restore_hive(&payload.state, identity, entropy, b"generate-document")?;

        let id = block_on(hive.generate_doc(vec![], nonempty![[0u8; 32]]))
            .map_err(|error| error.to_string())?;
        let doc_id = BASE64.encode(id.to_bytes());

        let secret_key = rng_seed(&entropy, b"doc-secret-v1");
        let signing_key = SigningKey::from_bytes(&signer_seed(&identity));
        let creator = BASE64.encode(signing_key.verifying_key().to_bytes());

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(doc_id.as_bytes());
        signed_data.extend_from_slice(&secret_key);
        signed_data.extend_from_slice(creator.as_bytes());
        let creator_signature = BASE64.encode(signing_key.sign(&signed_data).to_bytes());

        let ticket = CapabilityTicket {
            doc_id: doc_id.clone(),
            secret_key: BASE64.encode(secret_key),
            creator,
            authorized_writers: vec![],
            creator_signature,
        };

        capabilities.insert(doc_id.clone(), ticket);
        let mut res = state_result(&hive, capabilities)?;
        res.created = Some(doc_id);
        Ok(res)
    }();
    response(result)
}

// 2. Creator delegates permissions by issuing a signed invitation
#[no_mangle]
pub unsafe extern "C" fn keyhive_create_invite(input: *const c_char) -> *mut c_char {
    let result = || -> Result<CreateInviteResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: CreateInvitePayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let (hive, mut capabilities) = restore_hive(&payload.state, identity, [0u8; 32], b"create-invite")?;

        let signing_key = SigningKey::from_bytes(&signer_seed(&identity));
        let creator = BASE64.encode(signing_key.verifying_key().to_bytes());

        // Scope the borrow of capabilities so it ends before calling archive()
        let secret_key = {
            let ticket = capabilities
                .get_mut(&payload.doc_id)
                .ok_or_else(|| format!("Document '{}' not found", payload.doc_id))?;

            // Update local creator record to authorize writer
            if payload.rights.contains(&"write".to_string()) && !ticket.authorized_writers.contains(&payload.to) {
                ticket.authorized_writers.push(payload.to.clone());
            }

            ticket.secret_key.clone()
        }; // Borrow of `capabilities` ends here!

        // Creator signs the delegation granting rights to recipient
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(payload.doc_id.as_bytes());
        signed_data.extend_from_slice(payload.to.as_bytes());
        for r in &payload.rights {
            signed_data.extend_from_slice(r.as_bytes());
        }
        signed_data.extend_from_slice(secret_key.as_bytes());

        let delegation_sig = BASE64.encode(signing_key.sign(&signed_data).to_bytes());

        // Now capabilities can be safely moved into archive
        let updated_state = archive(&hive, capabilities)?;

        Ok(CreateInviteResult {
            invite: DelegationInvite {
                doc_id: payload.doc_id,
                recipient: payload.to,
                secret_key,
                rights: payload.rights,
                creator,
                delegation_sig,
            },
            state: updated_state,
        })
    }();
    response(result)
}
// 3. Recipient accepts the invitation and imports the capability
#[no_mangle]
pub unsafe extern "C" fn keyhive_accept_invite(input: *const c_char) -> *mut c_char {
    let result = || -> Result<StateResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: AcceptInvitePayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        let inv = payload.invite;

        let identity = seed_from_entropy(&BASE64.decode(payload.identity).map_err(|e| e.to_string())?)?;
        let (hive, mut capabilities) = restore_hive(&payload.state, identity, [0u8; 32], b"accept-invite")?;

        // Verify creator's signature on the delegation
        let creator_bytes = BASE64.decode(&inv.creator).map_err(|e| e.to_string())?;
        let creator_arr: [u8; 32] = creator_bytes.try_into().map_err(|_| "Invalid creator key length")?;
        let creator_key = VerifyingKey::from_bytes(&creator_arr).map_err(|e| e.to_string())?;

        let sig_bytes = BASE64.decode(&inv.delegation_sig).map_err(|e| e.to_string())?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "Invalid signature length")?;
        let sig = Signature::from_bytes(&sig_arr);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(inv.doc_id.as_bytes());
        signed_data.extend_from_slice(inv.recipient.as_bytes());
        for r in &inv.rights {
            signed_data.extend_from_slice(r.as_bytes());
        }
        signed_data.extend_from_slice(inv.secret_key.as_bytes());

        creator_key.verify(&signed_data, &sig).map_err(|_| "Invalid invite: creator signature verification failed")?;

        let ticket = CapabilityTicket {
            doc_id: inv.doc_id.clone(),
            secret_key: inv.secret_key,
            creator: inv.creator,
            authorized_writers: if inv.rights.contains(&"write".to_string()) {
                vec![inv.recipient]
            } else {
                vec![]
            },
            creator_signature: inv.delegation_sig,
        };

        capabilities.insert(inv.doc_id.clone(), ticket);
        let mut res = state_result(&hive, capabilities)?;
        res.created = Some(inv.doc_id);
        Ok(res)
    }();
    response(result)
}

// 4. Seal: encrypts payload with symmetric key and signs with Ed25519
#[no_mangle]
pub unsafe extern "C" fn keyhive_seal(input: *const c_char) -> *mut c_char {
    let result = || -> Result<SealedPacket, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: SealPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;

        let identity = BASE64.decode(payload.identity).map_err(|e| e.to_string())?;
        let entropy = BASE64.decode(payload.entropy).map_err(|e| e.to_string())?;
        let id_seed = seed_from_entropy(&identity)?;
        let nonce = seed_from_entropy(&entropy)?;

        let (_, capabilities) = restore_hive(&payload.state, id_seed, [0u8; 32], b"seal")?;
        let ticket = capabilities
            .get(&payload.doc_id)
            .ok_or_else(|| format!("Cannot seal: document capability '{}' not found in Keyhive state", payload.doc_id))?;

        let secret_key_bytes = BASE64.decode(&ticket.secret_key).map_err(|e| e.to_string())?;
        let secret_key_arr: [u8; 32] = secret_key_bytes.try_into().map_err(|_| "Invalid secret key length")?;

        let signing_key = SigningKey::from_bytes(&signer_seed(&id_seed));
        let writer = BASE64.encode(signing_key.verifying_key().to_bytes());

        // Check write permission
        if writer != ticket.creator && !ticket.authorized_writers.contains(&writer) {
            return Err(format!("Cannot seal: writer '{}' is not authorized to write to '{}'", writer, payload.doc_id));
        }

        let cipher_key = derive_doc_cipher_key(&secret_key_arr, &nonce);
        let ciphertext = cipher_xor(&cipher_key, payload.payload.as_bytes());

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(payload.doc_id.as_bytes());
        signed_data.extend_from_slice(&nonce);
        signed_data.extend_from_slice(&ciphertext);
        let signature = signing_key.sign(&signed_data);

        Ok(SealedPacket {
            doc_id: payload.doc_id,
            writer,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
            signature: BASE64.encode(signature.to_bytes()),
        })
    }();
    response(result)
}

// 5. Unseal: authenticates writer, checks capability, and decrypts payload
#[no_mangle]
pub unsafe extern "C" fn keyhive_unseal(input: *const c_char) -> *mut c_char {
    let result = || -> Result<UnsealResult, String> {
        let raw = unsafe { CStr::from_ptr(input) }.to_str().map_err(|e| e.to_string())?;
        let payload: UnsealPayload = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        let p = payload.packet;

        let identity = BASE64.decode(payload.identity).map_err(|e| e.to_string())?;
        let id_seed = seed_from_entropy(&identity)?;
        let (_, local_capabilities) = restore_hive(&payload.state, id_seed, [0u8; 32], b"unseal")?;

        let ticket = local_capabilities
            .get(&p.doc_id)
            .ok_or_else(|| format!("Access denied: document capability '{}' not found in Keyhive state", p.doc_id))?;

        // 1. Authorization Gate
        if p.writer != ticket.creator && !ticket.authorized_writers.contains(&p.writer) {
            return Err(format!("Unauthorized writer: '{}' does not have write access for doc '{}'", p.writer, p.doc_id));
        }

        // 2. Digital Signature Verification
        let writer_bytes = BASE64.decode(&p.writer).map_err(|e| e.to_string())?;
        let nonce_bytes = BASE64.decode(&p.nonce).map_err(|e| e.to_string())?;
        let cipher_bytes = BASE64.decode(&p.ciphertext).map_err(|e| e.to_string())?;
        let sig_bytes = BASE64.decode(&p.signature).map_err(|e| e.to_string())?;

        let writer_arr: [u8; 32] = writer_bytes.try_into().map_err(|_| "Invalid writer key length")?;
        let nonce_arr: [u8; 32] = nonce_bytes.try_into().map_err(|_| "Invalid nonce length")?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "Invalid signature length")?;

        let verifying_key = VerifyingKey::from_bytes(&writer_arr).map_err(|e| e.to_string())?;
        let signature = Signature::from_bytes(&sig_arr);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(p.doc_id.as_bytes());
        signed_data.extend_from_slice(&nonce_arr);
        signed_data.extend_from_slice(&cipher_bytes);

        verifying_key.verify(&signed_data, &signature).map_err(|_| "Packet signature verification failed: packet was tampered with or forged")?;

        // 3. Decrypt verified payload
        let secret_key_bytes = BASE64.decode(&ticket.secret_key).map_err(|e| e.to_string())?;
        let secret_key_arr: [u8; 32] = secret_key_bytes.try_into().map_err(|_| "Invalid secret key length")?;

        let cipher_key = derive_doc_cipher_key(&secret_key_arr, &nonce_arr);
        let plaintext_bytes = cipher_xor(&cipher_key, &cipher_bytes);
        let plaintext = String::from_utf8(plaintext_bytes).map_err(|e| format!("Invalid UTF-8 payload: {}", e))?;

        Ok(UnsealResult {
            doc_id: p.doc_id,
            writer: p.writer,
            plaintext,
            state: payload.state,
        })
    }();
    response(result)
}

#[allow(dead_code)]
fn _assert_rng_is_used(rng: &mut ChaCha20Rng) {
    let _ = rng.next_u32();
}