use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Query, State as AxumState},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::StreamExt as _;
use get_if_addrs::{get_if_addrs, IfAddr};
use rand::{rngs::OsRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs::File as StdFile,
    io::SeekFrom,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State as TauriState};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
    task::JoinHandle,
};
use tokio_util::io::ReaderStream;
use tower_http::services::{ServeDir, ServeFile};
use uuid::Uuid;
use walkdir::WalkDir;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkInterfaceInfo {
    id: String,
    name: String,
    address: String,
    cidr: String,
    mac: String,
    bluetooth: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerConfig {
    host_ip: String,
    port: u16,
    #[serde(default)]
    download_speed_limit_mbps: u64,
    #[serde(default)]
    tls_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls_cert_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls_key_path: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityState {
    link_secret: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppState {
    server: ServerConfig,
    security: SecurityState,
    shares: Vec<ShareRecordInternal>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareRecordInternal {
    id: String,
    name: String,
    local_path: String,
    description: String,
    access_mode: String,
    allow_mobile_access: bool,
    created_at: String,
    passcode_hash: String,
    passcode_hint: String,
    passcode_updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    passcode_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passcode_duration: Option<String>,
    ip_whitelist: String,
    #[serde(default)]
    allow_upload: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receive_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    speed_limit_mbps: Option<u64>,
    #[serde(default)]
    one_time_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upload_max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upload_extensions: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ShareRecordAdmin {
    id: String,
    name: String,
    encrypted_link_token: String,
    local_path: String,
    description: String,
    access_mode: String,
    allow_mobile_access: bool,
    created_at: String,
    passcode_hint: String,
    passcode_updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    passcode_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passcode_duration: Option<String>,
    ip_whitelist: String,
    allow_upload: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    receive_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    speed_limit_mbps: Option<u64>,
    one_time_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_max_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_extensions: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicShareInfo {
    id: String,
    name: String,
    description: String,
    access_mode: String,
    allow_mobile_access: bool,
    passcode_hint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    passcode_expires_at: Option<String>,
    ip_whitelist: String,
    upload_allowed: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicShareResponse {
    share: PublicShareInfo,
    client_ip: String,
    ip_allowed: bool,
    mobile_blocked: bool,
    passcode_expired: bool,
    occupied: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    token: String,
    expires_at: i64,
    client_ip: String,
    share: PublicShareInfo,
    files: Vec<PhysicalFile>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalFile {
    id: String,
    name: String,
    relative_path: String,
    #[serde(rename = "type")]
    file_type: String,
    size_bytes: u64,
    size: String,
    last_modified: String,
    category: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewResult {
    #[serde(rename = "type")]
    preview_type: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HashResult {
    file_name: String,
    size_bytes: u64,
    sha256: String,
    md5: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadReceipt {
    name: String,
    relative_path: String,
    size_bytes: u64,
    sha256: String,
    md5: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeIdleGuard {
    #[serde(rename = "type")]
    guard_type: String,
    active: bool,
    blocker_id: Option<u64>,
    note: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerLease {
    share_id: String,
    client_ip: String,
    expires_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditEvent {
    timestamp: String,
    kind: String,
    share_name: String,
    client_ip: String,
    file_name: String,
    size_bytes: u64,
    outcome: String,
    detail: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveJobResponse {
    job_id: String,
    share_name: String,
    status: String,
    total_bytes: u64,
    done_bytes: u64,
    size_bytes: u64,
    sha256: String,
    md5: String,
    error: String,
}

#[derive(Clone)]
struct ArchiveJob {
    share_name: String,
    temp_path: PathBuf,
    total_bytes: u64,
    done_bytes: u64,
    status: String,
    size_bytes: u64,
    sha256: String,
    md5: String,
    error: String,
    created_at: i64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    ok: bool,
    version: String,
    port: u16,
    running: bool,
    uptime_ms: u64,
    audit_events: usize,
    active_transfers: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerTransfer {
    id: u64,
    #[serde(rename = "type")]
    transfer_type: String,
    share_id: String,
    share_name: String,
    client_ip: String,
    file_name: String,
    size_bytes: u64,
    started_at: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerStateResponse {
    running: bool,
    host_ip: String,
    bind_address: String,
    port: u16,
    download_speed_limit_mbps: u64,
    tls_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_key_path: Option<String>,
    error: String,
    url_base: String,
    access_urls: Vec<String>,
    runtime_idle_guard: RuntimeIdleGuard,
    active_leases: Vec<ServerLease>,
    active_transfers: Vec<ServerTransfer>,
}

#[derive(Clone)]
struct ServerRuntime {
    running: bool,
    host_ip: String,
    bind_address: String,
    port: u16,
    error: String,
}

#[derive(Clone)]
struct AuthTokenRecord {
    token: String,
    share_id: String,
    client_ip: String,
    user_agent_hash: String,
    expires_at: i64,
}

#[derive(Clone)]
struct LeaseRecord {
    token: String,
    client_ip: String,
    expires_at: i64,
}

#[derive(Clone)]
struct ActiveTransfer {
    id: u64,
    transfer_type: String,
    share_id: String,
    share_name: String,
    client_ip: String,
    file_name: String,
    size_bytes: u64,
    started_at: i64,
}

struct ServerControl {
    shutdown: Option<axum_server::Handle>,
    handle: Option<JoinHandle<()>>,
}

struct Backend {
    state_path: PathBuf,
    audit_path: PathBuf,
    dist_dir: PathBuf,
    started_at_ms: u64,
    app_state: Mutex<AppState>,
    server_state: Mutex<ServerRuntime>,
    active_tokens: Mutex<HashMap<String, AuthTokenRecord>>,
    share_leases: Mutex<HashMap<String, LeaseRecord>>,
    active_transfers: Mutex<HashMap<u64, ActiveTransfer>>,
    audit_log: Mutex<VecDeque<AuditEvent>>,
    archive_jobs: Mutex<HashMap<String, Arc<tokio::sync::Mutex<ArchiveJob>>>>,
    passcode_attempts: Mutex<HashMap<String, (u32, i64)>>,
    server_control: Mutex<ServerControl>,
    next_transfer_id: AtomicU64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetServerConfigPayload {
    host_ip: String,
    port: u16,
    #[serde(default)]
    download_speed_limit_mbps: Option<u64>,
    #[serde(default)]
    tls_enabled: Option<bool>,
    #[serde(default)]
    tls_cert_path: Option<String>,
    #[serde(default)]
    tls_key_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSharePayload {
    name: String,
    local_path: String,
    #[serde(default)]
    description: String,
    passcode: String,
    passcode_expires_at: Option<String>,
    passcode_duration: Option<String>,
    ip_whitelist: Option<String>,
    access_mode: Option<String>,
    allow_mobile_access: Option<bool>,
    #[serde(default)]
    allow_upload: Option<bool>,
    #[serde(default)]
    receive_dir: Option<String>,
    #[serde(default)]
    speed_limit_mbps: Option<u64>,
    #[serde(default)]
    one_time_access: Option<bool>,
    #[serde(default)]
    upload_max_bytes: Option<u64>,
    #[serde(default)]
    upload_extensions: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSharePatch {
    description: Option<String>,
    passcode: Option<String>,
    passcode_expires_at: Option<String>,
    passcode_duration: Option<String>,
    ip_whitelist: Option<String>,
    access_mode: Option<String>,
    allow_mobile_access: Option<bool>,
    #[serde(default)]
    allow_upload: Option<bool>,
    #[serde(default)]
    receive_dir: Option<String>,
    #[serde(default)]
    speed_limit_mbps: Option<u64>,
    #[serde(default)]
    one_time_access: Option<bool>,
    #[serde(default)]
    upload_max_bytes: Option<u64>,
    #[serde(default)]
    upload_extensions: Option<String>,
}

#[derive(Deserialize)]
struct AccessQuery {
    share: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct AuthPayload {
    share: Option<String>,
    token: Option<String>,
    passcode: Option<String>,
}

#[derive(Deserialize)]
struct PathQuery {
    path: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct UploadQuery {
    path: Option<String>,
    token: Option<String>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadChunkQuery {
    token: Option<String>,
    name: String,
    #[serde(default)]
    path: Option<String>,
    upload_id: String,
    offset: u64,
    #[serde(default, rename = "final")]
    final_chunk: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadChunkStatusQuery {
    token: Option<String>,
    name: String,
    #[serde(default)]
    path: Option<String>,
    upload_id: String,
}

#[derive(Deserialize)]
struct ReceiveDirsQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct ArchiveStartQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct ArchiveStartPayload {
    paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveJobQuery {
    job_id: String,
    token: Option<String>,
}

#[derive(Deserialize)]
struct MediaQuery {
    path: String,
    token: Option<String>,
}

struct ArchiveQuery {
    path: Vec<String>,
    token: Option<String>,
}

impl<'de> Deserialize<'de> for ArchiveQuery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ArchiveQueryVisitor;

        impl<'de> serde::de::Visitor<'de> for ArchiveQueryVisitor {
            type Value = ArchiveQuery;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a query string with repeated `path` values")
            }

            fn visit_map<A>(self, mut map: A) -> Result<ArchiveQuery, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut path = Vec::new();
                let mut token = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "path" => path.push(map.next_value()?),
                        "token" => token = Some(map.next_value()?),
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(ArchiveQuery { path, token })
            }
        }

        deserializer.deserialize_map(ArchiveQueryVisitor)
    }
}

#[derive(Serialize)]
struct FilesResponse {
    files: Vec<PhysicalFile>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatResponse {
    ok: bool,
    expires_at: i64,
    share: PublicShareInfo,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }

    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error.to_string())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn audit_event(
    kind: &str,
    share_name: &str,
    client_ip: &str,
    file_name: &str,
    size_bytes: u64,
    outcome: &str,
    detail: &str,
) -> AuditEvent {
    AuditEvent {
        timestamp: iso_now(),
        kind: kind.to_string(),
        share_name: share_name.to_string(),
        client_ip: client_ip.to_string(),
        file_name: file_name.to_string(),
        size_bytes,
        outcome: outcome.to_string(),
        detail: detail.to_string(),
    }
}

fn api_error_from_path_result(error: anyhow::Error) -> ApiError {
    if error.to_string().contains("非法路径") {
        ApiError::bad_request(error)
    } else {
        ApiError::internal(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.message })).into_response()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkTokenPayload {
    purpose: String,
    share_id: String,
    issued_at: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn iso_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn iso_from_ms(ms: i64) -> String {
    let dt = DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64));
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn iso_from_system_time(time: SystemTime) -> String {
    let dt = DateTime::<Utc>::from(time);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn write_self_signed_cert(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};

    std::fs::create_dir_all(dir)?;
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    let key_pair = KeyPair::generate().context("生成密钥失败")?;
    let mut params = CertificateParams::new(vec![]).context("初始化证书参数失败")?;
    let mut sans = vec![SanType::DnsName(Ia5String::try_from("localhost").context("证书域名无效")?)];
    for item in network_interfaces() {
        if let Ok(ip) = item.address.parse::<IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        }
    }
    params.subject_alt_names = sans;
    let certificate = params.self_signed(&key_pair).context("生成自签名证书失败")?;
    std::fs::write(&cert_path, certificate.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((cert_path, key_path))
}

fn network_interfaces() -> Vec<NetworkInterfaceInfo> {
    let mut rows = Vec::new();
    if let Ok(interfaces) = get_if_addrs() {
        for iface in interfaces {
            if let IfAddr::V4(v4) = iface.addr {
                if v4.ip.is_loopback() {
                    continue;
                }
                let prefix = v4
                    .netmask
                    .octets()
                    .iter()
                    .map(|byte| byte.count_ones())
                    .sum::<u32>();
                let address = v4.ip.to_string();
                let name = iface.name;
                rows.push(NetworkInterfaceInfo {
                    id: format!("{}-{}", name, address),
                    name: name.clone(),
                    cidr: format!("{}/{}", address, prefix),
                    address,
                    mac: String::new(),
                    bluetooth: is_bluetooth_interface(&name),
                });
            }
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.address.cmp(&b.address)));
    rows
}

fn is_bluetooth_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("bluetooth")
        || lower.starts_with("bridge")
        || lower.starts_with("bnep")
        || lower.starts_with("pan")
        || lower.starts_with("bt-")
}

fn first_usable_ip() -> String {
    network_interfaces()
        .first()
        .map(|item| item.address.clone())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn normalize_host_ip(input: impl AsRef<str>) -> String {
    let clean = input.as_ref().trim();
    let usable: Vec<String> = network_interfaces().into_iter().map(|item| item.address).collect();
    if usable.iter().any(|item| item == clean) {
        clean.to_string()
    } else {
        first_usable_ip()
    }
}

fn access_urls_for_port(scheme: &str, port: u16, preferred_host_ip: &str) -> Vec<String> {
    let mut addresses = network_interfaces()
        .into_iter()
        .map(|item| item.address)
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        addresses.push("127.0.0.1".to_string());
    }
    let preferred = normalize_host_ip(preferred_host_ip);
    let mut ordered = vec![preferred];
    ordered.extend(addresses);
    ordered.sort();
    ordered.dedup();
    ordered
        .into_iter()
        .map(|address| format!("{scheme}://{}:{}", address, port))
        .collect()
}

fn default_app_state() -> AppState {
    AppState {
        server: ServerConfig {
            host_ip: first_usable_ip(),
            port: 8787,
            download_speed_limit_mbps: 0,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        },
        security: SecurityState {
            link_secret: random_secret(),
        },
        shares: Vec::new(),
    }
}

fn public_share(share: &ShareRecordInternal) -> PublicShareInfo {
    PublicShareInfo {
        id: share.id.clone(),
        name: share.name.clone(),
        description: share.description.clone(),
        access_mode: normalize_access_mode(Some(share.access_mode.as_str())),
        allow_mobile_access: share.allow_mobile_access,
        passcode_hint: share.passcode_hint.clone(),
        passcode_expires_at: share.passcode_expires_at.clone(),
        ip_whitelist: share.ip_whitelist.clone(),
        upload_allowed: share.allow_upload && share.receive_dir.is_some(),
    }
}

fn admin_share(share: &ShareRecordInternal, secret: &str) -> Result<ShareRecordAdmin> {
    Ok(ShareRecordAdmin {
        id: share.id.clone(),
        name: share.name.clone(),
        encrypted_link_token: create_encrypted_link_token(secret, &share.id)?,
        local_path: share.local_path.clone(),
        description: share.description.clone(),
        access_mode: normalize_access_mode(Some(share.access_mode.as_str())),
        allow_mobile_access: share.allow_mobile_access,
        created_at: share.created_at.clone(),
        passcode_hint: share.passcode_hint.clone(),
        passcode_updated_at: share.passcode_updated_at.clone(),
        passcode_expires_at: share.passcode_expires_at.clone(),
        passcode_duration: share.passcode_duration.clone(),
        ip_whitelist: share.ip_whitelist.clone(),
        allow_upload: share.allow_upload,
        receive_dir: share.receive_dir.clone(),
        speed_limit_mbps: share.speed_limit_mbps,
        one_time_access: share.one_time_access,
        upload_max_bytes: share.upload_max_bytes,
        upload_extensions: share.upload_extensions.clone(),
    })
}

fn link_cipher_key(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn create_encrypted_link_token(secret: &str, share_id: &str) -> Result<String> {
    let key = link_cipher_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("加密密钥初始化失败"))?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let payload = LinkTokenPayload {
        purpose: "share-link".to_string(),
        share_id: share_id.to_string(),
        issued_at: now_ms(),
    };
    let plaintext = serde_json::to_vec(&payload)?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| anyhow!("共享链接加密失败"))?;
    let mut output = Vec::with_capacity(nonce_bytes.len() + encrypted.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);
    Ok(URL_SAFE_NO_PAD.encode(output))
}

fn share_id_from_encrypted_link_token(secret: &str, token: &str) -> Option<String> {
    let raw = URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?;
    if raw.len() <= 12 {
        return None;
    }
    let (nonce_bytes, encrypted) = raw.split_at(12);
    let key = link_cipher_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let decrypted = cipher.decrypt(Nonce::from_slice(nonce_bytes), encrypted).ok()?;
    let payload: LinkTokenPayload = serde_json::from_slice(&decrypted).ok()?;
    if payload.purpose == "share-link" && !payload.share_id.is_empty() {
        Some(payload.share_id)
    } else {
        None
    }
}

fn normalize_alias(input: &str) -> Result<String> {
    let alias = input
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect::<String>();
    if alias.is_empty() {
        Err(anyhow!("共享别名不能为空，且只能包含英文、数字、下划线和短横线"))
    } else {
        Ok(alias)
    }
}

fn normalize_access_mode(input: Option<&str>) -> String {
    if input == Some("multi") {
        "multi".to_string()
    } else {
        "exclusive".to_string()
    }
}

fn normalize_ip_whitelist(input: Option<&str>) -> String {
    input
        .unwrap_or_default()
        .split(|ch: char| ch == ',' || ch == '，' || ch == ';' || ch == '；' || ch.is_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

fn normalize_upload_extensions(input: &str) -> String {
    input
        .split(|ch: char| ch == ',' || ch == '，' || ch == ';' || ch == '；' || ch.is_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.trim_start_matches('.').to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

fn normalize_receive_dir(allow_upload: bool, receive_dir: Option<&str>) -> Result<Option<String>, String> {
    if !allow_upload {
        return Ok(None);
    }
    let dir = receive_dir
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "允许上传时必须选择接收目录".to_string())?;
    let canonical = Path::new(dir)
        .canonicalize()
        .map_err(|error| format!("上传接收目录不存在：{error}"))?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| error.to_string())?;
    if !metadata.is_dir() {
        return Err("上传接收目录必须是文件夹".to_string());
    }
    Ok(Some(canonical.to_string_lossy().to_string()))
}

fn make_passcode_record(passcode: &str) -> Result<(String, String, String)> {
    let clean = passcode.trim();
    if clean.is_empty() {
        return Err(anyhow!("访问口令不能为空"));
    }
    let mut salt_bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt = hex::encode(salt_bytes);
    let params = ScryptParams::new(14, 8, 1, 32).context("scrypt 参数初始化失败")?;
    let mut output = [0_u8; 32];
    scrypt(clean.as_bytes(), salt.as_bytes(), &params, &mut output).context("访问口令哈希失败")?;
    let hint = if clean.chars().count() <= 4 {
        format!("{} 位 / 已加密保存", clean.chars().count())
    } else {
        let tail = clean
            .chars()
            .rev()
            .take(2)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>();
        format!("{} 位 / 末尾 {} / 已加密保存", clean.chars().count(), tail)
    };
    Ok((format!("scrypt${}${}", salt, hex::encode(output)), hint, iso_now()))
}

fn verify_passcode(passcode: &str, stored: &str) -> bool {
    if !stored.starts_with("scrypt$") {
        return false;
    }
    let parts = stored.split('$').collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }
    let expected = match hex::decode(parts[2]) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let params = match ScryptParams::new(14, 8, 1, 32) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut actual = vec![0_u8; expected.len()];
    if scrypt(passcode.trim().as_bytes(), parts[1].as_bytes(), &params, &mut actual).is_err() {
        return false;
    }
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .iter()
        .zip(expected.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn parse_expiry_ms(value: &Option<String>) -> Option<i64> {
    value
        .as_ref()
        .and_then(|item| DateTime::parse_from_rfc3339(item).ok())
        .map(|dt| dt.timestamp_millis())
}

fn is_passcode_expired(share: &ShareRecordInternal) -> bool {
    parse_expiry_ms(&share.passcode_expires_at)
        .map(|ms| ms <= now_ms())
        .unwrap_or(false)
}

fn request_user_agent_hash(headers: &HeaderMap) -> String {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    URL_SAFE_NO_PAD.encode(Sha256::digest(ua.as_bytes()))
}

fn is_mobile_user_agent(headers: &HeaderMap) -> bool {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let ua_mobile = headers
        .get("sec-ch-ua-mobile")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_string();
    let platform = headers
        .get("sec-ch-ua-platform")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .replace('"', "");
    ua_mobile == "?1"
        || platform.contains("Android")
        || platform.contains("iOS")
        || platform.contains("iPhone")
        || platform.contains("iPad")
        || ua.contains("Android")
        || ua.contains("iPhone")
        || ua.contains("iPad")
        || ua.contains("iPod")
        || ua.contains("Mobile")
        || ua.contains("Tablet")
        || ua.contains("Kindle")
        || ua.contains("Silk")
}

fn parse_ipv4(value: &str) -> Option<u32> {
    let addr: Ipv4Addr = value.trim().trim_start_matches("::ffff:").parse().ok()?;
    Some(u32::from(addr))
}

fn ip_in_whitelist(client_ip: &str, whitelist: &str) -> bool {
    if whitelist.trim().is_empty() {
        return true;
    }
    let clean_ip = client_ip.trim().trim_start_matches("::ffff:");
    let clean_ip_number = parse_ipv4(clean_ip);
    for rule in whitelist.split(',').map(str::trim).filter(|item| !item.is_empty()) {
        if clean_ip == rule {
            return true;
        }
        if rule.contains('*') {
            let ip_parts = clean_ip.split('.').collect::<Vec<_>>();
            let rule_parts = rule.split('.').collect::<Vec<_>>();
            if ip_parts.len() == 4
                && rule_parts.len() == 4
                && ip_parts
                    .iter()
                    .zip(rule_parts.iter())
                    .all(|(ip, pattern)| *pattern == "*" || ip == pattern)
            {
                return true;
            }
            continue;
        }
        if let Some((subnet, mask_text)) = rule.split_once('/') {
            let mask = mask_text.parse::<u32>().ok();
            let subnet_number = parse_ipv4(subnet);
            if let (Some(mask), Some(subnet_number), Some(clean_ip_number)) = (mask, subnet_number, clean_ip_number) {
                if mask <= 32 {
                    let mask_number = if mask == 0 { 0 } else { u32::MAX << (32 - mask) };
                    if (subnet_number & mask_number) == (clean_ip_number & mask_number) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn category_for_file(name: &str) -> &'static str {
    let ext = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "txt" | "md" | "pdf" | "doc" | "docx" | "rtf" => "document",
        "xls" | "xlsx" | "csv" | "tsv" => "spreadsheet",
        "js" | "ts" | "tsx" | "json" | "xml" | "html" | "css" | "ps1" | "sh" | "py" | "cs" => "code",
        "zip" | "7z" | "rar" | "tar" | "gz" | "msi" | "exe" => "archive",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "mp4" | "mov" | "mp3" | "wav" => "media",
        _ => "other",
    }
}

fn preview_media_kind(ext: &str) -> Option<&'static str> {
    const IMAGE: &[&str] = &[
        "png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "heic", "heif", "avif", "tiff",
        "tif", "ico",
    ];
    const VIDEO: &[&str] = &[
        "mp4", "mov", "m4v", "webm", "mkv", "avi", "mpeg", "mpg", "wmv", "flv", "ts", "3gp",
        "3g2",
    ];
    const AUDIO: &[&str] = &[
        "mp3", "wav", "m4a", "aac", "flac", "ogg", "opus", "wma", "amr", "aiff", "aif",
    ];
    if IMAGE.contains(&ext) {
        Some("image")
    } else if VIDEO.contains(&ext) {
        Some("video")
    } else if AUDIO.contains(&ext) {
        Some("audio")
    } else {
        None
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn encode_path_id(relative_path: &str) -> String {
    URL_SAFE_NO_PAD.encode(relative_path.as_bytes())
}

fn safe_resolve(root: &str, relative_path: Option<&str>) -> Result<PathBuf> {
    let root_full = Path::new(root)
        .canonicalize()
        .with_context(|| format!("共享路径不存在：{}", root))?;
    let root_meta = std::fs::metadata(&root_full)?;
    let rel_text = relative_path.unwrap_or_default().replace('\\', "/");
    if root_meta.is_file() {
        let root_name = root_full
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if rel_text.is_empty() || rel_text == "." || rel_text == root_name {
            return Ok(root_full);
        }
        return Err(anyhow!("非法路径：该共享仅包含一个指定文件"));
    }
    if rel_text.is_empty() || rel_text == "." {
        return Ok(root_full);
    }
    let rel = Path::new(&rel_text);
    if rel.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(anyhow!("非法路径：目标不在共享目录内"));
    }
    let full = root_full.join(rel).canonicalize()?;
    if full != root_full && !full.starts_with(&root_full) {
        return Err(anyhow!("非法路径：目标不在共享目录内"));
    }
    Ok(full)
}

async fn list_physical_files(root: String) -> Result<Vec<PhysicalFile>> {
    tokio::task::spawn_blocking(move || list_physical_files_sync(&root, 6, 5000))
        .await
        .context("读取共享目录任务失败")?
}

fn list_physical_files_sync(root: &str, max_depth: usize, max_items: usize) -> Result<Vec<PhysicalFile>> {
    let root_full = Path::new(root).canonicalize()?;
    let root_meta = std::fs::metadata(&root_full)?;
    if root_meta.is_file() {
        let name = root_full
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("file")
            .to_string();
        return Ok(vec![PhysicalFile {
            id: encode_path_id(&name),
            name: name.clone(),
            relative_path: name.clone(),
            file_type: "file".to_string(),
            size_bytes: root_meta.len(),
            size: format_bytes(root_meta.len()),
            last_modified: iso_from_system_time(root_meta.modified().unwrap_or_else(|_| SystemTime::now())),
            category: category_for_file(&name).to_string(),
        }]);
    }
    if !root_meta.is_dir() {
        return Err(anyhow!("共享路径不是目录"));
    }

    let mut entries = WalkDir::new(&root_full)
        .min_depth(1)
        .max_depth(max_depth + 1)
        .into_iter()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        b.file_type()
            .is_dir()
            .cmp(&a.file_type().is_dir())
            .then(a.path().cmp(b.path()))
    });

    let mut rows = Vec::new();
    for entry in entries.into_iter().take(max_items) {
        let path = entry.path();
        let metadata = entry.metadata()?;
        let relative_path = path
            .strip_prefix(&root_full)?
            .to_string_lossy()
            .replace('\\', "/");
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = metadata.is_dir();
        rows.push(PhysicalFile {
            id: encode_path_id(&relative_path),
            name: name.clone(),
            relative_path,
            file_type: if is_dir { "folder" } else { "file" }.to_string(),
            size_bytes: if is_dir { 0 } else { metadata.len() },
            size: if is_dir { "目录".to_string() } else { format_bytes(metadata.len()) },
            last_modified: iso_from_system_time(metadata.modified().unwrap_or_else(|_| SystemTime::now())),
            category: if is_dir { "folder" } else { category_for_file(&name) }.to_string(),
        });
    }
    Ok(rows)
}

async fn preview_physical_file(root: String, relative_path: Option<String>) -> Result<PreviewResult> {
    let full = safe_resolve(&root, relative_path.as_deref())?;
    let metadata = fs::metadata(&full).await?;
    if metadata.is_dir() {
        return Ok(PreviewResult {
            preview_type: "folder".to_string(),
            content: "目录不支持文本预览，请进入打包下载或选择目录内文件。".to_string(),
            truncated: None,
        });
    }
    let ext = full
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let text_like = [
        "txt", "md", "json", "xml", "html", "css", "js", "ts", "tsx", "csv", "log", "ps1",
        "sh", "py",
    ];
    if !text_like.contains(&ext.as_str()) {
        if let Some(kind) = preview_media_kind(&ext) {
            return Ok(PreviewResult {
                preview_type: kind.to_string(),
                content: String::new(),
                truncated: None,
            });
        }
        return Ok(PreviewResult {
            preview_type: "binary".to_string(),
            content: format!("此文件类型 (.{}) 不进行文本预览，可直接真实下载。", ext),
            truncated: None,
        });
    }
    let mut file = fs::File::open(&full).await?;
    let length = metadata.len().min(64 * 1024) as usize;
    let mut buffer = vec![0_u8; length];
    file.read_exact(&mut buffer).await?;
    Ok(PreviewResult {
        preview_type: "text".to_string(),
        content: String::from_utf8_lossy(&buffer).to_string(),
        truncated: Some(metadata.len() > length as u64),
    })
}

async fn hash_file(file_path: &Path) -> Result<(String, String)> {
    let mut file = fs::File::open(file_path).await?;
    let mut sha256 = Sha256::new();
    let mut md5_context = md5::Context::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        sha256.update(&buffer[..read]);
        md5_context.consume(&buffer[..read]);
    }
    Ok((hex::encode(sha256.finalize()), format!("{:x}", md5_context.compute())))
}

fn parse_range_header(range: Option<&str>, size: u64) -> Option<(u64, u64)> {
    let range = range?;
    let range = range.strip_prefix("bytes=")?;
    let (start, end) = range.split_once('-')?;
    let start = if start.is_empty() { 0 } else { start.parse::<u64>().ok()? };
    let end = if end.is_empty() {
        size.saturating_sub(1)
    } else {
        end.parse::<u64>().ok()?.min(size.saturating_sub(1))
    };
    if start > end || start >= size {
        None
    } else {
        Some((start, end))
    }
}

const MAX_UPLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn sanitize_upload_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 240
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return None;
    }
    let cleaned: String = trimmed.chars().filter(|ch| !ch.is_control()).collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn unique_upload_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let stem = Path::new(name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_string();
    let ext = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    for index in 1..1000 {
        let next = dir.join(format!("{stem} ({index}){ext}"));
        if !next.exists() {
            return next;
        }
    }
    let suffix = &Uuid::new_v4().to_string()[..8];
    dir.join(format!("{stem}-{suffix}{ext}"))
}

fn format_relative_path(root: &Path, full: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .to_string_lossy()
        .replace('\\', "/")
}

fn percent_encode_filename(name: &str) -> String {
    url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>()
}

fn collect_archive_files(root: &str, relative_paths: &[String]) -> Result<Vec<(PathBuf, String)>> {
    let root_full = Path::new(root).canonicalize()?;
    let root_is_file = std::fs::metadata(&root_full)?.is_file();
    let mut files = Vec::new();
    for relative_path in relative_paths {
        let full = safe_resolve(root, Some(relative_path))?;
        let metadata = std::fs::metadata(&full)?;
        if metadata.is_dir() {
            for entry in WalkDir::new(&full).into_iter().filter_map(Result::ok) {
                let path = entry.path();
                let metadata = entry.metadata()?;
                if !metadata.is_file() {
                    continue;
                }
                let zip_name = path
                    .strip_prefix(&root_full)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((path.to_path_buf(), zip_name));
            }
        } else {
            let zip_name = if root_is_file {
                root_full
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("file")
                    .to_string()
            } else {
                full.strip_prefix(&root_full)
                    .unwrap_or(&full)
                    .to_string_lossy()
                    .replace('\\', "/")
            };
            files.push((full, zip_name));
        }
    }
    Ok(files)
}

fn build_zip_sync(root: String, relative_paths: Vec<String>, output_path: PathBuf) -> Result<()> {
    let files = collect_archive_files(&root, &relative_paths)?;
    build_zip_from_files(files, output_path, |_| {})?;
    Ok(())
}

fn build_zip_from_files<F>(files: Vec<(PathBuf, String)>, output_path: PathBuf, mut on_progress: F) -> Result<u64>
where
    F: FnMut(u64),
{
    if files.is_empty() {
        return Err(anyhow!("没有可打包的真实文件"));
    }
    let file = StdFile::create(output_path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let mut done: u64 = 0;
    for (full_path, zip_name) in files {
        zip.start_file(zip_name, options)?;
        let mut input = StdFile::open(full_path)?;
        done += std::io::copy(&mut input, &mut zip)?;
        on_progress(done);
    }
    zip.finish()?;
    Ok(done)
}

impl Backend {
    async fn new(state_path: PathBuf, dist_dir: PathBuf) -> Result<Arc<Self>> {
        let mut app_state = match fs::read_to_string(&state_path).await {
            Ok(raw) => serde_json::from_str::<AppState>(&raw).unwrap_or_else(|_| default_app_state()),
            Err(_) => default_app_state(),
        };
        app_state.server.host_ip = normalize_host_ip(&app_state.server.host_ip);
        if app_state.security.link_secret.trim().is_empty() {
            app_state.security.link_secret = random_secret();
        }
        if app_state.server.port < 1024 {
            app_state.server.port = 8787;
        }
        let audit_path = state_path.with_file_name("audit.jsonl");
        let mut audit_log = VecDeque::new();
        if let Ok(raw) = fs::read_to_string(&audit_path).await {
            for line in raw.lines().rev().take(200) {
                if let Ok(event) = serde_json::from_str::<AuditEvent>(line) {
                    audit_log.push_front(event);
                }
            }
        }
        let server_state = ServerRuntime {
            running: false,
            host_ip: app_state.server.host_ip.clone(),
            bind_address: "0.0.0.0".to_string(),
            port: app_state.server.port,
            error: String::new(),
        };
        let backend = Arc::new(Self {
            state_path,
            audit_path,
            dist_dir,
            started_at_ms: now_ms() as u64,
            app_state: Mutex::new(app_state),
            server_state: Mutex::new(server_state),
            active_tokens: Mutex::new(HashMap::new()),
            share_leases: Mutex::new(HashMap::new()),
            active_transfers: Mutex::new(HashMap::new()),
            audit_log: Mutex::new(audit_log),
            archive_jobs: Mutex::new(HashMap::new()),
            passcode_attempts: Mutex::new(HashMap::new()),
            server_control: Mutex::new(ServerControl {
                shutdown: None,
                handle: None,
            }),
            next_transfer_id: AtomicU64::new(1),
        });
        backend.save_state().await?;
        Ok(backend)
    }

    async fn save_state(&self) -> Result<()> {
        let snapshot = self.app_state.lock().await.clone();
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&self.state_path, serde_json::to_vec_pretty(&snapshot)?).await?;
        Ok(())
    }

    async fn start_server(self: &Arc<Self>) -> Result<()> {
        self.stop_server().await;
        let runtime = self.server_state.lock().await.clone();
        let server_config = self.app_state.lock().await.server.clone();
        let listener = match std::net::TcpListener::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            runtime.port,
        )) {
            Ok(listener) => listener,
            Err(error) => {
                let mut server_state = self.server_state.lock().await;
                server_state.running = false;
                server_state.error = error.to_string();
                return Err(error.into());
            }
        };
        listener
            .set_nonblocking(true)
            .map_err(|error| anyhow!(error.to_string()))?;

        let tls_config = if server_config.tls_enabled {
            let cert_path = server_config
                .tls_cert_path
                .clone()
                .ok_or_else(|| anyhow!("TLS 已启用但缺少证书路径"))?;
            let key_path = server_config
                .tls_key_path
                .clone()
                .ok_or_else(|| anyhow!("TLS 已启用但缺少私钥路径"))?;
            Some(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?)
        } else {
            None
        };

        let router = self.router();
        let serve_handle = axum_server::Handle::new();
        let handle_for_control = serve_handle.clone();
        let server = tokio::spawn(async move {
            let result = if let Some(config) = tls_config {
                axum_server::from_tcp_rustls(listener, config)
                    .handle(serve_handle)
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            } else {
                axum_server::from_tcp(listener)
                    .handle(serve_handle)
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            };
            if let Err(error) = result {
                eprintln!("HTTP 服务运行错误：{error}");
            }
        });
        {
            let mut control = self.server_control.lock().await;
            control.shutdown = Some(handle_for_control);
            control.handle = Some(server);
        }
        {
            let mut server_state = self.server_state.lock().await;
            server_state.running = true;
            server_state.error.clear();
        }
        Ok(())
    }

    async fn stop_server(&self) {
        let (shutdown, handle) = {
            let mut control = self.server_control.lock().await;
            (control.shutdown.take(), control.handle.take())
        };
        if let Some(shutdown) = shutdown {
            shutdown.shutdown();
        }
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        self.server_state.lock().await.running = false;
    }

    fn router(self: &Arc<Self>) -> Router {
        let index = self.dist_dir.join("index.html");
        Router::new()
            .route("/api/server-state", get(api_server_state))
            .route("/api/health", get(api_health))
            .route("/api/public-share", get(api_public_share))
            .route("/api/auth", post(api_auth))
            .route("/api/heartbeat", post(api_heartbeat))
            .route("/api/files", get(api_files))
            .route("/api/preview", get(api_preview))
            .route("/api/preview-media", get(api_preview_media))
            .route("/api/upload", post(api_upload))
            .route("/api/upload-chunk", put(api_upload_chunk))
            .route("/api/upload-chunk/status", get(api_upload_chunk_status))
            .route("/api/receive-dirs", get(api_receive_dirs))
            .route("/api/hash", get(api_hash))
            .route("/api/download", get(api_download))
            .route("/api/archive", get(api_archive))
            .route("/api/archive/start", post(api_archive_start))
            .route("/api/archive/progress", get(api_archive_progress))
            .route("/api/archive/download", get(api_archive_download))
            .fallback_service(ServeDir::new(&self.dist_dir).fallback(ServeFile::new(index)))
            .with_state(self.clone())
    }

    async fn find_share_from_access(
        &self,
        share_name: Option<&str>,
        token: Option<&str>,
    ) -> Option<ShareRecordInternal> {
        let state = self.app_state.lock().await.clone();
        if let Some(token) = token.filter(|value| !value.trim().is_empty()) {
            let share_id = share_id_from_encrypted_link_token(&state.security.link_secret, token)?;
            return state.shares.into_iter().find(|share| share.id == share_id);
        }
        let clean = share_name.unwrap_or_default().to_ascii_lowercase();
        state
            .shares
            .into_iter()
            .find(|share| share.name.to_ascii_lowercase() == clean)
    }

    async fn prune_expired_activity(&self) {
        let now = now_ms();
        self.active_tokens
            .lock()
            .await
            .retain(|_, record| record.expires_at > now);
        self.share_leases
            .lock()
            .await
            .retain(|_, lease| lease.expires_at > now);
    }

    async fn ensure_lease(&self, share: &ShareRecordInternal, token_record: &AuthTokenRecord) -> bool {
        if normalize_access_mode(Some(&share.access_mode)) == "multi" {
            return true;
        }
        let mut leases = self.share_leases.lock().await;
        let now = now_ms();
        match leases.get(&share.id) {
            Some(existing) if existing.expires_at > now && existing.token != token_record.token => false,
            _ => {
                leases.insert(
                    share.id.clone(),
                    LeaseRecord {
                        token: token_record.token.clone(),
                        client_ip: token_record.client_ip.clone(),
                        expires_at: now + 45_000,
                    },
                );
                true
            }
        }
    }

    async fn get_server_state(&self) -> ServerStateResponse {
        self.prune_expired_activity().await;
        let runtime = self.server_state.lock().await.clone();
        let app_config = self.app_state.lock().await.server.clone();
        let scheme = if app_config.tls_enabled { "https" } else { "http" };
        let host_ip = normalize_host_ip(&runtime.host_ip);
        let leases = self
            .share_leases
            .lock()
            .await
            .iter()
            .filter(|(_, lease)| lease.expires_at > now_ms())
            .map(|(share_id, lease)| ServerLease {
                share_id: share_id.clone(),
                client_ip: lease.client_ip.clone(),
                expires_at: iso_from_ms(lease.expires_at),
            })
            .collect::<Vec<_>>();
        let transfers = self
            .active_transfers
            .lock()
            .await
            .values()
            .map(|transfer| ServerTransfer {
                id: transfer.id,
                transfer_type: transfer.transfer_type.clone(),
                share_id: transfer.share_id.clone(),
                share_name: transfer.share_name.clone(),
                client_ip: transfer.client_ip.clone(),
                file_name: transfer.file_name.clone(),
                size_bytes: transfer.size_bytes,
                started_at: iso_from_ms(transfer.started_at),
            })
            .collect::<Vec<_>>();
        ServerStateResponse {
            running: runtime.running,
            host_ip: host_ip.clone(),
            bind_address: runtime.bind_address,
            port: runtime.port,
            download_speed_limit_mbps: app_config.download_speed_limit_mbps,
            tls_enabled: app_config.tls_enabled,
            tls_cert_path: app_config.tls_cert_path.clone(),
            tls_key_path: app_config.tls_key_path.clone(),
            error: runtime.error,
            url_base: format!("{scheme}://{}:{}", host_ip, runtime.port),
            access_urls: access_urls_for_port(scheme, runtime.port, &host_ip),
            runtime_idle_guard: RuntimeIdleGuard {
                guard_type: "prevent-display-sleep".to_string(),
                active: false,
                blocker_id: None,
                note: "当前版本不启用系统防锁屏；系统手动锁屏仍由操作系统控制。".to_string(),
            },
            active_leases: leases,
            active_transfers: transfers,
        }
    }

    async fn begin_transfer(
        &self,
        transfer_type: &str,
        share: &ShareRecordInternal,
        token_record: &AuthTokenRecord,
        file_name: String,
        size_bytes: u64,
    ) -> u64 {
        let id = self.next_transfer_id.fetch_add(1, Ordering::SeqCst);
        self.active_transfers.lock().await.insert(
            id,
            ActiveTransfer {
                id,
                transfer_type: transfer_type.to_string(),
                share_id: share.id.clone(),
                share_name: share.name.clone(),
                client_ip: token_record.client_ip.clone(),
                file_name,
                size_bytes,
                started_at: now_ms(),
            },
        );
        id
    }

    async fn end_transfer(&self, id: u64) {
        self.active_transfers.lock().await.remove(&id);
    }

    async fn record_audit(&self, event: AuditEvent) {
        {
            let mut log = self.audit_log.lock().await;
            log.push_back(event.clone());
            if log.len() > 1000 {
                log.pop_front();
            }
        }
        if let Ok(metadata) = tokio::fs::metadata(&self.audit_path).await {
            if metadata.len() > 10 * 1024 * 1024 {
                let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                let archive = self.audit_path.with_file_name(format!("audit-{stamp}.jsonl"));
                let _ = tokio::fs::rename(&self.audit_path, &archive).await;
                if let Some(parent) = self.audit_path.parent() {
                    let mut files: Vec<PathBuf> = Vec::new();
                    if let Ok(mut entries) = tokio::fs::read_dir(parent).await {
                        while let Ok(Some(entry)) = entries.next_entry().await {
                            let name = entry.file_name().to_string_lossy().to_string();
                            if name.starts_with("audit-") && name.ends_with(".jsonl") {
                                files.push(entry.path());
                            }
                        }
                    }
                    files.sort();
                    while files.len() > 5 {
                        if let Some(oldest) = files.first() {
                            let _ = tokio::fs::remove_file(oldest).await;
                            files.remove(0);
                        }
                    }
                }
            }
        }
        let line = serde_json::to_string(&event).unwrap_or_default();
        if let Ok(mut file) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)
            .await
        {
            let _ = file.write_all(format!("{line}\n").as_bytes()).await;
        }
    }

    async fn effective_speed_limit(&self, share: &ShareRecordInternal) -> u64 {
        let global = self.app_state.lock().await.server.download_speed_limit_mbps;
        share.speed_limit_mbps.unwrap_or(global).saturating_mul(1024 * 1024)
    }
}

async fn require_auth(
    backend: &Arc<Backend>,
    headers: &HeaderMap,
    client_addr: SocketAddr,
    query_token: Option<&str>,
) -> Result<(AuthTokenRecord, ShareRecordInternal), ApiError> {
    backend.prune_expired_activity().await;
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let token = auth_header
        .strip_prefix("Bearer ")
        .map(str::to_string)
        .or_else(|| query_token.map(str::to_string))
        .unwrap_or_default();
    let record = backend
        .active_tokens
        .lock()
        .await
        .get(&token)
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "登录已过期，请重新验证口令"))?;
    let client_ip = client_addr.ip().to_string().trim_start_matches("::ffff:").to_string();
    if record.client_ip != client_ip || record.user_agent_hash != request_user_agent_hash(headers) {
        backend.active_tokens.lock().await.remove(&token);
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "会话已被设备指纹保护拒绝，请在原认证电脑上重新验证口令",
        ));
    }
    let share = {
        let state = backend.app_state.lock().await;
        state.shares.iter().find(|share| share.id == record.share_id).cloned()
    }
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "共享不存在或已被撤销"))?;

    if is_mobile_user_agent(headers) && !share.allow_mobile_access {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "移动/平板终端未被此共享开关允许访问",
        ));
    }
    if !ip_in_whitelist(&client_ip, &share.ip_whitelist) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "当前客户端 IP 不在白名单内"));
    }
    if !backend.ensure_lease(&share, &record).await {
        return Err(ApiError::new(
            StatusCode::LOCKED,
            "该共享正在被另一台客户端独占访问",
        ));
    }
    Ok((record, share))
}

async fn api_server_state(AxumState(backend): AxumState<Arc<Backend>>) -> Json<ServerStateResponse> {
    Json(backend.get_server_state().await)
}

async fn api_health(AxumState(backend): AxumState<Arc<Backend>>) -> Json<HealthResponse> {
    let state = backend.get_server_state().await;
    Json(HealthResponse {
        ok: state.running,
        version: env!("CARGO_PKG_VERSION").to_string(),
        port: state.port,
        running: state.running,
        uptime_ms: now_ms().saturating_sub(backend.started_at_ms as i64) as u64,
        audit_events: backend.audit_log.lock().await.len(),
        active_transfers: state.active_transfers.len(),
    })
}

async fn api_public_share(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AccessQuery>,
) -> Result<Json<PublicShareResponse>, ApiError> {
    let share = backend
        .find_share_from_access(query.share.as_deref(), query.token.as_deref())
        .await
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "共享不存在或已被撤销"))?;
    let client_ip = addr.ip().to_string().trim_start_matches("::ffff:").to_string();
    let occupied = if normalize_access_mode(Some(&share.access_mode)) == "multi" {
        false
    } else {
        backend
            .share_leases
            .lock()
            .await
            .get(&share.id)
            .map(|lease| lease.expires_at > now_ms())
            .unwrap_or(false)
    };
    Ok(Json(PublicShareResponse {
        share: public_share(&share),
        client_ip: client_ip.clone(),
        ip_allowed: ip_in_whitelist(&client_ip, &share.ip_whitelist),
        mobile_blocked: is_mobile_user_agent(&headers) && !share.allow_mobile_access,
        passcode_expired: is_passcode_expired(&share),
        occupied,
    }))
}

async fn api_auth(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthResponse>, ApiError> {
    let share = backend
        .find_share_from_access(payload.share.as_deref(), payload.token.as_deref())
        .await
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "共享不存在或已被撤销"))?;
    let client_ip = addr.ip().to_string().trim_start_matches("::ffff:").to_string();
    let now_ms_value = now_ms();
    if is_mobile_user_agent(&headers) && !share.allow_mobile_access {
        backend
            .record_audit(audit_event("auth_blocked", &share.name, &client_ip, "", 0, "blocked", "移动/平板终端未被允许访问"))
            .await;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "移动/平板终端未被此共享开关允许访问",
        ));
    }
    if !ip_in_whitelist(&client_ip, &share.ip_whitelist) {
        backend
            .record_audit(audit_event("auth_blocked", &share.name, &client_ip, "", 0, "blocked", "客户端 IP 不在白名单"))
            .await;
        return Err(ApiError::new(StatusCode::FORBIDDEN, "当前客户端 IP 不在白名单内"));
    }
    if is_passcode_expired(&share) {
        backend
            .record_audit(audit_event("auth_blocked", &share.name, &client_ip, "", 0, "blocked", "访问口令已过期"))
            .await;
        return Err(ApiError::new(StatusCode::FORBIDDEN, "访问口令已过期"));
    }
    let locked_until = backend
        .passcode_attempts
        .lock()
        .await
        .get(&share.id)
        .map(|(_, until)| *until)
        .unwrap_or(0);
    if locked_until > now_ms_value {
        let remaining_minutes = (locked_until - now_ms_value) / 60_000 + 1;
        backend
            .record_audit(audit_event(
                "auth_blocked",
                &share.name,
                &client_ip,
                "",
                0,
                "blocked",
                &format!("口令错误次数过多，已锁定 {remaining_minutes} 分钟"),
            ))
            .await;
        return Err(ApiError::new(
            StatusCode::LOCKED,
            format!("口令错误次数过多，已锁定 {remaining_minutes} 分钟"),
        ));
    }
    if !verify_passcode(payload.passcode.as_deref().unwrap_or_default(), &share.passcode_hash) {
        let detail = {
            let mut attempts = backend.passcode_attempts.lock().await;
            let entry = attempts.entry(share.id.clone()).or_insert((0, 0));
            entry.0 += 1;
            if entry.0 >= 5 {
                entry.1 = now_ms_value + 5 * 60 * 1000;
                entry.0 = 0;
            }
            if entry.1 > now_ms_value {
                "口令错误 5 次，已锁定 5 分钟".to_string()
            } else {
                format!("口令错误，剩余 {} 次机会", 5 - entry.0)
            }
        };
        backend
            .record_audit(audit_event("auth_failed", &share.name, &client_ip, "", 0, "fail", &detail))
            .await;
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "访问口令错误"));
    }
    if normalize_access_mode(Some(&share.access_mode)) != "multi" {
        let occupied = backend
            .share_leases
            .lock()
            .await
            .get(&share.id)
            .map(|lease| lease.expires_at > now_ms())
            .unwrap_or(false);
        if occupied {
            backend
                .record_audit(audit_event("auth_blocked", &share.name, &client_ip, "", 0, "blocked", "共享被其他客户端独占"))
                .await;
            return Err(ApiError::new(
                StatusCode::LOCKED,
                "该共享正在被另一台客户端独占访问",
            ));
        }
    }

    let token = random_token();
    let expires_at = parse_expiry_ms(&share.passcode_expires_at)
        .unwrap_or_else(|| now_ms() + 4 * 60 * 60 * 1000)
        .min(now_ms() + 4 * 60 * 60 * 1000);
    let record = AuthTokenRecord {
        token: token.clone(),
        share_id: share.id.clone(),
        client_ip: client_ip.clone(),
        user_agent_hash: request_user_agent_hash(&headers),
        expires_at,
    };
    backend.active_tokens.lock().await.insert(token.clone(), record.clone());
    backend.ensure_lease(&share, &record).await;
    backend.passcode_attempts.lock().await.remove(&share.id);
    if share.one_time_access {
        {
            let mut state = backend.app_state.lock().await;
            if let Some(stored) = state.shares.iter_mut().find(|item| item.id == share.id) {
                stored.passcode_expires_at = Some(iso_now());
            }
        }
        let _ = backend.save_state().await;
    }
    backend
        .record_audit(audit_event("auth_success", &share.name, &client_ip, "", 0, "ok", "口令认证通过，会话已建立"))
        .await;
    let files = list_physical_files(share.local_path.clone())
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(AuthResponse {
        token,
        expires_at,
        client_ip,
        share: public_share(&share),
        files,
    }))
}

async fn api_heartbeat(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let (record, share) = require_auth(&backend, &headers, addr, None).await?;
    backend.ensure_lease(&share, &record).await;
    Ok(Json(HeartbeatResponse {
        ok: true,
        expires_at: record.expires_at,
        share: public_share(&share),
    }))
}

async fn api_files(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<FilesResponse>, ApiError> {
    let (_record, share) = require_auth(&backend, &headers, addr, None).await?;
    let files = list_physical_files(share.local_path.clone())
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(FilesResponse { files }))
}

async fn api_preview(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<PathQuery>,
) -> Result<Json<PreviewResult>, ApiError> {
    let (_record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    let result = preview_physical_file(share.local_path.clone(), query.path)
        .await
        .map_err(api_error_from_path_result)?;
    Ok(Json(result))
}

async fn api_hash(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<PathQuery>,
) -> Result<Json<HashResult>, ApiError> {
    let (_record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    let full = safe_resolve(&share.local_path, query.path.as_deref()).map_err(ApiError::bad_request)?;
    let metadata = fs::metadata(&full).await.map_err(ApiError::internal)?;
    if metadata.is_dir() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "目录请使用 ZIP 打包下载"));
    }
    let (sha256, md5) = hash_file(&full).await.map_err(ApiError::internal)?;
    let file_name = full
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file")
        .to_string();
    Ok(Json(HashResult {
        file_name,
        size_bytes: metadata.len(),
        sha256,
        md5,
    }))
}

async fn api_download(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<PathQuery>,
) -> Result<Response, ApiError> {
    let (record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    let full = match safe_resolve(&share.local_path, query.path.as_deref()) {
        Ok(full) => full,
        Err(error) => {
            backend
                .record_audit(audit_event(
                    "path_blocked",
                    &share.name,
                    &record.client_ip,
                    query.path.as_deref().unwrap_or(""),
                    0,
                    "blocked",
                    "路径穿越/非法路径被拦截",
                ))
                .await;
            return Err(ApiError::bad_request(error));
        }
    };
    let metadata = fs::metadata(&full).await.map_err(ApiError::internal)?;
    if metadata.is_dir() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "目录请使用 ZIP 打包下载"));
    }
    let file_name = full
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file")
        .to_string();
    let transfer_id = backend
        .begin_transfer("download", &share, &record, file_name.clone(), metadata.len())
        .await;
    let (sha256, md5) = match hash_file(&full).await {
        Ok(value) => value,
        Err(error) => {
            backend.end_transfer(transfer_id).await;
            return Err(ApiError::internal(error));
        }
    };
    backend.end_transfer(transfer_id).await;
    let has_range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.starts_with("bytes="))
        .unwrap_or(false);
    backend
        .record_audit(audit_event(
            "download",
            &share.name,
            &record.client_ip,
            &file_name,
            metadata.len(),
            "ok",
            if has_range {
                "并发分块 Range 请求"
            } else {
                "SHA-256 已计算并开始下发"
            },
        ))
        .await;

    let range_header = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let speed_bytes_per_sec = backend.effective_speed_limit(&share).await;
    let mut response = stream_file_response(&full, &file_name, "application/octet-stream", false, range_header, speed_bytes_per_sec).await?;
    response
        .headers_mut()
        .insert("X-Content-SHA256", sha256.parse().expect("header value"));
    response
        .headers_mut()
        .insert("X-Content-MD5", md5.parse().expect("header value"));
    Ok(response)
}

async fn stream_file_response(
    full: &Path,
    file_name: &str,
    content_type: &str,
    inline: bool,
    range_header: Option<&str>,
    bytes_per_sec: u64,
) -> Result<Response, ApiError> {
    let size = fs::metadata(full).await.map_err(ApiError::internal)?.len();
    let range = parse_range_header(range_header, size);
    let mut file = fs::File::open(full).await.map_err(ApiError::internal)?;
    let disposition = if inline { "inline" } else { "attachment" };
    let mut builder = Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("{disposition}; filename*=UTF-8''{}", percent_encode_filename(file_name)),
        );
    let body = if let Some((start, end)) = range {
        file.seek(SeekFrom::Start(start)).await.map_err(ApiError::internal)?;
        let length = end - start + 1;
        builder = builder
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, end, size))
            .header(header::CONTENT_LENGTH, length.to_string());
        Body::from_stream(throttle_stream(ReaderStream::new(file.take(length)), bytes_per_sec))
    } else {
        builder = builder.header(header::CONTENT_LENGTH, size.to_string());
        Body::from_stream(throttle_stream(ReaderStream::new(file), bytes_per_sec))
    };
    builder.body(body).map_err(ApiError::internal)
}

fn throttle_stream<S, E>(stream: S, bytes_per_sec: u64) -> impl futures_util::Stream<Item = Result<Bytes, E>>
where
    S: futures_util::Stream<Item = Result<Bytes, E>> + Unpin + Send + 'static,
    E: Send + 'static,
{
    stream.then(move |item| async move {
        if bytes_per_sec > 0 {
            if let Ok(bytes) = &item {
                if !bytes.is_empty() {
                    let seconds = bytes.len() as f64 / bytes_per_sec as f64;
                    tokio::time::sleep(Duration::from_secs_f64(seconds)).await;
                }
            }
        }
        item
    })
}

async fn api_preview_media(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<MediaQuery>,
) -> Result<Response, ApiError> {
    let (record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    let full = match safe_resolve(&share.local_path, Some(&query.path)) {
        Ok(full) => full,
        Err(error) => {
            backend
                .record_audit(audit_event("path_blocked", &share.name, &record.client_ip, &query.path, 0, "blocked", "媒体预览路径穿越/非法路径被拦截"))
                .await;
            return Err(ApiError::bad_request(error));
        }
    };
    let metadata = fs::metadata(&full).await.map_err(ApiError::internal)?;
    if metadata.is_dir() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "目录不支持媒体预览"));
    }
    let file_name = full
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file")
        .to_string();
    let content_type = mime_guess::from_path(&full).first_or_octet_stream().to_string();
    let range_header = headers.get(header::RANGE).and_then(|value| value.to_str().ok());
    let speed_bytes_per_sec = backend.effective_speed_limit(&share).await;
    stream_file_response(&full, &file_name, &content_type, true, range_header, speed_bytes_per_sec).await
}

async fn api_upload(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<UploadQuery>,
    body: Body,
) -> Result<Json<UploadReceipt>, ApiError> {
    let (record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    if !share.allow_upload {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "该共享未开放上传"));
    }
    let receive_dir = share
        .receive_dir
        .clone()
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "上传接收目录未配置"))?;
    let target_dir_root = Path::new(&receive_dir)
        .canonicalize()
        .map_err(ApiError::internal)?;
    let target_dir = match resolve_upload_dir(&receive_dir, query.path.as_deref()).await {
        Ok(dir) => dir,
        Err(error) => {
            backend
                .record_audit(audit_event("path_blocked", &share.name, &record.client_ip, &query.name, 0, "blocked", "上传路径穿越/非法路径被拦截"))
                .await;
            return Err(error);
        }
    };
    let target_meta = fs::metadata(&target_dir).await.map_err(ApiError::internal)?;
    if !target_meta.is_dir() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "上传目标必须是目录"));
    }
    let file_name = sanitize_upload_name(&query.name)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "文件名无效"))?;
    let effective_max = share.upload_max_bytes.unwrap_or(MAX_UPLOAD_BYTES);
    if let Some(extensions) = &share.upload_extensions {
        let allowed: Vec<&str> = extensions.split(',').collect();
        let ext = Path::new(&file_name)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !allowed.contains(&ext.as_str()) {
            backend
                .record_audit(audit_event("upload", &share.name, &record.client_ip, &file_name, 0, "blocked", &format!("扩展名 .{ext} 不在白名单")))
                .await;
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("不允许上传 .{ext} 类型文件"),
            ));
        }
    }
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        if length > effective_max {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("文件超过 {} 上传上限", format_bytes(effective_max)),
            ));
        }
    }

    let final_path = unique_upload_path(&target_dir, &file_name);
    let temp_path = target_dir.join(format!(".upload-{}.part", Uuid::new_v4()));
    let transfer_id = backend
        .begin_transfer("upload", &share, &record, file_name.clone(), 0)
        .await;
    let speed_bytes_per_sec = backend.effective_speed_limit(&share).await;

    let result = async {
        let mut file = fs::File::create(&temp_path).await?;
        let mut sha = Sha256::new();
        let mut md5_context = md5::Context::new();
        let mut written: u64 = 0;
        let stream = throttle_stream(body.into_data_stream(), speed_bytes_per_sec);
        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|error| anyhow!("读取上传数据失败：{error}"))?;
            written += bytes.len() as u64;
            if written > effective_max {
                return Err(anyhow!("文件超过 {} 上传上限", format_bytes(effective_max)));
            }
            sha.update(&bytes);
            md5_context.consume(&bytes);
            file.write_all(&bytes).await?;
        }
        file.flush().await?;
        drop(file);
        fs::rename(&temp_path, &final_path).await?;
        let saved_name = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(&file_name)
            .to_string();
        Ok::<_, anyhow::Error>(UploadReceipt {
            name: saved_name,
            relative_path: format_relative_path(&target_dir_root, &final_path),
            size_bytes: written,
            sha256: hex::encode(sha.finalize()),
            md5: format!("{:x}", md5_context.compute()),
        })
    }
    .await;

    backend.end_transfer(transfer_id).await;
    match result {
        Ok(receipt) => {
            backend
                .record_audit(audit_event(
                    "upload",
                    &share.name,
                    &record.client_ip,
                    &receipt.name,
                    receipt.size_bytes,
                    "ok",
                    &format!("SHA-256 {}", &receipt.sha256[..receipt.sha256.len().min(12)]),
                ))
                .await;
            Ok(Json(receipt))
        }
        Err(error) => {
            let _ = fs::remove_file(&temp_path).await;
            backend
                .record_audit(audit_event("upload", &share.name, &record.client_ip, &file_name, 0, "fail", &error.to_string()))
                .await;
            Err(ApiError::internal(error))
        }
    }
}

async fn resolve_upload_dir(root: &str, relative: Option<&str>) -> Result<PathBuf, ApiError> {
    let root_full = Path::new(root)
        .canonicalize()
        .map_err(|error| ApiError::internal(anyhow!("上传接收目录不可用：{error}")))?;
    let mut current = root_full.clone();
    if let Some(relative) = relative.map(str::trim).filter(|value| !value.is_empty()) {
        for component in Path::new(relative).components() {
            match component {
                Component::Normal(part) => current = current.join(part),
                _ => {
                    return Err(ApiError::new(StatusCode::BAD_REQUEST, "非法路径：上传目标包含非法路径段"));
                }
            }
        }
        tokio::fs::create_dir_all(&current).await.map_err(ApiError::internal)?;
    }
    let canonical = current.canonicalize().map_err(ApiError::internal)?;
    if !canonical.starts_with(&root_full) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "非法路径：上传目标不在接收目录内"));
    }
    Ok(canonical)
}

async fn cleanup_stale_parts(dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    let cutoff = now_ms() - 24 * 60 * 60 * 1000;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(".upload-") && name.ends_with(".part") {
            if let Ok(metadata) = entry.metadata().await {
                if let Ok(modified) = metadata.modified() {
                    let age = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_millis() as i64)
                        .unwrap_or(0);
                    if age < cutoff {
                        let _ = tokio::fs::remove_file(entry.path()).await;
                    }
                }
            }
        }
    }
}

async fn api_upload_chunk(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<UploadChunkQuery>,
    body: Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    if !share.allow_upload {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "该共享未开放上传"));
    }
    let receive_dir = share
        .receive_dir
        .clone()
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "上传接收目录未配置"))?;
    let target_dir_root = Path::new(&receive_dir)
        .canonicalize()
        .map_err(ApiError::internal)?;
    let target_dir = match resolve_upload_dir(&receive_dir, query.path.as_deref()).await {
        Ok(dir) => dir,
        Err(error) => {
            backend
                .record_audit(audit_event("path_blocked", &share.name, &record.client_ip, &query.name, 0, "blocked", "上传分片路径穿越/非法路径被拦截"))
                .await;
            return Err(error);
        }
    };
    let file_name = sanitize_upload_name(&query.name)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "文件名无效"))?;
    let effective_max = share.upload_max_bytes.unwrap_or(MAX_UPLOAD_BYTES);
    cleanup_stale_parts(&target_dir).await;
    let part_path = target_dir.join(format!(".upload-{}.part", query.upload_id));
    let current_len = match tokio::fs::metadata(&part_path).await {
        Ok(metadata) => metadata.len(),
        Err(_) => 0,
    };
    if query.offset != current_len {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("分片偏移不连续：期望 {current_len}，收到 {}", query.offset),
        ));
    }
    if query.offset > effective_max {
        let _ = tokio::fs::remove_file(&part_path).await;
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("文件超过 {} 上传上限", format_bytes(effective_max)),
        ));
    }

    let speed_bytes_per_sec = backend.effective_speed_limit(&share).await;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&part_path)
        .await
        .map_err(ApiError::internal)?;
    let mut written: u64 = query.offset;
    let stream = throttle_stream(body.into_data_stream(), speed_bytes_per_sec);
    tokio::pin!(stream);
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|error| ApiError::internal(anyhow!("读取上传分片失败：{error}")))?;
        written += bytes.len() as u64;
        if written > effective_max {
            drop(file);
            let _ = tokio::fs::remove_file(&part_path).await;
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("文件超过 {} 上传上限", format_bytes(effective_max)),
            ));
        }
        file.write_all(&bytes).await.map_err(ApiError::internal)?;
    }
    file.flush().await.map_err(ApiError::internal)?;
    drop(file);

    if !query.final_chunk {
        return Ok(Json(serde_json::json!({ "received": written })));
    }

    let final_path = unique_upload_path(&target_dir, &file_name);
    tokio::fs::rename(&part_path, &final_path)
        .await
        .map_err(ApiError::internal)?;
    let (sha256, md5) = hash_file(&final_path).await.map_err(ApiError::internal)?;
    let saved_name = final_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(&file_name)
        .to_string();
    let receipt = UploadReceipt {
        name: saved_name,
        relative_path: format_relative_path(&target_dir_root, &final_path),
        size_bytes: written,
        sha256,
        md5,
    };
    backend
        .record_audit(audit_event(
            "upload",
            &share.name,
            &record.client_ip,
            &receipt.name,
            receipt.size_bytes,
            "ok",
            &format!("分片上传完成 SHA-256 {}", &receipt.sha256[..receipt.sha256.len().min(12)]),
        ))
        .await;
    Ok(Json(serde_json::to_value(&receipt).map_err(ApiError::internal)?))
}

async fn api_upload_chunk_status(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<UploadChunkStatusQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (_record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    if !share.allow_upload {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "该共享未开放上传"));
    }
    let receive_dir = share
        .receive_dir
        .clone()
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "上传接收目录未配置"))?;
    let target_dir = resolve_upload_dir(&receive_dir, query.path.as_deref()).await?;
    let part_path = target_dir.join(format!(".upload-{}.part", query.upload_id));
    let offset = match tokio::fs::metadata(&part_path).await {
        Ok(metadata) => metadata.len(),
        Err(_) => 0,
    };
    Ok(Json(serde_json::json!({ "uploadId": query.upload_id, "offset": offset })))
}

async fn api_receive_dirs(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ReceiveDirsQuery>,
) -> Result<Json<Vec<String>>, ApiError> {
    let (_record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    if !share.allow_upload {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "该共享未开放上传"));
    }
    let receive_dir = share
        .receive_dir
        .clone()
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "上传接收目录未配置"))?;
    let root = Path::new(&receive_dir)
        .canonicalize()
        .map_err(ApiError::internal)?;
    let mut dirs = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(&root).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                if metadata.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        dirs.push(name.to_string());
                    }
                }
            }
        }
    }
    dirs.sort();
    Ok(Json(dirs))
}

async fn prune_archive_jobs(backend: &Arc<Backend>) {
    let now = now_ms();
    let stale: Vec<String> = {
        let jobs = backend.archive_jobs.lock().await;
        jobs.iter()
            .filter(|(_, job)| {
                let created = job.try_lock().map(|guard| guard.created_at).unwrap_or(0);
                now.saturating_sub(created) > 15 * 60 * 1000
            })
            .map(|(id, _)| id.clone())
            .collect()
    };
    for id in stale {
        if let Some(job) = backend.archive_jobs.lock().await.remove(&id) {
            if let Ok(guard) = job.try_lock() {
                let _ = tokio::fs::remove_file(&guard.temp_path).await;
            }
        }
    }
}

async fn api_archive_start(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ArchiveStartQuery>,
    Json(payload): Json<ArchiveStartPayload>,
) -> Result<Json<ArchiveJobResponse>, ApiError> {
    let (record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    prune_archive_jobs(&backend).await;
    if payload.paths.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "未选择任何文件"));
    }
    let root = share.local_path.clone();
    let paths = payload.paths.clone();
    let files = tokio::task::spawn_blocking(move || collect_archive_files(&root, &paths))
        .await
        .map_err(ApiError::internal)?
        .map_err(api_error_from_path_result)?;
    if files.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "没有可打包的真实文件"));
    }
    let total_bytes: u64 = files
        .iter()
        .map(|(path, _)| std::fs::metadata(path).map(|metadata| metadata.len()).unwrap_or(0))
        .sum();
    let job_id = Uuid::new_v4().to_string();
    let temp_path = std::env::temp_dir().join(format!("lan-transfer-{}.zip", Uuid::new_v4()));
    let job = Arc::new(tokio::sync::Mutex::new(ArchiveJob {
        share_name: share.name.clone(),
        temp_path: temp_path.clone(),
        total_bytes,
        done_bytes: 0,
        status: "building".to_string(),
        size_bytes: 0,
        sha256: String::new(),
        md5: String::new(),
        error: String::new(),
        created_at: now_ms(),
    }));
    backend.archive_jobs.lock().await.insert(job_id.clone(), job.clone());

    let transfer_id = backend
        .begin_transfer("archive", &share, &record, format!("{}.zip", share.name), total_bytes)
        .await;
    let job_for_task = job.clone();
    let job_inner = job_for_task.clone();
    let backend_for_task = backend.clone();
    tokio::task::spawn(async move {
        let build_result = tokio::task::spawn_blocking(move || {
            let result = build_zip_from_files(files, temp_path.clone(), |progress| {
                if let Ok(mut guard) = job_inner.try_lock() {
                    guard.done_bytes = progress;
                }
            });
            (result, temp_path)
        })
        .await;
        match build_result {
            Ok((Ok(done), temp_path)) => {
                let (sha256, md5) = hash_file(&temp_path).await.unwrap_or_default();
                let mut guard = job_for_task.lock().await;
                guard.status = "ready".to_string();
                guard.size_bytes = done;
                guard.sha256 = sha256;
                guard.md5 = md5;
            }
            Ok((Err(error), _)) => {
                let mut guard = job_for_task.lock().await;
                guard.status = "error".to_string();
                guard.error = error.to_string();
            }
            Err(error) => {
                let mut guard = job_for_task.lock().await;
                guard.status = "error".to_string();
                guard.error = format!("打包任务失败：{error}");
            }
        }
        backend_for_task.end_transfer(transfer_id).await;
    });

    let guard = job.lock().await;
    Ok(Json(ArchiveJobResponse {
        job_id: job_id.clone(),
        share_name: guard.share_name.clone(),
        status: guard.status.clone(),
        total_bytes: guard.total_bytes,
        done_bytes: guard.done_bytes,
        size_bytes: guard.size_bytes,
        sha256: guard.sha256.clone(),
        md5: guard.md5.clone(),
        error: guard.error.clone(),
    }))
}

async fn api_archive_progress(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ArchiveJobQuery>,
) -> Result<Json<ArchiveJobResponse>, ApiError> {
    let (_record, _share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    prune_archive_jobs(&backend).await;
    let job = backend
        .archive_jobs
        .lock()
        .await
        .get(&query.job_id)
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "打包任务不存在或已过期"))?;
    let guard = job.lock().await;
    Ok(Json(ArchiveJobResponse {
        job_id: query.job_id,
        share_name: guard.share_name.clone(),
        status: guard.status.clone(),
        total_bytes: guard.total_bytes,
        done_bytes: guard.done_bytes,
        size_bytes: guard.size_bytes,
        sha256: guard.sha256.clone(),
        md5: guard.md5.clone(),
        error: guard.error.clone(),
    }))
}

async fn api_archive_download(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ArchiveJobQuery>,
) -> Result<Response, ApiError> {
    let (record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    prune_archive_jobs(&backend).await;
    let job = backend
        .archive_jobs
        .lock()
        .await
        .get(&query.job_id)
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "打包任务不存在或已过期"))?;
    let guard = job.lock().await;
    if guard.status == "building" {
        return Err(ApiError::new(StatusCode::CONFLICT, "打包尚未完成，请稍后重试"));
    }
    if guard.status == "error" {
        return Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, guard.error.clone()));
    }
    let temp_path = guard.temp_path.clone();
    let sha256 = guard.sha256.clone();
    let md5 = guard.md5.clone();
    let size = guard.size_bytes;
    drop(guard);

    let file_name = format!("{}.zip", share.name);
    let speed_bytes_per_sec = backend.effective_speed_limit(&share).await;
    let mut response = stream_file_response(&temp_path, &file_name, "application/zip", false, None, speed_bytes_per_sec).await?;
    response
        .headers_mut()
        .insert("X-Content-SHA256", sha256.parse().expect("header value"));
    response
        .headers_mut()
        .insert("X-Content-MD5", md5.parse().expect("header value"));

    let backend_for_cleanup = backend.clone();
    let job_id_for_cleanup = query.job_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(600)).await;
        if let Some(job) = backend_for_cleanup.archive_jobs.lock().await.remove(&job_id_for_cleanup) {
            if let Ok(guard) = job.try_lock() {
                let _ = tokio::fs::remove_file(&guard.temp_path).await;
            }
        }
    });
    backend
        .record_audit(audit_event("archive", &share.name, &record.client_ip, &file_name, size, "ok", "ZIP 打包完成并开始下发"))
        .await;
    Ok(response)
}

async fn api_archive(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ArchiveQuery>,
) -> Result<Response, ApiError> {
    let (record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    if query.path.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "未选择任何文件"));
    }
    let transfer_id = backend
        .begin_transfer("archive", &share, &record, format!("{}.zip", share.name), 0)
        .await;
    let temp_path = std::env::temp_dir().join(format!("lan-transfer-{}.zip", Uuid::new_v4()));
    let root = share.local_path.clone();
    let paths = query.path.clone();
    let output = temp_path.clone();
    let build_result = tokio::task::spawn_blocking(move || build_zip_sync(root, paths, output))
        .await
        .map_err(ApiError::internal)
        .and_then(|result| result.map_err(api_error_from_path_result));
    if let Err(error) = build_result {
        backend.end_transfer(transfer_id).await;
        if error.to_string().contains("非法路径") {
            backend
                .record_audit(audit_event("path_blocked", &share.name, &record.client_ip, "", 0, "blocked", "打包路径穿越/非法路径被拦截"))
                .await;
        }
        return Err(error);
    }
    let metadata = fs::metadata(&temp_path).await.map_err(ApiError::internal)?;
    let (sha256, md5) = hash_file(&temp_path).await.map_err(ApiError::internal)?;
    backend.end_transfer(transfer_id).await;
    backend
        .record_audit(audit_event("archive", &share.name, &record.client_ip, &format!("{}.zip", share.name), metadata.len(), "ok", "ZIP 打包完成并开始下发"))
        .await;
    let file = fs::File::open(&temp_path).await.map_err(ApiError::internal)?;
    let cleanup_path = temp_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(600)).await;
        let _ = fs::remove_file(cleanup_path).await;
    });
    let file_name = format!("{}-{}.zip", share.name, Utc::now().format("%Y-%m-%d"));
    Response::builder()
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename*=UTF-8''{}", percent_encode_filename(&file_name)),
        )
        .header(header::CONTENT_LENGTH, metadata.len().to_string())
        .header("X-Content-SHA256", sha256)
        .header("X-Content-MD5", md5)
        .body(Body::from_stream(ReaderStream::new(file)))
        .map_err(ApiError::internal)
}

#[tauri::command]
async fn get_network_interfaces() -> Vec<NetworkInterfaceInfo> {
    network_interfaces()
}

#[tauri::command]
async fn generate_self_signed_cert(backend: TauriState<'_, Arc<Backend>>) -> Result<serde_json::Value, String> {
    let dir = backend
        .state_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("tls");
    let (cert_path, key_path) = write_self_signed_cert(&dir).map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "certPath": cert_path.to_string_lossy(),
        "keyPath": key_path.to_string_lossy(),
    }))
}

#[tauri::command]
async fn get_server_state(backend: TauriState<'_, Arc<Backend>>) -> Result<ServerStateResponse, String> {
    Ok(backend.get_server_state().await)
}

#[tauri::command]
async fn set_server_config(
    backend: TauriState<'_, Arc<Backend>>,
    config: SetServerConfigPayload,
) -> Result<ServerStateResponse, String> {
    if config.port < 1024 {
        return Err("端口必须在 1024-65535 之间".to_string());
    }
    let speed_limit = config.download_speed_limit_mbps.unwrap_or(0);
    if speed_limit > 100_000 {
        return Err("传输限速必须在 0-100000 MB/s 之间（0 表示不限速）".to_string());
    }
    let tls_enabled = config.tls_enabled.unwrap_or(false);
    let tls_cert_path = config.tls_cert_path.filter(|value| !value.trim().is_empty());
    let tls_key_path = config.tls_key_path.filter(|value| !value.trim().is_empty());
    if tls_enabled {
        if tls_cert_path.is_none() || tls_key_path.is_none() {
            return Err("启用 HTTPS 时必须提供证书与私钥路径".to_string());
        }
        for path in [tls_cert_path.as_deref().expect("checked"), tls_key_path.as_deref().expect("checked")] {
            std::fs::read(path).map_err(|error| format!("读取 TLS 文件失败（{path}）：{error}"))?;
        }
    }
    let host_ip = normalize_host_ip(config.host_ip);
    {
        let mut app_state = backend.app_state.lock().await;
        app_state.server = ServerConfig {
            host_ip: host_ip.clone(),
            port: config.port,
            download_speed_limit_mbps: speed_limit,
            tls_enabled,
            tls_cert_path,
            tls_key_path,
        };
    }
    {
        let mut server_state = backend.server_state.lock().await;
        server_state.host_ip = host_ip;
        server_state.port = config.port;
    }
    backend.save_state().await.map_err(|error| error.to_string())?;
    if let Err(error) = backend.inner().clone().start_server().await {
        let mut server_state = backend.server_state.lock().await;
        server_state.running = false;
        server_state.error = error.to_string();
        return Err(error.to_string());
    }
    Ok(backend.get_server_state().await)
}

#[tauri::command]
async fn list_audit_events(backend: TauriState<'_, Arc<Backend>>) -> Result<Vec<AuditEvent>, String> {
    let events: Vec<AuditEvent> = backend.audit_log.lock().await.iter().rev().take(100).cloned().collect();
    Ok(events)
}

#[tauri::command]
async fn export_audit_csv(backend: TauriState<'_, Arc<Backend>>) -> Result<String, String> {
    let events = backend.audit_log.lock().await.clone();
    let mut csv = String::from("timestamp,kind,shareName,clientIp,fileName,sizeBytes,outcome,detail\n");
    let field = |value: &str| format!("\"{}\"", value.replace('"', "\"\""));
    for event in events.iter() {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            field(&event.timestamp),
            field(&event.kind),
            field(&event.share_name),
            field(&event.client_ip),
            field(&event.file_name),
            event.size_bytes,
            field(&event.outcome),
            field(&event.detail),
        ));
    }
    Ok(csv)
}

#[tauri::command]
async fn list_shares(backend: TauriState<'_, Arc<Backend>>) -> Result<Vec<ShareRecordAdmin>, String> {
    let state = backend.app_state.lock().await.clone();
    state
        .shares
        .iter()
        .map(|share| admin_share(share, &state.security.link_secret).map_err(|error| error.to_string()))
        .collect()
}

#[tauri::command]
async fn create_share(
    backend: TauriState<'_, Arc<Backend>>,
    payload: CreateSharePayload,
) -> Result<ShareRecordAdmin, String> {
    let alias = normalize_alias(&payload.name).map_err(|error| error.to_string())?;
    let local_path = Path::new(&payload.local_path)
        .canonicalize()
        .map_err(|error| format!("共享路径不存在：{}", error))?;
    let metadata = std::fs::metadata(&local_path).map_err(|error| error.to_string())?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err("只能共享真实存在的本机文件或目录".to_string());
    }
    let (passcode_hash, passcode_hint, passcode_updated_at) =
        make_passcode_record(&payload.passcode).map_err(|error| error.to_string())?;
    let allow_upload = payload.allow_upload.unwrap_or(false);
    let receive_dir = normalize_receive_dir(allow_upload, payload.receive_dir.as_deref())?;
    let share = {
        let mut state = backend.app_state.lock().await;
        if state.shares.iter().any(|share| share.name.eq_ignore_ascii_case(&alias)) {
            return Err("共享别名已存在".to_string());
        }
        let share = ShareRecordInternal {
            id: Uuid::new_v4().to_string(),
            name: alias,
            local_path: local_path.to_string_lossy().to_string(),
            description: payload.description,
            access_mode: normalize_access_mode(payload.access_mode.as_deref()),
            allow_mobile_access: payload.allow_mobile_access.unwrap_or(false),
            created_at: iso_now(),
            passcode_hash,
            passcode_hint,
            passcode_updated_at,
            passcode_expires_at: payload.passcode_expires_at,
            passcode_duration: payload.passcode_duration.or_else(|| Some("4h".to_string())),
            ip_whitelist: normalize_ip_whitelist(payload.ip_whitelist.as_deref()),
            allow_upload,
            receive_dir,
            speed_limit_mbps: payload.speed_limit_mbps.filter(|value| *value > 0),
            one_time_access: payload.one_time_access.unwrap_or(false),
            upload_max_bytes: payload.upload_max_bytes.filter(|value| *value > 0),
            upload_extensions: payload
                .upload_extensions
                .filter(|value| !value.trim().is_empty())
                .map(|value| normalize_upload_extensions(&value)),
        };
        state.shares.push(share.clone());
        share
    };
    backend
        .record_audit(audit_event("share_created", &share.name, "local-admin", "", 0, "ok", &share.local_path))
        .await;
    backend.save_state().await.map_err(|error| error.to_string())?;
    let secret = backend.app_state.lock().await.security.link_secret.clone();
    admin_share(&share, &secret).map_err(|error| error.to_string())
}

#[tauri::command]
async fn update_share(
    backend: TauriState<'_, Arc<Backend>>,
    id: String,
    patch: UpdateSharePatch,
) -> Result<ShareRecordAdmin, String> {
    let updated = {
        let mut state = backend.app_state.lock().await;
        let share = state
            .shares
            .iter_mut()
            .find(|share| share.id == id)
            .ok_or_else(|| "共享不存在".to_string())?;
        if let Some(description) = patch.description {
            share.description = description;
        }
        if let Some(ip_whitelist) = patch.ip_whitelist {
            share.ip_whitelist = normalize_ip_whitelist(Some(&ip_whitelist));
        }
        if let Some(access_mode) = patch.access_mode {
            share.access_mode = normalize_access_mode(Some(&access_mode));
        }
        if let Some(allow_mobile_access) = patch.allow_mobile_access {
            share.allow_mobile_access = allow_mobile_access;
        }
        if let Some(allow_upload) = patch.allow_upload {
            share.allow_upload = allow_upload;
            if !allow_upload {
                share.receive_dir = None;
            }
        }
        if let Some(dir) = patch.receive_dir {
            share.receive_dir = normalize_receive_dir(share.allow_upload, Some(&dir))?;
        }
        if let Some(speed) = patch.speed_limit_mbps {
            share.speed_limit_mbps = if speed > 0 { Some(speed) } else { None };
        }
        if let Some(one_time) = patch.one_time_access {
            share.one_time_access = one_time;
        }
        if let Some(max_bytes) = patch.upload_max_bytes {
            share.upload_max_bytes = if max_bytes > 0 { Some(max_bytes) } else { None };
        }
        if let Some(extensions) = patch.upload_extensions {
            share.upload_extensions = if extensions.trim().is_empty() {
                None
            } else {
                Some(normalize_upload_extensions(&extensions))
            };
        }
        share.passcode_expires_at = patch.passcode_expires_at;
        if patch.passcode_duration.is_some() {
            share.passcode_duration = patch.passcode_duration;
        }
        if let Some(passcode) = patch.passcode.filter(|value| !value.trim().is_empty()) {
            let (hash, hint, updated_at) = make_passcode_record(&passcode).map_err(|error| error.to_string())?;
            share.passcode_hash = hash;
            share.passcode_hint = hint;
            share.passcode_updated_at = updated_at;
        }
        share.clone()
    };
    backend.save_state().await.map_err(|error| error.to_string())?;
    let secret = backend.app_state.lock().await.security.link_secret.clone();
    admin_share(&updated, &secret).map_err(|error| error.to_string())
}

#[tauri::command]
async fn extend_share_expiry(
    backend: TauriState<'_, Arc<Backend>>,
    id: String,
    add_ms: i64,
) -> Result<ShareRecordAdmin, String> {
    if add_ms <= 0 {
        return Err("加时时长无效".to_string());
    }
    let updated = {
        let mut state = backend.app_state.lock().await;
        let share = state
            .shares
            .iter_mut()
            .find(|share| share.id == id)
            .ok_or_else(|| "共享不存在".to_string())?;
        if share.passcode_expires_at.is_some() {
            let current = parse_expiry_ms(&share.passcode_expires_at).unwrap_or_else(now_ms);
            let base = current.max(now_ms());
            share.passcode_expires_at = Some(iso_from_ms(base + add_ms));
        }
        share.clone()
    };
    backend.save_state().await.map_err(|error| error.to_string())?;
    let secret = backend.app_state.lock().await.security.link_secret.clone();
    admin_share(&updated, &secret).map_err(|error| error.to_string())
}

#[tauri::command]
async fn delete_share(backend: TauriState<'_, Arc<Backend>>, id: String) -> Result<bool, String> {
    let share_name = {
        let state = backend.app_state.lock().await;
        state
            .shares
            .iter()
            .find(|share| share.id == id)
            .map(|share| share.name.clone())
            .unwrap_or_default()
    };
    {
        let mut state = backend.app_state.lock().await;
        state.shares.retain(|share| share.id != id);
    }
    backend.share_leases.lock().await.remove(&id);
    backend
        .active_tokens
        .lock()
        .await
        .retain(|_, record| record.share_id != id);
    backend
        .record_audit(audit_event("share_deleted", &share_name, "local-admin", "", 0, "ok", "共享已撤销"))
        .await;
    backend.save_state().await.map_err(|error| error.to_string())?;
    Ok(true)
}

#[tauri::command]
async fn list_files(
    backend: TauriState<'_, Arc<Backend>>,
    share_id: String,
) -> Result<Vec<PhysicalFile>, String> {
    let share = {
        let state = backend.app_state.lock().await;
        state.shares.iter().find(|share| share.id == share_id).cloned()
    }
    .ok_or_else(|| "共享不存在".to_string())?;
    list_physical_files(share.local_path)
        .await
        .map_err(|error| error.to_string())
}

fn list_received_files_sync(root: &str) -> Result<Vec<PhysicalFile>> {
    let root_full = Path::new(root).canonicalize()?;
    let mut rows = Vec::new();
    for entry in WalkDir::new(&root_full).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path == root_full {
            continue;
        }
        let metadata = entry.metadata()?;
        let relative = path
            .strip_prefix(&root_full)?
            .to_string_lossy()
            .replace('\\', "/");
        let is_dir = metadata.is_dir();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("file")
            .to_string();
        let category = if is_dir {
            "folder".to_string()
        } else {
            category_for_file(&name).to_string()
        };
        rows.push(PhysicalFile {
            id: encode_path_id(&relative),
            name: name.clone(),
            relative_path: relative,
            file_type: if is_dir { "folder" } else { "file" }.to_string(),
            size_bytes: if is_dir { 0 } else { metadata.len() },
            size: if is_dir { "目录".to_string() } else { format_bytes(metadata.len()) },
            last_modified: iso_from_system_time(metadata.modified().unwrap_or_else(|_| SystemTime::now())),
            category,
        });
    }
    rows.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(rows)
}

#[tauri::command]
async fn list_received_files(backend: TauriState<'_, Arc<Backend>>, share_id: String) -> Result<Vec<PhysicalFile>, String> {
    let share = {
        let state = backend.app_state.lock().await;
        state.shares.iter().find(|share| share.id == share_id).cloned()
    }
    .ok_or_else(|| "共享不存在".to_string())?;
    let Some(receive_dir) = share.receive_dir.clone() else {
        return Ok(Vec::new());
    };
    list_received_files_sync(&receive_dir).map_err(|error| error.to_string())
}

#[tauri::command]
async fn delete_received_file(
    backend: TauriState<'_, Arc<Backend>>,
    share_id: String,
    relative_path: String,
) -> Result<bool, String> {
    let share = {
        let state = backend.app_state.lock().await;
        state.shares.iter().find(|share| share.id == share_id).cloned()
    }
    .ok_or_else(|| "共享不存在".to_string())?;
    let receive_dir = share
        .receive_dir
        .clone()
        .ok_or_else(|| "该共享未配置接收目录".to_string())?;
    let full = safe_resolve(&receive_dir, Some(&relative_path)).map_err(|error| error.to_string())?;
    let metadata = std::fs::metadata(&full).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        return Err("目录请逐个删除文件".to_string());
    }
    std::fs::remove_file(&full).map_err(|error| error.to_string())?;
    backend
        .record_audit(audit_event("received_file_deleted", &share.name, "local-admin", &relative_path, metadata.len(), "ok", "已删除访客回传文件"))
        .await;
    Ok(true)
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceInfo {
    token: String,
    share_id: String,
    share_name: String,
    client_ip: String,
    fingerprint: String,
    expires_at: i64,
}

#[tauri::command]
async fn list_devices(backend: TauriState<'_, Arc<Backend>>) -> Result<Vec<DeviceInfo>, String> {
    let state = backend.app_state.lock().await.clone();
    let tokens = backend.active_tokens.lock().await.clone();
    let mut devices: Vec<DeviceInfo> = tokens
        .values()
        .map(|record| {
            let share_name = state
                .shares
                .iter()
                .find(|share| share.id == record.share_id)
                .map(|share| share.name.clone())
                .unwrap_or_default();
            DeviceInfo {
                token: record.token.clone(),
                share_id: record.share_id.clone(),
                share_name,
                client_ip: record.client_ip.clone(),
                fingerprint: record.user_agent_hash.chars().take(12).collect(),
                expires_at: record.expires_at,
            }
        })
        .collect();
    devices.sort_by(|a, b| a.expires_at.cmp(&b.expires_at));
    Ok(devices)
}

#[tauri::command]
async fn kick_device(backend: TauriState<'_, Arc<Backend>>, token: String) -> Result<bool, String> {
    backend.active_tokens.lock().await.remove(&token);
    Ok(true)
}

#[tauri::command]
async fn preview_file(
    backend: TauriState<'_, Arc<Backend>>,
    share_id: String,
    relative_path: String,
) -> Result<PreviewResult, String> {
    let share = {
        let state = backend.app_state.lock().await;
        state.shares.iter().find(|share| share.id == share_id).cloned()
    }
    .ok_or_else(|| "共享不存在".to_string())?;
    preview_physical_file(share.local_path, Some(relative_path))
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn force_release(
    backend: TauriState<'_, Arc<Backend>>,
    share_id: String,
) -> Result<ServerStateResponse, String> {
    backend.share_leases.lock().await.remove(&share_id);
    backend
        .active_tokens
        .lock()
        .await
        .retain(|_, record| record.share_id != share_id);
    Ok(backend.get_server_state().await)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let project_dir =
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let resource_dir = app.path().resource_dir().unwrap_or_else(|_| {
                project_dir.clone()
            });
            let dist_dir = if resource_dir.join("dist").join("index.html").exists() {
                resource_dir.join("dist")
            } else if project_dir.join("dist").join("index.html").exists() {
                project_dir.join("dist")
            } else if project_dir.join("../dist").join("index.html").exists() {
                project_dir.join("../dist")
            } else {
                PathBuf::from("dist")
            };
            let backend = tauri::async_runtime::block_on(Backend::new(
                app_data_dir.join("lan-transfer-state.json"),
                dist_dir,
            ))?;
            app.manage(backend.clone());
            let boot_backend = backend.clone();
            tauri::async_runtime::spawn(async move {
                let _ = boot_backend.start_server().await;
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_network_interfaces,
            generate_self_signed_cert,
            get_server_state,
            set_server_config,
            list_audit_events,
            export_audit_csv,
            list_shares,
            create_share,
            update_share,
            extend_share_expiry,
            delete_share,
            list_files,
            list_received_files,
            delete_received_file,
            list_devices,
            kick_device,
            preview_file,
            force_release
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run();
}

#[cfg(test)]
mod smoke_tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    struct TestClient {
        port: u16,
    }

    impl TestClient {
        async fn request(
            &self,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            body: Option<&[u8]>,
        ) -> (u16, HashMap<String, String>, Vec<u8>) {
            let mut stream = TcpStream::connect(("127.0.0.1", self.port))
                .await
                .expect("connect to test server");
            let mut request = format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n",
                self.port
            );
            for (key, value) in headers {
                request.push_str(&format!("{key}: {value}\r\n"));
            }
            if let Some(payload) = body {
                request.push_str(&format!("Content-Length: {}\r\n", payload.len()));
            }
            request.push_str("\r\n");
            stream.write_all(request.as_bytes()).await.expect("write request");
            if let Some(payload) = body {
                stream.write_all(payload).await.expect("write body");
            }
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 8192];
            let mut header_end: Option<usize> = None;
            while header_end.is_none() {
                let read = stream.read(&mut buffer).await.expect("read headers");
                if read == 0 {
                    panic!("server closed connection before headers: {method} {path}");
                }
                raw.extend_from_slice(&buffer[..read]);
                header_end = raw.windows(4).position(|window| window == b"\r\n\r\n");
            }
            let separator = header_end.expect("header separator");
            let head = std::str::from_utf8(&raw[..separator]).expect("ascii head");
            let mut lines = head.lines();
            let status_line = lines.next().expect("status line");
            let status: u16 = status_line
                .split_whitespace()
                .nth(1)
                .expect("status code")
                .parse()
                .expect("numeric status");
            let mut response_headers = HashMap::new();
            for line in lines {
                if let Some((key, value)) = line.split_once(':') {
                    response_headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
                }
            }
            let content_length = response_headers
                .get("content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .expect("content-length required");
            while raw.len() < separator + 4 + content_length {
                let read = stream.read(&mut buffer).await.expect("read body");
                if read == 0 {
                    panic!("server closed connection before full body: {method} {path}");
                }
                raw.extend_from_slice(&buffer[..read]);
            }
            let body_bytes = raw[separator + 4..separator + 4 + content_length].to_vec();
            (status, response_headers, body_bytes)
        }

        async fn get(
            &self,
            path: &str,
            token: Option<&str>,
            range: Option<&str>,
        ) -> (u16, HashMap<String, String>, Vec<u8>) {
            let auth = token.map(|value| format!("Bearer {value}"));
            let mut headers: Vec<(&str, &str)> = Vec::new();
            if let Some(value) = auth.as_deref() {
                headers.push(("Authorization", value));
            }
            if let Some(value) = range {
                headers.push(("Range", value));
            }
            self.request("GET", path, &headers, None).await
        }

        async fn post_json(
            &self,
            path: &str,
            payload: &str,
            headers: &[(&str, &str)],
        ) -> (u16, HashMap<String, String>, Vec<u8>) {
            let mut all: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
            all.extend_from_slice(headers);
            self.request("POST", path, &all, Some(payload.as_bytes())).await
        }
    }

    async fn free_port() -> u16 {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral");
        listener.local_addr().expect("local addr").port()
    }

    fn sample_share(
        name: &str,
        local_path: &Path,
        passcode: &(String, String, String),
        access_mode: &str,
        allow_mobile: bool,
        whitelist: &str,
        expires_at: Option<String>,
        allow_upload: bool,
        receive_dir: String,
    ) -> ShareRecordInternal {
        ShareRecordInternal {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            local_path: local_path.to_string_lossy().to_string(),
            description: String::new(),
            access_mode: access_mode.to_string(),
            allow_mobile_access: allow_mobile,
            created_at: iso_now(),
            passcode_hash: passcode.0.clone(),
            passcode_hint: passcode.1.clone(),
            passcode_updated_at: passcode.2.clone(),
            passcode_expires_at: expires_at,
            passcode_duration: Some("4h".to_string()),
            ip_whitelist: whitelist.to_string(),
            allow_upload,
            receive_dir: if receive_dir.is_empty() {
                None
            } else {
                Some(receive_dir)
            },
            speed_limit_mbps: None,
            one_time_access: false,
            upload_max_bytes: None,
            upload_extensions: None,
        }
    }

    async fn register_share(backend: &Arc<Backend>, share: &ShareRecordInternal) -> String {
        {
            let mut state = backend.app_state.lock().await;
            state.shares.push(share.clone());
        }
        backend.save_state().await.expect("save state");
        let secret = backend.app_state.lock().await.security.link_secret.clone();
        create_encrypted_link_token(&secret, &share.id).expect("link token")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lan_transfer_smoke() {
        let state_dir = std::env::temp_dir().join(format!("lan-transfer-smoke-{}", Uuid::new_v4()));
        let share_dir = state_dir.join("share-root");
        let outside_dir = state_dir.join("outside-root");
        std::fs::create_dir_all(share_dir.join("nested")).expect("create share dirs");
        std::fs::create_dir_all(&outside_dir).expect("create outside dir");
        std::fs::write(share_dir.join("hello.txt"), "hello 内网闪传 smoke\n").expect("write hello");
        std::fs::write(share_dir.join("report.csv"), "name,size\nhello,5\n").expect("write csv");
        std::fs::write(share_dir.join("nested").join("data.json"), "{\"ok\":true}\n").expect("write json");
        std::fs::write(outside_dir.join("outside.txt"), "must not leak\n").expect("write outside");
        let png_bytes = hex::decode(
            "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c49444154789c62600000000100000181018f9714340000000049454e44ae426082",
        )
        .expect("png hex");
        std::fs::write(share_dir.join("photo.png"), &png_bytes).expect("write png");
        std::fs::write(share_dir.join("video.mp4"), b"\x00\x00\x00\x18ftypmp42").expect("write mp4");

        let media_bytes: Vec<u8> = {
            let mut bytes = vec![0_u8; 512 * 1024];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes
        };
        std::fs::write(share_dir.join("media.bin"), &media_bytes).expect("write media");

        let dist_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist");
        assert!(
            dist_dir.join("index.html").exists(),
            "npm run build 必须先执行，dist/index.html 不存在"
        );

        let port = free_port().await;
        let backend = Backend::new(state_dir.join("state.json"), dist_dir)
            .await
            .expect("backend init");
        {
            let mut app_state = backend.app_state.lock().await;
            app_state.server.port = port;
            let mut server_state = backend.server_state.lock().await;
            server_state.port = port;
        }
        let passcode = make_passcode_record("smoke-pass").expect("passcode record");
        let exclusive = sample_share("smoke-share", &share_dir, &passcode, "exclusive", false, "", None, false, String::new());
        let multi = sample_share("smoke-multi", &share_dir, &passcode, "multi", false, "", None, false, String::new());
        let whitelist_share = sample_share("smoke-whitelist", &share_dir, &passcode, "exclusive", false, "10.99.99.99", None, false, String::new());
        let mobile = sample_share("smoke-mobile", &share_dir, &passcode, "exclusive", false, "", None, false, String::new());
        let expired = sample_share(
            "smoke-expired",
            &share_dir,
            &passcode,
            "exclusive",
            false,
            "",
            Some(iso_from_ms(now_ms() - 1000)),
            false,
            String::new(),
        );
        let upload_root = state_dir.join("upload-root");
        std::fs::create_dir_all(&upload_root).expect("create upload root");
        let upload_share = sample_share(
            "smoke-upload",
            &share_dir,
            &passcode,
            "multi",
            false,
            "",
            None,
            true,
            upload_root.to_string_lossy().to_string(),
        );

        let exclusive_token = register_share(&backend, &exclusive).await;
        let multi_token = register_share(&backend, &multi).await;
        let whitelist_token = register_share(&backend, &whitelist_share).await;
        let mobile_token = register_share(&backend, &mobile).await;
        let expired_token = register_share(&backend, &expired).await;
        let upload_token = register_share(&backend, &upload_share).await;
        let lock_share = sample_share("smoke-lock", &share_dir, &passcode, "multi", false, "", None, false, String::new());
        let lock_token = register_share(&backend, &lock_share).await;
        let mut onetime_share = sample_share("smoke-onetime", &share_dir, &passcode, "exclusive", false, "", None, false, String::new());
        onetime_share.one_time_access = true;
        let onetime_token = register_share(&backend, &onetime_share).await;
        let mut policy_share = sample_share(
            "smoke-policy",
            &share_dir,
            &passcode,
            "multi",
            false,
            "",
            None,
            true,
            upload_root.to_string_lossy().to_string(),
        );
        policy_share.upload_extensions = Some("txt".to_string());
        policy_share.upload_max_bytes = Some(100);
        let policy_token = register_share(&backend, &policy_share).await;
        let mut speed_share = sample_share("smoke-speed", &share_dir, &passcode, "multi", false, "", None, false, String::new());
        speed_share.speed_limit_mbps = Some(1);
        let speed_token = register_share(&backend, &speed_share).await;

        backend.start_server().await.expect("start server");
        let client = TestClient { port };

        // 1. 管理端页面与服务器状态
        let (status, _, body) = client.get("/", None, None).await;
        assert_eq!(status, 200, "archive start failed: {}", String::from_utf8_lossy(&body));
        assert!(String::from_utf8_lossy(&body).contains("<div id=\"root\">"));
        let (status, _, state_body) = client.get("/api/server-state", None, None).await;
        assert_eq!(status, 200);
        let state: serde_json::Value = serde_json::from_slice(&state_body).expect("state json");
        assert_eq!(state["running"], true);
        assert_eq!(state["port"], port);

        // 2. 公开入口：加密链接与别名均可解析，初始策略正确
        let (status, _, body) = client.get(&format!("/api/public-share?token={exclusive_token}"), None, None).await;
        assert_eq!(status, 200);
        let public: serde_json::Value = serde_json::from_slice(&body).expect("public json");
        assert_eq!(public["ipAllowed"], true);
        assert_eq!(public["mobileBlocked"], false);
        assert_eq!(public["passcodeExpired"], false);
        assert_eq!(public["occupied"], false);
        let (status, _, _) = client.get("/api/public-share?share=smoke-share", None, None).await;
        assert_eq!(status, 200);

        // 3. 错误口令被拒绝
        let (status, _, _) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{exclusive_token}\",\"passcode\":\"wrong\"}}"), &[])
            .await;
        assert_eq!(status, 401);

        // 4. 正确口令认证，拿到文件清单
        let (status, _, body) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{exclusive_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 200);
        let auth: serde_json::Value = serde_json::from_slice(&body).expect("auth json");
        let session = auth["token"].as_str().expect("session token").to_string();
        let files = auth["files"].as_array().expect("files array");
        assert_eq!(files.len(), 7);
        let names: Vec<&str> = files.iter().filter_map(|item| item["name"].as_str()).collect();
        assert!(names.contains(&"hello.txt"));
        assert!(names.contains(&"media.bin"));
        assert!(names.contains(&"report.csv"));
        assert!(names.contains(&"photo.png"));
        assert!(names.contains(&"video.mp4"));
        assert!(names.contains(&"nested"));

        // 5. 独占租约已建立：再次认证被锁，公开入口显示被占用
        let (status, _, _) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{exclusive_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 423);
        let (status, _, body) = client.get(&format!("/api/public-share?token={exclusive_token}"), None, None).await;
        assert_eq!(status, 200);
        let public: serde_json::Value = serde_json::from_slice(&body).expect("public json");
        assert_eq!(public["occupied"], true);

        // 6. 会话心跳与文件列表
        let (status, _, _) = client
            .post_json("/api/heartbeat", "{}", &[("Authorization", &format!("Bearer {session}"))])
            .await;
        assert_eq!(status, 200);
        let (status, _, body) = client.get("/api/files", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        let listed: serde_json::Value = serde_json::from_slice(&body).expect("files json");
        assert_eq!(listed["files"].as_array().expect("files").len(), 7);

        // 7. 预览：文本与二进制类型
        let (status, _, body) = client.get("/api/preview?path=hello.txt", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        let preview: serde_json::Value = serde_json::from_slice(&body).expect("preview json");
        assert_eq!(preview["type"], "text");
        assert!(preview["content"].as_str().expect("content").contains("hello"));
        let (status, _, body) = client.get("/api/preview?path=media.bin", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        let preview: serde_json::Value = serde_json::from_slice(&body).expect("preview json");
        assert_eq!(preview["type"], "binary");

        // 7b. 媒体预览：照片/视频类型识别与内联媒体流（含 Range 断点）
        let (status, _, body) = client.get("/api/preview?path=photo.png", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        let preview: serde_json::Value = serde_json::from_slice(&body).expect("preview json");
        assert_eq!(preview["type"], "image");
        let (status, headers, body) = client.get("/api/preview-media?path=photo.png", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        assert_eq!(headers.get("content-type").map(String::as_str), Some("image/png"));
        assert_eq!(body, png_bytes);
        let (status, _, body) = client.get("/api/preview?path=video.mp4", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        let preview: serde_json::Value = serde_json::from_slice(&body).expect("preview json");
        assert_eq!(preview["type"], "video");
        let (status, headers, body) = client
            .get("/api/preview-media?path=video.mp4", Some(session.as_str()), Some("bytes=0-9"))
            .await;
        assert_eq!(status, 206);
        assert_eq!(body.len(), 10);
        assert!(headers.get("content-range").map(String::as_str).is_some());
        let (status, _, _body) = client.get("/api/preview-media?path=../outside.txt", Some(session.as_str()), None).await;
        assert_eq!(status, 400);

        // 8. 哈希一致、完整下载与 Range 断点续传正确
        let expected_sha = {
            let mut hasher = Sha256::new();
            hasher.update(&media_bytes);
            hex::encode(hasher.finalize())
        };
        let (status, _, body) = client.get("/api/hash?path=media.bin", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        let hash: serde_json::Value = serde_json::from_slice(&body).expect("hash json");
        assert_eq!(hash["sha256"].as_str().expect("sha"), expected_sha);
        assert_eq!(hash["sizeBytes"].as_u64().expect("size"), media_bytes.len() as u64);

        let (status, headers, body) = client.get("/api/download?path=media.bin", Some(session.as_str()), Some("bytes=0-999")).await;
        assert_eq!(status, 206);
        assert_eq!(body.len(), 1000);
        assert_eq!(
            headers.get("content-range").map(String::as_str),
            Some("bytes 0-999/524288")
        );
        assert_eq!(headers.get("x-content-sha256").map(String::as_str), Some(expected_sha.as_str()));
        assert_eq!(&body[..], &media_bytes[..1000]);

        let (status, headers, body) = client.get("/api/download?path=media.bin", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        assert_eq!(body, media_bytes);
        assert_eq!(headers.get("x-content-sha256").map(String::as_str), Some(expected_sha.as_str()));

        // 9. ZIP 打包：内容可解包且包含正确条目
        let (status, headers, body) = client
            .get(
                "/api/archive?path=hello.txt&path=nested%2Fdata.json",
                Some(session.as_str()),
                None,
            )
            .await;
        assert_eq!(status, 200);
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(body)).expect("zip archive");
        let mut names = Vec::new();
        for index in 0..archive.len() {
            let entry = archive.by_index(index).expect("zip entry");
            names.push(entry.name().to_string());
        }
        names.sort();
        assert_eq!(names, vec!["hello.txt", "nested/data.json"]);
        assert!(headers.get("x-content-sha256").is_some());

        // 9b. 打包任务流：start → 进度 → download，带进度与指纹
        let (status, _, body) = client
            .post_json(
                &format!("/api/archive/start?token={session}"),
                r#"{"paths":["hello.txt","nested/data.json"]}"#,
                &[],
            )
            .await;
        assert_eq!(status, 200);
        let job: serde_json::Value = serde_json::from_slice(&body).expect("job json");
        let job_id = job["jobId"].as_str().expect("job id").to_string();
        assert_eq!(job["status"], "building");
        let mut ready = false;
        for _ in 0..100 {
            let (status, _, body) = client.get(&format!("/api/archive/progress?jobId={job_id}"), Some(session.as_str()), None).await;
            assert_eq!(status, 200);
            let job: serde_json::Value = serde_json::from_slice(&body).expect("job json");
            if job["status"] == "ready" {
                assert!(job["sizeBytes"].as_u64().expect("size") > 0);
                assert!(!job["sha256"].as_str().expect("sha").is_empty());
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ready, "打包任务应在超时前完成");
        let (status, headers, body) = client.get(&format!("/api/archive/download?jobId={job_id}"), Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        assert!(headers.get("x-content-sha256").is_some());
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(body)).expect("zip archive");
        assert_eq!(archive.len(), 2);

        // 10. 路径穿越被拦截
        let (status, _, body) = client.get("/api/download?path=../outside.txt", Some(session.as_str()), None).await;
        assert_eq!(status, 400, "路径穿越必须以 400 明确拒绝");
        assert!(String::from_utf8_lossy(&body).contains("非法路径"));

        // 11. 一对多模式：两个客户端可同时认证
        let (status, _, _) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{multi_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 200);
        let (status, _, _) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{multi_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 200);

        // 12. IP 白名单拒绝
        let (status, _, body) = client.get(&format!("/api/public-share?token={whitelist_token}"), None, None).await;
        assert_eq!(status, 200);
        let public: serde_json::Value = serde_json::from_slice(&body).expect("public json");
        assert_eq!(public["ipAllowed"], false);
        let (status, _, _) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{whitelist_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 403);

        // 13. 移动端默认关闭
        let mobile_headers = [("User-Agent", "Mozilla/5.0 (Linux; Android 13)"), ("Sec-CH-UA-Mobile", "?1")];
        let (status, _, body) = client
            .request("GET", &format!("/api/public-share?token={mobile_token}"), &mobile_headers, None)
            .await;
        assert_eq!(status, 200);
        let public: serde_json::Value = serde_json::from_slice(&body).expect("public json");
        assert_eq!(public["mobileBlocked"], true);
        let (status, _, _) = client
            .post_json(
                "/api/auth",
                &format!("{{\"token\":\"{mobile_token}\",\"passcode\":\"smoke-pass\"}}"),
                &mobile_headers,
            )
            .await;
        assert_eq!(status, 403);

        // 14. 过期口令拒绝
        let (status, _, body) = client.get(&format!("/api/public-share?token={expired_token}"), None, None).await;
        assert_eq!(status, 200);
        let public: serde_json::Value = serde_json::from_slice(&body).expect("public json");
        assert_eq!(public["passcodeExpired"], true);
        let (status, _, _) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{expired_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 403);

        // 15. 手机回传上传：公开入口标记、流式落盘、指纹回执、自动重名、防护
        let (status, _, body) = client.get(&format!("/api/public-share?token={upload_token}"), None, None).await;
        assert_eq!(status, 200);
        let public: serde_json::Value = serde_json::from_slice(&body).expect("public json");
        assert_eq!(public["share"]["uploadAllowed"], true);

        let (status, _, body) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{upload_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 200);
        let upload_auth: serde_json::Value = serde_json::from_slice(&body).expect("upload auth json");
        let upload_session = upload_auth["token"].as_str().expect("upload session").to_string();

        let upload_body = "uploaded content 回传测试\n".as_bytes();
        let upload_path = format!(
            "/api/upload?token={}&name={}",
            upload_session,
            url::form_urlencoded::byte_serialize("汇报 2026.txt".as_bytes()).collect::<String>()
        );
        let (status, _, body) = client.request("POST", &upload_path, &[], Some(upload_body)).await;
        assert_eq!(status, 200);
        let receipt: serde_json::Value = serde_json::from_slice(&body).expect("upload receipt json");
        assert_eq!(receipt["name"], "汇报 2026.txt");
        assert_eq!(receipt["sizeBytes"], upload_body.len() as u64);
        let expected_sha = {
            let mut hasher = Sha256::new();
            hasher.update(upload_body);
            hex::encode(hasher.finalize())
        };
        assert_eq!(receipt["sha256"].as_str().expect("sha"), expected_sha);
        assert_eq!(std::fs::read(upload_root.join("汇报 2026.txt")).expect("saved file"), upload_body);

        let (status, _, body) = client.request("POST", &upload_path, &[], Some(upload_body)).await;
        assert_eq!(status, 200);
        let receipt: serde_json::Value = serde_json::from_slice(&body).expect("upload receipt json");
        assert_eq!(receipt["name"], "汇报 2026 (1).txt");
        assert!(upload_root.join("汇报 2026 (1).txt").exists());

        let (status, _, _) = client
            .request("POST", &format!("/api/upload?token={session}&name=evil.txt"), &[], Some(b"x".as_slice()))
            .await;
        assert_eq!(status, 403);
        let (status, _, _) = client
            .request(
                "POST",
                &format!("/api/upload?token={upload_session}&name=..%2Fevil.txt"),
                &[],
                Some(b"x".as_slice()),
            )
            .await;
        assert_eq!(status, 400);
        let (status, _, _) = client
            .request(
                "POST",
                &format!("/api/upload?token={upload_session}&name=ok.txt&path=../outside-root"),
                &[],
                Some(b"x".as_slice()),
            )
            .await;
        assert_eq!(status, 400);

        // 15b. 上传到接收目录子目录（服务端自动创建）
        let (status, _, body) = client
            .request(
                "POST",
                &format!("/api/upload?token={upload_session}&name=deep.txt&path=photos%2F2026"),
                &[],
                Some(b"deep content\n".as_slice()),
            )
            .await;
        assert_eq!(status, 200);
        let receipt: serde_json::Value = serde_json::from_slice(&body).expect("upload receipt json");
        assert_eq!(receipt["relativePath"], "photos/2026/deep.txt");
        assert_eq!(
            std::fs::read(upload_root.join("photos").join("2026").join("deep.txt")).expect("deep file"),
            b"deep content\n"
        );

        // 15c. 分片上传：续传状态、偏移校验、最终合并
        let chunk_upload_id = "chunk-test-1";
        let chunk_base = format!("/api/upload-chunk?token={upload_session}&name=chunk.bin&uploadId={chunk_upload_id}");
        let (status, _, body) = client.request("PUT", &format!("{chunk_base}&offset=0"), &[], Some(b"hello ".as_slice())).await;
        assert_eq!(status, 200);
        let chunk: serde_json::Value = serde_json::from_slice(&body).expect("chunk json");
        assert_eq!(chunk["received"], 6);
        let (status, _, body) = client
            .get(&format!("/api/upload-chunk/status?token={upload_session}&name=chunk.bin&uploadId={chunk_upload_id}"), None, None)
            .await;
        assert_eq!(status, 200);
        let chunk_status: serde_json::Value = serde_json::from_slice(&body).expect("chunk status json");
        assert_eq!(chunk_status["offset"], 6);
        let (status, _, _) = client.request("PUT", &format!("{chunk_base}&offset=3"), &[], Some(b"x".as_slice())).await;
        assert_eq!(status, 409);
        let (status, _, body) = client.request("PUT", &format!("{chunk_base}&offset=6&final=true"), &[], Some(b"world!".as_slice())).await;
        assert_eq!(status, 200);
        let receipt: serde_json::Value = serde_json::from_slice(&body).expect("chunk receipt json");
        assert_eq!(receipt["name"], "chunk.bin");
        assert_eq!(receipt["sizeBytes"], 12);
        assert_eq!(std::fs::read(upload_root.join("chunk.bin")).expect("chunk file"), b"hello world!");

        // 15d. 口令错误锁定：5 次错误后即使口令正确也拒绝
        for attempt in 0..5 {
            let (status, _, _) = client
                .post_json("/api/auth", &format!("{{\"token\":\"{lock_token}\",\"passcode\":\"wrong\"}}"), &[])
                .await;
            assert_eq!(status, 401, "第 {} 次错误口令应返回 401", attempt + 1);
        }
        let (status, _, body) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{lock_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 423, "锁定后正确口令也应被拒绝：{}", String::from_utf8_lossy(&body));

        // 15e. 一次性链接：认证成功后口令立即过期
        let (status, _, _) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{onetime_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 200);
        let (status, _, body) = client.get(&format!("/api/public-share?token={onetime_token}"), None, None).await;
        assert_eq!(status, 200);
        let public: serde_json::Value = serde_json::from_slice(&body).expect("public json");
        assert_eq!(public["passcodeExpired"], true);
        let (status, _, _) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{onetime_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 403);

        // 15f. 上传策略：扩展名白名单与大小上限
        let (status, _, body) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{policy_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 200);
        let policy_auth: serde_json::Value = serde_json::from_slice(&body).expect("policy auth json");
        let policy_session = policy_auth["token"].as_str().expect("policy session").to_string();
        let (status, _, _) = client
            .request("POST", &format!("/api/upload?token={policy_session}&name=evil.png"), &[], Some(b"x".as_slice()))
            .await;
        assert_eq!(status, 415);
        let big_body = vec![b'a'; 200];
        let (status, _, _) = client
            .request("POST", &format!("/api/upload?token={policy_session}&name=big.txt"), &[], Some(&big_body))
            .await;
        assert_eq!(status, 413);
        let (status, _, _) = client
            .request("POST", &format!("/api/upload?token={policy_session}&name=ok.txt"), &[], Some(b"fine".as_slice()))
            .await;
        assert_eq!(status, 200);

        // 15g. 每共享独立限速
        let (status, _, body) = client
            .post_json("/api/auth", &format!("{{\"token\":\"{speed_token}\",\"passcode\":\"smoke-pass\"}}"), &[])
            .await;
        assert_eq!(status, 200);
        let speed_auth: serde_json::Value = serde_json::from_slice(&body).expect("speed auth json");
        let speed_session = speed_auth["token"].as_str().expect("speed session").to_string();
        let (status, _, body) = client.get("/api/download?path=hello.txt", Some(speed_session.as_str()), None).await;
        assert_eq!(status, 200);
        assert_eq!(body, "hello 内网闪传 smoke\n".as_bytes());

        // 16. 审计日志：认证、下载、上传、路径拦截均有记录
        {
            let audit = backend.audit_log.lock().await.clone();
            let kinds: Vec<&str> = audit.iter().map(|event| event.kind.as_str()).collect();
            assert!(kinds.contains(&"auth_success"), "应有认证成功记录");
            assert!(kinds.contains(&"auth_failed"), "应有认证失败记录");
            assert!(kinds.contains(&"download"), "应有下载记录");
            assert!(kinds.contains(&"upload"), "应有上传记录");
            assert!(kinds.contains(&"path_blocked"), "应有路径拦截记录");
        }

        // 17. 限速配置下下载内容与指纹仍然正确
        {
            let mut app_state = backend.app_state.lock().await;
            app_state.server.download_speed_limit_mbps = 1;
        }
        let (status, _, body) = client.get("/api/download?path=hello.txt", Some(session.as_str()), None).await;
        assert_eq!(status, 200);
        assert_eq!(body, "hello 内网闪传 smoke\n".as_bytes());
        {
            let mut app_state = backend.app_state.lock().await;
            app_state.server.download_speed_limit_mbps = 0;
        }

        // 18. HTTPS 开关：启用后访问地址全部使用 https 前缀
        {
            let mut app_state = backend.app_state.lock().await;
            app_state.server.tls_enabled = true;
        }
        let tls_state = backend.get_server_state().await;
        assert!(tls_state.url_base.starts_with("https://"));
        assert!(tls_state.access_urls.iter().all(|url| url.starts_with("https://")));
        {
            let mut app_state = backend.app_state.lock().await;
            app_state.server.tls_enabled = false;
        }

        // 19. 自签名证书生成
        let cert_dir = state_dir.join("tls-test");
        let (cert_path, key_path) = write_self_signed_cert(&cert_dir).expect("self signed cert");
        assert!(cert_path.exists() && key_path.exists());
        let cert_pem = std::fs::read_to_string(&cert_path).expect("cert pem");
        let key_pem = std::fs::read_to_string(&key_path).expect("key pem");
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        drop(backend);
        let _ = std::fs::remove_dir_all(&state_dir);
    }
}
