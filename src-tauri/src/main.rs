use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State as AxumState},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use get_if_addrs::{get_if_addrs, IfAddr};
use rand::{rngs::OsRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
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
    io::{AsyncReadExt, AsyncSeekExt},
    net::TcpListener,
    sync::{oneshot, Mutex},
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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerConfig {
    host_ip: String,
    port: u16,
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
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

struct Backend {
    state_path: PathBuf,
    dist_dir: PathBuf,
    app_state: Mutex<AppState>,
    server_state: Mutex<ServerRuntime>,
    active_tokens: Mutex<HashMap<String, AuthTokenRecord>>,
    share_leases: Mutex<HashMap<String, LeaseRecord>>,
    active_transfers: Mutex<HashMap<u64, ActiveTransfer>>,
    server_control: Mutex<ServerControl>,
    next_transfer_id: AtomicU64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetServerConfigPayload {
    host_ip: String,
    port: u16,
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
struct ArchiveQuery {
    #[serde(default)]
    path: Vec<String>,
    token: Option<String>,
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
                rows.push(NetworkInterfaceInfo {
                    id: format!("{}-{}", iface.name, address),
                    name: iface.name,
                    cidr: format!("{}/{}", address, prefix),
                    address,
                    mac: String::new(),
                });
            }
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.address.cmp(&b.address)));
    rows
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

fn access_urls_for_port(port: u16, preferred_host_ip: &str) -> Vec<String> {
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
        .map(|address| format!("http://{}:{}", address, port))
        .collect()
}

fn default_app_state() -> AppState {
    AppState {
        server: ServerConfig {
            host_ip: first_usable_ip(),
            port: 8787,
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
    if files.is_empty() {
        return Err(anyhow!("没有可打包的真实文件"));
    }
    let file = StdFile::create(output_path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for (full_path, zip_name) in files {
        zip.start_file(zip_name, options)?;
        let mut input = StdFile::open(full_path)?;
        std::io::copy(&mut input, &mut zip)?;
    }
    zip.finish()?;
    Ok(())
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
        let server_state = ServerRuntime {
            running: false,
            host_ip: app_state.server.host_ip.clone(),
            bind_address: "0.0.0.0".to_string(),
            port: app_state.server.port,
            error: String::new(),
        };
        let backend = Arc::new(Self {
            state_path,
            dist_dir,
            app_state: Mutex::new(app_state),
            server_state: Mutex::new(server_state),
            active_tokens: Mutex::new(HashMap::new()),
            share_leases: Mutex::new(HashMap::new()),
            active_transfers: Mutex::new(HashMap::new()),
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
        let listener = match TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), runtime.port)).await {
            Ok(listener) => listener,
            Err(error) => {
                let mut server_state = self.server_state.lock().await;
                server_state.running = false;
                server_state.error = error.to_string();
                return Err(error.into());
            }
        };

        let router = self.router();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        {
            let mut control = self.server_control.lock().await;
            control.shutdown = Some(shutdown_tx);
            control.handle = Some(handle);
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
            let _ = shutdown.send(());
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
            .route("/api/public-share", get(api_public_share))
            .route("/api/auth", post(api_auth))
            .route("/api/heartbeat", post(api_heartbeat))
            .route("/api/files", get(api_files))
            .route("/api/preview", get(api_preview))
            .route("/api/hash", get(api_hash))
            .route("/api/download", get(api_download))
            .route("/api/archive", get(api_archive))
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
            error: runtime.error,
            url_base: format!("http://{}:{}", host_ip, runtime.port),
            access_urls: access_urls_for_port(runtime.port, &host_ip),
            runtime_idle_guard: RuntimeIdleGuard {
                guard_type: "prevent-display-sleep".to_string(),
                active: false,
                blocker_id: None,
                note: "Tauri 版本不再启用 Electron powerSaveBlocker；系统手动锁屏仍由操作系统控制。".to_string(),
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
    if is_mobile_user_agent(&headers) && !share.allow_mobile_access {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "移动/平板终端未被此共享开关允许访问",
        ));
    }
    if !ip_in_whitelist(&client_ip, &share.ip_whitelist) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "当前客户端 IP 不在白名单内"));
    }
    if is_passcode_expired(&share) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "访问口令已过期"));
    }
    if !verify_passcode(payload.passcode.as_deref().unwrap_or_default(), &share.passcode_hash) {
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
        .map_err(ApiError::internal)?;
    Ok(Json(result))
}

async fn api_hash(
    AxumState(backend): AxumState<Arc<Backend>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<PathQuery>,
) -> Result<Json<HashResult>, ApiError> {
    let (_record, share) = require_auth(&backend, &headers, addr, query.token.as_deref()).await?;
    let full = safe_resolve(&share.local_path, query.path.as_deref()).map_err(ApiError::internal)?;
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
    let full = safe_resolve(&share.local_path, query.path.as_deref()).map_err(ApiError::internal)?;
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

    let size = metadata.len();
    let range_header = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let range = parse_range_header(range_header, size);
    let mut file = fs::File::open(&full).await.map_err(ApiError::internal)?;
    let mut builder = Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename*=UTF-8''{}", percent_encode_filename(&file_name)),
        )
        .header("X-Content-SHA256", sha256)
        .header("X-Content-MD5", md5);

    let body = if let Some((start, end)) = range {
        file.seek(SeekFrom::Start(start)).await.map_err(ApiError::internal)?;
        let length = end - start + 1;
        builder = builder
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, end, size))
            .header(header::CONTENT_LENGTH, length.to_string());
        Body::from_stream(ReaderStream::new(file.take(length)))
    } else {
        builder = builder.header(header::CONTENT_LENGTH, size.to_string());
        Body::from_stream(ReaderStream::new(file))
    };
    builder.body(body).map_err(ApiError::internal)
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
        .and_then(|result| result.map_err(ApiError::internal));
    if let Err(error) = build_result {
        backend.end_transfer(transfer_id).await;
        return Err(error);
    }
    let metadata = fs::metadata(&temp_path).await.map_err(ApiError::internal)?;
    let (sha256, md5) = hash_file(&temp_path).await.map_err(ApiError::internal)?;
    backend.end_transfer(transfer_id).await;
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
    let host_ip = normalize_host_ip(config.host_ip);
    {
        let mut app_state = backend.app_state.lock().await;
        app_state.server = ServerConfig {
            host_ip: host_ip.clone(),
            port: config.port,
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
        };
        state.shares.push(share.clone());
        share
    };
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
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let resource_dir = app.path().resource_dir().unwrap_or_else(|_| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
            });
            let dist_dir = if resource_dir.join("dist").join("index.html").exists() {
                resource_dir.join("dist")
            } else {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist")
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
            get_server_state,
            set_server_config,
            list_shares,
            create_share,
            update_share,
            extend_share_expiry,
            delete_share,
            list_files,
            preview_file,
            force_release
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run();
}
