use crate::modules::service::pipe::{token_path, PIPE_NAME};
use crate::modules::service::protocol::{
    encode_frame, CoreRequest, CoreResponse, CoreSnapshot, MAX_FRAME_BYTES,
};
use std::io::{ErrorKind, Read, Write};
use std::sync::Mutex;
use std::time::Duration;

static IPC_ERRORS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record_error(message: String) {
    if let Ok(mut errors) = IPC_ERRORS.lock() {
        errors.push(message);
        if errors.len() > 5 {
            let excess = errors.len() - 5;
            errors.drain(..excess);
        }
    }
}

pub fn last_ipc_errors() -> Vec<String> {
    IPC_ERRORS
        .lock()
        .map(|errors| errors.clone())
        .unwrap_or_default()
}

pub struct CoreClient;

fn open_pipe() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)
}

fn read_frame(stream: &mut std::fs::File) -> Result<CoreResponse, String> {
    let mut prefix = [0u8; 4];
    read_exact_or_drop(stream, &mut prefix)?;
    let len = u32::from_le_bytes(prefix);
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err("bad frame".to_string());
    }
    let mut buf = vec![0u8; len as usize];
    read_exact_or_drop(stream, &mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| format!("decode: {e}"))
}

fn read_exact_or_drop(stream: &mut std::fs::File, buf: &mut [u8]) -> Result<(), String> {
    match stream.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Err("pipe closed".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn stored_token() -> String {
    std::fs::read_to_string(token_path())
        .map(|t| t.trim().to_string())
        .unwrap_or_default()
}

fn open_and_authenticate() -> Result<std::fs::File, String> {
    let mut file = match open_pipe() {
        Ok(file) => file,
        Err(_) => {
            record_error("pipe unavailable".to_string());
            return Err("service pipe unavailable".to_string());
        }
    };
    let token = stored_token();
    if token.len() < 64 {
        record_error("no service token (app must run elevated)".to_string());
        return Err("no service token — app cần chạy với quyền Administrator".to_string());
    }
    let payload = serde_json::to_vec(&CoreRequest::Hello { token }).map_err(|e| e.to_string())?;
    let frame = encode_frame(&payload).map_err(|e| e.to_string())?;
    file.write_all(&frame).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    match read_frame(&mut file)? {
        CoreResponse::Ok => Ok(file),
        CoreResponse::Err { code } => {
            record_error(format!("handshake rejected: {code}"));
            Err(format!("handshake rejected: {code}"))
        }
        _ => {
            record_error("unexpected handshake response".to_string());
            Err("unexpected handshake response".to_string())
        }
    }
}

fn call_inner(request: CoreRequest) -> Result<CoreResponse, String> {
    let mut file = open_and_authenticate()?;
    let payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let frame = encode_frame(&payload).map_err(|e| e.to_string())?;
    file.write_all(&frame).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    match read_frame(&mut file) {
        Ok(response) => Ok(response),
        Err(e) => {
            record_error(e.clone());
            Err(e)
        }
    }
}

impl CoreClient {
    pub fn call(request: CoreRequest, timeout: Duration) -> Result<CoreResponse, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(call_inner(request));
        });
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => {
                record_error("ipc timeout".to_string());
                Err("ipc timeout".to_string())
            }
        }
    }

    pub fn handshake(_timeout: Duration) -> Result<(), String> {
        open_and_authenticate().map(|_| ())
    }

    pub fn snapshot(tab: i32, known_hash: u64, timeout: Duration) -> Result<CoreSnapshot, String> {
        match Self::call(CoreRequest::Snapshot { tab, known_hash }, timeout)? {
            CoreResponse::Snapshot(snap) => Ok(*snap),
            CoreResponse::Err { code } => Err(code),
            _ => Err("unexpected snapshot response".to_string()),
        }
    }

    pub fn send(request: CoreRequest, timeout: Duration) -> Result<(), String> {
        match Self::call(request, timeout)? {
            CoreResponse::Ok => Ok(()),
            CoreResponse::Err { code } => Err(code),
            _ => Err("unexpected response".to_string()),
        }
    }
}
