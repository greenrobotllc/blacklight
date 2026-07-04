//! End-to-end integration test driving the real `blacklight` binary over a
//! local HTTP server, exercising the clean path and several tampering attacks.
//!
//! No Sigstore here (that path needs interactive OIDC); these tests cover the
//! verified-streaming half — the part that must abort mid-transfer on the first
//! bad byte. Signing/verification of the manifest is covered by unit-level API
//! use plus the manual staging check documented in the README.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

const GROUP: usize = 16 * 1024;

fn bin() -> PathBuf {
    // Cargo sets CARGO_BIN_EXE_<name> for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_blacklight"))
}

/// Minimal single-request-per-connection HTTP/1.1 file server rooted at `dir`.
/// If `tamper` is Some((path, offset)), it flips one byte of that path's body.
fn serve(dir: PathBuf, tamper: Option<(String, usize)>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let served2 = served.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let dir = dir.clone();
            let tamper = tamper.clone();
            let counter = served2.clone();
            thread::spawn(move || handle(stream, &dir, tamper, counter));
        }
    });
    (format!("http://{addr}"), served)
}

fn handle(
    mut stream: TcpStream,
    dir: &Path,
    tamper: Option<(String, usize)>,
    counter: Arc<AtomicUsize>,
) {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    if n == 0 {
        return;
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
    let rel = path.trim_start_matches('/');
    let full = dir.join(rel);
    let mut body = match std::fs::read(&full) {
        Ok(b) => b,
        Err(_) => {
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return;
        }
    };
    // Match guard rather than an `if let` chain, so this test compiles on the
    // documented MSRV (let-chains stabilized later than edition 2024's floor).
    match &tamper {
        Some((tpath, off)) if &path == tpath && *off < body.len() => {
            body[*off] ^= 0xFF;
        }
        _ => {}
    }
    counter.fetch_add(1, Ordering::SeqCst);
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

fn publish(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).unwrap();
    let status = Command::new(bin())
        .arg("publish")
        .arg(dir.join(name))
        .arg("--unsigned")
        .status()
        .unwrap();
    assert!(status.success(), "publish failed");
}

fn fetch(base: &str, name: &str, out: &Path) -> std::process::Output {
    Command::new(bin())
        .arg("fetch")
        .arg(format!("{base}/{name}.blacklight.json"))
        .arg("--allow-unsigned")
        .arg("-o")
        .arg(out)
        .output()
        .unwrap()
}

fn sample(size: usize) -> Vec<u8> {
    (0..size).map(|i| ((i * 7 + 3) % 256) as u8).collect()
}

#[test]
fn clean_download_succeeds_and_matches() {
    let dir = tempdir();
    let data = sample(5 * GROUP + 123);
    publish(&dir, "demo.bin", &data);
    let (base, _) = serve(dir.clone(), None);
    let out = dir.join("out.bin");
    let o = fetch(&base, "demo.bin", &out);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(std::fs::read(&out).unwrap(), data);
}

#[test]
fn tampered_artifact_aborts_with_no_output() {
    let dir = tempdir();
    let data = sample(10 * GROUP + 7);
    publish(&dir, "demo.bin", &data);
    // Flip a byte inside group 3.
    let off = 3 * GROUP + 500;
    let (base, _) = serve(dir.clone(), Some(("/demo.bin".into(), off)));
    let out = dir.join("out.bin");
    let o = fetch(&base, "demo.bin", &out);
    assert_eq!(o.status.code(), Some(3), "expected integrity exit code 3");
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("chunk group 3"), "stderr: {stderr}");
    assert!(!out.exists(), "a partial output file was left behind");
}

#[test]
fn tampered_outboard_is_rejected_before_streaming() {
    let dir = tempdir();
    let data = sample(8 * GROUP);
    publish(&dir, "demo.bin", &data);
    // Corrupt the outboard tree; it must no longer hash to the signed root.
    let (base, _) = serve(dir.clone(), Some(("/demo.bin.obao".into(), 40)));
    let out = dir.join("out.bin");
    let o = fetch(&base, "demo.bin", &out);
    assert_eq!(o.status.code(), Some(3));
    assert!(!out.exists());
}

#[test]
fn truncated_stream_is_rejected() {
    // The last group is short; if the server drops it entirely, length check fails.
    let dir = tempdir();
    let data = sample(4 * GROUP);
    publish(&dir, "demo.bin", &data);
    // Overwrite hosted artifact with a truncated copy (server serves as-is).
    std::fs::write(dir.join("demo.bin"), &data[..3 * GROUP]).unwrap();
    let (base, _) = serve(dir.clone(), None);
    let out = dir.join("out.bin");
    let o = fetch(&base, "demo.bin", &out);
    assert_eq!(o.status.code(), Some(3));
    assert!(!out.exists());
}

fn tempdir() -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "blacklight-it-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
