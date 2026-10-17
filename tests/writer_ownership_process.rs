//! Keep process spawning separate from immediate drop/reopen assertions.
//! A fork inherits other threads' flock descriptors until close-on-exec runs.
//! The ordinary ownership suite stays parallel in its own fork-free binary.
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use tempfile::tempdir;

#[path = "support/writer_ownership.rs"]
mod support;
use support::{Kind, contents, denied};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn writer_process_holder() {
    let Some(root) = std::env::var_os("PRAXIS_WRITER_TEST_ROOT") else {
        return;
    };
    let kind = match std::env::var("PRAXIS_WRITER_TEST_KIND").unwrap().as_str() {
        "core" => Kind::Core,
        "pointer" => Kind::Pointer,
        "record" => Kind::Record,
        _ => unreachable!(),
    };
    let mut owner = kind.open(Path::new(&root)).unwrap();
    owner.write_marker();
    println!("WRITER_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    owner.assert_marker();
}

#[test]
fn another_process_is_excluded_and_kill_releases_all_writer_leases() {
    for kind in [Kind::Core, Kind::Pointer, Kind::Record] {
        let dir = tempdir().unwrap();
        let mut child = Process(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "writer_process_holder",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("PRAXIS_WRITER_TEST_ROOT", dir.path())
                .env("PRAXIS_WRITER_TEST_KIND", kind.name())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let ready = BufReader::new(stdout)
                .lines()
                .any(|line| line.is_ok_and(|line| line.contains("WRITER_READY")));
            let _ = sender.send(ready);
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(20))
                .unwrap(),
            "child failed to open its writer"
        );
        reader.join().unwrap();
        let before = contents(dir.path());
        for second in [Kind::Core, Kind::Pointer, Kind::Record] {
            denied(second.open(dir.path()));
        }
        assert_eq!(contents(dir.path()), before);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let recovered = kind.open(dir.path()).unwrap();
        recovered.assert_marker();
    }
}
