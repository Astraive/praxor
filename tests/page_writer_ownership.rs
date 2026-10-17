use praxis::identity::{Aid, Cid, Eid, FieldId};
use praxis::record::PageRecordStore;
use praxis::store::StorageEngine;
use praxis::{PraxisConfig, PraxisEngine, PraxisError};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

fn denied<T>(result: praxis::Result<T>) {
    assert!(
        matches!(result, Err(PraxisError::AlreadyOpen { .. })),
        "expected typed AlreadyOpen for an independently owned root"
    );
}

#[test]
fn page_owner_excludes_independent_core_and_pointer_writers() {
    let dir = tempfile::tempdir().unwrap();
    let _owner = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    denied(PraxisEngine::open(PraxisConfig::new(dir.path())));
    denied(StorageEngine::open(dir.path(), 1024));
}

#[test]
fn core_owner_excludes_independent_page_writer() {
    let dir = tempfile::tempdir().unwrap();
    let _owner = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
    denied(PageRecordStore::open(dir.path(), Cid(1), Eid(2)));
    assert!(!dir.path().join(".praxis").exists());
}

#[test]
fn pointer_owner_excludes_independent_page_writer() {
    let dir = tempfile::tempdir().unwrap();
    let _owner = StorageEngine::open(dir.path(), 1024).unwrap();
    denied(PageRecordStore::open(dir.path(), Cid(1), Eid(2)));
    assert!(!dir.path().join(".praxis").exists());
}

#[test]
fn cloned_entity_retains_root_lease_until_last_drop() {
    let dir = tempfile::tempdir().unwrap();
    let mut owner = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    let rid = owner.put(&[(FieldId::Fixed(Aid(1)), b"retained")]).unwrap();
    let clone = owner.clone();
    drop(owner);
    denied(PageRecordStore::open(dir.path(), Cid(1), Eid(3)));
    assert_eq!(clone.get(rid).unwrap(), b"retained");
    drop(clone);

    let reopened = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    assert_eq!(reopened.get(rid).unwrap(), b"retained");
    assert!(dir.path().join(".praxor.writer.lock").is_file());
}

#[test]
fn page_writer_process_holder() {
    let Some(root) = std::env::var_os("PRAXIS_PAGE_WRITER_TEST_ROOT") else {
        return;
    };
    let mut store = PageRecordStore::open(&root, Cid(1), Eid(2)).unwrap();
    store
        .put(&[(FieldId::Fixed(Aid(1)), b"child acknowledged")])
        .unwrap();
    println!("PAGE_WRITER_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}

struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn page_writer_process_excludes_another_process_until_killed() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "page_writer_process_holder",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("PRAXIS_PAGE_WRITER_TEST_ROOT", dir.path())
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
            .any(|line| line.is_ok_and(|line| line.contains("PAGE_WRITER_READY")));
        let _ = sender.send(ready);
    });
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .unwrap(),
        "child did not acquire the page writer"
    );
    reader.join().unwrap();
    denied(PageRecordStore::open(dir.path(), Cid(1), Eid(3)));
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let reopened = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    assert_eq!(
        reopened.get(praxis::identity::Rid(1)).unwrap(),
        b"child acknowledged"
    );
}
