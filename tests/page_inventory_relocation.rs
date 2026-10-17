use praxis::identity::{Aid, Cid, Eid, FieldId, Rid};
use praxis::manifest::PageManifestStore;
use praxis::record::PageDatabase;
use std::path::{Path, PathBuf};

fn move_owned(from: &Path, to: &Path, owned: &Path) {
    let resolved = from.canonicalize().unwrap();
    assert!(resolved.is_absolute() && resolved.starts_with(owned) && resolved != owned);
    assert_eq!(to.parent().unwrap().canonicalize().unwrap(), owned);
    assert!(!to.exists());
    std::fs::rename(from, to).unwrap();
}

fn check(root: &Path, expected: &[&[u8]]) {
    let database = PageDatabase::open(root).unwrap();
    let page = database.entity(Cid(0x1_0001), Eid(0x2_0002)).unwrap();
    for (index, body) in expected.iter().enumerate() {
        assert_eq!(page.get(Rid(index as u64 + 1)).unwrap(), *body);
    }
}

fn append(root: &Path, expected_id: u64, body: &[u8]) -> PathBuf {
    let database = PageDatabase::open(root).unwrap();
    let mut page = database.entity(Cid(0x1_0001), Eid(0x2_0002)).unwrap();
    let rid = page.put(&[(FieldId::Fixed(Aid(1)), body)]).unwrap();
    assert_eq!(rid.0, expected_id);
    assert_eq!(page.get(rid).unwrap(), body);
    page.layout().page_manifest_path().path
}

#[test]
fn relocation_preserves_aliases_and_first_exact_current_checksum() {
    let fixture = tempfile::tempdir().unwrap();
    let owned = fixture.path().canonicalize().unwrap();
    let a = owned.join("A");
    let b = owned.join("B");
    let c = owned.join("C");
    let manifest_a = append(&a, 1, b"A");
    let first = PageManifestStore::open(manifest_a).load().unwrap();
    assert_eq!(first.files.len(), 3);
    check(&a, &[b"A"]);
    move_owned(&a, &b, &owned);
    check(&b, &[b"A"]);
    let manifest_b = append(&b, 2, b"B");
    let second = PageManifestStore::open(manifest_b).load().unwrap();
    assert_eq!(second.files.len(), 6);
    check(&b, &[b"A", b"B"]);
    move_owned(&b, &c, &owned);
    check(&c, &[b"A", b"B"]);
    let manifest_c = append(&c, 3, b"C");
    let store = PageManifestStore::open(&manifest_c);
    let third = store.load().unwrap();
    assert_eq!(third.files.len(), 9);
    assert!(
        third
            .files
            .windows(2)
            .all(|pair| pair[0].path <= pair[1].path)
    );
    check(&c, &[b"A", b"B", b"C"]);
    println!(
        "CONTROL A->B->C supported move/write/reopen PASS: manifest row counts3->6->9, no old source paths exist; Cid10001/Eid20002 preserved"
    );

    let current_page = third
        .files
        .iter()
        .position(|row| row.format == "record-page" && Path::new(&row.path).starts_with(&c))
        .unwrap();
    let expected = std::fs::read(&manifest_c).unwrap();
    let mut bad = third.clone();
    bad.files[current_page].checksum = "bad-current-checksum".into();
    store.save(&bad).unwrap();
    let before = std::fs::read(&manifest_c).unwrap();
    assert!(PageDatabase::open(&c).is_err());
    assert_eq!(std::fs::read(&manifest_c).unwrap(), before);
    std::fs::write(&manifest_c, &expected).unwrap();
    check(&c, &[b"A", b"B", b"C"]);
    println!(
        "CONTROL exact current path bad checksum refuses despite stale foreign aliases; restore/read PASS"
    );

    // Raw writer-produced duplicate order is a compatibility surface: existing
    // selected-file validation uses the FIRST exact path match, not every alias.
    let mut duplicated = third.clone();
    let mut bad_last = third.files[current_page].clone();
    bad_last.checksum = "bad-later-duplicate".into();
    duplicated.files.push(bad_last.clone());
    store.save(&duplicated).unwrap();
    check(&c, &[b"A", b"B", b"C"]);
    duplicated.files.insert(0, bad_last);
    store.save(&duplicated).unwrap();
    assert!(PageDatabase::open(&c).is_err());
    std::fs::write(&manifest_c, expected).unwrap();
    check(&c, &[b"A", b"B", b"C"]);
    println!("CONTROL first-exact-path checksum selection and duplicate raw-row order PASS");
}
