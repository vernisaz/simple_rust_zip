fn main() {
    let mut zip = simzip::ZipInfo::new("test.zip".into());
    zip.add(simzip::ZipEntry::new("test entry.txt".into(), "test content".as_bytes().to_vec()));
    let _ = zip.store();
}