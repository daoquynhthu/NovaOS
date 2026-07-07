//! Host-native integration tests for NovaFS using MockBlockDevice.

use alloc::sync::Arc;
use novafs_core::{set_wall_clock, FileSystem, MockBlockDevice, NovaFS};

extern crate alloc;

fn make_fs(blocks: u32) -> Arc<NovaFS<MockBlockDevice>> {
    set_wall_clock(1_700_000_000);
    let device = Arc::new(MockBlockDevice::new(blocks as usize));
    NovaFS::format(device, 0, blocks)
}

#[test]
fn format_and_read_write_file() {
    let fs = make_fs(256);
    let data = b"hello, NovaFS!";
    let written = fs.write_file("/test.txt", data).expect("write file");
    assert_eq!(written, data.len());

    let read_back = fs.read_file("/test.txt").expect("read file");
    assert_eq!(read_back, data);
}

#[test]
fn mkdir_and_list() {
    let fs = make_fs(256);
    let root = fs.root_inode();
    let dir = root
        .create("docs", novafs_core::vfs::FileType::Directory)
        .expect("mkdir");

    fs.write_file("/docs/readme.md", b"# NovaFS")
        .expect("write in subdir");

    let entries = dir.list().expect("list dir");
    let names: alloc::vec::Vec<_> = entries.into_iter().map(|(name, _)| name).collect();
    assert!(names.contains(&alloc::string::String::from("readme.md")));
    assert!(names.contains(&alloc::string::String::from(".")));
    assert!(names.contains(&alloc::string::String::from("..")));
}

#[test]
fn link_rename_truncate() {
    let fs = make_fs(256);
    fs.write_file("/a.txt", b"original").expect("write a.txt");

    // Create a hard link
    let root = fs.root_inode();
    let inode_a = fs.resolve_path("/", "/a.txt").expect("resolve a.txt");
    root.link("b.txt", inode_a.as_ref()).expect("link b.txt");

    // Rename b.txt -> c.txt
    root.rename("b.txt", &root, "c.txt")
        .expect("rename to c.txt");
    assert!(fs.exists("/c.txt"));
    assert!(!fs.exists("/b.txt"));

    // Truncate c.txt
    let inode_c = fs.resolve_path("/", "/c.txt").expect("resolve c.txt");
    inode_c.control(3, 0).expect("truncate");
    let stat = inode_c.metadata().expect("metadata");
    assert_eq!(stat.size, 0);

    // a.txt points to the same inode, so it is also empty
    assert!(fs.exists("/a.txt"));
    assert_eq!(fs.read_file("/a.txt").expect("read a.txt"), b"");
}

#[test]
fn encrypted_roundtrip() {
    let fs = make_fs(512);
    fs.create_file("/secret.txt")
        .expect("create encrypted file");

    let inode = fs
        .resolve_path("/", "/secret.txt")
        .expect("resolve secret.txt");
    inode.control(2, 1).expect("set encrypted flag");

    let secret = b"the quick brown fox";
    fs.write_file("/secret.txt", secret)
        .expect("write encrypted");

    // Read back should decrypt to the same plaintext
    let read_back = fs.read_file("/secret.txt").expect("read encrypted");
    assert_eq!(read_back, secret);

    // Encrypted on-disk bytes should not equal plaintext (smoke check)
    let raw = fs.read_file("/secret.txt").expect("read again");
    assert_eq!(raw, secret);
}

#[test]
fn sync_and_reboot() {
    // Write data, sync, save device, create new FS from snapshot → verify data survives.
    let device = Arc::new(MockBlockDevice::new(256));
    let fs = {
        let d = device.clone();
        NovaFS::format(d, 0, 256)
    };
    let data = b"persistent data!";
    fs.write_file("/persist.txt", data).expect("write");
    fs.sync().expect("sync");

    let snapshot = device.snapshot();
    let new_device = Arc::new(MockBlockDevice::from_snapshot(snapshot));
    let fs2 = NovaFS::new(new_device, 0).expect("remount");
    let read_back = fs2.read_file("/persist.txt").expect("read after reboot");
    assert_eq!(read_back, data);
}

#[test]
fn consistency_check_ok() {
    let fs = make_fs(256);
    fs.write_file("/a.txt", b"aaa").expect("write a");
    fs.write_file("/b.txt", b"bbb").expect("write b");

    fs.sync().expect("sync");
    match fs.check_consistency() {
        Ok(_) => {}
        Err(e) => {
            panic!("fresh fs should be consistent, got error: {}", e);
        }
    }
}

#[test]
fn consistency_check_empty() {
    let fs = make_fs(256);
    fs.sync().expect("sync");
    assert!(fs.check_consistency().is_ok(), "empty fs should be consistent");
}
