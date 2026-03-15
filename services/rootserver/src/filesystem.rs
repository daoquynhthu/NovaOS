


pub struct File {
    pub name: &'static str,
    pub data: &'static [u8],
}

pub static FILES: &[File] = &[
    File {
        name: "hello",
        data: include_bytes!("../../../target/x86_64-unknown-none/release/user_app"),
    },
    File {
        name: "serial_server",
        data: include_bytes!("../../../target/x86_64-unknown-none/release/serial_server"),
    },
    File {
        name: "fs_server",
        data: include_bytes!("../../../target/x86_64-unknown-none/release/fs_server"),
    },
];

pub fn get_file(name: &str) -> Option<&'static [u8]> {
    for file in FILES {
        if file.name == name {
            return Some(file.data);
        }
    }
    None
}

#[allow(dead_code)]
pub fn list_files() {

    println!("Available files:");
    for file in FILES {
        println!("  - {} ({} bytes)", file.name, file.data.len());
    }
}
