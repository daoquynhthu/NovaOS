use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
}

#[derive(Clone, Debug)]
pub struct FileStat {
    pub name: String,
    pub file_type: FileType,
    pub size: usize,
}

struct Node {
    file_type: FileType,
    data: Vec<u8>,
    children: BTreeMap<String, Node>,
}

impl Node {
    fn new_file() -> Self {
        Node {
            file_type: FileType::File,
            data: Vec::new(),
            children: BTreeMap::new(),
        }
    }

    fn new_dir() -> Self {
        Node {
            file_type: FileType::Directory,
            data: Vec::new(),
            children: BTreeMap::new(),
        }
    }
}

pub struct VirtualFileSystem {
    root: Node,
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        let root = Node::new_dir();
        Self { root }
    }

    // Helper to traverse path
    fn traverse_mut<'a>(&'a mut self, path: &str) -> Option<&'a mut Node> {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            return Some(&mut self.root);
        }

        let mut current = &mut self.root;
        for part in path.split('/') {
            if part.is_empty() { continue; }
            if !current.children.contains_key(part) {
                return None;
            }
            current = current.children.get_mut(part).unwrap();
        }
        Some(current)
    }
    
    fn traverse<'a>(&'a self, path: &str) -> Option<&'a Node> {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            return Some(&self.root);
        }

        let mut current = &self.root;
        for part in path.split('/') {
            if part.is_empty() { continue; }
            if !current.children.contains_key(part) {
                return None;
            }
            current = current.children.get(part).unwrap();
        }
        Some(current)
    }

    pub fn create_file(&mut self, path: &str) -> Result<(), &'static str> {
        let (parent_path, filename) = split_path(path);
        if let Some(parent) = self.traverse_mut(parent_path) {
            if parent.file_type != FileType::Directory {
                return Err("Parent is not a directory");
            }
            if parent.children.contains_key(filename) {
                return Err("File already exists");
            }
            parent.children.insert(filename.to_string(), Node::new_file());
            Ok(())
        } else {
            Err("Parent directory not found")
        }
    }

    pub fn create_dir(&mut self, path: &str) -> Result<(), &'static str> {
        let (parent_path, filename) = split_path(path);
        if let Some(parent) = self.traverse_mut(parent_path) {
            if parent.file_type != FileType::Directory {
                return Err("Parent is not a directory");
            }
            if parent.children.contains_key(filename) {
                return Err("Directory already exists");
            }
            parent.children.insert(filename.to_string(), Node::new_dir());
            Ok(())
        } else {
            Err("Parent directory not found")
        }
    }

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<usize, &'static str> {
        if let Some(node) = self.traverse_mut(path) {
            if node.file_type != FileType::File {
                return Err("Not a file");
            }
            node.data = data.to_vec();
            Ok(node.data.len())
        } else {
            Err("File not found")
        }
    }
    
    #[allow(dead_code)]
    pub fn append_file(&mut self, path: &str, data: &[u8]) -> Result<usize, &'static str> {
        if let Some(node) = self.traverse_mut(path) {
            if node.file_type != FileType::File {
                return Err("Not a file");
            }
            node.data.extend_from_slice(data);
            Ok(node.data.len())
        } else {
            Err("File not found")
        }
    }

    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        if let Some(node) = self.traverse(path) {
            if node.file_type == FileType::File {
                Some(node.data.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn list_dir(&self, path: &str) -> Option<Vec<FileStat>> {
        if let Some(node) = self.traverse(path) {
            if node.file_type == FileType::Directory {
                let mut entries = Vec::new();
                for (name, child) in &node.children {
                    entries.push(FileStat {
                        name: name.clone(),
                        file_type: child.file_type,
                        size: child.data.len(),
                    });
                }
                Some(entries)
            } else {
                None
            }
        } else {
            None
        }
    }
    
    pub fn exists(&self, path: &str) -> bool {
        self.traverse(path).is_some()
    }

    pub fn remove(&mut self, path: &str) -> Result<(), &'static str> {
        let (parent_path, filename) = split_path(path);
        if let Some(parent) = self.traverse_mut(parent_path) {
            if parent.file_type != FileType::Directory {
                return Err("Parent is not a directory");
            }
            if parent.children.remove(filename).is_some() {
                Ok(())
            } else {
                Err("File or directory not found")
            }
        } else {
            Err("Parent directory not found")
        }
    }
}

fn split_path(path: &str) -> (&str, &str) {
    let path = path.trim_end_matches('/');
    if let Some(idx) = path.rfind('/') {
        (&path[..idx], &path[idx+1..])
    } else {
        ("", path) // Root relative
    }
}

pub static VFS: Mutex<Option<VirtualFileSystem>> = Mutex::new(None);

pub fn init() {
    let mut fs = VirtualFileSystem::new();
    // Default directories
    fs.create_dir("/home").unwrap();
    fs.create_dir("/bin").unwrap();
    
    *VFS.lock() = Some(fs);
}
