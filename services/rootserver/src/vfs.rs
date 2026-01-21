use alloc::string::String;
use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::Mutex;

// Global VFS instance
pub static VFS: Mutex<Option<Arc<dyn FileSystem>>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: usize,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub inode_number: u64,
    pub nlink: u32,
}

impl FileStat {
    pub fn check_access(&self, uid: u32, gid: u32, access_mask: u16) -> bool {
        if uid == 0 { return true; } // Root always has access

        let effective_mode = if self.uid == uid {
            (self.mode >> 6) & 0x7
        } else if self.gid == gid {
            (self.mode >> 3) & 0x7
        } else {
            self.mode & 0x7
        };
        
        (effective_mode & access_mask) == access_mask
    }
}

/// The Abstract File System Trait
#[allow(dead_code)]
pub trait FileSystem: Send + Sync {
    fn root_inode(&self) -> Arc<dyn Inode>;
    fn sync(&self) -> Result<(), &'static str>;

    fn resolve_path(&self, cwd: &str, path: &str) -> Result<Arc<dyn Inode>, &'static str> {
        self.resolve_path_ex(cwd, path, true)
    }

    fn resolve_path_ex(&self, cwd: &str, path: &str, follow_last: bool) -> Result<Arc<dyn Inode>, &'static str> {
        let mut symlink_depth = 0;
        const MAX_SYMLINKS: u32 = 8;

        let mut current = self.root_inode();
        let full_path = if path.starts_with('/') {
            String::from(path)
        } else {
            let mut s = String::from(cwd);
            if !s.ends_with('/') { s.push('/'); }
            s.push_str(path);
            s
        };
        
        let mut components: Vec<String> = Vec::new();
        for part in full_path.split('/') {
            if part.is_empty() || part == "." { continue; }
            if part == ".." {
                components.pop();
            } else {
                components.push(String::from(part));
            }
        }
        
        if full_path.starts_with('/') {
            current = self.root_inode();
        }

        let mut i = 0;
        while i < components.len() {
            let part = &components[i];
            let next_inode = current.lookup(part)?;
            
            let metadata = next_inode.metadata()?;
            if metadata.file_type == FileType::Symlink {
                // Check if we should follow
                if i == components.len() - 1 && !follow_last {
                     current = next_inode;
                     i += 1;
                     continue;
                }

                if symlink_depth >= MAX_SYMLINKS {
                    return Err("Too many symbolic links");
                }
                symlink_depth += 1;
                
                let mut content = alloc::vec![0u8; metadata.size];
                next_inode.read_at(0, &mut content)?;
                let target = String::from_utf8(content).map_err(|_| "Invalid symlink content")?;
                
                if target.starts_with('/') {
                    // Absolute
                    current = self.root_inode();
                    let remaining = components.split_off(i + 1);
                    components.clear();
                    for p in target.split('/') {
                        if p.is_empty() || p == "." { continue; }
                        if p == ".." { components.pop(); } else { components.push(String::from(p)); }
                    }
                    components.extend(remaining);
                    i = 0;
                } else {
                    // Relative
                    let remaining = components.split_off(i + 1);
                    // Remove the symlink itself (at i)
                    components.pop(); 
                    
                    for p in target.split('/') {
                         if p.is_empty() || p == "." { continue; }
                         components.push(String::from(p));
                    }
                    components.extend(remaining);
                    // i stays same
                }
            } else {
                current = next_inode;
                i += 1;
            }
        }
        Ok(current)
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, &'static str> {
        let inode = self.resolve_path("/", path)?;
        let stat = inode.metadata()?;
        let mut buf = alloc::vec![0u8; stat.size];
        inode.read_at(0, &mut buf)?;
        Ok(buf)
    }

    fn exists(&self, path: &str) -> bool {
        self.resolve_path("/", path).is_ok()
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn Inode>, &'static str> {
         if let Some(idx) = path.rfind('/') {
            let (parent_path, name) = path.split_at(idx);
            let name = &name[1..];
            let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
            let parent = self.resolve_path("/", parent_path)?;
            parent.create(name, FileType::File)
        } else {
            let root = self.root_inode();
            root.create(path, FileType::File)
        }
    }

    #[allow(dead_code)]
    fn list_dir(&self, path: &str) -> Result<Vec<String>, &'static str> {
        let inode = self.resolve_path("/", path)?;
        let entries = inode.list()?;
        Ok(entries.into_iter().map(|(name, _)| name).collect())
    }

    fn append_file(&self, path: &str, data: &[u8]) -> Result<usize, &'static str> {
        let inode = self.resolve_path("/", path)?;
        let stat = inode.metadata()?;
        inode.write_at(stat.size, data)
    }

    fn write_file(&self, path: &str, data: &[u8]) -> Result<usize, &'static str> {
        // Try to create first
        match self.create_file(path) {
            Ok(inode) => inode.write_at(0, data),
            Err(e) if e == "File exists" => {
                // Resolve existing inode and overwrite (truncate first)
                if let Some(idx) = path.rfind('/') {
                    let (parent_path, name) = path.split_at(idx);
                    let name = &name[1..];
                    let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
                    let parent = self.resolve_path("/", parent_path)?;
                    let inode = parent.lookup(name)?;
                    
                    // Try to truncate to 0 (Op 3)
                    // If not supported, we just overwrite (which might leave trailing garbage)
                    let _ = inode.control(3, 0);
                    
                    inode.write_at(0, data)
                } else {
                    let root = self.root_inode();
                    let inode = root.lookup(path)?;
                    let _ = inode.control(3, 0);
                    inode.write_at(0, data)
                }
            },
            Err(e) => Err(e),
        }
    }
}

/// The Abstract Inode Trait (File or Directory)
pub trait Inode: Send + Sync {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, &'static str>;
    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize, &'static str>;
    fn metadata(&self) -> Result<FileStat, &'static str>;
    fn sync(&self) -> Result<(), &'static str>;
    
    // Directory Operations
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, &'static str>;
    fn create(&self, name: &str, type_: FileType) -> Result<Arc<dyn Inode>, &'static str>;
    fn list(&self) -> Result<Vec<(alloc::string::String, Arc<dyn Inode>)>, &'static str>;
    fn remove(&self, name: &str) -> Result<(), &'static str>;
    fn link(&self, _name: &str, _other: &dyn Inode) -> Result<(), &'static str> {
        Err("Not supported")
    }
    fn rename(&self, _old_name: &str, _new_parent: &Arc<dyn Inode>, _new_name: &str) -> Result<(), &'static str> {
        Err("Not supported")
    }
    fn control(&self, _op: u32, _arg: u64) -> Result<u64, &'static str> {
        Err("Not supported")
    }
}

/// Helper to resolve path (Delegates to FileSystem trait)
pub fn resolve_path(fs: &Arc<dyn FileSystem>, cwd: &str, path: &str) -> Result<Arc<dyn Inode>, &'static str> {
    fs.resolve_path(cwd, path)
}

pub fn check_permission(inode: &Arc<dyn Inode>, uid: u32, gid: u32, access: u16) -> bool {
    let stat = match inode.metadata() {
        Ok(s) => s,
        Err(_) => return false,
    };

    stat.check_access(uid, gid, access)
}
