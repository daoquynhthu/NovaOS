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
}

#[derive(Debug, Clone)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: usize,
}

/// The Abstract File System Trait
#[allow(dead_code)]
pub trait FileSystem: Send + Sync {
    fn root_inode(&self) -> Arc<dyn Inode>;
    fn sync(&self) -> Result<(), &'static str>;

    fn resolve_path(&self, cwd: &str, path: &str) -> Result<Arc<dyn Inode>, &'static str> {
        let mut current = self.root_inode();
        let full_path = if path.starts_with('/') {
            String::from(path)
        } else {
            let mut s = String::from(cwd);
            if !s.ends_with('/') { s.push('/'); }
            s.push_str(path);
            s
        };
        
        for part in full_path.split('/') {
            if part.is_empty() || part == "." { continue; }
            if part == ".." { continue; } // TODO: Parent support
            current = current.lookup(part)?;
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
        inode.list()
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
                // Remove and recreate to overwrite
                if let Some(idx) = path.rfind('/') {
                    let (parent_path, name) = path.split_at(idx);
                    let name = &name[1..];
                    let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
                    let parent = self.resolve_path("/", parent_path)?;
                    parent.remove(name)?;
                    let inode = parent.create(name, FileType::File)?;
                    inode.write_at(0, data)
                } else {
                    let root = self.root_inode();
                    root.remove(path)?;
                    let inode = root.create(path, FileType::File)?;
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
    fn list(&self) -> Result<Vec<String>, &'static str>;
    fn remove(&self, name: &str) -> Result<(), &'static str>;
}

/// Helper to resolve path (Delegates to FileSystem trait)
pub fn resolve_path(fs: &Arc<dyn FileSystem>, cwd: &str, path: &str) -> Result<Arc<dyn Inode>, &'static str> {
    fs.resolve_path(cwd, path)
}
