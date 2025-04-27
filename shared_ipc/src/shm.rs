// در shared_ipc/src/shm.rs
use memmap2::MmapMut;
use std::fs::File;
use std::io::{self};

pub struct SharedMemoryWriter {
    mmap: MmapMut,
    file: File,
}

impl SharedMemoryWriter {
    pub fn new(path: &str, size: usize) -> io::Result<Self> {
        let file = File::create(path)?;
        file.set_len(size as u64)?;
        let mmap = unsafe { MmapMut::map_mut(&file)? };

        Ok(Self { mmap, file })
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let len = data.len() as u32;
        let len_bytes = len.to_le_bytes();

        // Write length at the start
        self.mmap[..4].copy_from_slice(&len_bytes);
        self.mmap[4..(4 + data.len())].copy_from_slice(data);

        // Flush data to disk
        self.flush()?;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        // Flush the memory mapping to disk (write it to the actual file)
        self.mmap.flush()?;
        self.file.sync_all()?;
        Ok(())
    }

    pub fn clear(&mut self) -> io::Result<()> {
        // Set memory to 0 (optional - clearing data)
        self.mmap.fill(0);
        self.flush()?;
        Ok(())
    }
}

impl Drop for SharedMemoryWriter {
    fn drop(&mut self) {
        // Clean up: ensure to flush any final changes
        let _ = self.flush();
    }
}
