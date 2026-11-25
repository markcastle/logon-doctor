//! Fetches Microsoft's public debug symbols for a system DLL.
//!
//! Without symbols a call stack can only say "somewhere in profsvc.dll, near this exported
//! function". With the matching PDB it gives the real function name, which usually says outright
//! what the code is doing. The PDB is identified by a GUID stored inside the DLL and downloaded
//! from Microsoft's public symbol server with the curl.exe that ships with Windows 10.
//!
//! Everything here is best effort: if any step fails the capture still works, just with vaguer
//! function names.

use std::path::Path;

/// The PDB file name and symbol-server id recorded in a PE file's debug directory.
fn pdb_identity(dll: &Path) -> Option<(String, String)> {
    let d = std::fs::read(dll).ok()?;
    let u16at = |o: usize| d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32at = |o: usize| d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));

    if d.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = u32at(0x3c)? as usize;
    if d.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = u16at(pe + 6)? as usize;
    let opt = pe + 24;
    let opt_size = u16at(pe + 20)? as usize;
    // Data directories start at a different offset in 32- and 64-bit images.
    let dirs = opt + if u16at(opt)? == 0x20b { 112 } else { 96 };
    let debug_rva = u32at(dirs + 6 * 8)? as usize;
    let debug_size = u32at(dirs + 6 * 8 + 4)? as usize;

    let section_table = opt + opt_size;
    let mut debug_off = None;
    for i in 0..sections {
        let s = section_table + i * 40;
        let vsize = u32at(s + 8)? as usize;
        let va = u32at(s + 12)? as usize;
        let rsize = u32at(s + 16)? as usize;
        let raw = u32at(s + 20)? as usize;
        if debug_rva >= va && debug_rva < va + vsize.max(rsize) {
            debug_off = Some(debug_rva - va + raw);
            break;
        }
    }
    let debug_off = debug_off?;

    for i in 0..debug_size / 28 {
        let e = debug_off + i * 28;
        if u32at(e + 12)? != 2 {
            continue; // not a CodeView entry
        }
        let size = u32at(e + 16)? as usize;
        let p = u32at(e + 24)? as usize;
        if d.get(p..p + 4)? != b"RSDS" {
            continue;
        }
        let tail: String = d.get(p + 12..p + 20)?.iter().map(|b| format!("{:02X}", b)).collect();
        let id = format!("{:08X}{:04X}{:04X}{}{:X}", u32at(p + 4)?, u16at(p + 8)?, u16at(p + 10)?, tail, u32at(p + 20)?);
        let name_bytes = d.get(p + 24..p + size)?;
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..end]).to_string();
        // Some builds record a full build-machine path; only the file name matters.
        let name = name.rsplit(['\\', '/']).next().unwrap_or("").to_string();
        if name.is_empty() {
            return None;
        }
        return Some((name, id));
    }
    None
}

/// Make sure `dir` holds the PDBs matching the named System32 DLLs. Returns progress lines.
pub fn fetch(dir: &Path, dlls: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let sys = Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join("System32");
    if std::fs::create_dir_all(dir).is_err() {
        out.push(format!("Symbols: could not create {}", dir.display()));
        return out;
    }
    for dll in dlls {
        let Some((pdb, id)) = pdb_identity(&sys.join(dll)) else {
            out.push(format!("Symbols: could not read the debug id of {}", dll));
            continue;
        };
        let dest = dir.join(&pdb);
        let marker = dir.join(format!("{}.id", pdb));
        if dest.exists() && std::fs::read_to_string(&marker).map(|s| s.trim() == id).unwrap_or(false) {
            out.push(format!("Symbols: {} already present", pdb));
            continue;
        }
        let url = format!("https://msdl.microsoft.com/download/symbols/{}/{}/{}", pdb, id, pdb);
        let result = std::process::Command::new(sys.join("curl.exe"))
            .args(["-sSL", "--fail", "--max-time", "90", "-A", "Microsoft-Symbol-Server/10.0.0.0", "-o"])
            .arg(&dest)
            .arg(&url)
            .output();
        match result {
            Ok(o) if o.status.success() && dest.metadata().map(|m| m.len() > 4096).unwrap_or(false) => {
                let _ = std::fs::write(&marker, &id);
                out.push(format!("Symbols: downloaded {} from Microsoft's symbol server", pdb));
            }
            Ok(o) => {
                let _ = std::fs::remove_file(&dest);
                out.push(format!(
                    "Symbols: could not download {} ({}). Function names will be approximate.",
                    pdb,
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
            Err(e) => out.push(format!("Symbols: could not run curl.exe ({}). Function names will be approximate.", e)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn id_format() {
        // GUID {497B72F6-390A-44FC-878E-5A2D63C6CC4B}, age 1 -> symbol server id
        let id = format!("{:08X}{:04X}{:04X}{}{:X}", 0x497B72F6u32, 0x390Au16, 0x44FCu16, "878E5A2D63C6CC4B", 1u32);
        assert_eq!(id, "497B72F6390A44FC878E5A2D63C6CC4B1");
    }
}
