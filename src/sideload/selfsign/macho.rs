//! Mach-O binary parsing + signature injection.
//!
//! Reference: isideload/sideload/macho.d

use anyhow::{anyhow, bail, Result};

// === Constants ===
pub const MH_MAGIC: u32 = 0xfeedface;
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const FAT_MAGIC: u32 = 0xcafebabe;

pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SEGMENT_64: u32 = 0x19;

pub const MH_EXECUTE: u32 = 0x2;

pub const PAGE_SIZE_LOG2: u32 = 14;
pub const PAGE_SIZE: u32 = 1 << PAGE_SIZE_LOG2;

// === MachO struct ===
pub struct MachO {
    pub data: Vec<u8>,
    pub header_size: usize,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub filetype: u32,
    pub is_64bit: bool,
    pub code_signature_offset: usize,
    pub code_signature_size: u32,
    pub linkedit_offset: Option<usize>,
    pub text_offset: Option<usize>,
    pub text_size: u64,
}

impl MachO {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            bail!("File quá nhỏ");
        }

        let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        if magic_be == FAT_MAGIC {
            return Self::parse_fat(data);
        }

        let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        if magic_le == MH_MAGIC_64 {
            Self::parse_thin_64(data)
        } else if magic_le == MH_MAGIC {
            Self::parse_thin_32(data)
        } else {
            bail!("Magic không nhận dạng: 0x{:08x}", magic_le);
        }
    }

    fn parse_fat(data: &[u8]) -> Result<Self> {
        if data.len() < 16 {
            bail!("FAT header quá nhỏ");
        }

        // fat_header: magic(4) nfat_arch(4) = 8 bytes
        // fat_arch[0]: cputype(4) cpusubtype(4) offset(4) size(4) align(4) = 20 bytes
        let slice_offset = u32::from_be_bytes([
            data[8 + 8], data[8 + 9], data[8 + 10], data[8 + 11],
        ]) as usize;
        let slice_size = u32::from_be_bytes([
            data[8 + 12], data[8 + 13], data[8 + 14], data[8 + 15],
        ]) as usize;

        if slice_offset + slice_size > data.len() {
            bail!("FAT slice out of bounds");
        }

        let slice = data[slice_offset..slice_offset + slice_size].to_vec();
        Self::parse(&slice)
    }

    fn parse_thin_64(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            bail!("Header 64-bit quá nhỏ");
        }

        let cpu_type = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let cpu_subtype = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let filetype = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let ncmds = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let sizeofcmds = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        let mut macho = MachO {
            data: data.to_vec(),
            header_size: 32,
            cpu_type, cpu_subtype, filetype, ncmds, sizeofcmds,
            is_64bit: true,
            code_signature_offset: 0,
            code_signature_size: 0,
            linkedit_offset: None,
            text_offset: None,
            text_size: 0,
        };

        macho.scan_load_commands()?;
        Ok(macho)
    }

    fn parse_thin_32(data: &[u8]) -> Result<Self> {
        if data.len() < 28 {
            bail!("Header 32-bit quá nhỏ");
        }

        let cpu_type = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let cpu_subtype = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let filetype = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let ncmds = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let sizeofcmds = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        let mut macho = MachO {
            data: data.to_vec(),
            header_size: 28,
            cpu_type, cpu_subtype, filetype, ncmds, sizeofcmds,
            is_64bit: false,
            code_signature_offset: 0,
            code_signature_size: 0,
            linkedit_offset: None,
            text_offset: None,
            text_size: 0,
        };

        macho.scan_load_commands()?;
        Ok(macho)
    }

    fn scan_load_commands(&mut self) -> Result<()> {
        let mut pos = self.header_size;
        let end = self.header_size + self.sizeofcmds as usize;

        if end > self.data.len() {
            bail!("Load commands vượt file");
        }

        for _ in 0..self.ncmds {
            if pos + 8 > self.data.len() {
                bail!("Load command vượt file");
            }

            let cmd = u32::from_le_bytes([
                self.data[pos], self.data[pos+1], self.data[pos+2], self.data[pos+3],
            ]);
            let cmdsize = u32::from_le_bytes([
                self.data[pos+4], self.data[pos+5], self.data[pos+6], self.data[pos+7],
            ]) as usize;

            if cmdsize < 8 || pos + cmdsize > self.data.len() {
                bail!("cmdsize không hợp lệ: {}", cmdsize);
            }

            match cmd {
                LC_CODE_SIGNATURE => {
                    self.code_signature_offset = u32::from_le_bytes([
                        self.data[pos+8], self.data[pos+9], self.data[pos+10], self.data[pos+11],
                    ]) as usize;
                    self.code_signature_size = u32::from_le_bytes([
                        self.data[pos+12], self.data[pos+13], self.data[pos+14], self.data[pos+15],
                    ]);
                }
                LC_SEGMENT_64 if cmdsize >= 72 => {
                    let segname = &self.data[pos+8..pos+24];
                    let segname_str = String::from_utf8_lossy(segname)
                        .trim_end_matches('\0').to_string();

                    let fileoff = u64::from_le_bytes([
                        self.data[pos+40], self.data[pos+41], self.data[pos+42], self.data[pos+43],
                        self.data[pos+44], self.data[pos+45], self.data[pos+46], self.data[pos+47],
                    ]) as usize;
                    let filesize = u64::from_le_bytes([
                        self.data[pos+48], self.data[pos+49], self.data[pos+50], self.data[pos+51],
                        self.data[pos+52], self.data[pos+53], self.data[pos+54], self.data[pos+55],
                    ]);

                    if segname_str == "__LINKEDIT" {
                        self.linkedit_offset = Some(fileoff);
                    } else if segname_str == "__TEXT" {
                        self.text_offset = Some(fileoff);
                        self.text_size = filesize;
                    }
                }
                LC_SEGMENT if cmdsize >= 56 => {
                    let segname = &self.data[pos+8..pos+24];
                    let segname_str = String::from_utf8_lossy(segname)
                        .trim_end_matches('\0').to_string();

                    let fileoff = u32::from_le_bytes([
                        self.data[pos+32], self.data[pos+33], self.data[pos+34], self.data[pos+35],
                    ]) as usize;
                    let filesize = u32::from_le_bytes([
                        self.data[pos+36], self.data[pos+37], self.data[pos+38], self.data[pos+39],
                    ]) as u64;

                    if segname_str == "__LINKEDIT" {
                        self.linkedit_offset = Some(fileoff);
                    } else if segname_str == "__TEXT" {
                        self.text_offset = Some(fileoff);
                        self.text_size = filesize;
                    }
                }
                _ => {}
            }

            pos += cmdsize;
        }

        Ok(())
    }

    pub fn is_executable(&self) -> bool {
        self.filetype == MH_EXECUTE
    }

    pub fn code_limit(&self) -> usize {
        if self.code_signature_offset > 0 && self.code_signature_offset <= self.data.len() {
            self.code_signature_offset
        } else {
            self.data.len()
        }
    }
}

/// Inject SuperBlob vào Mach-O binary.
pub fn inject_signature(data: &[u8], superblob: &[u8]) -> Result<Vec<u8>> {
    let macho = MachO::parse(data)?;
    let mut out = macho.data.clone();

    let section_size = page_ceil(superblob.len() as u32) as usize;

    // Tìm LC_CODE_SIGNATURE
    let mut cs_cmd_pos: Option<usize> = None;
    {
        let mut pos = macho.header_size;
        for _ in 0..macho.ncmds {
            let cmd = u32::from_le_bytes([
                out[pos], out[pos+1], out[pos+2], out[pos+3],
            ]);
            if cmd == LC_CODE_SIGNATURE {
                cs_cmd_pos = Some(pos);
                break;
            }
            let cmdsize = u32::from_le_bytes([
                out[pos+4], out[pos+5], out[pos+6], out[pos+7],
            ]) as usize;
            pos += cmdsize;
        }
    }

    if let Some(cmd_pos) = cs_cmd_pos {
        let old_dataoff = u32::from_le_bytes([
            out[cmd_pos+8], out[cmd_pos+9], out[cmd_pos+10], out[cmd_pos+11],
        ]) as usize;
        let old_datasize = u32::from_le_bytes([
            out[cmd_pos+12], out[cmd_pos+13], out[cmd_pos+14], out[cmd_pos+15],
        ]) as usize;

        if superblob.len() <= old_datasize {
            out[old_dataoff..old_dataoff + superblob.len()]
                .copy_from_slice(superblob);
            for i in (old_dataoff + superblob.len())..(old_dataoff + old_datasize) {
                out[i] = 0;
            }
            return Ok(out);
        }

        // Truncate
        out.truncate(old_dataoff);
    } else {
        // Thêm LC_CODE_SIGNATURE mới
        let commands_end = macho.header_size + macho.sizeofcmds as usize;
        let next_page = page_floor(commands_end as u32 + 16) as usize;

        if next_page < commands_end + 16 {
            bail!("Không đủ chỗ thêm LC_CODE_SIGNATURE");
        }

        let mut new_cmd = [0u8; 16];
        new_cmd[0..4].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        new_cmd[4..8].copy_from_slice(&16u32.to_le_bytes());

        out.splice(commands_end..commands_end, new_cmd.iter().copied());

        let new_ncmds = macho.ncmds + 1;
        let new_sizeofcmds = macho.sizeofcmds + 16;

        out[16..20].copy_from_slice(&new_ncmds.to_le_bytes());
        out[20..24].copy_from_slice(&new_sizeofcmds.to_le_bytes());

        cs_cmd_pos = Some(commands_end);
    }

    let cmd_pos = cs_cmd_pos.ok_or_else(|| anyhow!("Không tìm được LC_CODE_SIGNATURE"))?;
    let new_dataoff = out.len() as u32;

    // Update LC_CODE_SIGNATURE dataoff + datasize
    out[cmd_pos+8..cmd_pos+12].copy_from_slice(&new_dataoff.to_le_bytes());
    out[cmd_pos+12..cmd_pos+16].copy_from_slice(&(superblob.len() as u32).to_le_bytes());

    // Update __LINKEDIT segment size
    update_linkedit(&mut out, &macho, section_size)?;

    // Append superblob
    out.extend_from_slice(superblob);

    // Pad to page
    let aligned = page_ceil(out.len() as u32) as usize;
    while out.len() < aligned {
        out.push(0);
    }

    Ok(out)
}

fn update_linkedit(out: &mut [u8], macho: &MachO, section_size: usize) -> Result<()> {
    if macho.linkedit_offset.is_none() {
        return Ok(());
    }

    let mut pos = macho.header_size;
    for _ in 0..macho.ncmds {
        let cmd = u32::from_le_bytes([out[pos], out[pos+1], out[pos+2], out[pos+3]]);
        let cmdsize = u32::from_le_bytes([out[pos+4], out[pos+5], out[pos+6], out[pos+7]]) as usize;

        if cmd == LC_SEGMENT_64 {
            let segname = String::from_utf8_lossy(&out[pos+8..pos+24])
                .trim_end_matches('\0').to_string();
            if segname == "__LINKEDIT" {
                let old_vmsize = u64::from_le_bytes([
                    out[pos+32], out[pos+33], out[pos+34], out[pos+35],
                    out[pos+36], out[pos+37], out[pos+38], out[pos+39],
                ]);
                let old_filesize = u64::from_le_bytes([
                    out[pos+48], out[pos+49], out[pos+50], out[pos+51],
                    out[pos+52], out[pos+53], out[pos+54], out[pos+55],
                ]);

                let extra_file = section_size as u64
                    - page_floor(old_filesize as u32) as u64;
                let extra_vm = section_size as u64
                    - page_floor(old_vmsize as u32) as u64;

                out[pos+32..pos+40].copy_from_slice(
                    &(old_vmsize + extra_vm).to_le_bytes());
                out[pos+48..pos+56].copy_from_slice(
                    &(old_filesize + extra_file).to_le_bytes());
            }
        } else if cmd == LC_SEGMENT {
            let segname = String::from_utf8_lossy(&out[pos+8..pos+24])
                .trim_end_matches('\0').to_string();
            if segname == "__LINKEDIT" {
                let old_vmsize = u32::from_le_bytes([
                    out[pos+28], out[pos+29], out[pos+30], out[pos+31],
                ]) as u64;
                let old_filesize = u32::from_le_bytes([
                    out[pos+36], out[pos+37], out[pos+38], out[pos+39],
                ]) as u64;

                let extra_file = section_size as u64
                    - page_floor(old_filesize as u32) as u64;
                let extra_vm = section_size as u64
                    - page_floor(old_vmsize as u32) as u64;

                out[pos+28..pos+32].copy_from_slice(
                    &((old_vmsize + extra_vm) as u32).to_le_bytes());
                out[pos+36..pos+40].copy_from_slice(
                    &((old_filesize + extra_file) as u32).to_le_bytes());
            }
        }

        pos += cmdsize;
    }

    Ok(())
}

fn page_floor(v: u32) -> u32 { v & !(PAGE_SIZE - 1) }
fn page_ceil(v: u32) -> u32 { (v + PAGE_SIZE - 1) & !(PAGE_SIZE - 1) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_functions() {
        assert_eq!(page_floor(0), 0);
        assert_eq!(page_floor(16384), 16384);
        assert_eq!(page_ceil(1), 16384);
        assert_eq!(page_ceil(16385), 32768);
    }
}
