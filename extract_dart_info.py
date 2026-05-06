import io
import os
import re
import requests
import struct
import sys
import zipfile
import zlib
from struct import unpack

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE
from elftools.elf.sections import SymbolTableSection

# ── Mach-O constants ──────────────────────────────────────────────────────────

_MACHO_MAGIC_64  = 0xfeedfacf
_MACHO_CIGAM_64  = 0xcffaedfe  # byte-swapped (big-endian binary on LE host)
_MACHO_FAT_MAGIC = 0xcafebabe  # stored big-endian in the file

_MACHO_LC_SEGMENT_64         = 0x19
_MACHO_LC_SYMTAB             = 0x02
_MACHO_LC_VERSION_MIN_MACOSX = 0x24
_MACHO_LC_VERSION_MIN_IOS    = 0x25
_MACHO_LC_BUILD_VERSION      = 0x32

_CPU_TYPE_ARM64  = 0x0100000C
_CPU_TYPE_X86_64 = 0x01000007

_BUILD_PLATFORM_MACOS = 1
_BUILD_PLATFORM_IOS   = 2

# ── Mach-O helpers ────────────────────────────────────────────────────────────

def _is_macho(path: str) -> bool:
    with open(path, 'rb') as f:
        raw = f.read(4)
    if len(raw) < 4:
        return False
    magic_le = struct.unpack('<I', raw)[0]
    magic_be = struct.unpack('>I', raw)[0]
    return magic_le in (_MACHO_MAGIC_64, _MACHO_CIGAM_64) or magic_be == _MACHO_FAT_MAGIC

def _fat_find_slice(data: bytes) -> bytes:
    """Return the arm64 (preferred) or x64 slice bytes from a fat Mach-O binary."""
    nfat_arch = struct.unpack_from('>I', data, 4)[0]
    slices = {}
    for i in range(nfat_arch):
        off = 8 + i * 20  # fat_arch is 20 bytes, all big-endian
        cputype, _, arch_offset, arch_size, _ = struct.unpack_from('>iiIII', data, off)
        slices[cputype] = (arch_offset, arch_size)
    for cpu in (_CPU_TYPE_ARM64, _CPU_TYPE_X86_64):
        if cpu in slices:
            o, s = slices[cpu]
            return data[o:o + s]
    raise ValueError("Fat Mach-O: no arm64 or x64 slice found")

def _macho_get_data(path: str) -> bytes:
    """Read file and, if it is a fat binary, return the preferred arch slice."""
    with open(path, 'rb') as f:
        data = f.read()
    if struct.unpack_from('>I', data, 0)[0] == _MACHO_FAT_MAGIC:
        data = _fat_find_slice(data)
    return data

def _macho_parse_load_cmds(data: bytes):
    """
    Walk all load commands in a thin Mach-O binary.
    Returns (segments, symoff, nsyms, stroff, os_name, arch).
      segments = list of (vmaddr, vmsize, fileoff)
      os_name  = 'ios' | 'macos' | None
    """
    _, cputype, _, _, ncmds, _, _, _ = struct.unpack_from('<IiIIIIII', data, 0)

    if cputype == _CPU_TYPE_ARM64:
        arch = 'arm64'
    elif cputype == _CPU_TYPE_X86_64:
        arch = 'x64'
    else:
        raise ValueError(f"Unsupported Mach-O cpu type: 0x{cputype & 0xFFFFFFFF:08x}")

    offset = 32  # sizeof(mach_header_64)
    segments = []
    symoff = nsyms = stroff = 0
    os_name = None

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, offset)
        if cmd == _MACHO_LC_SEGMENT_64:
            # segment_command_64: cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8) ...
            vmaddr, vmsize, fileoff = struct.unpack_from('<QQQ', data, offset + 24)
            segments.append((vmaddr, vmsize, fileoff))
        elif cmd == _MACHO_LC_SYMTAB:
            symoff, nsyms, stroff, _ = struct.unpack_from('<IIII', data, offset + 8)
        elif cmd == _MACHO_LC_BUILD_VERSION:
            platform = struct.unpack_from('<I', data, offset + 8)[0]
            if platform == _BUILD_PLATFORM_MACOS:
                os_name = 'macos'
            elif platform == _BUILD_PLATFORM_IOS:
                os_name = 'ios'
        elif cmd == _MACHO_LC_VERSION_MIN_IOS and os_name is None:
            os_name = 'ios'
        elif cmd == _MACHO_LC_VERSION_MIN_MACOSX and os_name is None:
            os_name = 'macos'
        offset += cmdsize

    return segments, symoff, nsyms, stroff, os_name, arch

def _macho_va_to_offset(va: int, segments: list):
    for vmaddr, vmsize, fileoff in segments:
        if vmaddr <= va < vmaddr + vmsize:
            return fileoff + (va - vmaddr)
    return None

def _macho_find_symbol(data: bytes, segments: list, symoff: int, nsyms: int,
                       stroff: int, sym_name: str):
    """Return the file offset for a named symbol, or None if not found."""
    NLIST64_SIZE = 16  # n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(8)
    for i in range(nsyms):
        n_strx, _, _, _, n_value = struct.unpack_from('<IBBHQ', data, symoff + i * NLIST64_SIZE)
        if n_value == 0:
            continue
        name_start = stroff + n_strx
        name_end = data.index(b'\x00', name_start)
        if data[name_start:name_end] == sym_name.encode():
            return _macho_va_to_offset(n_value, segments)
    return None

# ── Snapshot hash / flags extraction ──────────────────────────────────────────

def extract_snapshot_hash_flags_macho(libapp_file: str):
    data = _macho_get_data(libapp_file)
    segments, symoff, nsyms, stroff, _, _ = _macho_parse_load_cmds(data)
    file_off = _macho_find_symbol(data, segments, symoff, nsyms, stroff,
                                  '_kDartVmSnapshotData')
    if file_off is None:
        raise ValueError("Mach-O: Cannot find _kDartVmSnapshotData symbol")
    snapshot_hash = data[file_off + 20:file_off + 52].decode('ascii')
    flags_raw = data[file_off + 52:file_off + 52 + 256]
    flags = flags_raw[:flags_raw.index(b'\x00')].decode('utf-8').strip().split(' ')
    return snapshot_hash, flags

def extract_snapshot_hash_flags(libapp_file: str):
    if _is_macho(libapp_file):
        return extract_snapshot_hash_flags_macho(libapp_file)
    with open(libapp_file, 'rb') as f:
        elf = ELFFile(f)
        # find "_kDartVmSnapshotData" symbol
        dynsym = elf.get_section_by_name('.dynsym')
        sym = dynsym.get_symbol_by_name('_kDartVmSnapshotData')[0]
        #section = elf.get_section(sym['st_shndx'])
        assert sym['st_size'] > 128
        f.seek(sym['st_value']+20)
        snapshot_hash = f.read(32).decode()
        data = f.read(256) # should be enough
        flags = data[:data.index(b'\0')].decode().strip().split(' ')

    return snapshot_hash, flags

# ── Flutter framework info extraction ─────────────────────────────────────────

def extract_libflutter_info_macho(libflutter_file: str):
    data = _macho_get_data(libflutter_file)
    segments, symoff, nsyms, stroff, os_name, arch = _macho_parse_load_cmds(data)

    # Fallback: arm64 without explicit platform info is most likely iOS
    if os_name is None:
        os_name = 'ios' if arch == 'arm64' else 'macos'

    # Search binary data for Flutter engine SHA-1 hashes (40-char hex, null-delimited)
    sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', data)
    seen = set()
    engine_ids = []
    for h in sha_hashes:
        decoded = h.decode()
        if decoded not in seen:
            seen.add(decoded)
            engine_ids.append(decoded)

    assert len(engine_ids) >= 2, f'Expected >=2 Flutter engine hashes, found {len(engine_ids)}'
    engine_ids = engine_ids[:2]

    m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
    dart_version = m.group(1).decode() if m else None

    return engine_ids, dart_version, arch, os_name

def extract_libflutter_info(libflutter_file: str):
    if _is_macho(libflutter_file):
        return extract_libflutter_info_macho(libflutter_file)
    with open(libflutter_file, 'rb') as f:
        elf = ELFFile(f)
        if elf.header.e_machine == 'EM_AARCH64': # 183
            arch = 'arm64'
        elif elf.header.e_machine == 'EM_IA_64': # 50
            arch = 'x64'
        else:
            assert False, f"Unsupport architecture: {elf.header.e_machine}"

        section = elf.get_section_by_name('.rodata')
        data = section.data()

        sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', data)
        #print(sha_hashes)
        # all possible engine ids
        engine_ids = [ h.decode() for h in sha_hashes ]
        assert len(engine_ids) == 2, f'found hashes {", ".join(engine_ids)}'

        # beta/dev version of flutter might not use stable dart version (we can get dart version from sdk with found engine_id)
        # support stable, beta and dev channels
        m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
        if m is None:
            dart_version = None
        else:
            dart_version = m.group(1).decode()

    return engine_ids, dart_version, arch, 'android'

# ── Flutter SDK remote lookup (unchanged) ─────────────────────────────────────

def get_dart_sdk_url_size(engine_ids):
    #url = f'https://storage.googleapis.com/dart-archive/channels/stable/release/3.0.3/sdk/dartsdk-windows-x64-release.zip'
    for engine_id in engine_ids:
        url = f'https://storage.googleapis.com/flutter_infra_release/flutter/{engine_id}/dart-sdk-windows-x64.zip'
        resp = requests.head(url)
        if resp.status_code == 200:
           sdk_size = int(resp.headers['Content-Length'])
           return engine_id, url, sdk_size

    return None, None, None

def get_dart_commit(url):
    # in downloaded zip
    # * dart-sdk/revision - the dart commit id of https://github.com/dart-lang/sdk/
    # * dart-sdk/version  - the dart version
    # revision and version zip file records should be in first 4096 bytes
    # using stream in case a server does not support range
    commit_id = None
    dart_version = None
    fp = None
    with requests.get(url, headers={"Range": "bytes=0-4096"}, stream=True) as r:
        if r.status_code // 10 == 20:
            x = next(r.iter_content(chunk_size=4096))
            fp = io.BytesIO(x)

    if fp is not None:
        while fp.tell() < 4096-30 and (commit_id is None or dart_version is None):
            #sig, ver, flags, compression, filetime, filedate, crc, compressSize, uncompressSize, filenameLen, extraLen = unpack(fp, '<IHHHHHIIIHH')
            _, _, _, compMethod, _, _, _, compressSize, _, filenameLen, extraLen = unpack('<IHHHHHIIIHH', fp.read(30))
            filename = fp.read(filenameLen)
            #print(filename)
            if extraLen > 0:
                fp.seek(extraLen, io.SEEK_CUR)
            data = fp.read(compressSize)

            # expect compression method to be zipfile.ZIP_DEFLATED
            assert compMethod == zipfile.ZIP_DEFLATED, 'Unexpected compression method'
            if filename == b'dart-sdk/revision':
                commit_id = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
            elif filename == b'dart-sdk/version':
                dart_version = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()

    # TODO: if no revision and version in first 4096 bytes, get the file location from the first zip dir entries at the end of file (less than 256KB)
    return commit_id, dart_version

def extract_dart_info(libapp_file: str, libflutter_file: str):
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_file)
    #print('snapshot hash', snapshot_hash)
    #print(flags)

    engine_ids, dart_version, arch, os_name = extract_libflutter_info(libflutter_file)
    # print('possible engine ids', engine_ids)
    # print('dart version', dart_version)

    if dart_version is None:
        engine_id, sdk_url, sdk_size = get_dart_sdk_url_size(engine_ids)
        # print(engine_id)
        # print(sdk_url)
        # print(sdk_size)

        commit_id, dart_version = get_dart_commit(sdk_url)
        # print(commit_id)
        # print(dart_version)
        #assert dart_version == dart_version_sdk

    return dart_version, snapshot_hash, flags, arch, os_name


if __name__ == "__main__":
    if len(sys.argv) == 3:
        # Direct file paths: extract_dart_info.py <libapp> <libflutter>
        libapp_file = sys.argv[1]
        libflutter_file = sys.argv[2]
    else:
        # Legacy: directory containing libapp.so + libflutter.so
        libdir = sys.argv[1]
        libapp_file = os.path.join(libdir, 'libapp.so')
        libflutter_file = os.path.join(libdir, 'libflutter.so')

    print(extract_dart_info(libapp_file, libflutter_file))
