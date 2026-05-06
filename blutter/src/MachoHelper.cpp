#include "pch.h"
#include "MachoHelper.h"
#include <stdexcept>
#include <vector>

// Mach-O types defined locally so this file compiles on any host OS
// and against any Dart VM version (dart's mach_o.h was added in ~2.19).
namespace {

static constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf;
static constexpr uint32_t MH_CIGAM_64 = 0xcffaedfe; // byte-swapped
static constexpr uint32_t FAT_MAGIC_LE = 0xbebafeca; // 0xcafebabe stored big-endian

static constexpr uint32_t LC_SEGMENT_64 = 0x19;
static constexpr uint32_t LC_SYMTAB     = 0x02;

#pragma pack(push, 1)
struct mach_header_64 {
	uint32_t magic; int32_t cputype; int32_t cpusubtype;
	uint32_t filetype; uint32_t ncmds; uint32_t sizeofcmds;
	uint32_t flags; uint32_t reserved;
};
struct load_cmd {
	uint32_t cmd; uint32_t cmdsize;
};
struct segment_command_64 {
	uint32_t cmd; uint32_t cmdsize;
	char segname[16];
	uint64_t vmaddr; uint64_t vmsize;
	uint64_t fileoff; uint64_t filesize;
	uint32_t maxprot; uint32_t initprot;
	uint32_t nsects; uint32_t flags;
};
struct symtab_command {
	uint32_t cmd; uint32_t cmdsize;
	uint32_t symoff; uint32_t nsyms;
	uint32_t stroff; uint32_t strsize;
};
struct nlist_64 {
	uint32_t n_strx; uint8_t n_type; uint8_t n_sect;
	uint16_t n_desc; uint64_t n_value;
};
#pragma pack(pop)

static uint32_t bswap32(uint32_t v) {
	return ((v & 0xFF) << 24) | ((v >> 8 & 0xFF) << 16) | ((v >> 16 & 0xFF) << 8) | (v >> 24);
}

// Fat (universal) binary: return pointer to the arm64 or x64 Mach-O slice.
// All fat header fields are stored big-endian.
static const uint8_t* findSliceInFat(const uint8_t* base)
{
	static constexpr int32_t CPU_ARM64  = 0x0100000C;
	static constexpr int32_t CPU_X86_64 = 0x01000007;

	const uint32_t nfat_arch = bswap32(*reinterpret_cast<const uint32_t*>(base + 4));
	const uint8_t* arch_ptr = base + 8;
	const uint8_t* arm64 = nullptr, *x64 = nullptr;

	// fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4) — all big-endian
	for (uint32_t i = 0; i < nfat_arch; i++, arch_ptr += 20) {
		const int32_t  cputype = static_cast<int32_t>(bswap32(*reinterpret_cast<const uint32_t*>(arch_ptr)));
		const uint32_t offset  = bswap32(*reinterpret_cast<const uint32_t*>(arch_ptr + 8));
		if (cputype == CPU_ARM64)       arm64 = base + offset;
		else if (cputype == CPU_X86_64) x64   = base + offset;
	}

	if (arm64) return arm64;
	if (x64)   return x64;
	throw std::invalid_argument("Mach-O fat binary: no arm64 or x64 slice found");
}

static LibAppInfo findSnapshotsFromMachO(const uint8_t* base)
{
	const auto* hdr = reinterpret_cast<const mach_header_64*>(base);
	if (hdr->magic != MH_MAGIC_64)
		throw std::invalid_argument("Mach-O: Expected 64-bit little-endian binary");

	// Walk load commands: collect segment VA→file mappings and find symbol table
	struct SegInfo { uint64_t vmaddr, vmsize, fileoff; };
	std::vector<SegInfo> segs;
	uint32_t symoff = 0, nsyms = 0, stroff = 0;

	const uint8_t* lc = base + sizeof(mach_header_64);
	for (uint32_t i = 0; i < hdr->ncmds; i++) {
		const auto* cmd = reinterpret_cast<const load_cmd*>(lc);
		if (cmd->cmd == LC_SEGMENT_64) {
			const auto* seg = reinterpret_cast<const segment_command_64*>(lc);
			segs.push_back({seg->vmaddr, seg->vmsize, seg->fileoff});
		} else if (cmd->cmd == LC_SYMTAB) {
			const auto* st = reinterpret_cast<const symtab_command*>(lc);
			symoff = st->symoff; nsyms = st->nsyms; stroff = st->stroff;
		}
		lc += cmd->cmdsize;
	}

	// Translate a virtual address to a pointer into the mmap'd file
	auto va_to_ptr = [&](uint64_t va) -> const uint8_t* {
		for (const auto& seg : segs)
			if (va >= seg.vmaddr && va < seg.vmaddr + seg.vmsize)
				return base + seg.fileoff + (va - seg.vmaddr);
		return nullptr;
	};

	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;

	const auto* sym = reinterpret_cast<const nlist_64*>(base + symoff);
	const char* strtab = reinterpret_cast<const char*>(base + stroff);
	for (uint32_t i = 0; i < nsyms; i++, sym++) {
		if (sym->n_value == 0) continue;
		const char* name = strtab + sym->n_strx;
		if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0)
			vm_snapshot_data = va_to_ptr(sym->n_value);
		else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0)
			vm_snapshot_instructions = va_to_ptr(sym->n_value);
		else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0)
			isolate_snapshot_data = va_to_ptr(sym->n_value);
		else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0)
			isolate_snapshot_instructions = va_to_ptr(sym->n_value);
	}

	if (!vm_snapshot_data)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Data");
	if (!vm_snapshot_instructions)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Instructions");
	if (!isolate_snapshot_data)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Data");
	if (!isolate_snapshot_instructions)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = base,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
}

} // anonymous namespace

bool MachoHelper::IsMacho(const uint8_t* data)
{
	const uint32_t magic = *reinterpret_cast<const uint32_t*>(data);
	return magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == FAT_MAGIC_LE;
}

LibAppInfo MachoHelper::findSnapshots(const uint8_t* base)
{
	uint32_t magic = *reinterpret_cast<const uint32_t*>(base);

	if (magic == FAT_MAGIC_LE) {
		base  = findSliceInFat(base);
		magic = *reinterpret_cast<const uint32_t*>(base);
	}

	if (magic == MH_CIGAM_64)
		throw std::invalid_argument("Mach-O: Expected a host-endian (little-endian) header");

	return findSnapshotsFromMachO(base);
}
