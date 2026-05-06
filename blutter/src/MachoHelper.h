#pragma once
#include <stdint.h>
#include "ElfHelper.h"

class MachoHelper final
{
public:
	// Returns true if the 4-byte magic at the start of data belongs to a
	// Mach-O binary (thin 64-bit) or a fat (universal) binary.
	static bool IsMacho(const uint8_t* data);

	// Given a pointer to a mmap'd file that begins with a Mach-O or fat
	// magic, locate all four Dart snapshot sections and return their
	// in-memory addresses.  Throws std::invalid_argument on failure.
	static LibAppInfo findSnapshots(const uint8_t* base);

private:
	MachoHelper() = delete;
};
