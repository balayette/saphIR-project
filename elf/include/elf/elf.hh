#pragma once

#include <elf.h>
#include <string>
#include <vector>
#include "utils/view.hh"
#include "utils/fs.hh"

namespace elf
{
class elf_header
{
      public:
	elf_header() = default;
	elf_header(const Elf64_Ehdr &hdr)
	    : type_(hdr.e_type), machine_(hdr.e_machine),
	      version_(hdr.e_version), entry_(hdr.e_entry), flags_(hdr.e_flags)
	{
		ASSERT(std::memcmp(hdr.e_ident, ELFMAG, 4) == 0,
		       "Invalid elf header");
	}

	Elf64_Half type() const { return type_; }
	Elf64_Half machine() const { return machine_; }
	Elf64_Word version() const { return version_; }
	Elf64_Addr entry() const { return entry_; }
	Elf64_Word flags() const { return flags_; }

	std::string dump() const;

      private:
	Elf64_Half type_;
	Elf64_Half machine_;
	Elf64_Word version_;
	Elf64_Addr entry_;
	Elf64_Word flags_;
};

class section_header
{
      public:
	section_header(const std::string &name, const Elf64_Shdr &hdr)
	    : name_(name), type_(hdr.sh_type), flags_(hdr.sh_flags),
	      addr_(hdr.sh_addr), offset_(hdr.sh_offset), size_(hdr.sh_size),
	      link_(hdr.sh_link), align_(hdr.sh_addralign),
	      entsize_(hdr.sh_entsize)
	{
	}

	std::string name() const { return name_; }
	Elf64_Word type() const { return type_; }
	Elf64_Xword flags() const { return flags_; }
	Elf64_Addr addr() const { return addr_; }
	Elf64_Off offset() const { return offset_; }
	Elf64_Xword size() const { return size_; }
	Elf64_Word link() const { return link_; }
	Elf64_Xword align() const { return align_; }
	Elf64_Xword entsize() const { return entsize_; }

	utils::bufview<uint8_t> contents(const utils::mapped_file &file) const;

	std::string dump() const;

      private:
	std::string name_;
	Elf64_Word type_;
	Elf64_Xword flags_;
	Elf64_Addr addr_;
	Elf64_Off offset_;
	Elf64_Xword size_;
	Elf64_Word link_;
	Elf64_Xword align_;
	Elf64_Xword entsize_;
};

class program_header
{
      public:
	program_header(const Elf64_Phdr &hdr)
	    : type_(hdr.p_type), offset_(hdr.p_offset), vaddr_(hdr.p_vaddr),
	      paddr_(hdr.p_paddr), filesz_(hdr.p_filesz), memsz_(hdr.p_memsz),
	      align_(hdr.p_align)
	{
	}

	Elf64_Word type() const { return type_; }
	Elf64_Off offset() const { return offset_; }
	Elf64_Addr vaddr() const { return vaddr_; }
	Elf64_Addr paddr() const { return paddr_; }
	Elf64_Xword filesz() const { return filesz_; }
	Elf64_Xword memsz() const { return memsz_; }
	Elf64_Xword align() const { return align_; }

	utils::bufview<uint8_t> contents(const utils::mapped_file &file) const;

	std::string dump() const;

      private:
	Elf64_Word type_;
	Elf64_Off offset_;
	Elf64_Addr vaddr_;
	Elf64_Addr paddr_;
	Elf64_Xword filesz_;
	Elf64_Xword memsz_;
	Elf64_Xword align_;
};

class elf
{
      public:
	elf(utils::mapped_file &file);
	const elf_header &ehdr() { return ehdr_; }
	const std::vector<section_header> &shdrs() const { return shdrs_; }
	const std::vector<program_header> &phdrs() const { return phdrs_; }

	const section_header *section_by_name(const std::string &name);
	const program_header *segment_for_address(size_t addr);

	std::string dump() const;

      private:
	void build_sections(utils::mapped_file &file, const Elf64_Ehdr *ehdr);
	void build_program_headers(utils::mapped_file &file,
				   const Elf64_Ehdr *ehdr);

	elf_header ehdr_;
	std::vector<section_header> shdrs_;
	std::vector<program_header> phdrs_;
};

/*
 * Map a static ELF in memory
 */
std::pair<void *, size_t> map_elf(const elf &elf,
				  const utils::mapped_file &file);
} // namespace elf
