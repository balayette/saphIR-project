#pragma once

#include <sys/mman.h>
#include <string>
namespace utils
{
class mapped_file
{
      public:
	mapped_file(const std::string &filename,
		    int prot = PROT_WRITE | PROT_READ);
	~mapped_file();

	template <typename Dest>
	void read(Dest *dest, size_t offt, size_t num = 1);

	template <typename Dest, typename Size> Dest *ptr(Size offt);

	void *data() { return data_; }

      private:
	std::string filename_;
	int prot_;
	size_t size_;

	int fd_;
	uint8_t *data_;
};
} // namespace utils
#include "fs.hxx"
