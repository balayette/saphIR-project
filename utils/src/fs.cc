#include "utils/fs.hh"
#include "utils/assert.hh"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

namespace utils
{
mapped_file::mapped_file(const std::string &filename, int prot)
    : filename_(filename), prot_(prot)
{
	fd_ = open(filename.c_str(), O_RDONLY);
	ASSERT(fd_ != -1, "Couldn't open file");

	struct stat buf;
	ASSERT(fstat(fd_, &buf) != -1, "Couldn't stat file");

	size_ = buf.st_size;

	data_ = static_cast<uint8_t *>(
		mmap(NULL, size_, prot_, MAP_PRIVATE, fd_, 0));
	ASSERT(data_ != MAP_FAILED, "mmap failed");
}

mapped_file::~mapped_file()
{
	munmap(data_, size_);
	close(fd_);
}
} // namespace utils
