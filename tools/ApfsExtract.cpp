// SPDX-License-Identifier: GPL-2.0-or-later
// Standalone consumer of apfs-fuse's read-only library; no mount or block device.
#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/ApfsDir.h>
#include <ApfsLib/Decmpfs.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/GptPartitionMap.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static int fail(const char *message) {std::fprintf(stderr,"%s\n",message);return 1;}

int main(int argc,char **argv) {
    if(argc!=4 && argc!=5)return fail("Usage: apfs-extract regular-image volume-index /image/path [new-output-file]");
    struct stat source{};
    if(lstat(argv[1],&source) || !S_ISREG(source.st_mode))return fail("Input must be a regular image file");
    char *end=nullptr;errno=0;
    const unsigned long index=std::strtoul(argv[2],&end,10);
    if(errno || !*argv[2] || *end || index>=NX_MAX_FILE_SYSTEMS)return fail("Invalid volume index");
    std::unique_ptr<Device> device(Device::OpenDevice(argv[1]));
    if(!device)return fail("Cannot open image for reading");
    uint64_t offset=0,size=device->GetSize();GptPartitionMap partitions;
    if(partitions.LoadAndVerify(*device)) {
        const int first=partitions.FindFirstAPFSPartition();
        if(first<0)return fail("Image GPT has no APFS partition");
        partitions.GetPartitionOffsetAndSize(first,offset,size);
    }
    ApfsContainer container(device.get(),offset,size);
    if(!container.Init())return fail("Cannot read APFS container");
    std::unique_ptr<ApfsVolume> volume(container.GetVolume(static_cast<unsigned>(index)));
    if(!volume)return fail("Cannot read selected APFS volume");
    ApfsDir directory(*volume);uint64_t inode=2;std::string path=argv[3];
    if(path.empty() || path[0]!='/')return fail("Image path must be absolute");
    size_t at=1;
    while(at<path.size()) {
        const size_t slash=path.find('/',at);const auto part=path.substr(at,slash==std::string::npos?slash:slash-at);
        if(part.empty() || part=="." || part=="..")return fail("Image path must contain ordinary components");
        ApfsDir::DirRec entry;
        if(!directory.LookupName(entry,inode,part.c_str()))return fail("Image path component not found");
        inode=entry.file_id;
        if(slash==std::string::npos)break;
        at=slash+1;
    }
    ApfsDir::Inode info;
    if(!directory.GetInode(info,inode))return fail("Cannot read image inode");
    if(S_ISDIR(info.mode) && argc==4) {
        std::vector<ApfsDir::DirRec> children;
        if(!directory.ListDirectory(children,inode))return fail("Cannot list image directory");
        for(const auto &child:children)std::printf("%llu\t%s\n",static_cast<unsigned long long>(child.file_id),child.name.c_str());
        return 0;
    }
    if(argc!=5 || !S_ISREG(info.mode))return fail("Extraction requires a regular image file and a new output path");
    const bool compressed=info.bsd_flags&0x20U;std::vector<uint8_t> decoded;
    uint64_t length=info.ds_size;
    // Keep the offline extractor bounded even for a damaged inode. The
    // production APFS implementation is never involved in this host tool.
    constexpr uint64_t maximum=4ULL<<30;
    if(length>maximum || info.uncompressed_size>maximum)return fail("Image file exceeds extraction bound");
    if(compressed) {
        std::vector<uint8_t> attribute;
        if(!directory.GetAttribute(attribute,inode,"com.apple.decmpfs") || attribute.size()<16)return fail("Cannot read compression header");
        const auto *header=reinterpret_cast<const CompressionHeader *>(attribute.data());
        if(uint64_t(header->size)>maximum)return fail("Compression header exceeds extraction bound");
        if(!DecompressFile(directory,inode,decoded,attribute))return fail("Cannot decompress image file");
        length=decoded.size();
        if(length>maximum)return fail("Decoded image file exceeds extraction bound");
    }
    const int output=open(argv[4],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(output<0)return fail("Output must be a new local file");
    bool good=true;std::vector<uint8_t> buffer(1U<<20);
    for(uint64_t done=0;good && done<length;) {
        const size_t count=static_cast<size_t>(std::min<uint64_t>(buffer.size(),length-done));
        const uint8_t *bytes=nullptr;
        if(compressed)bytes=decoded.data()+done;
        else if(directory.ReadFile(buffer.data(),info.private_id,done,count))bytes=buffer.data();
        else {good=false;break;}
        for(size_t written=0;written<count;) {
            const ssize_t amount=write(output,bytes+written,count-written);
            if(amount<0 && errno==EINTR)continue;
            if(amount<=0){good=false;break;}
            written+=static_cast<size_t>(amount);
        }
        done+=count;
    }
    if(close(output))good=false;
    if(!good){unlink(argv[4]);return fail("Image read or output write failed");}
    std::printf("Extracted %llu bytes from inode %llu\n",static_cast<unsigned long long>(length),static_cast<unsigned long long>(inode));
    return 0;
}
