// SPDX-License-Identifier: MIT
// Local regular-file image construction. No mount, device or host chown operation.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type entry struct {
	Path       string            `json:"path"`
	Inode      uint64            `json:"inode"`
	Type       string            `json:"type"`
	Mode       uint16            `json:"mode"`
	UID        uint32            `json:"uid"`
	GID        uint32            `json:"gid"`
	Flags      uint32            `json:"bsd_flags"`
	Protection uint32            `json:"protection_class"`
	Birth      uint64            `json:"create_time_ns"`
	Modify     uint64            `json:"mod_time_ns"`
	Access     uint64            `json:"access_time_ns"`
	Change     uint64            `json:"change_time_ns"`
	Attrs      map[string]string `json:"xattrs_hex"`
	Blob       string            `json:"blob"`
	Bytes      uint64            `json:"bytes"`
	SHA        string            `json:"sha256"`
	Target     string            `json:"target"`
}
type manifest struct {
	Schema    int     `json:"schema_version"`
	Product   string  `json:"product"`
	Build     string  `json:"build"`
	Container string  `json:"container_uuid"`
	Volume    string  `json:"volume_uuid"`
	Size      int64   `json:"size_bytes"`
	Time      uint64  `json:"fixed_time_ns"`
	Entries   []entry `json:"entries"`
}

func need(ok bool, message string) error {
	if !ok {
		return fmt.Errorf("%s", message)
	}
	return nil
}
func uuid(s string) (result [16]byte, err error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return result, fmt.Errorf("invalid UUID")
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return result, fmt.Errorf("invalid UUID")
	}
	copy(result[:], b)
	if result == ([16]byte{}) {
		return result, fmt.Errorf("zero UUID")
	}
	return result, nil
}
func readRegular(p string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("not a bounded regular input: %s", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != st.Size() || int64(len(b)) > limit {
		return nil, fmt.Errorf("input size changed")
	}
	return b, nil
}
func timestamp(n uint64) (time.Time, error) {
	if n > uint64(1<<63-1) {
		return time.Time{}, fmt.Errorf("timestamp exceeds exact signed-nanosecond range")
	}
	return time.Unix(0, int64(n)), nil
}
func build(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: apfs-data-build manifest.json blob-directory new-image")
	}
	raw, err := readRegular(args[0], 16<<20)
	if err != nil {
		return err
	}
	var m manifest
	if err = json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if err = need(m.Schema == 1 && m.Product == "iPhone10,3" && m.Build == "20H392" && m.Size >= 512<<20 && m.Size <= 16<<30 && m.Size%4096 == 0 && len(m.Entries) > 0 && len(m.Entries) <= 100000, "invalid iPhone Data manifest"); err != nil {
		return err
	}
	container, err := uuid(m.Container)
	if err != nil {
		return err
	}
	volume, err := uuid(m.Volume)
	if err != nil {
		return err
	}
	fixed, err := timestamp(m.Time)
	if err != nil {
		return err
	}
	nodes := map[string]*apfswrite.Entry{}
	var total uint64
	for _, e := range m.Entries {
		if e.Path != "" && (path.IsAbs(e.Path) || path.Clean(e.Path) != e.Path || strings.HasPrefix(e.Path, "../") || e.Path == ".." || len(e.Path) >= 4096 || len(strings.Split(e.Path, "/")) > 64) {
			return fmt.Errorf("invalid Data path")
		}
		for _, c := range []byte(e.Path) {
			if c < 32 || c > 126 {
				return fmt.Errorf("this pinned iPhone tree requires ASCII path names")
			}
		}
		if nodes[e.Path] != nil || e.Inode == 0 || e.Protection != 0 || e.Flags & ^uint32(32) != 0 {
			return fmt.Errorf("duplicate or unsupported Data metadata")
		}
		mode := os.FileMode(e.Mode & 0777)
		if e.Mode&04000 != 0 {
			mode |= os.ModeSetuid
		}
		if e.Mode&02000 != 0 {
			mode |= os.ModeSetgid
		}
		if e.Mode&01000 != 0 {
			mode |= os.ModeSticky
		}
		switch e.Type {
		case "directory":
			if e.Mode&0170000 != 0040000 {
				return fmt.Errorf("directory mode differs")
			}
			mode |= os.ModeDir
		case "symlink":
			if e.Mode&0170000 != 0120000 {
				return fmt.Errorf("symlink mode differs")
			}
			mode |= os.ModeSymlink
		case "file":
			if e.Mode&0170000 != 0100000 {
				return fmt.Errorf("file mode differs")
			}
		default:
			return fmt.Errorf("unsupported Data inode type")
		}
		bt, err := timestamp(e.Birth)
		if err != nil {
			return err
		}
		mt, err := timestamp(e.Modify)
		if err != nil {
			return err
		}
		ct, err := timestamp(e.Change)
		if err != nil {
			return err
		}
		at, err := timestamp(e.Access)
		if err != nil {
			return err
		}
		flags := e.Flags
		n := &apfswrite.Entry{Name: path.Base(e.Path), Mode: mode, ModeExplicit: true, UID: e.UID, GID: e.GID, BSDFlags: &flags, Times: &hostdata.FileTimes{Birth: bt, Modify: mt, Change: ct, Access: at}, Xattrs: map[string][]byte{}}
		for k, v := range e.Attrs {
			b, err := hex.DecodeString(v)
			if err != nil || hex.EncodeToString(b) != v || len(b) > 4<<20 {
				return fmt.Errorf("invalid xattr encoding")
			}
			n.Xattrs[k] = b
		}
		if e.Type == "symlink" {
			if e.Target == "" || len(e.Target) >= 4096 || strings.ContainsRune(e.Target, 0) || !bytes.Equal(n.Xattrs["com.apple.fs.symlink"], append([]byte(e.Target), 0)) {
				return fmt.Errorf("symlink attribute differs")
			}
			n.Data = []byte(e.Target)
			delete(n.Xattrs, "com.apple.fs.symlink")
		} else if e.Type == "file" {
			if e.Blob != fmt.Sprintf("inode-%d", e.Inode) || e.Bytes > 256<<20 || total > 512<<20-e.Bytes {
				return fmt.Errorf("invalid file blob")
			}
			b, err := readRegular(filepath.Join(args[1], e.Blob), 256<<20)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(b)
			if uint64(len(b)) != e.Bytes || hex.EncodeToString(digest[:]) != e.SHA {
				return fmt.Errorf("file content differs")
			}
			total += e.Bytes
			if e.Flags&32 == 0 {
				n.Data = b
			}
			n.LinkGroup = e.Inode
		}
		nodes[e.Path] = n
	}
	root := nodes[""]
	if root == nil || !root.Mode.IsDir() {
		return fmt.Errorf("missing Data root")
	}
	for _, e := range m.Entries {
		if e.Path != "" {
			parent := nodes[path.Dir(e.Path)]
			if path.Dir(e.Path) == "." {
				parent = root
			}
			if parent == nil || !parent.Mode.IsDir() {
				return fmt.Errorf("missing directory parent")
			}
			parent.Children = append(parent.Children, nodes[e.Path])
		}
	}
	// O_EXCL refuses every existing path, including symbolic links and block devices.
	f, err := os.OpenFile(args[2], os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Truncate(m.Size); err != nil {
		return err
	}
	// This selects filename admission only. The emitted APFS v2 feature bits are
	// checked separately against the Darwin 22 reader; this is not a macOS image.
	err = apfswrite.CreateContainer(f, m.Size, &apfswrite.CreateOptions{TargetVersion: osversion.Version{Major: 15}, BlockSize: 4096, VolumeName: "Data", CaseSensitive: true, ContainerUUID: container, VolumeUUID: volume, Root: root, FixedTime: fixed, Role: 0})
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	fmt.Printf("APFS Data written: %d entries, %d bytes, UUID %s\n", len(m.Entries), m.Size, m.Volume)
	return nil
}
func main() {
	if err := build(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
