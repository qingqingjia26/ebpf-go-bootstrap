package tracehelper

import (
	"bufio"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

type KSymbol struct {
	Name string
	Addr uint64
	typ  string
}

type ksymSlice []KSymbol

func (ks ksymSlice) Len() int           { return len(ks) }
func (ks ksymSlice) Less(i, j int) bool { return ks[i].Addr < ks[j].Addr }
func (ks ksymSlice) Swap(i, j int)      { ks[i], ks[j] = ks[j], ks[i] }

type KSyms struct {
	syms ksymSlice
}

func NewKSyms() *KSyms {
	return &KSyms{syms: make(ksymSlice, 0, 10000)}
}

func (ks *KSyms) KSymload() error {
	filepath := "/proc/kallsyms"
	// Read file
	f, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filepath, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var addr uint64
		var name string
		var typ string
		_, err := fmt.Sscanf(sc.Text(), "%x %s %s", &addr, &typ, &name)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", sc.Text(), err)
		}
		ks.syms = append(ks.syms, KSymbol{Name: name, Addr: addr, typ: typ})
	}
	sort.Slice(ks.syms, func(i, j int) bool {
		return ks.syms[i].Addr > ks.syms[j].Addr
	})
	return nil
}

func (ks *KSyms) GetSym(addr uint64) (KSymbol, bool) {
	idx := sort.Search(len(ks.syms), func(i int) bool {
		return ks.syms[i].Addr <= addr
	})
	// fmt.Printf("idx: %d addr:%x len(ks.syms):%d\n", idx, addr, len(ks.syms))
	if idx < len(ks.syms) {
		return ks.syms[idx], true
	}
	return KSymbol{}, false
}

type ElfMap struct {
	startAddr uint64
	endAddr   uint64
	perms     string
	fileoff   uint64
	devMajor  uint64
	devMinor  uint64
	inode     uint64
}

type elfType uint16

const (
	EXEC elfType = iota + 1
	DYN
	PERF_MAP
	VDSO
	UNKNOWN
)

type USymbol struct {
	Name   string
	start  uint64
	size   uint64
	offset uint64
}
type usymSlice []USymbol

func (us usymSlice) Len() int           { return len(us) }
func (us usymSlice) Less(i, j int) bool { return us[i].start < us[j].start }
func (us usymSlice) Swap(i, j int)      { us[i], us[j] = us[j], us[i] }

type mapedFile struct {
	name       string
	shAddr     uint64
	shOffset   uint64
	typ        elfType
	syms       usymSlice
	typeInited bool
	symInited  bool
}

func (mf *mapedFile) initType() {
	if mf.typeInited {
		return
	}
	mf.typeInited = true
	ignoreArr := []string{"[uprobes]"}
	for _, s := range ignoreArr {
		if mf.name == s {
			mf.typ = UNKNOWN
			return
		}
	}
	if mf.name == "[vdso]" {
		mf.typ = VDSO
		return
	}
	file, err := elf.Open(mf.name)
	if err != nil {
		mf.typ = UNKNOWN
		log.Printf("failed to open %s: %v", mf.name, err)
		return
	}
	defer file.Close()
	if file.Type == elf.ET_EXEC {
		mf.typ = EXEC
		return
	} else if file.Type == elf.ET_DYN {
		mf.typ = DYN
		return
	} else {
		mf.typ = UNKNOWN
	}

}

func (mf *mapedFile) initDynInfo() {
	if mf.typ != DYN {
		return
	}
	if mf.shAddr != 0 {
		return
	}
	file, err := elf.Open(mf.name)
	if err != nil {
		log.Printf("failed to open %s: %v", mf.name, err)
		return
	}
	defer file.Close()

	for _, s := range file.Sections {
		if s.Name == ".text" {
			mf.shAddr = s.Addr
			mf.shOffset = s.Offset
			break
		}
	}
}

func isFileBackend(name string) bool {
	if name == "" {
		return false
	}
	arr := []string{"//anon", "/dev/zero", "/anon_hugepage", "[stack", "/SYSV", "[heap", "[uprobes", "[vsyscall", "[vvar", "[vdso"}
	for _, s := range arr {
		if strings.HasPrefix(name, s) {
			return false
		}
	}
	return true
}
func (mf *mapedFile) sortSym() {
	sort.Slice(mf.syms, func(i, j int) bool {
		return mf.syms[i].start > mf.syms[j].start
	})
}

func (mf *mapedFile) addSym(sym elf.Symbol) {
	usyms := USymbol{Name: sym.Name, start: sym.Value, size: sym.Size}
	mf.syms = append(mf.syms, usyms)
}
func (mf *mapedFile) loadSyms() {
	if mf.symInited {
		return
	}
	mf.symInited = true
	file, err := elf.Open(mf.name)
	if err != nil {
		log.Printf("failed to open %s: %v", mf.name, err)
	}
	defer file.Close()

	syms, err := file.Symbols()
	if err != nil {
		log.Printf("failed to read symbols from %s: %v", mf.name, err)
	}
	for _, s := range syms {
		mf.addSym(s)
	}

	dynsyms, err := file.DynamicSymbols()
	if err != nil {
		log.Printf("failed to read dynamic symbols from %s: %v", mf.name, err)
		return
	}
	for _, s := range dynsyms {
		mf.addSym(s)
	}
	mf.sortSym()
}

func (mf *mapedFile) getSym(offset uint64) (USymbol, bool) {
	if len(mf.syms) == 0 {
		mf.loadSyms()
	}
	idx := sort.Search(len(mf.syms), func(i int) bool {
		return mf.syms[i].start <= offset
	})
	if idx < len(mf.syms) && mf.syms[idx].start <= offset && offset < mf.syms[idx].start+mf.syms[idx].size {
		return mf.syms[idx], true
	}
	return USymbol{}, false
}

type procMemMapItem struct {
	name     string
	pid      int
	start    uint64
	end      uint64
	offset   uint64
	inode    uint64
	devMajor uint64
	devMinor uint64
	filename string
}

type USyms struct {
	dsos    map[string]*mapedFile
	memMaps []procMemMapItem
}

func NewUSyms() *USyms {
	return &USyms{dsos: make(map[string]*mapedFile), memMaps: make([]procMemMapItem, 0, 10)}
}

func (us *USyms) GetSym(addr uint64) (USymbol, bool) {
	for _, item := range us.memMaps {
		if item.start <= addr && addr < item.end {
			dso := us.dsos[item.name]
			offset := addr
			if dso.typ == DYN || dso.typ == VDSO {
				offset = addr - item.start + item.offset
				offset += dso.shAddr - dso.shOffset
			}
			us, ok := dso.getSym(offset)
			if ok {
				return us, true
			}
		}
	}
	return USymbol{}, false
}

func (us *USyms) LoadPid(pid int) error {
	filepath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filepath, err)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var start, end, offset, inode, devMajor, devMinor uint64
		var perm, name string
		fields := strings.Fields(sc.Text())
		var err error
		switch len(fields) {
		case 5:
			_, err = fmt.Sscanf(sc.Text(), "%x-%x %s %x %x:%x %d", &start, &end, &perm, &offset, &devMajor, &devMinor, &inode)
			name = ""
		case 6:
			_, err = fmt.Sscanf(sc.Text(), "%x-%x %s %x %x:%x %d %s", &start, &end, &perm, &offset, &devMajor, &devMinor, &inode, &name)
		default:
			return fmt.Errorf("failed to parse %s", sc.Text())
		}
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", sc.Text(), err)
		}
		if !isFileBackend(name) {
			continue
		}
		item := procMemMapItem{name: name, pid: pid, start: start, end: end, offset: offset, inode: inode, devMajor: devMajor, devMinor: devMinor, filename: fields[len(fields)-1]}
		us.memMaps = append(us.memMaps, item)
		if _, ok := us.dsos[name]; !ok {
			us.dsos[name] = &mapedFile{name: name}
		}
		dso := us.dsos[name]
		dso.initType()
		dso.initDynInfo()
	}
	return nil
}
