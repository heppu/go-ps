// +build linux solaris

package ps

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// User ids mapped to names
var users = make(map[int]string)

// Get user names and user ids from /etc/passwd
func init() {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), ":")
		if len(s) < 3 {
			continue
		}
		i, err := strconv.Atoi(s[2])
		if err != nil {
			continue
		}
		users[i] = s[0]
	}
	file.Close()
}

// UnixProcess is an implementation of Process that contains Unix-specific
// fields and information.
type UnixProcess struct {
	pid   int
	ppid  int
	state rune
	pgrp  int
	sid   int
	uid   int

	binary string
}

func (p *UnixProcess) Pid() int {
	return p.pid
}

func (p *UnixProcess) PPid() int {
	return p.ppid
}

func (p *UnixProcess) Uid() int {
	return p.uid
}

func (p *UnixProcess) User() string {
	return users[p.uid]
}

func (p *UnixProcess) Executable() string {
	return p.binary
}

func findProcess(pid int) (Process, error) {
	dir := fmt.Sprintf("/proc/%d", pid)
	_, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	return newUnixProcess(pid)
}

func processes() ([]Process, error) {
	d, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer d.Close()

	results := make([]Process, 0, 50)
	for {
		fis, err := d.Readdir(10)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		for _, fi := range fis {
			// We only care about directories, since all pids are dirs
			if !fi.IsDir() {
				continue
			}

			// We only care if the name starts with a numeric
			name := fi.Name()
			if name[0] < '0' || name[0] > '9' {
				continue
			}

			// From this point forward, any errors we just ignore, because
			// it might simply be that the process doesn't exist anymore.
			pid, err := strconv.ParseInt(name, 10, 0)
			if err != nil {
				continue
			}

			p, err := newUnixProcess(int(pid))
			if err != nil {
				continue
			}

			results = append(results, p)
		}
	}

	return results, nil
}

func newUnixProcess(pid int) (*UnixProcess, error) {
	p := &UnixProcess{pid: pid}
	return p, p.Refresh()
}
