// Copyright 2021 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The SmarOS provider fetches configuration from the metadata data directory
// on COM2 (ttyS1) using Joyent Metadata Protocol Specification (Version 2).
// Protocol spec available at: https://eng.joyent.com/mdata/protocol.html

package smartos

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/coreos/ignition/v2/config/v3_3_experimental/types"
	"github.com/coreos/ignition/v2/internal/log"
	"github.com/coreos/ignition/v2/internal/providers/util"
	"github.com/coreos/ignition/v2/internal/resource"

	"github.com/coreos/vcontext/report"
	"golang.org/x/sys/unix"
)

var (
	key          = "com.coreos:user-data"
	serialDevice = "/dev/ttyS1"
	crc32q       = crc32.MakeTable(0xEDB88320)
)

func FetchConfig(f *resource.Fetcher) (types.Config, report.Report, error) {
	logger := f.Logger
	conn, err := newConnection(logger, serialDevice)
	if err != nil {
		return types.Config{}, report.Report{}, err
	}
	defer conn.close()

	logger.Debug("sending request: GET " + key)
	data, err := conn.request(logger, "GET", []byte(key))
	if err != nil {
		return types.Config{}, report.Report{}, err
	}

	return util.ParseConfig(f.Logger, data)
}

// unixRawMode puts the serial connection opened at fd into something like raw
// mode. The input is available character by character, echoing is disabled,
// and special processing of terminal characters is disabled.
func unixRawMode(fd uintptr) error {
	tios, err := unix.IoctlGetTermios(int(fd), syscall.TCGETS)
	if err != nil {
		return err
	}
	tios.Iflag &^= unix.BRKINT | unix.INLCR | unix.INPCK | unix.ISTRIP | unix.IXON
	tios.Oflag &^= unix.OPOST
	tios.Cflag |= unix.CS8
	tios.Lflag &^= unix.ECHO | unix.ICANON | unix.IEXTEN | unix.ISIG

	// Block waiting for at least 1 char or timeout in 100ms.
	tios.Cc[unix.VMIN] = 0
	tios.Cc[unix.VTIME] = 1
	return unix.IoctlSetTermios(int(fd), unix.TCSETS, tios)
}

// fnctlSetLock exclusively locks the file at fd.
func fnctlSetLock(fd uintptr) error {
	flock := syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: io.SeekStart,
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(fd, syscall.F_SETLK, &flock)
}

type connection struct {
	f *os.File
}

func newConnection(logger *log.Logger, dev string) (connection, error) {
	f, err := connect(logger, serialDevice)
	if err != nil {
		return connection{}, err
	}
	if err := initProtocol(logger, f); err != nil {
		return connection{}, err
	}
	return connection{f}, nil
}

func (c connection) close() error {
	return c.f.Close()
}

func connect(logger *log.Logger, dev string) (*os.File, error) {
	logger.Debug("opening serial device")
	f, err := os.OpenFile(serialDevice,
		syscall.O_RDWR|syscall.O_EXCL|syscall.O_NOCTTY, 0666)
	if err != nil {
		return f, fmt.Errorf("failed to open serial device %q: %v", serialDevice, err)
	}
	logger.Debug("setting exclusive lock")
	if err := fnctlSetLock(f.Fd()); err != nil {
		return f, fmt.Errorf("failed to lock serial device %q: %v", serialDevice, err)
	}
	logger.Debug("setting raw mode")
	if err := unixRawMode(f.Fd()); err != nil {
		return f, fmt.Errorf("failed to set serial device %q to raw mode: %v", serialDevice, err)
	}
	return f, err
}

func initProtocol(logger *log.Logger, f *os.File) error {
	reader := bufio.NewReader(f)
	for n, err := reader.Discard(1); n > 0 && err == nil; {
	}
	logger.Debug("writing initial newline character")
	if _, err := f.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("failed to write to serial port: %v", err)
	}
	reply, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	logger.Debug("server response: %q", string(reply))
	if len(reply) < 1 {
		return errors.New("unexpected server response")
	}
	logger.Debug("negotiate version 2 protocol")
	if _, err := f.Write([]byte("NEGOTIATE V2\n")); err != nil {
		return errors.New("could not send character")
	}
	reply, err = reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("could not negotiate protocol version 2: %v", err)
	}
	logger.Debug("server response: %q", string(reply))
	if strings.TrimSpace(string(reply)) != "V2_OK" {
		return errors.New("server does not support version 2")
	}
	return nil
}

func newRequest(code string, payload []byte) (Frame, error) {
	if code == "" || len(payload) < 1 {
		return Frame{}, errors.New("invalid request")
	}
	f := Frame{
		Body: Body{
			RequestID: uint32(rand.Int31()),
			Code:      strings.ToUpper(code),
			Payload:   payload,
		},
	}
	f.Parse()
	return f, nil
}

func (c connection) request(logger *log.Logger, code string, payload []byte) ([]byte, error) {
	reader := bufio.NewReader(c.f)
	req, _ := newRequest(code, payload)
	r, _ := req.MarshalText()
	c.f.Write(r)
	reply, err := reader.ReadBytes('\n')
	if err != nil {
		return []byte{}, err
	}
	logger.Debug("response: %q", string(reply))
	var resp Frame
	if err := resp.UnmarshalText(reply); err != nil {
		logger.Debug("error reading reply: %v", err)
		return []byte{}, err
	}
	logger.Debug("unmarshalled response: %+v", resp)
	if resp.Body.RequestID != req.Body.RequestID {
		logger.Debug("request id does not match")
		return []byte{}, err
	}
	if resp.Body.Code != "SUCCESS" {
		logger.Debug("request failed with code: %q", resp.Body.Code)
		return []byte{}, err
	}
	return resp.Body.Payload, nil
}

type Frame struct {
	// The length (in bytes) of the Body of the message.
	BodyLength int
	// The CRC32 checksum of the Body of the message.
	BodyChecksum string
	//The active content in the message.
	Body Body
}

type Body struct {
	// A unique identifier for this request to be used in matching Requests
	// with their respective Responses.
	RequestID uint32
	// The code denoting the requested operation in a Request, or result of
	// the requested operation in a Response – i.e. generally Success or
	// some Error condition.
	Code string
	// The input parameter to a Request, or the returned value in a
	// Response.
	Payload []byte
}

// Parse fills in the BodyLength and BodyChecksum fields by parsing the body.
func (f *Frame) Parse() {
	body, _ := f.Body.MarshalText()
	f.BodyLength = len(body)
	f.BodyChecksum = fmt.Sprintf("%08x", crc32.Checksum(body, crc32q))
}

func (f *Frame) MarshalText() (text []byte, err error) {
	body, err := f.Body.MarshalText()
	if err != nil {
		return text, err
	}
	text = []byte(fmt.Sprintf("V2 %d %s %s\n", f.BodyLength, f.BodyChecksum, body))
	return text, nil
}

func (f *Frame) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	fields := strings.SplitN(s, " ", 4)
	if len(fields) != 4 {
		return errors.New("unexpected number of fields")
	}
	if fields[0] != "V2" {
		return errors.New("message start is not V2")
	}
	length, err := strconv.Atoi(fields[1])
	if err != nil {
		return errors.New("error parsing length")
	}
	f.BodyLength = length
	f.BodyChecksum = fields[2]
	body := fields[3]
	checksum := fmt.Sprintf("%08x", crc32.Checksum([]byte(body), crc32q))
	if f.BodyLength != len(body) || f.BodyChecksum != checksum {
		return errors.New("body length or checksum error")
	}
	err = f.Body.UnmarshalText([]byte(body))
	return err
}

func (b *Body) MarshalText() (text []byte, err error) {
	s := base64.StdEncoding.EncodeToString([]byte(b.Payload))
	text = []byte(fmt.Sprintf("%08x %s %s", b.RequestID, b.Code, s))
	return text, nil
}

func (b *Body) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	fields := strings.SplitN(s, " ", 3)
	if len(fields) < 2 {
		return errors.New("unexpected number of fields")
	}
	id, err := strconv.ParseUint(fields[0], 16, 32)
	if err != nil {
		return errors.New("error parsing request id")
	}
	b.RequestID = uint32(id)
	b.Code = fields[1]

	if len(fields) > 2 {
		b.Payload, err = base64.StdEncoding.DecodeString(fields[2])
	}
	return err
}
