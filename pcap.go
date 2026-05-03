package main

import (
	"encoding/binary"
	"io"
	"time"
)

const (
	MagicNumber   = 0xa1b2c3d4
	LinktypeUser0 = 220
)

type PcapWriter struct {
	w  io.Writer
	bo binary.ByteOrder
}

type GlobalHeader struct {
	Magic        uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      uint32
}

type PacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

type StreamId byte

const (
	StreamStdout StreamId = 0
	StreamStderr StreamId = 1
	StreamStdin  StreamId = 2
	StreamStart  StreamId = 10 // For signaling the start of a process execution
	StreamArgv   StreamId = 11 // For signaling the command-line arguments of a process execution
	StreamEnv    StreamId = 12 // For signaling the environment variables of a process execution
	StreamEnd    StreamId = 13 // For signaling the end of a process execution with exit code
)

func NewPcapWriter(w io.Writer) (*PcapWriter, error) {
	pw := &PcapWriter{w: w, bo: binary.LittleEndian}
	err := pw.writeGlobalHeader()
	return pw, err
}

func (pw *PcapWriter) writeGlobalHeader() error {
	hdr := GlobalHeader{
		Magic:        MagicNumber,
		VersionMajor: 2,
		VersionMinor: 4,
		Snaplen:      65535,
		Network:      LinktypeUser0,
	}
	return binary.Write(pw.w, pw.bo, hdr)
}

func (pw *PcapWriter) WritePacket(pid int, id StreamId, data []byte) error {
	t := time.Now()
	length := uint32(5 + len(data)) // int32 pid (4) + StreamId (1) + data

	hdr := PacketHeader{
		TsSec:   uint32(t.Unix()),
		TsUsec:  uint32(t.Nanosecond() / 1000),
		InclLen: length,
		OrigLen: length,
	}
	if err := binary.Write(pw.w, pw.bo, hdr); err != nil {
		return err
	}
	if err := binary.Write(pw.w, pw.bo, int32(pid)); err != nil {
		return err
	}
	if err := binary.Write(pw.w, pw.bo, id); err != nil {
		return err
	}
	_, err := pw.w.Write(data)
	return err
}
