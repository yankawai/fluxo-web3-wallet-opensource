package secureelement

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	ProtocolVersion  = byte(1)
	MaxSlotIDSize    = 64
	MaxChallengeSize = 128
	MaxPayloadSize   = 4096
	MaxErrorSize     = 512

	frameKindCommand  = byte(1)
	frameKindResponse = byte(2)
)

var frameMagic = [4]byte{'F', 'X', 'S', 'E'}

func EncodeCommand(command Command) ([]byte, error) {
	slot := []byte(command.SlotID)
	if len(slot) > MaxSlotIDSize {
		return nil, fmt.Errorf("%w: slot id too large", ErrInvalidCommand)
	}
	if len(command.Challenge) > MaxChallengeSize {
		return nil, fmt.Errorf("%w: challenge too large", ErrInvalidCommand)
	}
	if len(command.Payload) > MaxPayloadSize {
		return nil, fmt.Errorf("%w: payload too large", ErrInvalidCommand)
	}

	var buf bytes.Buffer
	buf.Write(frameMagic[:])
	buf.WriteByte(ProtocolVersion)
	buf.WriteByte(frameKindCommand)
	buf.WriteByte(byte(command.Opcode))
	writeUint32(&buf, command.Account)
	buf.WriteByte(byte(len(slot)))
	writeUint16(&buf, uint16(len(command.Challenge)))
	writeUint32(&buf, uint32(len(command.Payload)))
	buf.Write(slot)
	buf.Write(command.Challenge)
	buf.Write(command.Payload)
	return buf.Bytes(), nil
}

func DecodeCommand(frame []byte) (Command, error) {
	reader, err := newFrameReader(frame, frameKindCommand)
	if err != nil {
		return Command{}, err
	}

	opcode, err := reader.readByte()
	if err != nil {
		return Command{}, err
	}
	account, err := reader.readUint32()
	if err != nil {
		return Command{}, err
	}
	slotLen, err := reader.readByte()
	if err != nil {
		return Command{}, err
	}
	challengeLen, err := reader.readUint16()
	if err != nil {
		return Command{}, err
	}
	payloadLen, err := reader.readUint32()
	if err != nil {
		return Command{}, err
	}
	if slotLen > MaxSlotIDSize || challengeLen > MaxChallengeSize || payloadLen > MaxPayloadSize {
		return Command{}, fmt.Errorf("%w: frame exceeds limits", ErrInvalidCommand)
	}

	slot, err := reader.readBytes(int(slotLen))
	if err != nil {
		return Command{}, err
	}
	challenge, err := reader.readBytes(int(challengeLen))
	if err != nil {
		return Command{}, err
	}
	payload, err := reader.readBytes(int(payloadLen))
	if err != nil {
		return Command{}, err
	}
	if !reader.done() {
		return Command{}, fmt.Errorf("%w: trailing command bytes", ErrInvalidCommand)
	}

	return Command{
		Opcode:    Opcode(opcode),
		SlotID:    SlotID(slot),
		Account:   account,
		Challenge: challenge,
		Payload:   payload,
	}, nil
}

func EncodeResponse(response Response) ([]byte, error) {
	errBytes := []byte(response.Error)
	if len(response.Payload) > MaxPayloadSize {
		return nil, fmt.Errorf("%w: payload too large", ErrInvalidCommand)
	}
	if len(errBytes) > MaxErrorSize {
		return nil, fmt.Errorf("%w: error too large", ErrInvalidCommand)
	}

	var buf bytes.Buffer
	buf.Write(frameMagic[:])
	buf.WriteByte(ProtocolVersion)
	buf.WriteByte(frameKindResponse)
	writeUint16(&buf, uint16(response.Status))
	writeUint32(&buf, uint32(len(response.Payload)))
	writeUint16(&buf, uint16(len(errBytes)))
	buf.Write(response.Payload)
	buf.Write(errBytes)
	return buf.Bytes(), nil
}

func DecodeResponse(frame []byte) (Response, error) {
	reader, err := newFrameReader(frame, frameKindResponse)
	if err != nil {
		return Response{}, err
	}
	status, err := reader.readUint16()
	if err != nil {
		return Response{}, err
	}
	payloadLen, err := reader.readUint32()
	if err != nil {
		return Response{}, err
	}
	errorLen, err := reader.readUint16()
	if err != nil {
		return Response{}, err
	}
	if payloadLen > MaxPayloadSize || errorLen > MaxErrorSize {
		return Response{}, fmt.Errorf("%w: frame exceeds limits", ErrInvalidCommand)
	}
	payload, err := reader.readBytes(int(payloadLen))
	if err != nil {
		return Response{}, err
	}
	errBytes, err := reader.readBytes(int(errorLen))
	if err != nil {
		return Response{}, err
	}
	if !reader.done() {
		return Response{}, fmt.Errorf("%w: trailing response bytes", ErrInvalidCommand)
	}
	return Response{
		Status:  Status(status),
		Payload: payload,
		Error:   string(errBytes),
	}, nil
}

type frameReader struct {
	data []byte
	pos  int
}

func newFrameReader(frame []byte, kind byte) (*frameReader, error) {
	if len(frame) < len(frameMagic)+2 {
		return nil, fmt.Errorf("%w: short frame", ErrInvalidCommand)
	}
	for i, value := range frameMagic {
		if frame[i] != value {
			return nil, fmt.Errorf("%w: bad magic", ErrInvalidCommand)
		}
	}
	if frame[len(frameMagic)] != ProtocolVersion {
		return nil, fmt.Errorf("%w: protocol version", ErrInvalidCommand)
	}
	if frame[len(frameMagic)+1] != kind {
		return nil, fmt.Errorf("%w: frame kind", ErrInvalidCommand)
	}
	return &frameReader{data: frame, pos: len(frameMagic) + 2}, nil
}

func (r *frameReader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("%w: short frame", ErrInvalidCommand)
	}
	value := r.data[r.pos]
	r.pos++
	return value, nil
}

func (r *frameReader) readUint16() (uint16, error) {
	raw, err := r.readBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(raw), nil
}

func (r *frameReader) readUint32() (uint32, error) {
	raw, err := r.readBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw), nil
}

func (r *frameReader) readBytes(size int) ([]byte, error) {
	if size < 0 || r.pos+size > len(r.data) {
		return nil, fmt.Errorf("%w: short frame", ErrInvalidCommand)
	}
	value := append([]byte(nil), r.data[r.pos:r.pos+size]...)
	r.pos += size
	return value, nil
}

func (r *frameReader) done() bool {
	return r.pos == len(r.data)
}

func writeUint16(buf *bytes.Buffer, value uint16) {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], value)
	buf.Write(raw[:])
}

func writeUint32(buf *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	buf.Write(raw[:])
}
