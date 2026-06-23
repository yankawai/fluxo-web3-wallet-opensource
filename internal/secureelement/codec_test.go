package secureelement

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCommandFrameRoundTrip(t *testing.T) {
	command := Command{
		Opcode:    OpcodeSignEIP191Message,
		SlotID:    "primary",
		Account:   7,
		Challenge: []byte("challenge"),
		Payload:   []byte("message"),
	}
	frame, err := EncodeCommand(command)
	if err != nil {
		t.Fatalf("EncodeCommand() error = %v", err)
	}
	decoded, err := DecodeCommand(frame)
	if err != nil {
		t.Fatalf("DecodeCommand() error = %v", err)
	}
	if decoded.Opcode != command.Opcode || decoded.SlotID != command.SlotID || decoded.Account != command.Account {
		t.Fatalf("decoded command metadata mismatch: %+v", decoded)
	}
	if !bytes.Equal(decoded.Challenge, command.Challenge) || !bytes.Equal(decoded.Payload, command.Payload) {
		t.Fatalf("decoded command body mismatch: %+v", decoded)
	}
}

func TestResponseFrameRoundTrip(t *testing.T) {
	response := Response{
		Status:  StatusUnauthorized,
		Payload: []byte("payload"),
		Error:   "presence required",
	}
	frame, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}
	decoded, err := DecodeResponse(frame)
	if err != nil {
		t.Fatalf("DecodeResponse() error = %v", err)
	}
	if decoded.Status != response.Status || decoded.Error != response.Error || !bytes.Equal(decoded.Payload, response.Payload) {
		t.Fatalf("decoded response mismatch: %+v", decoded)
	}
}

func TestCommandFrameRejectsOversizedFields(t *testing.T) {
	tests := map[string]Command{
		"slot": {
			Opcode: OpcodePing,
			SlotID: SlotID(strings.Repeat("s", MaxSlotIDSize+1)),
		},
		"challenge": {
			Opcode:    OpcodePing,
			Challenge: bytes.Repeat([]byte{1}, MaxChallengeSize+1),
		},
		"payload": {
			Opcode:  OpcodePing,
			Payload: bytes.Repeat([]byte{1}, MaxPayloadSize+1),
		},
	}
	for name, command := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeCommand(command); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("EncodeCommand() error = %v, want %v", err, ErrInvalidCommand)
			}
		})
	}
}

func TestResponseFrameRejectsOversizedFields(t *testing.T) {
	if _, err := EncodeResponse(Response{Payload: bytes.Repeat([]byte{1}, MaxPayloadSize+1)}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("EncodeResponse(payload) error = %v, want %v", err, ErrInvalidCommand)
	}
	if _, err := EncodeResponse(Response{Error: strings.Repeat("e", MaxErrorSize+1)}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("EncodeResponse(error) error = %v, want %v", err, ErrInvalidCommand)
	}
}

func TestFrameRejectsInvalidEnvelope(t *testing.T) {
	command, err := EncodeCommand(Command{Opcode: OpcodePing})
	if err != nil {
		t.Fatalf("EncodeCommand() error = %v", err)
	}

	badMagic := append([]byte(nil), command...)
	badMagic[0] = 'X'
	if _, err := DecodeCommand(badMagic); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("DecodeCommand(badMagic) error = %v, want %v", err, ErrInvalidCommand)
	}

	badVersion := append([]byte(nil), command...)
	badVersion[4] = 99
	if _, err := DecodeCommand(badVersion); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("DecodeCommand(badVersion) error = %v, want %v", err, ErrInvalidCommand)
	}

	badKind := append([]byte(nil), command...)
	badKind[5] = frameKindResponse
	if _, err := DecodeCommand(badKind); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("DecodeCommand(badKind) error = %v, want %v", err, ErrInvalidCommand)
	}
}
