//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/yankawai/go-web3-wallet/internal/walletruntime"
)

var runtime = walletruntime.NewService()

func main() {
	api := map[string]any{
		"createVault": js.FuncOf(createVault),
		"unlockVault": js.FuncOf(unlockVault),
		"signMessage": js.FuncOf(signMessage),
		"lock":        js.FuncOf(lock),
		"lockAll":     js.FuncOf(lockAll),
	}
	js.Global().Set("walletCore", api)
	select {}
}

func createVault(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return jsonError("createVault requires password")
	}
	response, err := runtime.CreateVault(args[0].String())
	return jsonResult(response, err)
}

func unlockVault(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		return jsonError("unlockVault requires vault and password")
	}
	response, err := runtime.UnlockVault(args[0].String(), args[1].String())
	return jsonResult(response, err)
}

func signMessage(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		return jsonError("signMessage requires sessionId and message")
	}
	signed, err := runtime.SignMessage(args[0].String(), args[1].String())
	return jsonResult(signed, err)
}

func lock(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return jsonError("lock requires sessionId")
	}
	runtime.Lock(args[0].String())
	return jsonResult(map[string]bool{"locked": true}, nil)
}

func lockAll(js.Value, []js.Value) any {
	runtime.LockAll()
	return jsonResult(map[string]bool{"locked": true}, nil)
}

func jsonResult(value any, err error) any {
	if err != nil {
		return jsonError(err.Error())
	}
	body := map[string]any{
		"ok":   true,
		"data": value,
	}
	raw, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		return jsonError(marshalErr.Error())
	}
	return string(raw)
}

func jsonError(message string) any {
	raw, _ := json.Marshal(map[string]any{
		"ok":    false,
		"error": message,
	})
	return string(raw)
}
