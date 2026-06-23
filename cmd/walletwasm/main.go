//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/yankawai/go-web3-wallet/internal/walletcore"
)

func main() {
	api := map[string]any{
		"generateWallet":        js.FuncOf(generateWallet),
		"addressFromPrivateKey": js.FuncOf(addressFromPrivateKey),
		"signMessage":           js.FuncOf(signMessage),
	}
	js.Global().Set("walletCore", api)
	select {}
}

func generateWallet(js.Value, []js.Value) any {
	wallet, err := walletcore.GenerateWallet()
	return jsonResult(wallet, err)
}

func addressFromPrivateKey(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return jsonError("addressFromPrivateKey requires privateKey")
	}
	address, err := walletcore.AddressFromPrivateKey(args[0].String())
	return jsonResult(map[string]string{"address": address}, err)
}

func signMessage(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		return jsonError("signMessage requires privateKey and message")
	}
	signed, err := walletcore.SignMessage(args[0].String(), args[1].String())
	return jsonResult(signed, err)
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
