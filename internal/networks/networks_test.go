package networks

import "testing"

func TestDefaultNetworks(t *testing.T) {
	all := DefaultNetworks()
	if len(all) < 6 {
		t.Fatalf("network count = %d, want at least 6", len(all))
	}
	seen := map[int64]bool{}
	for _, network := range all {
		if network.ChainID == 0 || network.Name == "" || network.Symbol == "" || network.RPCURL == "" {
			t.Fatalf("network incomplete: %+v", network)
		}
		if seen[network.ChainID] {
			t.Fatalf("duplicate chain id %d", network.ChainID)
		}
		seen[network.ChainID] = true
	}
}

func TestFind(t *testing.T) {
	network, err := Find(1)
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if network.Key != "ethereum" {
		t.Fatalf("network key = %s", network.Key)
	}
	if _, err := Find(999999); err == nil {
		t.Fatalf("Find() expected unsupported chain error")
	}
}
