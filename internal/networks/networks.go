package networks

import "fmt"

type Network struct {
	Key         string `json:"key"`
	ChainID     int64  `json:"chainId"`
	Name        string `json:"name"`
	Symbol      string `json:"symbol"`
	RPCURL      string `json:"rpcUrl"`
	ExplorerURL string `json:"explorerUrl"`
}

const DefaultChainID = int64(1)

func DefaultNetworks() []Network {
	return []Network{
		{
			Key:         "ethereum",
			ChainID:     1,
			Name:        "Ethereum",
			Symbol:      "ETH",
			RPCURL:      "https://ethereum-rpc.publicnode.com",
			ExplorerURL: "https://etherscan.io",
		},
		{
			Key:         "sepolia",
			ChainID:     11155111,
			Name:        "Sepolia",
			Symbol:      "ETH",
			RPCURL:      "https://ethereum-sepolia-rpc.publicnode.com",
			ExplorerURL: "https://sepolia.etherscan.io",
		},
		{
			Key:         "polygon",
			ChainID:     137,
			Name:        "Polygon",
			Symbol:      "POL",
			RPCURL:      "https://polygon-bor-rpc.publicnode.com",
			ExplorerURL: "https://polygonscan.com",
		},
		{
			Key:         "arbitrum",
			ChainID:     42161,
			Name:        "Arbitrum One",
			Symbol:      "ETH",
			RPCURL:      "https://arbitrum-one-rpc.publicnode.com",
			ExplorerURL: "https://arbiscan.io",
		},
		{
			Key:         "optimism",
			ChainID:     10,
			Name:        "Optimism",
			Symbol:      "ETH",
			RPCURL:      "https://optimism-rpc.publicnode.com",
			ExplorerURL: "https://optimistic.etherscan.io",
		},
		{
			Key:         "base",
			ChainID:     8453,
			Name:        "Base",
			Symbol:      "ETH",
			RPCURL:      "https://base-rpc.publicnode.com",
			ExplorerURL: "https://basescan.org",
		},
	}
}

func Find(chainID int64) (Network, error) {
	for _, network := range DefaultNetworks() {
		if network.ChainID == chainID {
			return network, nil
		}
	}
	return Network{}, fmt.Errorf("unsupported chain id %d", chainID)
}
