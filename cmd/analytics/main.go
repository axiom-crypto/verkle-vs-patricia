package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/axiom-crypto/verkle-vs-patricia/histogram"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
)

var emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)

	snapshotPath := flag.String("chaindata", "", "Path of geth snapshot folder")
	flag.Parse()

	if len(*snapshotPath) == 0 {
		logger.Fatalf("--chaindata path can't be empty")
	}

	logger.Println("db type:", rawdb.PreexistingDatabase(*snapshotPath))
	db, err := rawdb.NewPebbleDBDatabase(*snapshotPath, 1024, 2000, "eth/db", true, false)
	if err != nil {
		logger.Fatalf("opening pebbledb: %s", err)
	}

	head := rawdb.ReadHeadBlock(db)
	if head == nil {
		logger.Fatalf("get head block: %s", err)
	}
	logger.Println("head block:", head.Number())

	// var PathDefaults = &trie.Config{
	// 	Preimages: false,
	// 	IsVerkle:  false,
	// 	PathDB:    pathdb.Defaults,
	// }

	statedb := state.NewDatabase(db)

	// t, err := trie.NewStateTrie(trie.StateTrieID(stateRoot), triedb)
	if err != nil {
		logger.Fatalf("new state trie: %s", err)
	}

	ctx := context.Background()
	ctx, cls := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cls()

	analyzeTries(ctx, head.Root(), statedb)
}

func analyzeTries(ctx context.Context, trieRoot common.Hash, statedb state.Database) {
	logger := log.New(os.Stderr, "trie", log.LstdFlags)
	// var storageTries int64
	lastReport := time.Now()

	// Histograms for the State Trie.
	// histStateTrieDepths := histogram.New[int]("State Trie - Depths")
	// histStatePathTypes := histogram.New[string]("State Trie - Path types")

	_addresses := [...]string{
		"0x06450dee7fd2fb8e39061434babcfc05599a6fb8", // XEN
		"0x5acc84a3e955bdd76467d3348077d003f00ffb97", // Forsage
		"0x00000000006c3852cbef3e08e8df289169ede581", // Seaport 1.1
		"0x2a0c0dbecc7e4d658f48e01e3fa353f44050c208", // IDEX
		"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
		"0x1a2a1c938ce3ec39b6d47113c7955baa9dd454f2", // Axie
		"0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85", // ENS
		"0x39755357759ce0d7f32dc8dc45414cca409ae24e", // Maker
		"0x06012c8cf97bead5deae237070f9587f8e7a266d", // CryptoKitties
		"0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e", // ENS Registry
		"0x495f947276749ce646f68ac8c248420045cb7b5e", // OpenSea storefront
		"0x0ba45a8b5d5575935b8158a88c631e9f9c95a2e5", // TellorMaster
		"0x000000000000ad05ccc4f10045630fb830b95127", // Blur
		"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH
		"0x06a6a7af298129e3a2ab396c9c06f91d3c54aba8", // 0xUniverse Galaxy
		"0x283af0b28c62c092c9727f1ee09c02ca627eb7f5", // ENS ETH Registrar
		"0x080bf510fcbf18b91105470639e9561022937712", // 0x Exchange
		"0x514910771af9ca656af840dff83e8264ecf986ca", // LINK
		"0x629a673a8242c2ac4b7b8c5d8735fbeac21a6205", // SorareTokens
		"0x58b6a8a3302369daec383334672404ee733ab239", // LPT
	}

	addresses := make([]common.Address, len(_addresses))
	for i, addr := range _addresses {
		addresses[i] = common.HexToAddress(addr)
	}

	stateTrie, _ := statedb.OpenTrie(trieRoot)

	for _, addr := range addresses {
		fmt.Println(addr)
		// Histograms for Storage Tries.
		histStorageTrieDepths := histogram.New[int]("Storage Trie - Depths - " + addr.String())

		account, _ := stateTrie.GetAccount(addr)
		storageTrie, err := statedb.OpenStorageTrie(trieRoot, addr, account.Root, nil)

		if err != nil {
			logger.Fatalf("failed to open storage trie: %s", err)
		}

		var storageTriesNumSlots int64
		storageIter, _ := storageTrie.NodeIterator(nil)
		for storageIter.Next(true) {
			if storageIter.Leaf() {
				if ctx.Err() != nil {
					break
				}
				storageTriesNumSlots += 1
				leafProof := storageIter.LeafProof()
				histStorageTrieDepths.Observe(len(leafProof))
			}

			if time.Since(lastReport) > time.Minute {

				// // Storage tries stdout reports.
				fmt.Printf("Walked %d Storage Slots for %s:\n", storageTriesNumSlots, addr.String())
				histStorageTrieDepths.Print(os.Stdout)

				fmt.Printf("-----\n\n")

				lastReport = time.Now()
			}
		}

		if storageIter.Error() != nil {
			logger.Fatalf("Failed to traverse storage trie: %s", err)
		}

		fmt.Println("Finished walking storage trie for", addr.String())
		fmt.Println("Total storage slots:", storageTriesNumSlots)
		fmt.Println("Storage trie depth histogram:")
		histStorageTrieDepths.Print(os.Stdout)
		fmt.Println("-----\n")

		if ctx.Err() != nil {
			return
		}
	}
}

func toShortPathTypes(nodeTypes []string) string {
	var sb strings.Builder
	for i, nodeType := range nodeTypes[:len(nodeTypes)-1] {
		switch nodeType {
		case "*trie.shortNode":
			if i == len(nodeTypes)-2 {
				sb.WriteString("L.")
				continue
			}
			sb.WriteString("E.")
		case "*trie.fullNode":
			sb.WriteString("B.")
		default:
			panic("unkown node type")
		}
	}
	strPath := sb.String()

	return strPath[:len(strPath)-1]
}
