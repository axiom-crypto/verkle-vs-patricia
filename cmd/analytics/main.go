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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
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
	triedb := statedb.TrieDB()
	t, _ := state.Database.OpenTrie(statedb, head.Root())
	// triedb := trie.NewDatabase(db, trie.HashDefaults)

	// t, err := trie.NewStateTrie(trie.StateTrieID(stateRoot), triedb)
	if err != nil {
		logger.Fatalf("new state trie: %s", err)
	}

	ctx := context.Background()
	ctx, cls := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cls()

	analyzeTries(ctx, head.Root(), t, triedb)
}

func analyzeTries(ctx context.Context, trieRoot common.Hash, t state.Trie, triedb *trie.Database) {
	logger := log.New(os.Stderr, "trie", log.LstdFlags)
	var leafNodes int
	var storageTries int64
	lastReport := time.Now()

	// Histograms for the State Trie.
	histStateTrieDepths := histogram.New[int]("State Trie - Depths")
	// histStatePathTypes := histogram.New[string]("State Trie - Path types")

	// Histograms for Storage Tries.
	histStorageTrieDepths := histogram.New[int]("Storage Trie - Depths")
	histStorageTriesNumSlots := histogram.New[int64]("Storage Trie - Number of used slots")

	iter, _ := t.NodeIterator(nil)
	for iter.Next(true) {
		if iter.Leaf() {
			leafNodes++

			// State Trie analysis.
			leafProof := iter.LeafProof()
			histStateTrieDepths.Observe(len(leafProof))
			// histStatePathTypes.Observe(toShortPathTypes(pathNodeTypes))

			// Storage tries analysis.
			var acc types.StateAccount
			if err := rlp.DecodeBytes(iter.LeafBlob(), &acc); err != nil {
				logger.Fatalf("invalid account encountered during traversal: %s", err)
			}
			if acc.Root != emptyRoot {
				storageTries++
				id := trie.StorageTrieID(trieRoot, common.BytesToHash(iter.LeafKey()), acc.Root)
				storageTrie, err := trie.NewStateTrie(id, triedb)
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
						// storageSlotCumDepth += int64(len(pathNodeTypes) - 1)
					}
				}
				// histStorageTrieDepths.Observe(int(storageSlotCumDepth / storageTriesNumSlots))
				histStorageTriesNumSlots.Observe(storageTriesNumSlots)

				if storageIter.Error() != nil {
					logger.Fatalf("Failed to traverse storage trie: %s", err)
				}
			}
		}

		if time.Since(lastReport) > time.Minute*1 {
			// State Trie stdout reports.
			fmt.Printf("Walked %d (EOA + SC) accounts:\n", leafNodes)
			histStateTrieDepths.Print(os.Stdout)
			// histStatePathTypes.Print(os.Stdout)
			fmt.Println()

			// Storage tries stdout reports.
			fmt.Printf("Walked %d Storage Tries:\n", storageTries)
			histStorageTrieDepths.Print(os.Stdout)
			histStorageTriesNumSlots.Print(os.Stdout)

			fmt.Printf("-----\n\n")

			lastReport = time.Now()

			// Persist .csv.
			// State Trie.
			histStateTrieDepths.ToCSV("statetrie_depth.csv")
			// histStatePathTypes.ToCSV("statetrie_pathtypes.csv")

			// Storage Tries.
			histStorageTrieDepths.ToCSV("storagetrie_depth.csv")
			histStorageTriesNumSlots.ToCSV("storagetrie_numslots.csv")

		}

		if ctx.Err() != nil {
			return
		}
	}
	if iter.Error() != nil {
		logger.Fatalf("iterating trie: %s", iter.Error())
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
