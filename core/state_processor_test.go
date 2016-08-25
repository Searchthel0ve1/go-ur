package core_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/urcapital/go-ur/accounts"
	"github.com/urcapital/go-ur/common"
	"github.com/urcapital/go-ur/core"
	"github.com/urcapital/go-ur/core/types"
	"github.com/urcapital/go-ur/crypto"
	"github.com/urcapital/go-ur/ethdb"
	"github.com/urcapital/go-ur/event"
	"github.com/urcapital/go-ur/params"
)

var (
	privKey     *ecdsa.PrivateKey
	privKeyJson = []byte(`{"address":"5d32e21bf3594aa66c205fde8dbee3dc726bd61d","Crypto":{"cipher":"aes-128-ctr","ciphertext":"bd9b82bdeecdf80c22747c2c18c389f2ce8a653c16dfbe830b66843f25c96543","cipherparams":{"iv":"7506def4dfb65d150541d45322feefbe"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"459c5c5cb4bcd402fbee2fa47b7c495d8b73e18fca476a191327cf970550ec4a"},"mac":"4cf2812e2e8bb628480ad16732dc51a82602bae192b4c2f09ce607485d5bde3a"},"id":"aa8ff3a6-826c-4ae8-967b-be398508baed","version":3}`)
)

func init() {
	k, err := accounts.DecryptKey(privKeyJson, "password")
	if err != nil {
		panic(err)
	}
	privKey = k.PrivateKey
}

func TestMinersReward(t *testing.T) {
	// setup a new blockchain, the privileged address as 1 UR
	gen, gendb, bchain, err := newBlockChain(crypto.PubkeyToAddress(privKey.PublicKey), urToWei(1))
	if err != nil {
		t.Error(err)
		return
	}
	minerk, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
		return
	}
	genAddress := func() common.Address {
		userk, err := crypto.GenerateKey()
		if err != nil {
			panic(err)
		}
		return crypto.PubkeyToAddress(userk.PublicKey)
	}
	minerAddr := crypto.PubkeyToAddress(minerk.PublicKey)
	tests := make([]transactionsTest, 0, 300)
	// mine for 100 blocks without any transaction
	minerBal := big.NewInt(0)
	for i := int64(0); i < 100; i++ {
		minerBal = new(big.Int).Add(minerBal, core.BlockReward)
		tests = append(tests, transactionsTest{
			[]genBlockFunc{setCoinbase(minerAddr)},
			[]testBlockFunc{checkBalance(bchain, minerAddr, minerBal)},
		})
	}
	// mine another 100 blocks, with 1 signup transaction
	txVal := big.NewInt(1)
	for i := int64(0); i < 100; i++ {
		userAddr := genAddress()
		addedBal := new(big.Int).Mul(big.NewInt(2), core.BlockReward)
		minerBal = new(big.Int).Add(minerBal, addedBal)
		tests = append(tests, transactionsTest{
			[]genBlockFunc{
				setCoinbase(minerAddr),
				sendTx(bchain, privKey, userAddr, txVal, []byte{0x01}),
			},
			[]testBlockFunc{
				checkBalance(bchain, minerAddr, minerBal),
			},
		})
	}
	// mine another 100 blocks, with 2 signup transaction
	for i := int64(0); i < 100; i++ {
		userAddr := genAddress()
		addedBal := new(big.Int).Mul(big.NewInt(3), core.BlockReward)
		minerBal = new(big.Int).Add(minerBal, addedBal)
		tests = append(tests, transactionsTest{
			[]genBlockFunc{
				setCoinbase(minerAddr),
				sendMultipleTx(bchain, privKey, userAddr, txVal, []byte{0x01}, 2),
			},
			[]testBlockFunc{
				checkBalance(bchain, minerAddr, minerBal),
			},
		})
	}
	if err := runTest(bchain, gen, gendb, tests); err != nil {
		t.Error(err)
		return
	}
}

func TestMembersReward(t *testing.T) {
	// // setup a new blockchain
	// gen, gendb, bchain, err := newBlockChain(crypto.PubkeyToAddress(privKey.PublicKey), common.Ether)
	// if err != nil {
	// 	t.Error(err)
	// 	return
	// }
	// minerk, err := crypto.GenerateKey()
	// if err != nil {
	// 	t.Error(err)
	// 	return
	// }
	// minerAddr := crypto.PubkeyToAddress(minerk.PublicKey)
	// members := make([]common.Address, 0, 8)
	// for i := 0; i < 8; i++ {
	// 	k, err := crypto.GenerateKey()
	// 	if err != nil {
	// 		t.Error(err)
	// 		return
	// 	}
	// 	members = append(members, crypto.PubkeyToAddress(k.PublicKey))
	// }
	// membersAccumulatedRewards := []*big.Int{
	// 	floatUrToWei("4000"),
	// 	floatUrToWei("3212.09"),
	// 	floatUrToWei("2727.25"),
	// 	floatUrToWei("2424.22"),
	// 	floatUrToWei("2242.41"),
	// 	floatUrToWei("2121.2"),
	// 	floatUrToWei("2060.6"),
	// 	floatUrToWei("2000"),
	// }
	// tests := make([]transactionsTest, 0, 200)
	// t.Log(tests)
	// for i := 0; i < 100; i++ {
	// 	mk, err := crypto.GenerateKey()
	// 	if err != nil {
	// 		t.Error(err)
	// 		return
	// 	}
	// 	tests = append(tests, transactionsTest{
	// 		[]genBlockFunc{
	// 			setCoinbase(minerAddr),
	// 			// sendSignupTx(bchain,privKey,members[],big.NewInt(1),lastB)
	// 		},
	// 		[]testBlockFunc{},
	// 	})
	// }
	// if err := runTest(bchain, gen, gendb, tests); err != nil {
	// 	t.Error(err)
	// 	return
	// }
}

type genBlockFunc func(int, *core.BlockGen)
type testBlockFunc func(blk *types.Block) error

type transactionsTest struct {
	Generate []genBlockFunc
	Test     []testBlockFunc
}

func showLogMessage(t *testing.T, msg string) genBlockFunc {
	return func(n int, bg *core.BlockGen) { t.Logf("currently at block %d: %s\n", n, msg) }
}

func sendMultipleTx(bchain *core.BlockChain, fromKey *ecdsa.PrivateKey, toAddr common.Address, val *big.Int, data []byte, count int) genBlockFunc {
	return func(n int, bg *core.BlockGen) {
		sendOneTx := sendTx(bchain, fromKey, toAddr, val, data)
		for i := 0; i < count; i++ {
			sendOneTx(n, bg)
		}
	}
}

func createTx(n int, bg *core.BlockGen, fromKey *ecdsa.PrivateKey, toAddr common.Address, val *big.Int, data []byte) *types.Transaction {
	nonce := bg.TxNonce(crypto.PubkeyToAddress(fromKey.PublicKey))
	tx, err := types.NewTransaction(nonce, toAddr, val, new(big.Int).Mul(params.TxGas, big.NewInt(100)), nil, data).SignECDSA(fromKey)
	if err != nil {
		panic(err)
	}
	return tx
}

func sendTx(bchain *core.BlockChain, fromKey *ecdsa.PrivateKey, toAddr common.Address, val *big.Int, data []byte) genBlockFunc {
	return func(n int, bg *core.BlockGen) {
		tx := createTx(n, bg, fromKey, toAddr, val, data)
		bg.AddTx(tx)
	}
}

func setCoinbase(addr common.Address) genBlockFunc {
	return func(n int, bg *core.BlockGen) {
		bg.SetCoinbase(addr)
	}
}

func runTest(bchain *core.BlockChain, genesis *types.Block, db *ethdb.MemDatabase, tests []transactionsTest) error {
	lastBlock := genesis
	for _, tst := range tests {
		blocks, _ := core.GenerateChain(nil, lastBlock, db, 1, func(n int, bg *core.BlockGen) {
			if tst.Generate != nil {
				for _, genFunc := range tst.Generate {
					genFunc(n, bg)
				}
			}
		})
		_, err := bchain.InsertChain(blocks)
		lastBlock = bchain.CurrentBlock()
		if err != nil {
			return err
		}
		if tst.Test != nil {
			for _, testFunc := range tst.Test {
				if err := testFunc(lastBlock); err != nil {
					return fmt.Errorf("failed at block %d: %s", lastBlock.NumberU64(), err.Error())
				}
			}
		}
	}
	return nil
}

func checkBalance(bchain *core.BlockChain, addr common.Address, exp *big.Int) testBlockFunc {
	return func(blk *types.Block) error {
		state, err := bchain.State()
		if err != nil {
			return err
		}
		bal := state.GetBalance(addr)
		if bal.Cmp(exp) == 0 {
			return nil
		}
		return fmt.Errorf("got a different balance than expected at address %s: %s (expected %s)", addr.Hex(), bal.String(), exp.String())
	}
}

func urToWei(ur int64) *big.Int { return new(big.Int).Mul(common.Ether, big.NewInt(ur)) }

func newBlockChain(privAddress common.Address, funds *big.Int) (*types.Block, *ethdb.MemDatabase, *core.BlockChain, error) {
	gen, gendb, err := setupGenesis(privAddress, funds)
	if err != nil {
		return nil, nil, nil, err
	}
	bchain, err := buildBlockChain(gendb, gen, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return gen, gendb, bchain, nil
}

func setupGenesis(privAddress common.Address, funds *big.Int) (*types.Block, *ethdb.MemDatabase, error) {
	gendb, err := ethdb.NewMemDatabase()
	if err != nil {
		return nil, nil, err
	}
	return core.GenesisBlockForTesting(gendb, privAddress, funds), gendb, nil
}

func buildBlockChain(gendb *ethdb.MemDatabase, genesis *types.Block, blocks types.Blocks) (*core.BlockChain, error) {
	bchain, err := core.NewBlockChain(gendb, core.MakeChainConfig(), core.FakePow{}, &event.TypeMux{})
	if err != nil {
		return nil, err
	}
	bchain.ResetWithGenesisBlock(genesis)

	if blocks != nil {
		_, err = bchain.InsertChain(types.Blocks(blocks))
		if err != nil {
			return nil, err
		}
	}

	return bchain, nil
}

func floatUrToWei(ur string) *big.Int {
	u, _ := new(big.Float).SetString(ur)
	urFloat, _ := new(big.Float).SetString(common.Ether.String())
	r, _ := new(big.Float).Mul(u, urFloat).Int(nil)
	return r
}

// func Test_ItDoesntApplyBonusesForNonQualifyingTransactions(t *testing.T) {
// 	transactionValue := big.NewInt(1000)
// 	randomSeed := time.Now().UnixNano()
// 	rand.Seed(randomSeed)

// 	for n, i := 100, 0; i <= n; i++ {
// 		var (
// 			gendb, _  = ethdb.NewMemDatabase()
// 			key, _    = crypto.HexToECDSA(RandHex(64))
// 			address   = crypto.PubkeyToAddress(key.PublicKey)
// 			funds     = big.NewInt(1000000000)
// 			toKey, _  = crypto.HexToECDSA(RandHex(64))
// 			toAddress = crypto.PubkeyToAddress(toKey.PublicKey)
// 			genesis   = GenesisBlockForTesting(gendb, address, funds)
// 		)

// 		var hasCollided bool
// 		for _, privilegedAddress := range PrivilegedAddresses {
// 			if privilegedAddress.Hex() == address.Hex() {
// 				hasCollided = true
// 			}
// 		}
// 		if hasCollided {
// 			continue
// 		}

// 	blocks, _ := GenerateChain(nil, genesis, gendb, 1, func(i int, block *BlockGen) {
// 		block.SetCoinbase(common.Address{0x00})
// 		// If the block number is multiple of 3, send a few bonus transactions to the miner
// 		tx, err := types.NewTransaction(block.TxNonce(address), toAddress, transactionValue, params.TxGas, nil, nil).SignECDSA(key)
// 		if err != nil {
// 			panic(err)
// 		}
// 		block.AddTx(tx)
// 	})

// 	statedb := buildBlockChain(t, gendb, genesis, blocks)

// 	expectedBalance := transactionValue
// 	assert.False(
// 		t,
// 		statedb.GetBalance(toAddress).Cmp(expectedBalance) == 1,
// 		fmt.Sprintf(
// 			"Wallet balance larger than expected, wanted '%s' got '%s'. Random seed: %d\n",
// 			expectedBalance,
// 			statedb.GetBalance(toAddress),
// 			randomSeed,
// 		),
// 	)
// }
// }

// func Test_ItAppliesBonusesForQualifyingTransactions(t *testing.T) {
// 	tests := []struct {
// 		TransactionValue        *big.Int
// 		ExpectedReceiverBalance *big.Int
// 	}{
// 		{
// 			TransactionValue:        big.NewInt(1),
// 			ExpectedReceiverBalance: big.NewInt(1000000000000000),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(20),
// 			ExpectedReceiverBalance: big.NewInt(20000000000000000),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(300),
// 			ExpectedReceiverBalance: big.NewInt(300000000000000000),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(4000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(4), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(50000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(50), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(600000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(600), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(7000000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(80000000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(900000000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(1000000000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(20000000000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(300000000000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        big.NewInt(4000000000000),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        new(big.Int).Mul(big.NewInt(1), common.Ether),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        new(big.Int).Mul(big.NewInt(20), common.Ether),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        new(big.Int).Mul(big.NewInt(300), common.Ether),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 		{
// 			TransactionValue:        new(big.Int).Mul(big.NewInt(4000), common.Ether),
// 			ExpectedReceiverBalance: new(big.Int).Mul(big.NewInt(2000), common.Ether),
// 		},
// 	}

// 	for _, test := range tests {

// 		var (
// 			funds           = new(big.Int).Mul(big.NewInt(10000), common.Ether)
// 			key, _          = crypto.HexToECDSA(RandHex(64))
// 			transactionAddr = crypto.PubkeyToAddress(key.PublicKey)
// 		)
// 		privKey, privAddress := setupPrivilegedAddress(t)
// 		genesis, gendb := setupGenesis(t, privAddress, funds)

// 		blocks, _ := GenerateChain(nil, genesis, gendb, 1, func(i int, block *BlockGen) {
// 			block.SetCoinbase(common.Address{0x00})

// 			tx, err := types.NewTransaction(block.TxNonce(privAddress), transactionAddr, test.TransactionValue, params.TxGas, nil, nil).SignECDSA(privKey)
// 			if err != nil {
// 				panic(err)
// 			}
// 			block.AddTx(tx)
// 		})

// 		statedb := buildBlockChain(t, gendb, genesis, blocks)

// 		assert.Equal(t, test.ExpectedReceiverBalance, statedb.GetBalance(transactionAddr))

// 		expectedPrivAddressBalance := new(big.Int).Sub(funds, test.TransactionValue)
// 		assert.Equal(t, expectedPrivAddressBalance, statedb.GetBalance(privAddress))
// 	}
// }

// func Test_ItAppliesMinerRewardBonusForNewSignupsInBlock(t *testing.T) {
// 	privKey, privAddress := setupPrivilegedAddress(t)

// 	tests := []struct {
// 		Description              string
// 		NumberOfSignups          int
// 		NumberOfBlocks           int
// 		AdditionalTransactionsFn func(int, *BlockGen, []common.Address)
// 	}{
// 		{
// 			Description:     "No signups",
// 			NumberOfSignups: 0,
// 			NumberOfBlocks:  1,
// 		},
// 		{
// 			Description:     "1 Signup",
// 			NumberOfSignups: 1,
// 			NumberOfBlocks:  1,
// 		},
// 		{
// 			Description:     "2 signups over 2 blocks",
// 			NumberOfSignups: 2,
// 			NumberOfBlocks:  2,
// 		},
// 		{
// 			Description:     "5 signups over 2 blocks",
// 			NumberOfSignups: 5,
// 			NumberOfBlocks:  2,
// 		},
// 		{
// 			Description:     "700 signups over 200 blocks",
// 			NumberOfSignups: 700,
// 			NumberOfBlocks:  200,
// 		},
// 		{
// 			Description:     "30 signups over 5 blocks, with non qualifying signup transactions",
// 			NumberOfSignups: 30,
// 			NumberOfBlocks:  5,
// 			AdditionalTransactionsFn: func(i int, block *BlockGen, nonSignupAddresses []common.Address) {
// 				tx, err := types.NewTransaction(block.TxNonce(privAddress), nonSignupAddresses[i], big.NewInt(int64(rand.Intn(1999999))), params.TxGas, nil, nil).SignECDSA(privKey)
// 				if err != nil {
// 					panic(err)
// 				}
// 				block.AddTx(tx)
// 			},
// 		},
// 	}

// 	transactionValue := big.NewInt(2000000)
// 	funds := new(big.Int).Mul(big.NewInt(1), common.Ether)

// 	for _, test := range tests {
// 		expectedBonusReward := new(big.Int).Mul(BlockReward, big.NewInt(int64(test.NumberOfSignups)))
// 		expectedBlockReward := new(big.Int).Mul(BlockReward, big.NewInt(int64(test.NumberOfBlocks)))
// 		genesis, gendb := setupGenesis(t, privAddress, funds)

// 		newAddresses := generateNewAddresses(t, test.NumberOfSignups)
// 		nonSignupAddresses := generateNewAddresses(t, test.NumberOfSignups)

// 		blocks, _ := GenerateChain(nil, genesis, gendb, test.NumberOfBlocks, func(i int, block *BlockGen) {
// 			block.SetCoinbase(common.Address{0x00})

// 			if test.AdditionalTransactionsFn != nil {
// 				test.AdditionalTransactionsFn(i, block, nonSignupAddresses)
// 			}

// 			if test.NumberOfBlocks < test.NumberOfSignups {
// 				// Distribute new signup transactions across blocks
// 				for j := (i * int(test.NumberOfSignups/test.NumberOfBlocks)); j < ((i + 1) * int(test.NumberOfSignups/test.NumberOfBlocks)); j++ {
// 					tx, err := types.NewTransaction(block.TxNonce(privAddress), newAddresses[j], transactionValue, params.TxGas, nil, nil).SignECDSA(privKey)
// 					if err != nil {
// 						panic(err)
// 					}
// 					block.AddTx(tx)
// 				}
// 				// On last block
// 				if test.NumberOfBlocks-1 == i {
// 					// Do any remaining transactions for new signups
// 					for j := (test.NumberOfSignups - (test.NumberOfSignups % test.NumberOfBlocks)); j < test.NumberOfSignups; j++ {
// 						tx, err := types.NewTransaction(block.TxNonce(privAddress), newAddresses[j], transactionValue, params.TxGas, nil, nil).SignECDSA(privKey)
// 						if err != nil {
// 							panic(err)
// 						}
// 						block.AddTx(tx)
// 					}
// 				}
// 			} else if i < test.NumberOfSignups {
// 				// 1 transaction per block
// 				tx, err := types.NewTransaction(block.TxNonce(privAddress), newAddresses[i], transactionValue, params.TxGas, nil, nil).SignECDSA(privKey)
// 				if err != nil {
// 					panic(err)
// 				}
// 				block.AddTx(tx)
// 			}
// 		})

// 		statedb := buildBlockChain(t, gendb, genesis, blocks)

// 		expectedMinerBalance := new(big.Int).Add(expectedBlockReward, expectedBonusReward)
// 		assert.Equal(t, expectedMinerBalance, statedb.GetBalance(common.Address{0x00}), test.Description)
// 	}
// }
