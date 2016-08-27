package core

import (
	"errors"
	"math/big"

	"encoding/binary"

	"github.com/urcapital/go-ur/common"
	"github.com/urcapital/go-ur/core/state"
	"github.com/urcapital/go-ur/core/types"
)

const (
	BonusMultiplier = 1e+15
	BonusCapUR      = 2000
)

// privileged addresses
var (
	MemberRewards = []*big.Int{
		floatUrToWei("2000.0"),
		floatUrToWei("60.60"),
		floatUrToWei("60.60"),
		floatUrToWei("121.21"),
		floatUrToWei("181.81"),
		floatUrToWei("303.03"),
		floatUrToWei("484.84"),
		floatUrToWei("787.91"),
	}
	privilegedAddresses = []common.Address{
		common.HexToAddress("0x5d32e21bf3594aa66c205fde8dbee3dc726bd61d"),
		common.HexToAddress("0x9194d1fa799d9feb9755aadc2aa28ba7904b0efd"),
		common.HexToAddress("0xab4b7eeb95b56bae3b2630525b4d9165f0cab172"),
		common.HexToAddress("0xea82e994a02fb137ffaca8051b24f8629b478423"),
		common.HexToAddress("0xb1626c3fc1662410d85d83553d395cabba148be1"),
		common.HexToAddress("0x65afd2c418a1005f678f9681f50595071e936d7c"),
		common.HexToAddress("0x49158a28df943acd20be7c8e758d8f4a9dc07d05"),
	}
)

func floatUrToWei(ur string) *big.Int {
	u, _ := new(big.Float).SetString(ur)
	urFloat, _ := new(big.Float).SetString(common.Ether.String())
	r, _ := new(big.Float).Mul(u, urFloat).Int(nil)
	return r
}

// SignupChain returns the signup chain up to 7 levels
func SignupChain(bc *BlockChain, tx *types.Transaction) []common.Address {
	r := make([]common.Address, 0, 7)
	addr, _ := tx.From()
	r = append(r, addr)
	curtx := tx
	var err error
	for err != errNoMoreMembers && len(r) < 7 {
		nexttx, err := nextMember(bc, curtx)
		if err == errInvalidChain {
			panic("something went wrong. got invalid data in signup transaction")
		}
		if err == errNoMoreMembers {
			return r
		}
		addr, _ := nexttx.From()
		r = append(r, addr)
		curtx = nexttx
	}
	return r
}

var (
	errNoMoreMembers               = errors.New("no more members in the chain")
	errInvalidChain                = errors.New("detected an invalid signup chain")
	errInvalidSignupMessageVersion = errors.New("invalid signup message version")
)

const currentSignupMessageVersion byte = 1

// looks in transaction data and retrieves the previous member in the signup chain
func nextMember(bc *BlockChain, tx *types.Transaction) (*types.Transaction, error) {
	data := tx.Data()
	if len(data) == 0 {
		return nil, errInvalidChain
	}
	if data[0] != currentSignupMessageVersion {
		return nil, errInvalidSignupMessageVersion
	}
	if len(data) == 1 {
		return nil, errNoMoreMembers
	}
	if len(data) != 41 {
		return nil, errInvalidChain
	}
	blocknr := binary.BigEndian.Uint64(data[1:9])
	var txid [32]byte
	copy(txid[:], data[9:])
	nexttx := bc.GetBlockByNumber(blocknr).Transaction(common.Hash(txid))
	return nexttx, nil
}

func IsSignupTransaction(tx *types.Transaction) bool {
	addr, _ := tx.From()
	data := tx.Data()
	return IsPrivilegedAddress(addr) && tx.Value().Cmp(big.NewInt(1)) == 0 && (len(data) == 1 || len(data) == 41)
}

func IsPrivilegedAddress(address common.Address) bool {
	for _, privilegedAddress := range privilegedAddresses {
		if address == privilegedAddress {
			return true
		}
	}
	return false
}

func CalculateNewSignupMinerRewards(reward *big.Int, transactions types.Transactions, statedb *state.StateDB) *big.Int {
	r := reward
	for _, transaction := range transactions {
		from, _ := transaction.From()
		if IsPrivilegedAddress(from) {
			r = new(big.Int).Add(r, BlockReward)
		}
	}
	return r
}
