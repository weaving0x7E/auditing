### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain contract balance

**Description:** The `PuppyRaffle::refund` function does not follow [CEI/FREI-PI](https://www.nascent.xyz/idea/youre-writing-require-statements-wrong) and as a result, enables participants to drain the contract balance. 

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address, and only after making that external call, we update the `players` array. 

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>  payable(msg.sender).sendValue(entranceFee);

@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

A player who has entered the raffle could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again and claim another refund. They could continue to cycle this until the contract balance is drained. 

**Impact:** All fees paid by raffle entrants could be stolen by the malicious participant. 

**Proof of Concept:** 

1. Users enters the raffle.
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`.
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their contract, draining the contract balance.

**Proof of Code:** 

<details>
<summary>Code</summary>
Add the following code to the `PuppyRaffleTest.t.sol` file. 

```javascript
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(address _puppyRaffle) {
        puppyRaffle = PuppyRaffle(_puppyRaffle);
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    fallback() external payable {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }
}

function testReentrance() public playersEntered {
    ReentrancyAttacker attacker = new ReentrancyAttacker(address(puppyRaffle));
    vm.deal(address(attacker), 1e18);
    uint256 startingAttackerBalance = address(attacker).balance;
    uint256 startingContractBalance = address(puppyRaffle).balance;

    attacker.attack();

    uint256 endingAttackerBalance = address(attacker).balance;
    uint256 endingContractBalance = address(puppyRaffle).balance;
    assertEq(endingAttackerBalance, startingAttackerBalance + startingContractBalance);
    assertEq(endingContractBalance, 0);
}
```
</details>

**Recommended Mitigation:** To fix this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally, we should move the event emission up as well. 

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        (bool success,) = msg.sender.call{value: entranceFee}("");
        require(success, "PuppyRaffle: Failed to refund player");
-        players[playerIndex] = address(0);
-        emit RaffleRefunded(playerAddress);
    }
```

### [H-2] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicate. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle stats will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make.

**Impact:** the gas cost for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering. and causing a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle::players` array so big, that no noe else enters, guaranteeing themselves the win. 

**Proof of Concept:**
100 player's gas cost is higher than 10 players 30x
```
// @audit DoS
@>  function testDOS() public{
        vm.txGasPrice(1);

        uint256 gasStart;
        uint256 gasEnd;

        gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * 10}(produceAddress(10,0));
        gasEnd = gasleft();
        console.log("10 player's gas cost", (gasStart - gasEnd) * tx.gasprice);

        gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * 100}(produceAddress(100,10));
        gasEnd = gasleft();
        console.log("100 player's gas cost", (gasStart - gasEnd) * tx.gasprice);
    }

    function produceAddress(uint64 quantity, uint256 offset) public returns(address[] memory){
        address[] memory addresses = new address[](quantity);
        for (uint256 i = 0; i < quantity; ++i){
            addresses[i] = address(i+offset);
        }
        return addresses;
    }
```

### [H-3] Weak randomness in `PuppyRaffle::selectWinner` allows anyone to choose winner

**Description:** Hashing `msg.sender`, `block.timestamp`, `block.difficulty` together creates a predictable final number. A predictable number is not a good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves. 

**Impact:** Any user can choose the winner of the raffle, winning the money and selecting the "rarest" puppy, essentially making it such that all puppies have the same rarity, since you can choose the puppy. 

**Proof of Concept:** 

There are a few attack vectors here. 

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and use that knowledge to predict when / how to participate. See the [solidity blog on prevrando](https://soliditydeveloper.com/prevrandao) here. `block.difficulty` was recently replaced with `prevrandao`.
2. Users can manipulate the `msg.sender` value to result in their index being the winner.

Using on-chain values as a randomness seed is a [well-known attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recommended Mitigation:** Consider using an oracle for your randomness like [Chainlink VRF](https://docs.chain.link/vrf/v2/introduction).

### [H-4] Integer overflow of `puppyRaffle::totalFees` loses fees

**Description:** In solidity versions prior to `0.8.0` integers were subject to integer overflows.

```javascript
uint64 myVar = type(uint64).max 18446744073709551615
myVar = myVar + 1
// my var will be zero
```

**Impact:**  In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `PuppYRaffle::withdrawFees`. However, if the `totalFees` variable overflows, the `feeAddress` my not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:**

```javascript
    function test_IntegerOverflow() public {
        puppyRaffle.enterRaffle{value: entranceFee * 100}(produceAddress(100,0));

        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        uint256 expectedPayout = ((entranceFee * 100) * 20 / 100);

        puppyRaffle.selectWinner();
        puppyRaffle.withdrawFees();
    }
```

**Recommended Mitigation:** There are few possible mitigations.
1. use a new version of solidity, and a `uint256` instead of `uint64` for `PuppyRaffle::totalFees`
2. You could also use the `SafeMath` library of Openzeppelin for version 0.7.6 of solidity, however you would still have a hard time with the `uint64` type if too many fees are collected.

# Low

### [L-1] `puppyRaffle::getActivePlayerIndex` return 0 for nor-existent players and for players at index 0, causing a player at index 0 to incorrectly think they have not entered the raffle

**Description:** If a player is in the `puppyRaffle::players` array at index 0, this will return 0, but according to the netspec, it will also return 0 if the player is not in the array. 

```javascript
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }
```

**Impact:** causing a player at index 0 to incorrectly think they have not entered the raffle

**Recommended Mitigation:**
The easiest recommendation would be revert id the player is not in the array instead of returning 0. You could also reserve the 0th position for any competition, but a better solution might be return an `int256` where the function returns -1 if the player is not active.

**Recommended Mitigation:** 
Consider allowing duplicate. User can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.

# Gas

### [G-1] unchanged state variables should be declared constant or immutable.
Reading from storage is much more expensive than reading from a constant or immutable

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2] Storage variable in a loop should be cached

Every time you call `players.length` you read from storage, as opposed to memory which is more gas efficient

```diff
+       uint256 playLength = player.length - 1;
-       for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 i = 0; i < playerLength; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
+           for (uint256 j = i + 1; j < playersLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

### [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

### [I-2] Missing checks for `address(0)` when assigning values to address state variables
Assigning values to address state variable without checking for `address(0)`.
- Found in src/PuppyRaffle.sol: 8662:23:25

### [I-3] `PuppyRaffle::selectWinner` should follow CEI, which is not a best practice
```diff
-       (bool success,) = winner.call{value: prizePool}("");
-       require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+       (bool success,) = winner.call{value: prizePool}("");
+       require(success, "PuppyRaffle: Failed to send prize pool to winner");
```
