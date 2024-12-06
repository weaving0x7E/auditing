### [S-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicate. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle stats will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make.

**Impact:** the gas cost for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering. and causing a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle::players` array so big, that no noe else enters, guaranteeing themselves the win. 

**Proof of Concept:**
100 player's gas cost is higher than 10 players 30x
```
// @audit Dos
@>    function testDOS() public{
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

**Recommended Mitigation:** 