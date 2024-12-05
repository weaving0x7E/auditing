### [H-1] Storing the password on-chain make it visible to anyone, and no longer private

**Description:** All data stored in-chain is visible to anyone, and can be read directly from the blockchain. The `PasswordStore::s_password` variable is intended to be a private variable and only accessed through the `PasswordStore::getPassword` function, which is intended to be only called by the owner of the contract.

We show one such method of reading any data off chain below.


**Impact:**  Anyone can read the private password, severely breaking the functionality of the protocol

**Proof of Concept:**
The below test case shows anyone can read the password directly from blockchain.

1. Create a locally running chain
```bash
make anvil
```

2. Deploy the contract to the chain
```
make deploy
```

3. Run the storage tool
```
cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 1 --rpc-url http://127.0.0.1:8545
```

you will get an output that looks like this:
`0x6d7950617373776f726400000000000000000000000000000000000000000014`

you can then parse that hex to a string with 
`cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014`

and get output of: 
`myPassword`


**Recommended Mitigation:** 

### [H-2] `Password::setPassword` has no access controls, meaning a non-owner could change the password

**Description:** The `PasswordStore::setPassword` function is set to be an `external` function, however, the natspec of the function and overall purpose of the smart contract is that `This function allows only the owner to set a new password.`

```javascript
   function setPassword(string memory newPassword) external {
    // @audit - There are noe access controls
        s_password = newPassword;
        emit SetNewPassword();
    }
```

**Impact:** 
Anyone can set the password of the contract, severely breaking the contract intended functionality

**Proof of Concept:**
```javascript
  function test_anyone_can_set_password(address randomAddress) public {
        vm.prank(randomAddress);
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword);

        vm.prank(owner);
        string memory actualPassword = passwordStore.getPassword();
        assertEq(actualPassword, expectedPassword);
    }
```

**Recommended Mitigation:** 
Add an access control to the `setPassword` function.