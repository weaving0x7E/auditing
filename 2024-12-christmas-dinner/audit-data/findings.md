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



</details>

**Recommended Mitigation:** 



