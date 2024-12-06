## Before Audit
* cloc
* solidity metrics

## Static Analysis

### Slither

#### Usage
Run Slither on a Hardhat/Foundry/Dapp/Brownie application:
`slither .`

This is the preferred option if your project has dependencies as Slither relies on the underlying compilation framework to compile source code.
However, you can run Slither on a single file that does not import dependencies:
`slither tests/uninitialized.sol`

### Aderyn
run Aderyn using the following command:

`aderyn [OPTIONS] path/to/your/project`