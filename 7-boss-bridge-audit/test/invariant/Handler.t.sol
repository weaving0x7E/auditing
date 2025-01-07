// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import { MessageHashUtils } from "openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {L1Token} from "../../src/L1Token.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";
import { L1BossBridge, L1Vault } from "../../src/L1BossBridge.sol";

contract Handler is Test{
    L1BossBridge bossBridge;
    L1Token token;
    address user0;
    address user1;
    L1Vault vault;
    uint256 operatorKey;

    constructor(
        L1BossBridge _l1BossBridge,
        L1Token _l1Token,
        uint256 _privateKey0,
        uint256 _privateKey1,
        uint256 _operatorKey
        
    ) {
        bossBridge = _l1BossBridge;
        token = _l1Token;
        user0 = vm.addr(_privateKey0);
        user1 = vm.addr(_privateKey1);
        vault = bossBridge.vault();
        operatorKey = _operatorKey;

        vm.prank(user0);
        token.approve(address(bossBridge), type(uint256).max);
    }

    function deposit(uint256 amount) public{
        amount = bound(amount, 0, 100 ether);
        bossBridge.depositTokensToL2(user0, user1, amount);
    }

    function withdraw(uint256 amount) public{
        amount = bound(amount, 0, 100 ether);
        bossBridge.depositTokensToL2(user0, user1, amount);
        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user0,amount), operatorKey);
        bossBridge.withdrawTokensToL1(user0, amount, v, r, s);
    }

    function _signMessage(
        bytes memory message,
        uint256 privateKey
    )
        private
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(privateKey, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));
    }

    function _getTokenWithdrawalMessage(address recipient, uint256 amount) private view returns (bytes memory) {
        return abi.encode(
            address(token), // target
            0, // value
            abi.encodeCall(IERC20.transferFrom, (address(vault), recipient, amount)) // data
        );
    }
}