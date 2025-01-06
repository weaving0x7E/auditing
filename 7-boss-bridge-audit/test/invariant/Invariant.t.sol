pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Handler} from "./Handler.t.sol";
import {L1Token} from "../../src/L1Token.sol";
import {L1BossBridge} from "../../src/L1BossBridge.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";

contract AttemptBrakeTest is StdInvariant, Test{
    Handler handler;
    L1BossBridge bossBridge;
    L1Token token;
    Account operator = makeAccount("operator");
    uint256 user0PrivateKey = 0x00002;
    uint256 user1PrivateKey = 0x00001;
    address deployer = makeAddr("deployer");
    address user0 = vm.addr(user0PrivateKey);
    address user1 = vm.addr(user1PrivateKey);

    function setUp() public {
        vm.startPrank(deployer);
        token = new L1Token();
        token.transfer(user0, 1000e18);
     
        // Deploy bridge
        bossBridge = new L1BossBridge(IERC20(token));
        
        bossBridge.setSigner(operator.addr, true);
        vm.stopPrank();

        handler = new Handler(bossBridge,token,user0PrivateKey,user1PrivateKey,operator.key);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = handler.deposit.selector;
        selectors[1] = handler.withdraw.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function invariant_userBalance() public {
        assert(token.balanceOf(user0) + token.balanceOf(address(bossBridge.vault())) == 1000e18);
    }
}