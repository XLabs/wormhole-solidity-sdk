
pragma solidity ^0.8.19;

import "wormhole-sdk/WormholeRelayerSDK.sol";
import "@openzeppelin/token/ERC20/IERC20.sol";
import "wormhole-sdk/testing/WormholeRelayerTest.sol";
import {Toy} from "./Fork.t.sol";

contract ChooseChainsTest is WormholeRelayerBasicTest {
    Toy toySource;
    Toy toyTarget;

    constructor() {
        setTestnetForkChains(4, 5);
    }

    function setUpSource() public override {
        require(wormholeSource.chainId() == 4);
        toySource = new Toy(address(relayerSource), address(wormholeSource));
        toySource.setRegisteredSender(targetChain, toUniversalAddress(address(this)));
    }

    function setUpTarget() public override {
        require(wormholeTarget.chainId() == 5);
        toyTarget = new Toy(address(relayerTarget), address(wormholeTarget));
        toyTarget.setRegisteredSender(sourceChain, toUniversalAddress(address(this)));
    }

    function testSendMessage() public {
        vm.recordLogs();
        (uint256 cost,) = relayerSource.quoteEVMDeliveryPrice(targetChain, 1e17, 100_000);
        relayerSource.sendPayloadToEvm{value: cost}(targetChain, address(toyTarget), abi.encode(55), 1e17, 100_000);
        performDelivery();

        vm.selectFork(targetFork);
        require(55 == toyTarget.payloadReceived());
    }

    function testSendMessageSource() public {
        vm.selectFork(targetFork);
        vm.recordLogs();

        (uint256 cost,) = relayerTarget.quoteEVMDeliveryPrice(sourceChain, 1e17, 100_000);
        relayerTarget.sendPayloadToEvm{value: cost}(sourceChain, address(toySource), abi.encode(56), 1e17, 100_000);
        performDelivery();

        vm.selectFork(sourceFork);
        require(56 == toySource.payloadReceived());
    }
}
