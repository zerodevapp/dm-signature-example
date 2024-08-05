// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Action, Delegation} from "delegation-framework/src/utils/Types.sol";
import {IDelegationManagerBatch} from "./interfaces/IDelegationManagerBatch.sol";
import "./SenderCreator.sol";

import {ECDSA} from "solady/utils/ECDSA.sol";

contract MultiTenantAccount {
    error ActionFailed(uint256 i, bytes reason);
    error WrongDelegator();
    error WrongDelegate();

    IEntryPoint public immutable ep;
    IDelegationManagerBatch public immutable dm;
    SenderCreator public immutable deployer;

    constructor(IEntryPoint _ep, IDelegationManagerBatch _dm) {
        ep = _ep;
        dm = _dm;
        deployer = new SenderCreator();
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256)
    {
        require(msg.sender == address(ep), "!ep");
        address caller = address(bytes20(bytes32(userOp.nonce)));
        address signer = ecrecover(
            userOpHash,
            uint8(bytes1(userOp.signature[64])),
            bytes32(userOp.signature[0:32]),
            bytes32(userOp.signature[32:64])
        );
        // NOTE : since auth is not allowed on validation phase, you should be have paymaster here, we don't send missingAccountFunds
        // But invoker can still pay for gas when someone staked for the invoker
        if (caller == signer) {
            return 0;
        }
        signer = ecrecover(
            ECDSA.toEthSignedMessageHash(userOpHash),
            uint8(bytes1(userOp.signature[64])),
            bytes32(userOp.signature[0:32]),
            bytes32(userOp.signature[32:64])
        );
        return caller == signer ? 0 : 1; // return true when caller == signer
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external {
        require(msg.sender == address(ep), "!ep");
        bytes calldata execData = userOp.callData[4:];
        (Delegation[] memory delegations, bytes32 executionMode, bytes memory executionData, bytes memory deleGatorInitCode) = abi.decode(execData, (Delegation[], bytes32, bytes, bytes));
        address signer = address(bytes20(bytes32(userOp.nonce)));
        if (delegations[0].delegator != signer) {
            revert WrongDelegator();
        }
        if (delegations[0].delegate != address(this)) {
            revert WrongDelegate();
        }
        if (deleGatorInitCode.length > 0) {
            deployer.createSender(deleGatorInitCode);
        }
        dm.redeemDelegation(abi.encode(delegations), executionMode, executionData);
    }
}
