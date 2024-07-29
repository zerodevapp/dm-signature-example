// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity 0.8.23;

import {ICaveatEnforcer, Action} from "delegation-framework/src/interfaces/ICaveatEnforcer.sol";

interface ICaveatEnforcerBatch {
    function beforeHook(
        bytes calldata _terms,
        bytes calldata _args,
        bytes32 _executionMode,
        bytes calldata _executionData,
        bytes32 _delegationHash,
        address _delegator,
        address _redeemer
    ) external;

    function afterHook(
        bytes calldata _terms,
        bytes calldata _args,
        bytes32 _executionMode,
        bytes calldata _executionData,
        bytes32 _delegationHash,
        address _delegator,
        address _redeemer
    ) external;
}
