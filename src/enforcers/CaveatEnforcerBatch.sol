// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity 0.8.23;

import {ICaveatEnforcerBatch} from "../interfaces/ICaveatEnforcerBatch.sol";

/**
 * @title CaveatEnforcer
 * @dev This abstract contract enforces caveats before and after the execution of an action.
 */
abstract contract CaveatEnforcerBatch is ICaveatEnforcerBatch {
    /// @inheritdoc ICaveatEnforcerBatch
    function beforeHook(bytes calldata, bytes calldata, bytes32, bytes calldata, bytes32, address, address)
        public
        virtual
    {}

    /// @inheritdoc ICaveatEnforcerBatch
    function afterHook(bytes calldata, bytes calldata, bytes32, bytes calldata, bytes32, address, address)
        public
        virtual
    {}
}
