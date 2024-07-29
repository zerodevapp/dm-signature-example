// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity 0.8.23;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Action} from "delegation-framework/src/interfaces/IDeleGatorCore.sol";

/**
 * @title IDeleGatorCore
 * @notice Interface for a DeleGator that exposes the minimal functionality required.
 */
interface IDeleGatorCoreBatch is IERC1271 {
    function executeFromExecutor(bytes32 mode, bytes calldata callData) external;
}
