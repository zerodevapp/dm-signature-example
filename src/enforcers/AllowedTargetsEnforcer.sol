// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity 0.8.23;

import "kernel/src/utils/ExecLib.sol";
import {CaveatEnforcerBatch} from "./CaveatEnforcerBatch.sol";

/**
 * @title AllowedTargetsEnforcer
 * @dev This contract enforces the allowed target addresses for a delegate.
 */
contract AllowedTargetsEnforcer is CaveatEnforcerBatch {
    ////////////////////////////// Custom Errors //////////////////////////////

    error InvalidCallType();
    error TargetNotAllowed();

    ////////////////////////////// Public Methods //////////////////////////////

    /**
     * @notice Allows the delegator to limit what addresses the delegate may call.
     * @dev This function enforces the allowed target addresses before the transaction is performed.
     * @param _terms A series of 20byte addresses, representing the addresses that the delegate is allowed to call.
     * @param _executionData The executionData the delegate is trying try to execute.
     */
    function beforeHook(
        bytes calldata _terms,
        bytes calldata,
        bytes32 _executionMode,
        bytes calldata _executionData,
        bytes32,
        address,
        address
    ) public pure override {
        address[] memory allowedTargets_ = getTermsInfo(_terms);
        (CallType callType_,,,) = ExecLib.decode(ExecMode.wrap(_executionMode));
        if (callType_ == CALLTYPE_SINGLE) {
            (address targetAddress_,,) = ExecLib.decodeSingle(_executionData);
            bool targetPass_ = _checkTargetAddress(allowedTargets_, targetAddress_);
            if (!targetPass_) {
                revert TargetNotAllowed();
            }
        } else if (callType_ == CALLTYPE_BATCH) {
            Execution[] calldata exec = ExecLib.decodeBatch(_executionData);
            for (uint256 j = 0; j < exec.length; j++) {
                address targetAddress_ = exec[j].target;
                bool targetPass_ = _checkTargetAddress(allowedTargets_, targetAddress_);
                if (!targetPass_) {
                    revert TargetNotAllowed();
                }
            }
        } else if (callType_ == CALLTYPE_DELEGATECALL) {
            address targetAddress_ = address(bytes20(_executionData[0:20]));
            bool targetPass_ = _checkTargetAddress(allowedTargets_, targetAddress_);
            if (!targetPass_) {
                revert TargetNotAllowed();
            }
        } else {
            revert InvalidCallType();
        }

        revert("AllowedTargetsEnforcer:target-address-not-allowed");
    }

    /**
     * @dev Checks the target address with set of allowed target addresses.
     * @param _allowedTargets The allowed targets array.
     * @param _targetAddress The target address of the calldata.
     * @return A boolean indicating whether the target address matches one of the allowed target addresses.
     */
    function _checkTargetAddress(address[] memory _allowedTargets, address _targetAddress)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < _allowedTargets.length; ++i) {
            if (_targetAddress == _allowedTargets[i]) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Decodes the terms used in this CaveatEnforcer.
     * @param _terms encoded data that is used during the execution hooks.
     * @return allowedTargets_ The allowed target addresses.
     */
    function getTermsInfo(bytes calldata _terms) public pure returns (address[] memory allowedTargets_) {
        uint256 j = 0;
        uint256 termsLength_ = _terms.length;
        require(termsLength_ % 20 == 0, "AllowedTargetsEnforcer:invalid-terms-length");
        allowedTargets_ = new address[](termsLength_ / 20);
        for (uint256 i = 0; i < termsLength_; i += 20) {
            allowedTargets_[j] = address(bytes20(_terms[i:i + 20]));
            j++;
        }
    }
}
