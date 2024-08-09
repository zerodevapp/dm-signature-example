// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity 0.8.23;

import "kernel/src/utils/ExecLib.sol";
import {CaveatEnforcerBatch} from "./CaveatEnforcerBatch.sol";

/**
 * @title AllowedMethodsEnforcer
 * @dev This contract enforces the allowed methods a delegate may call.
 */
contract AllowedMethodsEnforcer is CaveatEnforcerBatch {
    ////////////////////////////// Custom Errors //////////////////////////////

    error InvalidCallType();
    error MethodNotAllowed();

    ////////////////////////////// Public Methods //////////////////////////////

    /**
     * @notice Allows the delegator to limit what methods the delegate may call.
     * @dev This function enforces the allowed methods before the transaction is performed.
     * @param _terms A series of 4byte method identifiers, representing the methods that the delegate is allowed to call.
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
        bytes4[] memory allowedSignatures_ = getTermsInfo(_terms);
        (CallType callType_,,,) = ExecLib.decode(ExecMode.wrap(_executionMode));
        if (callType_ == CALLTYPE_SINGLE) {
            (,, bytes calldata callData_) = ExecLib.decodeSingle(_executionData);
            bytes4 targetSig_ = bytes4(callData_[0:4]);
            bool signaturePass_ = _checkSignature(allowedSignatures_, targetSig_);
            if (!signaturePass_) {
                revert MethodNotAllowed();
            }
        } else if (callType_ == CALLTYPE_BATCH) {
            Execution[] calldata exec_ = ExecLib.decodeBatch(_executionData);
            for (uint256 j = 0; j < exec_.length; j++) {
                bytes4 targetSig_ = bytes4(exec_[j].callData[0:4]);
                bool signaturePass_ = _checkSignature(allowedSignatures_, targetSig_);
                if (!signaturePass_) {
                    revert MethodNotAllowed();
                }
            }
        } else if (callType_ == CALLTYPE_DELEGATECALL) {
            bytes4 targetSig_ = bytes4(_executionData[20:24]);
            bool signaturePass_ = _checkSignature(allowedSignatures_, targetSig_);
            if (!signaturePass_) {
                revert MethodNotAllowed();
            }
        } else {
            revert InvalidCallType();
        }
    }

    /**
     * @dev Checks the method signature with set of allowed method signatures.
     * @param _allowedSignatures The allowed signatures array.
     * @param _targetSig The target method signature of the calldata.
     * @return A boolean indicating whether the target method signature matches one of the allowed target method signatures.
     */
    function _checkSignature(bytes4[] memory _allowedSignatures, bytes4 _targetSig) internal pure returns (bool) {
        for (uint256 i = 0; i < _allowedSignatures.length; ++i) {
            if (_targetSig == _allowedSignatures[i]) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Decodes the terms used in this CaveatEnforcer.
     * @param _terms encoded data that is used during the execution hooks.
     * @return allowedMethods_ The 4 byte identifiers for the methods that the delegate is allowed to call.
     */
    function getTermsInfo(bytes calldata _terms) public pure returns (bytes4[] memory allowedMethods_) {
        uint256 j = 0;
        uint256 termsLength_ = _terms.length;
        require(termsLength_ % 4 == 0, "AllowedMethodsEnforcer:invalid-terms-length");
        allowedMethods_ = new bytes4[](termsLength_ / 4);
        for (uint256 i = 0; i < termsLength_; i += 4) {
            allowedMethods_[j] = bytes4(_terms[i:i + 4]);
            j++;
        }
    }
}
