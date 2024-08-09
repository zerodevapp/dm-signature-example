// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity 0.8.23;

import {CaveatEnforcerBatch} from "./CaveatEnforcerBatch.sol";
import "kernel/src/utils/ExecLib.sol";

struct ParamRule {
    ParamCondition condition;
    uint64 offset;
    bytes32[] params;
}

enum ParamCondition {
    EQUAL,
    GREATER_THAN,
    LESS_THAN,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN_OR_EQUAL,
    NOT_EQUAL,
    ONE_OF
}

struct Permission {
    CallType callType;
    address target;
    bytes4 selector;
    ParamRule[] rules;
}

/**
 * @title AllowedParamsEnforcer
 * @dev This contract enforces that target, methods and params of the calldata to be executed matches the permissions.
 * @dev A common use case for this enforcer is enforcing function parameters.
 */
contract AllowedParamsEnforcer is CaveatEnforcerBatch {
    ////////////////////////////// Custom Errors //////////////////////////////

    error InvalidCallType();
    error CallViolatesParamRule();

    ////////////////////////////// Public Methods //////////////////////////////

    /**
     * @notice Allows the delegator to restrict the calldata that is executed
     * @dev This function enforces that a subset of the calldata to be executed matches the allowed subset of calldata.
     * @param _terms This is packed bytes
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
        Permission[] memory permissions_;

        (permissions_) = getTermsInfo(_terms);
        (CallType callType_,,,) = ExecLib.decode(ExecMode.wrap(_executionMode));
        if (callType_ == CALLTYPE_SINGLE) {
            (address target_,, bytes calldata callData_) = ExecLib.decodeSingle(_executionData);
            for (uint256 i = 0; i < permissions_.length; i++) {
                Permission memory permission_ = permissions_[i];
                if (
                    (permission_.target == target_ || permission_.target == address(0))
                        && permission_.selector == bytes4(callData_[0:4]) && permission_.callType == CALLTYPE_SINGLE
                ) {
                    bool permissionPass_ = _checkParams(callData_, permission_.rules);
                    if (!permissionPass_) {
                        revert CallViolatesParamRule();
                    }
                    return;
                }
            }
        } else if (callType_ == CALLTYPE_BATCH) {
            Execution[] calldata exec_ = ExecLib.decodeBatch(_executionData);
            for (uint256 j = 0; j < exec_.length; j++) {
                bool permissionFoundAndPassed_ = false;
                bytes4 execSelector_ = bytes4(exec_[j].callData[0:4]);
                for (uint256 i = 0; i < permissions_.length; i++) {
                    Permission memory permission_ = permissions_[i];
                    if (
                        (permission_.target == exec_[j].target || permission_.target == address(0))
                            && permission_.selector == execSelector_ && permission_.callType == CALLTYPE_BATCH
                    ) {
                        bool permissionPass_ = _checkParams(exec_[j].callData, permission_.rules);
                        if (!permissionPass_) {
                            revert CallViolatesParamRule();
                        }
                        permissionFoundAndPassed_ = true;
                        break;
                    }
                }
                if (!permissionFoundAndPassed_) {
                    revert("AllowedParamsEnforcer:no-matching-permissions-found");
                }
            }
            return;
        } else if (callType_ == CALLTYPE_DELEGATECALL) {
            address target_ = address(bytes20(_executionData[0:20]));
            bytes calldata callData_ = _executionData[20:];
            for (uint256 i = 0; i < permissions_.length; i++) {
                Permission memory permission_ = permissions_[i];
                if (
                    (permission_.target == target_ || permission_.target == address(0))
                        && permission_.selector == bytes4(callData_[0:4]) && permission_.callType == CALLTYPE_DELEGATECALL
                ) {
                    bool permissionPass_ = _checkParams(callData_, permission_.rules);
                    if (!permissionPass_) {
                        revert CallViolatesParamRule();
                    }
                    return;
                }
            }
        } else {
            revert InvalidCallType();
        }
        revert("AllowedParamsEnforcer:no-matching-permissions-found");
    }

    /**
     * @dev Checks the params of the calldata to be execute with set of allowed params.
     * @param _data The calldata of the execution.
     * @param _rules The rules array for the params of the calldata.
     * @return A boolean indicating whether all the params satisfies the defined set of rules.
     */
    function _checkParams(bytes calldata _data, ParamRule[] memory _rules) internal pure returns (bool) {
        for (uint256 i = 0; i < _rules.length; i++) {
            ParamRule memory rule_ = _rules[i];
            bytes32 param_ = bytes32(_data[4 + rule_.offset:4 + rule_.offset + 32]);
            // only ONE_OF condition can have multiple params
            if (rule_.condition == ParamCondition.EQUAL && param_ != rule_.params[0]) {
                return false;
            } else if (rule_.condition == ParamCondition.GREATER_THAN && param_ <= rule_.params[0]) {
                return false;
            } else if (rule_.condition == ParamCondition.LESS_THAN && param_ >= rule_.params[0]) {
                return false;
            } else if (rule_.condition == ParamCondition.GREATER_THAN_OR_EQUAL && param_ < rule_.params[0]) {
                return false;
            } else if (rule_.condition == ParamCondition.LESS_THAN_OR_EQUAL && param_ > rule_.params[0]) {
                return false;
            } else if (rule_.condition == ParamCondition.NOT_EQUAL && param_ == rule_.params[0]) {
                return false;
            } else if (rule_.condition == ParamCondition.ONE_OF) {
                bool oneOfStatus = false;
                for (uint256 j = 0; j < rule_.params.length; j++) {
                    if (param_ == rule_.params[j]) {
                        oneOfStatus = true;
                        break;
                    }
                }
                if (!oneOfStatus) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @notice Decodes the terms used in this CaveatEnforcer.
     * @param _terms encoded data that is used during the execution hooks.
     * @return permissions The permissions for the transaction.
     */
    function getTermsInfo(bytes calldata _terms) public pure returns (Permission[] memory permissions) {
        (permissions) = abi.decode(_terms, (Permission[]));
    }
}
