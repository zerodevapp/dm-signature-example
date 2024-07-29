// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity 0.8.23;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {ICaveatEnforcerBatch} from "./interfaces/ICaveatEnforcerBatch.sol";
import {ISignatureEnforcer} from "./interfaces/ISignatureEnforcer.sol";
import {IDelegationManagerBatch} from "./interfaces/IDelegationManagerBatch.sol";
import {IDeleGatorCoreBatch} from "./interfaces/IDeleGatorCoreBatch.sol";
import {Action, Delegation, Caveat} from "delegation-framework/src/utils/Types.sol";
import {EncoderLib} from "delegation-framework/src/libraries/EncoderLib.sol";
import {ERC1271Lib} from "delegation-framework/src/libraries/ERC1271Lib.sol";
import {DelegationManager} from "delegation-framework/src/DelegationManager.sol";

contract DelegationManagerBatch is IDelegationManagerBatch, Ownable2Step, Pausable, EIP712 {
    using MessageHashUtils for bytes32;

    ////////////////////////////// State //////////////////////////////

    /// @dev The name of the contract
    string public constant NAME = "DelegationManager";

    /// @dev The full version of the contract
    string public constant VERSION = "1.0.0";

    /// @dev The version used in the domainSeparator for EIP712
    string public constant DOMAIN_VERSION = "1";

    /// @dev Special authority value. Indicates that the delegator is the authority
    bytes32 public constant ROOT_AUTHORITY = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    /// @dev Special delegate value. Allows any delegate to redeem the delegation
    address public constant ANY_DELEGATE = address(0xa11);

    /// @dev A mapping of delegation hashes that have been cached onchain
    mapping(bytes32 delegationHash => bool isOnchain) public onchainDelegations;

    /// @dev A mapping of delegation hashes that have been disabled by the delegator
    mapping(bytes32 delegationHash => bool isDisabled) public disabledDelegations;

    ////////////////////////////// Modifier //////////////////////////////

    /**
     * @notice Require the caller to be the delegator
     * This is to prevent others from accessing protected methods.
     * @dev Check that the caller is delegator.
     */
    modifier onlyDeleGator(address delegator) {
        if (delegator != msg.sender) revert InvalidDelegator();
        _;
    }

    ////////////////////////////// Constructor //////////////////////////////

    /**
     * @notice Initializes Ownable and the DelegationManager's state
     * @param _owner The initial owner of the contract
     */
    constructor(address _owner) Ownable(_owner) EIP712(NAME, DOMAIN_VERSION) {
        bytes32 DOMAIN_HASH = _domainSeparatorV4();
        emit SetDomain(DOMAIN_HASH, NAME, DOMAIN_VERSION, block.chainid, address(this));
    }

    ////////////////////////////// External Methods //////////////////////////////

    /**
     * @notice Allows the owner of the DelegationManager to pause delegation redemption functionality
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Allows the owner of the DelegationManager to unpause the delegation redemption functionality
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice This method is used to cache a delegation's hash onchain for future use
     * @dev This method MUST be called by the delegator
     * @dev Caching a delegation onchain allows the system to trust that the delegation was already authorized at the time of
     * redemption
     * @param _delegation The delegation to be stored
     */
    function delegate(Delegation calldata _delegation) external onlyDeleGator(_delegation.delegator) {
        bytes32 delegationHash_ = getDelegationHash(_delegation);
        if (onchainDelegations[delegationHash_]) revert AlreadyExists();
        onchainDelegations[delegationHash_] = true;
        emit Delegated(delegationHash_, _delegation.delegator, _delegation.delegate, _delegation);
    }

    /**
     * @notice This method is used to disable a delegation. Disabled delegations will fail upon redemption.
     * @dev This method MUST be called by the delegator
     * @dev This method supports disabling offchain and onchain delegations
     * @param _delegation The delegation to be disabled
     */
    function disableDelegation(Delegation calldata _delegation) external onlyDeleGator(_delegation.delegator) {
        bytes32 delegationHash_ = getDelegationHash(_delegation);
        if (disabledDelegations[delegationHash_]) revert AlreadyDisabled();
        disabledDelegations[delegationHash_] = true;
        emit DisabledDelegation(delegationHash_, _delegation.delegator, _delegation.delegate, _delegation);
    }

    /**
     * @notice This method is used to enable a delegation
     * @dev This method MUST be called by the delegator
     * @dev This method supports enabling offchain and onchain delegations
     * @dev This method is only needed when a delegation has previously been disabled
     * @param _delegation The delegation to be disabled
     */
    function enableDelegation(Delegation calldata _delegation) external onlyDeleGator(_delegation.delegator) {
        bytes32 delegationHash_ = getDelegationHash(_delegation);
        if (!disabledDelegations[delegationHash_]) revert AlreadyEnabled();
        disabledDelegations[delegationHash_] = false;
        emit EnabledDelegation(delegationHash_, _delegation.delegator, _delegation.delegate, _delegation);
    }

    function redeemDelegation(bytes calldata _data, bytes32 _executionMode, bytes calldata _executionData)
        external
        whenNotPaused
    {
        Delegation[] memory delegations_ = abi.decode(_data, (Delegation[]));

        // Validate caller
        if (delegations_.length == 0) {
            revert NoDelegationsProvided();
        }

        // Load delegation hashes and validate signatures (leaf to root)
        bytes32[] memory delegationHashes_ = new bytes32[](delegations_.length);
        Delegation memory delegation_;

        // Validate caller
        if (delegations_[0].delegate != msg.sender && delegations_[0].delegate != ANY_DELEGATE) {
            revert InvalidDelegate();
        }

        for (uint256 i; i < delegations_.length; ++i) {
            delegation_ = delegations_[i];
            delegationHashes_[i] = EncoderLib._getDelegationHash(delegation_);

            if (delegation_.signature.length == 0) {
                // Ensure that delegations without signatures have already been validated onchain
                if (!onchainDelegations[delegationHashes_[i]]) {
                    revert InvalidDelegation();
                }
            } else {
                // If the delegation is offchain
                // Check if the delegator is an EOA or a contract
                address delegator_ = delegation_.delegator;

                if (delegator_.code.length == 0) {
                    // Validate delegation if it's an EOA
                    address result_ = ECDSA.recover(
                        MessageHashUtils.toTypedDataHash(getDomainHash(), delegationHashes_[i]), delegation_.signature
                    );
                    if (result_ != delegator_) revert InvalidSignature();
                } else {
                    // Validate delegation if it's a contract
                    bytes32 typedDataHash_ = MessageHashUtils.toTypedDataHash(getDomainHash(), delegationHashes_[i]);

                    bytes32 result_ = IERC1271(delegator_).isValidSignature(typedDataHash_, delegation_.signature);
                    if (result_ != ERC1271Lib.EIP1271_MAGIC_VALUE) {
                        revert InvalidSignature();
                    }
                }
            }
        }

        // (leaf to root)
        for (uint256 i; i < delegations_.length; ++i) {
            // Validate if delegation is disabled
            if (disabledDelegations[delegationHashes_[i]]) {
                revert CannotUseADisabledDelegation();
            }

            // Validate authority
            if (i != delegations_.length - 1) {
                if (delegations_[i].authority != delegationHashes_[i + 1]) {
                    revert InvalidAuthority();
                }
                // Validate delegate
                address nextDelegate = delegations_[i + 1].delegate;
                if (nextDelegate != ANY_DELEGATE && delegations_[i].delegator != nextDelegate) {
                    revert InvalidDelegate();
                }
            } else if (delegations_[i].authority != ROOT_AUTHORITY) {
                revert InvalidAuthority();
            }
        }

        {
            // beforeHook (leaf to root)
            for (uint256 i; i < delegations_.length; ++i) {
                _beforeHook(delegations_[i], delegationHashes_[i], _executionMode, _executionData);
            }
        }

        // Execute action (root)
        IDeleGatorCoreBatch(delegations_[delegations_.length - 1].delegator).executeFromExecutor(
            _executionMode, _executionData
        );

        // afterHook (root to leaf)
        for (uint256 i = delegations_.length; i > 0; --i) {
            _afterHook(delegations_[i - 1], delegationHashes_[i - 1], _executionMode, _executionData);
        }
        for (uint256 i; i < delegations_.length; ++i) {
            emit RedeemedDelegation(delegations_[delegations_.length - 1].delegator, msg.sender, delegations_[i]);
        }
    }

    function _beforeHook(
        Delegation memory delegation,
        bytes32 delegationHash,
        bytes32 executionMode,
        bytes calldata executionData
    ) internal {
        Caveat[] memory caveats_ = delegation.caveats;
        address delegator_ = delegation.delegator;
        uint256 caveatsLength_ = caveats_.length;
        for (uint256 j; j < caveatsLength_; ++j) {
            ICaveatEnforcerBatch enforcer_ = ICaveatEnforcerBatch(caveats_[j].enforcer);
            enforcer_.beforeHook(
                caveats_[j].terms,
                caveats_[j].args,
                executionMode,
                executionData,
                delegationHash,
                delegator_,
                msg.sender
            );
        }
    }

    function _afterHook(
        Delegation memory delegation,
        bytes32 delegationHash,
        bytes32 executionMode,
        bytes calldata executionData
    ) internal {
        Caveat[] memory caveats_ = delegation.caveats;
        address delegator_ = delegation.delegator;
        uint256 caveatsLength_ = caveats_.length;
        for (uint256 j; j < caveatsLength_; ++j) {
            ICaveatEnforcerBatch enforcer_ = ICaveatEnforcerBatch(caveats_[j].enforcer);
            enforcer_.afterHook(
                caveats_[j].terms,
                caveats_[j].args,
                executionMode,
                executionData,
                delegationHash,
                delegator_,
                msg.sender
            );
        }
    }

    function delegateSignature(address _requestor, bytes32 _messageHash, bytes calldata _data)
        external
        view
        returns (bytes4)
    {
        (Delegation[] memory delegations_, bytes memory signature) = abi.decode(_data, (Delegation[], bytes));

        // Validate caller
        if (delegations_.length == 0) {
            revert NoDelegationsProvided();
        }

        // Load delegation hashes and validate signatures (leaf to root)
        bytes32[] memory delegationHashes_ = new bytes32[](delegations_.length);
        Delegation memory delegation_;
        address redeemer = delegations_[0].delegate;

        // Validate caller
        if (delegations_[delegations_.length - 1].delegator != msg.sender) {
            revert InvalidDelegate();
        }

        for (uint256 i; i < delegations_.length; ++i) {
            delegation_ = delegations_[i];
            delegationHashes_[i] = EncoderLib._getDelegationHash(delegation_);

            if (delegation_.signature.length == 0) {
                // Ensure that delegations without signatures have already been validated onchain
                if (!onchainDelegations[delegationHashes_[i]]) {
                    revert InvalidDelegation();
                }
            } else {
                // If the delegation is offchain
                // Check if the delegator is an EOA or a contract
                address delegator_ = delegation_.delegator;

                if (delegator_.code.length == 0) {
                    // Validate delegation if it's an EOA
                    address result_ = ECDSA.recover(
                        MessageHashUtils.toTypedDataHash(getDomainHash(), delegationHashes_[i]), delegation_.signature
                    );
                    if (result_ != delegator_) revert InvalidSignature();
                } else {
                    // Validate delegation if it's a contract
                    bytes32 typedDataHash_ = MessageHashUtils.toTypedDataHash(getDomainHash(), delegationHashes_[i]);

                    bytes32 result_ = IERC1271(delegator_).isValidSignature(typedDataHash_, delegation_.signature);
                    if (result_ != ERC1271Lib.EIP1271_MAGIC_VALUE) {
                        revert InvalidSignature();
                    }
                }
            }
        }

        // (leaf to root)
        for (uint256 i; i < delegations_.length; ++i) {
            // Validate if delegation is disabled
            if (disabledDelegations[delegationHashes_[i]]) {
                revert CannotUseADisabledDelegation();
            }

            // Validate authority
            if (i != delegations_.length - 1) {
                if (delegations_[i].authority != delegationHashes_[i + 1]) {
                    revert InvalidAuthority();
                }
                // Validate delegate
                address nextDelegate = delegations_[i + 1].delegate;
                if (nextDelegate != ANY_DELEGATE && delegations_[i].delegator != nextDelegate) {
                    revert InvalidDelegate();
                }
            } else if (delegations_[i].authority != ROOT_AUTHORITY) {
                revert InvalidAuthority();
            }
        }

        {
            // beforeHook (leaf to root)
            for (uint256 i; i < delegations_.length; ++i) {
                if (!_beforeSignatureHook(delegations_[i], delegationHashes_[i], _requestor, _messageHash, redeemer)) {
                    return 0xffffffff;
                }
            }
        }

        // check signature for the first delegate
        //return IDeleGatorCoreBatch(delegations_[0].delegate).isValidSignature(
        //    _messageHash,
        //    signature
        //);
        if (redeemer.code.length == 0) {
            // Validate delegation if it's an EOA
            address result_ = ECDSA.recover(_messageHash, signature);
            if (result_ != redeemer) revert InvalidSignature();
        } else {
            // Validate delegation if it's a contract
            bytes32 result_ = IERC1271(redeemer).isValidSignature(_messageHash, signature);
            if (result_ != ERC1271Lib.EIP1271_MAGIC_VALUE) {
                revert InvalidSignature();
            }
        }

        return ERC1271Lib.EIP1271_MAGIC_VALUE;
    }

    function _beforeSignatureHook(
        Delegation memory delegation,
        bytes32 delegationHash,
        address requestor,
        bytes32 messageHash,
        address redeemer
    ) internal view returns (bool) {
        Caveat[] memory caveats_ = delegation.caveats;
        address delegator_ = delegation.delegator;
        uint256 caveatsLength_ = caveats_.length;
        for (uint256 j; j < caveatsLength_; ++j) {
            ISignatureEnforcer enforcer_ = ISignatureEnforcer(caveats_[j].enforcer);
            if (
                !enforcer_.checkSignatureVerification(
                    caveats_[j].terms, caveats_[j].args, requestor, messageHash, delegationHash, delegator_, msg.sender
                )
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice This method returns the domain hash used for signing typed data
     * @return bytes32 The domain hash
     */
    function getDomainHash() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @notice Creates a hash of a Delegation
     * @dev Used in EIP712 signatures and as a key for storing delegations onchain
     * @param _input A Delegation struct
     */
    function getDelegationHash(Delegation calldata _input) public pure returns (bytes32) {
        return EncoderLib._getDelegationHash(_input);
    }
}
