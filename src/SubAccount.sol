pragma solidity ^0.8.0;

import {DelegationManager} from "delegation-framework/src/DelegationManager.sol";
import {IDelegationManager} from "delegation-framework/src/interfaces/IDelegationManager.sol";
import {IDelegationManagerBatch} from "./interfaces/IDelegationManagerBatch.sol";
import {Action, Delegation, Caveat} from "delegation-framework/src/utils/Types.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {ExecMode, ExecLib} from "kernel/src/utils/ExecLib.sol";

import "./SenderCreator.sol";

import {LibClone} from "solady/utils/LibClone.sol";
import "forge-std/console.sol";

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
}

bytes32 constant ROOT_AUTHORITY = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

contract SubAccount {
    IDelegationManagerBatch public immutable dm;

    bool initialized;

    error AlreadyInitialized();
    error Forbidden();
    error InvalidSignature();

    constructor(IDelegationManagerBatch _dm) {
        dm = _dm;
    }

    function initialize(address _root) external {
        Caveat[] memory caveats = new Caveat[](0);
        if (!initialized) {
            initialized = true;
            dm.delegate(
                Delegation({
                    delegate: _root,
                    delegator: address(this),
                    authority: ROOT_AUTHORITY,
                    caveats: caveats,
                    salt: 0,
                    signature: hex""
                })
            );
        } else {
            revert AlreadyInitialized();
        }
    }

    function executeFromExecutor(ExecMode _executionMode, bytes calldata _executionData) external {
        ExecLib.execute(_executionMode, _executionData);
    }

    function isValidSignature(bytes32 _hash, bytes calldata _sig) external view returns (bytes4) {
        return dm.delegateSignature(msg.sender, _hash, _sig);
    }
}

contract SubAccountFactory {
    SubAccount public immutable implementation;
    SenderCreator public immutable deployer;

    error InitializeError();

    constructor(IDelegationManagerBatch _dm) {
        implementation = new SubAccount(_dm);
        deployer = new SenderCreator();
    }

    function createAccount(bytes calldata data, bytes32 salt) public payable returns (address) {
        bytes32 actualSalt = keccak256(abi.encodePacked(data, salt));
        (bool alreadyDeployed, address account) =
            LibClone.createDeterministicERC1967(msg.value, address(implementation), actualSalt);
        if (!alreadyDeployed) {
            (bool success,) = account.call(data);
            if (!success) {
                revert InitializeError();
            }
        }
        return account;
    }

    function createAccountWithParent(bytes calldata data, bytes32 salt, bytes calldata parentInitCode)
        public
        payable
        returns (address)
    {
        if (parentInitCode.length > 0) {
            deployer.createSender(parentInitCode);
        }
        return createAccount(data, salt);
    }

    function getAddress(bytes calldata data, bytes32 salt) public view virtual returns (address) {
        bytes32 actualSalt = keccak256(abi.encodePacked(data, salt));
        return LibClone.predictDeterministicAddressERC1967(address(implementation), actualSalt, address(this));
    }
}
