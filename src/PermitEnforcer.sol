pragma solidity ^0.8.23;

import {ISignatureEnforcer} from "./interfaces/ISignatureEnforcer.sol";
import {MessageHashUtils} from "src/DelegationManagerBatch.sol";

struct PermitTerms {
    address owner;
    address spender;
    uint256 maximum;
}

struct PermitArgs {
    uint256 value;
    uint256 nonce;
    uint256 deadline;
}

interface IUSDC {
    function balanceOf(address account) external view returns (uint256);
    function mint(address to, uint256 amount) external;
    function configureMinter(address minter, uint256 minterAllowedAmount) external;
    function masterMinter() external view returns (address);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) external;
    function nonces(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}
// keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")

bytes32 constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

contract PermitEnforcer is ISignatureEnforcer {
    IUSDC immutable usdc;

    constructor(IUSDC _usdc) {
        usdc = _usdc;
    }

    function checkSignatureVerification( // temporary name
        bytes calldata _terms,
        bytes calldata _args,
        address _requestor, // address of the contract that called initial DELEGATOR.isValidSignature(bytes32 hash, bytes calldata signature)
        bytes32 _messageHash, // hash that was given on initial DELEGATOR.isValidSignature(bytes32 hash, bytes calldata signature)
        bytes32 _delegateionHash,
        address _delegator,
        address _redeemer
    ) external view returns (bool) {
        PermitTerms memory pt = parseTerms(_terms);
        PermitArgs memory pa = parseArgs(_args);
        require(pt.maximum >= pa.value, "value exceeds maximum");
        bytes32 generatedTypedDataHash = MessageHashUtils.toTypedDataHash(
            usdc.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(PERMIT_TYPEHASH, pt.owner, pt.spender, pa.value, pa.nonce, pa.deadline))
        );
        require(generatedTypedDataHash == _messageHash, "message hash does not match args/terms");
        return _requestor == address(usdc);
    }

    function parseTerms(bytes calldata _terms) internal pure returns (PermitTerms memory) {
        return abi.decode(_terms, (PermitTerms));
    }

    function parseArgs(bytes calldata _args) internal pure returns (PermitArgs memory) {
        return abi.decode(_args, (PermitArgs));
    }
}
