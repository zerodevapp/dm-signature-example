pragma solidity ^0.8.23;

import {ISignatureEnforcer} from "./interfaces/ISignatureEnforcer.sol";

contract SignatureRequestorEnforcer is ISignatureEnforcer {
    function checkSignatureVerification( // temporary name
        bytes calldata _terms,
        bytes calldata _args,
        address _requestor, // address of the contract that called initial DELEGATOR.isValidSignature(bytes32 hash, bytes calldata signature)
        bytes32 _messageHash, // hash that was given on initial DELEGATOR.isValidSignature(bytes32 hash, bytes calldata signature)
        bytes32 _delegateionHash,
        address _delegator,
        address _redeemer
    ) external view returns (bool) {
        address allowedRequestor = abi.decode(_terms, (address));
        return _requestor == allowedRequestor;
    }
}
