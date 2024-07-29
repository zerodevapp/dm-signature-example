pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SubAccount, SubAccountFactory, ROOT_AUTHORITY} from "src/SubAccount.sol";
import {DelegationManager} from "delegation-framework/src/DelegationManager.sol";
import {DelegationManagerBatch, MessageHashUtils} from "src/DelegationManagerBatch.sol";
import {IDelegationManager} from "delegation-framework/src/interfaces/IDelegationManager.sol";
import {IDelegationManagerBatch} from "src/interfaces/IDelegationManagerBatch.sol";
import {Action, Delegation, Caveat} from "delegation-framework/src/utils/Types.sol";
import {PERMIT2_ADDRESS, CREATE2_PROXY, PERMIT2_INIT_CODE} from "src/constants.sol";
import {ERC20} from "solady/tokens/ERC20.sol";
import {EntryPointLib} from "./EntryPointLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import "forge-std/console.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {ExecMode, ExecLib} from "kernel/src/utils/ExecLib.sol";
import {SignatureRequestorEnforcer} from "src/SignatureRequestorEnforcer.sol";

contract MockCallee {
    mapping(address caller => uint256) public barz;

    function foo(uint256 bar) external payable {
        barz[msg.sender] = bar;
    }
}

contract MockERC20 is ERC20 {
    function name() public view override returns (string memory) {
        return "MOCK";
    }

    function symbol() public view override returns (string memory) {
        return "MOCK";
    }

    function mint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }
}

// keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
bytes32 constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

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

contract DMTest is Test {
    DelegationManagerBatch public dm;
    SubAccountFactory public factory;
    address master;
    uint256 masterKey;
    address session;
    uint256 sessionKey;
    SubAccount subAccount;
    MockCallee mockCallee;
    MockERC20 mockERC20;
    address owner;

    function setUp() external {
        (bool success,) = CREATE2_PROXY.call(PERMIT2_INIT_CODE);
        (master, masterKey) = makeAddrAndKey("Master");
        (session, sessionKey) = makeAddrAndKey("Session");
        owner = makeAddr("Owner");
        dm = new DelegationManagerBatch(owner);
        factory = new SubAccountFactory(IDelegationManagerBatch(address(dm)));
        subAccount =
            SubAccount(factory.createAccount(abi.encodeWithSelector(SubAccount.initialize.selector, master), 0));
        mockCallee = new MockCallee();
        mockERC20 = new MockERC20();
        mockERC20.mint(master, 1000);
    }

    function testMasterSignature() external {
        vm.startPrank(master);
        Delegation[] memory d = new Delegation[](1);
        Caveat[] memory c = new Caveat[](0);
        d[0] = Delegation({
            delegate: master,
            delegator: address(subAccount),
            authority: ROOT_AUTHORITY,
            caveats: c,
            salt: 0,
            signature: hex""
        });
        bytes32 h = keccak256(bytes.concat("he0000"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(masterKey, h);
        assertEq(subAccount.isValidSignature(h, abi.encode(d, bytes.concat(r, s, bytes1(v)))), bytes4(0x1626ba7e));
    }

    function testSessionKeyUseOnlyUSDCPermit() external {
        SignatureRequestorEnforcer signatureRequestorEnforcer = new SignatureRequestorEnforcer();
        //// USDC contract address on mainnet
        IUSDC usdc = IUSDC(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

        // spoof .configureMinter() call with the master minter account
        vm.prank(usdc.masterMinter());
        // allow this test contract to mint USDC
        usdc.configureMinter(address(this), type(uint256).max);
        // mint $1000 USDC to the test contract (or an external user)
        usdc.mint(address(this), 1000e6);
        vm.stopPrank();

        Delegation[] memory d = new Delegation[](2);
        Caveat[] memory e = new Caveat[](0);
        d[1] = Delegation({
            delegate: master,
            delegator: address(subAccount),
            authority: ROOT_AUTHORITY,
            caveats: e,
            salt: 0,
            signature: hex""
        });
        console.log("Master : ", master);
        // delegate usdc permit signature to session
        Caveat[] memory c = new Caveat[](1);
        c[0] = Caveat({enforcer: address(signatureRequestorEnforcer), terms: abi.encode(address(usdc)), args: hex""});
        d[0] = Delegation({
            delegate: session,
            delegator: master,
            authority: dm.getDelegationHash(d[1]),
            caveats: c,
            salt: 0,
            signature: hex""
        });
        d[0].signature = signDelegation(d[0], masterKey);

        address spender = makeAddr("Spender");
        uint256 allowance = 1000;
        bytes32 permitHash = MessageHashUtils.toTypedDataHash(
            usdc.DOMAIN_SEPARATOR(),
            keccak256(
                abi.encode(
                    PERMIT_TYPEHASH, address(subAccount), spender, allowance, usdc.nonces(owner), block.timestamp + 1000
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKey, permitHash);
        usdc.permit(
            address(subAccount),
            spender,
            allowance,
            block.timestamp + 1000,
            abi.encode(d, bytes.concat(r, s, bytes1(v)))
        );

        assertEq(usdc.allowance(address(subAccount), spender), allowance);
    }

    function signDelegation(Delegation memory delegation, uint256 key) internal returns (bytes memory) {
        bytes32 delegationHashWithDomainHash =
            MessageHashUtils.toTypedDataHash(dm.getDomainHash(), dm.getDelegationHash(delegation));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, delegationHashWithDomainHash);
        return abi.encodePacked(r, s, v);
    }
}
