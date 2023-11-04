//SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./IWhitelistRegistrarController.sol";
import "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";

address constant EAS_ADDRESS = 0x4200000000000000000000000000000000000021;
bytes32 constant LIST_SCHEMA = 0x3e3e2172aebb902cf7aa6e1820809c5b469af139e7a4265442b1c22b97c6b2a5;
uint256 constant DEADLINE = 1704067200;

bytes32 constant TOWN_NAMEHASH = 0x4e64474f406bfb88babba9d48fc501844ea2246343195cdcfe2fb6b54571b71b;
address constant NAMEWRAPPER_REGISTRY_ADDRESS = 0x888811E08f362edB8B1BF4A52c08fED2A58a427E;
address constant REGISTRAR_ADDRESS = 0xB02EDc247246ACD78294c62F403B3e64D5917031;
address constant PUBLIC_RESOLVER_ADDRESS = 0x888811Da0c852089cc8DFE6f3bAd190a46acaAE6;
uint256 constant DOMAIN_EXPIRATION = 1735689600;

interface IOwnerOf {
    function ownerOf(bytes32 node) external view returns (address owner);
}

contract RetrolistAttestor {
    /**
     * @dev The signature has an invalid length.
     */
    error ECDSAInvalidSignatureLength(uint256 length);

    error Forbidden();

    event RetrolistAttest(
        address indexed attestor,
        bytes32 indexed node,
        bytes32 indexed attestationUid,
        string listName,
        string listMetadataPtr
    );

    function attest(
        bytes32 node,
        uint256 listMetadataPtrType,
        string calldata listName,
        string calldata listMetadataPtr,
        bytes memory listSignature
    ) public {
        // Check node ownership
        if (IOwnerOf(NAMEWRAPPER_REGISTRY_ADDRESS).ownerOf(node) != msg.sender) {
            revert Forbidden();
        }

        if (listSignature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(listSignature, 0x20))
                s := mload(add(listSignature, 0x40))
                v := byte(0, mload(add(listSignature, 0x60)))
            }

            IEAS(EAS_ADDRESS).attestByDelegation(
                DelegatedAttestationRequest({
                    schema: LIST_SCHEMA,
                    data: AttestationRequestData({
                        recipient: msg.sender,
                        expirationTime: 0,
                        revocable: true,
                        refUID: bytes32(0),
                        data: abi.encode(
                            listName,
                            listMetadataPtrType,
                            listMetadataPtr
                        ),
                        value: 0
                    }),
                    signature: Signature({v: v, r: r, s: s}),
                    attester: msg.sender,
                    deadline: 1673891048
                })
            );
        } else {
            revert ECDSAInvalidSignatureLength(listSignature.length);
        }
    }

    event RetrolistRegisterDomain(
        address indexed owner,
        bytes32 indexed node,
        string name
    );

    function register(
        string calldata name,
        address owner,
        bytes32 secret,
        bytes[] calldata data,
        bytes calldata operatorSignature
    ) public payable {
        IWhitelistRegistrarController(REGISTRAR_ADDRESS).register{value: msg.value}(
            name,
            owner,
            DOMAIN_EXPIRATION,
            secret,
            PUBLIC_RESOLVER_ADDRESS,
            data,
            true,
            0,
            operatorSignature
        );

        emit RetrolistRegisterDomain(
            owner,
            keccak256(
                abi.encodePacked(
                    TOWN_NAMEHASH,
                    keccak256(abi.encodePacked(name))
                )
            ),
            name
        );
    }

    function registerAndAttest(
        string calldata name,
        address owner,
        bytes32 secret,
        bytes[] calldata data,
        bytes calldata operatorSignature,

        bytes32 node,
        uint256 listMetadataPtrType,
        string calldata listName,
        string calldata listMetadataPtr,
        bytes memory listSignature
    ) public payable {
        register(
            name,
            owner,
            secret,
            data,
            operatorSignature
        );

        attest(
            node,
            listMetadataPtrType,
            listName,
            listMetadataPtr,
            listSignature
        );
    }
}
