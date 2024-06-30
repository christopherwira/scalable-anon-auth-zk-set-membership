// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
import '../temp/contracts/hashauth_verifier.sol';

contract HashAuth is Verifier {
    uint constant INPUT_LENGTH = 9;
    bytes32 public current_merkle_root;
    mapping (bytes32 => bool) is_submitted;
    event successfulAuthentication(address agent);
    event successfulVerification(address agent);
    event successfulStatementCheck(address agent);

    function update_current_merkle_root(bytes32 new_merkle_root) public {
        current_merkle_root = new_merkle_root;
    }

    function decode_proof_input(uint[INPUT_LENGTH] memory input) pure internal returns (bytes32 statement_root, bool statement_membership_validity) {
        bytes32 decoded_root;
        bool decoded_membership_validity;

        uint32[INPUT_LENGTH] memory stripped_input;
        for(uint i = 0; i < INPUT_LENGTH; i++){
            stripped_input[i] = uint32(input[i]);
        }

        bytes memory accumulated_root;

        for(uint i = 0; i < INPUT_LENGTH-1; i++){
            accumulated_root = abi.encodePacked(accumulated_root, stripped_input[i]);
        }
        decoded_root = bytes32(accumulated_root);
        decoded_membership_validity = stripped_input[INPUT_LENGTH-1] == 1;
        return (decoded_root, decoded_membership_validity);
    }

    function check_replay_attack(Proof memory proof, uint[INPUT_LENGTH] memory input) public returns (bool) {
        bytes32 hash_result = keccak256(abi.encode(proof, input));
        if (is_submitted[hash_result]){
            return false;
        }
        is_submitted[hash_result] = true;
        return true;
    }

    function statement_check (Proof memory proof, uint[INPUT_LENGTH] memory input) internal returns (bool success) {
        bool statement_root_validity; // Is the given root identical to the current registered root?
        bool statement_membership_validity; // Is the membership value in the input returns true?
        bool replay_attack_validity; // Is the given proof is not replayed?

        bytes32 statement_root;
        (statement_root, statement_membership_validity) = decode_proof_input(input);
        statement_root_validity = statement_root == current_merkle_root;
        replay_attack_validity = check_replay_attack(proof, input);

        return statement_root_validity && statement_membership_validity && replay_attack_validity;
    }

    function authentication (Proof memory proof, uint[INPUT_LENGTH] memory input) internal returns (bool success) {
        bool statement_check_validity = statement_check(proof, input);
        if(!statement_check_validity){
            return false;
        }
        
        bool proof_validity; // Is the verification process of the ZKP returns true?
        proof_validity = verifyTx(proof, input);
        return statement_check_validity && proof_validity;
    }

    function authentication_with_broadcast (Proof memory proof, uint[INPUT_LENGTH] memory input) public {
        if(authentication(proof, input)){
            emit successfulAuthentication(msg.sender);
        }
    }

    function verification_with_broadcast (Proof memory proof, uint[INPUT_LENGTH] memory input) public {
        if(verifyTx(proof, input)){
            emit successfulVerification(msg.sender);
        }
    }

    function statement_check_with_broadcast (Proof memory proof, uint[INPUT_LENGTH] memory input) public {
        if (statement_check(proof,input)){
            emit successfulStatementCheck(msg.sender);
        }
    }
}
