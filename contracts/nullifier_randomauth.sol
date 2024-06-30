// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
import '../temp/contracts/nullifier_randomauth_verifier.sol';

contract NullifierRandomAuth is Verifier {
    uint constant INPUT_LENGTH = 14;
    uint constant AUTHENTICATION_ID_LENGTH = 5;
    bytes32 public current_merkle_root;
    mapping (bytes20 => bool) is_submitted;
    event successfulAuthentication(address agent);
    event successfulVerification(address agent);
    event successfulStatementCheck(address agent);

    function update_current_merkle_root(bytes32 new_merkle_root) public {
        current_merkle_root = new_merkle_root;
    }


    function decode_proof_input(uint[INPUT_LENGTH] memory input) pure internal returns (bytes32 statement_root, bytes20 statement_authentication_id, bool statement_membership_validity) {
        bytes32 decoded_root;
        bytes20 decoded_authentication_id;
        bool decoded_membership_validity;

        uint32[INPUT_LENGTH] memory stripped_input;
        for(uint i = 0; i < INPUT_LENGTH; i++){
            stripped_input[i] = uint32(input[i]);
        }

        bytes memory accumulated_root;
        bytes memory accumulated_authentication_id;

        for(uint i = 0; i < INPUT_LENGTH; i++){
            if(i< INPUT_LENGTH-AUTHENTICATION_ID_LENGTH-1) {
                accumulated_root = abi.encodePacked(accumulated_root, stripped_input[i]);
            }
            else if (i < INPUT_LENGTH-1) {
                accumulated_authentication_id = abi.encodePacked(accumulated_authentication_id, stripped_input[i]);
            }
        }
        decoded_root = bytes32(accumulated_root);
        decoded_authentication_id = bytes20(accumulated_authentication_id);
        decoded_membership_validity = stripped_input[INPUT_LENGTH-1] == 1;
        return (decoded_root, decoded_authentication_id, decoded_membership_validity);
    }

    function check_replay_attack(bytes20 authentication_id) public returns(bool) {
        if (is_submitted[authentication_id]){
            return false;
        }
        is_submitted[authentication_id] = true;
        return true;
    }

    function statement_check (Proof memory proof, uint[INPUT_LENGTH] memory input) internal returns (bool success) {
        bool statement_root_validity; // Is the given root identical to the current registered root?
        bool statement_authentication_id_validity; // Is the given authentication_id is valid according to the current authentication_id and is not submitted yet?
        bool statement_membership_validity; // Is the membership value in the input returns true?

        bytes20 statement_authentication_id;
        bytes32 statement_root;
        (statement_root, statement_authentication_id, statement_membership_validity) = decode_proof_input(input);
        statement_root_validity = statement_root == current_merkle_root;
        statement_authentication_id_validity = check_replay_attack(statement_authentication_id);

        return statement_root_validity && statement_authentication_id_validity && statement_membership_validity;
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
