// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
import '../temp/contracts/npauth_verifier.sol';

contract NPAuth is Verifier {
    uint constant INPUT_LENGTH = 14;
    uint constant ADDRESS_ACCOUNT_LENGTH = 5;
    bytes32 public current_merkle_root;
    event successfulAuthentication(address agent);
    event successfulVerification(address agent);
    event successfulStatementCheck(address agent);

    function update_current_merkle_root(bytes32 new_merkle_root) public {
        current_merkle_root = new_merkle_root;
    }

    function decode_proof_input(uint[INPUT_LENGTH] memory input) pure internal returns (bytes32 statement_root, address statement_agent, bool statement_membership_validity) {
        bytes32 decoded_root;
        address decoded_address;
        bool decoded_membership_validity;

        uint32[INPUT_LENGTH] memory stripped_input;
        for(uint i = 0; i < INPUT_LENGTH; i++){
            stripped_input[i] = uint32(input[i]);
        }

        bytes memory accumulated_root;
        bytes memory accumulated_address;

        for(uint i = 0; i < INPUT_LENGTH; i++){
            if(i< INPUT_LENGTH-ADDRESS_ACCOUNT_LENGTH-1) {
                accumulated_root = abi.encodePacked(accumulated_root, stripped_input[i]);
            }
            else if (i < INPUT_LENGTH-1) {
                accumulated_address = abi.encodePacked(accumulated_address, stripped_input[i]);
            }
        }
        decoded_root = bytes32(accumulated_root);
        decoded_address = address(uint160(bytes20(accumulated_address)));
        decoded_membership_validity = stripped_input[INPUT_LENGTH-1] == 1;
        return (decoded_root, decoded_address, decoded_membership_validity);
    }

    function check_replay_attack(address statement_agent) view public returns(bool) {
        return statement_agent == msg.sender;
    }

    function statement_check (Proof memory proof, uint[INPUT_LENGTH] memory input) internal view returns (bool success) {
        bool statement_root_validity; // Is the given root identical to the current registered root?
        bool statement_agent_validity; // Is the given agent address identical to the account that invoke this call?
        bool statement_membership_validity; // Is the membership value in the input returns true?

        address statement_agent;
        bytes32 statement_root;
        (statement_root, statement_agent, statement_membership_validity) = decode_proof_input(input);
        statement_root_validity = statement_root == current_merkle_root;
        statement_agent_validity = check_replay_attack(statement_agent);

        return statement_root_validity && statement_agent_validity && statement_membership_validity;
    }

    function authentication (Proof memory proof, uint[INPUT_LENGTH] memory input) internal view returns (bool success) {
        bool statement_check_validity = statement_check(proof, input);
        if (!statement_check_validity){
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
