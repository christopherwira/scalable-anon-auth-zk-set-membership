// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
import '../temp/contracts/nullifier_tokenauth_verifier.sol';

contract NullifierTokenAuth is Verifier {
    uint constant INPUT_LENGTH = 33;
    bytes32 public current_merkle_root;
    mapping (bytes32 => bool) is_submitted;
    mapping (bytes32 => bool) is_delegated;
    event successfulAuthentication(address agent);
    event successfulVerification(address agent);
    event successfulStatementCheck(address agent);

    function update_current_merkle_root(bytes32 new_merkle_root) public {
        current_merkle_root = new_merkle_root;
    }

    function decode_proof_input(uint[INPUT_LENGTH] memory input) pure internal returns (bytes32 statement_rt, bytes32 statement_sn, bytes32 statement_cm, bytes32 statement_wm, bool statement_proof_validity) {
        bytes32 decoded_rt;
        bytes32 decoded_sn;
        bytes32 decoded_cm;
        bytes32 decoded_wm;
        bool decoded_proof_validity;

        uint32[INPUT_LENGTH] memory stripped_input;
        for(uint i = 0; i < INPUT_LENGTH; i++){
            stripped_input[i] = uint32(input[i]);
        }

        bytes memory accumulated_rt;
        bytes memory accumulated_sn;
        bytes memory accumulated_cm;
        bytes memory accumulated_wm;

        for(uint i = 0; i < INPUT_LENGTH-1; i++){
            if (i<8){
                accumulated_rt = abi.encodePacked(accumulated_rt, stripped_input[i]);
            }
            else if (i>8-1 && i<16){
                accumulated_sn = abi.encodePacked(accumulated_sn, stripped_input[i]);
            }
            else if (i>16-1 && i<24){
                accumulated_cm = abi.encodePacked(accumulated_cm, stripped_input[i]);
            }
            else if (i>24-1 && i<32){
                accumulated_wm = abi.encodePacked(accumulated_wm, stripped_input[i]);
            }
        }
        decoded_rt = bytes32(accumulated_rt);
        decoded_sn = bytes32(accumulated_sn);
        decoded_cm = bytes32(accumulated_cm);
        decoded_wm = bytes32(accumulated_wm);

        decoded_proof_validity = stripped_input[INPUT_LENGTH-1] == 1;
        return (decoded_rt, decoded_sn, decoded_cm, decoded_wm, decoded_proof_validity);
    }

    function check_replay_attack(bytes32 statement_sn, bytes32 statement_wm) public returns (bool) {
        if (is_delegated[statement_sn]){
            return false;
        }
        if (is_submitted[statement_wm]){
            return false;
        }
        is_submitted[statement_wm] = true;
        return true;
    }

    function statement_check (Proof memory proof, uint[INPUT_LENGTH] memory input) internal returns (bool success) {
        bool statement_rt_validity; // Is the given rt identical to the current registered root?
        bool statement_proof_validity; // Is the proof value in the input returns true?
        bool replay_attack_validity; // Is the given proof is not replayed?

        bytes32 statement_rt;
        bytes32 statement_sn;
        bytes32 statement_cm;
        bytes32 statement_wm;

        (statement_rt, statement_sn, statement_cm, statement_wm, statement_proof_validity) = decode_proof_input(input);
        statement_rt_validity = statement_rt == current_merkle_root;
        replay_attack_validity = check_replay_attack(statement_sn, statement_wm);

        return statement_rt_validity && statement_proof_validity && replay_attack_validity;
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
