// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import "./RsaVerify.sol";

contract RsaVerifyContract {
    uint256 public s_counter;

    constructor() {
        s_counter++;
    }

    /** @dev Verifies a PKCSv1.5 SHA256 signature
     * @param _sha256 is the sha256 of the data
     * @param _s is the signature
     * @param _e is the exponent
     * @param _m is the modulus
     * @return true if success, false otherwise
     */
    function pkcs1Sha256(
        bytes32 _sha256,
        bytes memory _s,
        bytes memory _e,
        bytes memory _m
    ) public view returns (bool) {
        return RsaVerify.pkcs1Sha256(_sha256, _s, _e, _m);
    }

    /** @dev Verifies a PKCSv1.5 SHA256 signature
     * @param _data to verify
     * @param _s is the signature
     * @param _e is the exponent
     * @param _m is the modulus
     * @return 0 if success, >0 otherwise
     */
    function pkcs1Sha256Raw(
        bytes memory _data,
        bytes memory _s,
        bytes memory _e,
        bytes memory _m
    ) public view returns (bool) {
        return RsaVerify.pkcs1Sha256Raw(_data, _s, _e, _m);
    }

    // Used to test transaction gas fees.
    function pkcs1Sha256RawAndWriteToState(
        bytes memory _data,
        bytes memory _s,
        bytes memory _e,
        bytes memory _m
    ) public {
        require(
            RsaVerify.pkcs1Sha256Raw(_data, _s, _e, _m),
            "failed to verify"
        );
        s_counter++;
    }
}
