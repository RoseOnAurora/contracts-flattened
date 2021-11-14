// SPDX-License-Identifier: MIT

//  d8888b.  .d88b.  .d8888. d88888b
//  88  `8D .8P  Y8. 88'  YP 88'
//  88oobY' 88    88 `8bo.   88ooooo
//  88`8b   88    88   `Y8b. 88~~~~~
//  88 `88. `8b  d8' db   8D 88.
//  88   YD  `Y88P'  `8888Y' Y88888P

pragma solidity 0.6.12;

import "@boringcrypto/boring-solidity/contracts/libraries/BoringMath.sol";
import "@boringcrypto/boring-solidity/contracts/ERC20.sol";
import "@boringcrypto/boring-solidity/contracts/BoringOwnable.sol";

contract Rose is ERC20, BoringOwnable {
    using BoringMath for uint256;
    string public constant symbol = "ROSE";
    string public constant name = "Rose Token";
    uint8 public constant decimals = 18;
    uint256 public override totalSupply;
    uint256 public constant MAX_SUPPLY = 1000000000e18; // 1 billion ROSE

    function mint(address to, uint256 amount) public onlyOwner {
        require(to != address(0), "ROSE: no mint to zero address");
        require(MAX_SUPPLY >= totalSupply.add(amount), "ROSE: Don't go over MAX");

        totalSupply = totalSupply + amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
