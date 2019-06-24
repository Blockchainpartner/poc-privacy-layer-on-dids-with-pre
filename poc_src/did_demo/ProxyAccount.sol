pragma solidity ^0.5.0;

/**
 * @title ProxyAccount
 * @notice This ProxyAccount should aim to be an implementation of EIP 725 v2.
 * https://github.com/ethereum/eips/issues/725
 * @author Blockchain Partner - <phil@blockchainpartner.fr>
 */
contract ProxyAccount {
  /*
   *  Storage
   */
  address public owner;
  mapping(bytes32 => bytes) public store;

  /*
   *  Modifiers
   */
  modifier onlyOwner() {
    require(owner == msg.sender, "only-owner-allowed");
    _;
  }

  /*
   * Public functions
   */
  /// @dev Contract constructor sets initial owner.
  constructor() public {
    owner = msg.sender;
  }

  /// @dev Get stored data by key.
  /// @param _key Mapping key.
  /// @return Returns the data stored for that key.
  function getData(bytes32 _key) external view returns (bytes memory value) {
    return store[_key];
  }

  /// @dev Allows the owner of the contract to set new data.
  /// @param _key Mapping key to use.
  /// @param _value Data to store.
  function setData(bytes32 _key, bytes calldata _value) external onlyOwner {
    store[_key] = _value;
  }
}
