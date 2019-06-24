pragma solidity ^0.5.0;

/**
 * @title ClaimHolder
 * @notice This ClaimHolder should aim to be an implementation of EIP 735.
 * https://github.com/ethereum/EIPs/issues/735
 * @author Blockchain Partner - <phil@blockchainpartner.fr>
 */
contract ClaimHolder {
  /*
   *  Structures
   */
  struct Claim {
    bytes32 topic;
    address issuer;
    string uri;
  }

  /*
   *  Events
   */
  event ClaimAdded(uint indexed claimId, bytes32 indexed topic, address indexed issuer, string uri);

  /*
   *  Storage
   */
  address public owner;
  uint public nbClaims;
  mapping(uint => Claim) public claims;

  /*
   * Public functions
   */
  /// @dev Contract constructor sets initial owner.
  // TODO It should be set to `msg.sender` and ideally deployed through an instance of ProxyAccount.
  constructor(address _owner) public {
    owner = _owner;
  }

  /// @dev Get stored claim by ID.
  /// @param _claimId ID.
  /// @return Returns the claim details.
  function getClaim(uint _claimId) external view returns (bytes32 topic, address issuer, string memory uri) {
    return (claims[_claimId].topic, claims[_claimId].issuer, claims[_claimId].uri);
  }

  /// @dev Allows anyone to store a new claim.
  /// @param _topic Topic of the claim.
  /// @param _uri Detail URI. Typically an IPFS URI.
  function addClaim(bytes32 _topic, string calldata _uri) external returns (uint claimId) {
    claimId = nbClaims;

    claims[claimId].topic = _topic;
    claims[claimId].issuer = msg.sender;
    claims[claimId].uri = _uri;

    emit ClaimAdded(
      claimId,
      claims[claimId].topic,
      claims[claimId].issuer,
      claims[claimId].uri
    );

    nbClaims++;
    return claimId;
  }
}