/**
 *Submitted for verification at Etherscan.io on 2019-11-27
*/

pragma solidity ^0.4.24;

interface ERC721TokenReceiver
{

    function onERC721Received(address _operator, address _from, uint256 _tokenId, bytes _data) external returns(bytes4);

}

library Buffer {
	function hasCapacityFor(bytes memory buffer, uint256 needed) internal pure returns (bool) {
		uint256 size;
		uint256 used;
		
		assembly {
			size := mload(buffer)
			used := mload(add(buffer, 32))
		}
		return size >= 32 && used <= size - 32 && used + needed <= size - 32;
	}
	
	function toString(bytes memory buffer) internal pure returns (string memory) {
		require(hasCapacityFor(buffer, 0), "Buffer.toString: invalid buffer");
		string memory ret;
		assembly {
			ret := add(buffer, 32)
		}
		return ret;
	}
	
	function append(bytes memory buffer, string memory str) internal view {
		require(hasCapacityFor(buffer, bytes(str).length), "Buffer.append: no capacity");
		assembly {
			let len := mload(add(buffer, 32))
			pop(staticcall(gas, 0x4, add(str, 32), mload(str), add(len, add(buffer, 64)), mload(str)))
			mstore(add(buffer, 32), add(len, mload(str)))
		}
	}
	
	function rect(bytes memory buffer, int256 xpos, int256 ypos, uint256 width, uint256 height, uint256 rgb) internal pure {
		require(hasCapacityFor(buffer, 102), "Buffer.rect: no capacity");
		assembly {
			function numbx1(x, v) -> y {
				// v must be in the closed interval [0, 9]
				// otherwise it outputs junk
				mstore8(x, add(v, 48))
				y := add(x, 1)
			}
			function numbx2(x, v) -> y {
				// v must be in the closed interval [0, 99]
				// otherwise it outputs junk
				y := numbx1(numbx1(x, div(v, 10)), mod(v, 10))
			}
			function numbu3(x, v) -> y {
				// v must be in the closed interval [0, 999]
				// otherwise only the last 3 digits will be converted
				switch lt(v, 100)
				case 0 {
					// without input value sanitation: y := numbx2(numbx1(x, div(v, 100)), mod(v, 100))
					y := numbx2(numbx1(x, mod(div(v, 100), 10)), mod(v, 100))
				}
				default {
    				switch lt(v, 10)
    				case 0 { y := numbx2(x, v) }
    				default { y := numbx1(x, v) }
				}
			}
			function numbi3(x, v) -> y {
				// v must be in the closed interval [-999, 999]
				// otherwise only the last 3 digits will be converted
				if slt(v, 0) {
					v := add(not(v), 1)
					mstore8(x, 45)  // minus sign
					x := add(x, 1)
				}
				y := numbu3(x, v)
			}
			function hexrgb(x, v) -> y {
				let blo := and(v, 0xf)
				let bhi := and(shr(4, v), 0xf)
				let glo := and(shr(8, v), 0xf)
				let ghi := and(shr(12, v), 0xf)
				let rlo := and(shr(16, v), 0xf)
				let rhi := and(shr(20, v), 0xf)
				mstore8(x,         add(add(rhi, mul(div(rhi, 10), 39)), 48))
				mstore8(add(x, 1), add(add(rlo, mul(div(rlo, 10), 39)), 48))
				mstore8(add(x, 2), add(add(ghi, mul(div(ghi, 10), 39)), 48))
				mstore8(add(x, 3), add(add(glo, mul(div(glo, 10), 39)), 48))
				mstore8(add(x, 4), add(add(bhi, mul(div(bhi, 10), 39)), 48))
				mstore8(add(x, 5), add(add(blo, mul(div(blo, 10), 39)), 48))
				y := add(x, 6)
			}
			function append(x, str, len) -> y {
			    mstore(x, str)
			    y := add(x, len)
			}
			let strIdx := add(mload(add(buffer, 32)), add(buffer, 64))
			strIdx := append(strIdx, '<rect x="', 9)
			strIdx := numbi3(strIdx, xpos)
			strIdx := append(strIdx, '" y="', 5)
			strIdx := numbi3(strIdx, ypos)
			strIdx := append(strIdx, '" width="', 9)
			strIdx := numbu3(strIdx, width)
			strIdx := append(strIdx, '" height="', 10)
			strIdx := numbu3(strIdx, height)
			strIdx := append(strIdx, '" style="fill:#', 15)
			strIdx := hexrgb(strIdx, rgb)
			strIdx := append(strIdx, '; fill-opacity:1.0;"/>\n', 23)
			mstore(add(buffer, 32), sub(sub(strIdx, buffer), 64))
		}
	}
}


library Random
{
	/**
	* Initialize the pool with the entropy of the blockhashes of the blocks in the closed interval [earliestBlock, latestBlock]
	* The argument "seed" is optional and can be left zero in most cases.
	* This extra seed allows you to select a different sequence of random numbers for the same block range.
	*/
	function init(uint256 earliestBlock, uint256 latestBlock, uint256 seed) internal view returns (bytes32[] memory) {
		//require(block.number-1 >= latestBlock && latestBlock >= earliestBlock && earliestBlock >= block.number-256, "Random.init: invalid block interval");
		require(block.number-1 >= latestBlock && latestBlock >= earliestBlock, "Random.init: invalid block interval");
		bytes32[] memory pool = new bytes32[](latestBlock-earliestBlock+2);
		bytes32 salt = keccak256(abi.encodePacked(block.number,seed));
		for(uint256 i=0; i<=latestBlock-earliestBlock; i++) {
			// Add some salt to each blockhash so that we don't reuse those hash chains
			// when this function gets called again in another block.
			pool[i+1] = keccak256(abi.encodePacked(blockhash(earliestBlock+i),salt));
		}
		return pool;
	}
	
	/**
	* Initialize the pool from the latest "num" blocks.
	*/
	function initLatest(uint256 num, uint256 seed) internal view returns (bytes32[] memory) {
		return init(block.number-num, block.number-1, seed);
	}
	
	/**
	* Advances to the next 256-bit random number in the pool of hash chains.
	*/
	function next(bytes32[] memory pool) internal pure returns (uint256) {
		require(pool.length > 1, "Random.next: invalid pool");
		uint256 roundRobinIdx = uint256(pool[0]) % (pool.length-1) + 1;
		bytes32 hash = keccak256(abi.encodePacked(pool[roundRobinIdx]));
		pool[0] = bytes32(uint256(pool[0])+1);
		pool[roundRobinIdx] = hash;
		return uint256(hash);
	}
	
	/**
	* Produces random integer values, uniformly distributed on the closed interval [a, b]
	*/
	function uniform(bytes32[] memory pool, int256 a, int256 b) internal pure returns (int256) {
		require(a <= b, "Random.uniform: invalid interval");
		return int256(next(pool)%uint256(b-a+1))+a;
	}
}


contract tinyboxes
{
	event Minted(string svg);
	
    event Generated(uint indexed index, address indexed a, string value);

    /// @dev This emits when ownership of any NFT changes by any mechanism.
    ///  This event emits when NFTs are created (`from` == 0) and destroyed
    ///  (`to` == 0). Exception: during contract creation, any number of NFTs
    ///  may be created and assigned without emitting Transfer. At the time of
    ///  any transfer, the approved address for that NFT (if any) is reset to none.
    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);

    /// @dev This emits when the approved address for an NFT is changed or
    ///  reaffirmed. The zero address indicates there is no approved address.
    ///  When a Transfer event emits, this also indicates that the approved
    ///  address for that NFT (if any) is reset to none.
    event Approval(address indexed _owner, address indexed _approved, uint256 indexed _tokenId);

    /// @dev This emits when an operator is enabled or disabled for an owner.
    ///  The operator can manage all NFTs of the owner.
    event ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved);


    uint256 public totalSupply;
	uint256 i;
	uint256 colorIdx;
	int256 xpos;
	int256 ypos;
	uint256 width;
	uint256 height;
	uint256 colorscheme;
	uint256 blackwhitescheme;
    uint256 footerRNG;
    
    bytes4 internal constant MAGIC_ON_ERC721_RECEIVED = 0x150b7a02;

    uint public constant TOKEN_LIMIT = 80; // 80 for testing, 800 for prod;
    uint public constant ARTIST_PRINTS = 1; 
    
    
    function getprice() view returns(uint PRICE) {
    uint256 tokeninflation = (numTokens/2) * 1000000000000000;
        PRICE = tokeninflation + 160000000000000000; //in wei, starting price .16 eth, ending price .2 eth
    }


    address public constant artmuseum = 0x027Fb48bC4e3999DCF88690aEbEBCC3D1748A0Eb; //lolz

    mapping (uint => address) private idToCreator;
    mapping (uint => string) private idToRender;
    mapping (uint256 => uint) internal idTocolorCount;
    mapping (uint256 => uint) internal idToshapeCount;
    

    // ERC 165
    mapping(bytes4 => bool) internal supportedInterfaces;

    /**
     * @dev A mapping from NFT ID to the address that owns it.
     */
    mapping (uint256 => address) internal idToOwner;

    /**
     * @dev A mapping from NFT ID to the seed used to make it.
     */
    mapping (uint256 => uint256) internal idToSeed;
    mapping (uint256 => uint256) internal seedToId;

    /**
     * @dev Mapping from NFT ID to approved address.
     */
    mapping (uint256 => address) internal idToApproval;

    /**
     * @dev Mapping from owner address to mapping of operator addresses.
     */
    mapping (address => mapping (address => bool)) internal ownerToOperators;

    /**
     * @dev Mapping from owner to list of owned NFT IDs.
     */
    mapping(address => uint256[]) internal ownerToIds;

    /**
     * @dev Mapping from NFT ID to its index in the owner tokens list.
     */
    mapping(uint256 => uint256) internal idToOwnerIndex;

    /**
     * @dev Total number of tokens.
     */
    uint internal numTokens = 0;

    /**
     * @dev Guarantees that the msg.sender is an owner or operator of the given NFT.
     * @param _tokenId ID of the NFT to validate.
     */
    modifier canOperate(uint256 _tokenId) {
        address tokenOwner = idToOwner[_tokenId];
        require(tokenOwner == msg.sender || ownerToOperators[tokenOwner][msg.sender]);
        _;
    }

    /**
     * @dev Guarantees that the msg.sender is allowed to transfer NFT.
     * @param _tokenId ID of the NFT to transfer.
     */
    modifier canTransfer(uint256 _tokenId) {
        address tokenOwner = idToOwner[_tokenId];
        require(
            tokenOwner == msg.sender
            || idToApproval[_tokenId] == msg.sender
            || ownerToOperators[tokenOwner][msg.sender]
        );
        _;
    }

    /**
     * @dev Guarantees that _tokenId is a valid Token.
     * @param _tokenId ID of the NFT to validate.
     */
    modifier validNFToken(uint256 _tokenId) {
        require(idToOwner[_tokenId] != address(0));
        _;
    }

    /**
     * @dev Contract constructor.
     */
    constructor() public {
        supportedInterfaces[0x01ffc9a7] = true; // ERC165
        supportedInterfaces[0x80ac58cd] = true; // ERC721
        supportedInterfaces[0x780e9d63] = true; // ERC721 Enumerable
        supportedInterfaces[0x5b5e139f] = true; // ERC721 Metadata
    }


    string internal nftName = "tinyboxes";
    string internal nftSymbol = "[#][#]";	


	
    function getColorsandShapes(uint256 seed) internal view returns (uint256 colorCount, uint256 shapeCount){

    bytes32[] memory pool = Random.initLatest(4, seed);        
        
    colorCount = uint256(Random.uniform(pool, 1, 4) + Random.uniform(pool, 2, 4));
    shapeCount = uint256(Random.uniform(pool, 1, 8) + Random.uniform(pool, 2, 8) + Random.uniform(pool, 2, 8));
    
    }
	
	function perpetualrender(uint256 seed, uint256 colorCount, uint256 shapeCount) public view returns (string memory){
		string memory header = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100%" height="100%" viewBox="-100 -100 2600 2600" style="stroke-width:0; background-color:#121212;">\n\n<symbol id="upperleftquad3">\n<symbol id="upperleftquad2">\n<symbol id="upperleftquad">\n\n';
        string memory footer;

		bytes32[] memory pool = Random.initLatest(4, seed);
		
		uint256[] memory colorValues = new uint256[](colorCount);
		
		colorscheme = uint256(Random.uniform(pool, 0, 99));
		
		if (numTokens == 0) {
		    
		for(i=0; i<colorCount; i++) {
			blackwhitescheme = uint256(0x000000);
		    colorValues[i] = (blackwhitescheme * 65536) + (blackwhitescheme * 256) + blackwhitescheme;		
		}	
		
		}else if (numTokens >  73 && numTokens < 80) {

		for(i=0; i<colorCount; i++) {
			blackwhitescheme = uint256(0x0000ff);
		    colorValues[i] = (blackwhitescheme * 65536) + (blackwhitescheme * 256) + blackwhitescheme;
		}			    	    
	    
	    }else if (colorscheme < 7) {
		    
		for(i=0; i<colorCount; i++) {
			colorValues[i] = uint256(Random.uniform(pool, 0x000012, 0x0000ff));
		}
		
		} else if (colorscheme < 14){

		for(i=0; i<colorCount; i++) {
			colorValues[i] = uint256(Random.uniform(pool, 0x000012, 0x0000ff) * 256);
		}		    
		
		} else if (colorscheme < 21){    
		    
		for(i=0; i<colorCount; i++) {
			colorValues[i] = uint256(Random.uniform(pool, 0x000012, 0x0000ff) * 65536);
		}	
 
		} else if (colorscheme < 35){    
		    
		for(i=0; i<colorCount; i++) {
			colorValues[i] = uint256(Random.uniform(pool, 0x000012, 0x0000ff) * 256) + uint256(Random.uniform(pool, 0x000012, 0x0000ff)) ;
		}

		} else if (colorscheme < 49){    
		    
		for(i=0; i<colorCount; i++) {
			colorValues[i] = uint256(Random.uniform(pool, 0x000012, 0x0000ff) * 65536) + uint256(Random.uniform(pool, 0x000012, 0x0000ff)) ;
		}
		
		} else if (colorscheme < 63){    
		    
		for(i=0; i<colorCount; i++) {
			colorValues[i] = uint256(Random.uniform(pool, 0x000012, 0x0000ff) * 256) + uint256(Random.uniform(pool, 0x000012, 0x0000ff) * 65536) ;
		}

		} else if (colorscheme < 66){    
		    
		for(i=0; i<colorCount; i++) {
			blackwhitescheme = uint256(Random.uniform(pool, 0x000022, 0x0000ee));
		    colorValues[i] = (blackwhitescheme * 65536) + (blackwhitescheme * 256) + blackwhitescheme;
		    
		}
		
        } else {


		for(i=0; i<colorCount; i++) {
			colorValues[i] = uint256(Random.uniform(pool, 0x121212, 0xffffff));
		}
        }
		    
		bytes memory buffer = new bytes(8192);
		
		Buffer.append(buffer, header);
        
		if (seed % 4 == 1) {

		for(i=0; i<shapeCount; i++) {
			 colorIdx = uint256(Random.uniform(pool, 0, int256(colorCount)-1));
			 xpos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 3) * 220);
			 ypos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 3) * 220);
			 width = uint256(Random.uniform(pool, 80, 100));
			 height = uint256(Random.uniform(pool, 80, 100));
			Buffer.rect(buffer, xpos, ypos, width, height, colorValues[colorIdx]);
		}
		
		} else if (seed % 4 == 2){

		for(i=0; i<shapeCount; i++) {
			 colorIdx = uint256(Random.uniform(pool, 0, int256(colorCount)-1));
			 xpos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 3) * 220);
			 ypos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 3) * 220);
			 width = uint256(Random.uniform(pool, 160, 200));
			 height = uint256(Random.uniform(pool, 160, 200));
			Buffer.rect(buffer, xpos, ypos, width, height, colorValues[colorIdx]);
		}    
		
		} else if (seed % 4 == 3){

		for(i=0; i<shapeCount; i++) {
			 colorIdx = uint256(Random.uniform(pool, 0, int256(colorCount)-1));
			 xpos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 12) * 65);
			 ypos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 12) * 65);
			 width = uint(Random.uniform(pool, 25, 40)) + uint(Random.uniform(pool, 0, 1) * 700);
			 height = 740  - width + uint256(Random.uniform(pool, 10, 25));
			Buffer.rect(buffer, xpos, ypos, width, height, colorValues[colorIdx]);
		}    
		
		} else {
	
		for(i=0; i<shapeCount; i++) {
			 colorIdx = uint256(Random.uniform(pool, 0, int256(colorCount)-1));
		if (i % 2 == 0) {
			 xpos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 3) * 220);
			 ypos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 3) * 220);
			 width = uint256(Random.uniform(pool, 80, 100));
			 height = uint256(Random.uniform(pool, 80, 100));
			Buffer.rect(buffer, xpos, ypos, width, height, colorValues[colorIdx]);
		}
		  else { 
		    colorIdx = uint256(Random.uniform(pool, 0, int256(colorCount)-1));
			 xpos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 12) * 65);
			 ypos = Random.uniform(pool, -20, 20) + (Random.uniform(pool, 0 , 12) * 65);
			 width = uint(Random.uniform(pool, 25, 40)) + uint(Random.uniform(pool, 0, 1) * 700);
			 height = 740  - width + uint256(Random.uniform(pool, 10, 25));
			Buffer.rect(buffer, xpos, ypos, width, height, colorValues[colorIdx]);
		}   
		
        }	
		}
		
		
		footerRNG = uint256(Random.uniform(pool, 0, 99));
		
		if (footerRNG < 20) {
		footer = '\n</symbol>\n<g>\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 1) translate(-1003 0)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 -1) translate(-1003 -1003)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1003)">\n<use xlink:href="#upperleftquad"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 1) translate(-1331 0)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 -1) translate(-1331 -1331)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1331)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 1) translate(-2400 0)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 -1) translate(-2400 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(1 -1) translate(0 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n</svg>';
		} else if (footerRNG < 40){
		footer = '\n</symbol>\n<g>\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 1) translate(-1077 0)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 -1) translate(-1077 -1077)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1077)">\n<use xlink:href="#upperleftquad"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 1) translate(-1077 0)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 -1) translate(-1245 -1245)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1245)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 1) translate(-2400 0)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 -1) translate(-2400 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(1 -1) translate(0 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n</svg>';
		} else if (footerRNG < 60){
		footer = '\n</symbol>\n<g>\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 1) translate(-1163 0)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 -1) translate(-1163 -1163)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1163)">\n<use xlink:href="#upperleftquad"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 1) translate(-1611 0)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 -1) translate(-1611 -1611)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1611)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 1) translate(-2400 0)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 -1) translate(-2400 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(1 -1) translate(0 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n</svg>';
		} else if (footerRNG < 80){
		footer = '\n</symbol>\n<g>\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 1) translate(-1250 0)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 -1) translate(-1250 -1250)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1250)">\n<use xlink:href="#upperleftquad"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 1) translate(-1470 0)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 -1) translate(-1470 -1470)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1470)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 1) translate(-2400 0)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 -1) translate(-2400 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(1 -1) translate(0 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n</svg>';
		} else {
		footer = '\n</symbol>\n<g>\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 1) translate(-1281 0)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(-1 -1) translate(-1281 -1281)">\n<use xlink:href="#upperleftquad"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1281)">\n<use xlink:href="#upperleftquad"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 1) translate(-1101 0)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(-1 -1) translate(-1101 -1101)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n<g transform="scale(1 -1) translate(0 -1101)">\n<use xlink:href="#upperleftquad2"/>\n</g>\n\n</symbol>\n<g>\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 1) translate(-2400 0)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(-1 -1) translate(-2400 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n<g transform="scale(1 -1) translate(0 -2400)">\n<use xlink:href="#upperleftquad3"/>\n</g>\n</svg>';
		}
		
		Buffer.append(buffer, footer);
		
		return Buffer.toString(buffer);

	}
	

    function creator(uint _id) external view returns (address) {
        return idToCreator[_id];
    }
    
    function colorCount(uint _id) external view returns (uint256) {
        return idTocolorCount[_id];
    }
    
    function shapeCount(uint _id) external view returns (uint256) {
        return idToshapeCount[_id];
    }
    
    function createboxes(uint seed) external payable returns (string) {
        return _mint(seed, msg.sender);
    }

    //////////////////////////
    //// ERC 721 and 165  ////
    //////////////////////////

    /**
     * @dev Returns whether the target address is a contract.
     * @param _addr Address to check.
     * @return True if _addr is a contract, false if not.
     */
    function isContract(address _addr) internal view returns (bool addressCheck) {
        uint256 size;
        assembly { size := extcodesize(_addr) } // solhint-disable-line
        addressCheck = size > 0;
    }

    /**
     * @dev Function to check which interfaces are suported by this contract.
     * @param _interfaceID Id of the interface.
     * @return True if _interfaceID is supported, false otherwise.
     */
    function supportsInterface(bytes4 _interfaceID) external view returns (bool) {
        return supportedInterfaces[_interfaceID];
    }

    /**
     * @dev Transfers the ownership of an NFT from one address to another address. This function can
     * be changed to payable.
     * @notice This works identically to the other function with an extra data parameter, except this
     * function just sets data to ""
     * @param _from The current owner of the NFT.
     * @param _to The new owner.
     * @param _tokenId The NFT to transfer.
     */
    function safeTransferFrom(address _from, address _to, uint256 _tokenId) external {
        _safeTransferFrom(_from, _to, _tokenId, "");
    }

    /**
     * @dev Throws unless `msg.sender` is the current owner, an authorized operator, or the approved
     * address for this NFT. Throws if `_from` is not the current owner. Throws if `_to` is the zero
     * address. Throws if `_tokenId` is not a valid NFT. This function can be changed to payable.
     * @notice The caller is responsible to confirm that `_to` is capable of receiving NFTs or else
     * they maybe be permanently lost.
     * @param _from The current owner of the NFT.
     * @param _to The new owner.
     * @param _tokenId The NFT to transfer.
     */
    function transferFrom(address _from, address _to, uint256 _tokenId) external canTransfer(_tokenId) validNFToken(_tokenId) {
        address tokenOwner = idToOwner[_tokenId];
        require(tokenOwner == _from);
        require(_to != address(0));
        _transfer(_to, _tokenId);
    }

    /**
     * @dev Set or reaffirm the approved address for an NFT. This function can be changed to payable.
     * @notice The zero address indicates there is no approved address. Throws unless `msg.sender` is
     * the current NFT owner, or an authorized operator of the current owner.
     * @param _approved Address to be approved for the given NFT ID.
     * @param _tokenId ID of the token to be approved.
     */
    function approve(address _approved, uint256 _tokenId) external canOperate(_tokenId) validNFToken(_tokenId) {
        address tokenOwner = idToOwner[_tokenId];
        require(_approved != tokenOwner);
        idToApproval[_tokenId] = _approved;
        emit Approval(tokenOwner, _approved, _tokenId);
    }

    /**
     * @dev Enables or disables approval for a third party ("operator") to manage all of
     * `msg.sender`'s assets. It also emits the ApprovalForAll event.
     * @notice This works even if sender doesn't own any tokens at the time.
     * @param _operator Address to add to the set of authorized operators.
     * @param _approved True if the operators is approved, false to revoke approval.
     */
    function setApprovalForAll(address _operator, bool _approved) external {
        ownerToOperators[msg.sender][_operator] = _approved;
        emit ApprovalForAll(msg.sender, _operator, _approved);
    }

    /**
     * @dev Returns the number of NFTs owned by `_owner`. NFTs assigned to the zero address are
     * considered invalid, and this function throws for queries about the zero address.
     * @param _owner Address for whom to query the balance.
     * @return Balance of _owner.
     */
    function balanceOf(address _owner) external view returns (uint256) {
        require(_owner != address(0));
        return _getOwnerNFTCount(_owner);
    }

    /**
     * @dev Returns the address of the owner of the NFT. NFTs assigned to zero address are considered
     * invalid, and queries about them do throw.
     * @param _tokenId The identifier for an NFT.
     * @return Address of _tokenId owner.
     */
    function ownerOf(uint256 _tokenId) external view returns (address _owner) {
        _owner = idToOwner[_tokenId];
        require(_owner != address(0));
    }

    /**
     * @dev Get the approved address for a single NFT.
     * @notice Throws if `_tokenId` is not a valid NFT.
     * @param _tokenId ID of the NFT to query the approval of.
     * @return Address that _tokenId is approved for.
     */
    function getApproved(uint256 _tokenId) external view validNFToken(_tokenId) returns (address) {
        return idToApproval[_tokenId];
    }

    /**
     * @dev Checks if `_operator` is an approved operator for `_owner`.
     * @param _owner The address that owns the NFTs.
     * @param _operator The address that acts on behalf of the owner.
     * @return True if approved for all, false otherwise.
     */
    function isApprovedForAll(address _owner, address _operator) external view returns (bool) {
        return ownerToOperators[_owner][_operator];
    }

    /**
     * @dev Actually preforms the transfer.
     * @notice Does NO checks.
     * @param _to Address of a new owner.
     * @param _tokenId The NFT that is being transferred.
     */
    function _transfer(address _to, uint256 _tokenId) internal {
        address from = idToOwner[_tokenId];
        _clearApproval(_tokenId);

        _removeNFToken(from, _tokenId);
        _addNFToken(_to, _tokenId);

        emit Transfer(from, _to, _tokenId);
}

    /**
     * @dev Mints a new NFT.
     * @notice This is an internal function which should be called from user-implemented external
     * mint function. Its purpose is to show and properly initialize data structures when using this
     * implementation.
     * @param _to The address that will own the minted NFT.
     */

     
    function _mint(uint256 seed,  address _to) internal returns (string) {
        require(_to != address(0));
        require(numTokens < TOKEN_LIMIT, "ART SALE IS OVER. Tinyboxes are now only available on the secondary market.");
 //       require(block.timestamp < 1574711999, "ART SALE IS OVER. Tinyboxes are now only available on the secondary market.");
        uint amount = 0;
        if (numTokens >= ARTIST_PRINTS) {
            amount = getprice();
            require(msg.value >= amount);
        }
        if (numTokens < ARTIST_PRINTS) {
            require(_to == address(0x63a9dbCe75413036B2B778E670aaBd4493aAF9F3), "Only the creator can mint the alpha token. Wait your turn FFS");
        }

        uint id = numTokens + 1;

        (uint256 colorCount, uint256 shapeCount) = getColorsandShapes(seed);


        idTocolorCount[id] = colorCount;
        idToshapeCount[id] = shapeCount;
        
        idToCreator[id] = _to;
        idToRender[id] = perpetualrender(seed, colorCount, shapeCount);
        
        string memory uri = perpetualrender(seed, colorCount, shapeCount);
        emit Generated(id, _to, uri);

        numTokens = numTokens + 1;
        _addNFToken(_to, id);

        if (msg.value > amount) {
            msg.sender.transfer(msg.value - amount);
        }
        if (amount > 0) {
            artmuseum.transfer(amount);
        }

        emit Transfer(address(0), _to, id);
        return uri;
    
    }

    /**
     * @dev Assigns a new NFT to an address.
     * @notice Use and override this function with caution. Wrong usage can have serious consequences.
     * @param _to Address to which we want to add the NFT.
     * @param _tokenId Which NFT we want to add.
     */
    function _addNFToken(address _to, uint256 _tokenId) internal {
        require(idToOwner[_tokenId] == address(0));
        idToOwner[_tokenId] = _to;

        uint256 length = ownerToIds[_to].push(_tokenId);
        idToOwnerIndex[_tokenId] = length - 1;
    }

    /**
     * @dev Removes a NFT from an address.
     * @notice Use and override this function with caution. Wrong usage can have serious consequences.
     * @param _from Address from wich we want to remove the NFT.
     * @param _tokenId Which NFT we want to remove.
     */
    function _removeNFToken(address _from, uint256 _tokenId) internal {
        require(idToOwner[_tokenId] == _from);
        delete idToOwner[_tokenId];

        uint256 tokenToRemoveIndex = idToOwnerIndex[_tokenId];
        uint256 lastTokenIndex = ownerToIds[_from].length - 1;

        if (lastTokenIndex != tokenToRemoveIndex) {
            uint256 lastToken = ownerToIds[_from][lastTokenIndex];
            ownerToIds[_from][tokenToRemoveIndex] = lastToken;
            idToOwnerIndex[lastToken] = tokenToRemoveIndex;
        }

        ownerToIds[_from].length--;
    }

    /**
     * @dev Helper function that gets NFT count of owner. This is needed for overriding in enumerable
     * extension to remove double storage (gas optimization) of owner nft count.
     * @param _owner Address for whom to query the count.
     * @return Number of _owner NFTs.
     */
    function _getOwnerNFTCount(address _owner) internal view returns (uint256) {
        return ownerToIds[_owner].length;
    }

    /**
     * @dev Actually perform the safeTransferFrom.
     * @param _from The current owner of the NFT.
     * @param _to The new owner.
     * @param _tokenId The NFT to transfer.
     * @param _data Additional data with no specified format, sent in call to `_to`.
     */
    function _safeTransferFrom(address _from,  address _to,  uint256 _tokenId,  bytes memory _data) private canTransfer(_tokenId) validNFToken(_tokenId) {
        address tokenOwner = idToOwner[_tokenId];
        require(tokenOwner == _from);
        require(_to != address(0));

        _transfer(_to, _tokenId);

        if (isContract(_to)) {
            bytes4 retval = ERC721TokenReceiver(_to).onERC721Received(msg.sender, _from, _tokenId, _data);
            require(retval == MAGIC_ON_ERC721_RECEIVED);
        }
    }

    /**
     * @dev Clears the current approval of a given NFT ID.
     * @param _tokenId ID of the NFT to be transferred.
     */
    function _clearApproval(uint256 _tokenId) private {
        if (idToApproval[_tokenId] != address(0)) {
            delete idToApproval[_tokenId];
        }
    }

    //// Enumerable

    function totalSupply() public view returns (uint256) {
        return numTokens;
    }


    //// Metadata

    /**
      * @dev Returns a descriptive name for a collection of NFTokens.
      * @return Representing name.
      */
    function name() external view returns (string memory _name) {
        _name = nftName;
    }

    /**
     * @dev Returns an abbreviated name for NFTokens.
     * @return Representing symbol.
     */
    function symbol() external view returns (string memory _symbol) {
        _symbol = nftSymbol;
    }

    /**
     * @dev A distinct URI (RFC 3986) for a given NFT.
     * @param _tokenId Id for which we want uri.
     * @return URI of _tokenId.
     */
    function tokenURI(uint256 _tokenId) external view validNFToken(_tokenId) returns (string memory) {
        return idToRender[_tokenId];
    }
    
    
}
