Implementing Multi-Signature Account Abstraction for NFTs on zkSync

> MultiSignature (multisig) on zkSync are wallets that offer enhanced security and flexibility by allowing multiple parties to authorize transactions or actions on a blockchain account.
This feature is implemented based on Account Abstraction which allows transaction logic. 


Read more about zkSync here.
[zkSync Official docs](https://docs.zksync.io/build/developer-reference/account-abstraction.html#sending-transactions-from-an-account)

This tutorial will guide you through implementing multi-signature account abstraction for NFTs on zkSync, **enhancing security** and **control over NFT transactions**. This approach mitigaes the risk of unauthorized transactions and enhances the safety of digital assets. 

In this tutorial, you will: 
- Create a multi-signature smart contract to manage NFT transactions
- Implement account abstraction logic for multi-signature verification
- Mint and manage NFTs using the dployed multi-signature contract.


## Pre Requisites:
- Make sure your machine satisfies the [system requirements](https://github.com/matter-labs/era-compiler-solidity/tree/main#system-requirements).
- A Node.js installation running Node.js version 16.
- Some familiarity with deploying smart contracts on zkSync. If not, please refer to this [quickstart tutorial](https://docs.zksync.io/build/quick-start/hello-world.html).
- Some background knowledge on the concepts covered by the tutorial would be helpful too. Have a look at the following docs:
  - [Account abstraction protocol](https://docs.zksync.io/build/developer-reference/account-abstraction.html).
  - [Introduction to system contracts](https://docs.zksync.io/build/developer-reference/system-contracts.html).
  - [Smart contract deployment on zkSync Era](https://docs.zksync.io/build/developer-reference/system-contracts.html).
  - [Gas estimation for transactions guide](https://docs.zksync.io/build/developer-reference/fee-model.html#gas-estimation-for-transactions).
- You should also know [how to get your private key from your MetaMask wallet](https://support.metamask.io/hc/en-us/articles/360015289632-How-to-export-an-account-s-private-key)



### Setting Up the Project

Open your terminal or command prompt.

#### 1. Create the Project:

```bash
npx zksync-cli create multisig-nft-tutorial --template hardhat_solidity
```

#### 1.2 Navigate into the Project Directory:
Change the current directory to the project directory.
```bash
cd multisig-nft-tutorial
```


#### 1.3 Remove Example Contracts and Deploy Files:

```bash
rm -rf ./contracts/*
rm -rf ./deploy/*
```

#### 1.4 Add Required Libraries:
Install the zkSync contracts and OpenZeppelin contracts libraries.
```bash
yarn add -D @matterlabs/zksync-contracts @openzeppelin/contracts@4.9.5
```
#### 1.5  Configure Hardhat for zkSync in `hardhat.config.ts`
configuration file to allow interaction with system contracts:

```typescript
import { HardhatUserConfig } from "hardhat/config";
import "@matterlabs/hardhat-zksync-deploy";
import "@matterlabs/hardhat-zksync-solc";

import "@matterlabs/hardhat-zksync-verify";

const config: HardhatUserConfig = {
  zksolc: {
    version: "latest", // Uses latest available in https://github.com/matter-labs/zksolc-bin/
    settings: {
      isSystem: true, // ⚠️ Make sure to include this line
    },
  },
  defaultNetwork: "zkSyncTestnet",

  networks: {
    zkSyncTestnet: {
      url: "https://sepolia.era.zksync.dev",
      ethNetwork: "sepolia", // Can also be the RPC URL of the network (e.g. `https://sepolia.infura.io/v3/<API_KEY>`)
      zksync: true,
    },
  },
  solidity: {
    version: "0.8.20",
  },
};

export default config;

```
 ## Writing the Multi-Signature Smart Contract
Create a new file MultiSigWallet.sol in the contracts directory with the following code:

To understand how this works, 
Read [Account Abstraction MultiSig](https://docs.zksync.io/build/tutorials/smart-contract-development/account-abstraction/custom-aa-tutorial.html)
Since we are building an account with multiple signers, we would implement [EIP1271](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/83277ff916ac4f58fec072b8f28a252c1245c2f1/contracts/interfaces/IERC1271.sol#L12)
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@matterlabs/zksync-contracts/l2/system-contracts/interfaces/IAccount.sol";
import "@matterlabs/zksync-contracts/l2/system-contracts/libraries/TransactionHelper.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract MultiSigWallet is IAccount {
    using TransactionHelper for Transaction;
    
    address public owner1;
    address public owner2;
    bytes4 constant EIP1271_SUCCESS_RETURN_VALUE = 0x1626ba7e;
    bytes4 constant ACCOUNT_VALIDATION_SUCCESS_MAGIC = 0x739b9d1b;

    constructor(address _owner1, address _owner2) {
        owner1 = _owner1;
        owner2 = _owner2;
    }

    modifier onlyOwners() {
        require(msg.sender == owner1 || msg.sender == owner2, "Not an owner");
        _;
    }

    function validateTransaction(
        bytes32,
        bytes32 _suggestedSignedHash,
        Transaction calldata _transaction
    ) external payable override onlyBootloader returns (bytes4 magic) {
        magic = _validateTransaction(_suggestedSignedHash, _transaction);
    }

    function _validateTransaction(
        bytes32 _suggestedSignedHash,
        Transaction calldata _transaction
    ) internal returns (bytes4 magic) {
        // Incrementing the nonce of the account.
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
        );

        bytes32 txHash;
        if (_suggestedSignedHash == bytes32(0)) {
            txHash = _transaction.encodeHash();
        } else {
            txHash = _suggestedSignedHash;
        }

        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        require(totalRequiredBalance <= address(this).balance, "Not enough balance for fee + value");

        if (isValidSignature(txHash, _transaction.signature) == EIP1271_SUCCESS_RETURN_VALUE) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }
    }

    function executeTransaction(
        bytes32,
        bytes32,
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        _executeTransaction(_transaction);
    }

    function _executeTransaction(Transaction calldata _transaction) internal {
        uint256 to = _transaction.to;
        uint256 value = _transaction.reserved[1];
        bytes memory data = _transaction.data;

        bool success;
        assembly {
            success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
        }

        require(success);
    }

    function executeTransactionFromOutside(Transaction calldata _transaction) external payable {
        bytes4 magic = _validateTransaction(bytes32(0), _transaction);
        require(magic == ACCOUNT_VALIDATION_SUCCESS_MAGIC, "NOT VALIDATED");

        _executeTransaction(_transaction);
    }

    function isValidSignature(bytes32 _hash, bytes memory _signature) public view override returns (bytes4 magic) {
        magic = EIP1271_SUCCESS_RETURN_VALUE;

        if (_signature.length != 130) {
            _signature = new bytes(130);
            _signature[64] = bytes1(uint8(27));
            _signature[129] = bytes1(uint8(27));
        }

        (bytes memory signature1, bytes memory signature2) = extractECDSASignature(_signature);

        if (!checkValidECDSASignatureFormat(signature1) || !checkValidECDSASignatureFormat(signature2)) {
            magic = bytes4(0);
        }

        address recoveredAddr1 = ECDSA.recover(_hash, signature1);
        address recoveredAddr2 = ECDSA.recover(_hash, signature2);

        if (recoveredAddr1 != owner1 || recoveredAddr2 != owner2) {
            magic = bytes4(0);
        }
    }

    function payForTransaction(
        bytes32,
        bytes32,
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        bool success = _transaction.payToTheBootloader();
        require(success, "Failed to pay the fee to the operator");
    }

    function prepareForPaymaster(
        bytes32,
        bytes32,
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        _transaction.processPaymasterInput();
    }

    function checkValidECDSASignatureFormat(bytes memory _signature) internal pure returns (bool) {
        if (_signature.length != 65) {
            return false;
        }

        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := and(mload(add(_signature, 0x41)), 0xff)
        }
        if (v != 27 && v != 28) {
            return false;
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }
        return true;
    }

    function extractECDSASignature(bytes memory _fullSignature) internal pure returns (bytes memory signature1, bytes memory signature2) {
        require(_fullSignature.length == 130, "Invalid length");

        signature1 = new bytes(65);
        signature2 = new bytes(65);

        assembly {
            let r := mload(add(_fullSignature, 0x20))
            let s := mload(add(_fullSignature, 0x40))
            let v := and(mload(add(_fullSignature, 0x41)), 0xff)

            mstore(add(signature1, 0x20), r)
            mstore(add(signature1, 0x40), s)
            mstore8(add(signature1, 0x60), v)
        }

        assembly {
            let r := mload(add(_fullSignature, 0x61))
            let s := mload(add(_fullSignature, 0x81))
            let v := and(mload(add(_fullSignature, 0x82)), 0xff)

            mstore(add(signature2, 0x20), r)
            mstore(add(signature2, 0x40), s)
            mstore8(add(signature2, 0x60), v)
        }
    }

    fallback() external {
        assert(msg.sender != BOOTLOADER_FORMAL_ADDRESS);
    }

    receive() external payable {}
}

```

#### 3. Create an NFT Contract
Create a new file MyNFT.sol in the contracts directory with the following code:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyNFT is ERC721, Ownable {
    uint256 public nextTokenId;
    address public admin;

    constructor() ERC721("MyNFT", "MNFT") {
        admin = msg.sender;
    }

    function mint(address to) external onlyOwner {
        _safeMint(to, nextTokenId);
        nextTokenId++;
    }

    function setAdmin(address _admin) external onlyOwner {
        admin = _admin;
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override {
        require(msg.sender == admin || msg.sender == owner(), "Not authorized");
        _transfer(from, to, tokenId);
    }
}

```
#### 4. Integrate Multi-Signature Wallet with NFT Contract
In the MultiSigWallet.sol file, add a function to transfer NFTs:
```solidity
/**
 * @dev Transfer an NFT using multi-signature authorization.
 * @param nftContract Address of the NFT contract.
 * @param to Address to transfer the NFT to.
 * @param tokenId ID of the token to transfer.
 */
function transferNFT(
    address nftContract,
    address to,
    uint256 tokenId
) external onlyOwners {
    IERC721(nftContract).transferFrom(address(this), to, tokenId);
}

```
#### 5. Configure Deployment Scripts
Update hardhat.config.js to include zkSync:
```require("@matterlabs/hardhat-zksync-solc");
require("@matterlabs/hardhat-zksync-deploy");

module.exports = {
  zksolc: {
    version: "1.3.5",
    compilerSource: "binary",
    settings: {},
  },
  defaultNetwork: "zkSyncTestnet",
  networks: {
    zkSyncTestnet: {
      url: "https://testnet.era.zksync.dev",
      ethNetwork: "rinkeby",
      zksync: true,
    },
  },
  solidity: {
    version: "0.8.17",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
};
```
#### 6. Create Deployment Scripts
Create deployment scripts in the scripts directory:


#### deployMultiSig.js:

```javascript

const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying MultiSigWallet with the account:", deployer.address);

  const MultiSigWallet = await ethers.getContractFactory("MultiSigWallet");
  const multiSig = await MultiSigWallet.deploy(deployer.address, "0xAnotherOwnerAddress");  // Replace with actual second owner address
  await multiSig.deployed();

  console.log("MultiSigWallet deployed to:", multiSig.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
  ```
#### deployMyNFT.js:

```javascript
const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying MyNFT with the account:", deployer.address);

  const MyNFT = await ethers.getContractFactory("MyNFT");
  const nft = await MyNFT.deploy();
  await nft.deployed();

  console.log("MyNFT deployed to:", nft.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
 ```
#### Deploy the contracts with the following commands:

```bash
npx hardhat run scripts/deployMultiSig.js --network zkSyncTestnet
npx hardhat run scripts/deployMyNFT.js --network zkSyncTestnet
```

#### 7. Write Test Scripts

Create test scripts in the `test` directory to verify the multi-signature functionality with the NFT contract.

**multiSigWallet.test.js:**
```javascript
const { expect } = require("chai");

describe("MultiSigWallet", function () {
  let MultiSigWallet, multiSig, MyNFT, nft, owner1, owner2, addr1;

  beforeEach(async function () {
    [owner1, owner2, addr1] = await ethers.getSigners();

    // Deploy MultiSigWallet contract
    MultiSigWallet = await ethers.getContractFactory("MultiSigWallet");
    multiSig = await MultiSigWallet.deploy(owner1.address, owner2.address);
    await multiSig.deployed();

    // Deploy MyNFT contract
    MyNFT = await ethers.getContractFactory("MyNFT");
    nft = await MyNFT.deploy();
    await nft.deployed();

    // Set MultiSigWallet as admin of MyNFT
    await nft.setAdmin(multiSig.address);
  });

  it("Should mint and transfer NFT with multi-signature", async function () {
    // Mint an NFT to the MultiSigWallet
    await nft.mint(multiSig.address);

    // Attempt to transfer NFT with only one signature should fail
    await expect(
      multiSig.connect(owner1).transferNFT(nft.address, addr1.address, 0)
    ).to.be.revertedWith("Not an owner");

    // Successfully transfer NFT with both owners' signatures
    await multiSig.connect(owner2).transferNFT(nft.address, addr1.address, 0);

    // Verify the ownership of the NFT has been transferred
    expect(await nft.ownerOf(0)).to.equal(addr1.address);
  });
});
```

Run the tests with:

```bash
npx hardhat test
```


#### Resources
- [Account Abstraction in zkSync](https://docs.zksync.io/build/developer-reference/account-abstraction.html)
- [Account Abstraction Multi-Sig](https://docs.zksync.io/build/tutorials/smart-contract-development/account-abstraction/custom-aa-tutorial.html)

# Multi-Signature
