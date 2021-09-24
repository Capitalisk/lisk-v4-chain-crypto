const {
  cryptography: liskCryptography
} = require('@liskhq/lisk-client');

const fs = require('fs');
const util = require('util');

const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);

const LiskWSClient = require('lisk-v3-ws-client-manager');

const toBuffer = (data) => Buffer.from(data, 'hex');
const bufferToString = (hexBuffer) => hexBuffer.toString('hex');

const DEFAULT_RECENT_NONCES_MAX_COUNT = 10000;
const DEFAULT_TRANSACTION_STATE_FILE_PATH = './lisk-transaction-state.json';

class LiskChainCrypto {
  constructor({chainOptions}) {
    this.passphrase = chainOptions.passphrase;
    this.sharedPassphrase = chainOptions.sharedPassphrase;
    this.transactionStateFilePath = chainOptions.transactionStateFilePath || DEFAULT_TRANSACTION_STATE_FILE_PATH;
    this.recentNoncesMaxCount = chainOptions.recentNoncesMaxCount || DEFAULT_RECENT_NONCES_MAX_COUNT;
    this.lastTimestamp = 0;
    this.nonceIndex = 0n;
    this.rpcURL = chainOptions.rpcURL;
    this.apiClient = null;
    this.liskWsClient = new LiskWSClient({
      config: {
        rpcURL: this.rpcURL
      },
      logger: {
        info: () => {},
        warn: () => {},
        error: () => {}
      }
    });
  }

  async load() {
    this.apiClient = await this.liskWsClient.createWsClient(true);
    this.networkIdBytes = toBuffer(this.apiClient._nodeInfo.networkIdentifier);
    let { address: sharedAddress, publicKey: sharedPublicKey } = liskCryptography.getAddressAndPublicKeyFromPassphrase(this.sharedPassphrase);
    this.multisigWalletAddress = sharedAddress;
    this.multisigWalletPublicKey = sharedPublicKey;

    try {
      let transactionState = await readJSONFile(this.transactionStateFilePath);
      this.recentNoncesMap = new Map(
        Object.entries(transactionState.recentNonces).map(entry => [entry[0], BigInt(entry[1])])
      );
    } catch (error) {
      this.nonceIndex = await this._fetchMultisigAccountNonce();
      this.recentNoncesMap = new Map();
    }
  }

  async unload() {
    await this.liskWsClient.close();
  }

  // This method checks that:
  // 1. The signerAddress corresponds to the publicKey.
  // 2. The publicKey corresponds to the signature.
  async verifyTransactionSignature(transaction, signaturePacket) {
    let { signature: signatureToVerify, publicKey, signerAddress } = signaturePacket;
    let publicKeyBuffer = toBuffer(publicKey);
    let expectedAddress = liskCryptography.getBase32AddressFromAddress(
      liskCryptography.getAddressFromPublicKey(publicKeyBuffer)
    );
    if (signerAddress !== expectedAddress) {
      return false;
    }

    let liskTxn = {
      moduleID: transaction.moduleID,
      assetID: transaction.assetID,
      fee: BigInt(transaction.fee),
      asset: {
        amount: BigInt(transaction.amount),
        recipientAddress: liskCryptography.getAddressFromBase32Address(transaction.recipientAddress),
        data: transaction.message
      },
      nonce: BigInt(transaction.nonce),
      senderPublicKey: toBuffer(transaction.senderPublicKey),
      signatures: [],
      id: transaction.id
    };

    let txnBuffer = this.apiClient.transaction.encode(liskTxn);
    let transactionWithNetworkIdBuffer = Buffer.concat([this.networkIdBytes, txnBuffer]);

    return liskCryptography.verifyData(
      transactionWithNetworkIdBuffer,
      toBuffer(signatureToVerify),
      publicKeyBuffer
    );
  }

  async prepareTransaction(transactionData) {
    try {
      liskCryptography.validateBase32Address(transactionData.recipientAddress);
    } catch (error) {
      throw new Error(
        'Failed to prepare the transaction because the recipientAddress was invalid'
      );
    }

    let nonce = this._getNextNonce(transactionData);

    let txnData = {
      moduleID: 2,
      assetID: 0,
      fee: BigInt(transactionData.fee),
      asset: {
        amount: BigInt(transactionData.amount),
        recipientAddress: liskCryptography.getAddressFromBase32Address(transactionData.recipientAddress),
        data: ''
      },
      nonce
    };
    if (transactionData.message != null) {
      txnData.asset.data = transactionData.message;
    }
    let txn = await this.apiClient.transaction.create(txnData, this.sharedPassphrase);
    let signedTxn = await this.apiClient.transaction.sign(txn, [this.sharedPassphrase, this.passphrase]);

    let { address: signerAddress, publicKey: signerPublicKey } = liskCryptography.getAddressAndPublicKeyFromPassphrase(this.passphrase);

    let nonceString = signedTxn.nonce.toString();
    let multisigWalletAddressBase32 = liskCryptography.getBase32AddressFromAddress(this.multisigWalletAddress);

    let preparedTxn = {
      id: `${multisigWalletAddressBase32}-${nonceString}`, // Use the nonce as the id because it is consistent throughout the entire lifecycle of the transaction.
      message: signedTxn.asset.data,
      amount: signedTxn.asset.amount.toString(),
      timestamp: transactionData.timestamp,
      senderAddress: multisigWalletAddressBase32,
      recipientAddress: liskCryptography.getBase32AddressFromAddress(signedTxn.asset.recipientAddress),
      signatures: [],
      moduleID: signedTxn.moduleID,
      assetID: signedTxn.assetID,
      fee: signedTxn.fee.toString(),
      nonce: nonceString,
      senderPublicKey: bufferToString(signedTxn.senderPublicKey)
    };

    // The signature needs to be an object with a signerAddress property, the other
    // properties are flexible and depend on the requirements of the underlying blockchain.
    let multisigTxnSignature = {
      signerAddress: liskCryptography.getBase32AddressFromAddress(signerAddress),
      publicKey: bufferToString(signerPublicKey),
      signature: bufferToString(signedTxn.signatures.find(sigBuffer => sigBuffer.byteLength))
    };

    if (this.lastTimestamp !== transactionData.timestamp) {
      this.lastTimestamp = transactionData.timestamp;
      let transactionState = {
        recentNonces: Object.fromEntries([...this.recentNoncesMap.entries()].map(entry => [entry[0], entry[1].toString()]))
      };
      await writeJSONFile(this.transactionStateFilePath, transactionState);
    }

    return {transaction: preparedTxn, signature: multisigTxnSignature};
  }

  async _fetchMultisigAccountNonce() {
    let account = await this.apiClient.account.get(this.multisigWalletAddress);
    return account.sequence.nonce;
  }

  _computeTradeId(transactionData) {
    return `${transactionData.recipientAddress},${transactionData.message}`;
  }

  _getNextNonce(transactionData) {
    let tradeId = this._computeTradeId(transactionData);
    let existingNonce = this.recentNoncesMap.get(tradeId);

    if (existingNonce == null) {
      this.recentNoncesMap.set(tradeId, this.nonceIndex);
      while (this.recentNoncesMap.size > this.recentNoncesMaxCount) {
        let nextKey = this.recentNoncesMap.keys().next().value;
        this.recentNoncesMap.delete(nextKey);
      }
    } else {
      this.nonceIndex = existingNonce;
    }

    return this.nonceIndex++;
  }
}

async function readJSONFile(filePath) {
  return JSON.parse(await readFile(filePath));
}

async function writeJSONFile(filePath, object) {
  return writeFile(filePath, JSON.stringify(object, ' ', 2), {encoding: 'utf8'});
}

async function wait(duration) {
  return new Promise((resolve) => {
    setTimeout(resolve, duration);
  });
}

module.exports = LiskChainCrypto;
