const {
  cryptography: liskCryptography
} = require('@liskhq/lisk-client');

const LiskWSClient = require('lisk-v3-ws-client-manager');

const toBuffer = (data) => Buffer.from(data, 'hex');
const bufferToString = (hexBuffer) => hexBuffer.toString('hex');

class LiskChainCrypto {
  constructor({chainOptions}) {
    this.passphrase = chainOptions.passphrase;
    this.sharedPassphrase = chainOptions.sharedPassphrase;
    this.latestTimestamp = null;
    this.nonceIndex = 0;
    // Transaction messages can be used as unique identifiers when the ID is not known.
    this.recentTransactionMessageSet = new Set();
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
  }

  async unload() {
    await this.liskWsClient.close();
  }

  // This method checks that:
  // 1. The signerAddress corresponds to the publicKey.
  // 2. The publicKey corresponds to the signature.
  async verifyTransactionSignature(transaction, signaturePacket) {
    let { signature: signatureToVerify, publicKey, signerAddress } = signaturePacket;
    let expectedAddress = bufferToString(liskCryptography.getAddressFromPublicKey(publicKey));
    if (signerAddress !== expectedAddress) {
      return false;
    }

    let liskTxn = {
      moduleID: transaction.moduleID,
      assetID: transaction.assetID,
      fee: BigInt(transaction.fee),
      asset: {
        amount: BigInt(transaction.amount),
        recipientAddress: toBuffer(transaction.recipientAddress),
        data: transaction.message
      },
      nonce: BigInt(transaction.nonce),
      senderPublicKey: toBuffer(transaction.senderPublicKey),
      signatures: [],
      id: toBuffer(transaction.id)
    };

    let txnBuffer = this.apiClient.transaction.encode(liskTxn);
    let transactionWithNetworkIdBuffer = Buffer.concat([this.networkIdBytes, txnBuffer]);

    return liskCryptography.verifyData(
      transactionWithNetworkIdBuffer,
      toBuffer(signatureToVerify),
      toBuffer(publicKey)
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

    let nonce = await this._getNextNonce(transactionData);

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

    let preparedTxn = {
      id: bufferToString(signedTxn.id),
      message: signedTxn.asset.data,
      amount: signedTxn.asset.amount.toString(),
      timestamp: transactionData.timestamp,
      senderAddress: this.multisigWalletAddress,
      recipientAddress: bufferToString(signedTxn.asset.recipientAddress),
      signatures: [
        {
          signerAddress: this.multisigWalletAddress,
          publicKey: bufferToString(this.multisigWalletPublicKey),
          signature: bufferToString(signedTxn.signatures[0])
        }
      ],
      moduleID: signedTxn.moduleID,
      assetID: signedTxn.assetID,
      fee: signedTxn.fee.toString(),
      nonce: signedTxn.nonce.toString(),
      senderPublicKey: bufferToString(signedTxn.senderPublicKey)
    };

    // The signature needs to be an object with a signerAddress property, the other
    // properties are flexible and depend on the requirements of the underlying blockchain.
    let multisigTxnSignature = {
      signerAddress,
      publicKey: bufferToString(signerPublicKey),
      signature: bufferToString(signedTxn.signatures[1])
    };

    return {transaction: preparedTxn, signature: multisigTxnSignature};
  }

  async _fetchMultisigAccountNonce() {
    let account = await this.apiClient.account.get(this.multisigWalletAddress);
    return account.sequence.nonce;
  }

  async _getNextNonce(transactionData) {
    // If the latestTimestamp changes, it means that a new block is being processed.
    // In this case, reset the nonceIndex to 0.
    if (this.latestTimestamp !== transactionData.timestamp) {
      let nonce = await this._fetchMultisigAccountNonce();

      if (nonce > this.nonceIndex || transactionData.timestamp < this.latestTimestamp) {
        this.nonceIndex = nonce;
      }

      this.latestTimestamp = transactionData.timestamp;
      this.recentTransactionMessageSet.clear();
    }
    // If a transaction has already been encountered before, it means that the parent block is being
    // re-processed (due to a recent failure).
    // In this case, reset the nonceIndex to the one from the database.
    if (this.recentTransactionMessageSet.has(transactionData.message)) {
      let nonce = await this._fetchMultisigAccountNonce();
      this.nonceIndex = nonce;
      this.recentTransactionMessageSet.clear();
    }
    this.recentTransactionMessageSet.add(transactionData.message);

    return BigInt(this.nonceIndex++);
  }
}

module.exports = LiskChainCrypto;
