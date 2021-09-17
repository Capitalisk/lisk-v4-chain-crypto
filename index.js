const liskCryptography = require('@liskhq/lisk-cryptography');
const liskTransactions = require('@liskhq/lisk-transactions');

class LiskChainCrypto {
  constructor({chainOptions}) {
    this.passphrase = chainOptions.passphrase;
    this.sharedPassphrase = chainOptions.sharedPassphrase;
    this.latestTimestamp = null;
    this.nonceIndex = 0;
    // Transaction messages can be used as unique identifiers when the ID is not known.
    this.recentTransactionMessageSet = new Set();
  }

  async load() {}

  async unload() {}

  // This method checks that:
  // 1. The signerAddress corresponds to the publicKey.
  // 2. The publicKey corresponds to the signature.
  async verifyTransactionSignature(transaction, signaturePacket) {
    let { signature: signatureToVerify, publicKey, signerAddress } = signaturePacket;
    let expectedAddress = liskCryptography.getAddressFromPublicKey(publicKey);
    if (signerAddress !== expectedAddress) {
      return false;
    }
    let { signature, signSignature, signatures, ...transactionToHash } = transaction;
    let txnHash = liskCryptography.hash(liskTransactions.utils.getTransactionBytes(transactionToHash));
    return liskCryptography.verifyData(txnHash, signatureToVerify, publicKey);
  }

  async prepareTransaction(transactionData) {
    try {
      liskCryptography.validateBase32Address(transactionData.recipientAddress);
    } catch (error) {
      throw new Error(
        'Failed to prepare the transaction because the recipientAddress was invalid'
      );
    }

    let nonce = this._generateNextNonce(transactionData);

    let txnData = {
      moduleID: 2,
      assetID: 0,
      fee: BigInt(transactionData.fee),
      asset: {
        amount: BigInt(transactionData.amount),
        recipientAddress: liskCryptography.getAddressFromBase32Address(transactionData.recipientAddress),
        data: '',
        nonce
      },
      nonce
    };
    if (transactionData.message != null) {
      txnData.asset.data = transactionData.message;
    }
    let txn = await client.transaction.create(txnData, this.sharedPassphrase);
    let signedTxn = await client.transaction.sign(txn, [this.sharedPassphrase, this.passphrase]);

    let { address: sharedAddress, publicKey: sharedPublicKey } = liskCryptography.getAddressAndPublicKeyFromPassphrase(this.sharedPassphrase);
    let { address: signerAddress, publicKey: signerPublicKey } = liskCryptography.getAddressAndPublicKeyFromPassphrase(this.passphrase);

    let preparedTxn = {
      id: signedTxn.id.toString('hex'),
      message: signedTxn.asset.data,
      amount: signedTxn.asset.amount.toString(),
      timestamp: transactionData.timestamp,
      senderAddress: sharedAddress,
      recipientAddress: signedTxn.asset.recipientAddress.toString('hex'),
      signatures: [
        {
          signerAddress: sharedAddress,
          publicKey: sharedPublicKey.toString('hex'),
          signature: signedTxn.signatures[0].toString('hex')
        }
      ],
      moduleID: signedTxn.moduleID,
      assetID: signedTxn.assetID,
      fee: signedTxn.fee.toString(),
      nonce: signedTxn.asset.nonce.toString(),
      senderPublicKey: signedTxn.senderPublicKey.toString('hex')
    };

    // The signature needs to be an object with a signerAddress property, the other
    // properties are flexible and depend on the requirements of the underlying blockchain.
    let multisigTxnSignature = {
      signerAddress,
      publicKey: signerPublicKey.toString('hex'),
      signature: signedTxn.signatures[1].toString('hex')
    };

    return {transaction: preparedTxn, signature: multisigTxnSignature};
  }

  _generateNextNonce(transactionData) {
    // If the latestTimestamp changes, it means that a new block is being processed.
    // In this case, reset the nonceIndex to 0.
    if (this.latestTimestamp !== transactionData.timestamp) {
      this.latestTimestamp = transactionData.timestamp;
      this.nonceIndex = 0;
      this.recentTransactionMessageSet.clear();
    }
    // If a transaction has already been encountered before, it means that the parent block is being
    // re-processed (due to a past failure).
    // In this case, reset the nonceIndex to 0.
    if (this.recentTransactionMessageSet.has(transactionData.message)) {
      this.nonceIndex = 0;
      this.recentTransactionMessageSet.clear();
    }
    this.recentTransactionMessageSet.add(transactionData.message);

    return BigInt(transactionData.timestamp + this.nonceIndex++);
  }
}

module.exports = LiskChainCrypto;
