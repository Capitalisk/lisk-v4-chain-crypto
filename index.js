const liskCryptography = require('@liskhq/lisk-cryptography');
const liskTransactions = require('@liskhq/lisk-transactions');

class LiskChainCrypto {
  constructor({chainOptions}) {
    this.passphrase = chainOptions.passphrase;
    this.sharedPassphrase = chainOptions.sharedPassphrase;
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

  _computeNonceFromTimestamp(timestamp) {
    return BigInt(Math.round(timestamp / 1000) * 10000);
  }

  async prepareTransaction(transactionData) {
    try {
      liskCryptography.validateBase32Address(transactionData.recipientAddress);
    } catch (error) {
      throw new Error(
        'Failed to prepare the transaction because the recipientAddress was invalid'
      );
    }

    let nonce = this._computeNonceFromTimestamp(transactionData.timestamp);

    let txnData = {
      moduleID: 2,
      assetID: 0,
      fee: BigInt(transactionData.fee),
      asset: {
        amount: BigInt(transactionData.amount),
        recipientAddress: liskCryptography.getAddressFromBase32Address(transactionData.recipientAddress),
        data: '',
        nonce // TODO 222 HOW to handle nonce?
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
      moduleID: signedTxn.moduleID,
      assetID: signedTxn.assetID,
      fee: signedTxn.fee.toString(),
      asset: {
        amount: signedTxn.asset.amount.toString(),
        recipientAddress: signedTxn.asset.recipientAddress.toString('hex'),
        data: signedTxn.data,
        nonce: signedTxn.nonce.toString()
      },
      nonce: signedTxn.nonce.toString(),
      senderPublicKey: signedTxn.senderPublicKey.toString('hex'),
      signatures: [
        {
          signerAddress: sharedAddress,
          publicKey: sharedPublicKey.toString('hex'),
          signature: signedTxn.signatures[0].toString('hex')
        }
      ],
      id: signedTxn.id.toString('hex')
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
}

module.exports = LiskChainCrypto;
