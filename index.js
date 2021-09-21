const {
  cryptography: liskCryptography
} = require('@liskhq/lisk-client');

const LiskWSClient = require('lisk-v3-ws-client-manager');

// const TESTNET_NETWORK_ID = '15f0dacc1060e91818224a94286b13aa04279c640bd5d6f193182031d133df7c'; // Lisk testnet
const MAINNET_NETWORK_ID = '4c09e6a781fc4c7bdb936ee815de8f94190f8a7519becd9de2081832be309a99'; // Lisk mainnet
const DEFAULT_NETWORK_ID = MAINNET_NETWORK_ID;

class LiskChainCrypto {
  constructor({chainOptions}) {
    this.passphrase = chainOptions.passphrase;
    this.sharedPassphrase = chainOptions.sharedPassphrase;
    this.latestTimestamp = null;
    this.nonceIndex = 0;
    // Transaction messages can be used as unique identifiers when the ID is not known.
    this.recentTransactionMessageSet = new Set();
    this.networkIdBytes = Buffer.from(chainOptions.networkId || DEFAULT_NETWORK_ID, 'hex');
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
    let expectedAddress = liskCryptography.getAddressFromPublicKey(publicKey).toString('hex');
    if (signerAddress !== expectedAddress) {
      return false;
    }

    let liskTxn = {
      moduleID: transaction.moduleID,
      assetID: transaction.assetID,
      fee: BigInt(transaction.fee),
      asset: {
        amount: BigInt(transaction.amount),
        recipientAddress: Buffer.from(transaction.recipientAddress, 'hex'),
        data: transaction.message
      },
      nonce: BigInt(transaction.nonce),
      senderPublicKey: Buffer.from(transaction.senderPublicKey, 'hex'),
      signatures: [],
      id: Buffer.from(transaction.id, 'hex')
    };

    let txnBuffer = this.apiClient.transaction.encode(liskTxn);
    let transactionWithNetworkIdBuffer = Buffer.concat([this.networkIdBytes, txnBuffer]);

    return liskCryptography.verifyData(
      transactionWithNetworkIdBuffer,
      Buffer.from(signatureToVerify, 'hex'),
      Buffer.from(publicKey, 'hex')
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
      id: signedTxn.id.toString('hex'),
      message: signedTxn.asset.data,
      amount: signedTxn.asset.amount.toString(),
      timestamp: transactionData.timestamp,
      senderAddress: this.multisigWalletAddress,
      recipientAddress: signedTxn.asset.recipientAddress.toString('hex'),
      signatures: [
        {
          signerAddress: this.multisigWalletAddress,
          publicKey: this.multisigWalletPublicKey.toString('hex'),
          signature: signedTxn.signatures[0].toString('hex')
        }
      ],
      moduleID: signedTxn.moduleID,
      assetID: signedTxn.assetID,
      fee: signedTxn.fee.toString(),
      nonce: signedTxn.nonce.toString(),
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

  async _fetchMultisigAccountNonce() {
    let hexAddress = liskCryptography.getAddressFromBase32Address(this.multisigWalletAddress, 'lsk');
    let account = await this.apiClient.account.get(hexAddress);
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
