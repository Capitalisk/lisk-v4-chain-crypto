const {
  cryptography: liskCryptography,
  transactions: liskTransactions
} = require('@liskhq/lisk-client');

const crypto = require('crypto');

const LiskWSClient = require('lisk-v3-ws-client-manager');

const DEX_TRANSACTION_ID_LENGTH = 44;
const MAX_TRANSACTIONS_PER_TIMESTAMP = 100;
const API_BLOCK_FETCH_LIMIT = 50;

const toBuffer = (data) => Buffer.from(data, 'hex');
const bufferToString = (hexBuffer) => hexBuffer.toString('hex');
const computeDEXTransactionId = (senderAddress, nonce) => {
  return crypto.createHash('sha256').update(`${senderAddress}-${nonce}`).digest('hex').slice(0, DEX_TRANSACTION_ID_LENGTH);
};

class LiskChainCrypto {
  constructor({chainOptions, logger}) {
    this.moduleAlias = chainOptions.moduleAlias;
    this.passphrase = chainOptions.passphrase;
    this.sharedPassphrase = chainOptions.sharedPassphrase;
    this.nonceIndex = 0n;
    this.rpcURL = chainOptions.rpcURL;
    this.apiClient = null;
    this.logger = logger;

    this.transferAssetSchema = {
      '$id': 'lisk/transfer-asset',
      title: 'Transfer transaction asset',
      type: 'object',
      required: ['amount', 'recipientAddress', 'data'],
      properties: {
        amount: {dataType: 'uint64', fieldNumber: 1},
        recipientAddress: {dataType: 'bytes', fieldNumber: 2, minLength: 20, maxLength: 20},
        data: {dataType: 'string', fieldNumber: 3, minLength: 0, maxLength: 64}
      }
    };

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

  async load(channel, lastProcessedHeight) {
    this.channel = channel;
    this.apiClient = await this.liskWsClient.createWsClient(true);
    this.networkIdBytes = toBuffer(this.apiClient._nodeInfo.networkIdentifier);
    let { address: sharedAddress, publicKey: sharedPublicKey } = liskCryptography.getAddressAndPublicKeyFromPassphrase(this.sharedPassphrase);
    this.multisigWalletAddress = sharedAddress;
    this.multisigWalletAddressBase32 = liskCryptography.getBase32AddressFromAddress(this.multisigWalletAddress);
    this.multisigWalletPublicKey = sharedPublicKey;

    let account = await this.apiClient.account.get(this.multisigWalletAddress);
    this.multisigWalletKeys = account.keys;
    this.initialAccountNonce = account.sequence.nonce;

    await this.reset(lastProcessedHeight);
  }

  async unload() {
    await this.liskWsClient.close();
  }

  async reset(lastProcessedHeight) {
    let lastProcessedBlock = await this.channel.invoke(`${this.moduleAlias}:getBlockAtHeight`, {
      height: lastProcessedHeight
    });

    let oldOutboundTxns = await this.channel.invoke(`${this.moduleAlias}:getOutboundTransactions`, {
      walletAddress: this.multisigWalletAddressBase32,
      fromTimestamp: lastProcessedBlock.timestamp,
      limit: MAX_TRANSACTIONS_PER_TIMESTAMP,
      order: 'desc'
    });

    if (oldOutboundTxns.length) {
      let highestNonce = oldOutboundTxns.reduce((accumulator, txn) => {
        let txnNonce = BigInt(txn.nonce);
        if (txnNonce > accumulator) {
          return txnNonce;
        }
        return accumulator;
      }, 0n);
      this.nonceIndex = highestNonce + 1n;
    } else {
      this.nonceIndex = this.initialAccountNonce;
    }
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

    let nonce = this.nonceIndex++;

    let txnData = {
      moduleID: 2,
      assetID: 0,
      fee: BigInt(transactionData.fee),
      asset: {
        amount: BigInt(transactionData.amount),
        recipientAddress: liskCryptography.getAddressFromBase32Address(transactionData.recipientAddress),
        data: ''
      },
      nonce,
      senderPublicKey: this.multisigWalletPublicKey,
      signatures: []
    };
    if (transactionData.message != null) {
      txnData.asset.data = transactionData.message;
    }

    let signedTxn = liskTransactions.signMultiSignatureTransaction(
      this.transferAssetSchema,
      txnData,
      this.networkIdBytes,
      this.passphrase,
      this.multisigWalletKeys
    );

    liskTransactions.signMultiSignatureTransaction(this.transferAssetSchema, signedTxn, this.networkIdBytes, this.sharedPassphrase, this.multisigWalletKeys);
    liskTransactions.signMultiSignatureTransaction(this.transferAssetSchema, signedTxn, this.networkIdBytes, this.passphrase, this.multisigWalletKeys);

    let { address: signerAddress, publicKey: signerPublicKey } = liskCryptography.getAddressAndPublicKeyFromPassphrase(this.passphrase);

    let nonceString = signedTxn.nonce.toString();

    let preparedTxn = {
      id: computeDEXTransactionId(this.multisigWalletAddressBase32, nonceString),
      message: signedTxn.asset.data,
      amount: signedTxn.asset.amount.toString(),
      timestamp: transactionData.timestamp,
      senderAddress: this.multisigWalletAddressBase32,
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

    return {transaction: preparedTxn, signature: multisigTxnSignature};
  }
}

async function wait(duration) {
  return new Promise((resolve) => {
    setTimeout(resolve, duration);
  });
}

module.exports = LiskChainCrypto;
