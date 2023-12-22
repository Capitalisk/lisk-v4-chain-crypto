const {
  cryptography: liskCryptography,
  transactions: liskTransactions
} = require('@liskhq/lisk-client');

const axios = require('axios');
const crypto = require('crypto');

const DEX_TRANSACTION_ID_LENGTH = 44;
const MAX_TRANSACTIONS_PER_TIMESTAMP = 100;
const API_BLOCK_FETCH_LIMIT = 50;
const DEFAULT_ACK_TIMEOUT = 20000;

const TAG_TRANSACTION = liskTransactions.TAG_TRANSACTION;

const toBuffer = (data) => Buffer.from(data, 'hex');
const bufferToString = (hexBuffer) => hexBuffer.toString('hex');
const computeDEXTransactionId = (senderAddress, nonce) => {
  return crypto.createHash('sha256').update(`${senderAddress}-${nonce}`).digest('hex').slice(0, DEX_TRANSACTION_ID_LENGTH);
};

const tokenTransferSchema = {
  $id: '/lisk/transferParams',
  title: 'Transfer transaction params',
  type: 'object',
  required: ['tokenID', 'amount', 'recipientAddress', 'data'],
  properties: {
    tokenID: {
      dataType: 'bytes',
      fieldNumber: 1,
      minLength: 8,
      maxLength: 8,
    },
    amount: {
      dataType: 'uint64',
      fieldNumber: 2,
    },
    recipientAddress: {
      dataType: 'bytes',
      fieldNumber: 3,
      format: 'lisk32',
    },
    data: {
      dataType: 'string',
      fieldNumber: 4,
      minLength: 0,
      maxLength: 64,
    },
  },
};

class LiskChainCrypto {
  constructor({chainOptions, logger}) {
    this.moduleAlias = chainOptions.moduleAlias;
    this.passphrase = chainOptions.passphrase;
    this.sharedPassphrase = chainOptions.sharedPassphrase;
    this.chainId = chainOptions.chainId || '00000000';
    this.tokenId = chainOptions.tokenId || '0000000000000000';
    this.nonceIndex = 0n;
    this.serviceURL = chainOptions.serviceURL;
    this.ackTimeout = chainOptions.ackTimeout == null ? DEFAULT_ACK_TIMEOUT : chainOptions.ackTimeout;
    this.logger = logger;

    this.axiosClient = axios.create({
      baseURL: this.serviceURL,
      timeout: this.ackTimeout
    });
  }

  async load(channel, lastProcessedHeight) {
    this.channel = channel;
    this.chainIdBytes = toBuffer(this.chainId);
    let {publicKey: sharedPublicKey} = liskCryptography.legacy.getPrivateAndPublicKeyFromPassphrase(this.sharedPassphrase);
    let sharedAddress = liskCryptography.address.getLisk32AddressFromPublicKey(sharedPublicKey);
    this.multisigWalletAddress = sharedAddress;
    this.multisigWalletPublicKey = sharedPublicKey;


    const accountResponse = await this.axiosClient.get(`${this.serviceURL}/api/v3/auth`, {params: {address: this.multisigWalletAddress}});
    let accountAuth = accountResponse.data.data;
    this.multisigWalletKeys = {
      mandatoryKeys: accountAuth.mandatoryKeys.map(key => toBuffer(key)),
      optionalKeys: accountAuth.optionalKeys.map(key => toBuffer(key))
    };
    this.initialAccountNonce = BigInt(accountAuth.nonce);

    await this.reset(lastProcessedHeight);
  }

  async unload() {}

  async reset(lastProcessedHeight) {
    let lastProcessedBlock = await this.channel.invoke(`${this.moduleAlias}:getBlockAtHeight`, {
      height: lastProcessedHeight
    });

    let oldOutboundTxns = await this.channel.invoke(`${this.moduleAlias}:getOutboundTransactions`, {
      walletAddress: this.multisigWalletAddress,
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
    let expectedAddress = liskCryptography.address.getLisk32AddressFromAddress(
      liskCryptography.address.getAddressFromPublicKey(publicKeyBuffer)
    );
    if (signerAddress !== expectedAddress) {
      return false;
    }

    let liskTxn = {
      module: 'token',
      command: 'transfer',
      nonce: BigInt(transaction.nonce),
      fee: BigInt(transaction.fee),
      senderPublicKey: toBuffer(transaction.senderPublicKey),
      signatures: [],
      params: {
        tokenID: toBuffer(transaction.tokenID),
        recipientAddress: liskCryptography.address.getAddressFromLisk32Address(transaction.recipientAddress),
        amount: BigInt(transaction.amount),
        data: transaction.message
      },
      id: transaction.id
    };

    let txnBuffer = liskTransactions.getBytes(liskTxn, tokenTransferSchema);
    // let transactionWithNetworkIdBuffer = Buffer.concat([this.chainIdBytes, txnBuffer]);// TODO 00

    return liskCryptography.ed.verifyData(
      TAG_TRANSACTION,
      this.chainIdBytes,
      // transactionWithNetworkIdBuffer,
      txnBuffer,
      toBuffer(signatureToVerify),
      publicKeyBuffer
    );
  }

  async prepareTransaction(transactionData) {
    try {
      liskCryptography.address.validateLisk32Address(transactionData.recipientAddress);
    } catch (error) {
      throw new Error(
        'Failed to prepare the transaction because the recipientAddress was invalid'
      );
    }

    let nonce = this.nonceIndex++;

    const txnData = {
      module: 'token',
      command: 'transfer',
      nonce,
      fee: BigInt(transactionData.fee),
      senderPublicKey: this.multisigWalletPublicKey,
      signatures: [],
      params: {
        tokenID: toBuffer(this.tokenId),
        recipientAddress: liskCryptography.address.getAddressFromLisk32Address(transactionData.recipientAddress),
        amount: BigInt(transactionData.amount),
        data: ''
      }
    };

    if (transactionData.message != null) {
      txnData.params.data = transactionData.message;
    }

    let {publicKey: signerPublicKey, privateKey: signerPrivateKey} = liskCryptography.legacy.getPrivateAndPublicKeyFromPassphrase(this.passphrase);

    let signedTxn = liskTransactions.signMultiSignatureTransaction(
      txnData,
      this.chainIdBytes,
      signerPrivateKey,
      this.multisigWalletKeys,
      tokenTransferSchema
    );

    let signerAddress = liskCryptography.address.getLisk32AddressFromPublicKey(signerPublicKey);
    let nonceString = signedTxn.nonce.toString();

    let preparedTxn = {
      id: computeDEXTransactionId(this.multisigWalletAddress, nonceString),
      message: signedTxn.params.data,
      amount: signedTxn.params.amount.toString(),
      tokenID: signedTxn.params.tokenID.toString('hex'),
      timestamp: transactionData.timestamp,
      senderAddress: this.multisigWalletAddress,
      recipientAddress: liskCryptography.address.getLisk32AddressFromAddress(signedTxn.params.recipientAddress),
      signatures: [],
      module: signedTxn.module,
      command: signedTxn.command,
      fee: signedTxn.fee.toString(),
      nonce: nonceString,
      senderPublicKey: bufferToString(signedTxn.senderPublicKey)
    };

    // The signature needs to be an object with a signerAddress property, the other
    // properties are flexible and depend on the requirements of the underlying blockchain.
    let multisigTxnSignature = {
      signerAddress,
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
