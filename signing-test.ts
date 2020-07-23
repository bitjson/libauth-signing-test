import {
  SigningSerializationFlag,
  disassembleBytecodeBCH,
  hexToBin,
  instantiateSha256,
  stringify,
  bigIntToBinUint64LE,
  encodeOutpoints,
  encodeOutputsForSigning,
  encodeSequenceNumbersForSigning,
  binToHex,
  generateSigningSerializationBCH,
  instantiateSecp256k1,
  flattenBinArray,
  encodeDataPush,
  encodeTransaction,
  instantiateVirtualMachineBCH,
  decodeTransactionUnsafe,
} from '@bitauth/libauth';

const PRIVATE_KEY = hexToBin(
  '9618d321ca4afb37d3038a2644a375eaac257b50fee0f44ae8d1fbf4aa29e7a1'
);
const PUBLIC_KEY = hexToBin(
  '049d15e08105782ff4891da2c5c01a867ef6be0014ca93d5ee7ae5fc5e2bf64abaed328009be1ea26dff7c3f36028bec377a68002204e2b2cd5eb83b18bd5c0fe0'
);

const RAW_TX =
  '0200000001a5ba5ad95af829973dd59bea297de21b050dffa42d9a2d5cec1b0c9ce2f293500100000000ffffffff01a0860100000000001976a91458bd61a3083172b7ff3ab150ed8cd6a53fb2836088ac00000000';
const UTXO_LOCKING_SCRIPT =
  '76a91494c4dd77d0689459bebbc6ffe385f049e40cdd4d88ac';
console.log(
  `disassembled utxo locking script: ${disassembleBytecodeBCH(
    hexToBin(UTXO_LOCKING_SCRIPT)
  )}`
);
const UTXO_VALUE_SATOSHIS = 1_000_000;

// Wrap the application in an async function to allow use of await/async.
const main = async function () {
  const sha256 = await instantiateSha256();
  const libauthTransaction = decodeTransactionUnsafe(hexToBin(RAW_TX));
  console.log(`unsigned tx: ${stringify(libauthTransaction)}`);

  const signingSerialization = generateSigningSerializationBCH({
    correspondingOutput: Uint8Array.of(),
    coveredBytecode: hexToBin(UTXO_LOCKING_SCRIPT),
    locktime: libauthTransaction.locktime,
    outpointIndex: libauthTransaction.inputs[0].outpointIndex,
    outpointTransactionHash:
      libauthTransaction.inputs[0].outpointTransactionHash,
    outputValue: bigIntToBinUint64LE(BigInt(UTXO_VALUE_SATOSHIS)),
    sequenceNumber: libauthTransaction.inputs[0].sequenceNumber,
    sha256,
    signingSerializationType: Uint8Array.of(
      SigningSerializationFlag.allOutputs | SigningSerializationFlag.forkId
    ),
    transactionOutpoints: encodeOutpoints(libauthTransaction.inputs),
    transactionOutputs: encodeOutputsForSigning(libauthTransaction.outputs),
    transactionSequenceNumbers: encodeSequenceNumbersForSigning(
      libauthTransaction.inputs
    ),
    version: libauthTransaction.version,
  });
  console.log(`signingSerialization: ${binToHex(signingSerialization)}`);
  const signingSerializationHash = sha256.hash(
    sha256.hash(signingSerialization)
  );
  console.log(
    `signingSerializationHash: ${binToHex(signingSerializationHash)}`
  );

  // generate ecdsa signature
  const secp256k1 = await instantiateSecp256k1();
  const libauthSig = flattenBinArray([
    secp256k1.signMessageHashDER(PRIVATE_KEY, signingSerializationHash),
    Uint8Array.of(
      SigningSerializationFlag.allOutputs | SigningSerializationFlag.forkId
    ),
  ]);
  console.log(`libauth hashed sig: ${binToHex(libauthSig)}`);

  // applying a signature to transaction
  const libauthEncodedLibauthScriptSig = flattenBinArray([
    encodeDataPush(libauthSig),
    encodeDataPush(PUBLIC_KEY),
  ]);
  console.log(
    `libauth encoded libauth script sig: ${binToHex(
      libauthEncodedLibauthScriptSig
    )}`
  );
  libauthTransaction.inputs[0].unlockingBytecode = libauthEncodedLibauthScriptSig;

  console.log(
    `signed tx hex libauth: ${binToHex(encodeTransaction(libauthTransaction))}`
  );

  // verify correctness
  const program = {
    inputIndex: 0,
    sourceOutput: {
      lockingBytecode: hexToBin(UTXO_LOCKING_SCRIPT),
      satoshis: bigIntToBinUint64LE(BigInt(UTXO_VALUE_SATOSHIS)),
    },
    spendingTransaction: libauthTransaction,
  };

  const vm = await instantiateVirtualMachineBCH();
  const programEval = vm.evaluate(program);
  console.log('program evaluation post sig:');
  console.log(stringify(programEval));
};

main();
