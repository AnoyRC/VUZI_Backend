const express = require("express");
const router = express.Router();
require("dotenv").config();
const fs = require("fs");
const crypto = require("crypto");

const getUintEncodedString = (plainString) => {
  const hash = crypto.createHash("sha256").update(plainString).digest("hex");

  const uintArray = [];
  for (let i = 0; i < 16; i += 2) {
    uintArray.push(parseInt(hash.slice(i, i + 2), 16).toString());
  }

  return uintArray;
};

async function generatePasswordHash(passwordArray) {
  try {
    let { initialize } = await import("zokrates-js");
    const zokratesProvider = await initialize();

    const source = `import "hashes/sha256/256bitPadded" as sha256;
          import "utils/pack/u32/pack128" as pack128;
          
          def main(private u32[8] a) -> field[2] {
              u32[8] h = sha256(a);
              return [pack128(h[0..4]), pack128(h[4..8])];
          }`;

    const artifacts = zokratesProvider.compile(source);

    const { witness, output } = zokratesProvider.computeWitness(artifacts, [
      passwordArray,
    ]);
    const lineBreakCleanedOutput = output.split("\n");
    const cleanedArray = [...lineBreakCleanedOutput.slice(1, 3)].map((item) => {
      return item.trim().replace(/^"|"|,$/g, "");
    });

    return cleanedArray;
  } catch (error) {
    throw new Error(error);
  }
}

async function generateRecoveryHash(rescoveryArrays) {
  try {
    let { initialize } = await import("zokrates-js");
    const zokratesProvider = await initialize();

    const source = `import "hashes/sha256/256bitPadded" as sha256;
    import "utils/pack/u32/pack256" as pack256;
    
    def main(private u32[8] a, private u32[8] b, private u32[8] c, private u32[8] d) -> field[4] {
        u32[8] h1 = sha256(a);
        u32[8] h2 = sha256(b);
        u32[8] h3 = sha256(c);
        u32[8] h4 = sha256(d);
    
        return [pack256(h1), pack256(h2), pack256(h3), pack256(h4)];
    }`;

    const artifacts = zokratesProvider.compile(source);

    const { witness, output } = zokratesProvider.computeWitness(artifacts, [
      rescoveryArrays[0],
      rescoveryArrays[1],
      rescoveryArrays[2],
      rescoveryArrays[3],
    ]);
    const lineBreakCleanedOutput = output.split("\n");
    const cleanedArray = [...lineBreakCleanedOutput.slice(1, 5)].map((item) => {
      return item.trim().replace(/^"|"|,$/g, "");
    });

    return cleanedArray;
  } catch (error) {
    throw new Error(error);
  }
}

router.post("/passcode/hash", async (req, res) => {
  try {
    const password = req.body.password;

    if (!password) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const passwordHashUint8Array = getUintEncodedString(password);
    const passwordHash = await generatePasswordHash(passwordHashUint8Array);

    res.json({ passwordHash });
  } catch (err) {
    res.json({ error: err.message });
  }
});

router.post("/passcode/verify", async (req, res) => {
  const password = req.body.password;
  const passwordHashes = req.body.passwordHashes;
  const nonce = req.body.nonce;

  if (!password || !passwordHashes || !nonce) {
    return res.status(400).json({ error: "Bad Request" });
  }

  try {
    let { initialize } = await import("zokrates-js");
    const zokratesProvider = await initialize();

    const source = `import "hashes/sha256/256bitPadded" as sha256;
      import "utils/pack/u32/pack128" as pack128;
      import "utils/casts/u32_to_field" as u32_to_field;
      
      def main(private u32[8] password, private field uncheckedNonce, field[2] hashedPassword, u32 nonce) -> bool {
          u32[8] h = sha256(password);
          field[2] res = [pack128(h[0..4]), pack128(h[4..8])];
      
          assert(hashedPassword[0] == res[0]);
          assert(hashedPassword[1] == res[1]);
          assert(u32_to_field(nonce) == uncheckedNonce);
      
          return true;
      }`;

    // compilation
    const artifacts = zokratesProvider.compile(source);
    const passwordHashUint8Array = getUintEncodedString(password);

    const { witness, output } = zokratesProvider.computeWitness(artifacts, [
      passwordHashUint8Array,
      nonce.toString(),
      passwordHashes,
      nonce.toString(),
    ]);

    const provingKeyData = await fs.readFileSync(
      `${__dirname}/../../constants/passcode/proving.key`
    );

    const provingKey = new Uint8Array(provingKeyData);
    // generate proof
    const proof = zokratesProvider.generateProof(
      artifacts.program,
      witness,
      provingKey
    );

    const transposedProof = [proof.proof.a, proof.proof.b, proof.proof.c];
    res.json({ proof: transposedProof, inputs: proof.inputs });
  } catch (err) {
    console.log(err);
    res.json({ err: err.message });
  }
});

router.post("/recovery/hash", async (req, res) => {
  try {
    const recoveryArray = req.body.recoveryArray;

    if (!recoveryArray) {
      return res.status(400).json({ error: "Bad Request" });
    }

    let recoveryArrayUint8Array = [];

    recoveryArray.forEach((item) => {
      recoveryArrayUint8Array.push(getUintEncodedString(item));
    });

    const recoveryHashes = await generateRecoveryHash(recoveryArrayUint8Array);

    res.json({ recoveryHashes });
  } catch (err) {
    res.json({ error: err.message });
  }
});

router.post("/recovery/verify", async (req, res) => {
  const recoveryCode = req.body.recoveryCode;
  const recoveryHashes = req.body.recoveryHashes;
  const nonce = req.body.nonce;

  if (!recoveryCode || !recoveryHashes || !nonce) {
    return res.status(400).json({ error: "Bad Request" });
  }

  try {
    let { initialize } = await import("zokrates-js");
    const zokratesProvider = await initialize();

    const source = `import "hashes/sha256/256bitPadded" as sha256;
    import "utils/pack/u32/pack256" as pack256;
    import "utils/casts/u32_to_field" as u32_to_field;
    
    def main(private u32[8] recoveryCode, private field uncheckedNonce, field[4] recoveryHashes, u32 nonce ) -> bool {
        u32[8] h = sha256(recoveryCode);
        field p = pack256(h);
    
        assert(p == recoveryHashes[0] || p == recoveryHashes[1] || p == recoveryHashes[2] || p == recoveryHashes[3]);
        assert(u32_to_field(nonce) == uncheckedNonce);
        return true;
    }`;

    // compilation
    const artifacts = zokratesProvider.compile(source);

    const recoveryCodeUint8Array = getUintEncodedString(recoveryCode);

    const { witness, output } = zokratesProvider.computeWitness(artifacts, [
      recoveryCodeUint8Array,
      nonce.toString(),
      recoveryHashes,
      nonce.toString(),
    ]);

    const provingKeyData = await fs.readFileSync(
      `${__dirname}/../../constants/recovery/proving.key`
    );

    const provingKey = new Uint8Array(provingKeyData);
    // generate proof
    const proof = zokratesProvider.generateProof(
      artifacts.program,
      witness,
      provingKey
    );

    const transposedProof = [proof.proof.a, proof.proof.b, proof.proof.c];
    res.json({ proof: transposedProof, inputs: proof.inputs });
  } catch (err) {
    console.log(err);
    res.json({ err: err.message });
  }
});

module.exports = router;
