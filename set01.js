const _ = require("underscore");
const fs = require("fs");

// convert hex to base64
function challenge1(hex) {
  return Buffer.from(hex, "hex").toString("base64");
}

// xor two hex encoded strings, return hex
function challenge2(hex1, hex2) {
  const buf1 = Buffer.from(hex1, "hex");
  const buf2 = Buffer.from(hex2, "hex");
  return Buffer.from(buf1.map((item, index) => item ^ buf2[index])).toString(
    "hex"
  );
}

function challenge3(ciphertext) {
  function decode(cipher, key) {
    const buf = Buffer.from(cipher, "hex");
    return Buffer.from(buf.map((b) => b ^ key));
  }
  function score(buf) {
    return buf
      .map((byte) => ((byte >= 65 && byte <= 122) || byte == 32 ? 1 : 0))
      .reduce((a, b) => a + b);
  }

  const keys = _.sortBy(
    _.range(256).map((key) => {
      const decoded = decode(ciphertext, key);
      return { key, score: score(decoded), decoded: decoded.toString() };
    }),
    (item) => -item.score
  );
  // console.log(keys.slice(0, 5));
  return keys[0];
}

function readFile(file) {
  return new Promise(function (resolve, reject) {
    fs.readFile(file, "utf8", function (err, data) {
      if (err) {
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
}

async function readFileBase64(file) {
  let data = await readFile(file);
  return Buffer.from(data.replace(/\n/g, ""), "base64");
}

async function challenge4() {
  const data = await readFile("4.txt", "utf8");
  return _.sortBy(data.split("\n").map(challenge3), (item) => -item.score)[0]
    .decoded;
}

function encryptRepeatingXor(plaintext, key) {
  plaintext = Buffer.from(plaintext);
  key = Buffer.from(key);
  return Buffer.from(plaintext.map((b, i) => b ^ key[i % key.length])).toString(
    "hex"
  );
}

function numberOfSetBits(i) {
  i = i | 0;
  i = i - ((i >> 1) & 0x55555555);
  i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
  return (((i + (i >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
}

function editDist(s1, s2) {
  if (s1.length !== s2.length) {
    throw new Error(
      `Cannot calculate edit distance of items of different size. Item 1 length: ${s1.length} Item 2 length: ${s2.length}`
    );
  }
  const b1 = Buffer.from(s1);
  const b2 = Buffer.from(s2);
  return b1
    .map((b, i) => b ^ b2[i])
    .map(numberOfSetBits)
    .reduce((a, b) => a + b);
}

function pairs(items) {
  let [first, ...rest] = items;
  if (rest.length < 2) {
    return [items];
  }
  return rest.map((item) => [first, item]).concat(pairs(rest));
}

function avg(items) {
  if (items.length === 0) {
    throw new Error("Cannot calculate average of an empty array");
  }
  return items.reduce((a, b) => a + b) / items.length;
}

async function challenge6() {
  let data = await readFileBase64("6.txt");
  let keysizes = _.range(2, 41).map((keysize) => {
    let chunks = pairs(_.chunk(data, keysize).slice(0, 4));
    // let chunks = [_.chunk(data, keysize).slice(0, 2)];
    chunks = chunks.map(([a, b]) => editDist(a, b) / keysize);
    let avgDist = avg(chunks);
    // console.log({ avgDist, chunks });
    return { keysize, avgDist };
  });
  keysizes = _.sortBy(keysizes, (item) => item.avgDist);
  let keysize = keysizes[0].keysize;

  let chunks = _.chunk(data, keysize);
  let transposedChunks = _.range(keysize).map((i) =>
    chunks.map((chunk) => chunk[i])
  );
  let decoded = transposedChunks.map(challenge3);
  let plaintext = _.flatten(
    _.range(transposedChunks[0].length).map((i) =>
      decoded.map((c) => c.decoded[i])
    )
  ).join("");
  return {
    key: Buffer.from(decoded.map((chunk) => chunk.key)).toString(),
    plaintext,
  };
}

var aesjs = require("aes-js");

function descrypyAes(ciphertext, key) {
  ciphertext = Buffer.from(ciphertext);
  key = Buffer.from(key);
  let aesEcb = new aesjs.ModeOfOperation.ecb(key);
  return Buffer.from(aesEcb.decrypt(ciphertext)).toString();
}

async function challenge8() {
  let data = await readFile("8.txt");
  let ciphertexts = data.split("\n");
  for (let [i, ciphertext] of ciphertexts.entries()) {
    let blocks = _.sortBy(
      _.chunk(ciphertext, 16 * 2 /* two hex chars per byte */).map((block) =>
        block.join("")
      )
    );
    let dedup = _.uniq(blocks, true);

    if (blocks.length !== dedup.length) {
      //   console.log({ i, blocks: blocks.length, dedup: dedup.length });
      return i;
    }
  }
  return -1;
}

describe("set01", function () {
  it("challenge1", function () {
    expect(
      challenge1(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
      )
    ).toEqual(
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
  });
  it("challenge2", function () {
    expect(
      challenge2(
        "1c0111001f010100061a024b53535009181c",
        "686974207468652062756c6c277320657965"
      )
    ).toEqual("746865206b696420646f6e277420706c6179");
  });

  it("challenge3", function () {
    expect(
      challenge3(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
      ).decoded
    ).toEqual(`Cooking MC's like a pound of bacon`);
  });

  it("challenge4", async function () {
    expect(await challenge4()).toEqual("Now that the party is jumping\n");
  });

  it("challenge5", function () {
    expect(
      encryptRepeatingXor(
        `Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal`,
        "ICE"
      )
    ).toEqual(
      `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272` +
        `a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`
    );
  });

  it("editDist", function () {
    expect(editDist("this is a test", "wokka wokka!!!")).toEqual(37);
    expect(editDist("a", "b")).toEqual(2);
    expect(editDist("ad", "be")).toEqual(3);
    expect(editDist("Hello", "Hello")).toEqual(0);
  });

  it("challenge6", async function () {
    let solution = await challenge6();
    expect(solution.key).toEqual("Terminator X: Bring the noise");
  });

  it("challenge7", async function () {
    let ciphertext = await readFileBase64("7.txt");
    expect(
      descrypyAes(ciphertext, "YELLOW SUBMARINE").startsWith(
        `I'm back and I'm ringin' the bell`
      )
    ).toBe(true);
  });

  it("challenge8", async function () {
    expect(await challenge8()).toEqual(132);
  });
});
