/**
 * mlkem.test.js
 * K1: ML-KEM-768 (FIPS 203) KEM-примитив — round-trip через вендоренную pure-JS
 * либу. Дормантно (в путь обёртки ключей не подключён; K3/K4). Проверяет размеры
 * FIPS 203, сходимость shared secret, implicit rejection при чужом приватном.
 */

const { mlkemKeygen, mlkemEncaps, mlkemDecaps, MLKEM768 } = require('../dr/mlkem.js');

test('keygen — размеры ML-KEM-768 (FIPS 203)', () => {
    const { publicKeyHex, secretKeyHex } = mlkemKeygen();
    expect(publicKeyHex).toMatch(new RegExp(`^[0-9a-f]{${MLKEM768.publicKey * 2}}$`));   // 1184 байта
    expect(secretKeyHex.length).toBe(MLKEM768.secretKey * 2);                            // 2400 байт
});

test('encaps → decaps: shared secrets сходятся (round-trip)', () => {
    const { publicKeyHex, secretKeyHex } = mlkemKeygen();
    const { cipherTextHex, sharedSecret } = mlkemEncaps(publicKeyHex);
    expect(cipherTextHex.length).toBe(MLKEM768.cipherText * 2);   // 1088 байт
    expect(sharedSecret.length).toBe(MLKEM768.sharedSecret);      // 32 байта
    const recovered = mlkemDecaps(cipherTextHex, secretKeyHex);
    expect(Array.from(recovered)).toEqual(Array.from(sharedSecret));
});

test('две keygen дают разные пары (недетерминированность)', () => {
    expect(mlkemKeygen().publicKeyHex).not.toBe(mlkemKeygen().publicKeyHex);
});

test('чужой приватный → ДРУГОЙ shared secret (implicit rejection, не расшифровывается)', () => {
    const alice = mlkemKeygen();
    const { cipherTextHex, sharedSecret } = mlkemEncaps(alice.publicKeyHex);
    const eve = mlkemKeygen();
    const wrong = mlkemDecaps(cipherTextHex, eve.secretKeyHex);   // FIPS 203: не бросает, даёт другой secret
    expect(wrong.length).toBe(32);
    expect(Array.from(wrong)).not.toEqual(Array.from(sharedSecret));
});
