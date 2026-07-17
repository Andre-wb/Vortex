/**
 * identity-pin.test.js
 * TOFU-пиннинг аккаунтного Ed25519 пира: фиксация на первый контакт, детект
 * смены (block/warn), отсутствие тихого апдейта.
 */

const {
    pinPeerAccountEd, pinnedPeerAccountEd, clearPeerAccountEdPin,
} = require('../dr/identity-pin.js');

const ED_A = '11'.repeat(32);
const ED_B = '22'.repeat(32);

beforeEach(() => {
    localStorage.clear();
});

test('первый контакт: пиннит и возвращает trusted', () => {
    const r = pinPeerAccountEd(7, ED_A);
    expect(r).toEqual({ trusted: ED_A });
    expect(pinnedPeerAccountEd(7)).toBe(ED_A);
});

test('повторный тот же ключ: trusted, без изменений', () => {
    pinPeerAccountEd(7, ED_A);
    expect(pinPeerAccountEd(7, ED_A)).toEqual({ trusted: ED_A });
});

test('другой ключ у известного пира: changed, пин НЕ перезаписан', () => {
    pinPeerAccountEd(7, ED_A);
    const r = pinPeerAccountEd(7, ED_B);
    expect(r).toEqual({ changed: true, pinned: ED_A });
    expect(pinnedPeerAccountEd(7)).toBe(ED_A);   // пин остался прежним
});

test('пустой ключ → missing', () => {
    expect(pinPeerAccountEd(7, null)).toEqual({ missing: true });
    expect(pinPeerAccountEd(7, '')).toEqual({ missing: true });
});

test('пины изолированы по peerUserId', () => {
    pinPeerAccountEd(7, ED_A);
    pinPeerAccountEd(8, ED_B);
    expect(pinnedPeerAccountEd(7)).toBe(ED_A);
    expect(pinnedPeerAccountEd(8)).toBe(ED_B);
});

test('clear снимает пин (сброс доверия)', () => {
    pinPeerAccountEd(7, ED_A);
    clearPeerAccountEdPin(7);
    expect(pinnedPeerAccountEd(7)).toBeNull();
    // после сброса следующий контакт пиннит заново (TOFU)
    expect(pinPeerAccountEd(7, ED_B)).toEqual({ trusted: ED_B });
});
