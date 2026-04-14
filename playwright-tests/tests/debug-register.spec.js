const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin } = require('./helpers');

test('debug registration WAF error', async ({ request }) => {
    const username = `e2e_${randomStr()}`;
    const phone = `+7900${randomDigits(7)}`;

    const { csrfToken } = await registerAndLogin(request, username, phone);

    console.log('\n=== REGISTRATION RESPONSE ===');
    console.log('CSRF token obtained:', !!csrfToken);
    expect(csrfToken).toBeTruthy();
});
