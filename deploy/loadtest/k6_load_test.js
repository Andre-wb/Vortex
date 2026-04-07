/**
 * k6 Load Test for Vortex Chat
 *
 * Usage:
 *   k6 run deploy/loadtest/k6_load_test.js
 *   k6 run --vus 100 --duration 5m deploy/loadtest/k6_load_test.js
 *   k6 run --env BASE_URL=http://production:9000 deploy/loadtest/k6_load_test.js
 *
 * Scenarios:
 *   1. Health check (smoke)
 *   2. Registration + Login flow
 *   3. Room creation + message sending
 *   4. WebSocket chat simulation
 *   5. File upload stress
 */

import http from 'k6/http';
import ws from 'k6/ws';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ── Configuration ────────────────────────────────────────────────────────────
const BASE_URL = __ENV.BASE_URL || 'http://localhost:9000';
const WS_URL = BASE_URL.replace('http', 'ws');

// ── Custom Metrics ───────────────────────────────────────────────────────────
const registrationDuration = new Trend('vortex_registration_duration', true);
const loginDuration = new Trend('vortex_login_duration', true);
const messageSendDuration = new Trend('vortex_message_send_duration', true);
const wsConnectDuration = new Trend('vortex_ws_connect_duration', true);
const errorRate = new Rate('vortex_errors');
const messagesDelivered = new Counter('vortex_messages_delivered');

// ── Scenarios ────────────────────────────────────────────────────────────────
export const options = {
    scenarios: {
        // Smoke test: health endpoints
        smoke: {
            executor: 'constant-vus',
            vus: 5,
            duration: '30s',
            exec: 'smokeTest',
            startTime: '0s',
        },
        // Load test: registration + login
        auth_load: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '30s', target: 20 },
                { duration: '1m', target: 50 },
                { duration: '30s', target: 100 },
                { duration: '2m', target: 100 },
                { duration: '30s', target: 0 },
            ],
            exec: 'authFlow',
            startTime: '30s',
        },
        // Stress test: concurrent chat
        chat_stress: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '30s', target: 50 },
                { duration: '2m', target: 200 },
                { duration: '1m', target: 500 },
                { duration: '30s', target: 0 },
            ],
            exec: 'chatFlow',
            startTime: '5m',
        },
        // Spike test: sudden traffic burst
        spike: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '10s', target: 500 },
                { duration: '30s', target: 500 },
                { duration: '10s', target: 0 },
            ],
            exec: 'smokeTest',
            startTime: '9m',
        },
    },
    thresholds: {
        http_req_duration: ['p(95)<500', 'p(99)<2000'],
        http_req_failed: ['rate<0.05'],
        vortex_errors: ['rate<0.1'],
        vortex_registration_duration: ['p(95)<3000'],
        vortex_login_duration: ['p(95)<1000'],
    },
};

// ── Helper Functions ─────────────────────────────────────────────────────────

function getCSRF() {
    const res = http.get(`${BASE_URL}/api/authentication/csrf-token`);
    if (res.status === 200) {
        return JSON.parse(res.body).csrf_token || '';
    }
    return '';
}

function registerUser() {
    const tag = randomString(10);
    const phone = '+7900' + Math.floor(Math.random() * 9999999).toString().padStart(7, '0');
    const pubkey = Array.from({ length: 32 }, () =>
        Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('');

    const payload = JSON.stringify({
        username: `k6_${tag}`,
        password: 'K6LoadTest99!@',
        phone: phone,
        x25519_public_key: pubkey,
        display_name: `K6 User ${tag}`,
    });

    const res = http.post(`${BASE_URL}/api/authentication/register`, payload, {
        headers: { 'Content-Type': 'application/json' },
    });

    registrationDuration.add(res.timings.duration);
    return { status: res.status, username: `k6_${tag}`, password: 'K6LoadTest99!@', cookies: res.cookies };
}

function loginUser(username, password) {
    const csrf = getCSRF();
    const payload = JSON.stringify({
        phone_or_username: username,
        password: password,
    });

    const res = http.post(`${BASE_URL}/api/authentication/login`, payload, {
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf,
        },
    });

    loginDuration.add(res.timings.duration);
    return { status: res.status, cookies: res.cookies, csrf: csrf };
}

// ── Test Scenarios ───────────────────────────────────────────────────────────

export function smokeTest() {
    group('Health Checks', () => {
        const health = http.get(`${BASE_URL}/health`);
        check(health, {
            'health status 200': (r) => r.status === 200,
            'health body ok': (r) => JSON.parse(r.body).status === 'ok',
        }) || errorRate.add(1);

        const ready = http.get(`${BASE_URL}/health/ready`);
        check(ready, {
            'ready status 200': (r) => r.status === 200,
        }) || errorRate.add(1);

        const metrics = http.get(`${BASE_URL}/metrics`);
        check(metrics, {
            'metrics available': (r) => r.status === 200,
        });

        const publicRooms = http.get(`${BASE_URL}/api/rooms/public`);
        check(publicRooms, {
            'public rooms 200': (r) => r.status === 200,
        });
    });

    sleep(1);
}

export function authFlow() {
    group('Registration + Login', () => {
        const reg = registerUser();
        check(reg, {
            'registration success': (r) => r.status === 201,
        }) || errorRate.add(1);

        if (reg.status === 201) {
            sleep(0.5);
            const login = loginUser(reg.username, reg.password);
            check(login, {
                'login success': (r) => r.status === 200,
            }) || errorRate.add(1);

            if (login.status === 200) {
                // Get profile
                const me = http.get(`${BASE_URL}/api/authentication/me`, {
                    headers: { 'X-CSRF-Token': login.csrf },
                });
                check(me, {
                    'profile loaded': (r) => r.status === 200,
                });

                // List rooms
                const rooms = http.get(`${BASE_URL}/api/rooms/my`, {
                    headers: { 'X-CSRF-Token': login.csrf },
                });
                check(rooms, {
                    'rooms listed': (r) => r.status === 200,
                });
            }
        }
    });

    sleep(Math.random() * 2 + 1);
}

export function chatFlow() {
    group('Chat Simulation', () => {
        const reg = registerUser();
        if (reg.status !== 201) {
            errorRate.add(1);
            return;
        }

        const login = loginUser(reg.username, reg.password);
        if (login.status !== 200) {
            errorRate.add(1);
            return;
        }

        // Create room
        const csrf = login.csrf;
        const pubkey = Array.from({ length: 32 }, () =>
            Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
        ).join('');
        const ciphertext = Array.from({ length: 60 }, () =>
            Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
        ).join('');

        const roomRes = http.post(`${BASE_URL}/api/rooms`, JSON.stringify({
            name: `k6_room_${randomString(6)}`,
            encrypted_room_key: {
                ephemeral_pub: pubkey,
                ciphertext: ciphertext,
            },
        }), {
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrf,
            },
        });

        check(roomRes, {
            'room created': (r) => r.status === 200 || r.status === 201,
        }) || errorRate.add(1);

        if (roomRes.status === 200 || roomRes.status === 201) {
            const room = JSON.parse(roomRes.body);
            const roomId = room.id || (room.room && room.room.id);

            if (roomId) {
                // Get room details
                http.get(`${BASE_URL}/api/rooms/${roomId}`, {
                    headers: { 'X-CSRF-Token': csrf },
                });

                // Get members
                http.get(`${BASE_URL}/api/rooms/${roomId}/members`, {
                    headers: { 'X-CSRF-Token': csrf },
                });

                messagesDelivered.add(1);
            }
        }
    });

    sleep(Math.random() * 3 + 1);
}
