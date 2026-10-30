import http from 'k6/http';
import { check, sleep, group } from 'k6';

// ── Test Configuration & Load Stages ─────────────────────────────
export const options = {
    stages: [
        { duration: '15s', target: 10 }, // Ramp-up to 10 users
        { duration: '55s', target: 20 },  // Stay at 20 users (steady load)
        { duration: '30s', target: 100 }, // Stress spike to 50 users
        { duration: '30s', target: 20 },  // Ramp-down to 0 users
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'], // 95% requests must complete within 500ms
        http_req_failed: ['rate<0.05'],   // Error rate should be less than 5%
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5000';

export function setup() {
    // Setup runs once before test: create a test user for API tests
    const testUsername = `k6_test_${Date.now()}`;
    const testPassword = 'Password123!';

    const res = http.post(`${BASE_URL}/auth/signup`, JSON.stringify({
        username: testUsername,
        password: testPassword
    }), {
        headers: { 'Content-Type': 'application/json' },
    });

    if (res.status !== 201) {
        console.error(`[k6 setup error] Status ${res.status}: ${res.body}`);
    }

    return { username: testUsername, password: testPassword };
}

export default function (data) {
    // 1. Test Public Landing Page
    group('01_Landing_Page', function () {
        const res = http.get(`${BASE_URL}/`);
        check(res, {
            'landing page status is 200': (r) => r.status === 200,
        });
    });

    sleep(1);

    // 2. Test API Authentication (JWT Token Generation)
    let token = '';
    group('02_API_Login', function () {
        const loginPayload = JSON.stringify({
            username: data.username,
            password: data.password
        });

        const res = http.post(`${BASE_URL}/auth/login`, loginPayload, {
            headers: { 'Content-Type': 'application/json' },
        });

        const success = check(res, {
            'login status is 200': (r) => r.status === 200,
            'access token returned': (r) => r.json('access_token') !== undefined,
        });

        if (success) {
            token = res.json('access_token');
        }
    });

    sleep(1);

    // 3. Authenticated Expense Operations
    if (token) {
        const authHeaders = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        };

        // Add Expense
        group('03_Add_Expense', function () {
            const expensePayload = JSON.stringify({
                amount: Math.floor(Math.random() * 500) + 50,
                category: 'Food & Dining',
                date: new Date().toISOString().split('T')[0],
                description: 'K6 Automated Load Test Expense'
            });

            const res = http.post(`${BASE_URL}/expenses`, expensePayload, {
                headers: authHeaders
            });

            check(res, {
                'add expense status is 201': (r) => r.status === 201,
            });
        });

        sleep(1);

        // Fetch Expenses
        group('04_Get_Expenses', function () {
            const res = http.get(`${BASE_URL}/expenses`, {
                headers: authHeaders
            });

            check(res, {
                'get expenses status is 200': (r) => r.status === 200,
            });
        });
    }

    sleep(1);
}

