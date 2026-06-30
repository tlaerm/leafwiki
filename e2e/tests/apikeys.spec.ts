import { expect, test } from '@playwright/test';

const user = process.env.E2E_ADMIN_USER || 'admin';
const password = process.env.E2E_ADMIN_PASSWORD || 'admin';

test.describe('API Keys', () => {
  test('admin can create an API key and use it to authenticate', async ({ request }) => {
    // Login
    const loginResp = await request.post('/api/auth/login', {
      data: { identifier: user, password },
    });
    expect(loginResp.status()).toBe(200);

    // Get CSRF token from response header
    const csrf = loginResp.headers()['x-csrf-token'];

    // Create API key
    const createResp = await request.post('/api/apikeys', {
      data: { name: 'e2e-test-key' },
      headers: {
        'X-CSRF-Token': csrf,
      },
    });
    expect(createResp.status()).toBe(201);

    const keyData = await createResp.json();
    expect(keyData.key).toBeDefined();
    expect(keyData.name).toBe('e2e-test-key');

    // Use the API key to authenticate
    const authResp = await request.get('/api/auth/me', {
      headers: {
        'Authorization': `Bearer ${keyData.key}`,
      },
    });
    expect(authResp.status()).toBe(200);
    const authData = await authResp.json();
    expect(authData.username).toBe(user);

    // List keys
    const listResp = await request.get('/api/apikeys', {
      headers: {
        'Authorization': `Bearer ${keyData.key}`,
      },
    });
    expect(listResp.status()).toBe(200);
    const keys = await listResp.json();
    expect(keys.length).toBeGreaterThanOrEqual(1);

    // Revoke the key
    const revokeResp = await request.delete(`/api/apikeys/${keyData.id}`, {
      headers: {
        'Authorization': `Bearer ${keyData.key}`,
      },
    });
    expect(revokeResp.status()).toBe(204);

    // Auth with revoked key should fail
    const revokedAuthResp = await request.get('/api/auth/me', {
      headers: {
        'Authorization': `Bearer ${keyData.key}`,
      },
    });
    expect(revokedAuthResp.status()).toBe(401);
  });

  test('viewer cannot create API keys', async ({ request }) => {
    // Login as admin and create a viewer user
    const adminLoginResp = await request.post('/api/auth/login', {
      data: { identifier: user, password },
    });
    expect(adminLoginResp.status()).toBe(200);

    const adminCsrf = adminLoginResp.headers()['x-csrf-token'];

    const createUserResp = await request.post('/api/users', {
      data: { username: 'e2e-viewer', email: 'viewer@test.com', password: 'viewerpass123', role: 'viewer' },
      headers: {
        'X-CSRF-Token': adminCsrf,
      },
    });
    expect(createUserResp.status()).toBe(201);

    // Login as viewer
    const viewerLoginResp = await request.post('/api/auth/login', {
      data: { identifier: 'e2e-viewer', password: 'viewerpass123' },
    });
    expect(viewerLoginResp.status()).toBe(200);

    const viewerCsrf = viewerLoginResp.headers()['x-csrf-token'];

    // Viewer tries to create API key - should be rejected
    const createKeyResp = await request.post('/api/apikeys', {
      data: { name: 'viewer-key' },
      headers: {
        'X-CSRF-Token': viewerCsrf,
      },
    });
    expect(createKeyResp.status()).toBe(403);

    // Re-login as admin to clean up
    const adminLoginResp2 = await request.post('/api/auth/login', {
      data: { identifier: user, password },
    });
    expect(adminLoginResp2.status()).toBe(200);

    const adminCsrf2 = adminLoginResp2.headers()['x-csrf-token'];
    await request.delete('/api/users/e2e-viewer', {
      headers: {
        'X-CSRF-Token': adminCsrf2,
      },
    });
  });

  test('expired API key cannot authenticate', async ({ request }) => {
    // Login
    const loginResp = await request.post('/api/auth/login', {
      data: { identifier: user, password },
    });
    expect(loginResp.status()).toBe(200);

    const csrf = loginResp.headers()['x-csrf-token'];

    // Create an API key that expires in 1 second
    const createResp = await request.post('/api/apikeys', {
      data: { name: 'e2e-expired-key', expiresIn: '1s' },
      headers: {
        'X-CSRF-Token': csrf,
      },
    });
    expect(createResp.status()).toBe(201);

    const keyData = await createResp.json();

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Auth should fail
    const authResp = await request.get('/api/auth/me', {
      headers: {
        'Authorization': `Bearer ${keyData.key}`,
      },
    });
    expect(authResp.status()).toBe(401);
  });
});
