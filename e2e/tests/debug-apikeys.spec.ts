import { test, expect } from '@playwright/test';

const BASE_URL = 'https://notes.lukko.de';
const USER = 'thomas.laerm';
const PASSWORD = 'vtT0EMxqhYUjMl9HZxvL';

test('debug api key revoke via UI', async ({ page }) => {
  // Capture all responses for debugging
  const responses: { url: string; status: number; body: string }[] = [];
  page.on('response', async (res) => {
    const url = res.url();
    if (url.includes('/api/apikeys')) {
      try {
        const body = await res.text();
        responses.push({ url, status: res.status(), body });
      } catch {
        responses.push({ url, status: res.status(), body: '<no body>' });
      }
    }
  });

  // Also capture network errors
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      console.log('Console error:', msg.text());
    }
  });

  // 1. Navigate to login page
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' });

  // Fill in credentials
  await page.fill('input[data-testid="login-identifier"]', USER);
  await page.fill('input[data-testid="login-password"]', PASSWORD);
  await page.click('button[data-testid="login-submit"]');

  // Wait for login to complete
  await page.waitForSelector('[data-testid="user-toolbar-avatar"]', { timeout: 10000 });

  console.log('=== Logged in ===');

  // 2. Navigate to API keys page
  await page.goto(`${BASE_URL}/settings/apikeys`, { waitUntil: 'networkidle' });

  // Wait for the page to load and show content
  await page.waitForSelector('.settings', { timeout: 10000 });

  console.log('=== API Keys page loaded ===');

  // 3. Create an API key - click the "Create Key" button
  const createKeyBtn = page.locator('button:has-text("Create Key")').first();
  await createKeyBtn.click({ timeout: 5000 });

  // Wait for dialog to appear - Radix renders as div[role="dialog"]
  await page.waitForSelector('[role="dialog"]', { state: 'visible', timeout: 10000 });

  console.log('=== Create dialog opened ===');

  // Fill in the name - find the text input in the dialog
  const nameInput = page.locator('[role="dialog"]').locator('input[type="text"]').first();
  await nameInput.fill('debug-revoke-test');

  // Click create button in dialog
  const dialogCreateBtn = page.locator('[role="dialog"]').locator('button:has-text("Create")').first();
  await dialogCreateBtn.click();

  // Wait for key to be created (dialog shows the key in a code block)
  await page.waitForSelector('[role="dialog"] code', { state: 'visible', timeout: 10000 });

  console.log('=== API Key created ===');
  console.log('API responses so far:', JSON.stringify(responses, null, 2));

  // 4. Close the create dialog
  await page.keyboard.press('Escape');
  await page.waitForTimeout(500);

  // 5. Find and click the revoke button for our key
  // Wait for the key name to appear in the list
  await page.waitForSelector('text=debug-revoke-test', { timeout: 10000 });

  // Target the FIRST bordered row (most recent key) and click its revoke button
  const keyRow = page.locator('div.border').filter({ hasText: 'debug-revoke-test' }).first();
  const revokeBtn = keyRow.locator('button');
  await revokeBtn.click({ timeout: 5000 });

  console.log('=== Revoke button clicked ===');

  // Wait for the revoke dialog to appear
  await page.waitForSelector('[role="dialog"]', { state: 'visible', timeout: 5000 });

  console.log('=== Revoke dialog opened ===');

  // Click the confirm/revoke button in the dialog
  const confirmBtn = page.locator('[role="dialog"]').locator('button:has-text("Revoke")').first();
  await confirmBtn.click();

  console.log('=== Revoke confirm clicked ===');

  // Wait for a bit to see what happens
  await page.waitForTimeout(3000);

  console.log('=== All API responses ===');
  console.log(JSON.stringify(responses, null, 2));

  // Check for toast messages
  const toasts = await page.locator('[role="status"]').allTextContents();
  console.log('=== Toast messages ===');
  console.log(JSON.stringify(toasts, null, 2));

  // Check if revoke was successful or failed
  const hasErrorToast = await page.locator('text=Failed to revoke API key').isVisible().catch(() => false);
  const hasSuccessToast = await page.locator('text=API key revoked').isVisible().catch(() => false);

  console.log('=== Result ===');
  console.log('Has error toast:', hasErrorToast);
  console.log('Has success toast:', hasSuccessToast);

  // Print all apikeys-related responses
  for (const r of responses) {
    if (r.status >= 400) {
      console.log(`ERROR: ${r.url} -> ${r.status}: ${r.body}`);
    }
  }
});
