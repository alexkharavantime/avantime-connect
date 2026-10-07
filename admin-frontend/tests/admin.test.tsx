import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import App from '../src/App';
import { setAdminToken } from '../src/api/client';

beforeEach(() => setAdminToken(''));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test('users: authorization error is visible and applying the corrected token reloads', async () => {
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
    const authorized = (init.headers as Record<string, string>).Authorization === 'Bearer test-admin-token';
    return new Response(JSON.stringify(authorized
      ? [{ login: 'oleg', full_name: 'Oleg', app_type: 'desktop' }]
      : { detail: 'Требуется ключ администратора' }), { status: authorized ? 200 : 401 });
  }));
  render(<App />);
  expect((await screen.findByRole('alert')).textContent).toContain('Требуется ключ администратора');
  expect(screen.queryByText('Пользователей пока нет')).toBeNull();
  expect(screen.queryByRole('table')).toBeNull();
  fireEvent.change(screen.getByLabelText('Ключ администратора'), { target: { value: 'test-admin-token' } });
  fireEvent.click(screen.getByRole('button', { name: 'Применить' }));
  expect(await screen.findByRole('cell', { name: 'oleg', exact: true })).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
});

test('users: retry distinguishes a loading failure from an empty list', async () => {
  let failed = true;
  vi.stubGlobal('fetch', vi.fn(async () => new Response(
    JSON.stringify(failed ? { detail: 'Недоступно' } : []), { status: failed ? 503 : 200 })));
  render(<App />);
  expect((await screen.findByRole('alert')).textContent).toContain('Не удалось загрузить пользователей');
  expect(screen.queryByText('Пользователей пока нет')).toBeNull();
  failed = false;
  fireEvent.click(screen.getByRole('button', { name: 'Повторить', exact: true }));
  expect(await screen.findByText('Пользователей пока нет')).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
});

test.each([502, 202])('devices: pending revoke and unconfirmed HTTP %i remain retryable', async status => {
  let state = 'pending';
  let attempts = 0;
  vi.stubGlobal('confirm', vi.fn(() => true));
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/users/') return new Response('[]');
    if (url === '/api/devices/') return new Response(JSON.stringify([{
      login: 'oleg', device_name: 'Laptop', vpn_ip: '10.30.0.7', public_key: 'test-key',
      state, revoked: state === 'revoked',
    }]));
    if (url === '/api/devices/test-key/revoke') {
      attempts++;
      state = attempts === 1 ? 'revoking' : 'revoked';
      return new Response(JSON.stringify(attempts === 1
        ? { status: 'revoking', detail: 'Отзыв не подтверждён' } : { status: 'revoked' }),
        { status: attempts === 1 ? status : 200 });
    }
    throw new Error('Unexpected API request: ' + url);
  }));
  render(<App />);
  await screen.findByText('Пользователей пока нет');
  fireEvent.click(screen.getByRole('button', { name: 'Устройства', exact: true }));
  expect(await screen.findByRole('cell', { name: 'регистрация не завершена' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Отозвать', exact: true }));
  expect((await screen.findByRole('alert')).textContent).toContain('не подтверждён');
  expect(await screen.findByRole('cell', { name: 'отзыв не подтверждён, повторите' })).toBeTruthy();
  expect(screen.queryByRole('cell', { name: 'отозван', exact: true })).toBeNull();
  const retry = await screen.findByRole('button', { name: 'Повторить отзыв', exact: true });
  await waitFor(() => expect((retry as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(retry);
  expect(await screen.findByRole('cell', { name: 'отозван', exact: true })).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(attempts).toBe(2);
});
