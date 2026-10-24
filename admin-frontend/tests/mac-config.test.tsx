import { createPrivateKey, createPublicKey, webcrypto } from 'node:crypto';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import MacConfig from '../src/components/MacConfig';
import App from '../src/App';
import { generateTunnelKeys, renderConfig } from '../src/wireguard/config';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const profile = { vpn_ip: '10.30.0.7', server_public_key: Buffer.alloc(32, 1).toString('base64'),
  endpoint: 'vpn.example.com:51820', allowed_ips: '10.20.0.20/32, 10.40.0.10/32', keepalive: 25 };

test('native X25519 export is a valid WireGuard key pair and preserves assigned routes', async () => {
  vi.stubGlobal('crypto', webcrypto);
  const keys = await generateTunnelKeys();
  const privateKey = createPrivateKey({ key: Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(keys.privateKey, 'base64'),
  ]), format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
  expect(keys.publicKey).toBe(publicKey);
  const conf = renderConfig(keys, profile, '10.40.0.10');
  expect(conf).toContain(`PrivateKey = ${keys.privateKey}`);
  expect(conf).toContain('Address = 10.30.0.7/32\nDNS = 10.40.0.10');
  expect(conf).toContain(`AllowedIPs = ${profile.allowed_ips}`);
  expect(conf).not.toContain('0.0.0.0/0');
  expect(() => renderConfig(keys, {...profile, endpoint: 'vpn:51820\nPostUp = evil'}, '10.40.0.10')).toThrow();
  expect(() => renderConfig(keys, profile, '10.40.0.10\nPostUp = evil')).toThrow();
});

test('unsupported crypto does not create an invitation', async () => {
  vi.stubGlobal('crypto', {});
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  render(<MacConfig login="oleg" onClose={() => {}} />);
  fireEvent.click(screen.getByRole('button', {name: 'Создать конфигурацию'}));
  expect((await screen.findByRole('alert')).textContent).toContain('HTTPS');
  expect(fetch).not.toHaveBeenCalled();
});

test('lost enrollment response retains identity, never sends private keys, and downloads only after confirmation', async () => {
  vi.stubGlobal('crypto', webcrypto);
  const bodies: string[] = [];
  let invites = 0;
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    if (url.includes('/invites/')) { invites++; return new Response(JSON.stringify({token:'one-token'})); }
    if (url === '/api/enroll/') {
      bodies.push(init.body as string);
      if (bodies.length === 1) throw new Error('Network response lost');
      return new Response(JSON.stringify(profile));
    }
    throw new Error('Unexpected request');
  }));
  const createObjectURL = vi.fn(() => 'blob:test');
  vi.stubGlobal('URL', { createObjectURL, revokeObjectURL: vi.fn() });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  render(<MacConfig login="oleg" onClose={() => {}} />);
  fireEvent.click(screen.getByRole('button', {name: 'Создать конфигурацию'}));
  await screen.findByRole('alert');
  expect(screen.queryByRole('button', {name: 'Скачать .conf'})).toBeNull();
  fireEvent.click(screen.getByRole('button', {name: 'Повторить регистрацию'}));
  expect((await screen.findByRole('status')).textContent).toContain('10.30.0.7');
  expect(invites).toBe(1); expect(bodies[0]).toBe(bodies[1]);
  expect(Object.keys(JSON.parse(bodies[0])).sort()).toEqual(['device_name', 'public_key', 'token']);
  expect(createObjectURL).not.toHaveBeenCalled();
  vi.useFakeTimers();
  fireEvent.click(screen.getByRole('button', {name: 'Скачать .conf'}));
  expect(createObjectURL).toHaveBeenCalledOnce();
  vi.runAllTimers();
  vi.useRealTimers();
});

test('switching tabs and reapplying admin token preserve the in-memory Mac operation', async () => {
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/users/') return new Response(JSON.stringify([{login:'oleg', full_name:'Oleg', app_type:'desktop'}]));
    if (url === '/api/devices/') return new Response('[]');
    if (url.includes('/invites/')) return new Response('{"token":"one-token"}');
    if (url === '/api/enroll/') return new Response(JSON.stringify(profile));
    throw new Error('Unexpected request');
  }));
  render(<App />);
  fireEvent.click(await screen.findByRole('button', {name: 'WireGuard для Mac'}));
  fireEvent.click(screen.getByRole('button', {name: 'Создать конфигурацию'}));
  await screen.findByRole('button', {name: 'Скачать .conf'});
  fireEvent.click(screen.getByRole('button', {name: 'Устройства', exact:true}));
  fireEvent.click(screen.getByRole('button', {name: 'Применить', exact:true}));
  await waitFor(() => expect(screen.getByRole('button', {name: 'Скачать .conf'})).toBeTruthy());
});
