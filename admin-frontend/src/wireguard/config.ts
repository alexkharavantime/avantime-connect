import type { EnrollmentProfile } from '../api/client';

export interface TunnelKeys { privateKey: string; publicKey: string; }
const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

// Native X25519; never send the private key to the API or persist it in storage.
export async function generateTunnelKeys(): Promise<TunnelKeys> {
  if (!globalThis.crypto?.subtle) throw new Error('Откройте админку по HTTPS в современном браузере.');
  try {
    const keys = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
    if (!jwk.d) throw new Error('Missing private key');
    const raw = Uint8Array.from(atob(jwk.d.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    if (raw.length !== 32) throw new Error('Invalid private key');
    raw[0] &= 248; raw[31] &= 127; raw[31] |= 64;
    const privateKey = base64(raw); raw.fill(0);
    return { privateKey, publicKey: base64(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))) };
  } catch {
    throw new Error('Браузер не поддерживает создание ключей X25519. Используйте актуальный браузер и HTTPS.');
  }
}

function ipv4(value: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split('.').every(v => Number(v) <= 255);
}

export function validateDns(value: string): string {
  const addresses = value.split(',').map(v => v.trim());
  if (!addresses.length || !addresses.every(ipv4)) throw new Error('Укажите IPv4-адрес DNS или адреса через запятую.');
  return addresses.join(', ');
}

export function renderConfig(keys: TunnelKeys, profile: EnrollmentProfile, dns: string): string {
  const key = /^[A-Za-z0-9+/]{43}=$/;
  const routes = profile.allowed_ips.split(',').map(v => v.trim());
  const port = Number(profile.endpoint.slice(profile.endpoint.lastIndexOf(':') + 1));
  if (!key.test(keys.privateKey) || !key.test(profile.server_public_key) || !ipv4(profile.vpn_ip) ||
      !/^[a-zA-Z0-9.:[\]-]+:\d{1,5}$/.test(profile.endpoint) ||
      port < 1 || port > 65535 ||
      !routes.every(v => { const [ip, bits, extra] = v.split('/'); return !extra && ipv4(ip) && /^\d{1,2}$/.test(bits ?? '') && Number(bits) <= 32; }) ||
      !Number.isInteger(profile.keepalive) || profile.keepalive < 0 || profile.keepalive > 65535) {
    throw new Error('Сервер вернул некорректные параметры туннеля. Конфигурация не выдана.');
  }
  return `[Interface]\nPrivateKey = ${keys.privateKey}\nAddress = ${profile.vpn_ip}/32\nDNS = ${validateDns(dns)}\n\n[Peer]\nPublicKey = ${profile.server_public_key}\nEndpoint = ${profile.endpoint}\nAllowedIPs = ${routes.join(', ')}\nPersistentKeepalive = ${profile.keepalive}\n`;
}

export function downloadConfig(config: string) {
  const url = URL.createObjectURL(new Blob([config], { type: 'text/plain;charset=utf-8' }));
  const a = document.createElement('a'); a.href = url; a.download = 'Avantime-Mac.conf';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
