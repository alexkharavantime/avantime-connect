import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import { downloadConfig, generateTunnelKeys, renderConfig, TunnelKeys, validateDns } from '../wireguard/config';

export default function MacConfig({ login, onClose }: { login: string; onClose: () => void }) {
  const [name, setName] = useState('MacBook');
  // Matches the DNS host explicitly routed by the existing DEV/PROD access policy.
  const [dns, setDns] = useState('10.40.0.10');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [config, setConfig] = useState('');
  const [ip, setIp] = useState('');
  const [started, setStarted] = useState(false);
  const pending = useRef<{ keys: TunnelKeys; token?: string; name: string; dns: string }>();
  const inFlight = useRef(false);
  useEffect(() => {
    if (!started) return;
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = ''; };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [started]);

  async function create() {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true); setError('');
    try {
      if (!pending.current) {
        if (!name.trim() || name.length > 100) throw new Error('Введите имя устройства (до 100 символов).');
        const checkedDns = validateDns(dns);
        pending.current = { keys: await generateTunnelKeys(), name: name.trim(), dns: checkedDns };
        setStarted(true);
      }
      const p = pending.current;
      if (!p.token) p.token = (await api.createInvite(login)).token;
      // A failed/lost response MUST retry the same token, public key and name.
      const profile = await api.enroll({ token: p.token, public_key: p.keys.publicKey, device_name: p.name });
      setConfig(renderConfig(p.keys, profile, p.dns)); setIp(profile.vpn_ip);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { inFlight.current = false; setBusy(false); }
  }

  function close() {
    if (started && !confirm(config
      ? 'Файл .conf сохранён? После закрытия скачать его повторно нельзя. При потере файла отзовите устройство и создайте новое.'
      : 'Регистрация могла создать устройство. После закрытия проверьте раздел «Устройства» и отзовите незавершённое устройство перед новой попыткой. Закрыть?')) return;
    pending.current = undefined; setConfig(''); onClose();
  }

  return <section className="card no-print" aria-label="Конфигурация WireGuard для Mac">
    <h3>WireGuard для Mac — {login}</h3>
    <p>Создаётся отдельное устройство. Ключ хранится только в этой вкладке; сохраните файл перед закрытием страницы.</p>
    <label>Имя Mac <input value={name} maxLength={100} disabled={busy || started} onChange={e => setName(e.target.value)} /></label>
    <label>DNS для VPN <input value={dns} disabled={busy || started} onChange={e => setDns(e.target.value)} /></label>
    {!config && <button disabled={busy} onClick={create}>{busy ? 'Регистрация…' : started ? 'Повторить регистрацию' : 'Создать конфигурацию'}</button>}
    {error && <p role="alert">{error} {started && 'Не обновляйте страницу; повторите регистрацию с сохранёнными ключами.'}</p>}
    {config && <>
      <p role="status">Устройство зарегистрировано. VPN-IP: {ip}</p>
      <button onClick={() => downloadConfig(config)}>Скачать .conf</button>
      <p>На Mac: WireGuard → Import tunnel(s) from file → Avantime-Mac.conf → Activate.</p>
      <p>Файл содержит секретный ключ. Передайте его только владельцу Mac. Отзыв доступен в разделе «Устройства».</p>
    </>}
    <button disabled={busy} onClick={close}>Закрыть</button>
  </section>;
}
