import { useEffect, useState } from "react";
import { api, User, AppType, Device } from "../api/client";

export default function UsersPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [login, setLogin] = useState("");
  const [fullName, setFullName] = useState("");
  const [appType, setAppType] = useState<AppType>("desktop");
  const [environments, setEnvironments] = useState("prod");
  const [accessBusy, setAccessBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok?: string; err?: string }>({});
  const [invite, setInvite] = useState<{ login: string; token: string } | null>(null);

  async function load() {
    setLoading(true);
    setLoadError("");
    try {
      const [loadedUsers, loadedDevices] = await Promise.all([api.listUsers(), api.listDevices()]);
      setUsers(loadedUsers); setDevices(loadedDevices);
    }
    catch (e) { setLoadError(e instanceof Error ? e.message : String(e)); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);

  async function createUser() {
    setMsg({});
    try {
      await api.createUser({ login, full_name: fullName, app_type: appType, environments: environments.split(",") });
      setLogin(""); setFullName(""); setMsg({ ok: "Пользователь создан" }); load();
    } catch (e: any) { setMsg({ err: e.message }); }
  }
  async function makeInvite(l: string) {
    try { const r = await api.createInvite(l); setInvite({ login: l, token: r.token }); }
    catch (e: any) { setMsg({ err: e.message }); }
  }

  async function changeAccess(u: User, value?: string) {
    setAccessBusy(true); setMsg({});
    try {
      if (value) await api.setAccess(u.login, value.split(','), u.access_revision ?? 0);
      else await api.retryAccess(u.login);
      setMsg({ok: `Доступ ${u.login} применён. На компьютере нажмите «Обновить доступ».`});
    } catch (e) { setMsg({err: e instanceof Error ? e.message : String(e)}); }
    finally { await load(); setAccessBusy(false); }
  }

  return (
    <div>
      <div className="card">
        <h3>Новый пользователь</h3>
        <label>Логин</label>
        <input value={login} onChange={(e) => setLogin(e.target.value)} />
        <label>Полное имя (Фамилия Имя)</label>
        <input value={fullName} onChange={(e) => setFullName(e.target.value)} />
        <label>Тип подключения</label>
        <select value={appType} onChange={(e) => setAppType(e.target.value as AppType)}>
          <option value="desktop">Рабочий стол (Desktop)</option>
          <option value="remoteapp64">1С:Предприятие 8 (64-бит)</option>
          <option value="remoteapp32">1С:Предприятие 8 (32-бит)</option>
        </select>
        <label>Доступ к серверам</label>
        <select value={environments} onChange={e => setEnvironments(e.target.value)}>
          <option value="prod">Только PROD</option><option value="dev">Только DEV</option><option value="dev,prod">DEV и PROD</option>
        </select>
        <button className="primary" onClick={createUser}>Создать</button>
        {msg.ok && <div className="ok">{msg.ok}</div>}
        {msg.err && <div className="err">{msg.err}</div>}
      </div>

      {invite && (
        <div className="card">
          <h3>Приглашение для {invite.login}</h3>
          <p>Передайте пользователю токен (вставляется в утилиту один раз):</p>
          <div className="token">{invite.token}</div>
        </div>
      )}

      <div className="card">
        <h3>Пользователи</h3>
        {loading && <p role="status">Загрузка пользователей…</p>}
        {loadError && <div role="alert">
          <p>Не удалось загрузить пользователей: {loadError}</p>
          <button onClick={load}>Повторить</button>
        </div>}
        {!loading && !loadError && users.length === 0 && <p>Пользователей пока нет</p>}
        {!loading && !loadError && users.length > 0 && (
        <table>
          <thead><tr><th>Логин</th><th>Имя</th><th>Тип</th><th>Компьютеры / VPN-IP</th><th>Назначенный доступ</th><th></th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.login}>
                <td><code>{u.login}</code></td><td>{u.full_name}</td><td>{u.app_type}</td>
                <td>{devices.filter(d => d.login === u.login).length === 0 ? "Нет устройств" :
                  devices.filter(d => d.login === u.login).map(d => <div key={d.public_key} style={{marginBottom: 8}}>
                    <strong>{d.device_name}</strong><br/><code>{d.vpn_ip}</code>
                    <span> · {d.state === 'revoked' || d.revoked ? 'отозван' : d.state === 'active' ? 'активен' : 'ожидает / изменяется'}</span>
                  </div>)}</td>
                <td><select aria-label={`Доступ ${u.login}`} disabled={accessBusy} value={(u.environments ?? ['prod']).join(',')} onChange={e => changeAccess(u, e.target.value)}>
                  <option value="prod">Только PROD</option><option value="dev">Только DEV</option><option value="dev,prod">DEV и PROD</option>
                </select><button disabled={accessBusy} onClick={() => changeAccess(u)}>Повторить применение</button></td>
                <td><button className="primary" onClick={() => makeInvite(u.login)}>Приглашение</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        )}
      </div>
    </div>
  );
}
