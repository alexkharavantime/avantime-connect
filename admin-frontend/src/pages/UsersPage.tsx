import { useEffect, useState } from "react";
import { api, User, AppType } from "../api/client";

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [login, setLogin] = useState("");
  const [fullName, setFullName] = useState("");
  const [appType, setAppType] = useState<AppType>("desktop");
  const [msg, setMsg] = useState<{ ok?: string; err?: string }>({});
  const [invite, setInvite] = useState<{ login: string; token: string } | null>(null);

  const load = () => api.listUsers().then(setUsers).catch(() => {});
  useEffect(() => { load(); }, []);

  async function createUser() {
    setMsg({});
    try {
      await api.createUser({ login, full_name: fullName, app_type: appType });
      setLogin(""); setFullName(""); setMsg({ ok: "Пользователь создан" }); load();
    } catch (e: any) { setMsg({ err: e.message }); }
  }
  async function makeInvite(l: string) {
    try { const r = await api.createInvite(l); setInvite({ login: l, token: r.token }); }
    catch (e: any) { setMsg({ err: e.message }); }
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
        <table>
          <thead><tr><th>Логин</th><th>Имя</th><th>Тип</th><th></th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.login}>
                <td>{u.login}</td><td>{u.full_name}</td><td>{u.app_type}</td>
                <td><button className="primary" onClick={() => makeInvite(u.login)}>Приглашение</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
