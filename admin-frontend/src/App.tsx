import { useState } from "react";
import { setAdminToken } from "./api/client";
import UsersPage from "./pages/UsersPage";
import AuditPage from "./pages/AuditPage";
import DevicesPage from "./pages/DevicesPage";

export default function App() {
  const [tab, setTab] = useState<"users" | "devices" | "audit">("users");
  const [token, setToken] = useState("");
  const [version, setVersion] = useState(0);
  return (
    <div className="wrap">
      <h1>Avantime Connect — Admin <small>0.5.1</small></h1>
      <form className="card no-print" onSubmit={(e) => { e.preventDefault(); setAdminToken(token); setToken(""); setVersion(v => v + 1); }}>
        <label>Ключ администратора <input type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /></label>
        <button type="submit">Применить</button>
        <p>Ключ хранится только в памяти вкладки. После обновления страницы введите его снова.</p>
      </form>
      <div className="tabs no-print">
        <button className={tab === "users" ? "active" : ""} onClick={() => setTab("users")}>Пользователи</button>
        <button className={tab === "devices" ? "active" : ""} onClick={() => setTab("devices")}>Устройства</button>
        <button className={tab === "audit" ? "active" : ""} onClick={() => setTab("audit")}>Журнал доступа</button>
      </div>
      {tab === "users" ? <UsersPage key={version} /> : tab === "devices" ? <DevicesPage key={version} /> : <AuditPage key={version} />}
    </div>
  );
}
