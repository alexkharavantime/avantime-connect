import { useState } from "react";
import { setAdminToken } from "./api/client";
import UsersPage from "./pages/UsersPage";
import DevicesPage from "./pages/DevicesPage";

export default function App() {
  const [tab, setTab] = useState<"users" | "devices">("users");
  const [token, setToken] = useState("");
  const [version, setVersion] = useState(0);
  return (
    <div className="wrap">
      <h1>Avantime Connect — Admin</h1>
      <form className="card" onSubmit={(e) => { e.preventDefault(); setAdminToken(token); setToken(""); setVersion(v => v + 1); }}>
        <label>Ключ администратора <input type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /></label>
        <button type="submit">Применить</button>
        <p>Ключ хранится только в памяти вкладки. После обновления страницы введите его снова.</p>
      </form>
      <div className="tabs">
        <button className={tab === "users" ? "active" : ""} onClick={() => setTab("users")}>Пользователи</button>
        <button className={tab === "devices" ? "active" : ""} onClick={() => setTab("devices")}>Устройства</button>
      </div>
      {tab === "users" ? <UsersPage key={version} /> : <DevicesPage key={version} />}
    </div>
  );
}
