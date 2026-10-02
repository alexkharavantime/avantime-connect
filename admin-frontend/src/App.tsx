import { useState } from "react";
import UsersPage from "./pages/UsersPage";
import DevicesPage from "./pages/DevicesPage";

export default function App() {
  const [tab, setTab] = useState<"users" | "devices">("users");
  return (
    <div className="wrap">
      <h1>Avantime Connect — Admin</h1>
      <div className="tabs">
        <button className={tab === "users" ? "active" : ""} onClick={() => setTab("users")}>Пользователи</button>
        <button className={tab === "devices" ? "active" : ""} onClick={() => setTab("devices")}>Устройства</button>
      </div>
      {tab === "users" ? <UsersPage /> : <DevicesPage />}
    </div>
  );
}
