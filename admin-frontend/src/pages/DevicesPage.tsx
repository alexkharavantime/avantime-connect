import { useEffect, useState } from "react";
import { api, Device } from "../api/client";

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState("");
  const load = () => api.listDevices().then(d => { setDevices(d); setError(""); }).catch(e => setError(String(e)));
  useEffect(() => { load(); }, []);

  async function revoke(pk: string) {
    if (!confirm("Отозвать доступ этого устройства?")) return;
    try { await api.revoke(pk); await load(); } catch (e) { setError(String(e)); }
  }

  return (
    <div className="card">
      <h3>Устройства</h3>
      {error && <p role="alert">{error}</p>}
      <table>
        <thead><tr><th>Пользователь</th><th>Устройство</th><th>VPN IP</th><th>Статус</th><th></th></tr></thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.public_key}>
              <td>{d.login}</td><td>{d.device_name}</td><td>{d.vpn_ip}</td>
              <td>{d.revoked ? "отозван" : d.state === "pending" ? "регистрация не завершена" : d.state === "revoking" ? "отзыв не подтверждён" : d.state === "active" ? "активен" : "старая тестовая запись"}</td>
              <td>{!d.revoked && (d.state === "active" || d.state === "revoking") && <button className="danger" onClick={() => revoke(d.public_key)}>Отозвать</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
