import { useEffect, useState } from "react";
import { api, Device } from "../api/client";

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState("");
  const [revokeError, setRevokeError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const load = () => api.listDevices().then(d => { setDevices(d); setError(""); }).catch(e => setError(String(e)));
  useEffect(() => { load(); }, []);

  async function revoke(pk: string) {
    if (!confirm("Отозвать доступ этого устройства?")) return;
    setBusy(pk);
    setRevokeError("");
    try {
      const result = await api.revoke(pk);
      if (result.status !== "revoked") throw new Error("Отзыв не подтверждён, повторите отзыв");
    } catch (e) { setRevokeError(String(e)); }
    finally { await load(); setBusy(null); }
  }

  return (
    <div className="card">
      <h3>Устройства</h3>
      {error && <p role="alert">{error}</p>}
      {revokeError && <p role="alert">{revokeError}</p>}
      <table>
        <thead><tr><th>Пользователь</th><th>Устройство</th><th>VPN IP</th><th>Статус</th><th></th></tr></thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.public_key}>
              <td>{d.login}</td><td>{d.device_name}</td><td>{d.vpn_ip}</td>
              <td>{d.state === "revoking" ? "отзыв не подтверждён, повторите" : d.state === "revoked" ? "отозван" : d.state === "pending" ? "регистрация не завершена" : d.state === "active" ? "активен" : "старая тестовая запись"}</td>
              <td>{(d.state === "pending" || d.state === "active" || d.state === "revoking") && <button className="danger" disabled={busy !== null} onClick={() => revoke(d.public_key)}>{busy === d.public_key ? "Отзыв…" : d.state === "revoking" ? "Повторить отзыв" : "Отозвать"}</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
