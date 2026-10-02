import { useEffect, useState } from "react";
import { api, Device } from "../api/client";

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const load = () => api.listDevices().then(setDevices).catch(() => {});
  useEffect(() => { load(); }, []);

  async function revoke(pk: string) {
    if (!confirm("Отозвать доступ этого устройства?")) return;
    await api.revoke(pk); load();
  }

  return (
    <div className="card">
      <h3>Устройства</h3>
      <table>
        <thead><tr><th>Пользователь</th><th>Устройство</th><th>VPN IP</th><th>Статус</th><th></th></tr></thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.public_key}>
              <td>{d.login}</td><td>{d.device_name}</td><td>{d.vpn_ip}</td>
              <td>{d.revoked ? "отозван" : "активен"}</td>
              <td>{!d.revoked && <button className="danger" onClick={() => revoke(d.public_key)}>Отозвать</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
