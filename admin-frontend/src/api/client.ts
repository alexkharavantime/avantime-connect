const BASE = import.meta.env.VITE_API_BASE ?? "/api";

let adminToken = "";
export function setAdminToken(token: string) { adminToken = token; }

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(adminToken ? { Authorization: `Bearer ${adminToken}` } : {}), ...init?.headers },
  });
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return res.json();
}

export type AppType = "desktop" | "remoteapp32" | "remoteapp64";
export interface User { login: string; full_name: string; app_type: AppType; environments?: string[]; access_revision?: number; }
export interface Device { login: string; device_name: string; vpn_ip: string; public_key: string; revoked: boolean; state?: "pending" | "active" | "revoking" | "revoked"; }

export const api = {
  setAccess: (login: string, environments: string[], expected_revision: number) => req<{status: string}>(`/users/${encodeURIComponent(login)}/access`, {method: 'POST', body: JSON.stringify({environments, expected_revision})}),
  retryAccess: (login: string) => req<{status: string}>(`/users/${encodeURIComponent(login)}/access/retry`, {method: 'POST'}),
  listUsers:  () => req<User[]>("/users/"),
  createUser: (u: User) => req<{ login: string }>("/users/", { method: "POST", body: JSON.stringify(u) }),
  createInvite: (login: string) => req<{ token: string; expires_at: string }>(`/invites/${login}`, { method: "POST" }),
  listDevices: () => req<Device[]>("/devices/"),
  revoke: (pk: string) => req<{ status: string }>(`/devices/${encodeURIComponent(pk)}/revoke`, { method: "POST" }),
};
