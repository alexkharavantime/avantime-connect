import { useEffect, useState } from "react";
import { AuditEvent, getAudit, exportAudit } from "../api/client";
const actions: Record<string,string> = {invite: "Приглашение", enroll: "Регистрация устройства", access: "Изменение / применение доступа", revoke: "Отзыв"};
const statuses: Record<string,string> = {success: "Выполнено", error: "Ошибка / не подтверждено", unconfirmed: "Результат не подтверждён"};
export default function AuditPage() {
  const [login, setLogin] = useState(""); const [start, setStart] = useState(""); const [end, setEnd] = useState("");
  const [filter, setFilter] = useState(new URLSearchParams()); const [offset, setOffset] = useState(0);
  const [rows, setRows] = useState<AuditEvent[]>([]); const [total, setTotal] = useState(0);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const [exporting, setExporting] = useState(false);
  const [printRows, setPrintRows] = useState<AuditEvent[] | null>(null);
  const shown = printRows ?? rows;
  useEffect(() => { if(!printRows) return; const timer = setTimeout(() => { window.print(); setPrintRows(null); }, 100); return () => clearTimeout(timer); }, [printRows]);
  async function printAll() {
    setExporting(true); setError("");
    try {
      const params = new URLSearchParams(filter);
      // Freeze upper bound so new events do not shift pagination while collecting.
      const now = new Date().toISOString(); if(!params.has('end') || params.get('end')! > now) params.set('end', now);
      params.set('limit', '500'); let collected: AuditEvent[] = []; let total = 0;
      do { params.set('offset', String(collected.length)); const page = await getAudit(params);
        total = page.total; if(!page.items.length && collected.length < total) throw new Error('Журнал изменился, повторите печать');
        collected = collected.concat(page.items);
      } while(collected.length < total);
      setPrintRows(collected);
    } catch(e) {setError(String(e));} finally {setExporting(false);}
  }
  useEffect(() => { let alive = true; setBusy(true); setError(""); setRows([]);
    const params = new URLSearchParams(filter); params.set('offset', String(offset));
    getAudit(params).then(data => { if(alive) { setRows(data.items); setTotal(data.total); } })
      .catch(e => {if(alive) setError(String(e));}).finally(() => {if(alive) setBusy(false);});
    return () => {alive = false;};
  }, [filter, offset]);
  function apply(e: React.FormEvent) { e.preventDefault(); const params = new URLSearchParams();
    if(login) params.set('login', login);
    if(start) params.set('start', new Date(start + 'T00:00:00').toISOString());
    if(end) {const next = new Date(end + 'T00:00:00'); next.setDate(next.getDate()+1); params.set('end', next.toISOString());}
    setOffset(0); setFilter(params);
  }
  return <section className="card audit-page"><h2>Журнал доступа</h2>
    <p>Старые записи восстановлены только по сохранённым датам. «Выполнено» означает результат операции, а не активное соединение VPN. Каждый повтор операции — отдельная запись.</p>
    <form className="no-print" onSubmit={apply}>
      <label>Точный логин<input value={login} onChange={e=>setLogin(e.target.value)}/></label>
      <label>С даты<input type="date" value={start} onChange={e=>setStart(e.target.value)}/></label>
      <label>По дату включительно<input type="date" value={end} onChange={e=>setEnd(e.target.value)}/></label>
      <button disabled={busy}>Показать / обновить</button>
      <button type="button" disabled={busy || exporting || !!error} onClick={async()=>{setExporting(true); try{await exportAudit(filter);}catch(e){setError(String(e));}finally{setExporting(false);}}}>CSV — все записи по фильтру</button>
      <button type="button" disabled={busy || exporting || !!error || !rows.length} onClick={printAll}>Печать всего периода / PDF</button>
    </form>
    <p>Логин: {filter.get('login') || 'все'}. Период UTC: {filter.get('start') || 'начало'} — {filter.get('end') || 'сейчас'} (верхняя граница исключена).</p>
    {busy ? <p>Загрузка…</p> : error ? <p role="alert">Не удалось загрузить или выгрузить журнал: {error}</p> : <>
      <p>{printRows ? `Печатный отчёт: ${printRows.length} записей.` : `Записи ${rows.length ? offset+1 : 0}–${offset+rows.length} из ${total}. Печать и CSV включают весь выбранный период.`}</p>
      <div className="table-scroll"><table><thead><tr><th>Дата и время UTC</th><th>Операция / результат</th><th>Пользователь</th><th>Компьютер / IP</th><th>Доступ</th><th>Источник / инициатор</th></tr></thead><tbody>
        {shown.map(r=><tr key={r._id}><td>{r.timestamp.replace('T',' ').replace(/Z$/, '')}</td><td>{actions[r.action] || r.action}<br/>{statuses[r.status] || r.status}{r.http_status ? ` (HTTP ${r.http_status})` : ''}</td><td>{r.login || '—'}</td><td>{r.device_name || '—'}<br/>{r.vpn_ip || '—'}</td><td>{r.environments?.join(', ').toUpperCase() || '—'}</td><td>{r.source==='legacy' ? 'Из прежних данных' : 'Запись операции'}<br/>{r.actor==='shared_admin_key' ? 'Общий ключ администратора' : r.actor==='device_invitation' ? 'По приглашению' : 'Неизвестен'}</td></tr>)}
      </tbody></table></div>
      {!rows.length && <p>Записей за выбранный период нет.</p>}
      <div className="no-print"><button disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-100))}>Назад</button><button disabled={offset+rows.length>=total} onClick={()=>setOffset(offset+100)}>Далее</button></div>
    </>}
  </section>;
}
