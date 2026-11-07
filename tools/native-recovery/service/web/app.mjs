// Same-origin credential/session/CSRF pattern as the pinned legacy browser UI.
const $ = id => document.getElementById(id);
let csrf = null, snapshot = null;
async function api(path, body) {
  const response = await fetch(path, {method:body === undefined ? 'GET':'POST', credentials:'same-origin', cache:'no-store',
    headers: body === undefined ? {} : {'Content-Type':'application/json', ...(csrf ? {'X-CSRF-Token':csrf} : {})},
    ...(body === undefined ? {} : {body:JSON.stringify(body)})});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request refused.');
  if (result.csrf) csrf = result.csrf;
  return result;
}
function render(status) {
  snapshot = status;
  $('status').textContent = JSON.stringify({import:status.state, runtime:status.runtime, maintenance:status.maintenance}, null, 2);
  const phase = status.maintenance.state;
  $('refresh').disabled = false;
  $('admit').disabled = !status.maintenance.admission_available;
  $('recover').disabled = phase !== 'ARMED';
  $('start').disabled = !status.start_available || !$('confirmed').checked;
  $('stop').disabled = status.runtime?.state !== 'RUNNING';
  $('message').textContent = phase === 'UNCERTAIN' ? 'Uncertain: retained structural maintenance fence. Native reconciliation required; no retry or Start.' :
    phase === 'REPAIRED' ? 'Repair durably acknowledged. Feature retained. Only separate explicit Start launches the ship.' :
    phase === 'MAINTENANCE' ? 'Idle maintenance. Native controller/lifecycle bridge must be provisioned before admission.' : phase;
}
async function refresh(){render(await api('/api/status'));}
async function perform(path, body) {
  for (const id of ['admit','recover','start','stop']) $(id).disabled = true;
  try {render(await api(path,body));} catch(error) { $('message').textContent = error.message; try { await refresh(); } catch {} }
}
$('login').addEventListener('submit',async event=>{
  event.preventDefault();
  try {await api('/api/login',{password:$('password').value});$('password').value='';$('login').hidden=true;await refresh();}
  catch(error){$('password').value='';$('message').textContent=error.message;}
});
$('confirmed').addEventListener('change',()=>{if(snapshot)render(snapshot);});
$('refresh').addEventListener('click',()=>refresh().catch(error=>{$('message').textContent=error.message;}));
$('admit').addEventListener('click',()=>perform('/api/maintenance/admit',{}));
$('recover').addEventListener('click',()=>perform('/api/maintenance/recover',{}));
$('start').addEventListener('click',()=>perform('/api/start',{confirmed_stopped:$('confirmed').checked}));
$('stop').addEventListener('click',()=>perform('/api/stop',{}));
