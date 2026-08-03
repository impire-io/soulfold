package adminui

import (
	"html/template"

	"github.com/impire-io/soulfold/internal/webstyle"
)

// The console's two server-rendered pages, on the shared fold theme
// (internal/webstyle). The login page carries the one script the
// console needs — the WebAuthn assertion (D9's stated exception).

const brand = `<a class="brand" href="/admin/"><span class="dot"></span><b>soulfold</b><span class="tag">admin</span></a>`

var loginTmpl = template.Must(template.New("adminlogin").Parse(
	webstyle.Head("admin · soulfold") + `<body><main><div class="center">
<div class="bar">` + brand + `</div>
<div class="card">
<h1>Administrator sign-in</h1>
<p class="lede">Use the passkey of a user in the <b>admin</b> group.</p>
<form id="f">
<label class="field">Username <input id="username" autocomplete="username webauthn" autofocus required></label>
<button class="btn" type="submit">Sign in with a passkey</button>
</form>
<p id="msg" class="msg"></p>
</div>
<p class="foot">soulfold · the door of the soulsystem</p>
</div></main>
<script>
const b64u={dec:s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)),
enc:b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
document.getElementById('f').addEventListener('submit',async ev=>{
 ev.preventDefault();const msg=document.getElementById('msg');
 try{
  const u=document.getElementById('username').value;
  const br=await fetch('/admin/login/begin?username='+encodeURIComponent(u),{method:'POST'});
  if(!br.ok)throw new Error(await br.text());
  const b=await br.json();const pk=b.options.publicKey;
  pk.challenge=b64u.dec(pk.challenge);
  if(pk.allowCredentials)pk.allowCredentials.forEach(c=>c.id=b64u.dec(c.id));
  const cred=await navigator.credentials.get({publicKey:pk});
  const body={id:cred.id,rawId:b64u.enc(cred.rawId),type:cred.type,response:{
   authenticatorData:b64u.enc(cred.response.authenticatorData),
   clientDataJSON:b64u.enc(cred.response.clientDataJSON),
   signature:b64u.enc(cred.response.signature),
   userHandle:cred.response.userHandle?b64u.enc(cred.response.userHandle):null}};
  const fr=await fetch('/admin/login/finish?ceremonyID='+encodeURIComponent(b.ceremonyID),
   {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!fr.ok)throw new Error(await fr.text());
  window.location=(await fr.json()).redirect;
 }catch(e){msg.textContent='Sign-in failed: '+e.message;}
});
</script></body></html>`))

var dashTmpl = template.Must(template.New("adminmap").Parse(
	webstyle.Head("admin · soulfold") + `<body><main>
<div class="bar">
  ` + brand + `
  <div class="who">signed in as {{.Admin}}
    <form class="inline" method="post" action="/admin/logout"><button class="btn ghost" type="submit">sign out</button></form>
  </div>
</div>
{{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}
{{if .Invite}}<div class="reveal"><span class="k">enrolment link — copy it now, shown once</span><code>{{.Invite}}</code></div>{{end}}

<p class="eyebrow">people <span class="muted">· who exists, and what their tokens carry</span></p>
<div class="tablewrap">
<table>
<thead><tr><th>user</th><th>groups</th><th>passkeys</th><th>status</th><th>actions</th></tr></thead>
<tbody>
{{range .Users}}<tr>
 <td><div class="u-name">{{.Username}}</div>{{if .Display}}<div class="u-sub">{{.Display}}</div>{{end}}</td>
 <td>
   <form class="rowform" method="post" action="/admin/users/{{.Username}}/groups">
     <input type="hidden" name="csrf" value="{{$.CSRF}}">
     <input name="groups" value="{{.Groups}}" size="18" placeholder="none">
     <button class="btn ghost" type="submit">save</button>
   </form>
 </td>
 <td class="count">{{.Credentials}}</td>
 <td>{{if eq .Status "active"}}<span class="pill ok">active</span>{{else}}<span class="pill off">disabled</span>{{end}}</td>
 <td><div class="actions">
   <form class="inline" method="post" action="/admin/users/{{.Username}}/invite">
     <input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="btn ghost" type="submit">invite</button>
   </form>
   <form class="inline" method="post" action="/admin/users/{{.Username}}/status">
     <input type="hidden" name="csrf" value="{{$.CSRF}}">
     <input type="hidden" name="status" value="{{if eq .Status "active"}}disabled{{else}}active{{end}}">
     <button class="btn danger ghost" type="submit">{{if eq .Status "active"}}disable{{else}}enable{{end}}</button>
   </form>
 </div></td>
</tr>{{end}}
</tbody>
</table>
</div>

<div class="grid2">
  <div class="card">
    <h2>Add a person</h2>
    <p class="hint">They sign in only after you send them an invite — the “invite” button mints a single-use enrolment link.</p>
    <form method="post" action="/admin/users" style="margin-top:14px;display:flex;flex-direction:column;gap:12px">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <label class="field">username <input name="username" required></label>
      <label class="field">display name <input name="display_name"></label>
      <label class="field">groups <input name="groups" placeholder="engineering admin"></label>
      <button class="btn" type="submit">Create</button>
    </form>
  </div>
  <div class="card">
    <h2>Groups</h2>
    <p class="hint">Group names surface as the roles claim in every token — they name roles, they never carry permissions.</p>
    <div class="chips" style="margin-top:14px">
      {{if .Groups}}{{range .GroupList}}<span class="chip{{if eq . "admin"}} admin{{end}}">{{.}}</span>{{end}}{{else}}<span class="u-sub">none yet — groups appear when you assign them</span>{{end}}
    </div>
  </div>
</div>

<p class="eyebrow">oauth clients <span class="muted">· applications that sign people in through the fold</span></p>
<div class="tablewrap">
<table>
<thead><tr><th>client</th><th>redirect URIs</th><th></th></tr></thead>
<tbody>
{{range .Clients}}<tr>
 <td><div class="u-name">{{.ClientID}}</div>{{if .Name}}<div class="u-sub">{{.Name}}</div>{{end}}</td>
 <td class="u-sub">{{range .RedirectURIs}}{{.}}<br>{{end}}</td>
 <td><form class="inline" method="post" action="/admin/clients/{{.ClientID}}/delete">
   <input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="btn danger ghost" type="submit">delete</button></form></td>
</tr>{{else}}<tr><td colspan="3" class="u-sub">none registered — hosted MCP clients can register themselves via DCR</td></tr>{{end}}
</tbody>
</table>
</div>
<div class="card" style="margin-top:16px">
  <h2>Register a client</h2>
  <form method="post" action="/admin/clients" style="margin-top:14px;display:flex;flex-wrap:wrap;gap:12px;align-items:end">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label class="field">client id <input name="client_id" required></label>
    <label class="field">name <input name="name"></label>
    <label class="field" style="flex:1;min-width:220px">redirect URIs <input name="redirect_uris" placeholder="https://app.example/cb"></label>
    <button class="btn" type="submit">Register</button>
  </form>
</div>
<p class="foot">soulfold · the door of the soulsystem</p>
</main></body></html>`))
