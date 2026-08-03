package adminui

import "html/template"

// The console's two server-rendered pages. The style is inline and
// minimal — the fold ships no asset pipeline (constitution III). The
// login page carries the one script the console needs: the WebAuthn
// assertion (D9's stated exception).

const style = `<style>
:root{color-scheme:dark}
body{margin:0;background:#0d1015;color:#dfe5ee;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:1.5rem;letter-spacing:-.02em;margin:0 0 4px}
h2{font-size:.72rem;text-transform:uppercase;letter-spacing:.14em;color:#8a94a6;margin:38px 0 12px}
a{color:#a78bfa}
.top{display:flex;align-items:baseline;justify-content:space-between;gap:16px;border-bottom:1px solid #232c3b;padding-bottom:14px}
.top .who{font:.72rem ui-monospace,Menlo,monospace;color:#5c6577}
.flash{margin:16px 0;padding:12px 14px;border:1px solid #232c3b;border-left:2px solid #a78bfa;border-radius:8px;background:#12161d;color:#dfe5ee;font-size:.9rem}
.invite{margin:16px 0;padding:12px 14px;border:1px solid #2dd4bf55;border-radius:8px;background:#0f1a19;font-size:.9rem;word-break:break-all}
.invite code{color:#2dd4bf}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #1b2230;vertical-align:top}
th{font:.68rem ui-monospace,Menlo,monospace;text-transform:uppercase;letter-spacing:.1em;color:#5c6577}
td .mono{font:.82rem ui-monospace,Menlo,monospace;color:#8a94a6}
.pill{display:inline-block;font:.7rem ui-monospace,Menlo,monospace;padding:1px 7px;border-radius:999px;border:1px solid #232c3b;color:#8a94a6}
.pill.active{color:#2dd4bf;border-color:#2dd4bf55}
.pill.disabled{color:#fb7185;border-color:#fb718555}
form.inline{display:inline}
input,button,textarea{font:inherit}
input,textarea{background:#0b0e13;border:1px solid #232c3b;border-radius:6px;color:#dfe5ee;padding:6px 9px}
button{background:#a78bfa;color:#0b0e13;border:0;border-radius:6px;padding:6px 12px;font-weight:600;cursor:pointer}
button.ghost{background:transparent;border:1px solid #232c3b;color:#8a94a6;font-weight:400}
.card{border:1px solid #232c3b;border-radius:10px;background:#12161d;padding:18px 18px;margin:14px 0}
.card h3{margin:0 0 12px;font-size:.95rem}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
.row label{display:flex;flex-direction:column;gap:4px;font:.7rem ui-monospace,Menlo,monospace;color:#8a94a6}
.msg{color:#fb7185;margin:12px 0}
.center{max-width:400px;margin:12vh auto;text-align:center}
</style>`

var loginTmpl = template.Must(template.New("adminlogin").Parse(`<!doctype html>
<meta charset="utf-8"><title>admin · soulfold</title>` + style + `
<main><div class="center">
<h1>soulfold admin</h1>
<p style="color:#8a94a6">Sign in with the passkey of an administrator.</p>
<form id="f" class="row" style="justify-content:center">
<label>Username <input id="username" autocomplete="username webauthn" autofocus required></label>
<button type="submit">Sign in</button>
</form>
<p id="msg" class="msg"></p>
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
</script>`))

var dashTmpl = template.Must(template.New("adminmap").Parse(`<!doctype html>
<meta charset="utf-8"><title>admin · soulfold</title>` + style + `
<main>
<div class="top">
  <div><h1>soulfold admin</h1></div>
  <div class="who">signed in as {{.Admin}} ·
    <form class="inline" method="post" action="/admin/logout"><button class="ghost" type="submit">sign out</button></form>
  </div>
</div>
{{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}
{{if .Invite}}<div class="invite">enrollment link — copy it now, it is shown once:<br><code>{{.Invite}}</code></div>{{end}}

<h2>People</h2>
<table>
<tr><th>user</th><th>groups</th><th>passkeys</th><th>status</th><th>actions</th></tr>
{{range .Users}}<tr>
 <td>{{.Username}}{{if .Display}}<div class="mono">{{.Display}}</div>{{end}}</td>
 <td>
   <form class="inline" method="post" action="/admin/users/{{.Username}}/groups">
     <input type="hidden" name="csrf" value="{{$.CSRF}}">
     <input name="groups" value="{{.Groups}}" size="20" placeholder="none">
     <button class="ghost" type="submit">save</button>
   </form>
 </td>
 <td class="mono">{{.Credentials}}</td>
 <td>{{if eq .Status "active"}}<span class="pill active">active</span>{{else}}<span class="pill disabled">disabled</span>{{end}}</td>
 <td>
   <form class="inline" method="post" action="/admin/users/{{.Username}}/invite">
     <input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="ghost" type="submit">invite</button>
   </form>
   <form class="inline" method="post" action="/admin/users/{{.Username}}/status">
     <input type="hidden" name="csrf" value="{{$.CSRF}}">
     <input type="hidden" name="status" value="{{if eq .Status "active"}}disabled{{else}}active{{end}}">
     <button class="ghost" type="submit">{{if eq .Status "active"}}disable{{else}}enable{{end}}</button>
   </form>
 </td>
</tr>{{end}}
</table>

<div class="card">
  <h3>Add a person</h3>
  <form class="row" method="post" action="/admin/users">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label>username <input name="username" required></label>
    <label>display name <input name="display_name"></label>
    <label>groups <input name="groups" placeholder="engineering admin"></label>
    <button type="submit">Create</button>
  </form>
  <p class="mono" style="color:#5c6577;margin:10px 0 0">They sign in only after you send them an invite — the “invite” button mints a single-use enrolment link.</p>
</div>

<h2>Groups <span class="mono" style="color:#5c6577">(names surface as token roles)</span></h2>
<p class="mono" style="color:#8a94a6">{{if .Groups}}{{.Groups}}{{else}}none yet — groups appear when you assign them{{end}}</p>

<h2>OAuth clients</h2>
<table>
<tr><th>client</th><th>redirect URIs</th><th></th></tr>
{{range .Clients}}<tr>
 <td>{{.ClientID}}{{if .Name}}<div class="mono">{{.Name}}</div>{{end}}</td>
 <td class="mono">{{range .RedirectURIs}}{{.}}<br>{{end}}</td>
 <td><form class="inline" method="post" action="/admin/clients/{{.ClientID}}/delete">
   <input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="ghost" type="submit">delete</button></form></td>
</tr>{{end}}
</table>
<div class="card">
  <h3>Register a client</h3>
  <form class="row" method="post" action="/admin/clients">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label>client id <input name="client_id" required></label>
    <label>name <input name="name"></label>
    <label>redirect URIs <input name="redirect_uris" size="30" placeholder="https://app/cb"></label>
    <button type="submit">Register</button>
  </form>
</div>
</main>`))
