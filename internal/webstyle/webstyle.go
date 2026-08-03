// Package webstyle is the fold's shared visual language — one dark
// theme for the sign-in, enrolment, and admin surfaces, so they read as
// one product. Tokens descend from the impire.io / soulsystem design
// system (dark world, mono eyebrows, a violet accent with a rose edge
// for the fold — the door). No asset pipeline: it ships as a string
// (constitution III).
package webstyle

// Head returns a <head> for a fold page: charset, viewport, title, and
// the theme. Callers write the <body> markup after it.
func Head(title string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>` + title + `</title>` + CSS + `</head>`
}

// CSS is the theme, a single <style> block.
const CSS = `<style>
:root{
  --bg:#0d1015; --raise:#12161d; --panel:#151a22; --ink:#e7ecf3; --dim:#8a94a6;
  --faint:#5c6577; --line:#232c3b; --a:#a78bfa; --a2:#fb7185; --ok:#2dd4bf;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(680px 380px at 88% -8%,color-mix(in srgb,var(--a) 12%,transparent),transparent 70%),
             radial-gradient(560px 320px at -6% 8%,color-mix(in srgb,var(--a2) 9%,transparent),transparent 70%)}
main{position:relative;z-index:1;max-width:960px;margin:0 auto;padding:34px 26px 90px}
a{color:var(--a);text-underline-offset:3px}
::selection{background:#2b2352}

/* wordmark + top bar */
.brand{display:inline-flex;align-items:center;gap:9px;text-decoration:none;color:var(--ink);letter-spacing:.01em}
.brand b{font-weight:650}
.brand .tag{font:.62rem var(--mono);text-transform:uppercase;letter-spacing:.16em;color:var(--a2);
  border:1px solid color-mix(in srgb,var(--a2) 40%,var(--line));border-radius:999px;padding:2px 8px}
.brand .dot{width:7px;height:7px;border-radius:50%;background:var(--a);box-shadow:0 0 12px 1px color-mix(in srgb,var(--a) 70%,transparent)}
.bar{display:flex;align-items:center;justify-content:space-between;gap:16px;
  padding-bottom:18px;margin-bottom:8px;border-bottom:1px solid var(--line)}
.bar .who{font:.72rem var(--mono);color:var(--faint);display:flex;align-items:center;gap:12px}

.eyebrow{font:.66rem var(--mono);text-transform:uppercase;letter-spacing:.16em;color:var(--dim);margin:34px 0 12px}
.eyebrow .muted{color:var(--faint);letter-spacing:.04em}
h1{font-size:1.7rem;letter-spacing:-.02em;line-height:1.1;margin:0 0 6px;font-weight:700}
.lede{color:var(--dim);margin:0 0 8px;max-width:56ch}

/* flashes */
.flash{margin:16px 0;padding:12px 15px;border:1px solid var(--line);border-left:2px solid var(--a);
  border-radius:9px;background:var(--raise);font-size:.92rem}
.reveal{margin:16px 0;padding:14px 16px;border:1px solid color-mix(in srgb,var(--ok) 45%,var(--line));
  border-radius:10px;background:#0f1a19}
.reveal .k{font:.64rem var(--mono);text-transform:uppercase;letter-spacing:.14em;color:var(--ok);display:block;margin-bottom:8px}
.reveal code{font:.82rem var(--mono);color:var(--ink);word-break:break-all;background:#0b0e13;
  border:1px solid var(--line);border-radius:6px;padding:8px 10px;display:block}

/* cards */
.card{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:14px;background:var(--raise);padding:22px 22px}
.card::before{content:"";position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(360px 160px at 0% 0%,color-mix(in srgb,var(--a) 7%,transparent),transparent 70%)}
.card>*{position:relative}
.card h2{margin:0 0 4px;font-size:1rem}
.card .hint{color:var(--faint);font-size:.86rem;margin:8px 0 0}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:14px 0}

/* table */
.tablewrap{border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--raise)}
table{width:100%;border-collapse:collapse;font-size:.92rem}
thead th{font:.62rem var(--mono);text-transform:uppercase;letter-spacing:.12em;color:var(--faint);
  text-align:left;padding:12px 16px;background:#0f131a;border-bottom:1px solid var(--line)}
tbody td{padding:13px 16px;border-bottom:1px solid #1b2230;vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:#141a23}
.u-name{font-weight:600}
.u-sub{font:.74rem var(--mono);color:var(--faint)}
.count{font:.9rem var(--mono);color:var(--dim)}

/* pills */
.pill{display:inline-block;font:.68rem var(--mono);letter-spacing:.02em;padding:2px 9px;border-radius:999px;
  border:1px solid var(--line);color:var(--dim)}
.pill.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,var(--line));background:color-mix(in srgb,var(--ok) 8%,transparent)}
.pill.off{color:var(--a2);border-color:color-mix(in srgb,var(--a2) 45%,var(--line))}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.chip{font:.7rem var(--mono);padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--dim)}
.chip.admin{color:var(--a);border-color:color-mix(in srgb,var(--a) 45%,var(--line))}

/* inputs + buttons */
label.field{display:flex;flex-direction:column;gap:5px;font:.66rem var(--mono);text-transform:uppercase;letter-spacing:.1em;color:var(--dim)}
input,textarea{background:#0b0e13;border:1px solid var(--line);border-radius:8px;color:var(--ink);
  padding:9px 11px;font:inherit;transition:border-color .15s,box-shadow .15s}
input:focus,textarea:focus{outline:0;border-color:var(--a);box-shadow:0 0 0 3px color-mix(in srgb,var(--a) 18%,transparent)}
input::placeholder{color:var(--faint)}
.btn{font:600 .82rem var(--sans);border:0;border-radius:999px;padding:9px 18px;background:var(--a);color:#0b0e13;
  cursor:pointer;transition:filter .15s,transform .02s}
.btn:hover{filter:brightness(1.07)} .btn:active{transform:translateY(1px)}
.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--dim);padding:6px 13px;font-weight:500}
.btn.ghost:hover{border-color:var(--a);color:var(--ink)}
.btn.danger.ghost:hover{border-color:var(--a2);color:var(--a2)}
form.inline{display:inline}
.rowform{display:flex;gap:6px;align-items:center}
.actions{display:flex;gap:8px;flex-wrap:wrap}

/* the sign-in / enrol centered card */
.center{max-width:420px;margin:14vh auto 0}
.center .card{padding:30px 28px}
.center h1{font-size:1.5rem}
.center form{margin-top:16px;display:flex;flex-direction:column;gap:14px}
.center .btn{align-self:flex-start}
.msg{color:var(--a2);margin:12px 0 0;min-height:1.2em;font-size:.9rem}
.foot{margin-top:26px;font:.7rem var(--mono);color:var(--faint)}

@media(max-width:680px){.grid2{grid-template-columns:1fr}.tablewrap{overflow-x:auto}}
</style>`
