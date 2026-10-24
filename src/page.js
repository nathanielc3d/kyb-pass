// Single-page demo. The holder secret is generated and kept in the browser; only its hash is sent.
export const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KYB Pass: private EU business credentials (Midnight)</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#111;background:#fafafa}
h1{margin-bottom:.2rem}.sub{color:#555;margin-top:0}fieldset{border:1px solid #ccc;border-radius:8px;margin:1rem 0;padding:1rem;background:#fff}
label{display:block;margin:.4rem 0 .1rem;font-weight:600}input,select{width:100%;padding:.45rem;border:1px solid #bbb;border-radius:6px;box-sizing:border-box}
button{margin-top:.8rem;padding:.55rem 1rem;border:0;border-radius:6px;background:#2b2bd6;color:#fff;font-weight:600;cursor:pointer}
pre{background:#111;color:#e6e6e6;padding:1rem;border-radius:8px;overflow:auto;font-size:12.5px;max-height:420px}
.ok{color:#0a7a2f;font-weight:700}.bad{color:#b00020;font-weight:700}.note{font-size:13px;color:#555}
code{background:#eee;padding:0 .25rem;border-radius:4px}
</style></head><body>
<h1>KYB Pass</h1>
<p class="sub">Prove a business counterparty passed EU KYB, without revealing who it is. Issuer demo for a privacy-first credential on <b>Midnight</b>.</p>
<p class="note">Built by an AI agent (Grok Bot) operated by Nathaniel. Open source: <a href="https://github.com/nathanielc3d/kyb-pass">github.com/nathanielc3d/kyb-pass</a>.
Status: the off-chain issuer below is live; the Midnight Compact contract and zero-knowledge presentation are being built in Midnight Buildathon Wave 3.</p>

<fieldset><legend>1. Holder secret (stays in your browser)</legend>
<label>Holder secret</label><input id="secret" readonly>
<label>Holder commitment = SHA-256("kyb-pass/holder|" + secret), the only thing sent to the issuer</label><input id="commit" readonly>
<button id="regen" type="button">New secret</button></fieldset>

<fieldset><legend>2. Get a credential (live EU VIES check)</legend>
<label for="vat">EU VAT number</label><input id="vat" value="FR39356000000">
<label for="iban">IBAN (optional, checked offline, never stored or signed)</label><input id="iban" placeholder="FR76...">
<label for="name">Company name (optional)</label><input id="name" placeholder="La Poste">
<button id="issue" type="button">Run KYB checks and issue</button>
<p id="istatus" class="note"></p></fieldset>

<fieldset><legend>3. Present to a verifier (reference semantics, no ZK yet)</legend>
<label for="policy">Verifier policy</label><select id="policy"></select>
<label for="scope">Scope (e.g. verifier + invoice id). One presentation per scope.</label><input id="scope" value="marketplace-demo:invoice-0001">
<button id="present" type="button">Evaluate</button>
<p id="pstatus"></p></fieldset>

<h3>What the verifier would learn</h3><pre id="pres">(nothing yet)</pre>
<h3>Your credential (keep it private)</h3><pre id="cred">(nothing yet)</pre>
<script>
const $=(id)=>document.getElementById(id);
const hex=(b)=>"0x"+[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const sha=async(s)=>hex(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s)));
let cred=null;
async function regen(){const s=hex(crypto.getRandomValues(new Uint8Array(32)));$("secret").value=s;$("commit").value=await sha("kyb-pass/holder|"+s);}
regen();$("regen").onclick=regen;
fetch("/api/policies").then(r=>r.json()).then(ps=>{for(const p of ps){const o=document.createElement("option");o.value=p.id;o.textContent=p.id+" ("+(p.countries.length>5?"EU":p.countries.join(","))+", "+p.require_decision+(p.require_sepa_iban?", SEPA IBAN":"")+", <= "+p.max_age_days+" days"+(p.disclose_country?", discloses country":"")+")";$("policy").append(o);}});
$("issue").onclick=async()=>{$("istatus").textContent="Checking VIES...";
 const r=await fetch("/api/issue",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({vat:$("vat").value,iban:$("iban").value||undefined,name:$("name").value||undefined,holder_commitment:$("commit").value})});
 const d=await r.json();if(!r.ok){$("istatus").innerHTML='<span class="bad">'+(d.error||r.status)+'</span>';return;}
 cred=d.credential;$("cred").textContent=JSON.stringify(cred,null,2);
 $("istatus").innerHTML='Issued. Decision: <b>'+cred.claims.decision+'</b>. The signed leaf contains no VAT number, name or IBAN.';};
$("present").onclick=async()=>{if(!cred){$("pstatus").textContent="Get a credential first.";return;}
 const pol=$("policy").value;const r=await fetch("/api/evaluate",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({claims:cred.claims,policy:pol})});const d=await r.json();
 const ps=await (await fetch("/api/policies")).json();const p=ps.find(x=>x.id===pol);
 const nul=await sha("kyb-pass/nullifier|"+$("secret").value+"|"+$("scope").value);
 $("pstatus").innerHTML=d.ok?'<span class="ok">Policy satisfied</span>':'<span class="bad">Policy not satisfied: '+d.rules.filter(x=>!x.ok).map(x=>x.rule).join(", ")+'</span>';
 $("pres").textContent=JSON.stringify({kind:"kyb-pass/presentation-reference",zk:false,policy_id:pol,policy_hash:d.policy_hash,scope:$("scope").value,nullifier:nul,satisfied:d.ok,disclosed:p.disclose_country?{country:cred.claims.country}:{}},null,2);};
</script></body></html>`;
