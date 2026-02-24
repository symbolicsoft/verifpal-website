/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

import init, {
	wasm_verify,
	wasm_pretty
} from "/res/wasm/verifpal.js";

// ── Examples ────────────────────────────────────────────────────────────────

const EXAMPLES = {
	"simple": `// Simple Diffie-Hellman with AEAD
attacker[active]

principal Alice[
\tknows public c0
\tgenerates a
\tga = G^a
]

Alice -> Bob: ga

principal Bob[
\tknows public c0
\tgenerates m1, b
\tgb = G^b
\tgab = ga^b
\te1 = AEAD_ENC(gab, m1, c0)
]

Bob -> Alice: gb, e1

principal Alice[
\tgba = gb^a
\te1_dec = AEAD_DEC(gba, e1, c0)?
]

queries[
\tconfidentiality? m1
\tauthentication? Bob -> Alice: e1
]`,

	"trivial": `// Trivial model (minimal)
attacker[active]
principal Alice[ generates e ]
Alice -> Bob: e
principal Bob[ H = HASH(e) ]

queries[
\tconfidentiality? e
\tauthentication? Alice -> Bob: e
]`,

	"challenge-response": `// Challenge-Response Authentication
attacker[active]

principal Server[
\tknows private s
\tgs = G^s
]

principal Client[
\tknows private c
\tgc = G^c
\tgenerates nonce
]

Client -> Server: nonce

principal Server[
\tproof = SIGN(s, nonce)
]

Server -> Client: [gs], proof

principal Client[
\tvalid = SIGNVERIF(gs, nonce, proof)?
\tgenerates attestation
\tsigned = SIGN(c, attestation)
]

Client -> Server: gc, attestation, signed

principal Server[
\tstorage = SIGNVERIF(gc, attestation, signed)?
]

queries[
\tauthentication? Server -> Client: proof
\tauthentication? Client -> Server: signed
]`,

	"signal": `// Signal Protocol (simplified)
attacker[active]

principal Alice[
\tknows private alongterm
\tgalongterm = G^alongterm
]

principal Bob[
\tknows private blongterm, bs
\tgenerates bo
\tgblongterm = G^blongterm
\tgbs = G^bs
\tgbo = G^bo
\tgbssig = SIGN(blongterm, gbs)
]

Bob -> Alice: [gblongterm], gbssig, gbs, gbo

principal Alice[
\tgenerates ae1
\tgae1 = G^ae1
\tamaster = HASH(gbs^alongterm, gblongterm^ae1, gbs^ae1, gbo^ae1)
\tarkba1, ackba1 = HKDF(amaster, nil, nil)
]

principal Alice[
\tgenerates m1, ae2
\tgae2 = G^ae2
\tvalid = SIGNVERIF(gblongterm, gbs, gbssig)?
\takshared1 = gbs^ae2
\tarkab1, ackab1 = HKDF(akshared1, arkba1, nil)
\takenc1, akenc2 = HKDF(MAC(ackab1, nil), nil, nil)
\te1 = AEAD_ENC(akenc1, m1, HASH(galongterm, gblongterm, gae2))
]

Alice -> Bob: [galongterm], gae1, gae2, e1

principal Bob[
\tbmaster = HASH(galongterm^bs, gae1^blongterm, gae1^bs, gae1^bo)
\tbrkba1, bckba1 = HKDF(bmaster, nil, nil)
]

principal Bob[
\tbkshared1 = gae2^bs
\tbrkab1, bckab1 = HKDF(bkshared1, brkba1, nil)
\tbkenc1, bkenc2 = HKDF(MAC(bckab1, nil), nil, nil)
\tm1_d = AEAD_DEC(bkenc1, e1, HASH(galongterm, gblongterm, gae2))
]

phase[1]

principal Alice[leaks alongterm]
principal Bob[leaks blongterm]

queries[
\tconfidentiality? m1
\tauthentication? Alice -> Bob: e1
]`,

	"needham-schroeder": `// Needham-Schroeder Symmetric Key Protocol
attacker[active]

principal Alice[
\tknows private A
\tknows private B
\tknows private k_as
\tgenerates n_a
]

principal Bob[
\tknows private B
\tknows private k_bs
\tgenerates n_b
]

principal Server[
\tknows private k_as
\tknows private k_bs
]

principal Carol[]

Alice -> Server: A, B, n_a

principal Server[
\tgenerates k_ab
\te_bob = AEAD_ENC(k_bs, CONCAT(k_ab, A), nil)
\te_alice = AEAD_ENC(k_as, CONCAT(n_a, k_ab, B, e_bob), nil)
]

Server -> Alice: [e_alice]

principal Alice[
\te_alice_dec = AEAD_DEC(k_as, e_alice, nil)
\tn_a_response, k_ab_alice, B_alice, e_bob_alice = SPLIT(e_alice_dec)
\t_ = ASSERT(n_a, n_a_response)?
]

Alice -> Bob: e_bob_alice

principal Bob[
\te_bob_dec = AEAD_DEC(k_bs, e_bob_alice, nil)
\tk_ab_bob, A_bob = SPLIT(e_bob_dec)
\te_n_b = AEAD_ENC(k_ab_bob, n_b, nil)
]

Bob -> Alice: e_n_b

principal Alice[
\tn_b_alice = AEAD_DEC(k_ab_alice, e_n_b, nil)
\tn_b_minus_one = HASH(n_b_alice)
\te_n_b_minus_one = AEAD_ENC(k_ab_alice, n_b_minus_one, nil)
]

Alice -> Bob: e_n_b_minus_one

principal Bob[
\tn_b_minus_one_bob = AEAD_DEC(k_ab_bob, e_n_b_minus_one, nil)
\t_ = ASSERT(n_b_minus_one_bob, HASH(n_b))?
]

phase[1]

principal Server[
\tleaks k_ab
]

queries[
\tconfidentiality? k_ab
\tconfidentiality? n_b
\tauthentication? Alice -> Bob: e_bob_alice
\tauthentication? Alice -> Bob: e_n_b_minus_one
\tauthentication? Bob -> Alice: e_n_b
]`,

	"pke": `// Public Key Encryption with MAC
attacker[active]

principal Alice[
\tgenerates a
\tga = G^a
]

principal Bob[
\tgenerates b
\tgb = G^b
]

Alice -> Bob: [ga]
Bob -> Alice: [gb]

principal Alice[
\tgenerates m
\te = PKE_ENC(gb, m)
\th = MAC(gb^a, e)
]

Alice -> Bob: e, h

principal Bob[
\t_ = ASSERT(MAC(ga^b, e), h)?
\td = PKE_DEC(b, e)
]

queries[
\tconfidentiality? m
\tauthentication? Alice -> Bob: e
]`,

	"signature": `// Digital Signature with Encryption
attacker[active]

principal Alice[
\tknows public hmac_key
\tknows private key
\tknows private sk
\tpk = G^sk
]

principal Bob[
\tknows private key
]

Alice -> Bob: [pk]

principal Alice[
\tgenerates plaintext
\tciphertext = ENC(key, plaintext)
\tsignature = SIGN(sk, ciphertext)
]

Alice -> Bob: signature, ciphertext

principal Bob[
\tvrf = SIGNVERIF(pk, ciphertext, signature)?
\tplaintext_ = DEC(key, ciphertext)
]

queries[
\tconfidentiality? plaintext
\tauthentication? Alice -> Bob: ciphertext
\tauthentication? Alice -> Bob: signature
]`,

	"blind-signature": `// Blind Signature Protocol
attacker[active]

principal Signer[
\tknows private sk
\tgsk = G^sk
]

Signer -> Alice: [gsk]

principal Alice[
\tgenerates msg, blind_factor
\tblinded = BLIND(blind_factor, msg)
]

Alice -> Signer: blinded

principal Signer[
\tblind_sig = SIGN(sk, blinded)
]

Signer -> Alice: blind_sig

principal Alice[
\tsig = UNBLIND(blind_factor, blinded, blind_sig)
]

queries[
\tconfidentiality? msg
\tconfidentiality? blind_factor
\tauthentication? Signer -> Alice: blind_sig
]`,

	"shamir": `// Shamir Secret Sharing
attacker[active]

principal Bob[]
principal Alice[
\tgenerates k
\tgenerates m
\ts1, s2, s3 = SHAMIR_SPLIT(k)
\te = AEAD_ENC(k, m, nil)
]

Alice -> Bob: e, s1, s2

principal Bob[
\tkk = SHAMIR_JOIN(s1, s2)
\td = AEAD_DEC(kk, e, nil)?
]

queries[
\tconfidentiality? m
]`,

	"saltchannel": `// Salt Channel Protocol
attacker[active]

principal Server[
\tknows private s
\tgs = G^s
]

principal Client[
\tknows private c
\tgc = G^c
\tgenerates ec
\tm1 = G^ec
]

Client -> Server: m1

principal Server[
\tgenerates es
\tm2 = G^es
\tshared_s = m1^es
\tm3a = AEAD_ENC(shared_s, gs, nil)
\tm3b = AEAD_ENC(shared_s, SIGN(s, HASH(m1, m2)), nil)
]

Server -> Client: m2, m3a, m3b

principal Client[
\tshared_c = m2^ec
\tgs_dec = AEAD_DEC(shared_c, m3a, nil)
\tm3b_dec = AEAD_DEC(shared_c, m3b, nil)
\tvalid_c = SIGNVERIF(gs_dec, HASH(m1, m2), m3b_dec)?
\tm4a = AEAD_ENC(shared_c, gc, nil)
\tknows private pt1
\treq = AEAD_ENC(shared_c, pt1, nil)
]

Client -> Server: [m4a], [req]

queries[
\tconfidentiality? pt1
]`,

	"double-ratchet": `// Simplified Double Ratchet
attacker[active]

principal Alice[
\tknows private a_id
\tga_id = G^a_id
\tgenerates a_eph0
\tga_eph0 = G^a_eph0
]

principal Bob[
\tknows private b_id
\tgb_id = G^b_id
\tgenerates b_eph0
\tgb_eph0 = G^b_eph0
]

Alice -> Bob: [ga_id], [ga_eph0]
Bob -> Alice: [gb_id], [gb_eph0]

principal Alice[
\tdh_root = HASH(gb_id^a_id, gb_eph0^a_eph0)
\trk1, ck_a1 = HKDF(dh_root, nil, nil)
\tmk_a1, _ = HKDF(ck_a1, nil, nil)
\tgenerates msg1
\te1 = AEAD_ENC(mk_a1, msg1, ga_eph0)
]

Alice -> Bob: e1

principal Bob[
\tdh_root_b = HASH(ga_id^b_id, ga_eph0^b_eph0)
\trk1_b, ck_b1 = HKDF(dh_root_b, nil, nil)
\tmk_b1, _ = HKDF(ck_b1, nil, nil)
\tmsg1_b = AEAD_DEC(mk_b1, e1, ga_eph0)?
\tgenerates b_eph1
\tgb_eph1 = G^b_eph1
\trk2_b, ck_b2 = HKDF(rk1_b, HASH(ga_eph0^b_eph1), nil)
\tmk_b2, _ = HKDF(ck_b2, nil, nil)
\tgenerates msg2
\te2 = AEAD_ENC(mk_b2, msg2, gb_eph1)
]

Bob -> Alice: [gb_eph1], e2

principal Alice[
\trk2, ck_a2 = HKDF(rk1, HASH(gb_eph1^a_eph0), nil)
\tmk_a2, _ = HKDF(ck_a2, nil, nil)
\tmsg2_a = AEAD_DEC(mk_a2, e2, gb_eph1)?
]

queries[
\tconfidentiality? msg1
\tconfidentiality? msg2
\tauthentication? Alice -> Bob: e1
\tauthentication? Bob -> Alice: e2
\tequivalence? msg1, msg1_b
\tequivalence? msg2, msg2_a
]`,

	"ok": `// AEAD with Diffie-Hellman Key Exchange
attacker[active]

principal Alice[
\tknows private a
\ta_public = G^a
]
principal Bob[
\tknows private b
\tb_public = G^b
]

Alice -> Bob: [a_public]
Bob -> Alice: [b_public]

principal Alice[
\tgenerates plaintext
\tgenerates ad
\tss = b_public^a
\tkey = HASH(ss)
\tciphertext = AEAD_ENC(key, plaintext, ad)
]

Alice -> Bob: ad, ciphertext

principal Bob[
\tss_ = a_public^b
\tkey_ = HASH(ss_)
\tplaintext_ = AEAD_DEC(key_, ciphertext, ad)?
]

queries[
\tconfidentiality? plaintext
\tauthentication? Alice -> Bob: ciphertext
\tauthentication? Alice -> Bob: ad
]`
};

// ── Syntax Highlighting ─────────────────────────────────────────────────────

const VP_KEYWORDS = new Set([
	"principal", "phase", "queries", "attacker"
]);
const VP_QUERY_KEYWORDS = new Set([
	"confidentiality", "authentication", "freshness",
	"unlinkability", "equivalence", "precondition"
]);
const VP_LITERALS = new Set([
	"knows", "generates", "leaks"
]);
const VP_BUILTINS = new Set([
	"UNBLIND", "BLIND", "RINGSIGNVERIF", "RINGSIGN",
	"PW_HASH", "HASH", "HKDF", "AEAD_ENC", "AEAD_DEC",
	"ENC", "DEC", "ASSERT", "CONCAT", "SPLIT", "MAC",
	"SIGNVERIF", "SIGN", "PKE_ENC", "PKE_DEC",
	"SHAMIR_SPLIT", "SHAMIR_JOIN", "G", "nil",
	"active", "passive", "public", "private", "password"
]);

function highlightVerifpal(src) {
	let out = "";
	let i = 0;
	const n = src.length;
	while (i < n) {
		// Comments
		if (src[i] === "/" && i + 1 < n && src[i + 1] === "/") {
			let end = src.indexOf("\n", i);
			if (end === -1) end = n;
			out += '<span class="vp-comment">' + esc(src.slice(i, end)) + "</span>";
			i = end;
			continue;
		}
		// Arrow ->
		if (src[i] === "-" && i + 1 < n && src[i + 1] === ">") {
			out += '<span class="vp-arrow">-&gt;</span>';
			i += 2;
			continue;
		}
		// Guard brackets [...]
		if (src[i] === "[") {
			// Check if this is a guard: preceded by a space/comma and followed by identifier + ]
			const closeIdx = src.indexOf("]", i + 1);
			if (closeIdx !== -1) {
				const inner = src.slice(i + 1, closeIdx);
				// Guard constants look like [name] in message lines
				if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(inner) && i > 0 && /[: ,]/.test(src[i - 1])) {
					out += '<span class="vp-guard">[' + esc(inner) + "]</span>";
					i = closeIdx + 1;
					continue;
				}
			}
			out += esc(src[i]);
			i++;
			continue;
		}
		// Operators = ^ ? !
		if ("=^?".includes(src[i])) {
			out += '<span class="vp-operator">' + esc(src[i]) + "</span>";
			i++;
			continue;
		}
		// Words
		if (/[a-zA-Z_]/.test(src[i])) {
			let end = i + 1;
			while (end < n && /[a-zA-Z0-9_]/.test(src[end])) end++;
			const word = src.slice(i, end);
			// Check if followed by ? (query keyword)
			if (end < n && src[end] === "?" && VP_QUERY_KEYWORDS.has(word)) {
				out += '<span class="vp-query">' + esc(word) + "?</span>";
				i = end + 1;
				continue;
			}
			if (VP_KEYWORDS.has(word)) {
				out += '<span class="vp-keyword">' + esc(word) + "</span>";
			} else if (VP_LITERALS.has(word)) {
				out += '<span class="vp-literal">' + esc(word) + "</span>";
			} else if (VP_BUILTINS.has(word)) {
				out += '<span class="vp-builtin">' + esc(word) + "</span>";
			} else {
				out += esc(word);
			}
			i = end;
			continue;
		}
		out += esc(src[i]);
		i++;
	}
	return out;
}

function esc(s) {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ── Protocol Diagram Generator ──────────────────────────────────────────────

function parseDiagramData(src) {
	const principals = [];
	const principalSet = new Set();
	const events = []; // {type: "message"|"note"|"phase"}
	const lines = src.split("\n");
	let i = 0;

	// State machine: track whether we're inside a block and which kind
	// "principal" | "queries" | "attacker" | null
	let insideBlock = null;
	let bracketDepth = 0;
	let currentPrincipal = null;
	let currentExprs = [];

	function flushPrincipalNote() {
		if (currentPrincipal && currentExprs.length > 0) {
			events.push({
				type: "note",
				principal: currentPrincipal,
				lines: currentExprs
			});
		}
		currentPrincipal = null;
		currentExprs = [];
	}

	while (i < lines.length) {
		const rawLine = lines[i];
		const line = rawLine.trim();
		i++;

		if (!line || line.startsWith("//")) continue;

		// If we're inside a queries or attacker block, just track brackets and skip
		if (insideBlock === "queries" || insideBlock === "attacker") {
			for (const ch of line) {
				if (ch === "[") bracketDepth++;
				if (ch === "]") bracketDepth--;
			}
			if (bracketDepth <= 0) {
				insideBlock = null;
				bracketDepth = 0;
			}
			continue;
		}

		// If we're inside a principal block, collect expressions
		if (insideBlock === "principal") {
			for (const ch of line) {
				if (ch === "[") bracketDepth++;
				if (ch === "]") bracketDepth--;
			}
			if (bracketDepth <= 0) {
				// Block ended — collect any expression on the closing line before ]
				const beforeClose = line.replace(/\]$/, "").trim();
				if (beforeClose && beforeClose !== "]") {
					currentExprs.push(beforeClose);
				}
				flushPrincipalNote();
				insideBlock = null;
				bracketDepth = 0;
			} else {
				// Expression inside block
				if (line !== "]" && line !== "[") {
					currentExprs.push(line);
				}
			}
			continue;
		}

		// Top-level parsing

		// queries[...] block — skip entirely
		if (/^queries\s*\[/.test(line)) {
			insideBlock = "queries";
			bracketDepth = 0;
			for (const ch of line) {
				if (ch === "[") bracketDepth++;
				if (ch === "]") bracketDepth--;
			}
			if (bracketDepth <= 0) {
				insideBlock = null;
				bracketDepth = 0;
			}
			continue;
		}

		// attacker[...] — skip
		if (/^attacker\s*\[/.test(line)) {
			insideBlock = "attacker";
			bracketDepth = 0;
			for (const ch of line) {
				if (ch === "[") bracketDepth++;
				if (ch === "]") bracketDepth--;
			}
			if (bracketDepth <= 0) {
				insideBlock = null;
				bracketDepth = 0;
			}
			continue;
		}

		// Message: Alice -> Bob: x, y, z
		const msgMatch = line.match(/^([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*:\s*(.+)$/);
		if (msgMatch) {
			const [, sender, recipient, constants] = msgMatch;
			if (!principalSet.has(sender)) {
				principals.push(sender);
				principalSet.add(sender);
			}
			if (!principalSet.has(recipient)) {
				principals.push(recipient);
				principalSet.add(recipient);
			}
			events.push({
				type: "message",
				sender,
				recipient,
				label: constants.trim()
			});
			continue;
		}

		// Phase
		const phaseMatch = line.match(/^phase\s*\[\s*(\d+)\s*\]/);
		if (phaseMatch) {
			events.push({
				type: "phase",
				number: parseInt(phaseMatch[1])
			});
			continue;
		}

		// Principal block start
		const principalMatch = line.match(/^principal\s+([A-Za-z_]\w*)\s*\[/);
		if (principalMatch) {
			const name = principalMatch[1];
			if (!principalSet.has(name)) {
				principals.push(name);
				principalSet.add(name);
			}

			// Count brackets on this line
			bracketDepth = 0;
			for (const ch of line) {
				if (ch === "[") bracketDepth++;
				if (ch === "]") bracketDepth--;
			}

			currentPrincipal = name;
			currentExprs = [];

			// Extract expressions from the rest of this line (after the first [)
			const afterBracket = line.slice(line.indexOf("[") + 1).trim();
			if (bracketDepth <= 0) {
				// Single-line block like: principal Alice[ generates e ]
				const content = afterBracket.replace(/\]$/, "").trim();
				if (content) {
					// May contain multiple expressions separated by newlines (won't happen in single line)
					// but could have a single expression
					currentExprs.push(content);
				}
				flushPrincipalNote();
				bracketDepth = 0;
			} else {
				// Multi-line block
				if (afterBracket && afterBracket !== "]") {
					currentExprs.push(afterBracket);
				}
				insideBlock = "principal";
			}
			continue;
		}
	}

	return {
		principals,
		events
	};
}

function renderDiagram(src) {
	const {
		principals,
		events
	} = parseDiagramData(src);
	if (principals.length === 0) return '<div class="resultPlaceholder">No principals found in model.</div>';

	// Coordinate system: design at 2x, display at 1x via viewBox scaling
	const COL = 220;
	const MSG_LABEL_H = 16; // space for label text above arrow
	const MSG_ARROW_H = 14; // space for arrow line + gap below
	const MSG_H = MSG_LABEL_H + MSG_ARROW_H;
	const HDR_H = 28;
	const PAD_T = 12;
	const NLH = 14;
	const NPY = 6;
	const NGAP = 4;
	const CW = 7;
	const MC = 36;
	const PH_H = 24;

	const vbW = principals.length * COL;
	const cx = (i) => i * COL + COL / 2;

	let vbH = PAD_T + HDR_H + 14;
	for (const ev of events) {
		if (ev.type === "message") vbH += MSG_H;
		else if (ev.type === "note") vbH += NPY + ev.lines.length * NLH + NPY + NGAP;
		else if (ev.type === "phase") vbH += PH_H;
	}
	vbH += 16;

	// Display size: half the viewBox so text renders crisp but compact
	const dispW = Math.round(vbW / 2);
	const dispH = Math.round(vbH / 2);

	let s = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${vbW} ${vbH}" width="${dispW}" height="${dispH}">`;
	s += `<defs><marker id="ah" markerWidth="7" markerHeight="5" refX="7" refY="2.5" orient="auto"><path d="M0,0 L7,2.5 L0,5Z" fill="#888"/></marker></defs>`;

	for (let j = 0; j < principals.length; j++)
		s += `<line class="lifeline" x1="${cx(j)}" y1="${PAD_T + HDR_H}" x2="${cx(j)}" y2="${vbH - 6}"/>`;

	for (let j = 0; j < principals.length; j++) {
		const x = cx(j),
			bw = Math.min(COL - 20, principals[j].length * 11 + 28);
		s += `<rect class="principalBox" x="${x - bw / 2}" y="${PAD_T}" width="${bw}" height="${HDR_H - 4}"/>`;
		s += `<text class="principalLabel" x="${x}" y="${PAD_T + HDR_H / 2}" text-anchor="middle" dominant-baseline="middle">${escSvg(principals[j])}</text>`;
	}

	let y = PAD_T + HDR_H + 14;
	for (const ev of events) {
		if (ev.type === "message") {
			const si = principals.indexOf(ev.sender),
				ri = principals.indexOf(ev.recipient);
			if (si < 0 || ri < 0) {
				y += MSG_H;
				continue;
			}
			const x1 = cx(si),
				x2 = cx(ri),
				dx = x2 - x1,
				ad = Math.abs(dx);
			const r = ad > 0 ? 3 / ad : 0;
			y += MSG_LABEL_H;
			const mc = Math.max(Math.floor(ad / CW) - 2, 8);
			const lb = ev.label.length > mc ? ev.label.slice(0, mc - 1) + "\u2026" : ev.label;
			s += `<text class="msgLabel" x="${(x1 + x2) / 2}" y="${y - 4}" text-anchor="middle">${escSvg(lb)}</text>`;
			s += `<line class="msgArrow" x1="${x1 + dx * r}" y1="${y}" x2="${x2 - dx * r}" y2="${y}" marker-end="url(#ah)"/>`;
			y += MSG_ARROW_H;
		} else if (ev.type === "note") {
			const pi = principals.indexOf(ev.principal);
			if (pi < 0) continue;
			const x = cx(pi);
			const nh = NPY + ev.lines.length * NLH + NPY;
			const maxNW = COL - 12;
			const maxChars = Math.floor((maxNW - 16) / CW);
			const ml = Math.max(...ev.lines.map(l => Math.min(l.length, maxChars)));
			const nw = Math.min(Math.max(ml * CW + 16, 50), maxNW);
			s += `<rect class="noteBox" x="${x - nw / 2}" y="${y}" width="${nw}" height="${nh}"/>`;
			for (let li = 0; li < ev.lines.length; li++) {
				const lb = ev.lines[li].length > maxChars ? ev.lines[li].slice(0, maxChars - 1) + "\u2026" : ev.lines[li];
				s += `<text class="noteText" x="${x}" y="${y + NPY + (li + 1) * NLH - 3}" text-anchor="middle">${escSvg(lb)}</text>`;
			}
			y += nh + NGAP;
		} else if (ev.type === "phase") {
			const px1 = cx(0) - COL / 2 + 8,
				px2 = cx(principals.length - 1) + COL / 2 - 8;
			s += `<line class="phaseLine" x1="${px1}" y1="${y}" x2="${px2}" y2="${y}"/>`;
			s += `<text class="phaseLabel" x="${px1 + 4}" y="${y - 5}">phase[${ev.number}]</text>`;
			y += PH_H;
		}
	}
	s += "</svg>";
	return '<div class="diagramWrap">' + s + "</div>";
}

function escSvg(s) {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── Workbench App ───────────────────────────────────────────────────────────

let wasmReady = false;
let editorEl, highlightEl, resultsDiv, exampleSelect, verifyBtn, prettyBtn, diagramBtn, statusLabel;
let showingDiagram = false;

function syncHighlight() {
	highlightEl.innerHTML = highlightVerifpal(editorEl.value) + "\n";
	// Sync scroll
	const pre = highlightEl.parentElement;
	pre.scrollTop = editorEl.scrollTop;
	pre.scrollLeft = editorEl.scrollLeft;
}

async function initWorkbench() {
	editorEl = document.getElementById("editor");
	highlightEl = document.getElementById("highlightCode");
	resultsDiv = document.getElementById("results");
	exampleSelect = document.getElementById("exampleSelect");
	verifyBtn = document.getElementById("verifyBtn");
	prettyBtn = document.getElementById("prettyBtn");
	diagramBtn = document.getElementById("diagramBtn");
	statusLabel = document.getElementById("statusLabel");

	exampleSelect.addEventListener("change", () => {
		const name = exampleSelect.value;
		if (name && EXAMPLES[name]) {
			editorEl.value = EXAMPLES[name];
			syncHighlight();
			if (showingDiagram) {
				showDiagram();
			} else {
				resultsDiv.innerHTML = '<div class="resultPlaceholder">Click "Verify" to analyze this model.</div>';
			}
		}
	});

	verifyBtn.addEventListener("click", runVerify);
	prettyBtn.addEventListener("click", runPretty);
	diagramBtn.addEventListener("click", showDiagram);

	// Syntax highlight on input
	editorEl.addEventListener("input", syncHighlight);
	editorEl.addEventListener("scroll", () => {
		const pre = highlightEl.parentElement;
		pre.scrollTop = editorEl.scrollTop;
		pre.scrollLeft = editorEl.scrollLeft;
	});

	// Handle tab key in textarea
	editorEl.addEventListener("keydown", (e) => {
		if (e.key === "Tab") {
			e.preventDefault();
			const start = editorEl.selectionStart;
			const end = editorEl.selectionEnd;
			editorEl.value = editorEl.value.substring(0, start) + "\t" + editorEl.value.substring(end);
			editorEl.selectionStart = editorEl.selectionEnd = start + 1;
			syncHighlight();
		}
	});

	statusLabel.textContent = "Loading WASM...";
	verifyBtn.disabled = true;
	prettyBtn.disabled = true;
	diagramBtn.disabled = true;

	try {
		await init();
		wasmReady = true;
		statusLabel.textContent = "Ready";
		verifyBtn.disabled = false;
		prettyBtn.disabled = false;
		diagramBtn.disabled = false;
	} catch (e) {
		statusLabel.textContent = "WASM failed to load";
		diagramBtn.disabled = false; // Diagram works without WASM
		resultsDiv.innerHTML = '<div class="resultError">Failed to load WASM module: ' + escapeHtml(e.message) + "</div>";
	}

	// Load default example
	editorEl.value = EXAMPLES["simple"];
	syncHighlight();
}

function runVerify() {
	if (!wasmReady) return;
	showingDiagram = false;
	resultsDiv.innerHTML = '<div class="resultLoading">Verifying...</div>';
	verifyBtn.disabled = true;
	prettyBtn.disabled = true;

	setTimeout(() => {
		try {
			const raw = wasm_verify(editorEl.value);
			const result = JSON.parse(raw);
			renderResults(result);
		} catch (e) {
			resultsDiv.innerHTML = '<div class="resultError">Error: ' + escapeHtml(e.message) + "</div>";
		}
		verifyBtn.disabled = false;
		prettyBtn.disabled = false;
	}, 10);
}

function runPretty() {
	if (!wasmReady) return;
	try {
		const raw = wasm_pretty(editorEl.value);
		const result = JSON.parse(raw);
		if (result.ok) {
			editorEl.value = result.output;
			syncHighlight();
		} else {
			resultsDiv.innerHTML = '<div class="resultError">' + escapeHtml(result.error) + "</div>";
		}
	} catch (e) {
		resultsDiv.innerHTML = '<div class="resultError">Error: ' + escapeHtml(e.message) + "</div>";
	}
}

function showDiagram() {
	showingDiagram = true;
	const backBtn = '<button class="diagramBackBtn" onclick="document.getElementById(\'results\').innerHTML=\'<div class=resultPlaceholder>Click Verify to analyze this model.</div>\'">&larr; Back to results</button>';
	resultsDiv.innerHTML = backBtn + renderDiagram(editorEl.value);
}

function renderResults(result) {
	showingDiagram = false;
	let html = "";

	if (!result.ok) {
		html = '<div class="resultError">' + escapeHtml(result.error) + "</div>";
		if (result.messages && result.messages.length > 0) {
			html += renderMessages(result.messages);
		}
		resultsDiv.innerHTML = html;
		return;
	}

	html += '<div class="resultHeader">Results code: <strong>' + escapeHtml(result.code) + "</strong></div>";

	const failCount = result.results.filter(r => r.resolved).length;
	const total = result.results.length;

	for (const r of result.results) {
		const cls = r.resolved ? "resultFail" : "resultPass";
		const statusCls = r.resolved ? "fail" : "pass";
		const statusText = r.resolved ? "FAIL" : "PASS";
		html += '<div class="resultQuery ' + cls + '">';
		html += '<span class="queryStatus ' + statusCls + '">' + statusText + "</span>";
		html += '<div class="queryText">' + escapeHtml(r.query) + "</div>";
		if (r.summary) {
			html += '<div class="querySummary">' + escapeHtml(r.summary) + "</div>";
		}
		html += "</div>";
	}

	if (failCount === 0) {
		html += '<div class="resultSummary allPass">All ' + total + " queries pass.</div>";
	} else {
		html += '<div class="resultSummary hasFail">' + failCount + " of " + total + " queries failed.</div>";
	}

	if (result.messages && result.messages.length > 0) {
		html += renderMessages(result.messages);
	}

	resultsDiv.innerHTML = html;
}

function renderMessages(messages) {
	let html = '<div class="resultMessages"><details><summary>' + messages.length + " analysis messages</summary><pre>";
	for (const m of messages) {
		html += escapeHtml(m) + "\n";
	}
	html += "</pre></details></div>";
	return html;
}

function escapeHtml(s) {
	const div = document.createElement("div");
	div.textContent = s;
	return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", initWorkbench);