/**
 * GateControl -- Notizen & Aufgaben: the text of a note (Markdown) for the page, without HTML strings
 *
 * The plugin's ui/notemd.js renders a note's Markdown to an HTML string; this page never puts HTML strings into the
 * DOM. parse(md) reads the same Markdown with the same rules (CommonMark with GitHub's tables and task lists, the
 * subset the plugin uses — README "The text of a note") into a tree of blocks and inline nodes; notes-view.js builds
 * the DOM from it with createElement and textContent only. Raw HTML stays text, links only http / https / mailto,
 * pictures and files only the note's own attachments (`att:<id>`), `task:<id>` the task a line became.
 *
 *   parse(md) → [Block]
 *     { t: 'p', lines: [[Inline]] } · { t: 'h', level: 2…4, c: [Inline] } · { t: 'hr' } · { t: 'code', text }
 *     { t: 'quote', lines: [[Inline]] } · { t: 'table', head: [[Inline]], rows: [[[Inline]]] }
 *     { t: 'list', ordered, check, items: [{ c: [Inline], depth, line?, done?, label? }] }
 *   Inline: { t: 'text', v } · { t: 'b' | 'i' | 's', c: [Inline] } · { t: 'code', v } · { t: 'tag', v }
 *     · { t: 'link', href, c: [Inline] } · { t: 'img', att, alt } · { t: 'file', att, label } · { t: 'task', task, label }
 *   toHtml(blocks) → the HTML notemd.render would give (tests only: the same reading as the plugin's)
 *
 * The editor's toolbar (pure, on { value, start, end }): wrap (bold, italic, link), prefix (heading, lists, check
 * boxes), insert (a table, a picture).
 */
(function (root) {
	'use strict';

	const CHECK_RE = /^(\s*)([-*+])\s+\[([ xX])\]\s+(.*)$/;
	const BULLET_RE = /^(\s*)([-*+])\s+(.*)$/;
	const ORDERED_RE = /^(\s*)(\d{1,9})[.)]\s+(.*)$/;
	const HEAD_RE = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
	const HR_RE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;
	const FENCE_RE = /^\s{0,3}(```|~~~)/;
	const TABLE_SEP_RE = /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$/;
	const TASK_LINK_RE = /\s*\[[^\]]*\]\(task:(\d{1,12})\)/;
	// notemd escapes & < > " ' first (each becomes "…;") — a #tag after one of them is a tag there, too
	const TAG_RE = /(^|[\s(,;&<>"'])#([\p{L}\p{N}][\p{L}\p{N}_-]{0,40})/gu;
	// marks while the inline text is read (private use characters, removed from the text first)
	const M = { b: ['', ''], i: ['', ''], s: ['', ''], tag: ['', ''] };
	const OPEN = { '': 'b', '': 'i', '': 's', '': 'tag' };
	const CLOSE = { '': 'b', '': 'i', '': 's', '': 'tag' };

	function lines(md) { return String(md == null ? '' : md).replace(/\r\n?/g, '\n').split('\n'); }

	function safeUrl(u) {
		const s = String(u || '').trim();
		return /^(https?:\/\/|mailto:)[^\s<>"']+$/i.test(s) ? s : null;
	}

	/** One line of text → [Inline] (notemd's inline(), as a tree). */
	function inline(text) {
		const codes = [];
		const parts = [];
		let s = String(text).replace(/[\u0000-\u0002-]/g, '');
		s = s.replace(/`([^`\n]+)`/g, (_, c) => { codes.push(c); return `\u0000${codes.length - 1}\u0000`; });
		// text that may hold code placeholders → text and code nodes
		const withCodes = (str) => String(str).split(/\u0000(\d+)\u0000/).map((x, k) => (k % 2 ? { t: 'code', v: codes[+x] } : { t: 'text', v: x })).filter((n) => n.t === 'code' || n.v);
		s = s.replace(/(!?)\[([^\]\n]{0,300})\]\(([^)\s]{1,2000})\)/g, (all, bang, label, url) => {
			const m = /^(att|task):(\d{1,12})$/.exec(url);
			let node;
			if (m && m[1] === 'att') node = bang ? { t: 'img', att: Number(m[2]), alt: label } : { t: 'file', att: Number(m[2]), label };
			else if (m && m[1] === 'task') node = { t: 'task', task: Number(m[2]), label };
			else {
				const u = safeUrl(url);
				node = u && !bang ? { t: 'link', href: u, c: withCodes(label) } : { t: 'span', c: withCodes(all) };
			}
			parts.push(node);
			return `\u0001${parts.length - 1}\u0001`;
		});
		s = s.replace(/(^|[\s(])(https?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)])/g, (_, pre, u) => {
			parts.push({ t: 'link', href: u, c: [{ t: 'text', v: u }] });
			return `${pre}\u0001${parts.length - 1}\u0001`;
		});
		s = s.replace(/\*\*([^*\n]+)\*\*/g, `${M.b[0]}$1${M.b[1]}`)
			.replace(/__([^_\n]+)__/g, `${M.b[0]}$1${M.b[1]}`)
			.replace(/(^|[^*\w])\*([^*\n]+)\*(?![*\w])/g, `$1${M.i[0]}$2${M.i[1]}`)
			.replace(/(^|[^_\p{L}\p{N}])_([^_\n]+)_(?![_\p{L}\p{N}])/gu, `$1${M.i[0]}$2${M.i[1]}`)
			.replace(/~~([^~\n]+)~~/g, `${M.s[0]}$1${M.s[1]}`);
		s = s.replace(TAG_RE, (_, pre, tag) => `${pre}${M.tag[0]}#${tag}${M.tag[1]}`);
		// the marks → a tree (crossing marks close the inner ones early, as a browser would)
		const top = { c: [] };
		const stack = [top];
		let buf = '';
		const flush = () => { if (buf) { stack[stack.length - 1].c.push({ t: 'text', v: buf }); buf = ''; } };
		for (let i = 0; i < s.length; i++) {
			const ch = s[i];
			if (OPEN[ch]) { flush(); const n = { t: OPEN[ch], c: [] }; stack[stack.length - 1].c.push(n); stack.push(n); continue; }
			if (CLOSE[ch]) {
				flush();
				const k = stack.map((n) => n.t).lastIndexOf(CLOSE[ch]);
				if (k > 0) stack.length = k;
				continue;
			}
			if (ch === '\u0000' || ch === '\u0001') {
				const end = s.indexOf(ch, i + 1);
				const idx = Number(s.slice(i + 1, end));
				flush();
				stack[stack.length - 1].c.push(ch === '\u0000' ? { t: 'code', v: codes[idx] } : parts[idx]);
				i = end;
				continue;
			}
			buf += ch;
		}
		flush();
		return tidy(top.c);
	}

	/** A tag node keeps its text flat ({ t: 'tag', v }). */
	function tidy(list) {
		return list.map((n) => {
			if (n.t === 'tag') return { t: 'tag', v: plainOf(n.c) };
			if (n.c && n.t !== 'link') return { ...n, c: tidy(n.c) };
			return n;
		});
	}

	function plainOf(list) {
		return list.map((n) => (n.t === 'text' || n.t === 'code' ? n.v : n.c ? plainOf(n.c) : n.label || n.alt || '')).join('');
	}

	function cells(row) {
		const r = row.trim().replace(/^\|/, '').replace(/\|$/, '');
		const out = [];
		let cur = '';
		for (let i = 0; i < r.length; i++) {
			if (r[i] === '\\' && r[i + 1] === '|') { cur += '|'; i++; } else if (r[i] === '|') { out.push(cur.trim()); cur = ''; } else cur += r[i];
		}
		out.push(cur.trim());
		return out;
	}

	/** Markdown → [Block] (notemd's render(), as a tree). */
	function parse(md) {
		const ls = lines(md);
		const out = [];
		let para = [];
		let list = null;
		const flushPara = () => { if (para.length) { out.push({ t: 'p', lines: para.map(inline) }); para = []; } };
		const flushList = () => { if (list) { out.push(list); list = null; } };
		const flush = () => { flushPara(); flushList(); };
		for (let i = 0; i < ls.length; i++) {
			const l = ls[i];
			let m;
			if (FENCE_RE.test(l)) {
				flush();
				const fence = FENCE_RE.exec(l)[1];
				const code = [];
				i++;
				while (i < ls.length && ls[i].trim().indexOf(fence) !== 0) code.push(ls[i++]);
				out.push({ t: 'code', text: code.join('\n') });
				continue;
			}
			if (!l.trim()) { flush(); continue; }
			if ((m = HEAD_RE.exec(l))) { flush(); out.push({ t: 'h', level: Math.min(m[1].length + 1, 4), c: inline(m[2]) }); continue; }
			if (HR_RE.test(l)) { flush(); out.push({ t: 'hr' }); continue; }
			if (/^\s*>/.test(l)) {
				flush();
				const q = [];
				while (i < ls.length && /^\s*>/.test(ls[i])) q.push(ls[i++].replace(/^\s*>\s?/, ''));
				i--;
				out.push({ t: 'quote', lines: q.map(inline) });
				continue;
			}
			if (l.indexOf('|') >= 0 && i + 1 < ls.length && TABLE_SEP_RE.test(ls[i + 1]) && ls[i + 1].indexOf('-') >= 0) {
				flush();
				const head = cells(l);
				i += 2;
				const rows = [];
				while (i < ls.length && ls[i].indexOf('|') >= 0 && ls[i].trim()) rows.push(cells(ls[i++]));
				i--;
				out.push({ t: 'table', head: head.map(inline), rows: rows.map((r) => head.map((_, k) => inline(r[k] || ''))) });
				continue;
			}
			if ((m = CHECK_RE.exec(l))) {
				flushPara();
				if (!list || !list.check) { flushList(); list = { t: 'list', ordered: false, check: true, items: [] }; }
				list.items.push({ c: inline(m[4]), depth: Math.min(3, Math.floor(m[1].replace(/\t/g, '  ').length / 2)), line: i, done: m[3] !== ' ', label: m[4].replace(TASK_LINK_RE, '') });
				continue;
			}
			if ((m = BULLET_RE.exec(l)) || (m = ORDERED_RE.exec(l))) {
				flushPara();
				const ordered = /^\d/.test(m[2]);
				if (!list || list.ordered !== ordered || list.check) { flushList(); list = { t: 'list', ordered, check: false, items: [] }; }
				list.items.push({ c: inline(m[3]), depth: Math.min(3, Math.floor(m[1].replace(/\t/g, '  ').length / 2)) });
				continue;
			}
			flushList();
			para.push(l.trim());
		}
		flush();
		return out;
	}

	// ── the HTML of notemd.render (tests: the same reading as the plugin's) ──

	function esc(s) {
		return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
	}

	function inlineHtml(list, o) {
		return list.map((n) => {
			if (n.t === 'text') return esc(n.v);
			if (n.t === 'code') return `<code>${esc(n.v)}</code>`;
			if (n.t === 'b') return `<strong>${inlineHtml(n.c, o)}</strong>`;
			if (n.t === 'i') return `<em>${inlineHtml(n.c, o)}</em>`;
			if (n.t === 's') return `<del>${inlineHtml(n.c, o)}</del>`;
			if (n.t === 'tag') return `<span class="nm-tag">${esc(n.v)}</span>`;
			if (n.t === 'span') return inlineHtml(n.c, o);
			if (n.t === 'link') return `<a href="${esc(n.href)}" target="_blank" rel="noopener noreferrer">${inlineHtml(n.c, o)}</a>`;
			if (n.t === 'img' || n.t === 'file') {
				const a = o.att ? o.att(n.att) : null;
				const label = n.t === 'img' ? n.alt : n.label;
				if (!a) return `<span class="nm-missing">${esc(label || '')}</span>`;
				if (n.t === 'img' && a.url && /^image\//.test(a.mime || '')) return `<img class="nm-img" src="${esc(a.url)}" alt="${esc(label || a.name || '')}" loading="lazy" data-att="${n.att}">`;
				return `<a class="nm-file" href="#" data-att="${n.att}">${esc(label || a.name || '')}</a>`;
			}
			if (n.t === 'task') {
				const tk = o.task ? o.task(n.task) : null;
				return `<a class="nm-task${tk && tk.done ? ' is-done' : ''}" href="#" data-task="${n.task}">${esc((tk && tk.label) || n.label || '')}</a>`;
			}
			return '';
		}).join('');
	}

	function toHtml(blocks, opts) {
		const o = opts || {};
		return blocks.map((b) => {
			if (b.t === 'p') return `<p>${b.lines.map((l) => inlineHtml(l, o)).join('<br>')}</p>`;
			if (b.t === 'h') return `<h${b.level}>${inlineHtml(b.c, o)}</h${b.level}>`;
			if (b.t === 'hr') return '<hr>';
			if (b.t === 'code') return `<pre><code>${esc(b.text)}</code></pre>`;
			if (b.t === 'quote') return `<blockquote>${b.lines.map((l) => inlineHtml(l, o)).join('<br>')}</blockquote>`;
			if (b.t === 'table') {
				return `<div class="nm-table"><table><thead><tr>${b.head.map((c) => `<th>${inlineHtml(c, o)}</th>`).join('')}</tr></thead><tbody>${
					b.rows.map((r) => `<tr>${r.map((c) => `<td>${inlineHtml(c, o)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
			}
			const tag = b.ordered ? 'ol' : 'ul';
			const items = b.items.map((it) => {
				if (b.check) {
					return `<li class="nm-check${it.done ? ' is-done' : ''}${it.depth ? ` nm-d${it.depth}` : ''}" data-line="${it.line}"><input type="checkbox" class="nm-box" data-line="${it.line}"${it.done ? ' checked' : ''}${o.checkable ? '' : ' disabled'} aria-label="${esc(it.label)}"><span class="nm-ct">${inlineHtml(it.c, o)}</span></li>`;
				}
				return `<li${it.depth ? ` class="nm-d${it.depth}"` : ''}>${inlineHtml(it.c, o)}</li>`;
			}).join('');
			return `<${tag}${b.check ? ' class="nm-checks"' : ''}>${items}</${tag}>`;
		}).join('');
	}

	// ── the toolbar ─────────────────────────────────────────

	/** Text around the selection (bold, italic, a link) → { value, start, end } (the new selection: the inner text). */
	function wrap(st, before, after, placeholder) {
		const v = String(st.value || '');
		const s = Math.max(0, Math.min(st.start, v.length));
		const e = Math.max(s, Math.min(st.end, v.length));
		const inner = v.slice(s, e) || placeholder || '';
		return { value: v.slice(0, s) + before + inner + after + v.slice(e), start: s + before.length, end: s + before.length + inner.length };
	}

	/** A mark at the start of every selected line (a heading, a list, a check box); lines that have it lose it. */
	function prefix(st, mark) {
		const v = String(st.value || '');
		const s = Math.max(0, Math.min(st.start, v.length));
		const e = Math.max(s, Math.min(st.end, v.length));
		const from = v.lastIndexOf('\n', s - 1) + 1;
		let to = v.indexOf('\n', e);
		if (to < 0) to = v.length;
		const block = v.slice(from, to).split('\n');
		const all = block.every((l) => l.startsWith(mark));
		const next = block.map((l, i) => (all ? l.slice(mark.length) : (mark === '1. ' ? `${i + 1}. ` : mark) + l.replace(/^(#{1,6}\s+|[-*+]\s+\[[ xX]\]\s+|[-*+]\s+|\d{1,9}[.)]\s+)/, ''))).join('\n');
		const caret = from + next.length;
		return { value: v.slice(0, from) + next + v.slice(to), start: block.length > 1 ? from : caret, end: caret };
	}

	/** Text at the caret, on lines of its own (a table, a picture) → { value, start, end } (caret after it). */
	function insert(st, text) {
		const v = String(st.value || '');
		const s = Math.max(0, Math.min(st.start, v.length));
		const e = Math.max(s, Math.min(st.end, v.length));
		const pre = s > 0 && v[s - 1] !== '\n' ? '\n' : '';
		const post = e < v.length && v[e] !== '\n' ? '\n' : '';
		const add = pre + text + post;
		return { value: v.slice(0, s) + add + v.slice(e), start: s + add.length, end: s + add.length };
	}

	/** A table of two columns with the column word of the page's language. */
	function tableText(col) {
		return `| ${col} 1 | ${col} 2 |\n| --- | --- |\n|  |  |`;
	}

	/** The Markdown of an attachment: a picture shows in the text, any other file is a link. */
	function attachmentText(att, name, isImage) {
		const label = String(name || '').replace(/[[\]()\n]/g, '').slice(0, 120) || 'Datei';
		return `${isImage ? '!' : ''}[${label}](att:${att})`;
	}

	root.GCNotesMd = { parse, inline, toHtml, plainOf, safeUrl, wrap, prefix, insert, tableText, attachmentText, TASK_LINK_RE };
})(typeof self !== 'undefined' ? self : this);
