/*
 * Payload Spy
 * Перехватывает запрос Chat Completion из браузера, считает что в нём реально лежит
 * и сравнивает с usage, который вернул прокси.
 */

const MODULE = 'payload_spy';
const TAG = '[Payload Spy]';
const GEN_URL = '/api/backends/chat-completions/generate';
const HISTORY_MAX = 20;
const DEFAULTS = Object.freeze({ enabled: true, toast: true });

// Папка расширения берётся из URL, чтобы шаблон находился при любом имени репозитория.
const FOLDER = (() => {
    try {
        const m = decodeURIComponent(import.meta.url).match(/extensions\/(.+?)\/index\.js/);
        if (m) return m[1];
    } catch { /* ignore */ }
    return 'third-party/payload-spy';
})();

/** @type {any} отчёт последнего запроса */
let lastReport = null;
/** @type {any} отчёт, который сейчас открыт в попапе */
let currentReport = null;
/** @type {any[]} полные отчёты по последним запросам, новые первыми */
const history = [];
let seq = 0;

/* ---------------- settings ---------------- */

function getSettings() {
    const { extensionSettings } = SillyTavern.getContext();
    if (!extensionSettings[MODULE]) {
        extensionSettings[MODULE] = structuredClone(DEFAULTS);
    }
    for (const key of Object.keys(DEFAULTS)) {
        if (!Object.hasOwn(extensionSettings[MODULE], key)) {
            extensionSettings[MODULE][key] = DEFAULTS[key];
        }
    }
    return extensionSettings[MODULE];
}

function saveSettings() {
    SillyTavern.getContext().saveSettingsDebounced();
}

/* ---------------- helpers ---------------- */

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const fmt = (n) => (n === null || n === undefined || Number.isNaN(n) ? '—' : Number(n).toLocaleString('ru-RU'));

function textOf(content) {
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) return content.map((p) => (typeof p === 'string' ? p : p?.text ?? '')).join('');
    return content == null ? '' : JSON.stringify(content);
}

function hash(str) {
    // FNV-1a 32-bit: fast fingerprint only; exact text is also checked below.
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
        h ^= str.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(16);
}

function utf8Bytes(str) {
    try { return new TextEncoder().encode(str).length; }
    catch { return str.length; }
}

function countMatches(text, regex) {
    return [...text.matchAll(regex)].length;
}

function normalizeContentForDuplicate(message) {
    try { return JSON.stringify({ role: message?.role ?? '?', content: message?.content ?? null }); }
    catch { return String(message?.content ?? ''); }
}

function downloadJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
}

/* ---------------- analysis ---------------- */

function analyze(body, bodyChars) {
    const messages = Array.isArray(body.messages) ? body.messages : [];

    const rows = messages.map((m, i) => {
        const text = textOf(m?.content);
        const parts = Array.isArray(m?.content) ? m.content : [];
        return {
            i,
            role: m?.role ?? '?',
            text,
            chars: text.length,
            codePoints: [...text].length,
            think: /<\s*think\b/i.test(text),
            html: /<\s*(!doctype|html|head|body|script|iframe|div|details|summary|style|span|img|svg|table|section|p|br|ul|ol|li|a|pre|code)\b/i.test(text),
            figSp: countMatches(text, /\u2007/g),
            specialSpaces: {
                nbsp: countMatches(text, /\u00a0/g),
                narrowNbsp: countMatches(text, /\u202f/g),
                thin: countMatches(text, /\u2009/g),
                zeroWidth: countMatches(text, /[\u200b\u200c\u200d\ufeff]/g),
            },
            images: parts.filter((p) => ['image_url', 'image', 'input_image'].includes(p?.type)).length,
        };
    });

    const byRole = {};
    for (const r of rows) {
        byRole[r.role] ??= { n: 0, chars: 0 };
        byRole[r.role].n++;
        byRole[r.role].chars += r.chars;
    }

    const seen = new Map();
    for (const [i, message] of messages.entries()) {
        const normalized = normalizeContentForDuplicate(message);
        const text = rows[i]?.text ?? '';
        if (text.length < 200) continue;
        const key = `${normalized.length}:${hash(normalized)}`;
        const bucket = seen.get(key) ?? [];
        const exact = bucket.find((entry) => entry.normalized === normalized);
        if (exact) exact.indices.push(i);
        else bucket.push({ normalized, indices: [i] });
        seen.set(key, bucket);
    }
    const dups = [...seen.values()].flatMap((bucket) => bucket.filter((entry) => entry.indices.length > 1).map((entry) => entry.indices));

    const extraKeys = Object.entries(body)
        .filter(([k]) => k !== 'messages')
        .map(([k, v]) => {
            let size = 0;
            try { size = JSON.stringify(v ?? '').length; } catch { /* ignore */ }
            return [k, size];
        })
        .sort((a, b) => b[1] - a[1]);

    const tools = Array.isArray(body.tools) ? body.tools.length : 0;
    const toolsChars = tools ? JSON.stringify(body.tools).length : 0;

    return {
        id: ++seq,
        time: new Date().toLocaleTimeString('ru-RU'),
        model: body.model ?? '?',
        source: body.chat_completion_source ?? '?',
        bodyChars,
        bodyBytes: typeof bodyChars === 'number' ? null : null,
        n: rows.length,
        totalChars: rows.reduce((a, r) => a + r.chars, 0),
        rows,
        byRole,
        dups,
        extraKeys,
        tools,
        toolsChars,
        thinkCount: rows.filter((r) => r.think).length,
        htmlCount: rows.filter((r) => r.html).length,
        figSp: rows.reduce((a, r) => a + r.figSp, 0),
        specialSpaces: rows.reduce((a, r) => ({
            nbsp: a.nbsp + r.specialSpaces.nbsp,
            narrowNbsp: a.narrowNbsp + r.specialSpaces.narrowNbsp,
            thin: a.thin + r.specialSpaces.thin,
            zeroWidth: a.zeroWidth + r.specialSpaces.zeroWidth,
        }), { nbsp: 0, narrowNbsp: 0, thin: 0, zeroWidth: 0 }),
        images: rows.reduce((a, r) => a + r.images, 0),
        body,
        usage: null,
        status: null,
        stTokens: undefined,
    };
}

/** Приводит usage из разных форматов (OpenAI / Anthropic / Gemini) к одному виду. */
function validCount(value) {
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
    if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value);
    return null;
}

function normUsage(u) {
    if (!u || typeof u !== 'object') return null;
    const prompt = validCount(u.prompt_tokens ?? u.input_tokens ?? u.promptTokenCount ?? u.inputTokenCount);
    const completion = validCount(u.completion_tokens ?? u.output_tokens ?? u.candidatesTokenCount ?? u.outputTokenCount);
    const reasoning = validCount(u.completion_tokens_details?.reasoning_tokens ?? u.reasoning_tokens ?? u.thoughtsTokenCount);
    const cached = validCount(u.prompt_tokens_details?.cached_tokens ?? u.cachedContentTokenCount);
    if (prompt === null && completion === null && reasoning === null) return null;
    return { prompt, completion, reasoning, cached, raw: u };
}

function parseUsage(text) {
    // First try a normal JSON response.
    try {
        const json = JSON.parse(text);
        const found = normUsage(json?.usage ?? json?.usageMetadata ?? json?.response?.usage);
        if (found) return found;
    } catch { /* likely SSE or a non-JSON response */ }

    // SSE: parse each data event independently and prefer the last event that actually has usage.
    const events = [];
    for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data:')) continue;
        const data = trimmed.slice(5).trim();
        if (!data || data === '[DONE]') continue;
        try {
            const json = JSON.parse(data);
            const usage = normUsage(json?.usage ?? json?.usageMetadata ?? json?.response?.usage);
            if (usage) events.push(usage);
        } catch { /* ignore non-JSON SSE event */ }
    }
    if (events.length) return { ...events[events.length - 1], raw: { from: 'sse-final-event', eventCountWithUsage: events.length, usage: events[events.length - 1].raw } };

    // Fallback for proxy formats that embed usage keys in arbitrary JSON text.
    // Take the last valid object containing usage, rather than mixing independent fields across events.
    const candidates = [...text.matchAll(/\{[^{}]*\b(?:prompt_tokens|input_tokens|promptTokenCount|completion_tokens|output_tokens|candidatesTokenCount)\b[^{}]*\}/gs)];
    for (let i = candidates.length - 1; i >= 0; i--) {
        try {
            const obj = JSON.parse(candidates[i][0]);
            const usage = normUsage(obj.usage ?? obj.usageMetadata ?? obj);
            if (usage) return { ...usage, raw: { from: 'embedded-json', usage: usage.raw } };
        } catch { /* continue */ }
    }
    return null;
}

async function countWithST(report) {
    const { getTokenCountAsync } = SillyTavern.getContext();
    if (typeof getTokenCountAsync !== 'function') return null;
    // This is only a text-only estimate, not a reproduction of the provider's full prompt format.
    const joined = report.rows.map((r) => `${r.role}: ${r.text}`).join('\n');
    try {
        return await Promise.race([
            getTokenCountAsync(joined),
            new Promise((resolve) => setTimeout(() => resolve(null), 10000)),
        ]);
    } catch (e) {
        console.warn(TAG, 'tokenizer failed', e);
        return null;
    }
}

/* ---------------- fetch interceptor ---------------- */

async function finish(report, response) {
    try {
        report.status = response.status;
        const text = await response.clone().text();
        report.responseTextLength = text.length;
        report.usage = parseUsage(text);
        report.usageComparable = response.ok && report.usage !== null;
    } catch (e) {
        console.debug(TAG, 'usage not read', e);
    }

    notify(report);
}

function notify(report) {
    try {
        if (!getSettings().toast) return;
        const u = report.usage;
        const line = `${report.n} сообщ · ${report.totalChars} симв` + (u?.prompt != null ? ` · прокси: ${u.prompt} ток` : '');
        toastr.info(`${line}<br><small>тык: детали</small>`, 'Payload Spy', {
            timeOut: 12000,
            escapeHtml: false,
            onclick: () => openPopup(),
        });
    } catch (e) {
        console.debug(TAG, 'toast failed', e);
    }
}

async function readRequestBody(input, init) {
    if (init && Object.prototype.hasOwnProperty.call(init, 'body') && init.body != null) {
        const body = init.body;
        if (typeof body === 'string') return body;
        if (body instanceof URLSearchParams) return body.toString();
        if (body instanceof Blob) return await body.text();
        // FormData/streams are not JSON; avoid consuming or changing them.
        try { return JSON.stringify(body); } catch { return null; }
    }
    if (typeof Request !== 'undefined' && input instanceof Request) {
        try { return await input.clone().text(); } catch { return null; }
    }
    return null;
}

function installFetchSpy() {
    if (window.fetch.__payloadSpy) return;

    const origFetch = window.fetch.bind(window);
    const spy = async function (input, init) {
        let report = null;
        try {
            const url = typeof input === 'string' ? input : (input?.url ?? String(input));
            if (url.includes(GEN_URL) && getSettings().enabled) {
                const rawBody = await readRequestBody(input, init);
                if (typeof rawBody === 'string') {
                    const parsed = JSON.parse(rawBody);
                    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                        report = analyze(parsed, rawBody.length);
                        report.bodyBytes = utf8Bytes(rawBody);
                        report.requestUrl = url;
                        report.requestMethod = init?.method ?? input?.method ?? 'GET';
                        report.payloadHash = hash(rawBody);
                        lastReport = report;
                        history.unshift(report);
                        history.length = Math.min(history.length, HISTORY_MAX);
                    }
                }
            }
        } catch (e) {
            console.warn(TAG, 'analyze failed, request goes through untouched', e);
            report = null;
        }

        // Pass the original arguments unchanged to the real fetch.
        const response = await origFetch(input, init);
        if (report) finish(report, response).catch((e) => console.warn(TAG, e));
        return response;
    };
    spy.__payloadSpy = true;
    window.fetch = spy;
}

/* ---------------- report popup ---------------- */

function buildHtml(r) {
    const u = r.usage;
    const ratio = u?.prompt != null && r.stTokens != null && r.stTokens > 0 ? u.prompt / r.stTokens : null;

    const row = (label, value, cls = '') =>
        `<tr><td>${label}</td><td class="ps-val ${cls}">${value}</td></tr>`;

    const roleRows = Object.entries(r.byRole)
        .map(([role, v]) => row(esc(role), `${fmt(v.n)} шт · ${fmt(v.chars)} симв`))
        .join('');

    const top = [...r.rows]
        .sort((a, b) => b.chars - a.chars)
        .slice(0, 8)
        .map((x) => {
            const flags = `${x.think ? ' <span class="ps-warn">THINK</span>' : ''}${x.html ? ' <span class="ps-warn">HTML</span>' : ''}`;
            const preview = esc(x.text.replace(/\s+/g, ' ').slice(0, 50));
            return `<tr><td class="ps-mono">#${x.i} ${esc(x.role)}${flags}<div class="ps-preview">${preview}</div></td><td class="ps-val">${fmt(x.chars)}</td></tr>`;
        })
        .join('');

    const keys = r.extraKeys
        .slice(0, 10)
        .map(([k, v]) => row(`<span class="ps-mono">${esc(k)}</span>`, `${fmt(v)} симв`, k === 'tools' && v > 2 ? 'ps-warn' : ''))
        .join('');

    const hist = history
        .map((h) => {
            const perChar = h.usage?.prompt != null && h.totalChars ? (h.usage.prompt / h.totalChars).toFixed(3) : '—';
            const cur = h.id === r.id ? ' ps-current' : '';
            return `<tr class="ps-row${cur}" data-ps-id="${h.id}"><td>${esc(h.time)}</td><td class="ps-num">${fmt(h.n)}</td><td class="ps-num">${fmt(h.totalChars)}</td><td class="ps-num">${fmt(h.usage?.prompt)}</td><td class="ps-num">${perChar}</td><td class="ps-num">${h.thinkCount}/${h.htmlCount}</td></tr>`;
        })
        .join('');

    let verdict = '';
    if (ratio !== null) {
        verdict = `Отношение usage/input к текстовой оценке ST: <b class="${ratio > 1.15 ? 'ps-warn' : 'ps-ok'}">${ratio.toFixed(2)}×</b>. Это не доказательство завышения: оценка ST не включает гарантированно служебные токены, tools и мультимодальные данные.`;
    }

    const dupText = r.dups.length ? r.dups.map((a) => '#' + a.join(', #')).join(' | ') : 'нет';

    return `<div class="ps-popup">
<div class="ps-head">${esc(r.model)} · ${esc(r.source)} · ${esc(r.time)}${r.status ? ' · HTTP ' + r.status : ''}</div>

<h4>Что ушло</h4>
<table>
${row('Сообщений в запросе', fmt(r.n))}
${row('Символов в сообщениях', fmt(r.totalChars))}
${row('Размер body (JS-строка)', `${fmt(r.bodyChars)} UTF-16 units`)}
${row('Размер body (UTF-8)', r.bodyBytes == null ? '—' : `${fmt(r.bodyBytes)} байт`)}
${row('Хеш payload', esc(r.payloadHash ?? '—'))}
${row('Токенайзер ST (оценка только по тексту)', fmt(r.stTokens))}
</table>

<h4>Ответ прокси (usage)</h4>
<table>
${row('Input (prompt)', fmt(u?.prompt))}
${row('Output (completion)', fmt(u?.completion))}
${row('Reasoning внутри output', fmt(u?.reasoning))}
${row('Cached', fmt(u?.cached))}
${row('Токенов на символ', u?.prompt != null && r.totalChars ? (u.prompt / r.totalChars).toFixed(3) : '—')}
</table>
${verdict ? `<div class="ps-verdict">${verdict}</div>` : ''}

<h4>Подозрительное</h4>
<table>
${row('Сообщений с &lt;think&gt;', fmt(r.thinkCount), r.thinkCount ? 'ps-warn' : '')}
${row('Сообщений с HTML/CSS', fmt(r.htmlCount), r.htmlCount ? 'ps-warn' : '')}
${row('Фигурных пробелов (U+2007)', fmt(r.figSp), r.figSp ? 'ps-warn' : '')}
${row('NBSP / narrow NBSP / thin', `${fmt(r.specialSpaces.nbsp)} / ${fmt(r.specialSpaces.narrowNbsp)} / ${fmt(r.specialSpaces.thin)}`, (r.specialSpaces.nbsp + r.specialSpaces.narrowNbsp + r.specialSpaces.thin) ? 'ps-warn' : '')}
${row('Zero-width / BOM', fmt(r.specialSpaces.zeroWidth), r.specialSpaces.zeroWidth ? 'ps-warn' : '')}
${row('Дубли больших блоков (роль + точное содержимое)', esc(dupText), r.dups.length ? 'ps-warn' : '')}
${row('Tools (function calling)', `${fmt(r.tools)} шт · ${fmt(r.toolsChars)} симв`, r.tools ? 'ps-warn' : '')}
${row('Картинок', fmt(r.images))}
</table>

<h4>По ролям</h4>
<table>${roleRows}</table>

<h4>Самые жирные сообщения</h4>
<table>${top}</table>

<h4>Остальные поля body</h4>
<table>${keys}</table>

<h4>История запросов <small>(тык по строке открывает тот запрос)</small></h4>
<table>
<tr><th>Время</th><th class="ps-num">Сообщ</th><th class="ps-num">Симв</th><th class="ps-num">Прокси</th><th class="ps-num">ток/симв</th><th class="ps-num">think/html</th></tr>
${hist}
</table>
</div>`;
}

async function openPopup(target = null) {
    const report = target ?? lastReport;
    if (!report) {
        toastr.info('Ещё не было ни одной генерации', 'Payload Spy');
        return;
    }
    const { Popup, POPUP_TYPE, POPUP_RESULT } = SillyTavern.getContext();

    if (report.stTokens === undefined) {
        report.stTokens = await countWithST(report);
    }
    currentReport = report;

    const popup = new Popup(buildHtml(report), POPUP_TYPE.TEXT, '', {
        wide: true,
        large: true,
        allowVerticalScrolling: true,
        okButton: 'Закрыть',
        customButtons: [{ text: 'payload.json', icon: 'fa-download', result: POPUP_RESULT.CUSTOM1 }],
    });

    const result = await popup.show();
    if (result === POPUP_RESULT.CUSTOM1) {
        const shown = currentReport ?? report;
        downloadJson({
            metadata: { id: shown.id, time: shown.time, model: shown.model, source: shown.source, requestUrl: shown.requestUrl, requestMethod: shown.requestMethod, payloadHash: shown.payloadHash, status: shown.status },
            request: shown.body,
            localEstimate: { stTextTokens: shown.stTokens, messageCount: shown.n, messageTextUnits: shown.totalChars, bodyUtf16Units: shown.bodyChars, bodyUtf8Bytes: shown.bodyBytes },
            proxyUsage: shown.usage,
            diagnostics: { duplicates: shown.dups, thinkCount: shown.thinkCount, htmlCount: shown.htmlCount, figureSpaces: shown.figSp, specialSpaces: shown.specialSpaces, tools: shown.tools, toolsChars: shown.toolsChars, images: shown.images },
        }, `payload-${shown.time.replace(/:/g, '')}-${shown.id}.json`);
    }
}

/* ---------------- UI ---------------- */

async function initUI() {
    if (document.getElementById('payload_spy_settings')) return;

    try {
        const { renderExtensionTemplateAsync } = SillyTavern.getContext();
        const html = await renderExtensionTemplateAsync(FOLDER, 'settings', {});
        $('#extensions_settings2').append(html);
    } catch (e) {
        console.error(TAG, `не удалось загрузить settings.html из "${FOLDER}"`, e);
        return;
    }

    const s = getSettings();
    $('#ps_enabled').prop('checked', s.enabled).on('change', function () {
        getSettings().enabled = this.checked;
        saveSettings();
    });
    $('#ps_toast').prop('checked', s.toast).on('change', function () {
        getSettings().toast = this.checked;
        saveSettings();
    });
    $('#ps_open').on('click', () => openPopup());

    // Тык по строке истории внутри попапа: подменяем содержимое на выбранный запрос.
    $(document).on('click', '.ps-popup tr[data-ps-id]', async function () {
        const id = Number(this.dataset.psId);
        const report = history.find((h) => h.id === id);
        if (!report) return;
        if (report.stTokens === undefined) report.stTokens = await countWithST(report);
        currentReport = report;
        $('.ps-popup').replaceWith(buildHtml(report));
        document.querySelector('.ps-popup')?.scrollIntoView?.({ block: 'start' });
    });

    $('#ps_clear').on('click', () => {
        history.length = 0;
        lastReport = null;
        currentReport = null;
        toastr.success('История очищена', 'Payload Spy');
    });
}

/* ---------------- init ---------------- */

installFetchSpy();

window.payloadSpy = {
    open: openPopup,
    last: () => lastReport,
    history: () => [...history],
};

(function registerUI() {
    const { eventSource, event_types } = SillyTavern.getContext();
    eventSource.on(event_types.APP_INITIALIZED, initUI);
})();

console.log(TAG, `loaded, folder: ${FOLDER}`);
