/*
 * Payload Spy
 * Перехватывает запрос Chat Completion из браузера, считает что в нём реально лежит
 * и сравнивает с usage, который вернул прокси.
 */

const MODULE = 'payload_spy';
const TAG = '[Payload Spy]';
const GEN_URL = '/api/backends/chat-completions/generate';
const HISTORY_MAX = 10;
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
    let h = 5381;
    for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) | 0;
    return h;
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
            think: /<think>/i.test(text),
            html: /<\/?(div|details|summary|style|span|img|svg|table|section)\b/i.test(text),
            figSp: (text.match(/\u2007/g) || []).length,
            images: parts.filter((p) => p?.type === 'image_url' || p?.type === 'image').length,
        };
    });

    const byRole = {};
    for (const r of rows) {
        byRole[r.role] ??= { n: 0, chars: 0 };
        byRole[r.role].n++;
        byRole[r.role].chars += r.chars;
    }

    const seen = new Map();
    for (const r of rows) {
        if (r.chars < 200) continue;
        const key = `${r.chars}:${hash(r.text)}`;
        seen.set(key, [...(seen.get(key) ?? []), r.i]);
    }
    const dups = [...seen.values()].filter((a) => a.length > 1);

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
        images: rows.reduce((a, r) => a + r.images, 0),
        body,
        usage: null,
        status: null,
        stTokens: undefined,
    };
}

/** Приводит usage из разных форматов (OpenAI / Anthropic / Gemini) к одному виду. */
function normUsage(u) {
    if (!u || typeof u !== 'object') return null;
    const prompt = u.prompt_tokens ?? u.input_tokens ?? u.promptTokenCount ?? null;
    const completion = u.completion_tokens ?? u.output_tokens ?? u.candidatesTokenCount ?? null;
    const reasoning = u.completion_tokens_details?.reasoning_tokens ?? u.reasoning_tokens ?? u.thoughtsTokenCount ?? null;
    const cached = u.prompt_tokens_details?.cached_tokens ?? u.cachedContentTokenCount ?? null;
    if (prompt === null && completion === null) return null;
    return { prompt, completion, reasoning, cached, raw: u };
}

function parseUsage(text) {
    try {
        const json = JSON.parse(text);
        const found = normUsage(json?.usage ?? json?.usageMetadata);
        if (found) return found;
    } catch { /* не JSON, возможно SSE-стрим */ }

    const grab = (names) => {
        for (const name of names) {
            const all = [...text.matchAll(new RegExp(`"${name}"\\s*:\\s*(\\d+)`, 'g'))];
            if (all.length) return Number(all[all.length - 1][1]);
        }
        return null;
    };
    const prompt = grab(['prompt_tokens', 'input_tokens', 'promptTokenCount']);
    const completion = grab(['completion_tokens', 'output_tokens', 'candidatesTokenCount']);
    const reasoning = grab(['reasoning_tokens', 'thoughtsTokenCount']);
    if (prompt === null && completion === null) return null;
    return { prompt, completion, reasoning, cached: null, raw: { from: 'stream' } };
}

async function countWithST(report) {
    const { getTokenCountAsync } = SillyTavern.getContext();
    if (typeof getTokenCountAsync !== 'function') return null;
    const joined = report.rows.map((r) => r.text).join('\n');
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
        report.usage = parseUsage(text);
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

function installFetchSpy() {
    if (window.fetch.__payloadSpy) return;

    const origFetch = window.fetch.bind(window);

    const spy = async function (input, init) {
        let report = null;
        try {
            const url = typeof input === 'string' ? input : (input?.url ?? String(input));
            if (url.includes(GEN_URL) && typeof init?.body === 'string' && getSettings().enabled) {
                report = analyze(JSON.parse(init.body), init.body.length);
                lastReport = report;
                history.unshift(report);
                history.length = Math.min(history.length, HISTORY_MAX);
            }
        } catch (e) {
            console.warn(TAG, 'analyze failed, request goes through untouched', e);
            report = null;
        }

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
    const ratio = u?.prompt != null && r.stTokens ? u.prompt / r.stTokens : null;

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
        verdict = ratio > 1.15
            ? `Прокси насчитал в <b class="ps-warn">${ratio.toFixed(2)}×</b> больше, чем токенайзер ST по тому же payload. Лишнее считает прокси или бэкенд.`
            : `Прокси и токенайзер ST сходятся (<b class="ps-ok">${ratio.toFixed(2)}×</b>). Значит, раздут сам payload, смотри топ жирных сообщений и флаги выше.`;
    }

    const dupText = r.dups.length ? r.dups.map((a) => '#' + a.join(', #')).join(' | ') : 'нет';

    return `<div class="ps-popup">
<div class="ps-head">${esc(r.model)} · ${esc(r.source)} · ${esc(r.time)}${r.status ? ' · HTTP ' + r.status : ''}</div>

<h4>Что ушло</h4>
<table>
${row('Сообщений в запросе', fmt(r.n))}
${row('Символов в сообщениях', fmt(r.totalChars))}
${row('Размер всего body', `${fmt(r.bodyChars)} симв`)}
${row('Токенайзер ST по payload', fmt(r.stTokens))}
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
${row('Дубли больших блоков', esc(dupText), r.dups.length ? 'ps-warn' : '')}
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
        downloadJson(shown.body, `payload-${shown.time.replace(/:/g, '')}-${shown.id}.json`);
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
