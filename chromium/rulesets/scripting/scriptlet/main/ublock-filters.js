/*******************************************************************************

    uBlock Origin Lite - a comprehensive, MV3-compliant content blocker
    Copyright (C) 2014-present Raymond Hill

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see {http://www.gnu.org/licenses/}.

    Home: https://github.com/gorhill/uBlock

*/

// ruleset: ublock-filters

// Important!
// Isolate from global scope

// Start of local scope
(function uBOL_scriptlets() {

/******************************************************************************/

class ArglistParser {
    constructor(separatorChar = ',', mustQuote = false) {
        this.separatorChar = this.actualSeparatorChar = separatorChar;
        this.separatorCode = this.actualSeparatorCode = separatorChar.charCodeAt(0);
        this.mustQuote = mustQuote;
        this.quoteBeg = 0; this.quoteEnd = 0;
        this.argBeg = 0; this.argEnd = 0;
        this.separatorBeg = 0; this.separatorEnd = 0;
        this.transform = false;
        this.failed = false;
        this.reWhitespaceStart = /^\s+/;
        this.reWhitespaceEnd = /(?:^|\S)(\s+)$/;
        this.reOddTrailingEscape = /(?:^|[^\\])(?:\\\\)*\\$/;
        this.reTrailingEscapeChars = /\\+$/;
    }
    nextArg(pattern, beg = 0) {
        const len = pattern.length;
        this.quoteBeg = beg + this.leftWhitespaceCount(pattern.slice(beg));
        this.failed = false;
        const qc = pattern.charCodeAt(this.quoteBeg);
        if ( qc === 0x22 /* " */ || qc === 0x27 /* ' */ || qc === 0x60 /* ` */ ) {
            this.indexOfNextArgSeparator(pattern, qc);
            if ( this.argEnd !== len ) {
                this.quoteEnd = this.argEnd + 1;
                this.separatorBeg = this.separatorEnd = this.quoteEnd;
                this.separatorEnd += this.leftWhitespaceCount(pattern.slice(this.quoteEnd));
                if ( this.separatorEnd === len ) { return this; }
                if ( pattern.charCodeAt(this.separatorEnd) === this.separatorCode ) {
                    this.separatorEnd += 1;
                    return this;
                }
            }
        }
        this.indexOfNextArgSeparator(pattern, this.separatorCode);
        this.separatorBeg = this.separatorEnd = this.argEnd;
        if ( this.separatorBeg < len ) {
            this.separatorEnd += 1;
        }
        this.argEnd -= this.rightWhitespaceCount(pattern.slice(0, this.separatorBeg));
        this.quoteEnd = this.argEnd;
        if ( this.mustQuote ) {
            this.failed = true;
        }
        return this;
    }
    normalizeArg(s, char = '') {
        if ( char === '' ) { char = this.actualSeparatorChar; }
        let out = '';
        let pos = 0;
        while ( (pos = s.lastIndexOf(char)) !== -1 ) {
            out = s.slice(pos) + out;
            s = s.slice(0, pos);
            const match = this.reTrailingEscapeChars.exec(s);
            if ( match === null ) { continue; }
            const tail = (match[0].length & 1) !== 0
                ? match[0].slice(0, -1)
                : match[0];
            out = tail + out;
            s = s.slice(0, -match[0].length);
        }
        if ( out === '' ) { return s; }
        return s + out;
    }
    leftWhitespaceCount(s) {
        const match = this.reWhitespaceStart.exec(s);
        return match === null ? 0 : match[0].length;
    }
    rightWhitespaceCount(s) {
        const match = this.reWhitespaceEnd.exec(s);
        return match === null ? 0 : match[1].length;
    }
    indexOfNextArgSeparator(pattern, separatorCode) {
        this.argBeg = this.argEnd = separatorCode !== this.separatorCode
            ? this.quoteBeg + 1
            : this.quoteBeg;
        this.transform = false;
        if ( separatorCode !== this.actualSeparatorCode ) {
            this.actualSeparatorCode = separatorCode;
            this.actualSeparatorChar = String.fromCharCode(separatorCode);
        }
        while ( this.argEnd < pattern.length ) {
            const pos = pattern.indexOf(this.actualSeparatorChar, this.argEnd);
            if ( pos === -1 ) {
                return (this.argEnd = pattern.length);
            }
            if ( this.reOddTrailingEscape.test(pattern.slice(0, pos)) === false ) {
                return (this.argEnd = pos);
            }
            this.transform = true;
            this.argEnd = pos + 1;
        }
    }
}

class JSONPath {
    static create(query) {
        const jsonp = new JSONPath();
        jsonp.compile(query);
        return jsonp;
    }
    static toJSON(obj, stringifier, ...args) {
        return (stringifier || JSON.stringify)(obj, ...args)
            .replace(/\//g, '\\/');
    }
    get value() {
        return this.#compiled && this.#compiled.rval;
    }
    set value(v) {
        if ( this.#compiled === undefined ) { return; }
        this.#compiled.rval = v;
    }
    get valid() {
        return this.#compiled !== undefined;
    }
    compile(query) {
        this.#compiled = undefined;
        const r = this.#compile(query, 0);
        if ( r === undefined ) { return; }
        if ( r.i !== query.length ) {
            let val;
            if ( query.startsWith('=', r.i) ) {
                if ( /^=repl\(.+\)$/.test(query.slice(r.i)) ) {
                    r.modify = 'repl';
                    val = query.slice(r.i+6, -1);
                } else {
                    val = query.slice(r.i+1);
                }
            } else if ( query.startsWith('+=', r.i) ) {
                r.modify = '+';
                val = query.slice(r.i+2);
            }
            try { r.rval = JSON.parse(val); }
            catch { return; }
        }
        this.#compiled = r;
    }
    evaluate(root) {
        if ( this.valid === false ) { return []; }
        this.#root = root;
        const paths = this.#evaluate(this.#compiled.steps, []);
        this.#root = null;
        return paths;
    }
    apply(root) {
        if ( this.valid === false ) { return; }
        const { rval } = this.#compiled;
        this.#root = { '$': root };
        const paths = this.#evaluate(this.#compiled.steps, []);
        let i = paths.length
        if ( i === 0 ) { this.#root = null; return; }
        while ( i-- ) {
            const { obj, key } = this.#resolvePath(paths[i]);
            if ( rval !== undefined ) {
                this.#modifyVal(obj, key);
            } else if ( Array.isArray(obj) && typeof key === 'number' ) {
                obj.splice(key, 1);
            } else {
                delete obj[key];
            }
        }
        const result = this.#root['$'] ?? null;
        this.#root = null;
        return result;
    }
    dump() {
        return JSON.stringify(this.#compiled);
    }
    toJSON(obj, ...args) {
        return JSONPath.toJSON(obj, null, ...args)
    }
    get [Symbol.toStringTag]() {
        return 'JSONPath';
    }
    #UNDEFINED = 0;
    #ROOT = 1;
    #CURRENT = 2;
    #CHILDREN = 3;
    #DESCENDANTS = 4;
    #reUnquotedIdentifier = /^[A-Za-z_][\w]*|^\*/;
    #reExpr = /^([!=^$*]=|[<>]=?)(.+?)\]/;
    #reIndice = /^-?\d+/;
    #root;
    #compiled;
    #compile(query, i) {
        if ( query.length === 0 ) { return; }
        const steps = [];
        let c = query.charCodeAt(i);
        if ( c === 0x24 /* $ */ ) {
            steps.push({ mv: this.#ROOT });
            i += 1;
        } else if ( c === 0x40 /* @ */ ) {
            steps.push({ mv: this.#CURRENT });
            i += 1;
        } else {
            steps.push({ mv: i === 0 ? this.#ROOT : this.#CURRENT });
        }
        let mv = this.#UNDEFINED;
        for (;;) {
            if ( i === query.length ) { break; }
            c = query.charCodeAt(i);
            if ( c === 0x20 /* whitespace */ ) {
                i += 1;
                continue;
            }
            // Dot accessor syntax
            if ( c === 0x2E /* . */ ) {
                if ( mv !== this.#UNDEFINED ) { return; }
                if ( query.startsWith('..', i) ) {
                    mv = this.#DESCENDANTS;
                    i += 2;
                } else {
                    mv = this.#CHILDREN;
                    i += 1;
                }
                continue;
            }
            if ( c !== 0x5B /* [ */ ) {
                if ( mv === this.#UNDEFINED ) {
                    const step = steps.at(-1);
                    if ( step === undefined ) { return; }
                    i = this.#compileExpr(query, step, i);
                    break;
                }
                const s = this.#consumeUnquotedIdentifier(query, i);
                if  ( s === undefined ) { return; }
                steps.push({ mv, k: s });
                i += s.length;
                mv = this.#UNDEFINED;
                continue;
            }
            // Bracket accessor syntax
            if ( query.startsWith('[?', i) ) {
                const not = query.charCodeAt(i+2) === 0x21 /* ! */;
                const j = i + 2 + (not ? 1 : 0);
                const r = this.#compile(query, j);
                if ( r === undefined ) { return; }
                if ( query.startsWith(']', r.i) === false ) { return; }
                if ( not ) { r.steps.at(-1).not = true; }
                steps.push({ mv: mv || this.#CHILDREN, steps: r.steps });
                i = r.i + 1;
                mv = this.#UNDEFINED;
                continue;
            }
            if ( query.startsWith('[*]', i) ) {
                mv ||= this.#CHILDREN;
                steps.push({ mv, k: '*' });
                i += 3;
                mv = this.#UNDEFINED;
                continue;
            }
            const r = this.#consumeIdentifier(query, i+1);
            if ( r === undefined ) { return; }
            mv ||= this.#CHILDREN;
            steps.push({ mv, k: r.s });
            i = r.i + 1;
            mv = this.#UNDEFINED;
        }
        if ( steps.length === 0 ) { return; }
        if ( mv !== this.#UNDEFINED ) { return; }
        return { steps, i };
    }
    #evaluate(steps, pathin) {
        let resultset = [];
        if ( Array.isArray(steps) === false ) { return resultset; }
        for ( const step of steps ) {
            switch ( step.mv ) {
            case this.#ROOT:
                resultset = [ [ '$' ] ];
                break;
            case this.#CURRENT:
                resultset = [ pathin ];
                break;
            case this.#CHILDREN:
            case this.#DESCENDANTS:
                resultset = this.#getMatches(resultset, step);
                break;
            default:
                break;
            }
        }
        return resultset;
    }
    #getMatches(listin, step) {
        const listout = [];
        for ( const pathin of listin ) {
            const { value: owner } = this.#resolvePath(pathin);
            if ( step.k === '*' ) {
                this.#getMatchesFromAll(pathin, step, owner, listout);
            } else if ( step.k !== undefined ) {
                this.#getMatchesFromKeys(pathin, step, owner, listout);
            } else if ( step.steps ) {
                this.#getMatchesFromExpr(pathin, step, owner, listout);
            }
        }
        return listout;
    }
    #getMatchesFromAll(pathin, step, owner, out) {
        const recursive = step.mv === this.#DESCENDANTS;
        for ( const { path } of this.#getDescendants(owner, recursive) ) {
            out.push([ ...pathin, ...path ]);
        }
    }
    #getMatchesFromKeys(pathin, step, owner, out) {
        const kk = Array.isArray(step.k) ? step.k : [ step.k ];
        for ( const k of kk ) {
            const normalized = this.#evaluateExpr(step, owner, k);
            if ( normalized === undefined ) { continue; }
            out.push([ ...pathin, normalized ]);
        }
        if ( step.mv !== this.#DESCENDANTS ) { return; }
        for ( const { obj, key, path } of this.#getDescendants(owner, true) ) {
            for ( const k of kk ) {
                const normalized = this.#evaluateExpr(step, obj[key], k);
                if ( normalized === undefined ) { continue; }
                out.push([ ...pathin, ...path, normalized ]);
            }
        }
    }
    #getMatchesFromExpr(pathin, step, owner, out) {
        const recursive = step.mv === this.#DESCENDANTS;
        if ( Array.isArray(owner) === false ) {
            const r = this.#evaluate(step.steps, pathin);
            if ( r.length !== 0 ) { out.push(pathin); }
            if ( recursive !== true ) { return; }
        }
        for ( const { obj, key, path } of this.#getDescendants(owner, recursive) ) {
            if ( Array.isArray(obj[key]) ) { continue; }
            const q = [ ...pathin, ...path ];
            const r = this.#evaluate(step.steps, q);
            if ( r.length === 0 ) { continue; }
            out.push(q);
        }
    }
    #normalizeKey(owner, key) {
        if ( typeof key === 'number' ) {
            if ( Array.isArray(owner) ) {
                return key >= 0 ? key : owner.length + key;
            }
        }
        return key;
    }
    #getDescendants(v, recursive) {
        const iterator = {
            next() {
                const n = this.stack.length;
                if ( n === 0 ) {
                    this.value = undefined;
                    this.done = true;
                    return this;
                }
                const details = this.stack[n-1];
                const entry = details.keys.next();
                if ( entry.done ) {
                    this.stack.pop();
                    this.path.pop();
                    return this.next();
                }
                this.path[n-1] = entry.value;
                this.value = {
                    obj: details.obj,
                    key: entry.value,
                    path: this.path.slice(),
                };
                const v = this.value.obj[this.value.key];
                if ( recursive ) {
                    if ( Array.isArray(v) ) {
                        this.stack.push({ obj: v, keys: v.keys() });
                    } else if ( typeof v === 'object' && v !== null ) {
                        this.stack.push({ obj: v, keys: Object.keys(v).values() });
                    }
                }
                return this;
            },
            path: [],
            value: undefined,
            done: false,
            stack: [],
            [Symbol.iterator]() { return this; },
        };
        if ( Array.isArray(v) ) {
            iterator.stack.push({ obj: v, keys: v.keys() });
        } else if ( typeof v === 'object' && v !== null ) {
            iterator.stack.push({ obj: v, keys: Object.keys(v).values() });
        }
        return iterator;
    }
    #consumeIdentifier(query, i) {
        const keys = [];
        for (;;) {
            const c0 = query.charCodeAt(i);
            if ( c0 === 0x5D /* ] */ ) { break; }
            if ( c0 === 0x2C /* , */ ) {
                i += 1;
                continue;
            }
            if ( c0 === 0x27 /* ' */ ) {
                const r = this.#untilChar(query, 0x27 /* ' */, i+1)
                if ( r === undefined ) { return; }
                keys.push(r.s);
                i = r.i;
                continue;
            }
            if ( c0 === 0x2D /* - */ || c0 >= 0x30 && c0 <= 0x39 ) {
                const match = this.#reIndice.exec(query.slice(i));
                if ( match === null ) { return; }
                const indice = parseInt(query.slice(i), 10);
                keys.push(indice);
                i += match[0].length;
                continue;
            }
            const s = this.#consumeUnquotedIdentifier(query, i);
            if ( s === undefined ) { return; }
            keys.push(s);
            i += s.length;
        }
        return { s: keys.length === 1 ? keys[0] : keys, i };
    }
    #consumeUnquotedIdentifier(query, i) {
        const match = this.#reUnquotedIdentifier.exec(query.slice(i));
        if ( match === null ) { return; }
        return match[0];
    }
    #untilChar(query, targetCharCode, i) {
        const len = query.length;
        const parts = [];
        let beg = i, end = i;
        for (;;) {
            if ( end === len ) { return; }
            const c = query.charCodeAt(end);
            if ( c === targetCharCode ) {
                parts.push(query.slice(beg, end));
                end += 1;
                break;
            }
            if ( c === 0x5C /* \ */ && (end+1) < len ) {
                const d = query.charCodeAt(end+1);
                if ( d === targetCharCode ) {
                    parts.push(query.slice(beg, end));
                    end += 1;
                    beg = end;
                }
            }
            end += 1;
        }
        return { s: parts.join(''), i: end };
    }
    #compileExpr(query, step, i) {
        if ( query.startsWith('=/', i) ) {
            const r = this.#untilChar(query, 0x2F /* / */, i+2);
            if ( r === undefined ) { return i; }
            const match = /^[i]/.exec(query.slice(r.i));
            try {
                step.rval = new RegExp(r.s, match && match[0] || undefined);
            } catch {
                return i;
            }
            step.op = 're';
            if ( match ) { r.i += match[0].length; }
            return r.i;
        }
        const match = this.#reExpr.exec(query.slice(i));
        if ( match === null ) { return i; }
        try {
            step.rval = JSON.parse(match[2]);
            step.op = match[1];
        } catch {
        }
        return i + match[1].length + match[2].length;
    }
    #resolvePath(path) {
        if ( path.length === 0 ) { return { value: this.#root }; }
        const key = path.at(-1);
        let obj = this.#root
        for ( let i = 0, n = path.length-1; i < n; i++ ) {
            obj = obj[path[i]];
        }
        return { obj, key, value: obj[key] };
    }
    #evaluateExpr(step, owner, key) {
        if ( owner === undefined || owner === null ) { return; }
        if ( typeof key === 'number' ) {
            if ( Array.isArray(owner) === false ) { return; }
        }
        const k = this.#normalizeKey(owner, key);
        const hasOwn = Object.hasOwn(owner, k);
        if ( step.op !== undefined && hasOwn === false ) { return; }
        const target = step.not !== true;
        const v = owner[k];
        let outcome = false;
        switch ( step.op ) {
        case '==': outcome = (v === step.rval) === target; break;
        case '!=': outcome = (v !== step.rval) === target; break;
        case  '<': outcome = (v < step.rval) === target; break;
        case '<=': outcome = (v <= step.rval) === target; break;
        case  '>': outcome = (v > step.rval) === target; break;
        case '>=': outcome = (v >= step.rval) === target; break;
        case '^=': outcome = `${v}`.startsWith(step.rval) === target; break;
        case '$=': outcome = `${v}`.endsWith(step.rval) === target; break;
        case '*=': outcome = `${v}`.includes(step.rval) === target; break;
        case 're': outcome = step.rval.test(`${v}`); break;
        default: outcome = hasOwn === target; break;
        }
        if ( outcome ) { return k; }
    }
    #modifyVal(obj, key) {
        let { modify, rval } = this.#compiled;
        if ( typeof rval === 'string' ) {
            rval = rval.replace('${now}', `${Date.now()}`);
        }
        switch ( modify ) {
        case undefined:
            obj[key] = rval;
            break;
        case '+': {
            if ( rval instanceof Object === false ) { return; }
            const lval = obj[key];
            if ( lval instanceof Object === false ) { return; }
            if ( Array.isArray(lval) ) { return; }
            for ( const [ k, v ] of Object.entries(rval) ) {
                lval[k] = v;
            }
            break;
        }
        case 'repl': {
            const lval = obj[key];
            if ( typeof lval !== 'string' ) { return; }
            if ( this.#compiled.re === undefined ) {
                this.#compiled.re = null;
                try {
                    this.#compiled.re = rval.regex !== undefined
                        ? new RegExp(rval.regex, rval.flags)
                        : new RegExp(rval.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
                } catch {
                }
            }
            if ( this.#compiled.re === null ) { return; }
            obj[key] = lval.replace(this.#compiled.re, rval.replacement);
            break;
        }
        default:
            break;
        }
    }
}

class RangeParser {
    constructor(s) {
        this.not = s.charAt(0) === '!';
        if ( this.not ) { s = s.slice(1); }
        if ( s === '' ) { return; }
        const pos = s.indexOf('-');
        if ( pos !== 0 ) {
            this.min = this.max = parseInt(s, 10) || 0;
        }
        if ( pos !== -1 ) {
            this.max = parseInt(s.slice(pos + 1), 10) || Number.MAX_SAFE_INTEGER;
        }
    }
    unbound() {
        return this.min === undefined && this.max === undefined;
    }
    test(v) {
        const n = Math.min(Math.max(Number(v) || 0, 0), Number.MAX_SAFE_INTEGER);
        if ( this.min === this.max ) {
            return (this.min === undefined || n === this.min) !== this.not;
        }
        if ( this.min === undefined ) {
            return (n <= this.max) !== this.not;
        }
        if ( this.max === undefined ) {
            return (n >= this.min) !== this.not;
        }
        return (n >= this.min && n <= this.max) !== this.not;
    }
}

function abortCurrentScript(...args) {
    runAtHtmlElementFn(( ) => {
        abortCurrentScriptFn(...args);
    });
}

function abortCurrentScriptFn(
    target = '',
    needle = '',
    context = ''
) {
    if ( typeof target !== 'string' ) { return; }
    if ( target === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('abort-current-script', target, needle, context);
    const reNeedle = safe.patternToRegex(needle);
    const reContext = safe.patternToRegex(context);
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 3);
    const thisScript = document.currentScript;
    const chain = safe.String_split.call(target, '.');
    let owner = window;
    let prop;
    for (;;) {
        prop = chain.shift();
        if ( chain.length === 0 ) { break; }
        if ( prop in owner === false ) { break; }
        owner = owner[prop];
        if ( owner instanceof Object === false ) { return; }
    }
    let value;
    let desc = Object.getOwnPropertyDescriptor(owner, prop);
    if (
        desc instanceof Object === false ||
        desc.get instanceof Function === false
    ) {
        value = owner[prop];
        desc = undefined;
    }
    const debug = shouldDebug(extraArgs);
    const exceptionToken = getExceptionTokenFn();
    const scriptTexts = new WeakMap();
    const textContentGetter = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent').get;
    const getScriptText = elem => {
        let text = textContentGetter.call(elem);
        if ( text.trim() !== '' ) { return text; }
        if ( scriptTexts.has(elem) ) { return scriptTexts.get(elem); }
        const [ , mime, content ] =
            /^data:([^,]*),(.+)$/.exec(elem.src.trim()) ||
            [ '', '', '' ];
        try {
            switch ( true ) {
            case mime.endsWith(';base64'):
                text = self.atob(content);
                break;
            default:
                text = self.decodeURIComponent(content);
                break;
            }
        } catch {
        }
        scriptTexts.set(elem, text);
        return text;
    };
    const validate = ( ) => {
        const e = document.currentScript;
        if ( e instanceof HTMLScriptElement === false ) { return; }
        if ( e === thisScript ) { return; }
        if ( context !== '' && reContext.test(e.src) === false ) {
            // eslint-disable-next-line no-debugger
            if ( debug === 'nomatch' || debug === 'all' ) { debugger; }
            return;
        }
        if ( safe.logLevel > 1 && context !== '' ) {
            safe.uboLog(logPrefix, `Matched src\n${e.src}`);
        }
        const scriptText = getScriptText(e);
        if ( reNeedle.test(scriptText) === false ) {
            // eslint-disable-next-line no-debugger
            if ( debug === 'nomatch' || debug === 'all' ) { debugger; }
            return;
        }
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `Matched text\n${scriptText}`);
        }
        // eslint-disable-next-line no-debugger
        if ( debug === 'match' || debug === 'all' ) { debugger; }
        safe.uboLog(logPrefix, 'Aborted');
        throw new ReferenceError(exceptionToken);
    };
    // eslint-disable-next-line no-debugger
    if ( debug === 'install' ) { debugger; }
    try {
        Object.defineProperty(owner, prop, {
            get: function() {
                validate();
                return desc instanceof Object
                    ? desc.get.call(owner)
                    : value;
            },
            set: function(a) {
                validate();
                if ( desc instanceof Object ) {
                    desc.set.call(owner, a);
                } else {
                    value = a;
                }
            }
        });
    } catch(ex) {
        safe.uboErr(logPrefix, `Error: ${ex}`);
    }
}

function abortOnPropertyRead(
    chain = ''
) {
    if ( typeof chain !== 'string' ) { return; }
    if ( chain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('abort-on-property-read', chain);
    const exceptionToken = getExceptionTokenFn();
    const abort = function() {
        safe.uboLog(logPrefix, 'Aborted');
        throw new ReferenceError(exceptionToken);
    };
    const makeProxy = function(owner, chain) {
        const pos = chain.indexOf('.');
        if ( pos === -1 ) {
            const desc = Object.getOwnPropertyDescriptor(owner, chain);
            if ( !desc || desc.get !== abort ) {
                Object.defineProperty(owner, chain, {
                    get: abort,
                    set: function(){}
                });
            }
            return;
        }
        const prop = chain.slice(0, pos);
        let v = owner[prop];
        chain = chain.slice(pos + 1);
        if ( v ) {
            makeProxy(v, chain);
            return;
        }
        const desc = Object.getOwnPropertyDescriptor(owner, prop);
        if ( desc && desc.set !== undefined ) { return; }
        Object.defineProperty(owner, prop, {
            get: function() { return v; },
            set: function(a) {
                v = a;
                if ( a instanceof Object ) {
                    makeProxy(a, chain);
                }
            }
        });
    };
    const owner = window;
    makeProxy(owner, chain);
}

function abortOnPropertyWrite(
    prop = ''
) {
    if ( typeof prop !== 'string' ) { return; }
    if ( prop === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('abort-on-property-write', prop);
    const exceptionToken = getExceptionTokenFn();
    let owner = window;
    for (;;) {
        const pos = prop.indexOf('.');
        if ( pos === -1 ) { break; }
        owner = owner[prop.slice(0, pos)];
        if ( owner instanceof Object === false ) { return; }
        prop = prop.slice(pos + 1);
    }
    delete owner[prop];
    Object.defineProperty(owner, prop, {
        set: function() {
            safe.uboLog(logPrefix, 'Aborted');
            throw new ReferenceError(exceptionToken);
        }
    });
}

function abortOnStackTrace(
    chain = '',
    needle = ''
) {
    if ( typeof chain !== 'string' ) { return; }
    const safe = safeSelf();
    const needleDetails = safe.initPattern(needle, { canNegate: true });
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    if ( needle === '' ) { extraArgs.log = 'all'; }
    const makeProxy = function(owner, chain) {
        const pos = chain.indexOf('.');
        if ( pos === -1 ) {
            let v = owner[chain];
            Object.defineProperty(owner, chain, {
                get: function() {
                    const log = safe.logLevel > 1 ? 'all' : 'match';
                    if ( matchesStackTraceFn(needleDetails, log) ) {
                        throw new ReferenceError(getExceptionTokenFn());
                    }
                    return v;
                },
                set: function(a) {
                    const log = safe.logLevel > 1 ? 'all' : 'match';
                    if ( matchesStackTraceFn(needleDetails, log) ) {
                        throw new ReferenceError(getExceptionTokenFn());
                    }
                    v = a;
                },
            });
            return;
        }
        const prop = chain.slice(0, pos);
        let v = owner[prop];
        chain = chain.slice(pos + 1);
        if ( v ) {
            makeProxy(v, chain);
            return;
        }
        const desc = Object.getOwnPropertyDescriptor(owner, prop);
        if ( desc && desc.set !== undefined ) { return; }
        Object.defineProperty(owner, prop, {
            get: function() { return v; },
            set: function(a) {
                v = a;
                if ( a instanceof Object ) {
                    makeProxy(a, chain);
                }
            }
        });
    };
    const owner = window;
    makeProxy(owner, chain);
}

function adjustSetInterval(
    needleArg = '',
    delayArg = '',
    boostArg = ''
) {
    if ( typeof needleArg !== 'string' ) { return; }
    const safe = safeSelf();
    const reNeedle = safe.patternToRegex(needleArg);
    let delay = delayArg !== '*' ? parseInt(delayArg, 10) : -1;
    if ( isNaN(delay) || isFinite(delay) === false ) { delay = 1000; }
    let boost = parseFloat(boostArg);
    boost = isNaN(boost) === false && isFinite(boost)
        ? Math.min(Math.max(boost, 0.001), 50)
        : 0.05;
    self.setInterval = new Proxy(self.setInterval, {
        apply: function(target, thisArg, args) {
            const [ a, b ] = args;
            if (
                (delay === -1 || b === delay) &&
                reNeedle.test(a.toString())
            ) {
                args[1] = b * boost;
            }
            return target.apply(thisArg, args);
        }
    });
}

function adjustSetTimeout(
    needleArg = '',
    delayArg = '',
    boostArg = ''
) {
    if ( typeof needleArg !== 'string' ) { return; }
    const safe = safeSelf();
    const reNeedle = safe.patternToRegex(needleArg);
    let delay = delayArg !== '*' ? parseInt(delayArg, 10) : -1;
    if ( isNaN(delay) || isFinite(delay) === false ) { delay = 1000; }
    let boost = parseFloat(boostArg);
    boost = isNaN(boost) === false && isFinite(boost)
        ? Math.min(Math.max(boost, 0.001), 50)
        : 0.05;
    self.setTimeout = new Proxy(self.setTimeout, {
        apply: function(target, thisArg, args) {
            const [ a, b ] = args;
            if (
                (delay === -1 || b === delay) &&
                reNeedle.test(a.toString())
            ) {
                args[1] = b * boost;
            }
            return target.apply(thisArg, args);
        }
    });
}

function alertBuster() {
    window.alert = new Proxy(window.alert, {
        apply: function(a) {
            console.info(a);
        },
        get(target, prop) {
            if ( prop === 'toString' ) {
                return target.toString.bind(target);
            }
            return Reflect.get(target, prop);
        },
    });
}

function collateFetchArgumentsFn(resource, options) {
    const safe = safeSelf();
    const props = [
        'body', 'cache', 'credentials', 'duplex', 'headers',
        'integrity', 'keepalive', 'method', 'mode', 'priority',
        'redirect', 'referrer', 'referrerPolicy', 'url'
    ];
    const out = {};
    if ( collateFetchArgumentsFn.collateKnownProps === undefined ) {
        collateFetchArgumentsFn.collateKnownProps = (src, out) => {
            for ( const prop of props ) {
                if ( src[prop] === undefined ) { continue; }
                out[prop] = src[prop];
            }
        };
    }
    if (
        typeof resource !== 'object' ||
        safe.Object_toString.call(resource) !== '[object Request]'
    ) {
        out.url = `${resource}`;
    } else {
        let clone;
        try {
            clone = safe.Request_clone.call(resource);
        } catch {
        }
        collateFetchArgumentsFn.collateKnownProps(clone || resource, out);
    }
    if ( typeof options === 'object' && options !== null ) {
        collateFetchArgumentsFn.collateKnownProps(options, out);
    }
    return out;
}

function disableNewtabLinks() {
    document.addEventListener('click', ev => {
        let target = ev.target;
        while ( target !== null ) {
            if ( target.localName === 'a' && target.hasAttribute('target') ) {
                ev.stopPropagation();
                ev.preventDefault();
                break;
            }
            target = target.parentNode;
        }
    }, { capture: true });
}

function editInboundObjectFn(
    trusted = false,
    propChain = '',
    argPosRaw = '',
    jsonq = '',
) {
    if ( propChain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}edit-inbound-object`,
        propChain,
        jsonq
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const argPos = parseInt(argPosRaw, 10);
    if ( isNaN(argPos) ) { return; }
    const getArgPos = args => {
        if ( Array.isArray(args) === false ) { return; }
        if ( argPos >= 0 ) {
            if ( args.length <= argPos ) { return; }
            return argPos;
        }
        if ( args.length < -argPos ) { return; }
        return args.length + argPos;
    };
    const editObj = obj => {
        let clone;
        try {
            clone = safe.JSON_parse(safe.JSON_stringify(obj));
        } catch {
        }
        if ( typeof clone !== 'object' || clone === null ) { return; }
        const objAfter = jsonp.apply(clone);
        if ( objAfter === undefined ) { return; }
        safe.uboLog(logPrefix, 'Edited');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `After edit:\n${safe.JSON_stringify(objAfter, null, 2)}`);
        }
        return objAfter;
    };
    proxyApplyFn(propChain, function(context) {
        const i = getArgPos(context.callArgs);
        if ( i !== undefined ) {
            const obj = editObj(context.callArgs[i]);
            if ( obj ) {
                context.callArgs[i] = obj;
            }
        }
        return context.reflect();
    });
}

function editOutboundObjectFn(
    trusted = false,
    propChain = '',
    jsonq = '',
) {
    if ( propChain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}edit-outbound-object`,
        propChain,
        jsonq
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    proxyApplyFn(propChain, function(context) {
        const obj = context.reflect();
        const objAfter = jsonp.apply(obj);
        if ( objAfter === undefined ) { return obj; }
        safe.uboLog(logPrefix, 'Edited');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `After edit:\n${safe.JSON_stringify(objAfter, null, 2)}`);
        }
        return objAfter;
    });
}

function freezeElementProperty(
    property = '',
    selector = '',
    pattern = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('freeze-element-property', property, selector, pattern);
    const matcher = safe.initPattern(pattern, { canNegate: true });
    const owner = (( ) => {
        if ( Object.hasOwn(Element.prototype, property) ) {
            return Element.prototype;
        }
        if ( Object.hasOwn(HTMLElement.prototype, property) ) {
            return HTMLElement.prototype;
        }
        if ( Object.hasOwn(Node.prototype, property) ) {
            return Node.prototype;
        }
        return null;
    })();
    if ( owner === null ) { return; }
    const current = safe.Object_getOwnPropertyDescriptor(owner, property);
    if ( current === undefined ) { return; }
    const shouldPreventSet = (elem, a) => {
        if ( selector !== '' ) {
            if ( typeof elem.matches !== 'function' ) { return false; }
            if ( elem.matches(selector) === false ) { return false; }
        }
        return safe.testPattern(matcher, `${a}`);
    };
    Object.defineProperty(owner, property, {
        get: function() {
            return current.get
                ? current.get.call(this)
                : current.value;
        },
        set: function(a) {
            if ( shouldPreventSet(this, a) ) {
                safe.uboLog(logPrefix, 'Assignment prevented');
            } else if ( current.set ) {
                current.set.call(this, a);
            }
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Assigned:\n${a}`);
            }
            current.value = a;
        },
    });
}

function generateContentFn(trusted, directive) {
    const safe = safeSelf();
    const randomize = len => {
        const chunks = [];
        let textSize = 0;
        do {
            const s = safe.Math_random().toString(36).slice(2);
            chunks.push(s);
            textSize += s.length;
        }
        while ( textSize < len );
        return chunks.join(' ').slice(0, len);
    };
    if ( directive === 'true' ) {
        return randomize(10);
    }
    if ( directive === 'emptyObj' ) {
        return '{}';
    }
    if ( directive === 'emptyArr' ) {
        return '[]';
    }
    if ( directive === 'emptyStr' ) {
        return '';
    }
    if ( directive.startsWith('length:') ) {
        const match = /^length:(\d+)(?:-(\d+))?$/.exec(directive);
        if ( match === null ) { return ''; }
        const min = parseInt(match[1], 10);
        const extent = safe.Math_max(parseInt(match[2], 10) || 0, min) - min;
        const len = safe.Math_min(min + extent * safe.Math_random(), 500000);
        return randomize(len | 0);
    }
    if ( directive.startsWith('war:') ) {
        if ( scriptletGlobals.warOrigin === undefined ) { return ''; }
        return new Promise(resolve => {
            const warOrigin = scriptletGlobals.warOrigin;
            const warName = directive.slice(4);
            const fullpath = [ warOrigin, '/', warName ];
            const warSecret = scriptletGlobals.warSecret;
            if ( warSecret !== undefined ) {
                fullpath.push('?secret=', warSecret);
            }
            const warXHR = new safe.XMLHttpRequest();
            warXHR.responseType = 'text';
            warXHR.onloadend = ev => {
                resolve(ev.target.responseText || '');
            };
            warXHR.open('GET', fullpath.join(''));
            warXHR.send();
        }).catch(( ) => '');
    }
    if ( directive.startsWith('join:') ) {
        const parts = directive.slice(7)
                .split(directive.slice(5, 7))
                .map(a => generateContentFn(trusted, a));
        return parts.some(a => a instanceof Promise)
            ? Promise.all(parts).then(parts => parts.join(''))
            : parts.join('');
    }
    if ( trusted ) {
        return directive;
    }
    return '';
}

function getExceptionTokenFn() {
    const token = getRandomTokenFn();
    const oe = self.onerror;
    self.onerror = function(msg, ...args) {
        if ( typeof msg === 'string' && msg.includes(token) ) { return true; }
        if ( oe instanceof Function ) {
            return oe.call(this, msg, ...args);
        }
    }.bind();
    return token;
}

function getRandomTokenFn() {
    const safe = safeSelf();
    return safe.String_fromCharCode(Date.now() % 26 + 97) +
        safe.Math_floor(safe.Math_random() * 982451653 + 982451653).toString(36);
}

function jsonEdit(jsonq = '') {
    editOutboundObjectFn(false, 'JSON.parse', jsonq);
}

function jsonEditFetchRequest(jsonq = '', ...args) {
    jsonEditFetchRequestFn(false, jsonq, ...args);
}

function jsonEditFetchRequestFn(trusted, jsonq = '') {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}json-edit-fetch-request`,
        jsonq
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    const filterBody = body => {
        if ( typeof body !== 'string' ) { return; }
        let data;
        try { data = safe.JSON_parse(body); }
        catch { }
        if ( data instanceof Object === false ) { return; }
        const objAfter = jsonp.apply(data);
        if ( objAfter === undefined ) { return; }
        return safe.JSON_stringify(objAfter);
    }
    const proxyHandler = context => {
        const args = context.callArgs;
        const [ resource, options ] = args;
        const bodyBefore = options?.body;
        if ( Boolean(bodyBefore) === false ) { return context.reflect(); }
        const bodyAfter = filterBody(bodyBefore);
        if ( bodyAfter === undefined || bodyAfter === bodyBefore ) {
            return context.reflect();
        }
        if ( propNeedles.size !== 0 ) {
            const props = collateFetchArgumentsFn(resource, options);
            const matched = matchObjectPropertiesFn(propNeedles, props);
            if ( matched === undefined ) { return context.reflect(); }
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
            }
        }
        safe.uboLog(logPrefix, 'Edited');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `After edit:\n${bodyAfter}`);
        }
        options.body = bodyAfter;
        return context.reflect();
    };
    proxyApplyFn('fetch', proxyHandler);
    proxyApplyFn('Request', proxyHandler);
}

function jsonEditFetchResponse(jsonq = '', ...args) {
    jsonEditFetchResponseFn(false, jsonq, ...args);
}

function jsonEditFetchResponseFn(trusted, jsonq = '') {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}json-edit-fetch-response`,
        jsonq
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    proxyApplyFn('fetch', function(context) {
        const args = context.callArgs;
        const fetchPromise = context.reflect();
        if ( propNeedles.size !== 0 ) {
            const props = collateFetchArgumentsFn(...args);
            const matched = matchObjectPropertiesFn(propNeedles, props);
            if ( matched === undefined ) { return fetchPromise; }
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
            }
        }
        return fetchPromise.then(responseBefore => {
            const response = responseBefore.clone();
            return response.json().then(obj => {
                if ( typeof obj !== 'object' ) { return responseBefore; }
                const objAfter = jsonp.apply(obj);
                if ( objAfter === undefined ) { return responseBefore; }
                safe.uboLog(logPrefix, 'Edited');
                const responseAfter = Response.json(objAfter, {
                    status: responseBefore.status,
                    statusText: responseBefore.statusText,
                    headers: responseBefore.headers,
                });
                Object.defineProperties(responseAfter, {
                    ok: { value: responseBefore.ok },
                    redirected: { value: responseBefore.redirected },
                    type: { value: responseBefore.type },
                    url: { value: responseBefore.url },
                });
                return responseAfter;
            }).catch(reason => {
                safe.uboErr(logPrefix, 'Error:', reason);
                return responseBefore;
            });
        }).catch(reason => {
            safe.uboErr(logPrefix, 'Error:', reason);
            return fetchPromise;
        });
    });
}

function jsonEditXhrRequestFn(trusted, jsonq = '') {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}json-edit-xhr-request`,
        jsonq
    );
    const xhrInstances = new WeakMap();
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const xhrDetails = { method, url };
            const matched = propNeedles.size === 0 ||
                matchObjectPropertiesFn(propNeedles, xhrDetails);
            if ( matched ) {
                if ( safe.logLevel > 1 && Array.isArray(matched) ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
                }
                xhrInstances.set(this, xhrDetails);
            }
            return super.open(method, url, ...args);
        }
        send(body) {
            const xhrDetails = xhrInstances.get(this);
            if ( xhrDetails ) {
                body = this.#filterBody(body) || body;
            }
            super.send(body);
        }
        #filterBody(body) {
            if ( typeof body !== 'string' ) { return; }
            let data;
            try { data = safe.JSON_parse(body); }
            catch { }
            if ( data instanceof Object === false ) { return; }
            const objAfter = jsonp.apply(data);
            if ( objAfter === undefined ) { return; }
            body = safe.JSON_stringify(objAfter);
            safe.uboLog(logPrefix, 'Edited');
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `After edit:\n${body}`);
            }
            return body;
        }
    };
}

function jsonEditXhrResponse(jsonq = '', ...args) {
    jsonEditXhrResponseFn(false, jsonq, ...args);
}

function jsonEditXhrResponseFn(trusted, jsonq = '') {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}json-edit-xhr-response`,
        jsonq
    );
    const xhrInstances = new WeakMap();
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const xhrDetails = { method, url };
            const matched = propNeedles.size === 0 ||
                matchObjectPropertiesFn(propNeedles, xhrDetails);
            if ( matched ) {
                if ( safe.logLevel > 1 && Array.isArray(matched) ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
                }
                xhrInstances.set(this, xhrDetails);
            }
            return super.open(method, url, ...args);
        }
        get response() {
            const innerResponse = super.response;
            const xhrDetails = xhrInstances.get(this);
            if ( xhrDetails === undefined ) { return innerResponse; }
            const responseLength = typeof innerResponse === 'string'
                ? innerResponse.length
                : undefined;
            if ( xhrDetails.lastResponseLength !== responseLength ) {
                xhrDetails.response = undefined;
                xhrDetails.lastResponseLength = responseLength;
            }
            if ( xhrDetails.response !== undefined ) {
                return xhrDetails.response;
            }
            let obj;
            if ( typeof innerResponse === 'object' ) {
                obj = innerResponse;
            } else if ( typeof innerResponse === 'string' ) {
                try { obj = safe.JSON_parse(innerResponse); } catch { }
            }
            if ( typeof obj !== 'object' || obj === null ) {
                return (xhrDetails.response = innerResponse);
            }
            const objAfter = jsonp.apply(obj);
            if ( objAfter === undefined ) {
                return (xhrDetails.response = innerResponse);
            }
            safe.uboLog(logPrefix, 'Edited');
            const outerResponse = typeof innerResponse === 'string'
                ? JSONPath.toJSON(objAfter, safe.JSON_stringify)
                : objAfter;
            return (xhrDetails.response = outerResponse);
        }
        get responseText() {
            const response = this.response;
            return typeof response !== 'string'
                ? super.responseText
                : response;
        }
    };
}

function jsonPrune(
    rawPrunePaths = '',
    rawNeedlePaths = '',
    stackNeedle = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('json-prune', rawPrunePaths, rawNeedlePaths, stackNeedle);
    const stackNeedleDetails = safe.initPattern(stackNeedle, { canNegate: true });
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 3);
    proxyApplyFn('JSON.parse', function(context) {
        const objBefore = context.reflect();
        if ( rawPrunePaths === '' ) {
            safe.uboLog(logPrefix, safe.JSON_stringify(objBefore, null, 2));
        }
        const objAfter = objectPruneFn(
            objBefore,
            rawPrunePaths,
            rawNeedlePaths,
            stackNeedleDetails,
            extraArgs
        );
        if ( objAfter === undefined ) { return objBefore; }
        safe.uboLog(logPrefix, 'Pruned');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `After pruning:\n${safe.JSON_stringify(objAfter, null, 2)}`);
        }
        return objAfter;
    });
}

function jsonPruneFetchResponse(
    rawPrunePaths = '',
    rawNeedlePaths = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('json-prune-fetch-response', rawPrunePaths, rawNeedlePaths);
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    const stackNeedle = safe.initPattern(extraArgs.stackToMatch || '', { canNegate: true });
    const logall = rawPrunePaths === '';
    const applyHandler = function(target, thisArg, args) {
        const fetchPromise = Reflect.apply(target, thisArg, args);
        if ( propNeedles.size !== 0 ) {
            const props = collateFetchArgumentsFn(...args);
            const matched = matchObjectPropertiesFn(propNeedles, props);
            if ( matched === undefined ) { return fetchPromise; }
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
            }
        }
        return fetchPromise.then(responseBefore => {
            const response = responseBefore.clone();
            return response.json().then(objBefore => {
                if ( typeof objBefore !== 'object' ) { return responseBefore; }
                if ( logall ) {
                    safe.uboLog(logPrefix, safe.JSON_stringify(objBefore, null, 2));
                    return responseBefore;
                }
                const objAfter = objectPruneFn(
                    objBefore,
                    rawPrunePaths,
                    rawNeedlePaths,
                    stackNeedle,
                    extraArgs
                );
                if ( typeof objAfter !== 'object' ) { return responseBefore; }
                safe.uboLog(logPrefix, 'Pruned');
                const responseAfter = Response.json(objAfter, {
                    status: responseBefore.status,
                    statusText: responseBefore.statusText,
                    headers: responseBefore.headers,
                });
                Object.defineProperties(responseAfter, {
                    ok: { value: responseBefore.ok },
                    redirected: { value: responseBefore.redirected },
                    type: { value: responseBefore.type },
                    url: { value: responseBefore.url },
                });
                return responseAfter;
            }).catch(reason => {
                safe.uboErr(logPrefix, 'Error:', reason);
                return responseBefore;
            });
        }).catch(reason => {
            safe.uboErr(logPrefix, 'Error:', reason);
            return fetchPromise;
        });
    };
    self.fetch = new Proxy(self.fetch, {
        apply: applyHandler
    });
}

function jsonPruneXhrResponse(
    rawPrunePaths = '',
    rawNeedlePaths = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('json-prune-xhr-response', rawPrunePaths, rawNeedlePaths);
    const xhrInstances = new WeakMap();
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    const stackNeedle = safe.initPattern(extraArgs.stackToMatch || '', { canNegate: true });
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const xhrDetails = { method, url };
            let outcome = 'match';
            if ( propNeedles.size !== 0 ) {
                if ( matchObjectPropertiesFn(propNeedles, xhrDetails) === undefined ) {
                    outcome = 'nomatch';
                }
            }
            if ( outcome === 'match' ) {
                if ( safe.logLevel > 1 ) {
                    safe.uboLog(logPrefix, `Matched optional "propsToMatch", "${extraArgs.propsToMatch}"`);
                }
                xhrInstances.set(this, xhrDetails);
            }
            return super.open(method, url, ...args);
        }
        get response() {
            const innerResponse = super.response;
            const xhrDetails = xhrInstances.get(this);
            if ( xhrDetails === undefined ) {
                return innerResponse;
            }
            const responseLength = typeof innerResponse === 'string'
                ? innerResponse.length
                : undefined;
            if ( xhrDetails.lastResponseLength !== responseLength ) {
                xhrDetails.response = undefined;
                xhrDetails.lastResponseLength = responseLength;
            }
            if ( xhrDetails.response !== undefined ) {
                return xhrDetails.response;
            }
            let objBefore;
            if ( typeof innerResponse === 'object' ) {
                objBefore = innerResponse;
            } else if ( typeof innerResponse === 'string' ) {
                try {
                    objBefore = safe.JSON_parse(innerResponse);
                } catch {
                }
            }
            if ( typeof objBefore !== 'object' ) {
                return (xhrDetails.response = innerResponse);
            }
            const objAfter = objectPruneFn(
                objBefore,
                rawPrunePaths,
                rawNeedlePaths,
                stackNeedle,
                extraArgs
            );
            let outerResponse;
            if ( typeof objAfter === 'object' ) {
                outerResponse = typeof innerResponse === 'string'
                    ? safe.JSON_stringify(objAfter)
                    : objAfter;
                safe.uboLog(logPrefix, 'Pruned');
            } else {
                outerResponse = innerResponse;
            }
            return (xhrDetails.response = outerResponse);
        }
        get responseText() {
            const response = this.response;
            return typeof response !== 'string'
                ? super.responseText
                : response;
        }
    };
}

function jsonlEditFn(jsonp, text = '') {
    const safe = safeSelf();
    const lineSeparator = /\r?\n/.exec(text)?.[0] || '\n';
    const linesBefore = text.split('\n');
    const linesAfter = [];
    for ( const lineBefore of linesBefore ) {
        let obj;
        try { obj = safe.JSON_parse(lineBefore); } catch { }
        if ( typeof obj !== 'object' || obj === null ) {
            linesAfter.push(lineBefore);
            continue;
        }
        const objAfter = jsonp.apply(obj);
        if ( objAfter === undefined ) {
            linesAfter.push(lineBefore);
            continue;
        }
        const lineAfter = safe.JSON_stringify(objAfter);
        linesAfter.push(lineAfter);
    }
    return linesAfter.join(lineSeparator);
}

function jsonlEditXhrResponse(jsonq = '', ...args) {
    jsonlEditXhrResponseFn(false, jsonq, ...args);
}

function jsonlEditXhrResponseFn(trusted, jsonq = '') {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}jsonl-edit-xhr-response`,
        jsonq
    );
    const xhrInstances = new WeakMap();
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const xhrDetails = { method, url };
            const matched = propNeedles.size === 0 ||
                matchObjectPropertiesFn(propNeedles, xhrDetails);
            if ( matched ) {
                if ( safe.logLevel > 1 && Array.isArray(matched) ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
                }
                xhrInstances.set(this, xhrDetails);
            }
            return super.open(method, url, ...args);
        }
        get response() {
            const innerResponse = super.response;
            const xhrDetails = xhrInstances.get(this);
            if ( xhrDetails === undefined ) {
                return innerResponse;
            }
            const responseLength = typeof innerResponse === 'string'
                ? innerResponse.length
                : undefined;
            if ( xhrDetails.lastResponseLength !== responseLength ) {
                xhrDetails.response = undefined;
                xhrDetails.lastResponseLength = responseLength;
            }
            if ( xhrDetails.response !== undefined ) {
                return xhrDetails.response;
            }
            if ( typeof innerResponse !== 'string' ) {
                return (xhrDetails.response = innerResponse);
            }
            const outerResponse = jsonlEditFn(jsonp, innerResponse);
            if ( outerResponse !== innerResponse ) {
                safe.uboLog(logPrefix, 'Pruned');
            }
            return (xhrDetails.response = outerResponse);
        }
        get responseText() {
            const response = this.response;
            return typeof response !== 'string'
                ? super.responseText
                : response;
        }
    };
}

function m3uPrune(
    m3uPattern = '',
    urlPattern = ''
) {
    if ( typeof m3uPattern !== 'string' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('m3u-prune', m3uPattern, urlPattern);
    const toLog = [];
    const regexFromArg = arg => {
        if ( arg === '' ) { return /^/; }
        const match = /^\/(.+)\/([gms]*)$/.exec(arg);
        if ( match !== null ) {
            let flags = match[2] || '';
            if ( flags.includes('m') ) { flags += 's'; }
            return new RegExp(match[1], flags);
        }
        return new RegExp(
            arg.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*+/g, '.*?')
        );
    };
    const reM3u = regexFromArg(m3uPattern);
    const reUrl = regexFromArg(urlPattern);
    const pruneSpliceoutBlock = (lines, i) => {
        if ( lines[i].startsWith('#EXT-X-CUE:TYPE="SpliceOut"') === false ) {
            return false;
        }
        toLog.push(`\t${lines[i]}`);
        lines[i] = undefined; i += 1;
        if ( lines[i].startsWith('#EXT-X-ASSET:CAID') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        if ( lines[i].startsWith('#EXT-X-SCTE35:') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        if ( lines[i].startsWith('#EXT-X-CUE-IN') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        if ( lines[i].startsWith('#EXT-X-SCTE35:') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        return true;
    };
    const pruneInfBlock = (lines, i) => {
        if ( lines[i].startsWith('#EXTINF') === false ) { return false; }
        if ( reM3u.test(lines[i+1]) === false ) { return false; }
        toLog.push('Discarding', `\t${lines[i]}, \t${lines[i+1]}`);
        lines[i] = lines[i+1] = undefined; i += 2;
        if ( lines[i].startsWith('#EXT-X-DISCONTINUITY') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        return true;
    };
    const pruner = text => {
        if ( (/^\s*#EXTM3U/.test(text)) === false ) { return text; }
        if ( m3uPattern === '' ) {
            safe.uboLog(` Content:\n${text}`);
            return text;
        }
        if ( reM3u.multiline ) {
            reM3u.lastIndex = 0;
            for (;;) {
                const match = reM3u.exec(text);
                if ( match === null ) { break; }
                let discard = match[0];
                let before = text.slice(0, match.index);
                if (
                    /^[\n\r]+/.test(discard) === false &&
                    /[\n\r]+$/.test(before) === false
                ) {
                    const startOfLine = /[^\n\r]+$/.exec(before);
                    if ( startOfLine !== null ) {
                        before = before.slice(0, startOfLine.index);
                        discard = startOfLine[0] + discard;
                    }
                }
                let after = text.slice(match.index + match[0].length);
                if (
                    /[\n\r]+$/.test(discard) === false &&
                    /^[\n\r]+/.test(after) === false
                ) {
                    const endOfLine = /^[^\n\r]+/.exec(after);
                    if ( endOfLine !== null ) {
                        after = after.slice(endOfLine.index);
                        discard += discard + endOfLine[0];
                    }
                }
                text = before.trim() + '\n' + after.trim();
                reM3u.lastIndex = before.length + 1;
                toLog.push('Discarding', ...safe.String_split.call(discard, /\n+/).map(s => `\t${s}`));
                if ( reM3u.global === false ) { break; }
            }
            return text;
        }
        const lines = safe.String_split.call(text, /\n\r|\n|\r/);
        for ( let i = 0; i < lines.length; i++ ) {
            if ( lines[i] === undefined ) { continue; }
            if ( pruneSpliceoutBlock(lines, i) ) { continue; }
            if ( pruneInfBlock(lines, i) ) { continue; }
        }
        return lines.filter(l => l !== undefined).join('\n');
    };
    const urlFromArg = arg => {
        if ( typeof arg === 'string' ) { return arg; }
        if ( arg instanceof Request ) { return arg.url; }
        return String(arg);
    };
    proxyApplyFn('fetch', async function fetch(context) {
        const args = context.callArgs;
        const fetchPromise = context.reflect();
        if ( reUrl.test(urlFromArg(args[0])) === false ) { return fetchPromise; }
        const responseBefore = await fetchPromise;
        const responseClone = responseBefore.clone();
        const textBefore = await responseClone.text();
        const textAfter = pruner(textBefore);
        if ( textAfter === textBefore ) { return responseBefore; }
        const responseAfter = new Response(textAfter, {
            status: responseBefore.status,
            statusText: responseBefore.statusText,
            headers: responseBefore.headers,
        });
        Object.defineProperties(responseAfter, {
            url: { value: responseBefore.url },
            type: { value: responseBefore.type },
        });
        if ( toLog.length !== 0 ) {
            toLog.unshift(logPrefix);
            safe.uboLog(toLog.join('\n'));
        }
        return responseAfter;
    })
    self.XMLHttpRequest.prototype.open = new Proxy(self.XMLHttpRequest.prototype.open, {
        apply: async (target, thisArg, args) => {
            if ( reUrl.test(urlFromArg(args[1])) === false ) {
                return Reflect.apply(target, thisArg, args);
            }
            thisArg.addEventListener('readystatechange', function() {
                if ( thisArg.readyState !== 4 ) { return; }
                const type = thisArg.responseType;
                if ( type !== '' && type !== 'text' ) { return; }
                const textin = thisArg.responseText;
                const textout = pruner(textin);
                if ( textout === textin ) { return; }
                Object.defineProperty(thisArg, 'response', { value: textout });
                Object.defineProperty(thisArg, 'responseText', { value: textout });
                if ( toLog.length !== 0 ) {
                    toLog.unshift(logPrefix);
                    safe.uboLog(toLog.join('\n'));
                }
            });
            return Reflect.apply(target, thisArg, args);
        }
    });
}

function matchObjectPropertiesFn(propNeedles, ...objs) {
    const safe = safeSelf();
    const matched = [];
    for ( const obj of objs ) {
        if ( obj instanceof Object === false ) { continue; }
        for ( const [ prop, details ] of propNeedles ) {
            let value = obj[prop];
            if ( value === undefined ) { continue; }
            if ( typeof value !== 'string' ) {
                try { value = safe.JSON_stringify(value); }
                catch { }
                if ( typeof value !== 'string' ) { continue; }
            }
            if ( safe.testPattern(details, value) === false ) { return; }
            matched.push(`${prop}: ${value}`);
        }
    }
    return matched;
}

function matchesStackTraceFn(
    needleDetails,
    logLevel = ''
) {
    const safe = safeSelf();
    const exceptionToken = getExceptionTokenFn();
    const error = new safe.Error(exceptionToken);
    const docURL = new URL(self.location.href);
    docURL.hash = '';
    // Normalize stack trace
    const reLine = /(.*?@)?(\S+)(:\d+):\d+\)?$/;
    const lines = [];
    for ( let line of safe.String_split.call(error.stack, /[\n\r]+/) ) {
        if ( line.includes(exceptionToken) ) { continue; }
        line = line.trim();
        const match = safe.RegExp_exec.call(reLine, line);
        if ( match === null ) { continue; }
        let url = match[2];
        if ( url.startsWith('(') ) { url = url.slice(1); }
        if ( url === docURL.href ) {
            url = 'inlineScript';
        } else if ( url.startsWith('<anonymous>') ) {
            url = 'injectedScript';
        }
        let fn = match[1] !== undefined
            ? match[1].slice(0, -1)
            : line.slice(0, match.index).trim();
        if ( fn.startsWith('at') ) { fn = fn.slice(2).trim(); }
        let rowcol = match[3];
        lines.push(' ' + `${fn} ${url}${rowcol}:1`.trim());
    }
    lines[0] = `stackDepth:${lines.length-1}`;
    const stack = lines.join('\t');
    const r = needleDetails.matchAll !== true &&
        safe.testPattern(needleDetails, stack);
    if (
        logLevel === 'all' ||
        logLevel === 'match' && r ||
        logLevel === 'nomatch' && !r
    ) {
        safe.uboLog(stack.replace(/\t/g, '\n'));
    }
    return r;
}

function noEvalIf(
    needle = ''
) {
    if ( typeof needle !== 'string' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('noeval-if', needle);
    const reNeedle = safe.patternToRegex(needle);
    proxyApplyFn('eval', function(context) {
        const { callArgs } = context;
        const a = String(callArgs[0]);
        if ( needle !== '' && reNeedle.test(a) ) {
            safe.uboLog(logPrefix, 'Prevented:\n', a);
            return;
        }
        if ( needle === '' || safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, 'Not prevented:\n', a);
        }
        return context.reflect();
    });
}

function noWebrtc() {
    var rtcName = window.RTCPeerConnection ? 'RTCPeerConnection' : (
        window.webkitRTCPeerConnection ? 'webkitRTCPeerConnection' : ''
    );
    if ( rtcName === '' ) { return; }
    var log = console.log.bind(console);
    var pc = function(cfg) {
        log('Document tried to create an RTCPeerConnection: %o', cfg);
    };
    const noop = function() {
    };
    pc.prototype = {
        close: noop,
        createDataChannel: noop,
        createOffer: noop,
        setRemoteDescription: noop,
        toString: function() {
            return '[object RTCPeerConnection]';
        }
    };
    var z = window[rtcName];
    window[rtcName] = pc.bind(window);
    if ( z.prototype ) {
        z.prototype.createDataChannel = function() {
            return {
                close: function() {},
                send: function() {}
            };
        }.bind(null);
    }
}

function noWindowOpenIf(
    pattern = '',
    delay = '',
    decoy = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('no-window-open-if', pattern, delay, decoy);
    const targetMatchResult = pattern.startsWith('!') === false;
    if ( targetMatchResult === false ) {
        pattern = pattern.slice(1);
    }
    const rePattern = safe.patternToRegex(pattern);
    const autoRemoveAfter = (parseFloat(delay) || 0) * 1000;
    const setTimeout = self.setTimeout;
    const createDecoy = function(tag, urlProp, url) {
        const decoyElem = document.createElement(tag);
        decoyElem[urlProp] = url;
        decoyElem.style.setProperty('height','1px', 'important');
        decoyElem.style.setProperty('position','fixed', 'important');
        decoyElem.style.setProperty('top','-1px', 'important');
        decoyElem.style.setProperty('width','1px', 'important');
        document.body.appendChild(decoyElem);
        setTimeout(( ) => { decoyElem.remove(); }, autoRemoveAfter);
        return decoyElem;
    };
    const noopFunc = function(){};
    proxyApplyFn('open', function open(context) {
        if ( pattern === 'debug' && safe.logLevel !== 0 ) {
            debugger; // eslint-disable-line no-debugger
            return context.reflect();
        }
        const { callArgs } = context;
        const haystack = callArgs.join(' ');
        if ( rePattern.test(haystack) !== targetMatchResult ) {
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Allowed (${callArgs.join(', ')})`);
            }
            return context.reflect();
        }
        safe.uboLog(logPrefix, `Prevented (${callArgs.join(', ')})`);
        if ( delay === '' ) { return null; }
        if ( decoy === 'blank' ) {
            callArgs[0] = 'about:blank';
            const r = context.reflect();
            setTimeout(( ) => { r.close(); }, autoRemoveAfter);
            return r;
        }
        const decoyElem = decoy === 'obj'
            ? createDecoy('object', 'data', ...callArgs)
            : createDecoy('iframe', 'src', ...callArgs);
        let popup = decoyElem.contentWindow;
        if ( typeof popup === 'object' && popup !== null ) {
            Object.defineProperty(popup, 'closed', { value: false });
        } else {
            popup = new Proxy(self, {
                get: function(target, prop, ...args) {
                    if ( prop === 'closed' ) { return false; }
                    const r = Reflect.get(target, prop, ...args);
                    if ( typeof r === 'function' ) { return noopFunc; }
                    return r;
                },
                set: function(...args) {
                    return Reflect.set(...args);
                },
            });
        }
        if ( safe.logLevel !== 0 ) {
            popup = new Proxy(popup, {
                get: function(target, prop, ...args) {
                    const r = Reflect.get(target, prop, ...args);
                    safe.uboLog(logPrefix, `popup / get ${prop} === ${r}`);
                    if ( typeof r === 'function' ) {
                        return (...args) => { return r.call(target, ...args); };
                    }
                    return r;
                },
                set: function(target, prop, value, ...args) {
                    safe.uboLog(logPrefix, `popup / set ${prop} = ${value}`);
                    return Reflect.set(target, prop, value, ...args);
                },
            });
        }
        return popup;
    });
}

function objectFindOwnerFn(
    root,
    path,
    prune = false
) {
    const safe = safeSelf();
    let owner = root;
    let chain = path;
    for (;;) {
        if ( typeof owner !== 'object' || owner === null  ) { return false; }
        const pos = chain.indexOf('.');
        if ( pos === -1 ) {
            if ( prune === false ) {
                return safe.Object_hasOwn(owner, chain);
            }
            let modified = false;
            if ( chain === '*' ) {
                for ( const key in owner ) {
                    if ( safe.Object_hasOwn(owner, key) === false ) { continue; }
                    delete owner[key];
                    modified = true;
                }
            } else if ( safe.Object_hasOwn(owner, chain) ) {
                delete owner[chain];
                modified = true;
            }
            return modified;
        }
        const prop = chain.slice(0, pos);
        const next = chain.slice(pos + 1);
        let found = false;
        if ( prop === '[-]' && Array.isArray(owner) ) {
            let i = owner.length;
            while ( i-- ) {
                if ( objectFindOwnerFn(owner[i], next) === false ) { continue; }
                owner.splice(i, 1);
                found = true;
            }
            return found;
        }
        if ( prop === '{-}' && owner instanceof Object ) {
            for ( const key of Object.keys(owner) ) {
                if ( objectFindOwnerFn(owner[key], next) === false ) { continue; }
                delete owner[key];
                found = true;
            }
            return found;
        }
        if (
            prop === '[]' && Array.isArray(owner) ||
            prop === '{}' && owner instanceof Object ||
            prop === '*' && owner instanceof Object
        ) {
            for ( const key of Object.keys(owner) ) {
                if (objectFindOwnerFn(owner[key], next, prune) === false ) { continue; }
                found = true;
            }
            return found;
        }
        if ( safe.Object_hasOwn(owner, prop) === false ) { return false; }
        owner = owner[prop];
        chain = chain.slice(pos + 1);
    }
}

function objectPruneFn(
    obj,
    rawPrunePaths,
    rawNeedlePaths,
    stackNeedleDetails = { matchAll: true },
    extraArgs = {}
) {
    if ( typeof rawPrunePaths !== 'string' ) { return; }
    const safe = safeSelf();
    const prunePaths = rawPrunePaths !== ''
        ? safe.String_split.call(rawPrunePaths, / +/)
        : [];
    const needlePaths = prunePaths.length !== 0 && rawNeedlePaths !== ''
        ? safe.String_split.call(rawNeedlePaths, / +/)
        : [];
    if ( stackNeedleDetails.matchAll !== true ) {
        if ( matchesStackTraceFn(stackNeedleDetails, extraArgs.logstack) === false ) {
            return;
        }
    }
    if ( objectPruneFn.mustProcess === undefined ) {
        objectPruneFn.mustProcess = (root, needlePaths) => {
            for ( const needlePath of needlePaths ) {
                if ( objectFindOwnerFn(root, needlePath) === false ) {
                    return false;
                }
            }
            return true;
        };
    }
    if ( prunePaths.length === 0 ) { return; }
    let outcome = 'nomatch';
    if ( objectPruneFn.mustProcess(obj, needlePaths) ) {
        for ( const path of prunePaths ) {
            if ( objectFindOwnerFn(obj, path, true) ) {
                outcome = 'match';
            }
        }
    }
    if ( outcome === 'match' ) { return obj; }
}

function parsePropertiesToMatchFn(propsToMatch, implicit = '') {
    const safe = safeSelf();
    const needles = new Map();
    if ( propsToMatch === undefined || propsToMatch === '' ) { return needles; }
    const options = { canNegate: true };
    for ( const needle of safe.String_split.call(propsToMatch, /\s+/) ) {
        let [ prop, pattern ] = safe.String_split.call(needle, ':');
        if ( prop === '' ) { continue; }
        if ( pattern !== undefined && /[^$\w -]/.test(prop) ) {
            prop = `${prop}:${pattern}`;
            pattern = undefined;
        }
        if ( pattern !== undefined ) {
            needles.set(prop, safe.initPattern(pattern, options));
        } else if ( implicit !== '' ) {
            needles.set(implicit, safe.initPattern(prop, options));
        }
    }
    return needles;
}

function parseReplaceFn(s) {
    if ( s.charCodeAt(0) !== 0x2F /* / */ ) { return; }
    const parser = new ArglistParser('/');
    parser.nextArg(s, 1);
    let pattern = s.slice(parser.argBeg, parser.argEnd);
    if ( parser.transform ) {
        pattern = parser.normalizeArg(pattern);
    }
    if ( pattern === '' ) { return; }
    parser.nextArg(s, parser.separatorEnd);
    let replacement = s.slice(parser.argBeg, parser.argEnd);
    if ( parser.separatorEnd === parser.separatorBeg ) { return; }
    if ( parser.transform ) {
        replacement = parser.normalizeArg(replacement);
    }
    const flags = s.slice(parser.separatorEnd);
    try {
        return { re: new RegExp(pattern, flags), replacement };
    } catch {
    }
}

function preventAddEventListener(
    type = '',
    pattern = ''
) {
    const safe = safeSelf();
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 2);
    const logPrefix = safe.makeLogPrefix('prevent-addEventListener', type, pattern);
    const reType = safe.patternToRegex(type, undefined, true);
    const rePattern = safe.patternToRegex(pattern);
    const targetSelector = extraArgs.elements || undefined;
    const elementMatches = elem => {
        if ( targetSelector === 'window' ) { return elem === window; }
        if ( targetSelector === 'document' ) { return elem === document; }
        if ( elem && elem.matches && elem.matches(targetSelector) ) { return true; }
        const elems = Array.from(document.querySelectorAll(targetSelector));
        return elems.includes(elem);
    };
    const elementDetails = elem => {
        if ( elem instanceof Window ) { return 'window'; }
        if ( elem instanceof Document ) { return 'document'; }
        if ( elem instanceof Element === false ) { return '?'; }
        const parts = [];
        // https://github.com/uBlockOrigin/uAssets/discussions/17907#discussioncomment-9871079
        const id = String(elem.id);
        if ( id !== '' ) { parts.push(`#${CSS.escape(id)}`); }
        for ( let i = 0; i < elem.classList.length; i++ ) {
            parts.push(`.${CSS.escape(elem.classList.item(i))}`);
        }
        for ( let i = 0; i < elem.attributes.length; i++ ) {
            const attr = elem.attributes.item(i);
            if ( attr.name === 'id' ) { continue; }
            if ( attr.name === 'class' ) { continue; }
            parts.push(`[${CSS.escape(attr.name)}="${attr.value}"]`);
        }
        return parts.join('');
    };
    const shouldPrevent = (thisArg, type, handler) => {
        const matchesType = safe.RegExp_test.call(reType, type);
        const matchesHandler = safe.RegExp_test.call(rePattern, handler);
        const matchesEither = matchesType || matchesHandler;
        const matchesBoth = matchesType && matchesHandler;
        if ( safe.logLevel > 1 && matchesEither ) {
            debugger; // eslint-disable-line no-debugger
        }
        if ( matchesBoth && targetSelector !== undefined ) {
            if ( elementMatches(thisArg) === false ) { return false; }
        }
        return matchesBoth;
    };
    const proxyFn = function(context) {
        const { callArgs, thisArg } = context;
        let t, h;
        try {
            t = String(callArgs[0]);
            if ( typeof callArgs[1] === 'function' ) {
                h = String(safe.Function_toString(callArgs[1]));
            } else if ( typeof callArgs[1] === 'object' && callArgs[1] !== null ) {
                if ( typeof callArgs[1].handleEvent === 'function' ) {
                    h = String(safe.Function_toString(callArgs[1].handleEvent));
                }
            } else {
                h = String(callArgs[1]);
            }
        } catch {
        }
        if ( type === '' && pattern === '' ) {
            safe.uboLog(logPrefix, `Called: ${t}\n${h}\n${elementDetails(thisArg)}`);
        } else if ( shouldPrevent(thisArg, t, h) ) {
            return safe.uboLog(logPrefix, `Prevented: ${t}\n${h}\n${elementDetails(thisArg)}`);
        }
        return context.reflect();
    };
    runAt(( ) => {
        proxyApplyFn('EventTarget.prototype.addEventListener', proxyFn);
        if ( extraArgs.protect ) {
            const { addEventListener } = EventTarget.prototype;
            Object.defineProperty(EventTarget.prototype, 'addEventListener', {
                set() { },
                get() { return addEventListener; }
            });
        }
        proxyApplyFn('document.addEventListener', proxyFn);
        if ( extraArgs.protect ) {
            const { addEventListener } = document;
            Object.defineProperty(document, 'addEventListener', {
                set() { },
                get() { return addEventListener; }
            });
        }
    }, extraArgs.runAt);
}

function preventCanvas(
    contextType = ''
) {
    const safe = safeSelf();
    const pattern = safe.initPattern(contextType, { canNegate: true });
    const proto = globalThis.HTMLCanvasElement.prototype;
    proto.getContext = new Proxy(proto.getContext, {
        apply(target, thisArg, args) {
            if ( safe.testPattern(pattern, args[0]) ) { return null; }
            return Reflect.apply(target, thisArg, args);
        }
    });
}

function preventFetch(...args) {
    preventFetchFn(false, ...args);
}

function preventFetchFn(
    trusted = false,
    propsToMatch = '',
    responseBody = '',
    responseType = ''
) {
    const safe = safeSelf();
    const setTimeout = self.setTimeout;
    const scriptletName = `${trusted ? 'trusted-' : ''}prevent-fetch`;
    const logPrefix = safe.makeLogPrefix(
        scriptletName,
        propsToMatch,
        responseBody,
        responseType
    );
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 4);
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const validResponseProps = {
        ok: [ false, true ],
        status: [ 403 ],
        statusText: [ '', 'Not Found' ],
        type: [ 'basic', 'cors', 'default', 'error', 'opaque' ],
    };
    const responseProps = {
        statusText: { value: 'OK' },
    };
    const responseHeaders = {};
    if ( /^\{.*\}$/.test(responseType) ) {
        try {
            Object.entries(JSON.parse(responseType)).forEach(([ p, v ]) => {
                if ( p === 'headers' && trusted ) {
                    Object.assign(responseHeaders, v);
                    return;
                }
                if ( validResponseProps[p] === undefined ) { return; }
                if ( validResponseProps[p].includes(v) === false ) { return; }
                responseProps[p] = { value: v };
            });
        }
        catch { }
    } else if ( responseType !== '' ) {
        if ( validResponseProps.type.includes(responseType) ) {
            responseProps.type = { value: responseType };
        }
    }
    proxyApplyFn('fetch', function fetch(context) {
        const { callArgs } = context;
        const details = collateFetchArgumentsFn(...callArgs);
        if ( safe.logLevel > 1 || propsToMatch === '' && responseBody === '' ) {
            const out = Array.from(Object.entries(details)).map(a => `${a[0]}:${a[1]}`);
            safe.uboLog(logPrefix, `Called: ${out.join('\n')}`);
        }
        if ( propsToMatch === '' && responseBody === '' ) {
            return context.reflect();
        }
        const matched = matchObjectPropertiesFn(propNeedles, details);
        if ( matched === undefined || matched.length === 0 ) {
            return context.reflect();
        }
        return Promise.resolve(generateContentFn(trusted, responseBody)).then(text => {
            safe.uboLog(logPrefix, `Prevented with response "${text}"`);
            const headers = Object.assign({}, responseHeaders);
            if ( headers['content-length'] === undefined ) {
                headers['content-length'] = text.length;
            }
            const response = new Response(text, { headers });
            const props = Object.assign(
                { url: { value: details.url } },
                responseProps
            );
            safe.Object_defineProperties(response, props);
            if ( extraArgs.throttle ) {
                return new Promise(resolve => {
                    setTimeout(( ) => { resolve(response); }, extraArgs.throttle);
                });
            }
            return response;
        });
    });
}

function preventInnerHTML(
    selector = '',
    pattern = ''
) {
    freezeElementProperty('innerHTML', selector, pattern);
}

function preventRequestAnimationFrame(
    needleRaw = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('prevent-requestAnimationFrame', needleRaw);
    const needleNot = needleRaw.charAt(0) === '!';
    const reNeedle = safe.patternToRegex(needleNot ? needleRaw.slice(1) : needleRaw);
    proxyApplyFn('requestAnimationFrame', function(context) {
        const { callArgs } = context;
        const a = callArgs[0] instanceof Function
            ? safe.String(safe.Function_toString(callArgs[0]))
            : safe.String(callArgs[0]);
        if ( needleRaw === '' ) {
            safe.uboLog(logPrefix, `Called:\n${a}`);
        } else if ( reNeedle.test(a) !== needleNot ) {
            callArgs[0] = function(){};
            safe.uboLog(logPrefix, `Prevented:\n${a}`);
        }
        return context.reflect();
    });
}

function preventSetInterval(
    needleRaw = '',
    delayRaw = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('prevent-setInterval', needleRaw, delayRaw);
    const needleNot = needleRaw.charAt(0) === '!';
    const reNeedle = safe.patternToRegex(needleNot ? needleRaw.slice(1) : needleRaw);
    const range = new RangeParser(delayRaw);
    proxyApplyFn('setInterval', function(context) {
        const { callArgs } = context;
        const a = callArgs[0] instanceof Function
            ? safe.String(safe.Function_toString(callArgs[0]))
            : safe.String(callArgs[0]);
        const b = callArgs[1];
        if ( needleRaw === '' && range.unbound() ) {
            safe.uboLog(logPrefix, `Called:\n${a}\n${b}`);
            return context.reflect();
        }
        if ( reNeedle.test(a) !== needleNot && range.test(b) ) {
            callArgs[0] = function(){};
            safe.uboLog(logPrefix, `Prevented:\n${a}\n${b}`);
        }
        return context.reflect();
    });
}

function preventSetTimeout(
    needleRaw = '',
    delayRaw = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('prevent-setTimeout', needleRaw, delayRaw);
    const needleNot = needleRaw.charAt(0) === '!';
    const reNeedle = safe.patternToRegex(needleNot ? needleRaw.slice(1) : needleRaw);
    const range = new RangeParser(delayRaw);
    proxyApplyFn('setTimeout', function(context) {
        const { callArgs } = context;
        const a = callArgs[0] instanceof Function
            ? safe.String(safe.Function_toString(callArgs[0]))
            : safe.String(callArgs[0]);
        const b = callArgs[1];
        if ( needleRaw === '' && range.unbound() ) {
            safe.uboLog(logPrefix, `Called:\n${a}\n${b}`);
            return context.reflect();
        }
        if ( reNeedle.test(a) !== needleNot && range.test(b) ) {
            callArgs[0] = function(){};
            safe.uboLog(logPrefix, `Prevented:\n${a}\n${b}`);
        }
        return context.reflect();
    });
}

function preventXhr(...args) {
    return preventXhrFn(false, ...args);
}

function preventXhrFn(
    trusted = false,
    propsToMatch = '',
    directive = ''
) {
    if ( typeof propsToMatch !== 'string' ) { return; }
    const safe = safeSelf();
    const scriptletName = trusted ? 'trusted-prevent-xhr' : 'prevent-xhr';
    const logPrefix = safe.makeLogPrefix(scriptletName, propsToMatch, directive);
    const xhrInstances = new WeakMap();
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const warOrigin = scriptletGlobals.warOrigin;
    const safeDispatchEvent = (xhr, type) => {
        try {
            xhr.dispatchEvent(new Event(type));
        } catch {
        }
    };
    proxyApplyFn('XMLHttpRequest.prototype.open', function(context) {
        const { thisArg, callArgs } = context;
        xhrInstances.delete(thisArg);
        const [ method, url, ...args ] = callArgs;
        if ( warOrigin !== undefined && url.startsWith(warOrigin) ) {
            return context.reflect();
        }
        const haystack = { method, url };
        if ( propsToMatch === '' && directive === '' ) {
            safe.uboLog(logPrefix, `Called: ${safe.JSON_stringify(haystack, null, 2)}`);
            return context.reflect();
        }
        if ( matchObjectPropertiesFn(propNeedles, haystack) ) {
            const xhrDetails = Object.assign(haystack, {
                xhr: thisArg,
                defer: args.length === 0 || !!args[0],
                directive,
                headers: {
                    'date': '',
                    'content-type': '',
                    'content-length': '',
                },
                url: haystack.url,
                props: {
                    response: { value: '' },
                    responseText: { value: '' },
                    responseXML: { value: null },
                },
            });
            xhrInstances.set(thisArg, xhrDetails);
        }
        return context.reflect();
    });
    proxyApplyFn('XMLHttpRequest.prototype.send', function(context) {
        const { thisArg } = context;
        const xhrDetails = xhrInstances.get(thisArg);
        if ( xhrDetails === undefined ) {
            return context.reflect();
        }
        xhrDetails.headers['date'] = (new Date()).toUTCString();
        let xhrText = '';
        switch ( thisArg.responseType ) {
        case 'arraybuffer':
            xhrDetails.props.response.value = new ArrayBuffer(0);
            xhrDetails.headers['content-type'] = 'application/octet-stream';
            break;
        case 'blob':
            xhrDetails.props.response.value = new Blob([]);
            xhrDetails.headers['content-type'] = 'application/octet-stream';
            break;
        case 'document': {
            const parser = new DOMParser();
            const doc = parser.parseFromString('', 'text/html');
            xhrDetails.props.response.value = doc;
            xhrDetails.props.responseXML.value = doc;
            xhrDetails.headers['content-type'] = 'text/html';
            break;
        }
        case 'json':
            xhrDetails.props.response.value = {};
            xhrDetails.props.responseText.value = '{}';
            xhrDetails.headers['content-type'] = 'application/json';
            break;
        default: {
            if ( directive === '' ) { break; }
            xhrText = generateContentFn(trusted, xhrDetails.directive);
            if ( xhrText instanceof Promise ) {
                xhrText = xhrText.then(text => {
                    xhrDetails.props.response.value = text;
                    xhrDetails.props.responseText.value = text;
                });
            } else {
                xhrDetails.props.response.value = xhrText;
                xhrDetails.props.responseText.value = xhrText;
            }
            xhrDetails.headers['content-type'] = 'text/plain';
            break;
        }
        }
        if ( xhrDetails.defer === false ) {
            xhrDetails.headers['content-length'] = `${xhrDetails.props.response.value}`.length;
            Object.defineProperties(xhrDetails.xhr, {
                readyState: { value: 4 },
                responseURL: { value: xhrDetails.url },
                status: { value: 200 },
                statusText: { value: 'OK' },
            });
            Object.defineProperties(xhrDetails.xhr, xhrDetails.props);
            return;
        }
        Promise.resolve(xhrText).then(( ) => xhrDetails).then(details => {
            Object.defineProperties(details.xhr, {
                readyState: { value: 1, configurable: true },
                responseURL: { value: xhrDetails.url },
            });
            safeDispatchEvent(details.xhr, 'readystatechange');
            return details;
        }).then(details => {
            xhrDetails.headers['content-length'] = `${details.props.response.value}`.length;
            Object.defineProperties(details.xhr, {
                readyState: { value: 2, configurable: true },
                status: { value: 200 },
                statusText: { value: 'OK' },
            });
            safeDispatchEvent(details.xhr, 'readystatechange');
            return details;
        }).then(details => {
            Object.defineProperties(details.xhr, {
                readyState: { value: 3, configurable: true },
            });
            Object.defineProperties(details.xhr, details.props);
            safeDispatchEvent(details.xhr, 'readystatechange');
            return details;
        }).then(details => {
            Object.defineProperties(details.xhr, {
                readyState: { value: 4 },
            });
            safeDispatchEvent(details.xhr, 'readystatechange');
            safeDispatchEvent(details.xhr, 'load');
            safeDispatchEvent(details.xhr, 'loadend');
            safe.uboLog(logPrefix, `Prevented with response:\n${details.xhr.response}`);
        });
    });
    proxyApplyFn('XMLHttpRequest.prototype.getResponseHeader', function(context) {
        const { thisArg } = context;
        const xhrDetails = xhrInstances.get(thisArg);
        if ( xhrDetails === undefined || thisArg.readyState < thisArg.HEADERS_RECEIVED ) {
            return context.reflect();
        }
        const headerName = `${context.callArgs[0]}`;
        const value = xhrDetails.headers[headerName.toLowerCase()];
        if ( value !== undefined && value !== '' ) { return value; }
        return null;
    });
    proxyApplyFn('XMLHttpRequest.prototype.getAllResponseHeaders', function(context) {
        const { thisArg } = context;
        const xhrDetails = xhrInstances.get(thisArg);
        if ( xhrDetails === undefined || thisArg.readyState < thisArg.HEADERS_RECEIVED ) {
            return context.reflect();
        }
        const out = [];
        for ( const [ name, value ] of Object.entries(xhrDetails.headers) ) {
            if ( !value ) { continue; }
            out.push(`${name}: ${value}`);
        }
        if ( out.length !== 0 ) { out.push(''); }
        return out.join('\r\n');
    });
}

function proxyApplyFn(
    target = '',
    handler = ''
) {
    let context = globalThis;
    let prop = target;
    for (;;) {
        const pos = prop.indexOf('.');
        if ( pos === -1 ) { break; }
        context = context[prop.slice(0, pos)];
        if ( context instanceof Object === false ) { return; }
        prop = prop.slice(pos+1);
    }
    const fn = context[prop];
    if ( typeof fn !== 'function' ) { return; }
    if ( proxyApplyFn.CtorContext === undefined ) {
        proxyApplyFn.ctorContexts = [];
        proxyApplyFn.CtorContext = class {
            constructor(...args) {
                this.init(...args);
            }
            init(callFn, callArgs) {
                this.callFn = callFn;
                this.callArgs = callArgs;
                return this;
            }
            reflect() {
                const r = Reflect.construct(this.callFn, this.callArgs);
                this.callFn = this.callArgs = this.private = undefined;
                proxyApplyFn.ctorContexts.push(this);
                return r;
            }
            static factory(...args) {
                return proxyApplyFn.ctorContexts.length !== 0
                    ? proxyApplyFn.ctorContexts.pop().init(...args)
                    : new proxyApplyFn.CtorContext(...args);
            }
        };
        proxyApplyFn.applyContexts = [];
        proxyApplyFn.ApplyContext = class {
            constructor(...args) {
                this.init(...args);
            }
            init(callFn, thisArg, callArgs) {
                this.callFn = callFn;
                this.thisArg = thisArg;
                this.callArgs = callArgs;
                return this;
            }
            reflect() {
                const r = Reflect.apply(this.callFn, this.thisArg, this.callArgs);
                this.callFn = this.thisArg = this.callArgs = this.private = undefined;
                proxyApplyFn.applyContexts.push(this);
                return r;
            }
            static factory(...args) {
                return proxyApplyFn.applyContexts.length !== 0
                    ? proxyApplyFn.applyContexts.pop().init(...args)
                    : new proxyApplyFn.ApplyContext(...args);
            }
        };
        proxyApplyFn.isCtor = new Map();
        proxyApplyFn.proxies = new WeakMap();
        proxyApplyFn.nativeToString = Function.prototype.toString;
        const proxiedToString = new Proxy(Function.prototype.toString, {
            apply(target, thisArg) {
                let proxied = thisArg;
                for(;;) {
                    const fn = proxyApplyFn.proxies.get(proxied);
                    if ( fn === undefined ) { break; }
                    proxied = fn;
                }
                return proxyApplyFn.nativeToString.call(proxied);
            }
        });
        proxyApplyFn.proxies.set(proxiedToString, proxyApplyFn.nativeToString);
        Function.prototype.toString = proxiedToString;
    }
    if ( proxyApplyFn.isCtor.has(target) === false ) {
        proxyApplyFn.isCtor.set(target, fn.prototype?.constructor === fn);
    }
    const proxyDetails = {
        apply(target, thisArg, args) {
            return handler(proxyApplyFn.ApplyContext.factory(target, thisArg, args));
        }
    };
    if ( proxyApplyFn.isCtor.get(target) ) {
        proxyDetails.construct = function(target, args) {
            return handler(proxyApplyFn.CtorContext.factory(target, args));
        };
    }
    const proxiedTarget = new Proxy(fn, proxyDetails);
    proxyApplyFn.proxies.set(proxiedTarget, fn);
    context[prop] = proxiedTarget;
}

function removeAttr(
    rawToken = '',
    rawSelector = '',
    behavior = ''
) {
    if ( typeof rawToken !== 'string' ) { return; }
    if ( rawToken === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('remove-attr', rawToken, rawSelector, behavior);
    const tokens = safe.String_split.call(rawToken, /\s*\|\s*/);
    const selector = tokens
        .map(a => `${rawSelector}[${CSS.escape(a)}]`)
        .join(',');
    if ( safe.logLevel > 1 ) {
        safe.uboLog(logPrefix, `Target selector:\n\t${selector}`);
    }
    const asap = /\basap\b/.test(behavior);
    let timerId;
    const rmattrAsync = ( ) => {
        if ( timerId !== undefined ) { return; }
        timerId = safe.onIdle(( ) => {
            timerId = undefined;
            rmattr();
        }, { timeout: 17 });
    };
    const rmattr = ( ) => {
        if ( timerId !== undefined ) {
            safe.offIdle(timerId);
            timerId = undefined;
        }
        try {
            const nodes = document.querySelectorAll(selector);
            for ( const node of nodes ) {
                for ( const attr of tokens ) {
                    if ( node.hasAttribute(attr) === false ) { continue; }
                    node.removeAttribute(attr);
                    safe.uboLog(logPrefix, `Removed attribute '${attr}'`);
                }
            }
        } catch {
        }
    };
    const mutationHandler = mutations => {
        if ( timerId !== undefined ) { return; }
        let skip = true;
        for ( let i = 0; i < mutations.length && skip; i++ ) {
            const { type, addedNodes, removedNodes } = mutations[i];
            if ( type === 'attributes' ) { skip = false; }
            for ( let j = 0; j < addedNodes.length && skip; j++ ) {
                if ( addedNodes[j].nodeType === 1 ) { skip = false; break; }
            }
            for ( let j = 0; j < removedNodes.length && skip; j++ ) {
                if ( removedNodes[j].nodeType === 1 ) { skip = false; break; }
            }
        }
        if ( skip ) { return; }
        asap ? rmattr() : rmattrAsync();
    };
    const start = ( ) => {
        rmattr();
        if ( /\bstay\b/.test(behavior) === false ) { return; }
        const observer = new MutationObserver(mutationHandler);
        observer.observe(document, {
            attributes: true,
            attributeFilter: tokens,
            childList: true,
            subtree: true,
        });
    };
    runAt(( ) => { start(); }, safe.String_split.call(behavior, /\s+/));
}

function replaceFetchResponseFn(
    trusted = false,
    pattern = '',
    replacement = '',
    propsToMatch = ''
) {
    if ( trusted !== true ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('replace-fetch-response', pattern, replacement, propsToMatch);
    if ( pattern === '*' ) { pattern = '.*'; }
    const rePattern = safe.patternToRegex(pattern);
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 4);
    const reIncludes = extraArgs.includes ? safe.patternToRegex(extraArgs.includes) : null;
    self.fetch = new Proxy(self.fetch, {
        apply: function(target, thisArg, args) {
            const fetchPromise = Reflect.apply(target, thisArg, args);
            if ( pattern === '' ) { return fetchPromise; }
            if ( propNeedles.size !== 0 ) {
                const props = collateFetchArgumentsFn(...args);
                const matched = matchObjectPropertiesFn(propNeedles, props);
                if ( matched === undefined ) { return fetchPromise; }
                if ( safe.logLevel > 1 ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
                }
            }
            return fetchPromise.then(responseBefore => {
                const response = responseBefore.clone();
                return response.text().then(textBefore => {
                    if ( reIncludes && reIncludes.test(textBefore) === false ) {
                        return responseBefore;
                    }
                    const textAfter = textBefore.replace(rePattern, replacement);
                    if ( textAfter === textBefore ) { return responseBefore; }
                    safe.uboLog(logPrefix, 'Replaced');
                    const responseAfter = new Response(textAfter, {
                        status: responseBefore.status,
                        statusText: responseBefore.statusText,
                        headers: responseBefore.headers,
                    });
                    Object.defineProperties(responseAfter, {
                        ok: { value: responseBefore.ok },
                        redirected: { value: responseBefore.redirected },
                        type: { value: responseBefore.type },
                        url: { value: responseBefore.url },
                    });
                    return responseAfter;
                }).catch(reason => {
                    safe.uboErr(logPrefix, reason);
                    return responseBefore;
                });
            }).catch(reason => {
                safe.uboErr(logPrefix, reason);
                return fetchPromise;
            });
        }
    });
}

function runAt(fn, when) {
    const intFromReadyState = state => {
        const targets = {
            'loading': 1, 'asap': 1,
            'interactive': 2, 'end': 2, '2': 2,
            'complete': 3, 'idle': 3, '3': 3,
        };
        const tokens = Array.isArray(state) ? state : [ state ];
        for ( const token of tokens ) {
            const prop = `${token}`;
            if ( Object.hasOwn(targets, prop) === false ) { continue; }
            return targets[prop];
        }
        return 0;
    };
    const runAt = intFromReadyState(when);
    if ( intFromReadyState(document.readyState) >= runAt ) {
        fn(); return;
    }
    const onStateChange = ( ) => {
        if ( intFromReadyState(document.readyState) < runAt ) { return; }
        fn();
        safe.removeEventListener.apply(document, args);
    };
    const safe = safeSelf();
    const args = [ 'readystatechange', onStateChange, { capture: true } ];
    safe.addEventListener.apply(document, args);
}

function runAtHtmlElementFn(fn) {
    if ( document.documentElement ) {
        fn();
        return;
    }
    const observer = new MutationObserver(( ) => {
        observer.disconnect();
        fn();
    });
    observer.observe(document, { childList: true });
}

function safeSelf() {
    if ( scriptletGlobals.safeSelf ) {
        return scriptletGlobals.safeSelf;
    }
    const self = globalThis;
    const safe = {
        'Array_from': Array.from,
        'Error': self.Error,
        'Function_toStringFn': self.Function.prototype.toString,
        'Function_toString': thisArg => safe.Function_toStringFn.call(thisArg),
        'Math_floor': Math.floor,
        'Math_max': Math.max,
        'Math_min': Math.min,
        'Math_random': Math.random,
        'Object': Object,
        'Object_defineProperty': Object.defineProperty.bind(Object),
        'Object_defineProperties': Object.defineProperties.bind(Object),
        'Object_fromEntries': Object.fromEntries.bind(Object),
        'Object_getOwnPropertyDescriptor': Object.getOwnPropertyDescriptor.bind(Object),
        'Object_hasOwn': Object.hasOwn.bind(Object),
        'Object_toString': Object.prototype.toString,
        'RegExp': self.RegExp,
        'RegExp_test': self.RegExp.prototype.test,
        'RegExp_exec': self.RegExp.prototype.exec,
        'Request_clone': self.Request.prototype.clone,
        'String': self.String,
        'String_fromCharCode': String.fromCharCode,
        'String_split': String.prototype.split,
        'XMLHttpRequest': self.XMLHttpRequest,
        'addEventListener': self.EventTarget.prototype.addEventListener,
        'removeEventListener': self.EventTarget.prototype.removeEventListener,
        'fetch': self.fetch,
        'JSON': self.JSON,
        'JSON_parseFn': self.JSON.parse,
        'JSON_stringifyFn': self.JSON.stringify,
        'JSON_parse': (...args) => safe.JSON_parseFn.call(safe.JSON, ...args),
        'JSON_stringify': (...args) => safe.JSON_stringifyFn.call(safe.JSON, ...args),
        'log': console.log.bind(console),
        // Properties
        logLevel: 0,
        // Methods
        makeLogPrefix(...args) {
            return this.sendToLogger && `[${args.join(' \u205D ')}]` || '';
        },
        uboLog(...args) {
            if ( this.sendToLogger === undefined ) { return; }
            if ( args === undefined || args[0] === '' ) { return; }
            return this.sendToLogger('info', ...args);
            
        },
        uboErr(...args) {
            if ( this.sendToLogger === undefined ) { return; }
            if ( args === undefined || args[0] === '' ) { return; }
            return this.sendToLogger('error', ...args);
        },
        escapeRegexChars(s) {
            return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        },
        initPattern(pattern, options = {}) {
            if ( pattern === '' ) {
                return { matchAll: true, expect: true };
            }
            const expect = (options.canNegate !== true || pattern.startsWith('!') === false);
            if ( expect === false ) {
                pattern = pattern.slice(1);
            }
            const match = /^\/(.+)\/([gimsu]*)$/.exec(pattern);
            if ( match !== null ) {
                return {
                    re: new this.RegExp(
                        match[1],
                        match[2] || options.flags
                    ),
                    expect,
                };
            }
            if ( options.flags !== undefined ) {
                return {
                    re: new this.RegExp(this.escapeRegexChars(pattern),
                        options.flags
                    ),
                    expect,
                };
            }
            return { pattern, expect };
        },
        testPattern(details, haystack) {
            if ( details.matchAll ) { return true; }
            if ( details.re ) {
                return this.RegExp_test.call(details.re, haystack) === details.expect;
            }
            return haystack.includes(details.pattern) === details.expect;
        },
        patternToRegex(pattern, flags = undefined, verbatim = false) {
            if ( pattern === '' ) { return /^/; }
            const match = /^\/(.+)\/([gimsu]*)$/.exec(pattern);
            if ( match === null ) {
                const reStr = this.escapeRegexChars(pattern);
                return new RegExp(verbatim ? `^${reStr}$` : reStr, flags);
            }
            try {
                return new RegExp(match[1], match[2] || undefined);
            }
            catch {
            }
            return /^/;
        },
        getExtraArgs(args, offset = 0) {
            const entries = args.slice(offset).reduce((out, v, i, a) => {
                if ( (i & 1) === 0 ) {
                    const rawValue = a[i+1];
                    const value = /^\d+$/.test(rawValue)
                        ? parseInt(rawValue, 10)
                        : rawValue;
                    out.push([ a[i], value ]);
                }
                return out;
            }, []);
            return this.Object_fromEntries(entries);
        },
        onIdle(fn, options) {
            if ( self.requestIdleCallback ) {
                return self.requestIdleCallback(fn, options);
            }
            return self.requestAnimationFrame(fn);
        },
        offIdle(id) {
            if ( self.requestIdleCallback ) {
                return self.cancelIdleCallback(id);
            }
            return self.cancelAnimationFrame(id);
        }
    };
    scriptletGlobals.safeSelf = safe;
    if ( scriptletGlobals.bcSecret === undefined ) { return safe; }
    // This is executed only when the logger is opened
    safe.logLevel = scriptletGlobals.logLevel || 1;
    let lastLogType = '';
    let lastLogText = '';
    let lastLogTime = 0;
    safe.toLogText = (type, ...args) => {
        if ( args.length === 0 ) { return; }
        const text = `[${document.location.hostname || document.location.href}]${args.join(' ')}`;
        if ( text === lastLogText && type === lastLogType ) {
            if ( (Date.now() - lastLogTime) < 5000 ) { return; }
        }
        lastLogType = type;
        lastLogText = text;
        lastLogTime = Date.now();
        return text;
    };
    try {
        const bc = new self.BroadcastChannel(scriptletGlobals.bcSecret);
        let bcBuffer = [];
        safe.sendToLogger = (type, ...args) => {
            const text = safe.toLogText(type, ...args);
            if ( text === undefined ) { return; }
            if ( bcBuffer === undefined ) {
                return bc.postMessage({ what: 'messageToLogger', type, text });
            }
            bcBuffer.push({ type, text });
        };
        bc.onmessage = ev => {
            const msg = ev.data;
            switch ( msg ) {
            case 'iamready!':
                if ( bcBuffer === undefined ) { break; }
                bcBuffer.forEach(({ type, text }) =>
                    bc.postMessage({ what: 'messageToLogger', type, text })
                );
                bcBuffer = undefined;
                break;
            case 'setScriptletLogLevelToOne':
                safe.logLevel = 1;
                break;
            case 'setScriptletLogLevelToTwo':
                safe.logLevel = 2;
                break;
            }
        };
        bc.postMessage('areyouready?');
    } catch {
        safe.sendToLogger = (type, ...args) => {
            const text = safe.toLogText(type, ...args);
            if ( text === undefined ) { return; }
            safe.log(`uBO ${text}`);
        };
    }
    return safe;
}

function setConstant(
    ...args
) {
    setConstantFn(false, ...args);
}

function setConstantFn(
    trusted = false,
    chain = '',
    rawValue = ''
) {
    if ( chain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('set-constant', chain, rawValue);
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 3);
    function setConstant(chain, rawValue) {
        const trappedProp = (( ) => {
            const pos = chain.lastIndexOf('.');
            if ( pos === -1 ) { return chain; }
            return chain.slice(pos+1);
        })();
        const cloakFunc = fn => {
            safe.Object_defineProperty(fn, 'name', { value: trappedProp });
            return new Proxy(fn, {
                defineProperty(target, prop) {
                    if ( prop !== 'toString' ) {
                        return Reflect.defineProperty(...arguments);
                    }
                    return true;
                },
                deleteProperty(target, prop) {
                    if ( prop !== 'toString' ) {
                        return Reflect.deleteProperty(...arguments);
                    }
                    return true;
                },
                get(target, prop) {
                    if ( prop === 'toString' ) {
                        return function() {
                            return `function ${trappedProp}() { [native code] }`;
                        }.bind(null);
                    }
                    return Reflect.get(...arguments);
                },
            });
        };
        if ( trappedProp === '' ) { return; }
        const thisScript = document.currentScript;
        let normalValue = validateConstantFn(trusted, rawValue, extraArgs);
        if ( rawValue === 'noopFunc' || rawValue === 'trueFunc' || rawValue === 'falseFunc' ) {
            normalValue = cloakFunc(normalValue);
        }
        let aborted = false;
        const mustAbort = function(v) {
            if ( trusted ) { return false; }
            if ( aborted ) { return true; }
            aborted =
                (v !== undefined && v !== null) &&
                (normalValue !== undefined && normalValue !== null) &&
                (typeof v !== typeof normalValue);
            if ( aborted ) {
                safe.uboLog(logPrefix, `Aborted because value set to ${v}`);
            }
            return aborted;
        };
        // https://github.com/uBlockOrigin/uBlock-issues/issues/156
        //   Support multiple trappers for the same property.
        const trapProp = function(owner, prop, configurable, handler) {
            if ( handler.init(configurable ? owner[prop] : normalValue) === false ) { return; }
            const odesc = safe.Object_getOwnPropertyDescriptor(owner, prop);
            let prevGetter, prevSetter;
            if ( odesc instanceof safe.Object ) {
                owner[prop] = normalValue;
                if ( odesc.get instanceof Function ) {
                    prevGetter = odesc.get;
                }
                if ( odesc.set instanceof Function ) {
                    prevSetter = odesc.set;
                }
            }
            try {
                safe.Object_defineProperty(owner, prop, {
                    configurable,
                    get() {
                        if ( prevGetter !== undefined ) {
                            prevGetter();
                        }
                        return handler.getter();
                    },
                    set(a) {
                        if ( prevSetter !== undefined ) {
                            prevSetter(a);
                        }
                        handler.setter(a);
                    }
                });
                safe.uboLog(logPrefix, 'Trap installed');
            } catch(ex) {
                safe.uboErr(logPrefix, ex);
            }
        };
        const trapChain = function(owner, chain) {
            const pos = chain.indexOf('.');
            if ( pos === -1 ) {
                trapProp(owner, chain, false, {
                    v: undefined,
                    init: function(v) {
                        if ( mustAbort(v) ) { return false; }
                        this.v = v;
                        return true;
                    },
                    getter: function() {
                        if ( document.currentScript === thisScript ) {
                            return this.v;
                        }
                        safe.uboLog(logPrefix, 'Property read');
                        return normalValue;
                    },
                    setter: function(a) {
                        if ( mustAbort(a) === false ) { return; }
                        normalValue = a;
                    }
                });
                return;
            }
            const prop = chain.slice(0, pos);
            const v = owner[prop];
            chain = chain.slice(pos + 1);
            if ( v instanceof safe.Object || typeof v === 'object' && v !== null ) {
                trapChain(v, chain);
                return;
            }
            trapProp(owner, prop, true, {
                v: undefined,
                init: function(v) {
                    this.v = v;
                    return true;
                },
                getter: function() {
                    return this.v;
                },
                setter: function(a) {
                    this.v = a;
                    if ( a instanceof safe.Object ) {
                        trapChain(a, chain);
                    }
                }
            });
        };
        trapChain(window, chain);
    }
    runAt(( ) => {
        setConstant(chain, rawValue);
    }, extraArgs.runAt);
}

function shouldDebug(details) {
    if ( details instanceof Object === false ) { return false; }
    return scriptletGlobals.canDebug && details.debug;
}

function spoofCSS(
    selector,
    ...args
) {
    if ( typeof selector !== 'string' ) { return; }
    if ( selector === '' ) { return; }
    const toCamelCase = s => s.replace(/-[a-z]/g, s => s.charAt(1).toUpperCase());
    const propToValueMap = new Map();
    const privatePropToValueMap = new Map();
    for ( let i = 0; i < args.length; i += 2 ) {
        const prop = toCamelCase(args[i+0]);
        if ( prop === '' ) { break; }
        const value = args[i+1];
        if ( typeof value !== 'string' ) { break; }
        if ( prop.charCodeAt(0) === 0x5F /* _ */ ) {
            privatePropToValueMap.set(prop, value);
        } else {
            propToValueMap.set(prop, value);
        }
    }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('spoof-css', selector, ...args);
    const instanceProperties = [ 'cssText', 'length', 'parentRule' ];
    const spoofStyle = (prop, real) => {
        const normalProp = toCamelCase(prop);
        const shouldSpoof = propToValueMap.has(normalProp);
        const value = shouldSpoof ? propToValueMap.get(normalProp) : real;
        if ( shouldSpoof ) {
            safe.uboLog(logPrefix, `Spoofing ${prop} to ${value}`);
        }
        return value;
    };
    const cloackFunc = (fn, thisArg, name) => {
        const trap = fn.bind(thisArg);
        Object.defineProperty(trap, 'name', { value: name });
        Object.defineProperty(trap, 'toString', {
            value: ( ) => `function ${name}() { [native code] }`
        });
        return trap;
    };
    self.getComputedStyle = new Proxy(self.getComputedStyle, {
        apply: function(target, thisArg, args) {
            // eslint-disable-next-line no-debugger
            if ( privatePropToValueMap.has('_debug') ) { debugger; }
            const style = Reflect.apply(target, thisArg, args);
            const targetElements = new WeakSet(document.querySelectorAll(selector));
            if ( targetElements.has(args[0]) === false ) { return style; }
            const proxiedStyle = new Proxy(style, {
                get(target, prop) {
                    if ( typeof target[prop] === 'function' ) {
                        if ( prop === 'getPropertyValue' ) {
                            return cloackFunc(function getPropertyValue(prop) {
                                return spoofStyle(prop, target[prop]);
                            }, target, 'getPropertyValue');
                        }
                        return cloackFunc(target[prop], target, prop);
                    }
                    if ( instanceProperties.includes(prop) ) {
                        return Reflect.get(target, prop);
                    }
                    return spoofStyle(prop, Reflect.get(target, prop));
                },
                getOwnPropertyDescriptor(target, prop) {
                    if ( propToValueMap.has(prop) ) {
                        return {
                            configurable: true,
                            enumerable: true,
                            value: propToValueMap.get(prop),
                            writable: true,
                        };
                    }
                    return Reflect.getOwnPropertyDescriptor(target, prop);
                },
            });
            return proxiedStyle;
        },
        get(target, prop) {
            if ( prop === 'toString' ) {
                return target.toString.bind(target);
            }
            return Reflect.get(target, prop);
        },
    });
    Element.prototype.getBoundingClientRect = new Proxy(Element.prototype.getBoundingClientRect, {
        apply: function(target, thisArg, args) {
            // eslint-disable-next-line no-debugger
            if ( privatePropToValueMap.has('_debug') ) { debugger; }
            const rect = Reflect.apply(target, thisArg, args);
            const targetElements = new WeakSet(document.querySelectorAll(selector));
            if ( targetElements.has(thisArg) === false ) { return rect; }
            let { x, y, height, width } = rect;
            if ( privatePropToValueMap.has('_rectx') ) {
                x = parseFloat(privatePropToValueMap.get('_rectx'));
            }
            if ( privatePropToValueMap.has('_recty') ) {
                y = parseFloat(privatePropToValueMap.get('_recty'));
            }
            if ( privatePropToValueMap.has('_rectw') ) {
                width = parseFloat(privatePropToValueMap.get('_rectw'));
            } else if ( propToValueMap.has('width') ) {
                width = parseFloat(propToValueMap.get('width'));
            }
            if ( privatePropToValueMap.has('_recth') ) {
                height = parseFloat(privatePropToValueMap.get('_recth'));
            } else if ( propToValueMap.has('height') ) {
                height = parseFloat(propToValueMap.get('height'));
            }
            return new self.DOMRect(x, y, width, height);
        },
        get(target, prop) {
            if ( prop === 'toString' ) {
                return target.toString.bind(target);
            }
            return Reflect.get(target, prop);
        },
    });
}

function trustedEditInboundObject(propChain = '', argPos = '', jsonq = '') {
    editInboundObjectFn(true, propChain, argPos, jsonq);
}

function trustedJsonEdit(jsonq = '') {
    editOutboundObjectFn(true, 'JSON.parse', jsonq);
}

function trustedJsonEditFetchResponse(jsonq = '', ...args) {
    jsonEditFetchResponseFn(true, jsonq, ...args);
}

function trustedJsonEditXhrRequest(jsonq = '', ...args) {
    jsonEditXhrRequestFn(true, jsonq, ...args);
}

function trustedJsonEditXhrResponse(jsonq = '', ...args) {
    jsonEditXhrResponseFn(true, jsonq, ...args);
}

function trustedOverrideElementMethod(
    methodPath = '',
    selector = '',
    disposition = ''
) {
    if ( methodPath === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-override-element-method', methodPath, selector, disposition);
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 3);
    proxyApplyFn(methodPath, function(context) {
        let override = selector === '';
        if ( override === false ) {
            const { thisArg } = context;
            try {
                override = thisArg.closest(selector) === thisArg;
            } catch {
            }
        }
        if ( override === false ) {
            return context.reflect();
        }
        safe.uboLog(logPrefix, 'Overridden');
        if ( disposition === '' ) { return; }
        if ( disposition === 'debug' && safe.logLevel !== 0 ) {
            debugger; // eslint-disable-line no-debugger
        }
        if ( disposition === 'throw' ) {
            throw new ReferenceError();
        }
        return validateConstantFn(true, disposition, extraArgs);
    });
}

function trustedPreventDomBypass(
    methodPath = '',
    targetProp = ''
) {
    if ( methodPath === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-prevent-dom-bypass', methodPath, targetProp);
    proxyApplyFn(methodPath, function(context) {
        const elems = new Set(context.callArgs.filter(e => e instanceof HTMLElement));
        const r = context.reflect();
        if ( elems.length === 0 ) { return r; }
        for ( const elem of elems ) {
            try {
                if ( `${elem.contentWindow}` !== '[object Window]' ) { continue; }
                if ( elem.contentWindow.location.href !== 'about:blank' ) {
                    if ( elem.contentWindow.location.href !== self.location.href ) {
                        continue;
                    }
                }
                if ( targetProp !== '' ) {
                    let me = self, it = elem.contentWindow;
                    let chain = targetProp;
                    for (;;) {
                        const pos = chain.indexOf('.');
                        if ( pos === -1 ) { break; }
                        const prop = chain.slice(0, pos);
                        me = me[prop]; it = it[prop];
                        chain = chain.slice(pos+1);
                    }
                    it[chain] = me[chain];
                } else {
                    Object.defineProperty(elem, 'contentWindow', { value: self });
                }
                safe.uboLog(logPrefix, 'Bypass prevented');
            } catch {
            }
        }
        return r;
    });
}

function trustedPreventFetch(...args) {
    preventFetchFn(true, ...args);
}

function trustedPreventXhr(...args) {
    return preventXhrFn(true, ...args);
}

function trustedReplaceArgument(
    propChain = '',
    argposRaw = '',
    argraw = ''
) {
    if ( propChain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-replace-argument', propChain, argposRaw, argraw);
    const argoffset = parseInt(argposRaw, 10) || 0;
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 3);
    let replacer;
    if ( argraw.startsWith('repl:/') ) {
        const parsed = parseReplaceFn(argraw.slice(5));
        if ( parsed === undefined ) { return; }
        replacer = arg => `${arg}`.replace(replacer.re, replacer.replacement);
        Object.assign(replacer, parsed);
    } else if ( argraw.startsWith('add:') ) {
        const delta = parseFloat(argraw.slice(4));
        if ( isNaN(delta) ) { return; }
        replacer = arg => Number(arg) + delta;
    } else {
        const value = validateConstantFn(true, argraw, extraArgs);
        replacer = ( ) => value;
    }
    const reCondition = extraArgs.condition
        ? safe.patternToRegex(extraArgs.condition)
        : /^/;
    const getArg = context => {
        if ( argposRaw === 'this' ) { return context.thisArg; }
        const { callArgs } = context;
        const argpos = argoffset >= 0 ? argoffset : callArgs.length - argoffset;
        if ( argpos < 0 || argpos >= callArgs.length ) { return; }
        context.private = { argpos };
        return callArgs[argpos];
    };
    const setArg = (context, value) => {
        if ( argposRaw === 'this' ) {
            if ( value !== context.thisArg ) {
                context.thisArg = value;
            }
        } else if ( context.private ) {
            context.callArgs[context.private.argpos] = value;
        }
    };
    proxyApplyFn(propChain, function(context) {
        if ( argposRaw === '' ) {
            safe.uboLog(logPrefix, `Arguments:\n${context.callArgs.join('\n')}`);
            return context.reflect();
        }
        const argBefore = getArg(context);
        if ( extraArgs.condition !== undefined ) {
            if ( safe.RegExp_test.call(reCondition, argBefore) === false ) {
                return context.reflect();
            }
        }
        const argAfter = replacer(argBefore);
        if ( argAfter !== argBefore ) {
            setArg(context, argAfter);
            safe.uboLog(logPrefix, `Replaced argument:\nBefore: ${JSON.stringify(argBefore)}\nAfter: ${argAfter}`);
        }
        return context.reflect();
    });
}

function trustedReplaceFetchResponse(...args) {
    replaceFetchResponseFn(true, ...args);
}

function trustedReplaceOutboundText(
    propChain = '',
    rawPattern = '',
    rawReplacement = '',
    ...args
) {
    if ( propChain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-replace-outbound-text', propChain, rawPattern, rawReplacement, ...args);
    const rePattern = safe.patternToRegex(rawPattern);
    const replacement = rawReplacement.startsWith('json:')
        ? safe.JSON_parse(rawReplacement.slice(5))
        : rawReplacement;
    const extraArgs = safe.getExtraArgs(args);
    const reCondition = safe.patternToRegex(extraArgs.condition || '');
    proxyApplyFn(propChain, function(context) {
        const encodedTextBefore = context.reflect();
        let textBefore = encodedTextBefore;
        if ( extraArgs.encoding === 'base64' ) {
            try { textBefore = self.atob(encodedTextBefore); }
            catch { return encodedTextBefore; }
        }
        if ( rawPattern === '' ) {
            safe.uboLog(logPrefix, 'Decoded outbound text:\n', textBefore);
            return encodedTextBefore;
        }
        reCondition.lastIndex = 0;
        if ( reCondition.test(textBefore) === false ) { return encodedTextBefore; }
        const textAfter = textBefore.replace(rePattern, replacement);
        if ( textAfter === textBefore ) { return encodedTextBefore; }
        safe.uboLog(logPrefix, 'Matched and replaced');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, 'Modified decoded outbound text:\n', textAfter);
        }
        let encodedTextAfter = textAfter;
        if ( extraArgs.encoding === 'base64' ) {
            encodedTextAfter = self.btoa(textAfter);
        }
        return encodedTextAfter;
    });
}

function trustedReplaceXhrResponse(
    pattern = '',
    replacement = '',
    propsToMatch = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-replace-xhr-response', pattern, replacement, propsToMatch);
    const xhrInstances = new WeakMap();
    if ( pattern === '*' ) { pattern = '.*'; }
    const rePattern = safe.patternToRegex(pattern);
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 3);
    const reIncludes = extraArgs.includes ? safe.patternToRegex(extraArgs.includes) : null;
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const outerXhr = this;
            const xhrDetails = { method, url };
            let outcome = 'match';
            if ( propNeedles.size !== 0 ) {
                if ( matchObjectPropertiesFn(propNeedles, xhrDetails) === undefined ) {
                    outcome = 'nomatch';
                }
            }
            if ( outcome === 'match' ) {
                if ( safe.logLevel > 1 ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch"`);
                }
                xhrInstances.set(outerXhr, xhrDetails);
            }
            return super.open(method, url, ...args);
        }
        get response() {
            const innerResponse = super.response;
            const xhrDetails = xhrInstances.get(this);
            if ( xhrDetails === undefined ) {
                return innerResponse;
            }
            const responseLength = typeof innerResponse === 'string'
                ? innerResponse.length
                : undefined;
            if ( xhrDetails.lastResponseLength !== responseLength ) {
                xhrDetails.response = undefined;
                xhrDetails.lastResponseLength = responseLength;
            }
            if ( xhrDetails.response !== undefined ) {
                return xhrDetails.response;
            }
            if ( typeof innerResponse !== 'string' ) {
                return (xhrDetails.response = innerResponse);
            }
            if ( reIncludes && reIncludes.test(innerResponse) === false ) {
                return (xhrDetails.response = innerResponse);
            }
            const textBefore = innerResponse;
            const textAfter = textBefore.replace(rePattern, replacement);
            if ( textAfter !== textBefore ) {
                safe.uboLog(logPrefix, 'Match');
            }
            return (xhrDetails.response = textAfter);
        }
        get responseText() {
            const response = this.response;
            if ( typeof response !== 'string' ) {
                return super.responseText;
            }
            return response;
        }
    };
}

function trustedSetConstant(
    ...args
) {
    setConstantFn(true, ...args);
}

function trustedSuppressNativeMethod(
    methodPath = '',
    signature = '',
    how = '',
    stack = ''
) {
    if ( methodPath === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-suppress-native-method', methodPath, signature, how, stack);
    const signatureArgs = safe.String_split.call(signature, /\s*\|\s*/).map(v => {
        if ( /^".*"$/.test(v) ) {
            return { type: 'pattern', re: safe.patternToRegex(v.slice(1, -1)) };
        }
        if ( /^\/.+\/$/.test(v) ) {
            return { type: 'pattern', re: safe.patternToRegex(v) };
        }
        if ( v === 'false' ) {
            return { type: 'exact', value: false };
        }
        if ( v === 'true' ) {
            return { type: 'exact', value: true };
        }
        if ( v === 'null' ) {
            return { type: 'exact', value: null };
        }
        if ( v === 'undefined' ) {
            return { type: 'exact', value: undefined };
        }
    });
    const stackNeedle = safe.initPattern(stack, { canNegate: true });
    proxyApplyFn(methodPath, function(context) {
        const { callArgs } = context;
        if ( signature === '' ) {
            safe.uboLog(logPrefix, `Arguments:\n${callArgs.join('\n')}`);
            return context.reflect();
        }
        for ( let i = 0; i < signatureArgs.length; i++ ) {
            const signatureArg = signatureArgs[i];
            if ( signatureArg === undefined ) { continue; }
            const targetArg = i < callArgs.length ? callArgs[i] : undefined;
            if ( signatureArg.type === 'exact' ) {
                if ( targetArg !== signatureArg.value ) {
                    return context.reflect();
                }
            }
            if ( signatureArg.type === 'pattern' ) {
                if ( safe.RegExp_test.call(signatureArg.re, targetArg) === false ) {
                    return context.reflect();
                }
            }
        }
        if ( stackNeedle.matchAll !== true ) {
            const logLevel = safe.logLevel > 1 ? 'all' : '';
            if ( matchesStackTraceFn(stackNeedle, logLevel) === false ) {
                return context.reflect();
            }
        }
        if ( how === 'debug' ) {
            debugger; // eslint-disable-line no-debugger
            return context.reflect();
        }
        safe.uboLog(logPrefix, `Suppressed:\n${callArgs.join('\n')}`);
        if ( how === 'abort' ) {
            throw new ReferenceError();
        }
    });
}

function validateConstantFn(trusted, raw, extraArgs = {}) {
    const safe = safeSelf();
    let value;
    if ( raw === 'undefined' ) {
        value = undefined;
    } else if ( raw === 'false' ) {
        value = false;
    } else if ( raw === 'true' ) {
        value = true;
    } else if ( raw === 'null' ) {
        value = null;
    } else if ( raw === "''" || raw === '' ) {
        value = '';
    } else if ( raw === '[]' || raw === 'emptyArr' ) {
        value = [];
    } else if ( raw === '{}' || raw === 'emptyObj' ) {
        value = {};
    } else if ( raw === 'noopFunc' ) {
        value = function(){};
    } else if ( raw === 'trueFunc' ) {
        value = function(){ return true; };
    } else if ( raw === 'falseFunc' ) {
        value = function(){ return false; };
    } else if ( raw === 'throwFunc' ) {
        value = function(){ throw ''; };
    } else if ( /^-?\d+$/.test(raw) ) {
        value = parseInt(raw);
        if ( isNaN(raw) ) { return; }
        if ( Math.abs(raw) > 0x7FFF ) { return; }
    } else if ( trusted ) {
        if ( raw.startsWith('json:') ) {
            try { value = safe.JSON_parse(raw.slice(5)); } catch { return; }
        } else if ( raw.startsWith('{') && raw.endsWith('}') ) {
            try { value = safe.JSON_parse(raw).value; } catch { return; }
        }
    } else {
        return;
    }
    if ( extraArgs.as !== undefined ) {
        if ( extraArgs.as === 'function' ) {
            return ( ) => value;
        } else if ( extraArgs.as === 'callback' ) {
            return ( ) => (( ) => value);
        } else if ( extraArgs.as === 'resolved' ) {
            return Promise.resolve(value);
        } else if ( extraArgs.as === 'rejected' ) {
            return Promise.reject(value);
        }
    }
    return value;
}

function xmlPrune(
    selector = '',
    selectorCheck = '',
    urlPattern = ''
) {
    if ( typeof selector !== 'string' ) { return; }
    if ( selector === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('xml-prune', selector, selectorCheck, urlPattern);
    const reUrl = safe.patternToRegex(urlPattern);
    const extraArgs = safe.getExtraArgs(Array.from(arguments), 3);
    const queryAll = (xmlDoc, selector) => {
        const isXpath = /^xpath\(.+\)$/.test(selector);
        if ( isXpath === false ) {
            return Array.from(xmlDoc.querySelectorAll(selector));
        }
        const xpr = xmlDoc.evaluate(
            selector.slice(6, -1),
            xmlDoc,
            null,
            XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE,
            null
        );
        const out = [];
        for ( let i = 0; i < xpr.snapshotLength; i++ ) {
            const node = xpr.snapshotItem(i);
            out.push(node);
        }
        return out;
    };
    const pruneFromDoc = xmlDoc => {
        try {
            if ( selectorCheck !== '' && xmlDoc.querySelector(selectorCheck) === null ) {
                return xmlDoc;
            }
            if ( extraArgs.logdoc ) {
                const serializer = new XMLSerializer();
                safe.uboLog(logPrefix, `Document is\n\t${serializer.serializeToString(xmlDoc)}`);
            }
            const items = queryAll(xmlDoc, selector);
            if ( items.length === 0 ) { return xmlDoc; }
            safe.uboLog(logPrefix, `Removing ${items.length} items`);
            for ( const item of items ) {
                if ( item.nodeType === 1 ) {
                    item.remove();
                } else if ( item.nodeType === 2 ) {
                    item.ownerElement.removeAttribute(item.nodeName);
                }
                safe.uboLog(logPrefix, `${item.constructor.name}.${item.nodeName} removed`);
            }
        } catch(ex) {
            safe.uboErr(logPrefix, `Error: ${ex}`);
        }
        return xmlDoc;
    };
    const pruneFromText = text => {
        if ( (/^\s*</.test(text) && />\s*$/.test(text)) === false ) {
            return text;
        }
        try {
            const xmlParser = new DOMParser();
            const xmlDoc = xmlParser.parseFromString(text, 'text/xml');
            pruneFromDoc(xmlDoc);
            const serializer = new XMLSerializer();
            text = serializer.serializeToString(xmlDoc);
        } catch {
        }
        return text;
    };
    const urlFromArg = arg => {
        if ( typeof arg === 'string' ) { return arg; }
        if ( arg instanceof Request ) { return arg.url; }
        return String(arg);
    };
    self.fetch = new Proxy(self.fetch, {
        apply: function(target, thisArg, args) {
            const fetchPromise = Reflect.apply(target, thisArg, args);
            if ( reUrl.test(urlFromArg(args[0])) === false ) {
                return fetchPromise;
            }
            return fetchPromise.then(responseBefore => {
                const response = responseBefore.clone();
                return response.text().then(text => {
                    const responseAfter = new Response(pruneFromText(text), {
                        status: responseBefore.status,
                        statusText: responseBefore.statusText,
                        headers: responseBefore.headers,
                    });
                    Object.defineProperties(responseAfter, {
                        ok: { value: responseBefore.ok },
                        redirected: { value: responseBefore.redirected },
                        type: { value: responseBefore.type },
                        url: { value: responseBefore.url },
                    });
                    return responseAfter;
                }).catch(( ) =>
                    responseBefore
                );
            });
        }
    });
    self.XMLHttpRequest.prototype.open = new Proxy(self.XMLHttpRequest.prototype.open, {
        apply: async (target, thisArg, args) => {
            if ( reUrl.test(urlFromArg(args[1])) === false ) {
                return Reflect.apply(target, thisArg, args);
            }
            thisArg.addEventListener('readystatechange', function() {
                if ( thisArg.readyState !== 4 ) { return; }
                const type = thisArg.responseType;
                if (
                    type === 'document' ||
                    type === '' && thisArg.responseXML instanceof XMLDocument
                ) {
                    pruneFromDoc(thisArg.responseXML);
                    const serializer = new XMLSerializer();
                    const textout = serializer.serializeToString(thisArg.responseXML);
                    Object.defineProperty(thisArg, 'responseText', { value: textout });
                    if ( typeof thisArg.response === 'string' ) {
                        Object.defineProperty(thisArg, 'response', { value: textout });
                    }
                    return;
                }
                if (
                    type === 'text' ||
                    type === '' && typeof thisArg.responseText === 'string'
                ) {
                    const textin = thisArg.responseText;
                    const textout = pruneFromText(textin);
                    if ( textout === textin ) { return; }
                    Object.defineProperty(thisArg, 'response', { value: textout });
                    Object.defineProperty(thisArg, 'responseText', { value: textout });
                    return;
                }
            });
            return Reflect.apply(target, thisArg, args);
        }
    });
}

/******************************************************************************/

const scriptletGlobals = {}; // eslint-disable-line

const $scriptletFunctions$ = /* 47 */
[trustedJsonEditXhrRequest,adjustSetTimeout,jsonPruneFetchResponse,jsonPruneXhrResponse,trustedReplaceXhrResponse,trustedReplaceFetchResponse,trustedPreventDomBypass,jsonPrune,jsonEdit,setConstant,jsonlEditXhrResponse,noWindowOpenIf,abortCurrentScript,trustedSuppressNativeMethod,abortOnStackTrace,preventRequestAnimationFrame,preventInnerHTML,trustedSetConstant,trustedReplaceOutboundText,trustedReplaceArgument,preventXhr,preventSetTimeout,preventFetch,removeAttr,trustedOverrideElementMethod,preventAddEventListener,abortOnPropertyRead,adjustSetInterval,preventSetInterval,abortOnPropertyWrite,noWebrtc,noEvalIf,trustedPreventFetch,disableNewtabLinks,trustedJsonEditFetchResponse,trustedJsonEdit,trustedJsonEditXhrResponse,jsonEditXhrResponse,xmlPrune,m3uPrune,jsonEditFetchResponse,trustedPreventXhr,trustedEditInboundObject,spoofCSS,alertBuster,preventCanvas,jsonEditFetchRequest];

const $scriptletArgs$ = /* 3195 */ ["[?..userAgent*=\"channel\"]..client[?.clientName==\"WEB\"]+={\"clientScreen\":\"CHANNEL\"}","propsToMatch","/player?","[?..userAgent=/adunit|channel|lactmilli|instream|eafg/]..referer=repl({\"regex\":\"$\",\"replacement\":\"#reloadxhr\"})","[native code]","17000","0.001","adPlacements adSlots playerResponse.adPlacements playerResponse.adSlots [].playerResponse.adPlacements [].playerResponse.adSlots","","adPlacements adSlots playerResponse.adPlacements playerResponse.adSlots","/playlist?","/\\/player(?:\\?.+)?$/","\"adPlacements\"","\"no_ads\"","/playlist\\?list=|\\/player(?:\\?.+)?$|watch\\?[tv]=/","/\"adPlacements.*?([A-Z]\"\\}|\"\\}{2,4})\\}\\],/","/\"adPlacements.*?(\"adSlots\"|\"adBreakHeartbeatParams\")/gms","$1","player?","\"adSlots\"","/^\\W+$/","Node.prototype.appendChild","fetch","Request","JSON.parse","entries.[-].command.reelWatchEndpoint.adClientParams.isAd","/get_watch?","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.viewer.sideFeedUnit.nodes.[].new_adverts.nodes.[-].sponsored_data","data.viewer.sideFeedUnit.nodes.[].new_adverts.nodes.[-].sponsored_data","/graphql","..data.viewer..nodes.*[?.__typename==\"AdsSideFeedUnit\"]","Env.nxghljssj","false","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.serpResponse.results.edges.[-].rendering_strategy.view_model.story.sponsored_data.ad_id","..node[?.*.__typename==\"SponsoredData\"]",".data[?.category==\"SPONSORED\"].node",".data.viewer.news_feed.edges.*[?.category==\"SPONSORED\"].node","console.clear","undefined","globalThis","break;case","WebAssembly","atob","Array.from","\"/NodeList/\"","prevent","inlineScript","Document.prototype.querySelectorAll","\"/^\\[d[a-z]t[a-z]?-[0-9a-z]{2,4}\\]$/\"","HTMLElement.prototype.querySelectorAll","\"/.*\\[[^imns].+\\].*/\"","Element.prototype.hasAttribute","\"/[\\S\\s]+/\"","Document.prototype.evaluate","\"/.*/\"","Document.prototype.createTreeWalker","aclib","/stackDepth:3\\s+get injectedScript.+inlineScript/","setTimeout","/stackDepth:3.+inlineScript:\\d{4}:1/","Date","MessageChannel","/stackDepth:2.+inlineScript/","/\\.(gif|jpe?g|png|webp)/","requestAnimationFrame","Array.prototype.join","/^[\\S\\s]{2000,6000}$/","DOMTokenList.prototype.remove","/^[\\S\\s]{3000,4000}$/","/cssText'|:'style'/","Promise.resolve","/jso\\$|\\(_0x|(['\"`]\\s*[-0-9A-Z_a-z]+\\s*['\"`],\\s*){50,}|ByDZ/","json:{\"isShowingPop\":false}","aclib.runInterstitial","{}","as","function","Function.prototype.toString","( ) => value","runInterstitial(e){if(this.#fe.interstitial)return void this.#r.error(\"interstitial zone already loaded on page\");this.#fe.interstitial=!0;const{zoneId:t,sub1:r,isAutoTag:n,collectiveZoneId:i,linkedZoneId:o,aggressivity:s,recordPageView:a,abTest:c,tagVersionSuffix:u}=e;if(!t)throw new Error(\"mandatory zoneId is not provided!\");if(!we(t))throw new Error(\"zoneId is not a string!\");this.#r.debug(\"loading interstitial on page\");const l={zoneId:t,sub1:r,isAutoTag:n,collectiveZoneId:i,linkedZoneId:o,aggressivity:s,recordPageView:a,abTest:c,tagVersionSuffix:u,adcashGlobalName:this.#xe,adserverDomain:this.#v,adblockSettings:this.#s,uniqueFingerprint:this.#C,isLoadedAsPartOfLibrary:!1};if(this.#pe.add(t),this.#Ce.Interstitial)return l.isLoadedAsPartOfLibrary=!0,void new this.#Ce.Interstitial(l);if(window.Interstitial)new Interstitial(l);else{const e=document.createElement(\"script\");e.type=\"text/javascript\",e.src=`${location.protocol}//${this.#he}/script/interstitial.js`,e.setAttribute(\"a-lib\",\"1\"),e.onload=()=>{new Interstitial(l)},e.onerror=()=>{this.#r.error(`failed loading ${e.src}`)},document.head.appendChild(e)}}","Element.prototype.getAttribute","0","json:\"class\"","condition","d-z","/vast.php?","/click\\.com|preroll|native_render\\.js|acscdn/","length:10001","]();}","500","162.252.214.4","true","c.adsco.re","adsco.re:2087","/^ [-\\d]/","Math.random","parseInt(localStorage['\\x","adBlockDetected","Math","localStorage['\\x","-load.com/script/","length:101",")](this,...","3000-6000","(new Error(","/fd/ls/lsp.aspx","document.getElementById","json:\"body\"","ad-detection-bait","document.querySelector","-id-","scriptBlocked","blocked","testUrls","[]",".offsetHeight>0","/^https:\\/\\/pagead2\\.googlesyndication\\.com\\/pagead\\/js\\/adsbygoogle\\.js\\?client=ca-pub-3497863494706299$/","data-instype","ins.adsbygoogle:has(> div#aswift_0_host)","stay","url:https://googleads.g.doubleclick.net/pagead/ads?client=ca-pub-3497863494706299 method:HEAD mode:no-cors","throttle","121","String.prototype.indexOf","json:\"/\"","/premium","HTMLIFrameElement.prototype.remove","iframe[src^=\"https://googleads.g.doubleclick.net/pagead/ads?client=ca-pub-3497863494706299\"]","adblock","4000-","++","g.doubleclick.net","length:100000","String.prototype.includes","/Copyright|doubleclick$/","favicon","length:252","Headers.prototype.get","/.+/","image/png.","/^text\\/plain;charset=UTF-8$/","json:\"content-type\"","cache-control","Headers.prototype.has","summerday","length:10","{\"type\":\"cors\"}","/offsetHeight|loaded/","HTMLScriptElement.prototype.onerror","pagead2.googlesyndication.com/pagead/js/adsbygoogle.js method:HEAD","emptyStr","Node.prototype.contains","{\"className\":\"adsbygoogle\"}","abort","load","showFallbackModal","Object.prototype.adsStrategy","json:{\"tag\":\"\",\"phase\":0,\"permaProvider\":0,\"tempoProvider\":0,\"buckets\":[],\"comment\":\"no-user\",\"rotationPaused\":true}","_adBlockState","Keen","stream.insertion","/video/auth/media","akamaiDisableServerIpLookup","noopFunc","MONETIZER101.init","/outboundLink/","v.fwmrm.net/ad/g/","war:noop-vmap1.xml","DD_RUM.addAction","nads.createAd","trueFunc","t++","dvtag.getTargeting","ga","class|style","div[id^=\"los40_gpt\"]","huecosPBS.nstdX","null","config.globalInteractions.[].bsData","googlesyndication","DTM.trackAsyncPV","_satellite","_satellite.getVisitorId","mobileanalytics","newPageViewSpeedtest","pubg.unload","generateGalleryAd","mediator","Object.prototype.subscribe","gbTracker","gbTracker.sendAutoSearchEvent","Object.prototype.vjsPlayer.ads","marmalade","setInterval","url:ipapi.co","doubleclick","isPeriodic","*","data-woman-ex","a[href][data-woman-ex]","data-trm-action|data-trm-category|data-trm-label",".trm_event","KeenTracking","network_user_id","cloudflare.com/cdn-cgi/trace","History","/(^(?!.*(Function|HTMLDocument).*))/","api","google.ima.OmidVerificationVendor","Object.prototype.omidAccessModeRules","googletag.cmd","skipAdSeconds","0.02","/recommendations.","_aps","/api/analytics","Object.prototype.setDisableFlashAds","DD_RUM.addTiming","chameleonVideo.adDisabledRequested","AdmostClient","analytics","native code","15000","(null)","5000","datalayer","Object.prototype.isInitialLoadDisabled","lr-ingest.io","listingGoogleEETracking","dcsMultiTrack","urlStrArray","pa","Object.prototype.setConfigurations","/gtm.js","JadIds","Object.prototype.bk_addPageCtx","Object.prototype.bk_doJSTag","passFingerPrint","optimizely","optimizely.initialized","google_optimize","google_optimize.get","_gsq","_gsq.push","_gsDevice","iom","iom.c","_conv_q","_conv_q.push","google.ima.settings.setDisableFlashAds","pa.privacy","populateClientData4RBA","YT.ImaManager","UOLPD","UOLPD.dataLayer","__configuredDFPTags","URL_VAST_YOUTUBE","Adman","dplus","dplus.track","_satellite.track","/EzoIvent|TDELAY/","google.ima.dai","/froloa.js","adv","gfkS2sExtension","gfkS2sExtension.HTML5VODExtension","click","/event_callback=function\\(\\){window\\.location=t\\.getAttribute\\(\"href\"\\)/","AnalyticsEventTrackingJS","AnalyticsEventTrackingJS.addToBasket","AnalyticsEventTrackingJS.trackErrorMessage","initializeslideshow","b()","3000","ads","fathom","fathom.trackGoal","Origami","Origami.fastclick","{\"value\": \".ad-placement-interstitial\"}",".easyAdsBox","jad","hasAdblocker","Sentry","Sentry.init","TRC","TRC._taboolaClone","fp","fp.t","fp.s","initializeNewRelic","turnerAnalyticsObj","turnerAnalyticsObj.setVideoObject4AnalyticsProperty","turnerAnalyticsObj.getVideoObject4AnalyticsProperty","optimizelyDatafile","optimizelyDatafile.featureFlags","fingerprint","fingerprint.getCookie","gform.utils","gform.utils.trigger","get_fingerprint","moatPrebidApi","moatPrebidApi.getMoatTargetingForPage","readyPromise","cpd_configdata","cpd_configdata.url","yieldlove_cmd","yieldlove_cmd.push","dataLayer.push","1.1.1.1/cdn-cgi/trace","_etmc","_etmc.push","freshpaint","freshpaint.track","ShowRewards","stLight","stLight.options","DD_RUM.addError","sensorsDataAnalytic201505","sensorsDataAnalytic201505.init","sensorsDataAnalytic201505.quick","sensorsDataAnalytic201505.track","s","s.tl","taboola timeout","clearInterval(run)","smartech","/TDELAY|EzoIvent/","sensors","sensors.init","/piwik-","2200","2300","sensors.track","googleFC","adn","adn.clearDivs","_vwo_code","live.streamtheworld.com/partnerIds","gtag","_taboola","_taboola.push","clicky","clicky.goal","WURFL","_sp_.config.events.onSPPMObjectReady","gtm","gtm.trackEvent","mParticle.Identity.getCurrentUser","_omapp.scripts.geolocation","{\"value\": {\"status\":\"loaded\",\"object\":null,\"data\":{\"country\":{\"shortName\":\"\",\"longName\":\"\"},\"administrative_area_level_1\":{\"shortName\":\"\",\"longName\":\"\"},\"administrative_area_level_2\":{\"shortName\":\"\",\"longName\":\"\"},\"locality\":{\"shortName\":\"\",\"longName\":\"\"},\"original\":{\"ip\":\"\",\"ip_decimal\":null,\"country\":\"\",\"country_eu\":false,\"country_iso\":\"\",\"city\":\"\",\"latitude\":null,\"longitude\":null,\"user_agent\":{\"product\":\"\",\"version\":\"\",\"comment\":\"\",\"raw_value\":\"\"},\"zip_code\":\"\",\"time_zone\":\"\"}},\"error\":\"\"}}","JSGlobals.prebidEnabled","i||(e(),i=!0)","2500","elasticApm","elasticApm.init","ga.sendGaEvent","adConfig","ads.viralize.tv","adobe","MT","MT.track","ClickOmniPartner","adex","adex.getAdexUser","Adkit","Object.prototype.shouldExpectGoogleCMP","apntag.refresh","pa.sendEvent","Munchkin","Munchkin.init","Event","ttd_dom_ready","ramp","appInfo.snowplow.trackSelfDescribingEvent","_vwo_code.init","adobePageView","adobeSearchBox","elements",".dropdown-menu a[href]","dapTracker","dapTracker.track","newrelic","newrelic.setCustomAttribute","adobeDataLayer","adobeDataLayer.push","Object.prototype._adsDisabled","Object.defineProperty","1","json:\"_adsEnabled\"","_adsDisabled","utag","utag.link","_satellite.kpCustomEvent","Object.prototype.disablecommercials","Object.prototype._autoPlayOnlyWithPrerollAd","Sentry.addBreadcrumb","sensorsDataAnalytic201505.register","freestar.newAdSlots","String.prototype.allReplace","executaGoogleAnalytics3","initJWPlayerMux","initJWPlayerMux.utils","initJWPlayerMux.utils.now","ambossAnalytics","ambossAnalytics.getUserAttribution","ytInitialPlayerResponse.playerAds","ytInitialPlayerResponse.adPlacements","ytInitialPlayerResponse.adSlots","playerResponse.adPlacements","playerResponse.adPlacements playerResponse.playerAds playerResponse.adSlots adPlacements playerAds adSlots important","reelWatchSequenceResponse.entries.[-].command.reelWatchEndpoint.adClientParams.isAd entries.[-].command.reelWatchEndpoint.adClientParams.isAd","url:/reel_watch_sequence?","Object","fireEvent","enabled","force_disabled","hard_block","header_menu_abvs","10000","adsbygoogle","nsShowMaxCount","toiads","objVc.interstitial_web","adb","navigator.userAgent","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.serpResponse.results.edges.[-].relay_rendering_strategy.view_model.story.sponsored_data.ad_id","/\\{\"node\":\\{\"role\":\"SEARCH_ADS\"[^\\n]+?cursor\":[^}]+\\}/g","/api/graphql","/\\{\"node\":\\{\"__typename\":\"MarketplaceFeedAdStory\"[^\\n]+?\"cursor\":(?:null|\"\\{[^\\n]+?\\}\"|[^\\n]+?MarketplaceSearchFeedStoriesEdge\")\\}/g","/\\{\"node\":\\{\"__typename\":\"VideoHomeFeedUnitSectionComponent\"[^\\n]+?\"sponsored_data\":\\{\"ad_id\"[^\\n]+?\"cursor\":null\\}/","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.node","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.node.story.sponsored_data.ad_id","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.marketplace_search.feed_units.edges.[-].node.story.sponsored_data.ad_id","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.viewer.marketplace_feed_stories.edges.[-].node.story.sponsored_data.ad_id","data.viewer.instream_video_ads data.scrubber","..node[?.__typename==\"MarketplaceFeedAdStory\"]","__eiPb","detector","_ml_ads_ns","jQuery","cookie","showAds","adBlockerDetected","show","SmartAdServerASMI","repl:/\"adBlockWallEnabled\":true/\"adBlockWallEnabled\":false/","adBlockWallEnabled","_sp_._networkListenerData","SZAdBlockDetection","_sp_.config","AntiAd.check","open","/^/","showNotice","_sp_","$","_sp_.mms.startMsg","retrievalService","admrlWpJsonP","yafaIt","LieDetector","ClickHandler","IsAdblockRequest","InfMediafireMobileFunc","1000","newcontent","ExoLoader.serve","Fingerprint2","request=adb","AdController","popupBlocked","/\\}\\s*\\(.*?\\b(self|this|window)\\b.*?\\)/","_0x","stop","onload","ga.length","btoa","adcashMacros","grecaptcha.ready","BACK","jwplayer.utils.Timer","puOverlay","adblock_added","admc","exoNoExternalUI38djdkjDDJsio96","String.prototype.charCodeAt","ai_","window.open","SBMGlobal.run.pcCallback","SBMGlobal.run.gramCallback","(!o)","(!i)","Object.prototype.hideAds","Object.prototype._getSalesHouseConfigurations","player-feedback","samInitDetection","decodeURI","decodeURIComponent","Date.prototype.toUTCString","Adcash","lobster","openLity","ad_abblock_ad","String.fromCharCode","shift","PopAds","AdBlocker","Adblock","addEventListener","displayMessage","runAdblock","document.createElement","TestAdBlock","ExoLoader","loadTool","cticodes","imgadbpops","document.write","redirect","4000","sadbl","adblockcheck","doSecondPop","arrvast","onclick","RunAds","/^(?:click|mousedown)$/","bypassEventsInProxies","jQuery.adblock","test-block","adi","ads_block","blockAdBlock","blurred","exoOpts","doOpen","prPuShown","flashvars.adv_pre_src","showPopunder","IS_ADBLOCK","page_params.holiday_promo","__NA","ads_priv","ab_detected","adsEnabled","document.dispatchEvent","t4PP","href|target","a[href=\"https://imgprime.com/view.php\"][target=\"_blank\"]","complete","String.prototype.charAt","sc_adv_out","mz","ad_blocker","AaDetector","_abb","puShown","/doOpen|popundr/","pURL","readyState","serve","stop()","Math.floor","AdBlockDetectorWorkaround","apstagLOADED","jQuery.hello","/Adb|moneyDetect/","isShowingAd","VikiPlayer.prototype.pingAbFactor","player.options.disableAds","__htapop","exopop","/^(?:load|click)$/","popMagic","script","atOptions","XMLHttpRequest","flashvars.adv_pre_vast","flashvars.adv_pre_vast_alt","x_width","getexoloader","disableDeveloper","oms.ads_detect","Blocco","2000","_site_ads_ns","hasAdBlock","pop","ltvModal","luxuretv.config","popns","pushiserve","creativeLoaded-","exoframe","/^load[A-Za-z]{12,}/","rollexzone","ALoader","Object.prototype.AdOverlay","tkn_popunder","detect","dlw","40000","ctt()","can_run_ads","test","adsBlockerDetector","NREUM","pop3","__ads","ready","popzone","FlixPop.isPopGloballyEnabled","falseFunc","/exo","ads.pop_url","checkAdblockUser","checkPub","6000","tabUnder","check_adblock","l.parentNode.insertBefore(s","_blank","ExoLoader.addZone","encodeURIComponent","isAdBlockActive","raConf","__ADX_URL_U","tabunder","RegExp","POSTBACK_PIXEL","mousedown","preventDefault","'0x","Aloader","advobj","replace","popTimes","addElementToBody","phantomPopunders","$.magnificPopup.open","adsenseadBlock","stagedPopUnder","seconds","clearInterval","CustomEvent","exoJsPop101","popjs.init","-0x","closeMyAd","smrtSP","adblockSuspected","nextFunction","250","xRds","cRAds","myTimer","1500","advertising","countdown","tiPopAction","rmVideoPlay","r3H4","disasterpingu","document.querySelectorAll","AdservingModule","backRedirect","adv_pre_duration","adv_post_duration","/^(click|mousedown|mousemove|touchstart|touchend|touchmove)/","system.popunder","ab1","ab2","hidekeep","pp12","__Y","App.views.adsView.adblock","document.createEvent","ShowAdbblock","style","clientHeight","flashvars.adv_pause_html","/^(?:click|mousedown|mousemove|touchstart|touchend|touchmove)$/","BOOTLOADER_LOADED","PerformanceLongTaskTiming","proxyLocation","Int32Array","$.fx.off","popMagic.init","/DOMContentLoaded|load/","y.readyState","document.getElementsByTagName","smrtSB","href","#opfk","byepopup","awm","location","adBlockEnabled","getCookie","history.go","dataPopUnder","/error|canplay/","(t)","EPeventFire","additional_src","300","____POP","openx","is_noadblock","window.location","()","hblocked","AdBlockUtil","css_class.show","/adbl/i","CANG","DOMContentLoaded","adlinkfly","updato-overlay","innerText","/amazon-adsystem|example\\.com/","document.cookie","|","attr","scriptSrc","SmartWallSDK","segs_pop","cxStartDetectionProcess","Abd_Detector","counter","paywallWrapper","isAdBlocked","/enthusiastgaming|googleoptimize|googletagmanager/","css_class","ez","path","*.adserverDomain","10","$getWin","/doubleclick|googlesyndication/","__NEXT_DATA__.props.clientConfigSettings.videoAds","blockAds","_ctrl_vt.blocked.ad_script","registerSlideshowAd","50","debugger","mm","shortener","require","/^(?!.*(einthusan\\.io|yahoo|rtnotif|ajax|quantcast|bugsnag))/","caca","getUrlParameter","trigger","Ok","given","getScriptFromCss","method:HEAD","safelink.adblock","goafricaSplashScreenAd","try","/adnxs.com|onetag-sys.com|teads.tv|google-analytics.com|rubiconproject.com|casalemedia.com/","openPopunder","0x","xhr.prototype.realSend","initializeCourier","userAgent","_0xbeb9","1800","popAdsClickCount","redirectPage","adblocker","ad_","azar","popunderSetup","https","popunder","preventExit","hilltop","jsPopunder","vglnk","aadblock","S9tt","popUpUrl","Notification","srcdoc","iframe","readCookieDelit","trafficjunky","checked","input#chkIsAdd","adSSetup","adblockerModal","750","html","capapubli","Aloader.serve","mouseup","sp_ad","app_vars.force_disable_adblock","adsHeight","onmousemove","button","yuidea-","adsBlocked","_sp_.msg.displayMessage","pop_under","location.href","_0x32d5","url","blur","CaptchmeState.adb","glxopen","adverts-top-container","disable","200","/googlesyndication|outbrain/","CekAab","timeLeft","testadblock","document.addEventListener","google_ad_client","UhasAB","adbackDebug","googletag","performance","rbm_block_active","adNotificationDetected","SubmitDownload1","show()","user=null","getIfc","!bergblock","overlayBtn","adBlockRunning","htaUrl","_pop","n.trigger","CnnXt.Event.fire","_ti_update_user","&nbsp","document.body.appendChild","BetterJsPop","/.?/","setExoCookie","adblockDetected","frg","abDetected","target","I833","urls","urls.0","Object.assign","KeepOpeningPops","bindall","ad_block","time","KillAdBlock","read_cookie","ReviveBannerInterstitial","eval","GNCA_Ad_Support","checkAdBlocker","midRoll","adBlocked","Date.now","AdBlock","iframeTestTimeMS","runInIframe","deployads","='\\x","Debugger","stackDepth:3","warning","100","_checkBait","[href*=\"ccbill\"]","close_screen","onerror","dismissAdBlock","VMG.Components.Adblock","adblock_popup","FuckAdBlock","isAdEnabled","promo","_0x311a","mockingbird","adblockDetector","crakPopInParams","console.log","hasPoped","Math.round","flashvars.protect_block","flashvars.video_click_url","h1mm.w3","banner","google_jobrunner","blocker_div","onscroll","keep-ads","#rbm_block_active","checkAdblock","checkAds","#DontBloxMyAdZ","#pageWrapper","adpbtest","initDetection","alert","check","isBlanketFound","showModal","myaabpfun","sec","_wm","adFilled","//","NativeAd","gadb","damoh.ani-stream.com","showPopup","mouseout","clientWidth","adrecover","checkadBlock","gandalfads","Tool","clientSide.adbDetect","HTMLAnchorElement.prototype.click","anchor.href","cmnnrunads","downloadJSAtOnload","run","ReactAds","phtData","adBlocker","StileApp.somecontrols.adBlockDetected","killAdBlock","innerHTML","google_tag_data","readyplayer","noAdBlock","autoRecov","adblockblock","popit","popstate","noPop","Ha","rid","[onclick^=\"window.open\"]","tick","spot","adsOk","adBlockChecker","_$","12345","flashvars.popunder_url","urlForPopup","isal","/innerHTML|AdBlock/","checkStopBlock","overlay","popad","!za.gl","document.hidden","adblockEnabled","ppu","adspot_top","is_adblocked","/offsetHeight|google|Global/","an_message","Adblocker","pogo.intermission.staticAdIntermissionPeriod","localStorage","timeoutChecker","t","my_pop","nombre_dominio",".height","!?safelink_redirect=","document.documentElement","break;case $.","time.html","block_detected","/^(?:mousedown|mouseup)$/","ckaduMobilePop","tieneAdblock","popundr","obj","ujsmediatags method:HEAD","adsAreBlocked","spr","document.oncontextmenu","document.onmousedown","document.onkeydown","compupaste","redirectURL","bait","!atomtt","TID","!/download\\/|link/","Math.pow","adsanity_ad_block_vars","pace","ai_adb","openInNewTab",".append","!!{});","runAdBlocker","setOCookie","document.getElementsByClassName","td_ad_background_click_link","initBCPopunder","flashvars.logo_url","flashvars.logo_text","nlf.custom.userCapabilities","displayCookieWallBanner","adblockinfo","JSON","pum-open","svonm","/\\/VisitorAPI\\.js|\\/AppMeasurement\\.js/","popjs","/adblock/i","count","LoadThisScript","showPremLite","closeBlockerModal","5","keydown","Popunder","ag_adBlockerDetected","document.head.appendChild","bait.css","Date.prototype.toGMTString","initPu","jsUnda","ABD","adBlockDetector.isEnabled","adtoniq","__esModule","break","myFunction_ads","areAdsDisplayed","gkAdsWerbung","pop_target","onLoadEvent","is_banner","$easyadvtblock","mfbDetect","!/^https:\\/\\/sendvid\\.com\\/[0-9a-z]+$/","Pub2a","length:40000-60000","block","console","send","ab_cl","V4ss","#clickfakeplayer","popunders","visibility","show_dfp_preroll","show_youtube_preroll","brave_load_popup","pageParams.dispAds","PrivateMode","scroll","document.bridCanRunAds","doads","pu","advads_passive_ads","tmohentai","pmc_admanager.show_interrupt_ads","ai_adb_overlay","AlobaidiDetectAdBlock","showMsgAb","Advertisement","type","input[value^=\"http\"]","wutimeBotPattern","adsbytrafficjunkycontext","abp1","$REACTBASE_STATE.serverModules.push","popup_ads","ipod","pr_okvalida","scriptwz_url","enlace","Popup","$.ajax","appendChild","Exoloader","offsetWidth","zomap.de","/$|adBlock/","adblockerpopup","adblockCheck","checkVPN","cancelAdBlocker","Promise","setNptTechAdblockerCookie","for-variations","!api?call=","cnbc.canShowAds","ExoSupport","/^(?:click|mousedown|mouseup)$/","di()","getElementById","loadRunative","value.media.ad_breaks","onAdVideoStart","zonefile","pwparams","fuckAdBlock","firefaucet","mark","stop-scrolling","detectAdBlock","Adv","blockUI","adsafeprotected","'\\'","oncontextmenu","Base64","disableItToContinue","google","parcelRequire","mdpDeBlocker","flashvars.adv_start_html","mobilePop","/_0x|debug/","my_inter_listen","EviPopunder","adver","tcpusher","preadvercb","document.readyState","prerollMain","popping","adsrefresh","/ai_adb|_0x/","canRunAds","mdp_deblocker","adBlock","bi()","#divDownload","modal","dclm_ajax_var.disclaimer_redirect_url","$ADP","load_pop_power","MG2Loader","/SplashScreen|BannerAd/","Connext","break;","checkTarget","i--","Time_Start","blocker","adUnits","afs_ads","b2a","data.[].vast_url","deleted","MutationObserver","ezstandalone.enabled","damoh","foundation.adPlayer.bitmovin","homad-global-configs","weltConfig.switches.videoAdBlockBlocker","XMLHttpRequest.prototype.open","svonm.com","/\"enabled\":\\s*true/","\"enabled\":false","adReinsertion","window.__gv_org_tfa","Object.prototype.adReinsertion","getHomadConfig","aud.springserve.com","<VAST version=\"3.0\"></VAST>","timeupdate","testhide","getComputedStyle","doOnce","popi","googlefc","angular","detected","{r()","450","ab","go_popup","Debug","offsetHeight","length","noBlocker","/youboranqs01|spotx|springserve/","js-btn-skip","r()","adblockActivated","penci_adlbock","Number.isNaN","fabActive","gWkbAdVert","noblock","wgAffiliateEnabled","!gdrivedownload","document.onclick","daCheckManager","prompt","data-popunder-url","saveLastEvent","friendlyduck",".post.movies","purple_box","detectAdblock","adblockDetect","adsLoadable","allclick_Public","a#clickfakeplayer",".fake_player > [href][target]",".link","'\\x","initAdserver","splashpage.init","window[_0x","checkSiteNormalLoad","/blob|injectedScript/","ASSetCookieAds","___tp","STREAM_CONFIGS",".clickbutton","Detected","XF","hide","mdp",".test","backgroundBanner","interstitial","letShowAds","antiblock","ulp_noadb",".show","url:!luscious.net","Object.prototype.adblock_detected","afterOpen","AffiliateAdBlock",".appendChild","adsbygoogle.loaded","ads_unblocked","xxSetting.adBlockerDetection","ppload","RegAdBlocking","a.adm","checkABlockP","Drupal.behaviors.adBlockerPopup","ADBLOCK","fake_ad","samOverlay","!refine?search","native","koddostu_com_adblock_yok","player.ads.cuePoints","adthrive","!t.me","bADBlock","better_ads_adblock","tie","Adv_ab","ignore_adblock","$.prototype.offset","ea.add","ad_pods.0.ads.0.segments.0.media ad_pods.1.ads.1.segments.1.media ad_pods.2.ads.2.segments.2.media ad_pods.3.ads.3.segments.3.media ad_pods.4.ads.4.segments.4.media ad_pods.5.ads.5.segments.5.media ad_pods.6.ads.6.segments.6.media ad_pods.7.ads.7.segments.7.media ad_pods.8.ads.8.segments.8.media","mouseleave","NativeDisplayAdID","t()","zendplace","mouseover","event.triggered","_cpp","sgpbCanRunAds","pareAdblock","ppcnt","data-ppcnt_ads","main[onclick]","Blocker","AdBDetected","navigator.brave","document.activeElement","{ \"value\": {\"tagName\": \"IFRAME\" }}","runAt","2","clickCount","body","hasFocus","{\"value\": \"Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1\"}","timeSec","getlink","/wpsafe|wait/","timer","/getElementById|gotoo/","/visibilitychange|blur/","stopCountdown","ppuQnty","web_share_ads_adsterra_config wap_short_link_middle_page_ad wap_short_link_middle_page_show_time data.ads_cpm_info","value","Object.prototype.isAllAdClose","DOMNodeRemoved","data.meta.require_addon data.meta.require_captcha data.meta.require_notifications data.meta.require_og_ads data.meta.require_video data.meta.require_web data.meta.require_related_topics data.meta.require_custom_ad_step data.meta.og_ads_offers data.meta.addon_url data.displayAds data.linkCustomAdOffers","data.getDetailPageContent.linkCustomAdOffers.[-].title","data.getTaboolaAds.*","/chp_?ad/","/adblock|isRequestPresent/","bmcdn6","window.onload","devtools","documentElement.innerHTML","{\"type\": \"opaque\"}","document.hasFocus","/adoto|\\/ads\\/js/","htmls","?key=","isRequestPresent","xmlhttp","data-ppcnt_ads|onclick","#main","#main[onclick*=\"mainClick\"]",".btn-success.get-link","fouty","disabled",".btn-primary","focusOut","googletagmanager","suaads","/window\\.location\\.href|n/","8000","json:\"drall_Suaads_annersads_JS__randomAds\"","/randomAds|div-gpt-ad|divAdsInit/","json:\"ADs-1\"","json:\"click\"","visibilitychange","window.addEventListener","/visibilitychange|blur|pageshow|keydown|beforeunload|pagehide/","/\\$\\('|ai-close/","app_vars.please_disable_adblock","bypass",".MyAd > a[target=\"_blank\"]","antiAdBlockerHandler","onScriptError","php","div_form","private","navigator.webkitTemporaryStorage.queryUsageAndQuota","contextmenu","remainingSeconds","0.1","Math.random() <= 0.15","checkBrowser","bypass_url","1600","class","#rtg-snp21","adsby","showadas","submit","validateForm","throwFunc","/pagead2\\.googlesyndication\\.com|inklinkor\\.com/","EventTarget.prototype.addEventListener","delete window","/countdown--|getElementById/","SMart1","/outbrain\\.com|adligature\\.com|quantserve\\.com|srvtrck\\.com|googlesyndication/","{\"type\": \"cors\"}","doTest","checkAdsBlocked",".btn","http","3","document.visibilityState","hidden","1e3*","/veepteero|tag\\.min\\.js/","aSl.gcd","/\\/4.+ _0/","chp_ad","document.documentElement.lang.toLowerCase","[onclick^=\"pop\"]","Light.Popup","maxclick","#get-link-button","Swal.fire","surfe.pro","czilladx","adsbygoogle.js","!devuploads.com","war:googlesyndication_adsbygoogle.js","window.adLink","localStorage._d","blank","google_srt","json:0.61234","vizier","checkAdBlock","shouldOpenPopUp","displayAdBlockerMessage","pastepc","detectedAdblock","pagead2.googlesyndication.com/pagead/js/adsbygoogle.js","googletagservices","isTabActive","a[target=\"_blank\"]","[href*=\"survey\"]","adForm","/adsbygoogle|googletagservices/","clicked","decodeURIComponent(escape","clicksCount",".data.isAdsEnabled=false","/api/files","document.createTreeWalker","json:{\"acceptNode\": \"function() { return NodeFilter.FILTER_REJECT; }\"}","..directLink","..props[?.children*=\"clicksCount\"].children","adskeeper",".downloadbtn","zigi_tag_id","(function(","setCookie","advertisement3","start","!/(flashbang\\.sh|dl\\.buzzheavier\\.com)/","!dl.buzzheavier.com","!buzzheavier.com","removeChild","notifyExec","fairAdblock","data.value data.redirectUrl data.bannerUrl","/admin/settings","!gcloud","/seconds--|timeLeft--/","json:\"main\"","/div-gpt-ad-dgking|\\.GoogleActiveViewElement/","/div-gpt-ad-|\\.adsbygoogle/","json:\"container\"","adblock_detected","/pub\\.clickadu|bing\\.com/","a","\"/chp_?ad/\"","/blocked|null|return/","remaining--","secondsLeft","script[data-domain=","document.body.appendChild(s)","push",".call(null)","ov.advertising.tisoomi.loadScript","abp","userHasAdblocker","embedAddefend","/injectedScript.*inlineScript/","/(?=.*onerror)(?=^(?!.*(https)))/","/injectedScript|blob/","hommy.mutation.mutation","hommy","hommy.waitUntil","ACtMan","video.channel","/(www\\.[a-z]{8,16}\\.com|cloudfront\\.net)\\/.+\\.(css|js)$/","/popundersPerIP[\\s\\S]*?Date[\\s\\S]*?getElementsByTagName[\\s\\S]*?insertBefore/","clearTimeout","/www|cloudfront/","shouldShow","matchMedia","target.appendChild(s","l.appendChild(s)","document.body.appendChild(s","no-referrer-when-downgrade","/^data:/","Document.prototype.createElement","\"script\"","litespeed/js","appendTo:","myEl","ExoDetector","!embedy","Pub2","/loadMomoVip|loadExo|includeSpecial/","loadNeverBlock","flashvars.mlogo","adver.abFucker.serve","displayCache","vpPrerollVideo","SpecialUp","zfgloaded","parseInt","/btoa|break/","/\\st\\.[a-zA-Z]*\\s/","navigator","/(?=^(?!.*(https)))/","key in document","zfgformats","zfgstorage","zfgloadedpopup","/\\st\\.[a-zA-Z]*\\sinlineScript/","zfgcodeloaded","outbrain","/inlineScript|stackDepth:1/","wpadmngr.com","adserverDomain",".js?_=","FingerprintJS","/https|stackDepth:3/","HTMLAllCollection","shown_at","!/d/","PlayerConfig.config.CustomAdSetting","affiliate","_createCatchAllDiv","/click|mouse/","document","PlayerConfig.trusted","PlayerConfig.config.AffiliateAdViewLevel","univresalP","puTSstrpcht","!/prcf.fiyar|themes|pixsense|.jpg/","hold_click","focus","js_func_decode_base_64","decodeURIComponent(atob","/(?=^(?!.*(https|injectedScript)))/","jQuery.popunder","AdDetect","ai_front","abDetectorPro","/googlesyndication|doubleclick/","src=atob","Document.prototype.querySelector","\"/[0-9a-f]+-modal/\"","/\\/[0-9a-f]+\\.js\\?ver=/","tie.ad_blocker_detector","admiral","..admiralScriptCode",".props[?.id==\"admiral-bootstrap\"].dangerouslySetInnerHTML","decodeURI(decodeURI","dc.adfree","error","gnt.x.uam","interactive","g$.hp","json:{\"gnt-d-adm\":true,\"gnt-d-bt\":true}","gnt.u.z","__INITIAL_DATA__.siteData.admiralScript",".cmd.unshift","/admiral/","runtimeConfig.AM_PATH","..props[?.id==\"admiral-initializer\"].children","..props.children.*[?.key==\"admiral-script\"]","..props.config.ad.enabled=false","..Admiral.isEnabled=false","..admiral=false","/ad\\.doubleclick\\.net|static\\.dable\\.io/","error-report.com","loader.min.js","content-loader.com","HTMLScriptElement.prototype.setAttribute","/error-report|new Promise|;await new|:\\[?window|&&window,|void 0\\]|location\\.href|void 0\\|\\|window/","objAd.loadAdShield","window.myAd.runAd","RT-1562-AdShield-script-on-Huffpost","{\"value\": \"(function(){let link=document.createElement('link');link.rel='stylesheet';link.href='//image.ygosu.com/style/main.css';document.head.appendChild(link)})()\"}","error-report","{\"value\": \"(function(){let link=document.createElement('link');link.rel='stylesheet';link.href='https://loawa.com/assets/css/loawa.min.css';document.head.appendChild(link)})()\"}","/07c225f3\\.online|content-loader\\.com|css-load\\.com|html-load\\.com/","html-load.com","repl:/\"$//","json:\"setTimeout((()=>{if(!location.pathname.startsWith('/game'))return;const t=document.getElementById('question-label');t&&(window.animation=lottie.loadAnimation({container:t,renderer:'svg',loop:!0,autoplay:!1,path:'/assets/animationsLottielab/gameDots.json'}))}),1e3);\"","__cfRLUnblockHandlers","disableAdShield","json:\"freestar-bootstrap\"","/^[A-Z][a-z]+_$/","\"data-sdk\"","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=","AHE.is_member","USER.features.ad_shield","AppBootstrapData.config.adshieldAdblockRecovery","AppBootstrapData.config.adshieldNativeAdRecovery","AppBootstrapData.__initializeFeatures__.adshieldAdblockRecovery.enabled","AppState.reduxState.features.adshieldAdblockRecovery","..adshieldAdblockRecovery=false","/fetchappbootstrapdata","..adshieldAdblockRecovery.enabled=false","__NEXT_DATA__.runtimeConfig.enableShieldScript","HT.features.ad_shield.enabled","Object.prototype._adShieldLoaded","HTMLScriptElement.prototype.onload","..AdShield.isEnabled=false","String.prototype.match","__adblocker","__INITIAL_STATE__.config.theme.ads.isAdBlockerEnabled","generalTimeLeft","__INITIAL_STATE__.gameLists.gamesNoPrerollIds.indexOf","__aaZoneid","DoodPop",".check=false","#over","document.ontouchend","Array.prototype.shift","/^.+$/s","HTMLElement.prototype.click","premium","'1'","playID","openNewTab","download-wrapper","MDCore.adblock","Please wait","#downloadvideo","ads playerAds","pop_init","adsbyjuicy","np.detect","mode:no-cors","prerolls midrolls postrolls comm_ad house_ad pause_ad block_ad end_ad exit_ad pin_ad content_pool vertical_ad elements","/detail","adClosedTimestamp","data.item.[-].business_info.ad_desc","/feed/rcmd","killads","NMAFMediaPlayerController.vastManager.vastShown","reklama-flash-body","fakeAd","adUrl",".azurewebsites.net","assets.preroll assets.prerollDebug","/stream-link","/doubleclick|ad-delivery|googlesyndication/","__NEXT_DATA__.runtimeConfig._qub_sdk.qubConfig.video.adBlockerDetectorEnabled","data.[].relationships.advert data.[].relationships.vast","offers","/#EXT-X-DISCONTINUITY\\n(?:#EXTINF:.*,\\n.+?adType=preroll[\\s\\S]+?)(?=#EXT-X-DISCONTINUITY)/gm","/.*\\.m3u8/","tampilkanUrl","()=>","2900-3100",".layers.*[?.metadata.name==\"POI_Ads\"]","/PCWeb_Real.json","/gaid=","war:noop-vast2.xml","consent","arePiratesOnBoard","__INIT_CONFIG__.randvar","instanceof Event","prebidConfig.steering.disableVideoAutoBid","xml","await _0x","json:\"Blog1\"","ad-top","adblock.js","adbl",".getComputedStyle","STORAGE2","app_advert","googletag._loaded_","closeBanner","NoTenia","breaks interstitials info","interstitials","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\".mp.lura.live/prod/\")]] | //*[name()=\"MPD\"]/@mediaPresentationDuration)",".mpd","ads.policy.skipMode","/play","ad_slots","plugins.dfp","lura.live/prod/","/prog.m3u8","!embedtv.best",".offsetHeight","!asyaanimeleri.",".*[?.linkurl^=\"http\"]","initPop","app._data.ads","message","adsense","reklamlar","json:[{\"sure\":\"0\"}]","/api/video","Object.prototype.showInterstitialAd","skipAdblockCheck","/srvtrck|adligature|quantserve|outbrain/","createAgeModal","Object[_0x","adsPlayer","this","json:\"mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/145.0.0.0 safari/537.36\"","mozilla/5.0","popup=","()}",".art-control-fullscreen","pubAdsService","offsetLeft","config.pauseInspect","appContext.adManager.context.current.adFriendly","HTMLIFrameElement",".style","dsanity_ad_block_vars","show_download_links","downloadbtn","height","blockAdBlock._options.baitClass","/AdBlock/i","charAt","fadeIn","checkAD","latest!==","detectAdBlocker",".ready","/'shift'|break;/","document.blocked_var","____ads_js_blocked","wIsAdBlocked","WebSite.plsDisableAdBlock","css","videootv","ads_blocked","samDetected","Drupal.behaviors.agBlockAdBlock","NoAdBlock","mMCheckAgainBlock","countClicks","settings.adBlockerDetection","eabdModal","ab_root.show","gaData","wrapfabtest","fuckAdBlock._options.baitClass","$ado","/ado/i","app.js","popUnderStage","samAdBlockAction","googlebot","advert","bscheck.adblocker","qpcheck.ads","tmnramp","!sf-converter.com","clickAds.banner.urls","json:[{\"url\":{\"limit\":0,\"url\":\"\"}}]","ad","show_ads","ignielAdBlock","isContentBlocked","GetWindowHeight","/pop|wm|forceClick/","CloudflareApps.installs.Ik7rmQ4t95Qk.options.measureDomain","detectAB1",".init","ActiveXObject","uBlockOriginDetected","/_0x|localStorage\\.getItem/","google_ad_status","googletag._vars_","googletag._loadStarted_","google_unique_id","google.javascript","google.javascript.ads","google_global_correlator","ads.servers.[].apiAddress","paywallGateway.truncateContent","Constant","u_cfg","adBlockDisabled","__NEXT_DATA__.props.pageProps.adVideo","blockedElement","/ad","onpopstate","popState","adthrive.config","__C","ad-block-popup","exitTimer","innerHTML.replace","ajax","abu","countDown","HTMLElement.prototype.insertAdjacentHTML","_ads","eabpDialog","TotemToolsObject","puHref","flashvars.adv_postpause_vast","/Adblock|_ad_/","advads_passive_groups","GLX_GLOBAL_UUID_RESULT","Pop","f.parentNode.removeChild(f)","swal","keepChecking","t.pt","clickAnywhere urls","a[href*=\"/ads.php\"][target=\"_blank\"]","nitroAds","class.scroll","/showModal|isBlanketFound/","disableDeveloperTools","[onclick*=\"window.open\"]","openWindow","Check","checkCookieClick","readyToVote","12000","target|href","a[href^=\"//\"]","wpsite_clickable_data","insertBefore","offsetParent","meta.advertise","next","vidorev_jav_plugin_video_ads_object.vid_ads_m_video_ads","data.attributes.config.freewheel data.attributes.config.featureFlags.dPlayer","data.attributes.ssaiInfo.forecastTimeline data.attributes.ssaiInfo.vendorAttributes.nonLinearAds data.attributes.ssaiInfo.vendorAttributes.videoView data.attributes.ssaiInfo.vendorAttributes.breaks.[].ads.[].adMetadata data.attributes.ssaiInfo.vendorAttributes.breaks.[].ads.[].adParameters data.attributes.ssaiInfo.vendorAttributes.breaks.[].timeOffset","xpath(//*[name()=\"MPD\"][.//*[name()=\"BaseURL\" and contains(text(),'dash_clear_fmp4') and contains(text(),'/a/')]]/@mediaPresentationDuration | //*[name()=\"Period\"][./*[name()=\"BaseURL\" and contains(text(),'dash_clear_fmp4') and contains(text(),'/a/')]])","ssaiInfo","data.attributes.ssaiInfo","/videoPlaybackInfo","adsProvider.init","SDKLoaded","css_class.scroll","mnpwclone","0.3","7000","[href*=\"nihonjav\"]","/null|Error/","bannersRequest","vads","a[href][onclick^=\"getFullStory\"]","!newdmn","popUp","devtoolschange","rccbase_styles","POPUNDER_ENABLED","plugins.preroll","DHAntiAdBlocker","/out.php","ishop_codes","#advVid","location.replace","showada","showax","adp","__tnt","compatibility","popundrCheck","history.replaceState","rexxx.swp","constructor","p18","clickHandler","onbeforeunload","window.location.href","prebid","asc","json:{\"cmd\": [null], \"que\": [null], \"wrapperVersion\": \"6.19.0\", \"refreshQue\": {\"waitDelay\": 3000, \"que\": []}, \"isLoaded\": true, \"bidderSettings\": {}, \"libLoaded\": true, \"version\": \"v9.20.0\", \"installedModules\": [], \"adUnits\": [], \"aliasRegistry\": {}, \"medianetGlobals\": {}}","google_tag_manager","json:{ \"G-Z8CH48V654\": { \"_spx\": false, \"bootstrap\": 1704067200000, \"dataLayer\": { \"name\": \"dataLayer\" } }, \"SANDBOXED_JS_SEMAPHORE\": 0, \"dataLayer\": { \"gtmDom\": true, \"gtmLoad\": true, \"subscribers\": 1 }, \"sequence\": 1 }","ADBLOCKED","Object.prototype.adsEnabled","ai_run_scripts","clearInterval(i)","marginheight","ospen","pu_count","mypop","adblock_use","Object.prototype.adblockFound","download","1100","createCanvas","bizpanda","Q433","/pop|_blank/","movie.advertising.ad_server playlist.movie.advertising.ad_server","unblocker","playerAdSettings.adLink","playerAdSettings.waitTime","computed","manager","window.location.href=link","moonicorn.network","/dyn\\.ads|loadAdsDelayed/","xv.sda.pp.init","xv.conf.dyn.ads","onreadystatechange","skmedix.com","skmedix.pl","MediaContainer.Metadata.[].Ad","doubleclick.com","opaque","_init","href|target|data-ipshover-target|data-ipshover|data-autolink|rel","a[href^=\"https://thumpertalk.com/link/click/\"][target=\"_blank\"]","/touchstart|mousedown|click/","latest","secs","event.simulate","isAdsLoaded","adblockerAlert","/^https?:\\/\\/redirector\\.googlevideo\\.com.*/","/.*m3u8/","cuepoints","cuepoints.[].start cuepoints.[].end cuepoints.[].start_float cuepoints.[].end_float","Period[id*=\"-roll-\"][id*=\"-ad-\"]","pubads.g.doubleclick.net/ondemand","/ads/banner","reachGoal","Element.prototype.attachShadow","Adb","randStr","SPHMoverlay","ai","timer.remove","popupBlocker","afScript","Object.prototype.parseXML","Object.prototype.blackscreenDuration","Object.prototype.adPlayerId","/ads",":visible","mMcreateCookie","downloadButton","SmartPopunder.make","readystatechange","document.removeEventListener",".button[href^=\"javascript\"]","animation","status","adsblock","pub.network","timePassed","timeleft","input[id=\"button1\"][class=\"btn btn-primary\"][disabled]","t(a)",".fadeIn()","result","evolokParams.adblock","[src*=\"SPOT\"]","asap stay",".pageProps.__APOLLO_STATE__.*[?.__typename==\"AotSidebar\"]","/_next/data","pageProps.__TEMPLATE_QUERY_DATA__.aotFooterWidgets","props.pageProps.data.aotHomepageTopBar props.pageProps.data.aotHomepageTopBar props.pageProps.data.aotHeaderAdScripts props.pageProps.data.aotFooterWidgets","counter--","daadb","l-1","_htas","magnificPopup","skipOptions","method:HEAD url:doubleclick.net","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\"https:\")]])","style.display","tvid.in/log","1150","0.5","testadtags ad","document.referrer","quadsOptions","history.pushState","loadjscssfile","load_ads","/debugger|offsetParent/","/ads|imasdk/","6","__NEXT_DATA__.props.pageProps.adsConfig","make_rand_div","new_config.timedown","catch","google_ad","response.timeline.elements.[-].advertiserId","url:/api/v2/tabs/for_you","timercounter","document.location","innerHeight","cainPopUp","#timer","!bowfile.com","cloudfront.net/?","href|target|data-onclick","a[id=\"dl\"][data-onclick^=\"window.open\"]","a.getAttribute(\"data-ad-client\")||\"\"","truex","truex.client","answers","!display","/nerveheels/","No","foreverJQ","/document.createElement|stackDepth:2/","container.innerHTML","top-right","hiddenProxyDetected","SteadyWidgetSettings.adblockActive","temp","inhumanity_pop_var_name","url:googlesyndication","enforceAdStatus","hashchange","history.back","starPop","Element.prototype.matches","litespeed","__PoSettings","HTMLSelectElement","youtube","aTagChange","Object.prototype.ads","display","a[onclick^=\"setTimeout\"]","detectBlockAds","eb","/analytics|livestats/","/nextFunction|2000/","resource_response.data.[-].pin_promotion_id resource_response.data.results.[-].pin_promotion_id","initialReduxState.pins.{-}.pin_promotion_id initialReduxState.resources.UserHomefeedResource.*.data.[-].pin_promotion_id","player","mahimeta","__htas","chp_adblock_browser","/adb/i","tdBlock",".t-out-span [href*=\"utm_source\"]","src",".t-out-span [src*=\".gif\"]","notifier","penciBlocksArray",".panel-body > .text-center > button","modal-window","isScrexed","fallbackAds","popurl","SF.adblock","() => n(t)","() => t()","startfrom","Math.imul","checkAdsStatus","wtg-ads","/ad-","void 0","/__ez|window.location.href/","D4zz","Object.prototype.ads.nopreroll_",").show()","/open.*_blank/","advanced_ads_ready","loadAdBlocker","HP_Scout.adBlocked","SD_IS_BLOCKING","isBlocking","adFreePopup","Object.prototype.isPremium","__BACKPLANE_API__.renderOptions.showAdBlock",".quiver-cam-player--ad-not-running.quiver-cam-player--free video","debug","Object.prototype.isNoAds","tv3Cmp.ConsentGiven","distance","site-access","chAdblock","/,ad\\n.+?(?=#UPLYNK-SEGMENT)/gm","/uplynk\\.com\\/.*?\\.m3u8/","remaining","/ads|doubleclick/","/Ads|adbl|offsetHeight/",".innerHTML","onmousedown",".ob-dynamic-rec-link","setupSkin","/app.js","dqst.pl","PvVideoSlider","_chjeuHenj","[].data.searchResults.listings.[-].targetingSegments","noConflict","preroll_helper.advs","/show|innerHTML/","create_ad","contador","Object.prototype.enableInterstitial","addAds","/show|document\\.createElement/","loadXMLDoc","register","MobileInGameGames","__osw","uniconsent.com","/coinzillatag|czilladx/","divWidth","Script_Manager","Script_Manager_Time","bullads","Msg","!download","/click|mousedown/","adjsData","AdService.info.abd","UABP","adBlockDetectionResult","popped","/xlirdr|hotplay\\-games|hyenadata/","document.body.insertAdjacentHTML","exo","tic","download_loading","detector_launch","pu_url","Click","afStorage","puShown1","onAdblockerDetected","htmlAds","second","lycos_ad","150","passthetest","checkBlock","/thaudray\\.com|putchumt\\.com/","popName","vlitag","asgPopScript","/(?=^(?!.*(jquery|turnstile|challenge-platform)))/","Object.prototype.loadCosplay","Object.prototype.loadImages","FMPoopS","/window\\['(?:\\\\x[0-9a-f]{2}){2}/","urls.length","importantFunc","console.warn","sam","current()","confirm","pandaAdviewValidate","showAdBlock","aaaaa-modal","/(?=^(?!.*(http)))/","$onet","adsRedirectPopups","canGetAds","method:/head/i","Array.prototype.includes","json:\"none\"","/brave-api|script-content|bait|real/","length:11000","goToURL","ad_blocker_active","init_welcome_ad","setinteracted",".MediaStep","data.xdt_injected_story_units.ad_media_items","dataLayer","document.body.contains","nothingCanStopMeShowThisMessage","window.focus","imasdk","TextEncoder.prototype.encode","!/^\\//","fakeElement","adEnable","adtech-brightline adtech-google-pal adtech-iab-om","/playbackInfo","fallback.ssaiInfo manifest.url","fallback.ssaiInfo","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start | //*[name()=\"Period\"][not(.//*[name()=\"SegmentTimeline\"])][not(.//*[name()=\"ContentProtection\"])] | //*[name()=\"Period\"][./*[name()=\"BaseURL\"]][not(.//*[name()=\"ContentProtection\"])][not(.//*[name()=\"AdaptationSet\"][@contentType=\"text\"])])","/dash.mpd","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start | //*[name()=\"Period\"][not(.//*[name()=\"SegmentTimeline\"])][not(.//*[name()=\"ContentProtection\"])] | //*[name()=\"Period\"][./*[name()=\"BaseURL\"]][not(.//*[name()=\"ContentProtection\"])])","/-vod-.+\\.mpd/","htmlSectionsEncoded","event.dispatch","adx","popupurls","displayAds","cls_report?","-0x1","childNodes","wbar","[href=\"/bestporn.html\"]","_adshrink.skiptime","gclid","event","!yt1d.com","button#getlink","button#gotolink","AbleToRunAds","PreRollAd.timeCounter","result.ads","tpc.googlesyndication.com","id","#div-gpt-ad-footer","#div-gpt-ad-pagebottom","#div-gpt-ad-relatedbottom-1","#div-gpt-ad-sidebottom","goog","document.body","abpblocked","p$00a","openAdsModal","paAddUnit","gloacmug.net","items.[-].potentialActions.0.object.impressionToken items.[-].hasPart.0.potentialActions.0.object.impressionToken","context.adsIncluded","refresh","adt","Array.prototype.indexOf","interactionCount","/cloudfront|thaudray\\.com/","test_adblock","vastEnabled","/adskeeper|cloudflare/","#gotolink","detectadsbocker","c325","two_worker_data_js.js","adobeModalTestABenabled","FEATURE_DISABLE_ADOBE_POPUP_BY_COUNTRY","questpassGuard","isAdBlockerEnabled","shortConfig","akadb","eazy_ad_unblocker","json:\"\"","unlock","dataset.zone","adswizz.com","document.onkeypress","adsSrc","sssp","emptyObj","[style*=\"background-image: url\"]","[href*=\"click?\"]","/freychang|passback|popunder|tag|banquetunarmedgrater/","google-analytics","myTestAd","/<VAST version.+VAST>/","<VAST version=\\\"4.0\\\"></VAST>","deezer.getAudiobreak","Ads","smartLoaded","..ads_audio=false","ShowAdBLockerNotice","ad_listener","!shrdsk","notify","AdB","push-allow-modal",".hide","(!0)","Delay","ima","Cookiebot","\"adsBlocked\"","stream.insertion.adSession stream.insertion.points stream.insertion stream.sources.*.insertion pods.0.ads","ads.metadata ads.document ads.dxc ads.live ads.vod","site-access-popup","*.tanya_video_ads","deblocker","data?","script.src","/#EXT-X-DISCONTINUITY.{1,100}#EXT-X-DISCONTINUITY/gm","mixed.m3u8","feature_flags.interstitial_ads_flag","feature_flags.interstitials_every_four_slides","?","downloadToken","waldoSlotIds","Uint8Array","redirectpage","13500","adblockstatus","adScriptLoaded","/adoto|googlesyndication/","props.sponsoredAlternative","ad-delivery","document.documentElement.lang","adSettings","banner_is_blocked","consoleLoaded?clearInterval","Object.keys","[?.context.bidRequestId].*","RegExp.prototype.test","json:\"wirtualnemedia\"","/^dobreprogramy$/","decodeURL","updateProgress","/salesPopup|mira-snackbar/","Object.prototype.adBlocked","DOMAssistant","rotator","adblock popup vast","detectImgLoad","killAdKiller","current-=1","/zefoy\\.com\\S+:3:1/","/getComputedStyle|bait/","AController_3","json:\"div\"","ins",".clientHeight","googleAd","/showModal|chooseAction|doAction|callbackAdsBlocked/","_shouldProcessLink","cpmecs","/adlink/i","[onclick]","noreferrer","[onload^=\"window.open\"]","dontask","aoAdBlockDetected","button[onclick^=\"window.open\"]","function(e)","touchstart","Brid.A9.prototype.backfillAdUnits","adlinkfly_url","siteAccessFlag","/adblocker|alert/","doubleclick.net/instream/ad_status.js","war:doubleclick_instream_ad_status.js","redURL","/children\\('ins'\\)|Adblock|adsbygoogle/","dct","slideShow.displayInterstitial","openPopup","Object.getPrototypeOf","plugins","ai_wait_for_jquery","pbjs","tOS2","ips","Error","/stackDepth:1\\s/","tryShowVideoAdAsync","chkADB","onDetected","detectAdblocker","document.ready","a[href*=\"torrentico.top/sim/go.php\"]","success.page.spaces.player.widget_wrappers.[].widget.data.intervention_data","VAST","{\"value\": \"Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1\"}","navigator.standalone","navigator.platform","{\"value\": \"iPhone\"}","Storage.prototype.setItem","searchCount","empire.pop","empire.direct","empire.directHideAds","(!1)","pagead2.googlesyndication.com","empire.mediaData.advisorMovie","empire.mediaData.advisorSerie","fuckadb","[type=\"submit\"]","setTimer","auto_safelink","!abyss.to","daadb_get_data_fetch","penci_adlbock.ad_blocker_detector","siteAccessPopup","/adsbygoogle|adblock|innerHTML|setTimeout/","/innerHTML|_0x/","Object.prototype.adblockDetector","biteDisplay","blext","/[a-z]\\(!0\\)/","800","vidorev_jav_plugin_video_ads_object","vidorev_jav_plugin_video_ads_object_post","dai_iframe","popactive","/detectAdBlocker|window.open/","S_Popup","eazy_ad_unblocker_dialog_opener","rabLimit","-1","popUnder","/GoToURL|delay/","nudgeAdBlock","/googlesyndication|ads/","/Content/_AdBlock/AdBlockDetected.html","adBlckActive","AB.html","feedBack.showAffilaePromo","ShowAdvertising","a img:not([src=\"images/main_logo_inverted.png\"])","visible","a[href][target=\"_blank\"],[src^=\"//ad.a-ads.com/\"]","avails","amazonaws.com","ima3_dai","topaz.","FAVE.settings.ads.ssai.prod.clips.enabled","FAVE.settings.ads.ssai.prod.liveAuth.enabled","FAVE.settings.ads.ssai.prod.liveUnauth.enabled","ssaiInfo fallback.ssaiInfo","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start | //*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\".prd.media.\")]])","/sandbox/i","analytics.initialized","autoptimize","UserCustomPop","method:GET","data.reg","time-events","/#EXTINF:[^\\n]+\\nhttps:\\/\\/redirector\\.googlevideo\\.com[^\\n]+/gms","/\\/ondemand\\/.+\\.m3u8/","/redirector\\.googlevideo\\.com\\/videoplayback[\\s\\S]*?dclk_video_ads/",".m3u8","phxSiteConfig.gallery.ads.interstitialFrequency","loadpagecheck","popupAt","modal_blocker","art3m1sItemNames.affiliate-wrapper","\"\"","isOpened","playerResponse.adPlacements playerResponse.playerAds adPlacements playerAds","Array.prototype.find","affinity-qi","GeneratorAds","isAdBlockerActive","pop.doEvent","'shift'","bFired","scrollIncrement","di.app.WebplayerApp.Ads.Adblocks.app.AdBlockDetectApp.startWithParent","a#downloadbtn[onclick^=\"window.open\"]","alink","/ads|googletagmanager/","sharedController.adblockDetector",".redirect","sliding","a[onclick]","infoey","settings.adBlockDetectionEnabled","displayInterstitialAdConfig","response.ads","/api","unescape","checkAdBlockeraz","blockingAds","Yii2App.playbackTimeout","setC","popup","/atob|innerHTML/","/adScriptPath|MMDConfig/","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start | //*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),'adease')]])","[media^=\"A_D/\"]","adease adeaseBlob vmap","adease","aab","ips.controller.register","plugins.adService","QiyiPlayerProphetData.a.data","wait","/adsbygoogle|doubleclick/","adBreaks.[].startingOffset adBreaks.[].adBreakDuration adBreaks.[].ads adBreaks.[].startTime adBreak adBreakLocations","/session.json","xpath(//*[name()=\"Period\"][not(contains(@id,\"subclip\"))] | //*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start)","/\\/episode\\/.+?\\.mpd\\?/","session.showAds","toggleAdBlockInfo","cachebuster","config","OpenInNewTab_Over","/native|\\{n\\(\\)/","[style^=\"background\"]","[target^=\"_\"]","bodyElement.removeChild","aipAPItag.prerollSkipped","aipAPItag.setPreRollStatus","\"ads_disabled\":false","\"ads_disabled\":true","payments","reklam_1_saniye","reklam_1_gecsaniye","reklamsayisi","reklam_1","psresimler","data","runad","url:doubleclick.net","war:googletagservices_gpt.js","[target=\"_blank\"]","\"flashtalking\"","/(?=^(?!.*(cdn-cgi)))/","criteo","war:32x32.png","HTMLImageElement.prototype.onerror","data.home.home_timeline_urt.instructions.[].entries.[-].content.itemContent.promotedMetadata","url:/Home","data.search_by_raw_query.search_timeline.timeline.instructions.[].entries.[-].content.itemContent.promotedMetadata","url:/SearchTimeline","data.threaded_conversation_with_injections_v2.instructions.[].entries.[-].content.items.[].item.itemContent.promotedMetadata","url:/TweetDetail","data.user.result.timeline_v2.timeline.instructions.[].entries.[-].content.itemContent.promotedMetadata","url:/UserTweets","data.immersiveMedia.timeline.instructions.[].entries.[-].content.itemContent.promotedMetadata","url:/ImmersiveMedia","powerAPITag","rodo.checkIsDidomiConsent","protection","xtime","smartpop","EzoIvent","/doubleclick|googlesyndication|vlitag/","overlays","googleAdUrl","/googlesyndication|nitropay/","uBlockActive","/api/v1/events","Scribd.Blob.AdBlockerModal","AddAdsV2I.addBlock","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),'/ad/')]])","/Detect|adblock|style\\.display|\\[native code]|\\.call\\(null\\)/","/google_ad_client/","total","popCookie","/0x|sandCheck/","hasAdBlocker","ShouldShow","offset","startDownload","cloudfront","[href*=\"jump\"]","!direct","a0b","/outbrain|criteo|thisiswaldo|media\\.net|ohbayersbur|adligature|quantserve|srvtrck|\\.css|\\.js/","2000-5000","contrformpub","data.device.adsParams data.device.adSponsorshipTemplate","url:/appconfig","innerWidth","initials.yld-pdpopunder",".main-wrap","/googlesyndication|googima\\.js/","__brn_private_mode","download_click","Object.prototype.skipPreroll","/adskeeper|bidgear|googlesyndication|mgid/","fwmrm.net","/\\/ad\\/g\\/1/","adverts.breaks","result.responses.[].response.result.cards.[-].data.offers","ADB","downloadTimer","/ads|google/","injectedScript","/googlesyndication|googletagservices/","DisableDevtool","eClicked","number","sync","PlayerLogic.prototype.detectADB","ads-twitter.com","all","havenclick","VAST > Ad","/tserver","Object.prototype.prerollAds","secure.adnxs.com/ptv","war:noop-vast4.xml","notifyMe","alertmsg","/streams","adsClasses","gsecs","adtagparameter","dvsize","52","removeDLElements","/\\.append|\\.innerHTML|undefined|\\.css|blocker|flex|\\$\\('|obfuscatedMsg/","warn","adc","majorse","completed","testerli","showTrkURL","/popunder/i","readyWait","document.body.style.backgroundPosition","invoke","ssai_manifest ad_manifest playback_info.ad_info qvt.playback_info.ad_info","Object.prototype.setNeedShowAdblockWarning","load_banner","initializeChecks","HTMLDocument","video-popup","splashPage","adList","adsense-container","detect-modal","/_0x|dtaf/","ifmax","adRequest","nads","nitroAds.abp","adinplay.com","onloadUI","war:google-ima.js","/^data:text\\/javascript/","randomNumber","current.children","probeScript","PageLoader.DetectAb","!koyso.","adStatus","popUrl","one_time","PlaybackDetails.[].DaiVod","consentGiven","ad-block","data.searchClassifiedFeed.searchResultView.0.searchResultItemsV2.edges.[-].node.item.content.creative.clickThroughEvent.adsTrackingMetadata.metadata.adRequestId","data.me.personalizedFeed.feedItems.[-].promo.creative.clickThroughUrl.adsTrackingMetadata.metadata.adRequestId","data.me.rhrFeed.feedItems.[-].promo.creative.clickThroughUrl.adsTrackingMetadata.metadata.sponsor","mdpDeblocker","doubleclick.net","BN_CAMPAIGNS","media_place_list","...","/\\{[a-z]\\(!0\\)\\}/","canRedirect","/\\{[a-z]\\(e\\)\\}/","[].data.displayAdsV3.data.[-].__typename","[].data.TopAdsProducts.data.[-].__typename","[].data.topads.data.[-].__typename","/\\{\"id\":\\d{9,11}(?:(?!\"ads\":\\{\"id\":\"\").)+?\"ads\":\\{\"id\":\"\\d+\".+?\"__typename\":\"ProductCarouselV2\"\\},?/g","/graphql/InspirationCarousel","/\\{\"category_id\"(?:(?!\"ads\":\\{\"id\":\"\").)+?\"ads\":\\{\"id\":\"\\d+\".+?\"__typename\":\"ProductCarouselV2\"\\},?/g","/graphql/InspirationalCarousel","/\\{\"id\":\\d{9,11}(?:(?!\"isTopads\":false).)+?\"isTopads\":true.+?\"__typename\":\"recommendationItem\"\\},/g","/\\/graphql\\/productRecommendation/i","/,\\{\"id\":\\d{9,11}(?:(?!\"isTopads\":false).)+?\"isTopads\":true(?:(?!\"__typename\":\"recommendationItem\").)+?\"__typename\":\"recommendationItem\"\\}(?=\\])/","/\\{\"(?:productS|s)lashedPrice\"(?:(?!\"isTopads\":false).)+?\"isTopads\":true.+?\"__typename\":\"recommendationItem\"\\},?/g","/graphql/RecomWidget","/\\{\"appUrl\"(?:(?!\"isTopads\":false).)+?\"isTopads\":true.+?\"__typename\":\"recommendationItem\"\\},?/g","/graphql/ProductRecommendationQuery","adDetails","/secure?","data.search.products.[-].sponsored_ad.ad_source","url:/plp_search_v2?","GEMG.GPT.Interstitial","amiblock","String.prototype.concat","adBlockerDismissed","adBlockerDismissed_","karte3","18","callbackAdsBlocked","sandDetect",".ad-zone","showcfkModal","amodule.data","emptyArr","inner-ad","_ET","jssdks.mparticle.com","session.sessionAds session.sessionAdsRequired","/session","getComputedStyle(el)","/(?=^(?!.*(orchestrate|cloudflare)))/","Object.prototype.ADBLOCK_DETECTION",".features.*[?.slug==\"adblock-detection\"].enabled=false","/ad/","/count|verify|isCompleted/","postroll","itemList.[-].ad_info.ad_id","url:api/recommend/item_list/","/adinplay|googlesyndication/","!hidan.sh","ask","interceptClickEvent","isAdBlockDetected","pData.adblockOverlayEnabled","ad_block_detector","attached","div[class=\"share-embed-container\"]","/^\\w{11}[1-9]\\d+\\.ts/","cabdSettings","/outbrain|adligature|quantserve|adligature|srvtrck/","adsConfiguration","/vod",".streams.*.adUnits=[]","/manifest/video","/#EXTINF[^\\n]+\\n[^\\n]+?segment[^\\n]+/gms","layout.sections.mainContentCollection.components.[].data.productTiles.[-].sponsoredCreative.adGroupId","/search","fp-screen","puURL","!vidhidepre.com","[onclick*=\"_blank\"]","[onclick=\"goToURL();\"]","a[href][onclick^=\"window.open\"]","leaderboardAd","#leaderboardAd","placements.processingFile","dtGonza.playeradstime","\"-1\"","EV.Dab","ablk","shutterstock.com","Object.prototype.adUrl","sorts.[].recommendationList.[-].contentMetadata.EncryptedAdTrackingData","/ads|chp_?ad/","ads.[-].ad_id","wp-ad","/clarity|googlesyndication/","playerEnhancedConfig.run","/aff|jump/","!/mlbbox\\.me|_self/","aclib.runPop","ADS.isBannersEnabled","ADS.STATUS_ERROR","json:\"COMPLETE\"","button[onclick*=\"open\"]","getComputedStyle(testAd)","openPopupForChapter","Object.prototype.popupOpened","src_pop","gifs.[-].cta.link","boosted_gifs","adsbygoogle_ama_fc_has_run","doThePop","thanksgivingdelights","yes.onclick","!vidsrc.","popundersPerIP","createInvisibleTrigger","jwDefaults.advertising","elimina_profilazione","elimina_pubblicita","snigelweb.com","abd","pum_popups","checkerimg","uzivo","openDirectLinkAd","!nikaplayer.com",".adsbygoogle:not(.adsbygoogle-noablate)","json:\"img\"","playlist.movie.advertising.ad_server","PopUnder","data.[].affiliate_url","cdnpk.net/v2/images/search?","cdnpk.net/Rest/Media/","war:noop.json","data.[-].inner.ctaCopy","?page=","/gampad/ads?",".adv-",".length === 0",".length === 31","window.matchMedia('(display-mode: standalone)').matches","Object.prototype.DetectByGoogleAd","a[target=\"_blank\"][style]","/adsActive|POPUNDER/i","/Executed|modal/","[breakId*=\"Roll\"]","/content.vmap","/#EXT-X-KEY:METHOD=NONE\\n#EXT(?:INF:[^\\n]+|-X-DISCONTINUITY)\\n.+?(?=#EXT-X-KEY)/gms","/media.m3u8","window.navigator.brave","showTav","document['\\x","showADBOverlay","springserve.com","document.documentElement.clientWidth","outbrain.com","s4.cdnpc.net/front/css/style.min.css","slider--features","s4.cdnpc.net/vite-bundle/main.css","data-v-d23a26c8","cdn.taboola.com/libtrc/san1go-network/loader.js","feOffset","hasAdblock","taboola","adbEnableForPage","/adblock|isblock/i","/\\b[a-z] inlineScript:/","result.adverts","data.pinotPausedPlaybackPage","fundingchoicesmessages","isAdblock","button[id][onclick*=\".html\"]","dclk_video_ads","ads breaks cuepoints times","odabd","pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?ord=","b.google_reactive_tag_first","sbs.demdex.net/dest5.html?d_nsid=0&ord=","Demdex.canSetThirdPartyCookies","securepubads.g.doubleclick.net/pagead/ima_ppub_config?ippd=https%3A%2F%2Fwww.sbs.com.au%2Fondemand%2F&ord=","[\"4117\"]","configs.*.properties.componentConfigs.slideshowConfigs.*.interstitialNativeAds","url:/config","list.[].link.kicker","/content/v1/cms/api/amp/Document","properties.tiles.[-].isAd","/mestripewc/default/config","openPop","circle_animation","CountBack","990","/location\\.(replace|href)|stopAndExitFullscreen/","displayAdBlockedVideo","/undefined|displayAdBlockedVideo/","cns.library","json:\"#app-root\"","google_ads_iframe","data-id|data-p","[data-id],[data-p]","BJSShowUnder","BJSShowUnder.bindTo","BJSShowUnder.add","JSON.stringify","Object.prototype._parseVAST","Object.prototype.createAdBlocker","Object.prototype.isAdPeriod","breaks custom_breaks_data pause_ads video_metadata.end_credits_time","pause_ads","/playlist","breaks","breaks custom_breaks_data pause_ads","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\"/ads-\")]] | //*[name()=\"Period\"][starts-with(@id,\"ad\")] | //*[name()=\"Period\"][starts-with(@id,\"Ad\")] | //*[name()=\"Period\"]/@start)","MPD Period[id^=\"Ad\"i]","ABLK","_n_app.popunder","_n_app.options.ads.show_popunders","N_BetterJsPop.object","jwplayer.vast","Fingerprent2","test.remove","isAdb","/click|mouse|touch/","opopnso","c0ZZ","cuepointPlaylist vodPlaybackUrls.result.playbackUrls.cuepoints vodPlaylistedPlaybackUrls.result.playbackUrls.pauseBehavior vodPlaylistedPlaybackUrls.result.playbackUrls.pauseAdsResolution vodPlaylistedPlaybackUrls.result.playbackUrls.intraTitlePlaylist.[-].shouldShowOnScrubBar ads","xpath(//*[name()=\"Period\"][.//*[@value=\"Ad\"]] | /*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start)","[value=\"Ad\"]","xpath(//*[name()=\"Period\"][.//*[@value=\"Draper\"]] | /*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start)","[value=\"Draper\"]","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\"/interstitial/\")]] | /*[name()=\"MPD\"][.//*[name()=\"BaseURL\" and contains(text(),\"/interstitial/\")]]/@mediaPresentationDuration | /*[name()=\"MPD\"][.//*[name()=\"BaseURL\" and contains(text(),\"/interstitial/\")]]/*[name()=\"Period\"]/@start)","ue_adb_chk","ad.doubleclick.net bid.g.doubleclick.net ggpht.com google.co.uk google.com googleads.g.doubleclick.net googleads4.g.doubleclick.net googleadservices.com googlesyndication.com googleusercontent.com gstatic.com gvt1.com prod.google.com pubads.g.doubleclick.net s0.2mdn.net static.doubleclick.net surveys.g.doubleclick.net youtube.com ytimg.com","lifeOnwer","jsc.mgid.com","movie.advertising",".mandatoryAdvertising=false","/player/configuration","vast_urls","show_adverts","runCheck","adsSlotRenderEndSeen","DOMTokenList.prototype.add","\"-\"","removedNodes.forEach","__NEXT_DATA__.props.pageProps.broadcastData.remainingWatchDuration","json:9999999999","/\"remainingWatchDuration\":\\d+/","\"remainingWatchDuration\":9999999999","/stream","/\"midTierRemainingAdWatchCount\":\\d+,\"showAds\":(false|true)/","\"midTierRemainingAdWatchCount\":0,\"showAds\":false","a[href][onclick^=\"openit\"]","cdgPops","json:\"1\"","pubfuture","/doubleclick|google-analytics/","flashvars.mlogo_link","'script'","/ip-acl-all.php","URLlist","adBlockNotice","aaw","aaw.processAdsOnPage","displayLayer","adId","underpop","adBlockerModal","10000-15000","/adex|loadAds|adCollapsedCount|ad-?block/i","/^function\\(\\).*requestIdleCallback.*/","/function\\([a-z]\\){[a-z]\\([a-z]\\)}/","OneTrust","OneTrust.IsAlertBoxClosed","FOXIZ_MAIN_SCRIPT.siteAccessDetector","120000","openAdBlockPopup","drama-online","zoneid","\"data-cfasync\"","Object.init","advanced_ads_check_adblocker","div[class=\"nav tabTop\"] + div > div:first-child > div:first-child > a:has(> img[src*=\"/\"][src*=\"_\"][alt]), #head + div[id] > div:last-child > div > a:has(> img[src*=\"/\"][src*=\"_\"][alt])","/(?=^(?!.*(_next)))/","[].props.slides.[-].adIndex","#ad_blocker_detector","adblockTrigger","20","Date.prototype.toISOString","insertAd","!/^\\/|_self|alexsports|nativesurge/","method:HEAD mode:no-cors","attestHasAdBlockerActivated","extInstalled","blockThisUrl","SaveFiles.add","detectSandbox","bait.remove","/rekaa","pop_tag","/HTMLDocument|blob/","=","/wp-content\\/uploads\\/[a-z]+\\/[a-z]+\\.js/","google-ca-pub-4459622307906677","wbDeadHinweis","()=>{var c=Kb","0.2","fired","popupInterval","adbon","*.aurl","/cs?id=","repl:/\\.mp4$/.mp3/",".mp4","-banner","PopURL","LCI.adBlockDetectorEnabled","!y2meta","ConsoleBan","disableDevtool","ondevtoolopen","onkeydown","window.history.back","close","lastPopupTime","button#download","mode:\"no-cors\"","!magnetdl.","googlesyndication.com","repl:/blank/self/","stoCazzo","_insertDirectAdLink","Visibility","importFAB","uas","ast","json:1","a[href][target=\"_blank\"]","url:ad/banner.gif","window.__CONFIGURATION__.adInsertion.enabled","window.__CONFIGURATION__.features.enableAdBlockerDetection","_carbonads","_bsa","redirectOnClick","widgets.outbrain.com","2d","/googletagmanager|ip-api/","&&",".ads={\"movie\":false,\"series\":false,\"episode\":false,\"comments\":false,\"preroll\":false}","/settings","()=>j(e=>e-1)","timeleftlink","handlePopup","bannerad sidebar ti_sidebar","moneyDetect","play","EFFECTIVE_APPS_GCB_BLOCKED_MESSAGE","sub","checkForAdBlocker","/navigator|location\\.href/","mode:cors","!self","/createElement|addEventListener|clientHeight/","uberad_mode","data.getFinalClickoutUrl data.sendSraBid",".php","!notunmovie","handleRedirect","testAd","imasdk.googleapis.com","/topaz/api","data.availableProductCount","results.[-].advertisement","/partners/home","__aab_init","show_videoad_limited","__NATIVEADS_CANARY__","[breakId]","_VMAP_","ad_slot_recs","/doc-page/recommenders",".smartAdsForAccessNoAds=true","/doc-page/afa","Object.prototype.adOnAdBlockPreventPlayback","pre_roll_url","post_roll_url",".result.PlayAds=false","/api/get-urls","/adsbygoogle|dispatchEvent/","OfferwallSessionTracker","player.preroll",".redirected","/;if\\(!\\(|=null/","promos","TNCMS.DMP","/pop?","=>",".metadata.hideAds=true","a2d.tv/play/","adblock_detect","link.click","document.body.style.overflow","fallback","!addons.mozilla.org","rot_url","/await|clientHeight/","Function","..adTimeout=0","/api/v","!/\\/download|\\/play|cdn\\.videy\\.co/","!_self","#fab","www/delivery","/\\/js/","/\\/4\\//","prads","/googlesyndication|doubleclick|adsterra/",".adsbygoogle","/googlesyndication\\.com|offsetHeight/","String.prototype.split","null,http","..searchResults.*[?.isAd==true]","..mainContentComponentsListProps.*[?.isAd==true]","/search/snippet?","googletag.enums","json:{\"OutOfPageFormat\":{\"REWARDED\":true}}","cmgpbjs","displayAdblockOverlay","start_full_screen_without_ad","drupalSettings.coolmath.hide_preroll_ads",".submit","pbjs.libLoaded","flashvars.adv_pre_url","/!/","()&&","Object.prototype.adBlockerPop","clkUnder","adsArr","onClick","..data.expectingAds=false","/profile","[href^=\"https://whulsaux.com\"]","adRendered","Object.prototype.clickAds.emit","!storiesig","openUp",".result.timeline.*[?.type==\"ad\"]","/livestitch","protectsubrev.com","dispatchEvent(window.catchdo)","En(e-1)","!adShown","/blocker|detected/","3200-","/window\\.location\\.href/","AdProvider","AdProvider.push","ads_","ad_blocker_detector",".result.items.*[?.content*=\"'+'\"]","/comments","img[onerror]","..allowAdblock=true","/initPops|popLite|popunder/","[?.type==\"ads\"].visibility.status=\"hidden\"","/^755$/","shouldRun","ad-ipd","window.getComputedStyle","maddenwiped","/redirect.php?","*.*","/api/banners","checkBanners","/detect|bait/i","++;break;}}}}}","__adBlockState","__revCatchInitialized","ab.dt","json:\"header\"","/^[a-zA-Z]{15}$/","data.initPlaybackSession.adScenarios data.initPlaybackSession.adExperience.adExperienceTypes",".data.initPlaybackSession.adExperience.adsEnabled=false","ConFig.config.ads","json:{\"pause\":{\"state\":{}}}","Object.prototype.adblockPlugin","initializePopupAd","fireAd","juicy_tags","!youtu","injectAd",".isAdFree=true","resumeGame","/eeea5e31|new\\s+Function/","timeLeft--","data.*.elements.edges.[].node.outboundLink","data.children.[].data.outbound_link","method:POST url:/logImpressions","rwt",".js","_oEa","ADMITAD","body:browser","_hjSettings","bmak.js_post","method:POST","utreon.com/pl/api/event method:POST","log-sdk.ksapisrv.com/rest/wd/common/log/collect method:POST","firebase.analytics","require.0.3.0.__bbox.define.[].2.is_linkshim_supported","/(ping|score)Url","Object.prototype.updateModifiedCommerceUrl","HTMLAnchorElement.prototype.getAttribute","data-direct-ad","fingerprintjs-pro-react","flashvars.event_reporting","dataLayer.trackingId user.trackingId","Object.prototype.has_opted_out_tracking","cX_atfr","process","process.env","/VisitorAPI|AppMeasurement/","Visitor","''","?orgRef","analytics/bulk-pixel","eventing","send_gravity_event","send_recommendation_event","window.screen.height","method:POST body:zaraz","onclick|oncontextmenu|onmouseover","a[href][onclick*=\"this.href\"]","libAnalytics","json: {\"status\":{\"dataAvailable\":false},\"data\":{}}","libAnalytics.data.get","cmp.inmobi.com/geoip","method:POST url:pfanalytics.bentasker.co.uk","discord.com/api/v9/science","a[onclick=\"fire_download_click_tracking();\"]","adthrive._components.start","method:POST body:page_view",".*[?.operationName==\"TrackEvent\"]","/v1/api","ftr__startScriptLoad","url:/undefined method:POST","linkfire.tracking","miner","CoinNebula","blogherads","Math.sqrt","update","/(trace|beacon)\\.qq\\.com/","splunkcloud.com/services/collector","event-router.olympics.com","hostingcloud.racing","tvid.in/log/","excess.duolingo.com/batch","/eventLog.ajax","t.wayfair.com/b.php?","navigator.sendBeacon","segment.io","mparticle.com","ceros.com/a?data","pluto.smallpdf.com","method:/post/i url:/\\/\\/chatgpt\\.com\\/ces\\/v1\\/[a-z]$/","method:/post/i url:ab.chatgpt.com/v1/rgstr","/eventhub\\.\\w+\\.miro\\.com\\/api\\/stream/","logs.netflix.com","s73cloud.com/metrics/","location.reload",".cdnurl=[\"data:video/mp4;base64,AAAAHGZ0eXBNNFYgAAACAGlzb21pc28yYXZjMQAAAAhmcmVlAAAGF21kYXTeBAAAbGliZmFhYyAxLjI4AABCAJMgBDIARwAAArEGBf//rdxF6b3m2Ui3lizYINkj7u94MjY0IC0gY29yZSAxNDIgcjIgOTU2YzhkOCAtIEguMjY0L01QRUctNCBBVkMgY29kZWMgLSBDb3B5bGVmdCAyMDAzLTIwMTQgLSBodHRwOi8vd3d3LnZpZGVvbGFuLm9yZy94MjY0Lmh0bWwgLSBvcHRpb25zOiBjYWJhYz0wIHJlZj0zIGRlYmxvY2s9MTowOjAgYW5hbHlzZT0weDE6MHgxMTEgbWU9aGV4IHN1Ym1lPTcgcHN5PTEgcHN5X3JkPTEuMDA6MC4wMCBtaXhlZF9yZWY9MSBtZV9yYW5nZT0xNiBjaHJvbWFfbWU9MSB0cmVsbGlzPTEgOHg4ZGN0PTAgY3FtPTAgZGVhZHpvbmU9MjEsMTEgZmFzdF9wc2tpcD0xIGNocm9tYV9xcF9vZmZzZXQ9LTIgdGhyZWFkcz02IGxvb2thaGVhZF90aHJlYWRzPTEgc2xpY2VkX3RocmVhZHM9MCBucj0wIGRlY2ltYXRlPTEgaW50ZXJsYWNlZD0wIGJsdXJheV9jb21wYXQ9MCBjb25zdHJhaW5lZF9pbnRyYT0wIGJmcmFtZXM9MCB3ZWlnaHRwPTAga2V5aW50PTI1MCBrZXlpbnRfbWluPTI1IHNjZW5lY3V0PTQwIGludHJhX3JlZnJlc2g9MCByY19sb29rYWhlYWQ9NDAgcmM9Y3JmIG1idHJlZT0xIGNyZj0yMy4wIHFjb21wPTAuNjAgcXBtaW49MCBxcG1heD02OSBxcHN0ZXA9NCB2YnZfbWF4cmF0ZT03NjggdmJ2X2J1ZnNpemU9MzAwMCBjcmZfbWF4PTAuMCBuYWxfaHJkPW5vbmUgZmlsbGVyPTAgaXBfcmF0aW89MS40MCBhcT0xOjEuMDAAgAAAAFZliIQL8mKAAKvMnJycnJycnJycnXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXiEASZACGQAjgCEASZACGQAjgAAAAAdBmjgX4GSAIQBJkAIZACOAAAAAB0GaVAX4GSAhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZpgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGagC/AySEASZACGQAjgAAAAAZBmqAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZrAL8DJIQBJkAIZACOAAAAABkGa4C/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmwAvwMkhAEmQAhkAI4AAAAAGQZsgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGbQC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBm2AvwMkhAEmQAhkAI4AAAAAGQZuAL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGboC/AySEASZACGQAjgAAAAAZBm8AvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZvgL8DJIQBJkAIZACOAAAAABkGaAC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmiAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZpAL8DJIQBJkAIZACOAAAAABkGaYC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmoAvwMkhAEmQAhkAI4AAAAAGQZqgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGawC/AySEASZACGQAjgAAAAAZBmuAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZsAL8DJIQBJkAIZACOAAAAABkGbIC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBm0AvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZtgL8DJIQBJkAIZACOAAAAABkGbgCvAySEASZACGQAjgCEASZACGQAjgAAAAAZBm6AnwMkhAEmQAhkAI4AhAEmQAhkAI4AhAEmQAhkAI4AhAEmQAhkAI4AAAAhubW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAABDcAAQAAAQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAzB0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAA+kAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAALAAAACQAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAPpAAAAAAABAAAAAAKobWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAB1MAAAdU5VxAAAAAAALWhkbHIAAAAAAAAAAHZpZGUAAAAAAAAAAAAAAABWaWRlb0hhbmRsZXIAAAACU21pbmYAAAAUdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAAAx1cmwgAAAAAQAAAhNzdGJsAAAAr3N0c2QAAAAAAAAAAQAAAJ9hdmMxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAALAAkABIAAAASAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGP//AAAALWF2Y0MBQsAN/+EAFWdCwA3ZAsTsBEAAAPpAADqYA8UKkgEABWjLg8sgAAAAHHV1aWRraEDyXyRPxbo5pRvPAyPzAAAAAAAAABhzdHRzAAAAAAAAAAEAAAAeAAAD6QAAABRzdHNzAAAAAAAAAAEAAAABAAAAHHN0c2MAAAAAAAAAAQAAAAEAAAABAAAAAQAAAIxzdHN6AAAAAAAAAAAAAAAeAAADDwAAAAsAAAALAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAAiHN0Y28AAAAAAAAAHgAAAEYAAANnAAADewAAA5gAAAO0AAADxwAAA+MAAAP2AAAEEgAABCUAAARBAAAEXQAABHAAAASMAAAEnwAABLsAAATOAAAE6gAABQYAAAUZAAAFNQAABUgAAAVkAAAFdwAABZMAAAWmAAAFwgAABd4AAAXxAAAGDQAABGh0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAACAAAAAAAABDcAAAAAAAAAAAAAAAEBAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAQkAAADcAABAAAAAAPgbWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAC7gAAAykBVxAAAAAAALWhkbHIAAAAAAAAAAHNvdW4AAAAAAAAAAAAAAABTb3VuZEhhbmRsZXIAAAADi21pbmYAAAAQc21oZAAAAAAAAAAAAAAAJGRpbmYAAAAcZHJlZgAAAAAAAAABAAAADHVybCAAAAABAAADT3N0YmwAAABnc3RzZAAAAAAAAAABAAAAV21wNGEAAAAAAAAAAQAAAAAAAAAAAAIAEAAAAAC7gAAAAAAAM2VzZHMAAAAAA4CAgCIAAgAEgICAFEAVBbjYAAu4AAAADcoFgICAAhGQBoCAgAECAAAAIHN0dHMAAAAAAAAAAgAAADIAAAQAAAAAAQAAAkAAAAFUc3RzYwAAAAAAAAAbAAAAAQAAAAEAAAABAAAAAgAAAAIAAAABAAAAAwAAAAEAAAABAAAABAAAAAIAAAABAAAABgAAAAEAAAABAAAABwAAAAIAAAABAAAACAAAAAEAAAABAAAACQAAAAIAAAABAAAACgAAAAEAAAABAAAACwAAAAIAAAABAAAADQAAAAEAAAABAAAADgAAAAIAAAABAAAADwAAAAEAAAABAAAAEAAAAAIAAAABAAAAEQAAAAEAAAABAAAAEgAAAAIAAAABAAAAFAAAAAEAAAABAAAAFQAAAAIAAAABAAAAFgAAAAEAAAABAAAAFwAAAAIAAAABAAAAGAAAAAEAAAABAAAAGQAAAAIAAAABAAAAGgAAAAEAAAABAAAAGwAAAAIAAAABAAAAHQAAAAEAAAABAAAAHgAAAAIAAAABAAAAHwAAAAQAAAABAAAA4HN0c3oAAAAAAAAAAAAAADMAAAAaAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAACMc3RjbwAAAAAAAAAfAAAALAAAA1UAAANyAAADhgAAA6IAAAO+AAAD0QAAA+0AAAQAAAAEHAAABC8AAARLAAAEZwAABHoAAASWAAAEqQAABMUAAATYAAAE9AAABRAAAAUjAAAFPwAABVIAAAVuAAAFgQAABZ0AAAWwAAAFzAAABegAAAX7AAAGFwAAAGJ1ZHRhAAAAWm1ldGEAAAAAAAAAIWhkbHIAAAAAAAAAAG1kaXJhcHBsAAAAAAAAAAAAAAAALWlsc3QAAAAlqXRvbwAAAB1kYXRhAAAAAQAAAABMYXZmNTUuMzMuMTAw\"]","/storage-resolve/files/audio/interactive","json:\"https://\"","data:video/mp4",".state_machine.tracks.*[?.metadata.uri^=\"spotify:ad:\"].manifest.file_urls_mp3.*.file_id=1","/track-playback",".state_machine.tracks.*[?.metadata.uri^=\"spotify:ad:\"].manifest.file_urls_mp3.*.file_url=\"data:video/mp4;base64,AAAAHGZ0eXBNNFYgAAACAGlzb21pc28yYXZjMQAAAAhmcmVlAAAGF21kYXTeBAAAbGliZmFhYyAxLjI4AABCAJMgBDIARwAAArEGBf//rdxF6b3m2Ui3lizYINkj7u94MjY0IC0gY29yZSAxNDIgcjIgOTU2YzhkOCAtIEguMjY0L01QRUctNCBBVkMgY29kZWMgLSBDb3B5bGVmdCAyMDAzLTIwMTQgLSBodHRwOi8vd3d3LnZpZGVvbGFuLm9yZy94MjY0Lmh0bWwgLSBvcHRpb25zOiBjYWJhYz0wIHJlZj0zIGRlYmxvY2s9MTowOjAgYW5hbHlzZT0weDE6MHgxMTEgbWU9aGV4IHN1Ym1lPTcgcHN5PTEgcHN5X3JkPTEuMDA6MC4wMCBtaXhlZF9yZWY9MSBtZV9yYW5nZT0xNiBjaHJvbWFfbWU9MSB0cmVsbGlzPTEgOHg4ZGN0PTAgY3FtPTAgZGVhZHpvbmU9MjEsMTEgZmFzdF9wc2tpcD0xIGNocm9tYV9xcF9vZmZzZXQ9LTIgdGhyZWFkcz02IGxvb2thaGVhZF90aHJlYWRzPTEgc2xpY2VkX3RocmVhZHM9MCBucj0wIGRlY2ltYXRlPTEgaW50ZXJsYWNlZD0wIGJsdXJheV9jb21wYXQ9MCBjb25zdHJhaW5lZF9pbnRyYT0wIGJmcmFtZXM9MCB3ZWlnaHRwPTAga2V5aW50PTI1MCBrZXlpbnRfbWluPTI1IHNjZW5lY3V0PTQwIGludHJhX3JlZnJlc2g9MCByY19sb29rYWhlYWQ9NDAgcmM9Y3JmIG1idHJlZT0xIGNyZj0yMy4wIHFjb21wPTAuNjAgcXBtaW49MCBxcG1heD02OSBxcHN0ZXA9NCB2YnZfbWF4cmF0ZT03NjggdmJ2X2J1ZnNpemU9MzAwMCBjcmZfbWF4PTAuMCBuYWxfaHJkPW5vbmUgZmlsbGVyPTAgaXBfcmF0aW89MS40MCBhcT0xOjEuMDAAgAAAAFZliIQL8mKAAKvMnJycnJycnJycnXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXiEASZACGQAjgCEASZACGQAjgAAAAAdBmjgX4GSAIQBJkAIZACOAAAAAB0GaVAX4GSAhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZpgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGagC/AySEASZACGQAjgAAAAAZBmqAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZrAL8DJIQBJkAIZACOAAAAABkGa4C/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmwAvwMkhAEmQAhkAI4AAAAAGQZsgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGbQC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBm2AvwMkhAEmQAhkAI4AAAAAGQZuAL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGboC/AySEASZACGQAjgAAAAAZBm8AvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZvgL8DJIQBJkAIZACOAAAAABkGaAC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmiAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZpAL8DJIQBJkAIZACOAAAAABkGaYC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmoAvwMkhAEmQAhkAI4AAAAAGQZqgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGawC/AySEASZACGQAjgAAAAAZBmuAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZsAL8DJIQBJkAIZACOAAAAABkGbIC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBm0AvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZtgL8DJIQBJkAIZACOAAAAABkGbgCvAySEASZACGQAjgCEASZACGQAjgAAAAAZBm6AnwMkhAEmQAhkAI4AhAEmQAhkAI4AhAEmQAhkAI4AhAEmQAhkAI4AAAAhubW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAABDcAAQAAAQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAzB0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAA+kAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAALAAAACQAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAPpAAAAAAABAAAAAAKobWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAB1MAAAdU5VxAAAAAAALWhkbHIAAAAAAAAAAHZpZGUAAAAAAAAAAAAAAABWaWRlb0hhbmRsZXIAAAACU21pbmYAAAAUdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAAAx1cmwgAAAAAQAAAhNzdGJsAAAAr3N0c2QAAAAAAAAAAQAAAJ9hdmMxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAALAAkABIAAAASAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGP//AAAALWF2Y0MBQsAN/+EAFWdCwA3ZAsTsBEAAAPpAADqYA8UKkgEABWjLg8sgAAAAHHV1aWRraEDyXyRPxbo5pRvPAyPzAAAAAAAAABhzdHRzAAAAAAAAAAEAAAAeAAAD6QAAABRzdHNzAAAAAAAAAAEAAAABAAAAHHN0c2MAAAAAAAAAAQAAAAEAAAABAAAAAQAAAIxzdHN6AAAAAAAAAAAAAAAeAAADDwAAAAsAAAALAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAAiHN0Y28AAAAAAAAAHgAAAEYAAANnAAADewAAA5gAAAO0AAADxwAAA+MAAAP2AAAEEgAABCUAAARBAAAEXQAABHAAAASMAAAEnwAABLsAAATOAAAE6gAABQYAAAUZAAAFNQAABUgAAAVkAAAFdwAABZMAAAWmAAAFwgAABd4AAAXxAAAGDQAABGh0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAACAAAAAAAABDcAAAAAAAAAAAAAAAEBAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAQkAAADcAABAAAAAAPgbWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAC7gAAAykBVxAAAAAAALWhkbHIAAAAAAAAAAHNvdW4AAAAAAAAAAAAAAABTb3VuZEhhbmRsZXIAAAADi21pbmYAAAAQc21oZAAAAAAAAAAAAAAAJGRpbmYAAAAcZHJlZgAAAAAAAAABAAAADHVybCAAAAABAAADT3N0YmwAAABnc3RzZAAAAAAAAAABAAAAV21wNGEAAAAAAAAAAQAAAAAAAAAAAAIAEAAAAAC7gAAAAAAAM2VzZHMAAAAAA4CAgCIAAgAEgICAFEAVBbjYAAu4AAAADcoFgICAAhGQBoCAgAECAAAAIHN0dHMAAAAAAAAAAgAAADIAAAQAAAAAAQAAAkAAAAFUc3RzYwAAAAAAAAAbAAAAAQAAAAEAAAABAAAAAgAAAAIAAAABAAAAAwAAAAEAAAABAAAABAAAAAIAAAABAAAABgAAAAEAAAABAAAABwAAAAIAAAABAAAACAAAAAEAAAABAAAACQAAAAIAAAABAAAACgAAAAEAAAABAAAACwAAAAIAAAABAAAADQAAAAEAAAABAAAADgAAAAIAAAABAAAADwAAAAEAAAABAAAAEAAAAAIAAAABAAAAEQAAAAEAAAABAAAAEgAAAAIAAAABAAAAFAAAAAEAAAABAAAAFQAAAAIAAAABAAAAFgAAAAEAAAABAAAAFwAAAAIAAAABAAAAGAAAAAEAAAABAAAAGQAAAAIAAAABAAAAGgAAAAEAAAABAAAAGwAAAAIAAAABAAAAHQAAAAEAAAABAAAAHgAAAAIAAAABAAAAHwAAAAQAAAABAAAA4HN0c3oAAAAAAAAAAAAAADMAAAAaAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAACMc3RjbwAAAAAAAAAfAAAALAAAA1UAAANyAAADhgAAA6IAAAO+AAAD0QAAA+0AAAQAAAAEHAAABC8AAARLAAAEZwAABHoAAASWAAAEqQAABMUAAATYAAAE9AAABRAAAAUjAAAFPwAABVIAAAVuAAAFgQAABZ0AAAWwAAAFzAAABegAAAX7AAAGFwAAAGJ1ZHRhAAAAWm1ldGEAAAAAAAAAIWhkbHIAAAAAAAAAAG1kaXJhcHBsAAAAAAAAAAAAAAAALWlsc3QAAAAlqXRvbwAAAB1kYXRhAAAAAQAAAABMYXZmNTUuMzMuMTAw\""];

const $scriptletArglists$ = /* 3777 */ "0,0,1,2;0,3,1,2;1,4,5,6;2,7,8,1,2;2,9,8,1,10;3,7,8,1,11;4,12,13,14;4,15,8,14;4,16,17,11;5,12,13,18;5,19,13,18;5,19,13,20;6,21,22;6,21,23;6,21,24;7,25;5,19,13,26;7,27;3,28,8,1,29;8,30;9,31,32;7,33;8,34;10,35,1,29;10,34,1,29;10,36,1,29;11;9,37,38;12,39,40;12,41,42;13,43,44,45,46;13,47,48;13,49,50;13,51,52,45,46;13,53,54,45,46;13,55,54,45,46;14,56,57;14,58,59;15,60;14,61,62;16,8,63;15,64;12,65,66;12,67,68;12,21,69;12,70,71;17,56,72;9,73,74,75,76;18,77,78,79;19,80,81,82,83,84;20,85;20,86,87;21,88,89;20,90,91;20,92;20,93;11,94;12,95,96;9,97,38;12,98,99;22,100,101;21,102,103;21,104,103;20,105;19,106,81,107,83,108;19,109,81,107,83,110;9,111,32;9,112,32;9,113,114;21,115;20,116;23,117,118,119;22,120,8,8,121,122;19,123,81,124,83,125;24,126,127;21,128;21,8,129;15,130;22,131,132;19,133,81,8,83,134;22,135,136;18,137,138,139,83,140;19,137,81,141,83,142;19,143,81,141,83,142;22,144,145,146;21,147;9,148,38;22,149,150;13,151,152,153;25,154,155;17,156,157,75,76;9,158,38;26,159;3,160,8,1,161;9,162,163;26,164;1,165;22,166,167;20,166,167;9,168,163;9,169,170;1,171,89;9,172,170;9,173,163;23,174,175;9,176,177;7,178;22,179;9,180,163;9,181,74;9,182,163;20,183;27;9,184,163;9,185,163;9,186,163;9,187,163;9,188,163;9,189,74;9,190,163;9,191,163;22,192;28,193;22,194;22,195;1,196,197;23,198,199;23,200,201,119;12,202;9,203,8;20,204;20,195;14,205,206;22,207;9,208,74;9,209,74;9,210,74;27,211,8,212;20,213;9,214,74;20,215;9,216,163;20,207;9,217,163;9,218,91;9,219,74;9,220,74;1,221,222,6;1,223,224,6;9,225,114;9,226,163;20,227;9,228,163;9,229,163;9,230,163;9,231,74;9,232,163;20,233;26,234;9,235,163;9,236,163;9,237,163;9,238,74;9,239,91;9,240,74;9,241,163;9,242,74;9,243,163;9,244,8;9,245,74;9,246,163;9,247,74;9,248,163;9,249,163;9,250,74;9,251,163;9,252,163;9,253,74;9,254,74;9,255,74;9,256,74;9,257,74;9,258,74;9,259,163;9,260,163;1,261,224;9,262,74;20,263;27,264,197;9,265,74;9,266,163;25,267,268;9,269,74;9,270,163;9,271,163;9,272,163;1,273,274;1,275,197;9,276,74;9,277,163;9,278,74;9,279,163;19,109,81,280,83,281;9,282,38;9,283,91;9,284,74;9,285,163;9,286,74;9,287,114;9,288,74;9,289,163;9,290,163;9,291,163;9,292,74;9,293,163;9,294,163;9,295,74;9,296,114;9,297,74;9,298,163;9,299,163;9,300,163;9,301,163;9,302,74;9,303,163;1,304,224,6;9,305,74;9,306,8;9,307,74;9,308,163;9,309,163;20,310;9,311,74;9,312,163;9,313,74;9,314,163;9,315,163;9,316,74;9,317,163;9,318,163;9,319,74;9,320,163;9,321,163;9,322,163;9,323,74;9,324,163;1,325,197,6;1,326,224,6;9,327,163;22,204;1,328,197,6;9,329,74;9,330,163;22,331;1,196,332,6;1,196,333,6;9,334,163;21,335;9,336,74;9,337,163;9,338,74;20,339;9,340,163;9,341,74;9,342,163;9,343,74;9,344,163;9,345,74;9,346,163;9,347,74;9,348,163;9,349,163;17,350,351;9,352,32;1,4,274,6;1,353,354,6;9,355,74;9,356,163;9,357,163;1,358,197,6;20,359;9,360,74;9,361,74;9,362,163;9,363,163;9,364,74;9,365,163;9,366,163;9,367,32;9,368,163;9,369,163;9,370,74;9,371,163;25,267,372;9,373,163;9,374,38;9,375,163;9,376,163;9,377,163;9,378,163;25,267,8,379,380;9,381,74;9,382,163;9,383,74;9,384,163;9,385,74;9,386,163;9,387,91;19,388,389,390,83,391;9,392,74;9,393,163;9,394,163;9,395,91;9,396,32;9,397,163;9,398,163;9,399,170;9,400,389;9,401,163;9,402,74;9,403,74;9,404,163;9,405,74;9,406,163;9,407,38;9,408,38;9,409,38;9,410,38;7,411;2,412,8,1,413;25,154,414;28,415,89;7,416,417;25,154,418;28,419,420;22,421;9,422,81;22,423;9,424,8;28,425;26,426;7,427;4,428,74,429;4,430,74,429;4,431,74,429;7,432,433;7,434;7,435;3,436,8,1,429;8,437;10,437,1,29;26,438;26,439;25,8,425;21,425;9,440,177;12,441,442;12,443;21,444;21,445;26,446;19,24,81,447,83,448;1,8,420;26,449;29,450;9,451,38;30;26,452;12,453;22,454;25,267,455;29,456;12,457,449;26,458;26,459;26,460;29,461;26,462;25,267,463;25,154,464;21,465,466;26,467;26,468;29,469;20,470;9,471,163;12,109,472;12,98,473;1,474,197;26,475;26,453;25,154,476;26,477;26,478;26,37;29,479;1,480,197;25,8,481;26,482;26,483;26,484;12,58,485;26,486;14,487,488;12,457,489;29,453;26,490;26,491;25,154,492;25,154,493;20,179;9,494,91;9,495,163;22,496;12,457,497;12,498,499;26,500;26,501;12,457,502;29,503;29,504;12,505,506;26,507;25,8,474;12,457,508;25,8,509;12,510,511;26,512;21,485;12,513,485;29,501;26,443;12,441,514;26,515;26,516;29,517;29,518;12,106,519;1,520,521;14,476,46;26,97;9,522,32;9,523,32;26,524;9,525,114;23,526;26,527;25,528,529;26,530;12,457,531;12,457,532;12,457,38;26,533;26,534;9,535,32;26,498;12,476,453;26,536;26,537;26,538;9,539,8;9,540,32;29,541;9,542,91;29,543;29,544;29,545;9,546,91;26,547;12,457,509;29,548;26,513;23,549,550,551;9,552,170;1;29,553;25,8,453;26,554;9,555,32;26,556;12,515;26,557;12,558,559;29,560;28,561;12,457,562;27,563;26,564;29,565;21,566;9,534,91;26,567;21,568;26,569;9,570,163;9,571,91;29,572;25,267,573;25,574,575;12,513,576;29,577;12,98,578;9,37,170;9,579,8;9,580,8;9,581,389;25,582;21,583;26,584;21,585,586;9,587,91;26,588;25,8,589;12,457,590;9,591,8;26,592;14,426,593;25,154,594;15,595;25,596;14,513,597;26,598;9,599,163;9,600,177;14,109,601;1,602,603;1,604,466,6;9,605,91;21,606,81;9,607,163;9,39,177;26,608;9,128,32;12,609,489;9,610,91;12,441,611;29,612;9,613,614;25,8,615;26,616;21,617,466;12,58,466;21,618,619;26,620;12,42,499;9,621,91;12,513,622;28,474;25,8,623;26,624;29,625;9,626,32;26,627;12,628;12,42,629;12,630,631;25,632,633;21,634;26,635;26,636;31,637;26,638;26,639;26,640;9,641,163;12,106,38;9,642,163;29,643;1,644;27,645;21,109,224;26,646;26,647;26,648;12,510,649;29,650;29,651;9,652,32;21,653,654;9,655,91;9,656,32;27,657,658;12,475,128;25,154,659;27,660,586;29,661;29,515;26,662;25,267,633;26,663;9,664,32;25,154,586;12,665,575;12,42;26,666;21,667;29,668;29,669;25,670,671;12,672,673;29,674;25,154,425;12,441,675;26,676;9,677,32;26,610;21,665,466;12,498,42;26,678;29,679;21,680;21,681;26,543;31,515;9,682,8;21,510,81;25,683,671;25,8,634;12,441,478;12,478,684;26,685;26,686;26,687;9,688,91;9,37,163;21,653,586;26,689;25,154,653;25,690,691;12,692,526;29,693;23,694,695;21,696,224;12,697,698;9,699,32;11,623;26,128;12,700;25,8,701;26,702;9,558,91;25,703,704;29,705;21,706,707;12,610;12,58,708;22,709;12,710,711;21,712,586;25,154,713;12,457,714;9,443,91;21,715;25,8,716;21,716;12,457,445;29,97;21,717,274;25,718,719;21,720,89;12,58,109;21,721,586;11,722;12,441,723;11,724;9,725,74;9,726,8;26,727;29,728;12,106,128;9,729,163;26,730;27,731,586;26,732;9,733,32;20,734;21,735;1,736,197,212;9,128,163;9,737,8;7,197,738;11,8,739;12,24,42;12,478;29,740;20,741;9,742,38;12,457,743;9,744,32;9,534,163;26,745;21,712,746;21,747;26,748;25,718,749;26,750;20,751;9,752,163;26,753;12,476,478;25,632,754;9,755,91;11,756;12,498,757;26,456;22,758;9,759,32;26,760;12,106,761;20,762;9,763,163;25,8,764;29,765;21,766,274;12,457,767;26,768;27,8,769;26,770;27,8,8,81;21,771;12,106,772;20,773;12,774,520;12,457,774;26,775;14,723,776;25,528,777;25,718,778;12,564,779;26,780;25,528,474;12,457,781;12,58,782;26,783;29,784;21,474,586;26,785;12,510,513;29,478;23,786,787;12,788;12,42,498;12,476;12,388,789;29,499;23,790,791;26,792;26,723;28,793,466;21,275,794;12,457,795;26,796;9,478,177;26,797;25,798,623;9,799,91;26,572;26,800;29,801;23,802,803;27,804,197;9,805,32;9,806,163;25,267,807;21,808,89;12,572;26,809;25,154,810;12,811;9,812,38;26,813;12,457,453;25,154,814;21,509,224;21,815,816;20,817;29,805;21,818,81;27,819;12,106,820;12,821,822;9,823,32;26,824;26,825;26,826;21,827,466;22,275;9,828,32;29,829;21,830;28,831,466;29,832;21,474;11,833,739;12,106,834;29,835;9,42,163;25,8,60;26,836;9,837,163;21,838,389;9,839,163;12,106,275;9,840,163;20,758;25,718,841;12,505,499;12,388,842;26,843;1,844,521;26,845;26,625;12,457,846;9,128,389;9,847,389;21,848;23,849;29,850;7,851,852;12,853,777;21,457;21,854,466;29,635;29,855;21,808;12,106,856;9,857,81;9,275,91;29,858;25,267,859;26,860;12,861,637;9,862,91;29,863;21,425,81;25,8,864;21,865;9,866,163;12,441,867;9,530,389;12,58,868;12,58,869;29,870;12,564,868;12,98,871;26,872;14,505,873;21,874,875;28,876;23,694,877;29,878;12,513,879;21,421;12,441,880;25,267,474;9,881,32;22,179,758;26,837;21,882,89;26,883;26,884;26,885;21,509;26,886;29,887;27,8,8,6;9,888,170;12,889;12,476,526;26,890;9,891,91;14,892,46;9,893,8;9,894,38;9,530,32;21,808,420;26,895;12,106,896;9,897,91;12,106,898;12,106,899;21,900,586;21,901,466;26,902;29,903;12,457,904;12,457,905;12,457,896;21,897;12,106,906;12,457,907;12,106,908;29,909;22,195,145,146;21,177,521;25,154,910;25,154,911;12,510,653;21,712,354;21,912,274;27,857;9,913,81;26,914;21,915,354;21,712,222;25,267,754;11,916;29,498;26,917;9,918,32;12,457,128;22,919;21,920;25,921,922;21,923;9,924,163;12,457,925;21,712,466;12,513,926;9,927,163;9,928,163;25,718,929;12,505,42;9,930,91;29,931;1,932;29,933;12,692,576;29,934;9,935,32;9,97,163;9,936,163;21,723,354;21,489;29,937;21,938;9,939,163;21,940,586;9,941,91;29,935;25,154,942;28,712,224;26,943;26,944;25,945,946;29,947;26,948;14,513,46;23,526,949;1,950;29,951;9,952,91;12,487,629;12,457,953;28,954,955;9,956,8;26,499;12,457,957;9,909,91;9,958,91;21,959;20,275;21,960;12,821,267;12,106,961;12,193,698;26,962;11,963,81;9,964,91;9,697,91;27,645,197;9,965,32;25,528,966;21,967,658;9,968,32;21,969;1,8,8,212;21,970,89;21,971,420;25,267,221;26,578;9,972,81;9,829,163;26,973;27,644;21,974;27,8,8,212;9,975,81;25,267,623;26,976;26,977;12,97;12,457,978;11,979;26,505;12,980,981;12,630,764;27,982,466;29,983;25,984,764;9,985,163;12,95,896;9,986,81;25,267,987;11,128,389,988;22,989;25,267;9,990,32;12,991;12,992;12,993;12,994;25,718,995;26,996;21,997,389;11,998;12,850;26,999;11,1000;9,1001,163;26,1002;26,1003;21,1004;9,1005,163;28,1006,466;25,632,1007;9,1008,32;26,231;12,441,777;12,723,1009;29,1010;9,509,32;26,1011;12,821,1012;26,476;9,1013,8;9,1014,8;9,1015,32;14,42,46;26,903;21,1016;12,106,1017;12,42,625;12,1018,474;21,1019;20,1020;20,1021;21,961,586;14,98,46;26,1022;25,718,1023;21,1023;12,457,772;21,892,466;9,1024,81;9,1025,91;9,1026,91;9,1027,32;21,128,1028;25,1029;26,1030;21,1031;21,177;12,513,1032;12,58,1033;26,1034;26,1035;26,1036;12,630,634;29,1037;9,1038,614;26,1039;12,513,1040;12,98,1041;26,1042;9,1043,91;9,1044,91;9,1045,177;14,106,1046;9,1047,91;9,1048,32;1,950,466,6;29,1049;26,777;11,1050;26,1051;22,179,1052;25,718,421;21,425,619;12,106,1053;12,513,1054;12,106,1055;29,1056;26,908;12,821,653;11,454,389;26,1057;23,694,1058;26,1059;25,454,764;28,1060,466;21,522;12,388,40;26,56;9,1061,32;9,1062,32;21,1063;26,553;26,1064;25,154,1065;25,1066,474;26,1067;9,1068,91;12,519,787;26,1069;26,61;9,1036,163;26,1070;31,1071;26,1072;29,1073;9,1074,91;29,1075;9,1076,389;31,275;23,1077,1078;12,60,871;12,1032,871;29,1079;9,97,32;21,1080;11,275;9,1081,389;26,1082;29,1083;21,1084;9,1085,91;12,478,694;26,1086;12,1087;12,821,1088;9,1089,170;12,692,1090;12,95,1091;21,1092;22,1093;12,441,38;21,1094;29,1095;29,1096;25,718,1097;29,1098;12,457,867;12,1099,961;12,513,961;26,1100;12,106,1101;11,1102,739,988;29,128;9,1103,91;29,1104;25,1105,1106;12,457,1107;21,712;26,1108;7,1109;28,1110;12,95,1111;26,1112;12,513,589;26,1113;9,1114,91;21,867;14,414,1115;21,1116;26,1117;21,1118;21,1119,586;22,1120;9,956,38;12,552;25,8,1121;26,805;23,1122;26,1123;12,625,578;12,1124;22,1125;26,1126;21,1127;9,1128,8;25,945;9,264,91;29,1129;21,1130;28,1130;25,267,1131;26,1132;12,1133;12,513,1134;25,8,489;26,1135;28,551,746;28,1136;9,1137,38;12,516,1138;25,154,1090;12,106,1139;21,1140;9,1141,91;29,1142;21,1143;21,8,389;25,8,1144;9,469,91;21,38;21,909,389;12,457,1145;29,911;12,457,1146;12,441,1113;21,805;9,1147,8;26,1148;9,1149,163;26,1150;12,441,128;27,1151;1,1151;26,1152;12,505,1153;21,653;25,8,1154;9,97,91;12,892,1111;12,441,1004;27,1155;9,1156,81;21,1157;20,195,145;26,1158;21,1159,586;28,764;28,772;26,1160;7,1161;27,8,197,81;9,534,170;21,997;25,267,777;12,457,58;12,106,1162;12,457,275;12,441,772;12,457,1163;12,98,634;12,457,95;9,1164,91;20,1165;9,1166,74;20,1167;9,1168,32;14,1169,1170;4,1171,1172,1170;7,1173;9,1174,38;9,1175,163;9,1176,163;32,1177,1178;25,1179;7,416,1180;21,1181,654;21,112;12,1182;12,58,1183;12,1184;25,1066,1107;26,1185;12,457,1186;21,1187,81;21,653,1188;25,154,38;9,1189,32;25,718,1086;9,1190,74;25,154,764;21,1191;25,718,478;12,457,1192;12,106,1193;9,1194,91;9,421,177;12,513,128;20,1195;27,1196,466;21,1197,81;26,931;28,1060;28,787;25,1198;26,1199;12,457,478;26,1200;9,1201,32;21,606,875;9,1202,91;9,1203,91;9,1204,32;9,275,177;11,1205;12,1206,777;33;29,1207;12,861,867;12,457,1208;23,1209;31,747;25,267,1210;26,1068;12,457,1211;12,98,499;12,457,476;25,267,8,379,1212;21,1213;20,421;9,1214,163;26,888;26,1215;9,1216,91;12,837;12,1217;23,694,1218;23,694,1219;23,694,1220;12,98,1221;26,1222;26,1223;12,505,1224;25,8,445;25,844,575;21,1225;14,890,1226;9,1227,177;21,764;12,665,358;26,1228;26,1229;23,849,1230;12,510,822;21,1231,89;12,109,1232;12,457,1233;21,1234;25,8,275;26,1127;12,457,1235;29,1236;25,267,1237;9,1238,91;21,1146;25,154,1239;28,421;9,1240,91;21,1241,466;22,1242;9,1243,32;12,457,1157;12,441,1157;21,1244;7,1245;21,1241;25,154,1246;9,1247,91;9,1248,91;12,476,128;9,1249,32;26,1184;26,1250;26,1251;12,513,1252;9,453,38;26,1253;9,1254,177;12,510,1255;12,441,267;9,1256,91;12,499,488;21,811;25,8,478;21,1257;11,1258;21,1259;27,660,197,6;26,1142;9,1260,177;9,421,170;9,1261,38;26,1262;11,1263;21,1264;21,698;9,97,177;25,718,867;9,1265,389;26,1266;26,519;9,1267,32;26,1268;26,1269;12,42,474;21,908;26,1270;9,1143,32;7,1271;25,1272,1273;21,1274,81;21,275;12,457,1275;25,1276,1277;25,718,805;14,625,46;1,8,420,81;26,479;26,1278;9,1279,91;26,1280;11,1281;23,1282,1283;12,510,1157;12,510,1284;12,510,508;12,821,805;28,938;9,964,32;29,1285;9,1286,38;17,1287,1288,1289,1290;26,1291;27,844,197,212;21,908,586;19,1181,81,1292,83,1181;9,1293,170;17,426,1294;27,731,197,212;9,1295,81;1,1296,197,6;27,1297,197,6;27,1298,197,212;1,1299,197,212;26,1285;27,844,197,6;25,1300;25,811,1301;31,1302;7,1303;1,1304,197;9,1305,91;12,510,1306;12,547,646;12,476,421;7,1307;7,1308;7,1309;31,1310;21,1311;22,1312;12,1313,1314;21,1315;22,195,8,1316;9,1317,170;12,1313,938;22,1318;25,154,1319;12,510,1314;12,510,275;11,1320;9,1321,91;26,1322;23,1323,1324;23,1323,1325,119;23,526,1326,119;9,1327,91;23,1328,1329;25,811,1330;22,1331;27,819,197,6;26,992;14,109,1332;21,1333,1334;19,106,81,1335,83,1336;19,106,81,1337,83,1336;19,821,81,1338,83,1339;19,1340,81,1338,83,1341;27,1298,197,6;1,1342,197,6;27,731,197,6;25,718,701;21,1192;26,1343;25,154,1344;31,805;23,694,1345;25,718,1346;25,718,808;21,474,89;29,1347;23,1282,8,119;11,1348;9,785,38;1,1349;9,1350,32;9,1351,163;9,994,163;25,1352,633;25,1339,1353;1,8,197,1354;18,499,1355,32;29,1313;14,426,1356;26,1357;27,1298,466,6;27,1298,1358,6;25,267,1030;12,513,1346;23,1359,1360,119;26,993;27,1024,197,6;25,1352;21,1321;22,1361;9,1362,91;25,1363,1364;9,908,1365;20,1366;12,1367,1368;25,718,617;21,902;27,1369,197,6;1,1107,197,6;31,425;26,1370;22,1371,1372;27,844,197;1,844,197;25,154,1373;26,1374;23,526,1375;31,966;14,106,805;11,8,1028;1,844,197,6;14,22,1376;17,1287,1288,1289,1377;9,1378,1379;1,1107,197;21,1380;22,1381;11,454,739;21,8,586;21,454,466;9,1382,81;11,1383;31,1384;25,718,1385;23,526,1386;26,1387;25,267,1388;25,267,8,379,1389;26,1319;26,1390;22,1391;20,1392;31,421;22,1393;11,1394;27,8,197,212;1,8,197,212;22,421,1395;9,1396,177;12,24,1397;25,267,1398;17,1399,1400;9,1401,74;21,1402;25,267,489;25,267,1403;21,1404;12,665,1405;25,267,513;9,1406,38;25,718,453;22,1407;22,1408;27,660;9,1409,91;24,928,1410;23,694,1411,119;25,267,1412;27,660,466,6;22,1413;25,811;1,8,619;12,58,973;14,692,805;9,1414,1290;27,660,466;1,950,466;12,22,95;22,741;28,1320;12,58,1415;12,24,1032;25,267,453;25,267,1416;34,1417,1,1418;19,1419,1290,1420;8,1421;8,1422;22,1423;23,1328,1424;25,267,589;25,267,1090;11,1425;26,42;12,123,1426;12,700,1427;9,1428,91;26,1429;11,1430;11,1431;11,1432;25,267,1433;28,1434;12,513,805;14,106,1435;3,1436,8,1,1437;11,1438;20,1125,145;11,8,739,988;27,1439,197;19,109,81,1440,83,1441;19,665,81,1440,83,1442;19,106,81,1443,83,1444;22,1445;21,1446,654;13,861,1447;21,1448;27,1449,197;21,1181;27,1450;25,1339;25,718,1451;12,513,1451;25,154,1452;21,1453,89;21,1454,739;21,1454;9,1455,163;21,223,739;9,1456,32;21,1457;26,1458;14,98,879;14,95,1459;14,95,1460;14,95,1461;12,58,1462;9,1463,74;9,1464,163;12,1465;7,1466;18,42,138,8,83,1467;25,267,575;12,42,1468;12,1469,1468;18,42,138,8,83,1470;29,837;25,8,575;12,457,575;12,41,1099;25,8,1471;12,58,622;12,1472,622;12,513,1473;12,513,1474;25,154,1475;12,513,1476;12,513,622,1477;13,1478,1479,45,1480;12,513,1481;31,622;12,547,1482;26,1483;11,1484;26,1485;25,8,573;21,1486;14,513,1487;9,1488,8;26,1489;29,1490;28,454;9,1491,38;21,1090;29,1492;12,98,1493;12,24,981;12,1494,981;25,8,981;12,98,981;12,505,1495;14,95,1496;12,24,1099;12,1497,981;14,414,1498;12,1367,1499;26,1500;26,1501;12,1099,24;12,1099,981;12,1018,40;12,498,1502;14,95,1503;12,98,1504;20,1505;14,578,1506;12,41,42,1477;12,60,1507;12,39,1508,1477;12,519,1509;12,1497,1510;14,478,1511;12,22,40;12,510,1512;25,632,1513;11,1514;9,1515,114;21,1516;14,692,1517;25,1518,4,379,1519;9,1520,91;9,1521,1377;9,1522,163;25,154,1523;25,267,1523;27,1298;11,1524;9,1525,32;25,8,1526;21,511,586;31,1527;12,513,1527;31,1528;25,154,938;14,665,1529;26,1530;13,861,1447,45;21,1531;29,1532;12,1160,1004;12,1160,1004,1477;25,154,1533;21,488;22,1534,145,1372;20,1534,145;25,718,1535;13,1536,1537,153,1538;9,1539,32;12,513,1540;9,1540,163;8,1541;8,1542;12,513,1543,1477;9,1544,91;25,1545,1157;12,1540;9,1546,38,1289,1547;17,1548,1549;9,1550,91;9,1551;16,576,1552;25,1553;9,1554,38;8,1555;8,1556;35,1557;35,1558;35,1559;22,1560;21,1561;21,1562;21,1563;19,1564,389,8,83,1565;9,1566,163;9,1567,163;7,1568;19,1564,389,1569,83,1570;19,1564,389,1571,83,1570;31,1572;16,576,1573;19,1564,81,1574;19,1564,389,1575,83,1565;9,1576,91;9,1577,91;21,4,89;19,106,81,1578,83,1579;13,1564,1580,153;25,154,1561;12,513,1581;9,1117,163;9,1582,389;7,1583;9,1584,32;9,1584,32,1289,1547;9,1585,32;9,1585,32,1289,1547;9,1586,32;9,1586,32,1289,1547;9,1587,32;9,1587,32,1289,1547;36,1588,1,1589;36,1590,1,1589;16,576,1570;9,1591,32;9,1592,81;9,1593,91;9,1594,38;35,1595;12,1596,1597,1477;9,1598,32;27,1599,197,6;9,1600,170;26,1601;29,1602;35,1603;23,680,1604;9,1605,177;9,1206,177;18,1606,1607,8,83,776;14,1608,474;17,1609,1610;9,1611,389;14,513,1612;25,154,1613;9,1614,81;12,457,505;31,193;1,1615,197,6;28,128;23,849,1616;1,731;7,1617;12,1618;26,1619;25,1620;22,1621;22,1505;25,718,425;2,1622,8,1,1623;25,718,1624;2,1625,8,1,1626;9,1627,91;9,1628,91;12,1206,1629;12,821,1630;2,1631,8,1,1632;2,1633,8,1,1634;22,1635;28,445;9,1636,32;7,1637;7,1638;4,1639,8,1640;25,267,1641;12,821,489;21,1642,1643;37,1644,1,1645;22,1646,1647;21,1648;9,1649,32;9,1650,38;25,267,1651,379,1292;9,1652,91;21,8,875;20,1653;21,1654;19,106,81,1655,83,1656;22,1657;21,1658;25,267,763;21,763;25,154,1659;25,8,1660;25,718,1661;9,1662,91;21,1663;9,1664,32;25,718,997;7,1665,1666;38,1667,8,1668;3,275,1669,1,1670;7,1671;7,1672;39,1673,1674;11,1675;12,58,128;12,513,1676;12,630,426;11,1677;8,1678;12,821,1679;9,1680,114;14,58,476;25,1681,1682;17,1683,1684;2,275,8,1,1685;9,1686,32;9,1687,91;22,1688;14,513,1689;11,623,389,988;12,821,1690;21,1659;12,821,1030;9,1691,38;19,133,1692,1693,83,1694;11,1695;25,267,58;25,267,1696,379,1697;9,1698,170;21,1699;9,1700,32;12,441,414;12,510,867;9,1701,32;26,1702;12,106,1703;26,1704;27,1705;1,1706;21,1707;28,1707;9,1708,177;21,808,466;25,154,1709;21,1710;21,903;21,1711,81;12,106,421;12,499,1712;31,445;21,441;25,528,1713;12,692,772;12,457,1714;12,388,578;21,911;21,454;25,718,1715;12,505,1716;9,1717,389;9,1718,32;9,1719,32;12,513,506;9,1720,177;12,457,1721;26,1722;9,1723,32;9,1724,32;21,909;26,1714;26,1725;26,1726;26,1727;12,810,95;9,1728,81;9,1729,32;21,1730;21,1731;12,457,1241;31,867;21,1732;12,457,1733;14,457,1498;9,1734,177;12,564,519;14,1735,1736;14,513,1737;25,154,576;31,1738;12,457,1739;12,630,1740;12,457,1741;9,1742,163;9,1743,163;22,777;29,1744;11,1745;17,1746,1747;21,1748;12,476,425;12,106,1749;12,861,1750;9,1751,614;21,1208,466;26,1752;25,8,1753;9,1754,38;9,1755,163;27,731,197;21,1184;12,109,425;25,154,1053;26,1749;12,457,1756;12,578,1757;9,1758,32;25,8,1759;26,1760;9,1761,74;9,1762,91;9,1763,389;9,1764,74;9,1765,74;9,1766,389;7,1767;9,1768,163;12,58,1769;26,1770;25,718,128;31,716;9,1771,91;9,1772,38;21,1676,875;9,1773,163;28,747;9,944,32;20,1774;29,1775;21,1776;26,1777;29,1778;21,1779;21,1780;21,1781;12,476,1782;9,1783,614;27,1784;29,1785;9,660,81;12,457,1786;14,98,911;21,1787;9,498,163;26,1788;12,476,1789;9,1790,8;26,941;21,1682;21,1791;26,1792;26,1793;26,1032;12,98,1262;25,8,1794;21,825;21,1795,875;21,1796,89;21,1797,466;26,1141;14,95,1798;7,1799;21,1676;25,1545;23,694,1800;21,1801;21,1802,466;25,154,1803;21,1804;23,526,1805,119;9,1806,163;21,1807;26,1808;12,479;1,1809,1810;23,1811,1812;26,1813;21,1814;12,1010,1815;7,1816;25,267,1471;27,1817,466,6;9,1818,8;7,1819;7,1820;38,1821,8,1668;7,1822;3,1823,8,1,1824;9,1825,163;9,1826,91;21,1827;26,1828;27,8,8,1829;1,8,1830,81;28,1676;23,694,1831,119;21,1832,420;25,718,489;12,1833;25,718,42;12,106,1292;25,8,1834;23,526,1835;11,1836,389;26,1837;25,1838;26,1839;26,444;9,1840,32;9,1841,163;9,1842,91;21,1843;12,1844;12,457,1845;29,1601;31,489;25,798,499;21,1846,707;9,1847,91;9,1848,91;29,1661;26,1849;12,1850,1851;26,1852;26,1853;26,1854;12,505,1855;9,1856,38;12,388,1857;12,1858;29,558;21,1859;20,1860;17,1861,1862;17,1863,1864;9,1865,32;9,1866,32;25,8,1433;14,58,805;9,425,81;26,1867;28,1868,466;12,505,1869;29,1870;9,505,170;25,267,1871;12,1872;9,1873,32;9,1874,32;12,441,275;12,692,336;1,1875,1876;9,1877,163;26,1878;26,1879;25,1681;25,8,1880;14,95,8;9,1067,91;12,476,22;28,106,420;14,441,1004;7,1881;12,513,1882;9,1883,8;9,1884,81;25,267,1217;21,22;14,24,1885;12,98,637;22,1886;12,106,805;25,154,889;12,441,1193;21,1887;22,1888;25,718,1889;9,1890,163;9,1891,38;12,578,1892;14,973,46;26,626;12,457,1707;18,42,1893,1894;7,1895;22,1896,8,1897;14,837,1898;23,1899,1900;12,513,1750;25,1901,1902;27,1903;25,811,221;25,811,1904;12,499,764;9,1905,91;9,1906,163;12,441,896;39,1907,1908;7,1909,1910;38,1911,8,1912;22,1913;12,505,488;21,1914;14,564,8;26,1915;21,1916;26,842;14,564,1917;26,1918;27,474;14,892,476;25,718,764;21,1919;27,1920;12,499,42;26,897;26,1921;29,1922;9,1923,163;9,1924,389;9,1925,8;20,1926;22,1926;21,8,274;26,1602;12,821,1192;12,723,1927;25,1066,38;12,1928;27,1929;26,1930;25,1931,1932;23,694,1933;1,1934;12,22,1935;12,106,1936;20,1937;12,821,421;27,1938;27,1939;23,1328,1940;12,457,606;25,1066,601;25,267,1941;1,1942,274;12,22,1943;26,1944;23,1077,1945,1946;20,179,145;40,1947,1,1948;2,1949,8,1,1948;7,1950;27,1951;28,1952;27,1953;12,513,1954;9,1215,163;21,1955;27,1956;22,1957;38,1958,8,1668;12,106,1959;22,1960;26,24;27,1784,1961,1962;7,1963;26,1964;12,564,515;12,1965;9,680,163;9,1966,163;12,513,1967;14,98,488;1,1968;21,1969;22,1970;9,1763,1971;9,1972,38;21,965;12,513,442;14,513,1973;12,487,637;9,1974,81;25,798,1975;21,1976;25,267,1291;2,1977,8,1,1978;27,1979;27,1024,197;21,1980;14,837;21,1125;25,154,902;25,1066,1981;26,1982;26,560;27,1983;12,457,421;11,1984;22,1985;23,1986,1987,119;41,179,1988;9,1989,74;9,1990,163;21,1991;28,1992;22,1993;12,106,1994;14,1995,1996;12,821,1997;21,1998,586;9,1999,32;1,474,222;1,808,1334;14,98,8;9,2000,32;14,95,1885;27,2001;14,457,46;26,2002;20,2003;21,2004;9,1939,81;14,98,776;14,58,275;14,95,46;9,1968,170;26,1922;25,2005;26,2006;9,2007,389;12,513,425;12,510,488;14,2008,2009;12,2010;14,2011,414;11,2012;1,2013,1810;14,487,776;1,1859,197;9,2014,163;21,2015,224;14,22,46;23,526,2016;20,454;12,1160;11,454,81;22,1748;12,106,1018;12,106,475;9,2017,163;22,220;21,2018;12,457,22;12,106,601;20,2019;25,154,2020;26,558;7,2021;7,2022;29,1160;25,154,2023;20,2024;12,476,787;12,513,2025;26,2026;14,1054,476;26,23;14,513,879;21,2027;20,1748;12,692,2028;23,694,2029,119;23,2030,2031,119;20,2032;23,1328,803;27,731,8,212;9,2033,114;23,1328,2034;12,457,2035;1,2036,224;25,154,575;12,109,474;26,2037;25,267,2038;9,2039,91;1,2040,197;1,2041,197;9,2042,81;12,2043;12,519;14,22,776;26,2044;12,106,867;22,2045;20,2046;12,58,2047;1,2048,197;9,2049,163;9,2050,91;21,2051;32,179,76,1372;25,718,1658;25,8,2052;12,630,747;25,1066;26,2053;12,2054;12,95,997;12,441,1994;9,2055,32;9,2056,32;25,8,2057;1,2058,222,212;9,2059,91;9,2060,8;25,1179,8,379,2061;28,2062;14,98,474;9,2063,74;9,2064,91;27,2065;31,128;12,510,777;21,2066;1,660;12,2067;12,98,505;7,275;39,2068,2069;1,2070,466,6;22,179,145,146;22,2071;21,2072;25,154,2073;23,2074,2075,119;9,2076,163;27,731;14,476,2077;22,2078;1,445,521;26,2079;29,2080;7,2081;12,457,2082;26,2083;21,2084;14,513,2085;27,2086;9,2087,32;12,193,2088;12,457,805;21,2089;27,2015;9,275,38;9,1011,38;26,2090;12,60,506;12,441,1955;12,513,2091;21,2092;12,505,1004;9,97,614;9,2093,38;22,2094;20,2095;9,2096,389;26,2097;26,2098;29,2099;21,2100;9,941,163;12,861,499;11,2101;25,2102,1975;12,821,2103;9,2104,163;21,2105;9,2106,38;9,2107,91;11,2108;28,275;26,2109;12,457,2110;26,2111;1,2112,197;29,2113;26,2114;28,2115;23,526,8,119;29,2116;25,425;9,2117,91;26,2118;12,106,653;12,513,2119;27,2120;12,519,2121;21,712,2122;1,1363,224;12,505,637;9,2123,91;26,2124;20,2125;25,267,2126;20,1348;26,1247;22,2127;26,2128;26,414;21,694;14,487,2129;26,2130;26,2131;12,1497,777;26,2132;31,777;12,98,2133;12,564,2134;12,388,1041;12,106,938;14,513,1498;26,2135;26,2136;12,457,2137;12,513,453;27,2138;12,2139,698;9,2140,91;12,2141;21,2142;20,1534;12,457,1427;14,513,2143;21,1642;12,2144,128;26,2145;9,2146,91;22,2147;19,2148,81,2149,83,2150;22,421,2151;12,2152;9,2153,32;9,2154,163;1,2155,586;23,694,2156,119;25,718,681;7,2157;12,2158,1117;21,177,739;27,1024;29,865;9,2159,170;12,2160;25,267,2161;9,777,38;12,513,867;21,8,89;21,589;1,4,224;22,2162;19,2163,81,163,83,589;9,2065,81;11,2164;26,2116;29,1770;12,106,2165;9,1206,8;9,2166,91;7,2167;2,1822,8,1,2168;2,2169,2170,1,2168;38,2171,8,2172;38,2173,8,2174;12,24,2175;25,267,2176;25,154,128;20,1312;20,2177;25,8,98;25,718,2178;9,2179,81;20,2180;26,525;12,42,2181;21,649;28,2182;12,457,2183;12,513,1090;23,694,2184;21,2015;9,2185,81;27,660,197,212;21,2186;21,2187,274;11,2188;23,1328,2189;23,1328,2190;12,2097;9,2191,91;9,2192,81;7,2193;14,842;22,2194;23,2195,2196;23,2195,2197;23,2195,2198;23,2195,2199;25,154,578;25,154,508;25,8,911;28,2200;25,8,2200;25,8,2201;9,2202,38;29,2203;14,457,2204;9,2205,163;22,2206;7,2207;7,2208;21,2209;9,2210,81;12,2211,777;25,8,1146;31,2212;19,109,81,163,83,128;21,808,274;22,2213;9,2214,163;9,888,163;28,1192;9,2215,32;12,908;22,2216;23,1328,2217;9,2218,32;29,2219;21,173;9,2220,114;25,267,2221;9,2222,91;9,2223,163;9,2224,32;1,2225,222;29,2226;25,811,890;26,2227;19,133,81,2228,83,2229;12,513,2230;27,857,8,212;20,2231;21,1797;12,2232;26,1346;25,718,2233;9,2234,2235;23,680,2236,119;23,694,2237,119;22,2238;22,2239;12,441,1146;21,2240;21,267;12,564,95;5,2241,2242,2243;21,2244;9,2245,91;35,2246;21,2247;21,2248;11,2249;14,513,2250;25,8,2251;12,457,2252;28,2253;12,457,973;21,453;21,2254;21,2255;12,441,173;22,2256;9,819,81;9,2257,163;13,861,2258;14,821,2009;14,1702,46;14,1494,805;7,2259;7,2260;12,547;21,2261;7,2262;31,2263;12,1770;21,2264;12,513,2265;39,2266,2267;12,1099,1916;9,2268,32;9,2269,32;21,617;11,2270;27,2271;31,505;9,2272,91;12,42,2273;1,2274,2275,6;21,1192,875;9,2276,32;9,2277,91;22,2278;9,965,163;7,2279;22,2280;29,843;25,718,2281;9,2282,114;25,718,179;9,2283,32;31,1157;27,2284;42,2285,81,2286;19,2287,81,2288,83,2289;1,2290,197;27,2291,197;21,2292;12,513,489;9,2293,32;25,154,777;29,2294;29,2295;7,2296;29,2097;12,457,534;21,2297;21,1192,816;26,2298;27,2299,197,6;21,439;14,42,2300;21,2301;9,2302,163;19,513,81,2303,83,2304;12,513,267;9,2026,163;25,718,2305;9,2306,91;14,109,2307;12,505,22;25,267,2308;11,2309;21,2310;23,526,2311,551;11,2312;23,476,2313;21,637;14,58,2314;26,2315;23,526,2316;25,1066,2317;21,2318;9,2319,114;25,718,2320;21,2321;21,1189;21,2322;25,154,1157;14,42,861;22,2323,2324;21,2325;21,2326;9,2327,81;9,2328,91;21,511;12,821,2329;14,2330,2331;26,2332;29,608;9,825,91;29,2333;9,2334,2122;27,474,197,6;12,2335,425;14,2336,2337;25,154,106;28,879;9,863,163;14,973,2338;21,2339;12,510,1163;26,1402;21,2340;26,1286;29,2341;29,2342;23,694,2343;7,2344;26,2345;17,426,2346;9,2347,91;17,2348,2349;13,2350,2351;27,731,466,6;9,2352,38;9,2353,38;9,2354,38;1,2355,197;20,2356;9,2357,389;9,2358,389;21,2359;12,630,457;21,601;14,513,805;23,526,2360;9,2361,81;29,2362;11,2363,389;25,718,2364;9,2365,81;21,2366;21,2367;15,2368;21,2226;9,2369,163;21,2370;9,2371,91;21,2372,2373;9,2374,74;9,2375,74;22,2376;21,856;25,267,2377;21,2378;21,97;9,2379,739;26,2380;26,358;9,2381,2382;21,2383;21,2384;9,2385,163;20,2386;29,731;12,109,128;12,41,474;12,106,2387;29,2388;28,2389;9,2390,163;9,2391,74;43,2392,1060,2393;43,2394,1060,2393;7,2395;2,2395,8,1,2396;22,2397;2,2162,8,1,2398;9,2399,32;9,2400,32;9,2401,32;2,2402,8,1,2168;3,2402,8,1,2168;38,2403,8,2172;21,1859,707;11,8,389;25,267,2404;28,2405;14,499,2406;14,487,457;31,2407;22,2408;25,718,1846;15,454;9,148,177;7,2409;20,2410;5,2411,2412;39,2413,2414;9,2415,2235;9,2416,163;12,441,2417;25,154,2418;9,2419,2420;25,267,2421;7,2422;19,2423,81,38,83,2424;26,2425;9,2426,163;25,632,2427;12,499,2428;12,821,867;14,513,601;1,2429,197;27,2430,197;9,2431,32;23,526,2432,119;25,267,2433;22,2434;9,2435,163;25,154,4;9,2044,163;21,2436;25,154,665;12,513,2437;23,526,2438;29,2439;31,508;29,2126;9,2440,32;9,2441,32;7,2442;2,2442,8,1,2443;12,519,2444;25,1023;9,2445,163;21,1709;9,2446,32;9,894,8;27,445,466,6;12,1390;9,2447,81;1,2448;21,2449;21,2450;21,2451;38,2452,2453,1668;7,2454,2455;26,2456;12,2457;2,2458;7,2458;28,896;12,510,22;9,2459,74;27,2460;22,2461;2,2462,8,1,2463;38,2464,8,2465;7,2466;9,2467,614;12,519,2468;26,2469;12,457,777;12,723,1032;12,2470;21,2471;23,680,2472,119;23,694,2473,119;14,476,2474;9,2475,91;9,2476,170;4,2477,2478,2479;9,2480,81;9,2481,81;9,2482,389;9,2483,8;21,2484;14,58,2485;26,2486;25,154,2239;22,2487,2488;23,694,2489,119;12,513,39;13,22,2490;14,109,2491;20,2492;20,2194,2493;9,2494,38;3,2495,8,1,2496;3,2497,8,1,2498;3,2499,8,1,2500;3,2501,8,1,2502;3,2503,8,1,2504;9,2505,2235;21,772;9,2315,32;29,2044;9,2506,163;29,2507;9,2508,81;12,510,2509;22,741,145,146;12,22,128;21,2510;22,2511,145,1372;25,718,2512;12,1374;12,457,2513;1,2382,197,6;20,2514;29,2515;22,2516;9,2517,163;9,2518,32;38,2519,8,1668;21,2520;29,148;12,821,2521;27,1875;21,1433;1,2522,466,6;29,1141;27,8,466,6;1,660,197,6;12,457,2523;25,154,275;20,741,145;28,2524;12,39,1513;9,2525,32;25,267,2526;21,2527;1,2528,1334;22,2529;23,694,2530,119;11,2531;28,2532;22,2533;21,8,2534;21,2535;2,2536,8,1,2537;12,519,2538;9,2539,8;25,267,4,379,2540;20,2541;22,2541;1,764,197;21,754,81;26,2542;12,24,40;9,2543,91;12,457,2449;9,2544,91;20,2545;25,632,973;20,2546;22,2546;20,2547;7,2548;7,2549;21,2550;27,2551;22,2552,145,1372;14,42,2553;9,1406,163;22,2554;9,2555,163;9,1414,91;9,2556,91;9,2557,81;9,2558,91;9,2559,163;22,2560;7,197,2561;22,2562;38,2563,8,2564;9,540,163;9,2565,114;12,457,526;22,2566,2567;9,2568,163;25,267,808;12,457,2569;2,2442,8,1,2570;9,2571,38;9,2572,81;7,2573,416;9,2574,2575;14,441,2576;21,2577;21,2578;26,2579;9,2580,91;9,2581,389;9,2582,32;12,457,1023;44;25,8,1682;14,821,1157;12,861,474;12,24,2583;31,2584;21,2585;26,2586;20,421,145;27,2587,466;1,660,197;21,1181,586;7,2588;9,2589,163;27,1875,197,212;27,660,197;12,457,2590;12,1136,2591;14,22,2592;9,1726,163;21,2593;25,267,2594;26,1847;21,1214;9,2595,114;19,106,81,177,83,2596;25,154,2597;28,2598;21,1714;12,441,1692;9,2599,91;31,506;7,2600;21,2601;14,388,776;9,2602,91;20,2603;9,2604,163;19,106,81,177,83,1146;22,179,2605;12,106,2263,2606;12,821,2607;21,2608;29,2609;9,2610,81;11,2611;25,267,973;21,2612;26,2613;9,2614,389;7,2615;9,2616,91;22,179,8,146;1,1875,466,6;12,441,2617;7,2618;7,2619;7,2620;12,1136,2621;22,2622;21,2623;21,2624;21,2625,707;21,2626;25,718,2627;25,1545,2628;7,2629;7,2630;7,2631;5,2632,8,2633;5,2634,8,2635;5,2636,8,2637;5,2638,8,2637;5,2639,8,2640;5,2641,8,2642;2,2643,8,1,2644;12,513,40;1,1024;2,2645,8,1,2646;9,2647,163;9,2648,81;18,2649,138,2650,83,2651;9,2652,2653;9,2507,163;12,1136,2654;9,2655,163;19,109,81,107,83,2656;25,154,2657;9,2658,2659;21,2660;21,2661;22,2662;2,2663,8,1,2664;21,2305;21,2665;14,106,2666;9,2667,8;35,2668;20,2669;27,2670,8,6;9,2671,38;9,1237,38;2,2672,8,1,2673;22,2674;11,2675;12,1858,2676;12,510,1846;12,1497,2677;21,1846;21,37;9,2678,32;9,2679,81;21,2680;12,340,128;25,267,2681,379,2682;39,2683,2414;9,2684,38;22,2685;29,1406;2,2686,8,1,2687;34,2688,1,2689;4,2690,8,2414;9,1011;2,2691,8,1,2692;25,267,2693;12,106,2694;11,2695;21,513;23,526,2696,551;23,526,2697,551;23,526,2698,551;25,267,961;25,718,2699;12,821,2700;26,2038;7,2701;17,2702,2703;26,2704;12,106,2705;11,2706;9,2707;7,2708;31,2709;7,2710;12,1010,2711;22,2712;9,2713,1365;28,589;11,2714;1,8,420,6;11,2715;12,58,2716;9,2717,32;17,2718,2719;23,526,2720;25,718,1193;21,2721;9,444,32;28,439;25,267,2722;26,2723;12,564,2724;11,1425,739,988;7,2725;7,2726;9,2727,91;25,267,2728;22,2729;14,513,2730;11,2731;12,1469,2732;28,56;14,513,2733;9,2734,74;14,106,46;9,2735,389;9,2736,389;22,2737;9,2738,74;26,2739;9,2740,163;12,58,106;25,718,534;11,2741;25,267,2742;11,2743;25,154,601;19,665,81,107,83,2744;19,665,81,2745,83,787;25,718,1966;7,2746;25,718,920;12,821,777;25,267,2747;12,821,808;2,2748,8,1,2749;22,2750,2751;2,2752,8,1,2753;22,2754;21,2755;18,42,2756,2757;18,42,2758,91;9,2759,163;12,476,973;9,917,163;24,928,2760;25,267,2761;21,2762;38,2763,8,2764;5,2765,8,2766;9,2767,38;12,2768;21,2769;29,2770;20,2771;26,2772;41,2773,1505;41,2774,2775;41,2776,2777;41,2778,2779;21,2780;20,2781;29,2782;21,2783;14,1469,2784;26,1661;26,2716;22,1331,145;7,2785;7,2786;12,106,489;22,2787;12,821,509;9,2788,32;23,526,2789;39,2790,2414;20,2413;7,2791;26,2792;41,2793,2794;41,2795,2796;41,2797,2798;2,2799,8,1,2800;2,197,2801,1,2802;2,2803,8,1,2804;21,1060,586;9,2805,163;27,2806;1,2807,2808;21,2809;21,2810;12,457,2811;9,2812,91;19,665,81,2813,83,2814;23,2815,2816,119;1,8,8,81;9,2817,74;9,2818,163;9,2819,163;12,2820;9,2821,163;9,2822,163;9,2823,614;2,2824,2825,1,2826;2,2824,2827,1,2826;2,2828,8,1,2826;7,2828;7,2824,2825;7,2824,2827;38,2829,2830,1668;12,95,515;9,2831,32;9,2832,177;9,2833,32;9,2834,74;26,2835;29,2836;21,2837,875;9,2838,32;25,2839,474;9,483,163;29,2840;29,2841;7,2842;38,2843,2844,1668;38,2845,2846,1668;38,2847,8,1668;9,2848,389;9,1141,389;32,2162,2849;29,2850;21,128,586;12,513,2851;3,2852,8,1,10;36,2853,2854;9,2855,74;12,106,425;7,2856;9,1784,81;9,2857,163;9,2858,91;13,2859,2860;12,1163,2861;12,513,874;17,2862,2863;5,2864,2865,2866;5,2867,2868,2866;23,526,2316,119;23,526,2869,119;12,457,2870;17,1964,2871;20,2872,145;9,911,163;25,798,453;22,2873;12,22,425;9,2874,8;12,513,2875;11,623,389;9,733,163;22,2876;9,2877,114;12,821,973;25,718,2878;12,513,1113;9,2879,74;9,2880,163;9,537,38;12,1136,805;14,513,2881;25,267,2882;12,457,2883;21,2884;12,109,2226;21,8,2885;21,2886;28,2886;25,154,2887;25,1545,2888;9,2889,74;9,2890,170;21,1193;25,718,474;31,1959;28,2027;31,2027;9,2891,163;12,56;21,42,2892;9,2893,163;14,1136,2894;25,718,601;22,741,145,1372;1,2070,8,212;12,513,2895;13,1564,2896,153;14,513,2897;31,1658;9,2898,163;43,2899,2015,1053;14,513,476;14,578,2900;7,2901;21,2902;14,2148,2903;11,623,2904;12,2905,1507;12,519,2906;11,2907;22,179,2908;9,2909,91;9,2910,91;12,457,2911;9,2912,163;12,58,489;9,2913,163;25,718,1099;21,1453;21,1846,875;12,1367,453;21,2914;22,2915;12,513,2916;21,508;14,42,2917;22,2918;9,173,170;13,2859,2860,45,2919;32,179,2920;21,2921;21,8,420;27,2922,466,2923;21,2924;25,267,2925;9,2926,81;2,197,2927,1,2928;19,2287,81,2929,83,2930;25,718,2931;25,267,2932;9,2933,32;11,2934;26,2935;26,2936;26,2937;26,2938;26,1859;26,2939;9,2555,38;26,994;26,2940;12,821,2941;23,526,2942,551;21,2943;11,2944,389;22,2945;19,489,389,2946;9,2947,91;12,510,601;25,718,863;14,564,2948;12,665,973;25,718,195;25,718,2949;21,2949;9,846,32;25,718,1030;9,2950,38;9,2951,114;21,2952;17,1609,2953;24,928,2954;20,2955;9,2956,32;9,2957,32;9,2958,74;9,2959,74;31,179;12,821,997;26,2960;22,2961;21,179;45,2962;25,154,534;12,513,1023;20,2963;25,154,2964;34,2965,1,2966;1,2967,197;21,1429;27,2968,466,6;25,267,2969;12,821,128;7,2970;21,2971;25,2972,763;28,2973;21,2974;29,2975;25,718,2976;22,2977;11,2978;21,2979;9,2980;7,2981;11,2982;11,2983;25,718,2984;31,1023;21,2985;22,2986;20,2986;2,2162,8,1,2987;3,2162,8,1,2987;7,2485,2988;25,718,193;7,2989;22,2990;9,2991,91;9,2992,163;9,2993,91;38,2994,8,2995;3,2996,8,1,2997;36,2998,1,2999;25,267,698;12,825;9,3000,32;9,3001;9,3002;34,3003,1,3004;21,3005;25,718,3006;9,3007,163;25,267,694;12,1367,879;21,3008;28,3009;12,821,3010;25,1681,474;25,945,1859;21,3011;11,3012;21,3013;34,3014,1,3015;12,58,1181;9,3016,163;25,267,3017;21,195;21,3018;12,510,3019;12,821,3019;21,2318,466;11,3020;7,197,3021;31,938;25,154,3022;21,3023;36,3024,1,3025;11,3026;11,3027;31,3028;22,3029;22,3030;11,3031;12,193,489;9,3032,114;22,3033;21,3034;21,3035;19,3036,1692,8,83,3037;8,3038;8,3039;40,3039,1,3040;17,3041,3042;9,3043,32;9,3044,32;9,1125,32;9,3045,32;9,3046,91;28,3047;26,3048;9,3049,8;21,3050,746;25,1066,3051;9,3052,38;9,1540,38;26,2113;25,267,3053;9,3054,74;14,564,3055;34,3056,1,3057;24,1608,3058;1,3059,197,6;9,3060,163;11,3061;9,3062,163;37,3063,1,3064;20,3065,145;25,1545,3066;21,3067;15,112;25,267,3068;12,513,3069;21,8,3070;21,3071;9,3072,163;9,3073,163;22,3074;20,3074;21,3075;25,267,837;28,489;40,3076,1,3077;23,879,3078,119;12,1367,489;35,3079;21,3080;35,3081;31,509;19,2148,81,2149,83,3082;27,1951,197;12,866,3083;20,3084;21,3085;11,3086;25,267,3087;2,3088,8,1,3089;25,718,3090;21,3091;21,3092;9,3093,38;9,3094,91;19,109,81,2149,83,275;9,3095,32;19,106,81,3096,83,3097;3,3098,8,1,29;36,3099,1,29;17,3100,3101;9,3102,38;9,3103,163;28,1181;25,267,3104;26,3105;11,3106;12,478,637;25,154,3107;22,1937;35,3108;1,3109,224,6;12,58,3110;1,3111,197;7,3112;7,3113;20,3114;9,3115,163;12,513,3116;26,3117;29,3118;14,478,1055;22,3119;9,3120,38;9,1863,38;9,3121,32;20,3122;26,2158;20,3123;20,3124;9,3125,163;7,3126;25,8,3127;9,3128,163;19,3129,81,82,83,3130;20,3131;9,3132,8;7,3133;9,3134,170;15,3135;9,3136,74;9,3137,74;20,3138;9,3139,74;19,1853,1290,3140,83,3141;20,3142;22,3143;9,3144,163;9,3145,163;14,3146,58;22,3147;23,3148,3149,119;17,3150,3151;9,3152,163;20,3153;20,3154;20,3155;23,526,3156,551;9,3157,163;22,3158;46,3159,1,3160;29,3161;9,2485,91;22,3162;9,3163,74;26,41;26,3164;29,3165;28,3166;14,3167,3168;20,3169;22,3170;22,3171;22,3172;22,3173;20,3174;20,3175;20,3176;9,3177,163;22,3178;22,3179;20,3180;22,3181;22,3182;22,3183;20,3184;22,3185;20,3186;28,22;28,3187;34,3188,1,3189;19,2287,81,3190,83,3191;34,3192,1,3193;34,3194,1,3193";

const $scriptletArglistRefs$ = /* 13081 */ "383;995,1707;1705;112;1534;26;94;445,588;26,454;2905;440,454,757,1094,1095;1655;1100,2079;1707;1269,2487,2488;26,440,441,442;1708,2153;1655;26,1463;1655;1655;1655;2731;3377,3378;28,366,479,486,1959;404,2685,2686;383,479;1343;530,1709;1655;3168;1021;2073;412,1655,1804;112;502,1095,1161;910;1655;1655;1655;2731;1655;2979,2980,2981,2982,2983;26;26,366,423,427,428,429,430,1707;454,963,964,965,966,967,968;1655;2929;995;366;1705;454,693;648;3183,3184;1707;995;1868;26,366,454,1709;363;107,108;26,2353;1792;112;390;112;390,394,423,797;107,410;454,2711;1925,1926,1927,1928;191,712;1463;3749;995;351;1655;26;26,415,995,1708,1832,1833;440,454,757,1187,1706;3543;26,479;1792;26,757,1188;26,354,366;603,693;1655;363;940,1259;131,143,542,684,1792;2719;1338;1655;786,1499;26;28,1710;1655;383,390,454,501,757,1371;112;28,29,382;218,219;2448;3454;29;635,2107;635,3660;1534;1708,2153;1826,3499;1708,2153;1711,2828;390,421,422,1705;131;1135,3543;3747;1655;656;479;26,1041;2205;3589;363;1655;1865;107;107;1655;1866;1655;1338;26,3685;1655;26,454,995,1546,1547;26,107,454,1533,1534,1535,1536;592;383,390,454;1708;366,383,630;26,423,1534;801;1655;26;1869;1655;2831;454;1266,1655,2559;1655;26,27,28,29,1834;729;3702;1655;1394;366,446,474;1655;1258;1178;1534;995;2073,2074;1709;2084;26,107,454,1533,1534,1535,1536;1270;2172;1655;398,1666;26,366,754;26,1588,1595;995;1655;2835;26,27,28,29;1045,1655;542;26,442,443,444,808;1655;142;1269;2186,2187,2188;611;572;26,693,2500;26;26,415;3055;366,824;390;112;1463;899;3102;458;831;1100,1348;1798;1225;1709;26,383,454,544,587;1144,1182,1463,2610;447;2606,2607;592;391,995,2704;26;780;1100,1428,1709,2227;26,3097;1603,2694;995;1792;102;1792;3479;1792;360,361,1792;415,416;592,626,1679;371;107,1774,1775,2409;2209,3020;332,1265,1655;711,2413;390;2868,2869,2870,2871,2872,2873;410;124,2016;1655;1792;2086;1792;3152;2367;2378,2508,2575;1373;26,415,1832,1833;26;377,594,817,818;1444;354;26,440,454,757,1187,1706;454,1185,1186,1707;1497;372;1463;1707;3284;410,2438,2439;460,614;363,1655;131,143,363,542,619;1242;390,499,995,1534;1262,1655;1338;1672;26,1322,1706;1534;26,770,1706;592,1271,2343;1707;1338;1334;1338;556;366,383,500,630,846;1198;1655;112;1775;1463;26,3066;1463;29,546,592;592;1808;1145;1145;1145;592;29;26,624,1249;565;417,1103;3178;1100,1648,2227;3183,3184,3518;285,286;455;366,455,479;3132,3133;2539;1655;1534;1655;2802;715,716;26,1463;454;3575;26,454;474,592,1181;852;592,1534,1679,2923;693;1655;1463,1464,1465,1466;3482,3483;1733;3681,3682;1534;1709;995,1124,1125;1655,1792;1655;2034;107;26,831,1708,2111;1775;907,1706;1266,1655,1661;686;2864,2865;26,442,443;1655;124,705,2073,2301,2881,2882,2883,2884;1655;3376;1534;479;26,1612;2534;169,170;134,135,2501;390,455,479,857;112;366,383,630;26;-405,-2686,-2687;26;26,395,479,576,630,711,752,767;3289;3473;1324;1776,1777;26,786;783,1174,1655;29,635,1918;1463;515,1113;546;1297;1655;26;421;26,995,1708,1720;479,1534,1708;1655;1986,1987;479;1792;26,417,1712,1848;995;1534;169;1792;454,1706;1426,1427;1733;26,423,461,462,463;478;2839,2840;1706,1707,1708,1711;1792,2627;1792,2627;3046,3047;26,28,398,603;26;783;1595;26,1707;592;26,50,51,52,53,54,55,995,1534;463;366,383,479,630;1708;26,502,1161;29,592,3469;502,1095;1033;111;1898,1899,1900,1901,1902,1903;1104,1105;1706;124,3177;1775;403;1866;1733;1708;443,808;443,808;60,61,1261,1268,1655,1792,2445;2251;385;371,1792;614,1190;363,1776,1777;492;26;26;1655;112;1463;56,57;26,995;2087;1534;1534;225,363;693,1708,1713,2875,2876;1463;592,1691;1708;454,757;592,1598;1463;56,57;26,592;592,624,872;1792;3696;1534;995;479,544,3071,3073;656;1733;445;1100;26,454;1054;359;2888;1124;1279;468,592;1655;26;1348;1655;1655;635;29,131,592,2258,2259,2260,2261;1792;1808;1182;1540,1562,1563;2461,2462;592;26,479,1709;1463;1463;1655;363;63;26;592;363;1655;1705;786;26,592;499;1463;2754;29,592;1610;26;1676;26;26,1733;454,1496,1497,1498,705;2794;833;1708;1733;26,1733,1734;1709;2592;26,454,1100;1159;1775,3716;26,3656,3657,3658,3659;26,479,1706,1708;410,1761;1247;1768;1612,2761,2762,2763;1463;499;3137;1655;3116;26,574;415;26,1534;26,50,51,53,54,55,1534;26;26,415,995,1832,1833;474;1086,1087;382,390;1247;2978;1792;1136,3543;1324;1463;93;28,995;454;1705;1534,3093;635,1605,1606;26,395,603,693;479;2069;415,949;1707;1655;454,693;995,1717;1705;332,373,1265,1656;3509,3510;839;410;1708;26,1534,3093;366,730;1678;1534,3276;2953;390,2479;366;995;995;1338;357,358,359,1258,1655;1463;1655;107;2126;26,1709;455,1706;359;474,546,1025;1655;1655;3191;3191;1463;1823;26;2946;1789;1743;936;371;860;3347,3348,3349,3350,3351,3352,3353,3354,3355,3356;423;26,417,1103,1729;440;592;430;1863,3715;26,383,549,571,572;434,571;434,571;26,574;335;2118,2119;592,2821;1705;29;3709;592;995;1708,2153;173;2286;26,1706;2552;2286;1792;2286;638;2286;2286;2286;591;26;1463;2286;56,57;56,57;1792;1654;124,1894,3770;667,1792;1655;112;390,454,757;26;401;717,718,719;601;1768;1497,2486;26,574;479;1733;3768;26,2505;390,395,440,454,500;26,1843,1845;2689;1709;2343;107,2409;2301,2881;2731;26;423,1710;1706;56,57;454;1707;784;2684;107;2113;26;2841;335,1407,1408;363;26;1707;390;3701;2694;1496;592;499;395,479,1016,1017,1018,1708,1709;1808;26,574;383,390,454,479,587,857;730;394,1745,1746;2947,2948;665,666,1708;26,1707;981;1655,1792;26,473;382,592;455;26;56,57;1468,1469;1655;1709;366,383,1709;1655;1655;1655;1655;1655;1655;1655;1655;1655;1750;588,635,1610,1613,1616,1617,1618;476;2694;2017;434;588,635,1610,1614,1615;592,1463,1673,1674;592;417;2378;603,693;603,693;603,624,693,2235;603,693;1719;1484;1463;2642;433,1113,1114;26,3582;1534;26,366,394,479,554,555,556,557,1705;499;112,1477,1478;958;3717;976,986,2388;1648,3670;1655;1855;1655;1054;363,1259,1655;804,968,1551,1552,1553;26,417,1712,1848;656;1324;454,757;1792;29,415,515,546,592,2124,3382;1708;1707,1717;744;468;1655;1198;1708,2153;479,937;26;26,454,479,757;1039;1399;1263,3119;2893;1655;26;26;1707;1792;1730;1410;3277;75;1247;771,2590;26,454,757,1612;1081;26,995,2064,2154;1534,1708;373;897;366;1707,1712;26,443;1713;1706;26,1368,1736;2098,2099;1792;26;423,1706;1710,1711;26,417,479,603,995,1534,1706,1730,3018;1733;494,495;679,680,681,682;26;401,679,680,906,1534,1708;2400;2089;26,27,28,29,1834;131,143,1792;354;1923;1923;26;124;26,1191,2408,2414;1097;1669;1706;1534;551,1172;173;479;1935;1658;1789;683;1655;1855,3025,3027,3028,3029;3519,3520;1463;454;1209;2361;366,824;2642;26;56,57;943,944;592;592;592;26,693,1534,2500;3616,3617,3618;1219;3582;402,423,614;592;1706;2348;107,824;417,1534,1733;56,57;455,861;1463;141,3162;366,999;454;1534,3093;223,224,2207,2208,2209,2210;1493;112,448,449,450,451,452,453,454;417;26,3180,3548;2217;401,428,499,995;1534;56,57,1534;1710;56,57;995;896,2120;131,888,893,894;613,614;3376;26,474;26,1707;433,465;1463;1368,1369;56,57;693,995;56,57;546;26;26,995,1534,1959,2017;995;1317;26;26,1707;651;3072;410;1742;101,3694;718,3058,3059,3060,3061;454,500,757,1709;26;26,383,454,1706;454,757;786,1499;2600;3565;390,485;1789;3728;363;1792;1534;1707;635,3582;366;2157;572,930,1287,1534;635;29;1938;26,2495;635;26;635;1463;1706;3528;1534;1929;1413;3590;377;1716;401,1015,1707;1708;112,1477,1479;2124;592;359,1338,1463;627;112;943,944;433,585;26,1534;1707;406,408;26,1154,1534;1705;1722;390,454;1655;1942;1463;1463;501,1706;1655;390,980;1311;3038,3039;3771;1655;2748;56,57;742,867;410;3290;1033,1034,1035,1036;335,1742;26,2771;661,955,3333;3295,3296;1792;1709;479;26,29,1534;1375;786,1499;592;1176;586,612;1045,1655;630,1097,1705;454,693;786;1534,1708;1708;3376;1655;688;757,905;454,757;1612,2761,2762;442;26,415,995,1832,1833;26,415,995,1832,1833;417;1463;897;3014;383;1706;1655;26;1463;56,57;592;26,415,995,1832,1833;26,415,1534,1832,1833;2806;995;26;26,415,1534,1832,1833;1534;1792;1011,1281;26;353;26;1463;592;2408;28,1763,1764;591;1775;1749;390,588,735;112;995;1718;373,1655;26,995,2527,3091,3092;1693;995;995;1534;403;3038;468;585,2493,2494;592;1467,1468,1469;1706;107,3388;363;454,1469,1496,1497,1498,705;403;26,1534,2571,3093;592;2277;456;592;995,1708;26;1094;553;373;592;1534;825,826,1534;26,1604;1707;705;26,995,2527,3091,3092;1534;1706;1733;1463;1707;1710;2086;26,27,693,1708,3032;454;2449;234,235;2182;467,1776,1777;2354;1534,1673;484,592;2045,2046;434,549,572,592;1463;382,390;26;1450,1463,1550;1463;614;515,546,592;515,546,1853;1709;2953;402,404,771,1691,3551;1534;2066,3735,3736;1730,1732;1463;1708;3385;1244;1463;1707,1708;3599;3598,3599,3600;26;433,592;26;1713;1247;1534,3303,3304,3305,3306;454,1437;1463;924,925;56,57;1463;3358;886;1463;107;26,434,592;1534,1709;681;26,693,995,1534;2784,2785;1706;786;26,995,2527,3091,3092;592;1708;1463;1534;582;29,390,1677;56,57;1534;1534;1655;1463;1387;1707;1198;1100;592;26,1708;984;2211;813;26;1534;1463;1271;811;431;1707;2252;455;26,383,549,572,573;26,383,571,573,809;26,383,549,571,572,573,574;2145,2146,3721;26,383,549,571,572;1745;1655;780;1244;293;377;2940,2941;2228,2229,2944;403;26;1706;1655;30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49;592;546,592,1463;592,1242,1343;2518;29,546;29,574;592;29,546;3514;29,1743;592;3688;546;479;26,1706;403;1463;1182;26,949,1051,1612,3041;26,1706;601;1708,2153;1708,2153;195,332,1655,1657;26,603,995;592,1679;29,592,1708,2124;995;592,1463;1874,3561;56,57;26;56,57;1464;1655;985;661;354;454;455;468,592;26,479;1463;717,718,719;3394,3395;390;1797;1706;1209;2359;104,105,107,108;1064;26,1534;366,692,693,808;90,3636;1792;1212;366,3069;592;1032;1534,1673;1240;26,28,395,398,603,693;2554,2555;359;1463;26,948,1709;412,1655;1655;574,2319,2320,2321,2322;75;26,546,624,868,1527;454,757;1133;26,1844,1845;366,1707;1707;995,1534,3237;363;780;216,217;1463;592;26;377;383;625;1706;26;26,477;592;1450,1463,1550;2928;1463;2570;1789,2010;1063,1655;1103,3455;603;29,554,3088;1708;1463;1655;592;995;3401;1707;1463;3754;107;1534;2124,2408;1866;26,3548;26;2775;1463;1935;1776,1777;1709;1858;1463;363,1792;499;26,366,1162,1707;1463;1247;402,468,592;26;1463;2288;3653,3654;995;1789;592;1980;1768;621,940,1655;26,1097,1711;1463;1655;1244;26;1789,1792;592;1534;1877,3380,3381;26,1706,1707,1708;1463;29;1467,1468,1469;592;592;26;468,592;463,743,1130,1131,1132;390;26;572;592;26;249;1655;383;1235;26;1463;2294;2747;592;454;1211;804;1655,3665;3485;1710;2952;1486,3491,3495,3496;26,463,743;1672;26,455;546;512;2135;1467,1468,1469;1467,1468,1469;1574,1575,1576;1447;3302;3187,3188;335;3391,3392,3393;26,1493;454,757;1655;1708;1709;1679;2206;2989,2990;995;603,693;603,693;801;359,592,851;123;3475;3033,3034;1707;454,693;592;592;26,3514,3515,3516,3517;1463;1707;1792;1463;2694;26,479,757,1188,1705;635,2402,2680,2681;1088;366,390,440,454,560,757;454,757,1544;390,543;1463;544;1534;653,654;1713;503,1179;783;1714;1534;333,1655;827;410;2738;240,1581,1582;26;26,1534,3404;26,1534;26,417,1712,1848,1849,1850;3759;3667;974;1467,1468,1469;29;1052,1953;1655;1706,1707,1708;366,544;961;546;1438;943,944;1456;454,1645;1706;1247;1361;1144;503,504,2190;1922;26,2874;1338;1769;26,995;29,592,2055;26,112,394,1707;592;366,401;440;1467,1468,1469;56,57;213,214;1467,1468,1469;1700;592;635,3217,3218;1271;992;1655;1343;415,572,592;75;943,944;26;1463;1187;465,1004,1005;1382;592;1655;1713;1709;1809;1352;415,592;1198,1667,1668;1706,1713;2213;391;565,1705;1463;390,540;26,394;26;56,57;1709;2546;929;373,376;26;26,29,1534,3648;26,29,86,1534,3648;1706;26,29,415,1534,1832,1833;26,28,395,398,603,693,770;1673,1733;26,920,921;3341;1733;1534;1655;390,454,757,758,759;26,1534,2535;1558;454;1467,1468,1469;26,834;1463;430,680,1103;454,824;26;1292;-1369,-1370;1245;2844;1467,1468,1469;1467,1468,1469;1742;26;995,1101;1463;1260;1706;26;802,1469,1471,1472,1475;3339,3340;107;403,2150;1463;1463;1672;415,572;3311;2642;468,1213;434;56,57;811;390;592;614,1190;3033,3034;1709;922;26,402;2186,2187,2188;1463;572;592;592;26;26;1706;1796;1450,1463,1550;1709;3342;26,442,443;463;1708;26;786;1706;995;1248;1775;2264;2750,3713;3712;1534;603;1611,1612;532;603;1708;28;26,770,1274;995;246,247,1608,1872;26,1652,1742;506;2372;2028;1706,1708;1709;26;693,1709,2289;26,995;831;1463;1463;544,1708;1763,1764;1463;994;995;1534,1572;1655;955;592;532;26,3548;780,2047;1707;995,1534;402,434,549;592;26;3578;26,1534;463;1534;410;995,1707;1655;26;474,1707,2017;26,3278;1134;718,3058,3059,3060,3061;26,2601,2602;410,454,546,592,995,1534,1956,3056,3057;1316;3615;693;1706;26,415,1534,1832,1833;26;3684;322,323;1463;771;29;1463;26,1707;2491;602,1534;366;635,3582;1707;1706;26,546,1534;1534,3303,3304,3305,3306;995;2348;1463;741,742;1534;546;1655;28,394,433,455,468,810;359,2279;410,1419,2472;1707,1708;423,1719;3771;3771;3771;3771;3771;3771;592,1730;1655;2476;1467,1468,1469;1467,1468,1469;943,944;705;546,592;1709;995;395,1018,1708;401;2914,2915;1534;3514;1463;592;1463;1677,3651,3652;455;2225;1707;3122;2542;972;454;592;1463;477;474,1710,2017;1463;26;932,933;26,1368,1736;592;1247;1508;1182,1463;592;1866;731;2428;26,434,592;29;1463,1763,1764;1463;1792;499;1708;423;107,410,2570,3233;1792;463;1463;614,868,955,1036,1190,1698;503;614,868,870,955,1036,1190,1698;455;1792;940;1792;1463;1655;1798;1103,3455;529,530,531,1709;961;592;1763,1764;3376;26,630;77,107,2803,2971,2973,2974,2975,2976,2978;673;1117;2576;955,2295;780;267;1463;2702;410,1761;1655;1324,1463;1463;1209;1708,2337;3571;1706;383;592;1133;2358;592;26;455,733,734,1709;454,1496,1497,1498,705;375;26,415,995,1832,1833;26;2675,2676,2677,2678;1463;391,811;26;592;1263,1655;530,531,1709;1386;107;2694;-27,-1535;107;1574,1575,1576;655;1792;753;757,1709;546;592;928;363;1708,1733;619;107;1097,1224;2851;1713,2356;1792;1209;1467,1468,1469;1529;1707;454;2877;1041;757;757,1311,1709;454;318;503;591;592;2890;1708;1240;28;26,1368,1736;2576;3078,3079;1431;1707;390,479;468;2510;433;1314;1742;1463;454,1496,1497,1498,705;454,1496,1497,1498,705;1655;401;1706,1707,1708,1709;479;2086;1709;1328;454;1655;162,163,1307;26;499;28,29;592;69,1463,2664;-27,-28,-29,-30,-1835;984;1707;1706,1707,1708,1709;530,531,1709;26,1230;1463;1222;1352;2712,2713;26;26,592,984,1534,1708,2524,2525,2527,3093;26,28,592;635;592;995;1548;1706;2988;1534;995;1707;1711;26;1655;1463,1493;1792;1934;1672;3552;995;995;1534,1584;1655;592;1709;1655;3444;1247;3703;26;112,454,565;1060;1706;1706;3033,3034;26,1189;1463;592;497,625,678;1100,1709,2079;551,2120;1438,1463;1463;1655;652;672;681;26;26;1636;1707;1792;529,530,531,1709;3376;1100,2236;1648;1034;2485;1463;1463;3411;64,65,66,67,68;1792,1804;685;2095,2097;995;771;2365;1247;1463;1707;635;669;1706;1247;26,545,693,995,1733;-27,-1104,-1535,-3568;1247;545;1247;1247;1247;1710;1463;366,736;3139;930;1655;2694;1655;26,2742,2743;1852;1463;1271;1655;2586;592;1198;897;390,995;457,458;28,1733;995;1706;1792;1463;28,592;377;2960,2961;26,29;26;26;592;3113;1231;851;1534;1709;1707,1708;463;592;1100;560,1444,1445;506;3683;3683;3683;1463;638;26,638,1651;3597;1710;1324;592;1463;1763,1764;681,2705;1672,1706;888;2117;394,1745,1746;29;394,1745,1746;2173;394,1745,1746;394,1745,1746;394,1745,1746;99;635;1463;1463;2421,2422;2703;1859;1705;1906;1789;1463;1463;1789;371;86;1121;1709;29;592;29,1743;603;592;592;592;1763,1764;592;3514;26;29,1743;592;26,28,29,3253,3254,3255;592,1463;3514;2221,2304,2305;592;29;640;603;592,1742;592,1344;592;592;29;515;455;592;592;29,546,729;3234;1767;1463;454;1707;1463;1655;592;1463;1574,1575,1576;1742;546;1655;26;26;1707;2286;26;2286;2286;1209;592;26,592,995,2527;1463;786,1981;1648;1708,2153;1708,2153;1708,2153;391;1780;988;989;366;2286;1708,2153;2286;1572;1655;840;1463;103;592;592;2286;1451,1452,1453;1463;189,190;546;1584,3507;112;1706,1707;26;2090;1463;3715;2577;455;1463;2522,2523;454,757,2179,2180;26;1709;1707;2591;1708;1792;1231;1706;366;1708,2575;1493;1463;1577;1247;2658;415;109,184;1655;1917;417,692;940,1655;3500;3564;305,306;29;29,546,995,1708,2124;1706;1410;1247;2161;634;107;635;2694;995;592;26;454,1564;454,757,1249;1709;454,1564;3033,3034;1103,3455;635;1792;3105;26,952;410,530,1124,1679,1689;26;1534;3337,3338;635;415;26,933,1840;2621,2622;656;2843;546;383,501;487;546,961;26,2114;26;512;995,1707;26,995,1463,1534,2130,2664;26,1706;26,501;26;1709;466;383;26;995;26,377,1251;1323;455;1355;415,1874,3625;415,635,1730,1874,3625;1733;2692;2632;954;1789,1809;394,468;3570;359,1463;1870;1708;1706;1067;1709;1182,1244;1212;841,842;1534;1710;26;1303;363;874;1804;3452;879;26,576,630,711,752,767;1276;330,1662,1808;26,1534;1534;859;1463;1706,1707;2477,2478;1655;29;1706;1463;592,1463;26;26,1384;1463,2385;-27;2696;1655;592,1189;1463;1463;2247;831,1707,1956;1711;1756;1602;371,3720;29;886;1463;892;468;1124;26;2152;410,1359,1463,1761;780;26;592;1763,1764;430;383;1655;1709;1706,2933,3042;1324;1313;635;786,1499;1463;2694;1784,1785,1786,1787,1827;488;479;1463;2290;1655;395,479,1016,1017,1018,1708,1709;1655;1497;415,572;1792;1792;1709;592;394,1745,1746;506,585,592,711;1463;-384,-391,-455,-480,-588,-858;1706;546;1655;635;2693;107;371,1655;1732;995;806;1497;29,546,1463;1463,1534;26,50,51,52,53,54,55,995,1534;3205;1463,2926;1338;26,546,592;455;394,661,1213;26,479;592;26,382,511,512;592;572;468;592,872,2203;26,814;3211,3212;1677;402,479,546,592;479,592;480,481;26,383,395,396,3362,3363,3364,3365;26,383,395,396,3362,3363,3364,3365;26,383;26,383,395,396,3362,3363,3364,3365;26,383,395,396,3362,3363,3364,3365;1784,1785,1786,1787,1827;26;26,383,395,396,3362,3363,3364,3365;26,383,395,396,3362,3363,3364,3365;26,383,395,396,3362,3363,3364,3365;26,383,395,396,3362,3363,3364,3365;569,1432;1521;603;26,693,2083;730;1775;1497,1655;2731;1149;1463;1677;1433,1434,1435,1436;757;1399;2263;1789,2676;1293;351,783,1781,1782,3628,3629,3630,3631;515,546,1733,2658;1494;371;546;1054,1463;592;1463;1136,3543;403;26;995;1463;705;3512;405;3228;742;2509;3273;3514;2694;592;381;29;1677;2002;26;1730;995;403;1156;786,1499;1463;603,693;3322,3323,3324,3325,3326,3327,3328;1792,3568,3569;1093;403;1534;1707;1709;1182,1244;382;2584;592;955,1311;1373;546;592;592;592,2806;2184;26,112;26;995,1963;2665;592;881;1784,1785,1786,1787,1827;390,395,454,757,1209,2070,2071;454,627;26,454,757,1022,1100;1463,1534,1634;366,390,440,454,560,757;454,757,1544;390,395,454;2161;434,1852;363;29,1680;2193;454,757,995,1554;773,774;410;3588;1534;1534,1706,1730;1463;1742;382;1497;1463;1289;1655;1655;1655;26;1710;2852,2853;359;2946;1534;1707;26,398;931;410,1761;26,417,995,1848,1849,1850;26,603,693,2234;26,417,1712,1848,1849,1850;1463;1486,1487,1488,1489;2170;1784,1785,1786,1787,1827;1655;1250,1957;3165;29;862;1438;878;26,377,821;1348;2048;455,592;1247;2199;1534;26,902,1711;366,630;1463;592;1706,1707,1708;681,2933;2578;503,1677;2551;635,3216,3218;1463;1111;578;366,401;423;390,402;532;2262;875;3527;753;468,626;661;1855;390;1608;2296;3043;29;401;1244;26,112;1463,2697;2694;371,1792;2269,2270;331,1265,1655;468,549;1707;3461;468;128;176,177,178,179,180;592,625,1707;995;570,659;1534;107;1733;454,705,1496,1585;592;1713;26,1023,1705;26,560,2332;468;1976;29,1496,1534,1723;592;826,1707;568,1708;112,421;26,1706;26,423,2271;995,1534;120;1463;1534;3711;26,995;1713;995;1713;1467,1468,1469;1534;995;1534;454,1446;1534;390,454,757,1706;1634;1066;2875;1713;705,1648;26,455,501,544,603,656,808;1706;1706;705,824,3604;3196,3197,3198;1100,1247,1372;26,3465,3466,3467;603;1709;26,1705;26,415,1534,1832,1833;26,1534;635,2548;454;1368,1369,1736;417,680,906,1708,1730;1750;906;26;479,3341;26,469;2524;1733;3514;26,415,1534,1832,1833;26;656;1327;1534;390,1707;125;1534;107,2846;1706;1655;1124,2945;705,2301,2881,2882;26,515,546,1733,2658,2659;335,1600;2357;418;3169;26;1707;1730;26,430;3679,3680;1655,1792;1783;26,1534;3556,3557,3558,3559;515;506,592;382,572;112,706;3033,3034;3033,3034;3033,3034;3033,3034;2633;488;3587;943,944;26,545,616,1706;592;592;26,1463;415;455;592;26;592;592;29,455;455;950,2062;592;421;2806;943,944;2716;592;2520;592;390,1708;26;2694;455,1534,1708;390,1708;354,708,709;1463;1709;1707;395,592,1709,2028;468;635;1707;401;1247;1534;1180;592;26,995,2527,3091,3092;26,948,949;1497;99,239;995;1733;658,771,1709;592;479,995;1708;1112;2774;1706;995,1534;479,770;390,995;1247;592,1742;26,831;278;29;995;26;852;1706;881;188,3262,3263;1463;26;592;1419;1456;1463;1655;1024,1705;1463;627;26;26,592,640;1244;995;1463;604;1708;995;2080;592;1708,1744;124,280;26,3402;792;3538;29,515;1463;390,627;770;1463;499;359;656;1563;635,1590,1610;959;1463;656;1463;359,1338,2694;614,1190;1707;838;625;26;603,693;635;625;943,944;26;29;1916;1709;410;390,410,421,422,1706,2041;592;1534;1534,3303,3304,3305,3306,3308;1708;112,1100;2196;603,1097;26,480,2642,2729;943,944;426;2008;560,1444,1445;1463;1938;1707;454,757;656;2194;656;576,630;1463;592;3690;1182;468;479;2694;1792;1763,1764;1222;26,28,398,479,603,919;515;1709;1707;26,479,1534;29;636;1182;383,474,788;1655;746,1655,1792;2731;107;1655;1969;1463;973;1244,1463;546;1463;1540,1562,1563;1409;2225,2226;995;26;468;1655;550;425;468;1463;592;592;1705;1707;995;415,572,592;107;26;3376;1182;2237;26;410,669,1100,2375;410,1244,1463;26;546;26;592;1784,1785,1786,1787,1827;656;1709;851,983,1182,1463,1472,1501,1502,1503,1504,1505;831;1463;26;410,1182;592;3706,3707;995;1743;1497;3126;705,995,1720,2308,2309,2310,2311;592;546,3687;26;1713;1259,1655;237,238;3669;656;802,1469,1470,1471,1473,1475,1476;107,410,2570;627;592,2394;1655;1655;1463;1707;417;107;1463;394,512,614,742,1179,2064;240,241,243,315;661;742;26,434,460,503,742,872,902,2064,2928,3627;896,1463;107,1775,2409;1706,1707,1708;1463;3663,3766,3767;363,1658;800,801;922;1717;3650;1889;107;107;2067;2263;1709;1621,1647;1542,1543,1646;3209;1463;359;1020;3412,3413;390,592;2623;923;29,2801,2802,2803;544,1705;546;530,531,1709;2501;112,366,415,548;112,1479,1506,1507;3031;359;107,2560;995;1247;1247;1534;410,1271;26,454;390,454,757;454,1496,1497,1498,705;26,454,479,548,757;1585;26,1534;26,366,479,695,2500;592,3536;29;3497;1463;1463;3689;1548,1763,1764;1467,1468,1469;383,703;335;112;1094;1770;1429;2746;26;3739;107,454,2298;1472,1509,1510;618;440;107,1463;2618;1103;1463;60,61,1788;1463;3386;1463;655,745;383;445,565;1706;366;1709;2436;454,757;26,415,995,1832,1833;3109;3672,3673;26,29,592;1733;1534;26,383,454;509;1103;390;1472,2959;1001;112,407,409;820;546;1338;1655;1463;359;696;2284,2285;1534;1534;26,592,2527;995;1534,1895;26,536,537,538;2004;390,454;440;642,643;592;26;434,468;1352;592;354;847;26,377,479;3002,3003;1677,1687;354;454;1463;1463;56;2778,2779,2780;2328;592;2515;1534;377,2337;2946;1534;1463;1838,1839;1463,2012;1706;468;922,1611,1613;1625;1534,3303,3304,3305,3306;1724;26;1715,3320,3321;603;995;1708,2521,2656;635;902;26;961,1726,2148;28,603;995;26;26;26;26,933,1840;1942;75;3472;627;3582;26;351;366;26,1497,3056;1534;1463;107;1534;1497;744,1706;26;366;2650,2651;1463;390,1708;1676;410,1761,1762;943,944;995;26,29;1937,2689;26,640;995;705,1709,1730,2221;831;1463;1534,1584;1829,1830;1765;1655;1655;1078;1808;1655;2035;1348;506,868;592;181;1299;28;1655;2731;26,468,572;440,1706;2908,2909;1655;1792;592;26;468;75;112,1477,1478;103;3638;635,1541,1542,1543;26,1610;1710;1247;1247;995;1247;1210;783;1247;1708;1247;1463;26,27,544,545,546,1708;1247;1247;1463;865,1450,1463,1550;1247;1534;26;592;1708;1463;546;1879;390,778;1463;433,476,592;3166;1463;2432;1247;479,1709;3466;26;107,649,650,651;656;282,283;404,3551;1655;599;1463;638,693;728;377,479;657;1706;592;433,464;1534;433,1113;2535;592;592;592;506;2901;995,1534;1707;1733;1463;1463,1720;2886,2888,2889;1705;592;744;1463;592;1103,3455;546;2465;434,902;107,2409;2661;592;592;592;26;26,2140;592;2807;3683;-27,-639;1247;26;1020;651;26,1708;1247;546;655;2768;1463;1247;1648,3533,3534,3535;1706;26,603;1463,3145;1419;112;26;394,1745,1746;394,1745,1746;394,1745,1746;394,1745,1746;26,383,571,572;433,434,435,436,437,438;394,1745,1746;1528;592,1594;1970;2447,2648,2649;383,415,479,576,630,732;1792;1792;1745;1169;403;1706;390,1708;1021;363;627;1706,1707,1708;3376;440;943,944;943,944;943,944;995,2745;592;335,515,592;382,402;29,515;515,592,1463;592;592;547,1677;592;403,592;29,1677;603;29;29;592;592;592;592;29;26;1463;359,2562;1097,1707;2142,2143,2144;103;1733;828;1463;2048;1253;592;1463;1463;1534;1603;572;260,297;1463;592;1708,2153;1463,2009;1707;693;26,410,1706,1710;693,711;26;546,574;1706;777;1655;546;1942;1463;1291;390,391,1712;572;792;2286;1247;682;1124;1463;1808;371,1290;257;2066;359;2399;2500;1493;1280;592;1950;1792;1463;2793;1705;1655;1707;995,1463;1655;454;112,627;1534;390,454,496;391;390,1707;1706;1706;454,757,2085;1463;1655;1100;440,693,1706,2931;1706;26,382;2689;415;1438;1124;26,28,1249,1534,1679,2923;26,1534,1679,1733,2923;26;3090;2230;26,1534;26,1534;1093;1416;2727;29;654;1463;1792;1708,2805;29,1708,2124;592,1706;813;546;515;402,592;107;592;1712;603;1534;1706;1946;635,1534;2419;1655;1287;941;26;1655;1707;2707;3743;500,1707;1534;1054,1463;1247;995,3105;1463;454,757;479,854;635,1584;1706,1707,1708,1709;1463;26;592;86;1706;26;455;26,995,2527,3091,3092;26;1212;1588;995;3552;1534;26;995;26;26,1708;26,479,1708;1709;26,995,2664;995;1708;1710;26,693,995,1534;26;1709;1709;390,1708;1707;26,995,1534;390,1709;1707;26,2326;1707;26;886;2106;1792;2224;1655;945;592;415,1874,3625;363;2212;26,404,2737;26,3582;995;592;26;1034,2341;1463;2086;544;592;945;1103,3455;1706,1707,1708,1709;1709;783;831;2832,2833;26;29;26;29;3315,3316,3769;592,1763,1764;635;603;1655,1794;792,2491,2789,2790,2791,2792;1385;3166;1705;1706,1707,1708,1709;26,3359,3360,3361;1706,1707,1708,1709;2900;1447;393;1463;1463;2201;479;479,592;1338;1709;1070;29,1463;592;1247;26;1743;1354;995;26;995;26;542;1247;410,3545,3546,3547;75,107;26,81,82,83,84,1534,3336;366;112,1711;1463;2777;1401;244,245;2691;1301;26;416;26,574;107,1485;3130;410,1761;1711;1851;3376;3720;107;1463;1463;656;1655;1792;2029;1463;445,454,500,805;1896;363,1792;3637;390,1708;26,395,479,576,630,631,1722;1244;2068;26,995;454,757,1710,1711;592;3202;592;394,1745,1746;394,1745,1746;394,1745,1746;394,1745,1746;1882;592;2368,2369;479,730;1368,1369;1463;394,1745,1746;1745,1746,1747;1708;995;2429;2429;2429,2430;797;1706;1534;1264;1517;786;401,1708,1956;1763,1764;107,1775;1338;26,592,640;592;592;592;592;1006;522,523;390,433,763,764;592;624;592;592;463;2647;592;26,402;592,1677;468,592;592;3443;455,592,863;548,661;592,910;592,786;468,592;592;29,592;592;26,393,572,1143,1144;26,401,1707,1708;26;26;26;1792;26;546,635,1706,3635;289;1655;608,609,610;592;1463;3400;395,405,501,995,1534,1705;592;1644;28;107,2390;474,2287;995;3376;1164;546;1707,1734,2241;29,1733;546;1463;1655;1222;3250,3251;2986;382;26,3548;1672;1672;506,592;454;561;1711;26;1711;592;1373;2219;1463;1655;910;1534;1655;792,2934;1463;1655;454;1706,1709;390,1708;1463;592;390;831;410,1469,1516,1517,1518,1519;29,580,3300;29,580,1534,3300;1655;112;1887;893,1239;1463;1655;578;410;417;1463;1655;676,1463;26,377,2107;26;390;603,693;603,693;2890;107;1463;1051;2408;272;359;592;390,1246;1049;29,1084;1463;542;2438,3005;26;1709;656;415;415,546;460,2531;455;1691;592;592;455;500,2134;592;995;1449;995;3167;26,417,995,1709,1850;390,454,479,1710;1463;1710;26,970,1706;390,1708;390,1708;705;3747;26,468;2626;391;112;1463;3529;1361;1463;499,771;383;2841,2866,2867;3199;26,3343,3344,3345,3730,3731;26,402;1277;783;1655;2086;1708;445;995;26,383,468,592;2447;995,1706;26,1707;2009;995;366,551;26,383,393,394,395,398,3750;26,397,398;26,417,1103,3455;1324;29,580,3300;1534;390,479;1534;1708;390,857;26,592,995,2124;26;366,479;546,1534,3462,3463,3464;401,421,664;592;1094;1677;1421;1463;1463;2263;403;1655,1659;592;1058;1857,2001;421;3110;560;2004;1039;3586;2532;1463;1792;1463;1226;1463;112;458,2856;1655;532;970,1454,1455;970,1454,1455;1655;1463;1359;1463;1281;3376;103;1784,1785,1786,1787,1827;2902,2903,2904;498;460;592;592;3714;3714;1809,2984;454,1284,1500;2371;506,539;26;904;107;592,1708;1733;268;26;1463;705,2301,2881,2882;1463;693,2333;592;592;1463;2688;1054;1463;2694;454;1431;669;506;1852;1198;2141;1851;1272,1705;1152,1389;2251;1534;1655;635,3104;1534;2079;1964;389;-27,-28,-29,-30,-1535,-1835,2979,2980,2981,2982,2983;1247;26;1706,1707,1708,1709;26;3171;2830;1247;401;1463;1497,3023;454,705,1496,1585;742,2399;26,335,995,1943;995,1543,1707;29;956,2005,2083;1463;2274;28,390;1324;366,383,1116;1706,1707,1708;1247;762;1463;26;26;26,1368,1736;1792;1119,1792;334;107;1709;995;26,415;113;29,546;1710;1710;1707;351,1126,1127;1706;995,1709;3418,3740;26;26,859,1242,2293;415,572,592;29;107;3447,3448;430,635,1103,3257,3258,3259;479;1713;1705;995;1157;995,1534;3310;3376;1761;1915;401,1534,1730;479,655;454;1707;26;1463;335,1324;281;1798;995,1534,1733;479;112;26,544,630;1198;778,1940,1941;1184;1952;26,442;1080;1789;572,2242;1711;592;1103,1534,3455;3760,3761;26,3379;454,1956,2620;1775;1463;1655;635;335;592;1100;440;1947;1709;1809;1655;1534;26;592;2506;1707;26,1463,3317;3329,3330,3331,3456;29;1909;468,592;26;592;592,3080;2808;546,1852;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;872,955,2848,2928;1705;592,3192,3193,3194,3195;2345;515;592;454,1284;394,423,547,1709;2440;26,3021;592;943,944;943,944;26,1534;1707;3487;1438;1463;26,366,479,1706,1708;1463;2306;693;1708;1463;390;15,-27,-1535;1534;26,2906;1707;2346,2347;1463;2642,2725;876;124;1808;382,574,1672;1706,1720;658;1733;1463;545,693,1710;26,59;946;26,1534;1463;1456;1463;1706;1709;1733;693,1706;682,947;544,2083;2286;1000;1708;1691;366,525,526;1708;1708;1691;26,59;26,59;1708;1534,3093;592;831;3257;592;26,1534;26;1655;26,59;3505;423,995;995;26,428,1707;1534,1707;382;26,59;592;1463;480;1708,1836,1837,1838,1839;1348;417;786,1499;897;-27,-28,-29,-30,-1835;1463;26;2086;26,59;26;1733;1655;1801,1802;635,1590,1610;784;693,1103,3455;625;630,711,752,1097,1273,1672,1705;1463;335;3110;394,468,496,592;1534;382,390,434,456;1062;503,2164,2484;1463;1463;656;831;3632;1534;1675;28;1707;26,3693;1707;1534;1463;995;546;627;1463;363;26,417,1848,1850;1467,1468,1469;592;943,944;2556;2703;2471;3013;417;786;546;2962;1472,1509,1510;410,2385;340;1809;112,1831;454,824;1991;1792;3506;29;1706;454;1463;1894,2019,2020,2021,2022,2023,2024;1463;1768;1784,1785,1786,1787,1827;1463;26,479,3227;1775;1655;1655;2694;1463;29;506,549;359;107,2409;2576;1463;1796;1463;2409;1706;1056;1399;2827;455;656;1247;1706;592;454,757;2731;592;26;2950;366,1860;1420;804,968,1551,1552,1553;26,454,592,1706;410,3384;802;2169;3406;2660;1808;359;351,1126,1127;592;638,1534,1612,3404;1709;1792,1804;546;2059;1244;3291;550;2088;1534;635;1463;1463;1247;1534;693,1706;1463;831;403;2822;780;26;1534,3093;1534,3093;1534,3093;1463;1792;1247;753;3332;872;867,868;661;460,503,872,3627;1103,3455;831,1352;1280;1496;1124;1463;26,1103,3455;1792,1804;2044;592;2334;635;874;455;371;3048,3049;3376;-27,-1104,-1535,-3456;403;1792,1804;3009;87,88;1705;1677;532;984;2012;635;592;532;1463;1127;434,468;415,572;1463;1284,1495;440,769;1463,1527,1528;107,1182;107,1775,2409;1951;1587;995;335;995,996;3729;1990,1991;26,454,757,1100,1709;1103,3455;2110;26;112;454,757;1463;29;26;1247;1463;592;1655;995;1348;1292;29,468;3746;390,479,922;578;1248;995;786,1499;922,1619,1620,1621;592;29;468;1463;366;1792;103;592;1808;2930;565,566;515;1463;1655;479,500,630;988;455,468,592;637,638,2017;468;455;2849;592;1463;26,1708,2324;455,592;415,572,592;1707;995;618;107;26,1710;1534;26;2192;976;592;26,415,1832,1833;786;591,592,1337;359,2435;2797;655,831,1128,1129,3214;479;3109;1603;1103,3455;26,1577;592;1463;26,415,995,1832,1833;300;1463;3758;454,831,997;1463,2334;995;1709;2954,2955;619;1526;1463;1710;592;1463;753;2132;635,3417;1904;1136,3543;3709;1463;995;166,167,168;592;26,2491,2492;592;551;592;995;395;124;1463;363,1209;373;373;373;373;454;417;366,390,592,757;2687;1792;454,1496,1497,1498,705;1540,1562,1563;1463;786;366;-27,-28,-29,-30,-1835;136;1244;1488,1490,1491,1492;1792,1804;26;390,468;29;107;1707;2086;1733;603,2737;2553;515;1655;390,661;1463;1609;1707;26,1534;404;26;2447;390,454,757;1527,1653,1857;1706;26,1086,1855,1856;112,2963,2964,2965,2966,2967;1709;26;1709;1708;1463;592;1710;1265,1655;107;1503,1628;2497,3282,3283;1676;1708;1520,2244,2245,2246;124;1463;430;26;3098;995;995;476,995;1450,1463,1550;780;107;403;831,2078;995;26;851,2517;2588;107;1655;468;930;1672;592;635,1475;1706;112;1411;1534;546;359;403;705;390,1708;667,1040;367;107,1774,1775,2409;1463,1496,2664;1829,1830;1305,1306;1707;961;780;1547;403;1463;592,1190;592,1853;479,592;1247;29,592;542;1792;1405;1936;635,3101;592;785;1463;1463;1960,1961;961;2596;1463;107;1534,3303,3304,3305,3306;1247;1708;995;26,377,1709;1247;1247;546;415,572,592;1247;468,1196;468;1247;1124,2968;1463;592;2083;1247;3508;410;551;107;410,2773;1463;546;1009,1010;1008;506;1463;1463;542;248;1651;995;995;1708;1708,1713;1706;2055;2215;26;2642;2373;29,506,1672,3357;592;434,589;592;2467;2082;592;1707;1488,1490,1491,1492;26,59;574,592,1067;592;1435,1448;1463;2548;107,1209;943,944;592;-27,-639;1795,1803,2420;1733;2701;1463;3532;402;592;390,454,900,901;1672;1248;1463;600;2337;1103;1291;1399;2280,3015;56,57;433,434,435,436,437,438;434;394,1745,1746;394,1745,1746;394,1745,1746;383;432,433,434,435,436,437,438;592;394,1745,1746;394,1745,1746;394,1745,1746;394,1745,1746;394,1745,1746;394,1745,1746;471,472;394,1745,1746;1707;394,1745,1746;382,423,468;394,1745,1746;394,1745,1746;440;592;1463;2078;400;591;410,1463,2992;547,2637,2638;1662;359;440;2337;3299;995;1789;1463;2919;1146;1463;103;415,2277;592;1677;26,27,28,29,1834;29,546;26;603;29,546;3514;592;592;603;26;592;26;592;29,421,455,546,574,1431,1672;26;468;878;26,59;124;1054,1463;390,995,1707,2765;1907;2694;3521,3522;1776,1777;1175;592;1655;2731;26;3514;592;878;2399;1708,2153;1463,1757;112,635,1324;482,711,961,1956;2286;1708,2153;1463;415,572,592;637;366,1706;1217;995,1708;1463;1463;440;1783;1047;2311;2558;1677;1655;366,383,1705;592;1124;2107;995;479;652,2128,2129,2130;983;1655;591;592;1463;1463;627,1507;546;351,1126,1127;390,506,1703;455,503,506,2164;592,1679,3334,3335;1463;705,2301,2881,2882;1792;995;592;1985;454;1348;390,454,1710;1463;1463;377,544;301,302;1115;1655;112,635,1324;26,434,592;3603;3603;1549;2400,3267,3268;995,1534;2009;1534;29,1534,1733;29;26,394,592,1364,1365,1677;691;513,514,515;1672;705;390,1708;1493;592;592,1706;635;515,1733;592;2502;806;1059,1710;26,29;2273;29,1708,2124;1706;26,402;499,955;1572;1707;546,1708;1463,1766;592;1405;592,1324;455;1472,1509,1510,1511,1512,1513,1514;371;1706;1022;363;2464;354;468;479;1527;359;1730,1758;470;995;26,851,1846;592;107,131,1637;2783;1463;592;658,694,1706;390,1706;2694;808;568,995;1463;363;1324;403;592;383;1463;546;592;1730;147,148,3449,3737;124,1324,1677;1789;1463;479,591;26,59;995,1733;415;546;1386;112;26,1708;1655;366;1707;1463;619;1527,2216;592;592;1463;1450,1463,1550;991;1707;1338;479;635,3279;29;1707;995;1534;26;26;1534;592;1733;1534,1733;1706;28;479,603,1707;1725;26,995;335,1709;415,572,592;107,1775,2409;415,572;627,730,799;1707;592;827;410;468,592;1463;1247;2881;1534;1051;1463;26;1439;415,592;627;3725,3726;415;1244;1456;26,1733;232,233;26;1792,1804;1862;480;2364;3142,3143,3144;445,1028;1534,1707;1103;415;1463;1655;1808;565;2682;1247;1727;1247;26,455;591;1463;1463;479;479,592;995;995;995;866;26,1534;592;603;410;592;592;29;2124,2597;1247;1792,1804;1247;1655;2850;720;26,59;1709;415;26,59;1348;1750;2303;3755;390,454,905;580;415,572,592;831,2251,3214;443,592,808,2518;1463;1655;1743;592;1053;1706,1707,1708;1792;1940,3000,3001;935,1206;592;359;26;1043;1463;874;1706;1676;710;3762;26,402;3376;1762;2731;1235;410,1761,2802;630;26;3376;26;1463;1792;423;390,1077;546;546;1534;1097;474,631,1330,1331,1332;629,1722;363,1109;1945;592;1083;2744;2473,2474;390,423,434,1677;394,1745,1746;394,1745,1746;2612;1655;943,944;1677;546;377;1399;1247;394,1745,1746;394,1745,1746;1463;394,1745,1746;394,1745,1746;394,1745,1746;1655;112;2579;3035,3036;390,1708;2875;1706;2694;1655;26,415,1832,1833;1144,1182,2610;390,1077;1463;1463;1709;572;1093;115;2731;3095;1463;468,592;592;592;592;1463;1222;390,1077;26,640;1677;943,944;382,390,592;1669;550,552;390,468;1124,2802;390;592,3573,3574;463;592;468,661;753;390,506,1703,2215;592;390,506,1703,2215;433;2328;592;1311;592;26,402;592;468;592;995;410,454,1022,1463,1493;75;3366,3367,3368,3369;1463;1789;1463;3655;1233;363,1792;1655;1147;592;2530;1352;3135;390;383,1706;26;1706,1707;2731;1710;1972;1402;335;56,57;2461;3181;1463;635;1463;2408;592;1854;1463;479;1155;1804;1463;1402,2717,2718,2813;1463;1655;377,390,592;854,3488,3489,3490,3491,3492,3493,3494;546;26,1534;786;1711;2924;454;3116;1463;808;403;382;1182;1247;1399;1707;995;942;1809;1094;1655;1792;1100;1655;831;592;493;2881;592;1534;3148;2398;1182,1463;786,2751,2752,2753;1997,1998;1463,1603;26;887;885;26,59;3376;3226;1137;592;1310;479;1198;124,3421,3422,3423,3424,3425,3426,3427;3011;1709;592;2340;592;1222;26,592;592;1247;2419;1463;26;551;546;1792;455;454,1380;804,968,1551,1552,1553;1463;402,434,549;1467,1468,1469;390,1708;390,1708;592;619;1463;26,396;468,1222;2124;3252;3765;1247;831,1359,2634,2695;961;26;1792,1804;26,479,1705;2334,2560,2994,2995,2996,2997;503,2164;499,771;26,1707;551;1463;2949;1655;1463;1463;1792;26;455;689;107,410,2664,2665,3388;107,131,359,410,1009,2662,2663,3388;1708,2337;2330;1708,3671;619;26,933,1840;3376;351,1126,1127;1463;26,399;29,1733;1705;1707;366,417,1099,1100,1101,1102,1534;26;26,417,995,1534,1712,1848,1849,1850;579,580,603;1534;1792;1677;1412;402,549,1672;390,1708;410,1548,1763,2355,2387;479;2423,2424,2425,2426;26;359;124;603;1395,1396;828;995,1534;1209;363;1463;1182;546,592,693;3708;1472,1633,2643;1709;1707;1706;801;1009,1010,1011;1352;26,417,1534,1712,1848,1850;1706,1707,1708;1463;1443;1463;1948;1243;804,968,1551,1552,1553;1463;1655;1463;1252;1054,1463;26;2694;592;943,944;468;390,468;706;1133;1867;26;410;970,1454,1455;635,3201;970,1454,1455;546;1463;1463;578;546;1463;26,1534;26,557,1048;107,1774,1775,2409;1031;1708,2153;1706;454,757,1544;103,196,197;26;1463;403;2286;1775;1386;971;812;2358;3633,3634;2825;592;207,208;943,944;995;213,214,215;1851;1124;26,377,423,479;1463;1708,2153;107,2409;366,401,1252;592;592;3723,3724;1756;359;592;390,402;592;592;433,835;2642;572;625;390,415;26,933,1840;512;479;1979;26,383,499,1708,1720;2694;1750;1655;995;85,86;3704;390;56,57;1362;58;403;417;3108;592,2161;1463;592;780;107;26,995,1534;29;941;1707;1707;454,1442;995,1534;1705;363,1776,1777,1778;592;1463;1655;1247;1463;3270;1247;1463;423,1707;1386;1463;1707,2171;603;2328;592;3280,3281;26,3465,3466,3467;1709;1733;1733;2527;995;1488,1490,1491,1492;455,506;1463;592;1463;1463;560,1444,1445;28;417,680,995,1534;2302;1792;1707;390,460,564;2694;995;415,572;872,955;401;1534;1318;592;577;26;855;1450,1463,1550;3420;908;1386;1655;1655,1789,1792,1807,3077;107;580;780;1655;26;636;107;468,592,736;792,961,2654,2655;1648;3700;1672,3248;592;592,1672;592;592;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;2737;512,592;402;26,592;26,3021;1222;479;455;415,572,592;26,434,592;26,402,614;26,402;1401;592;383;2407;1463;1691;463;382,506;1708;2508;512;1463;1463;1603;434;2905;382,1691,1701;26;366,390;1086;724,725;1709;995;26;1709;479,501,1150,1705;546;223,224,2207,2208,2209;995;2454,2455;2455,2468;3257;1709;1707;1709;693,2137;1706;455,1707;995;1572;1708;1708;995;574,2027,2028,2323;995;753;1779;546;1463;638,1595;410;592;112,897;1463;1706;1463;635;26,995;592;26;995;1103,3455;26,112,440,1124;26;26,995;131,1637;26;1572;1463;2731;1655;1655;1247;753;26,995,1848,1850;410,1761;26,417,1534,1848,1850;1324;1463;3094;1532;1463;1463;747;366;943,944;1691;1244;2036;2303;656;2507;506,549,1205;995;403,592;410;26;410;804;635,1534;390,1708;1534,3303,3304,3305,3306;592;1733;29;1706;1534,3303,3304,3305,3306;1534,3303,3304,3305,3306;26;3308;1534;26,27,28,29,1834;1463;592;1463;1534;1665;3170;3771;29;2255,2561;546;1655;1124;359;1548;26,1706;107,112;468;1789;2432;2000;1463;403;1173,2465;3474;995;434;402,592;29,131,592,705,2258,2259,2260,2261;3457;753;1463;1655;419;975;1463;1400;669;1878;371;1655;1792;3006;2635,2636;1655;1438;2511;1776,1777;1540,1562,1563;1706;1463;434;455;455;2100;1463;468,592;26;492;2104;1463;363;1655;1168;3429,3430,3431;1792;1463;995;107,454,831,2720;1463;1463;1463;359;592;1094;995;897;1463;468,661,1698;1124;995;1706;434;592,1182;403;592,1463;2644;2642;1969;3147;1359;2031,2032;1684;1684;1463;1730;995,1730;592;403;592;1325;1672,1995;1446;869,870;867,868;26,434,742,902,2064;867,869;1608;1913,1914;995;1103,3455;1655;1301;1244,1463;1789;1707;29,592;97,98;2830;351;979;1463;3756;2307;1463;1759,3229;2198;1182;569;569,786;569,1100,1497;1463;1463;1463;107,961;1792,1799;1707;2174,2175;1534;1806;995;3223;107;1182,1565;3106;3576,3577;1463;103;26,693,982,1720;3514;390;635;1324;512,595,596,597,598;382,468,1691;2391;2480;1463;652;1463;1463;366,554,1721;390,454,757,984,1214;1687;995;2419;2694;354;410;1116;416;1708;1222;2786;359,1338;1463;1706,2238;390,1708;592;663;1222;1463;592,3537;3539;2642;1124;792,1469,1471,1474,1475,1569;947,1463;3149,3150;1792;586;560,1444,1445;454,1496,1497,1498,705;410,1469,1516,1517,1518,1519;1763,1764;26,1534;401,995,1101,2575;736;801;1792;1324;366;3120;1604;1247;1352;29,546;1708;592;1655;592;127;1784,1785,1786,1787,1827;363;29,592,2451,2452;1463;780;29;592;468,1677;1066;1792;26;1463;639,742;1463;1710;423,770;3553;499;1103;107;831,2442,2443,2444;26,563;1294;2727;26,415,1534,1832,1833;2061;1534;1716;592;1540,1562,1563;1463;26,995;26,1353,1354;3114;1463;26,831,1324,1534;1463;1009,1010;546;1534,1584;28,780,1534;410,1761;1252;1463;26,857;769;1103,3455;1655;1792,1804;26;395;390,1708;410,1288;1463;1792;1002;1534;1708;26;995;26;635,1851;603;1463;1247;1583;454,693;753;1463;1463;2460;469;1655;592;1463;1694;434;1463;373,376;454,1496,1497,1498,705;1240;1655;1464;479,624;1655;1256,1257;635,1463;26;440;1136,3543;1463;1708;26,603;592;415;26,383,565,1627;2694;551;26,2526,2527,3091,3092;1713;1809;1708;26;592;1534;1463;1463;410,2148,2441;2382,2383;440;1463;1222;417,1497;1124;26;995;1912;1463;1463;1355;1399;240,243;1792;2679;2731;1463;2438,2439;2936,2937;1677;1463;1463;390,1708;3540;1386,2282;421,592,1100;503,2164,2484;592;592,3204;2344;468;592;434;417,1103;107,1672;995;1534;1103;943,944;943,944;1578,1579,1580;546;26;26,393,433,1191,1192;1655;440;1655;2080;1534,2080;1227,1228;588,831,1244,2107,2758,2759,2760;362,1152;760;2722;1829,1830;1829,1830;390,1708;1450,1550,1633;827;995;930;592;468,592;26;1463;962;1655;1208;551;1100;26,468;107,1761;546;1655;592;1463;832;507;897;107;1596;1247;26,479,547;1707;1707;1247;26;371,1792;1348;1733;1463;1247;479;377,383,415,474,698,699,1672;652;592;592;203;627;2166;3692;1242,1792;1076;1247;649,650,651;1247;468;3232;454;1034;995,1708;1655;592;1708,2378;1706;1710;1713;592;363;1222;390;1463;2642;592;3691;3607;26,2706;3065;29,2838;943,944;515,546;592;1696;1463;383,1708;3271;1655;995,1838,1839;1839;410,1321;1707;1463;1463;1650;390,1708;415,515,1423;995;26;1463;592;1708;592;592;26,1537,1538;592;625;107,1774,1775,2409;753;592;753;646;748;995,1733;1095,1838,1839;2042;607;1372;209,210,211;403;782;742;995;753;737,738,739,1730;3346;1709;1463;1655;1399;26,1232;1232;394,1745,1746;394,1745,1746;572;394,1745,1746;394,1745,1746;394,1745,1746;394,1745,1746;432,433,434,435,436,437,438;394,1745,1746;3581;943,944;1463;2831;371,1792;1464;26,1709;410,2999;690;2557;995,1534;1152,1419;786,787;295;1593,2628;86,3612,3613,3614;2465;391,831;1463;1463;995,1463;627;656;1100;454,757;943,944;592;635;26,1368,1736;592;592,919;603;592;592,2156;592,1742;592;28;603;1677;1100;2905;632;434;434;1435;359;506;1463;1054,1463;2009;1451,1452,1453;1798;1707;474;1829,1830;434;560,1444,1445;1749;351;2694;3550;1463;2116;1463;1463;1324;1463;112;638;26,557;1124,2377;1767;1792,1804;1463;455,546;971;656;1463;26;468;592;1463;2286;1248;1463;808;1463;1463;956,1184;1247;1706;1463;546;1463;1463;2151;1222;1463;780;974;1463;3174;2363;1399;1399;546;1655;423,433;1295;592;3701;1719;1534;1708;995;454;454;454;1463;874,917;3432;2063;1072;1368,1369,1735,1736;1324;107,1572;2317;635;938;1534;26,434;395;2931;1577;1792;454;627;955;26;1212;1247;1247;1416;3121;1463;1707;955,2489;592;468;468;2842;1193;15,324,325,326,327,328,329;1950;1397;383;1182;1709;1100;434,549;26;592;107,1775,2409;592;592;1655;402,592,2177;2567;1763,1764;592;26,660;594,1164;546;1242;546;3583;390,1708;26,468,482,483;1463;1463;546,635;546;1472,1474;1876;3645,3677;1463,1761;1655;107;1463;1655;3265;26,1847;26;26;1022;378,379,380;705;3744;874;1120;694;1220;107;630;780;1656;1655;1540,1562,1563;2935;1655;1655;1792;410;26,107;403,1706;1534,3303,3304,3305,3306;1009,1010,1011;1463,1534;995;995;2101;26,383,1191,2338,2339;1959;26,2505;26,2505;112,26;26;26;26;3010;430,995;2404;391;1707;1057;592;943,944;1380;1248;808;1399;1030;124;434;592;1655;1463;1707;1463;1655,1808;1655;1655;1577;1707;371;390;794,1655;635,1685,3292,3293;131,388,1655;1463;1706,2181,2543;1707;390,1708;995,1707;943,944;1706;995,1707;2327;377;395,417,995;592;1463;786;635;995;390,1708;1655;591;1792;1706,1707,1708;995;1124;1792;1463;1792;1431;1120;560,1444,1445;26,29,1534;2951;1463;592;1709;468;1404;468;2256;29;811;271;2419;831,1706;3531;1738,1739,1740,1741;2694;1792;359,1338;2978;995;2080;152;1655;185;2481;1472;335;2026;1124;635,1874;2927;401,995,1730;1463;3594;26,515,546,1733,2658;2658;1463;1749;29,515,546,1463;26,417,995,1720,1848,1850;1463;1708;786;1655;783;2009;1792;1706;29;1707;1534;592;1222;463;468;1247;29;1463;1463;1247;1054,1463;546;118,119;1534;1967;755;770,1955;1339,1340;1789;3420;1705;1655;26;1706;1463;592;1792;1792;1247;1247;786;1399;377,921;2017;26,921;1707;29,515,546;546,831,1681,2672,2673;1463;1463;1399;100;3646;546;390,1708;26;1769;1655;2278;2583;455;630,768;28;630;1706;1711;26,395;1711;1706;3732;455;1355;656;383;394,1745,1746;433;3592;1572;26,902,1711;366,383,730,806,807;394,1745,1746;394,1745,1746;394,1745,1746;394,1745,1746;359;1905;2887;2275;26;26;1140,1141;440;107,2409;1463;1950;895;1708;29;592;592,648;1672;1677;592;592;390;434;506,592;390,506,1703;1672;592;592;592;390,506,1703;1222;512;390;468;2215;390,506,1703;753;433,1696,1697;455,506,562;415,572,592;753;468;26,377;26,377;1222;29,635;434;415,572,592;1463;654;592;26,410,761;1789;1709;1534;1534;1655;1851;2645;731;532;1463;382;1463;1108;2918;1003;455,592;26;934;70,71,72,73,74;592;1467,1468,1469;1100;1994;468;1463;1463;3374,3375;1709;382;353,2881;1655;515;943,944;1534,2165,3297;1711;2009;3433;695;656;1792,1804;382;1463;2905;26,575,576,1709;1463;2509;778;479;1463;26,682,995;1095,1838,1839;592;1792,1804;1463;112;2986;455,2392;26,468;29,1534,3300,3460;592;2586,3173;831;124;2969;592;158;390,1708;454,1523;592;592;468;29;26;592;1711;468;3111;468;603;112;398,402,549;240,241,242,243;440;1081;1706;1463;546;454;410,1761;1706;1709;1463,2401,2402;3183,3184;2898;1463;454;2231,2232,2233;410;592;26;390,1708;1463;1713;410;3511;107;546;1463;786;1463;479;1708;1244;1792;256;26;26;592;704;3608;2419;1229;3115;1708;455;455;1338;635;401;417;1789;786,1499;351,1126,1127;26,1708;2086;1709;1463;2896;366;1463;1463;592;26,399;592;627;430,1534,3434,3435;995;705,804,1534;995;1919,1920;29;415,572,592;26,423,1707;1534;430;26,28,976,995,2757;1338;434;150;401;366,698,751,752;803;1463;995;943,944;479;1709;410,761,798;592;2629,2630;831;1463;1463;468;592;1314;3314;29,546;1979;1707;1708;1463;26,417,995,1848,1850;1463;578,685,1054,1539,1540;1101;1463;1253;107;363;1709;107,410;1248;1463;592;1463;2878;2548;915;2749;3235;1399;2004;1871;1247;26;1410,1792;671,672,1707,1708;1345;1792;1784,1785,1786,1787,1827;335;107,2409;107,2409;1607;363;1809;2563;454;592;1792;1655;250;801;1534;26;1367;382,592,1118;1438;592;3153,3154,3155,3156,3157,3158,3159,3160,3161;635,3215,3218;423;1655;415,770,771;86,968,1491,1638,1639,1640,1641,1642,1643;635;578;753;1124;1370;26,933,1840;685,1540,1562,1563;3440;546;1670;1792;1419;1247;1247;831;1792;1463;753;26;1051,2924;977;1707;1733;1463;1683;625;1419;995;592;1534;1198;26;2370;1463;1399;1247;1247;592;391;3033,3034;1655;1655;1496,1723;454,705,1496,1585;26;1707;592;1247;1247;1359;29,1463;2257;592;2276;635,1249;434;26,995,1368,1736;204;995;1534,1733;1708;1717;654;1247;943,944;26,434;29;1103,3455;591;107;722;592;1463;1463;1711;974;2736;1463;1463;359;359;592,1707;390,1708;2195;503,872,955,2928;635,1671;995;26,366,417,501,502,1534,1677,1733;390,1708;2772;1534;1809;26;735;26;592;1954;2991;468;1235;1463;2120;2624;1247;1655;1706;1730;1792;3024,3026;423,831,1707;26;1103;288,1775;1463;335;1655;1247;3370,3371,3372,3373;2666;662;1822;29,1672;592;592,1100;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;3033,3034;617;943,944;995;26,366,383,730;995;592;824,1191;421;390,416,980,1182,1183;26;592;29;943,944;26,402;943,944;382;1534,2605;1655;26;1241;1463;1368,1369;995;26;26,1709;1170;943,944;1463;382,506,592,1691;26,592;1709;1707;3501,3502;1463;995;391;775,776;3312;1606;434;1534;1708;2454,2455;2455,2468;635,2350;1706;1733;1708;26;1707;693;682,995,1717;1463;26;455,1691;26,995,2311,2315,2316;1247;1709;1358;1709;1463;1463;2318;1706;468;638;468;468;1301;1463;26,454,757;1534;753;753;831;592;1103,3455;957;1691;1463;592;1706;1707;831;1792;415;2249,2250;1292;433,624,2642;786;592;551,592,955;1677;479,730;1399;1235;3706,3707;911;1463;1942,2007;1534,3303,3304,3305,3306;107;1709;423;335,1648,3405;1708;1705;3385;415;1463;635,1541,1542,1543;1706,1707,1708;897;2251;592;2447;1763,1764;600;403;1463;410,1469,1516,1517,1518,1519;710;455;943,944;1707;107,410,2379,2380;1463;592;1792;1247;2731;1226;86;591;1463;1792,1804;831,1054,1463,1522;107;1706;929;592;1463;1463;382,548,592;1463;1463;943,944;592;75,3138;402;1463;354;1248;667;410,1469,1516,1517,1518,1519;1463;1655;410,2386;391;1144,1410,1463,1465,1472,2587;786,1499;1463;592,2139;592;1648;1692;1226;1655;592;592;366;434;1036,1698,3403;482,1066;1463;1463;1103,3455;2642;943,944;1463;1463;2403;802,1469,1471,1475;107,410,2570;3376;1792;1792;592;402,434;1534,3093;1534,3093;1534,3093;1534,3093;1534,3093;1534,3093;2419;132;962;1792;742;851;456;433;107,108;359;1054;1399;639;592,955;2781,2782;1399;1463;1463;1463;1463;1727;28,569,1463,3022;1399;2972;395,592,631,2176;3223;26,479;1463,2334;1709;792,2730;26,990;1708;474;-27,-28,-29,-30,-1535,-1835,-1852;26,983,1720;382;1463;1463;1776,1777;3396,3397;592;499;3376;786;1655;26;826,2537;3112;1106;26;693;3231;682,1103,3455;3190;739;1463;1534;1103,3455;1792;390,2411,2412;2764;1706;1374;1463;2775;1100;1463;112;26,872,873;2553;592;1544;801;713;1083;3127;2419;26;601,2652,2653;3166;801;2604;2604;1534;1534;1664;423,1090;1936;565;3752;603;656;1655;410;995;592;2698,2699;1463;1792,1804;685,3439;1205;783;753;753;403;2419;744,1706;1463;26,578;403;1763,1764;956;1706;1463;1792;403;1247;1655;1709;2050;1472;3543;831;390;395;499;1792;852;2165;682,995,1720,2165;968,1491,2814,2815,2816,2817,2818,2819,2820;26,933,1840;1247;1463;26,1537,1538;783;592;3710;2078;546;480;363;3172;780;395;395,682;1463;1182;403;2939;943,944;26,2500;1319,1320,1706;592;995;1463;112;1707;1708;351,1126,1127;2033;831;415,572,592;995;3553;592;1252;1247;468,592;1655;1463;1463;26;3298;1122;1573;635;1706;592,1708;26;1054,1463,1520;1022,1763,1764,1765;2123;1655;592,2139;592;1463;1171;1451,1452,1453;1463;417,995,1534;26,454,592,780,1284;995;1463;1463;1450,1550,1633;1655;434;672,995,1100;731;592;753;1124;831,3214;1463,2894;1677;2109;390,1708;2475;1463;781;2942;2890;468;56,57;592;482,943,944;639,2848;656;335;1463;468,1695;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;816;816;783;635;506,592;592,685,2992,3471;592;783;2204;479,1309,1534;76,3274,3275;1399;1463;107,1500,2541;2694;26,417,1708,1848,1850;91,3674,3675,3676;831;1463;410,1469,1516,1517,1518,1519;2700;1103,3455;1247;635,1584;1247;1247;770;1710;1809;3481;26,693;1244;2286;1247;1247;390,1708;1247;455;1247;455;1247;786;468;383,415,698;474;2970;389;877;1574,1575,1576;1463;434;1655;1435,1448;1706;1463;786;546;2694;468;1463;1655;850;1463;1706;1708;2625;26;753;888;1438;592;592;2838;546,592;592;592;592;592;506;434,592,1852,2133;592;592;506,592,2490;351,1126,1127;440,1431;1707;1534,1708,3303,3304,3305,3306;592,1705,1708,1717;26,2437;753;592;995;879;1464;2942;2214;592;3319;1463;421;1463;638,1597;1706;410,1419,1603,2504;410;112;403;592;927,1232;394,1745,1746;394,1745,1746;394,1745,1746;394,1745,1746;107;568,569;1599;1789,1793;26;1463;1463;752;3543;2329;783;1222;635,2641;26,1534;546;2280;669,995,1463,1673;1463;1247;1253;2017;1463;1463;592;391;503,740,1033,2055,2056;26,933,1840;1244;592;26;592;546;506,592;592;26,2823,2824;1706,1707,1708;736,950,980;479;417,1534;410,546,995,1500,1534,1563,3052,3053,3054,3055;474;1419;592;468;26;515;468;546;1103;26;572;403;434;1463;1463;995,3117;1708,2153;454,1348,1472;1655;391;546;1419,2148;1463;780;26;29;1335;1310;1463,1687;1792;1463;656;1136,3543;532;107;1399;26,27,28,29;1124;1792;592;107;1463;455;351,1126,1127;592;1655;423,433;423,433;423,433;423,433;423,433;423,433;1301;103;1254;26,377,391,423,501,819;403;1439;112;652,1182;434;303,304;635;1706;2069;26,1249,1679,1733,2923;2415;1655;1655;852,1158;433;2409;1463;75,1812,1813,1814,1815,1816,1817,1818,1819,1820,1821,3050,3051;1655;1749;1706;546;1707;546;546;995;26,546;1708;635;1730,1731;592;1414;545;1655;1463;26;1054,1469,1633;1123;417;658;390,1708;658;1655;366,1672;1655;1655;1463;1399;2251;390,506,1703,2215;1854;107,1949;1463;2721;351,1126,1127;658;592;1463;1710;831;1399;831,1054,1463,1522;1497;351;415;943,944;2694;1733;355,356;1706,1707,1708,1709;1798;2635,2636;1789,1792;3514;390,1708;26,1534;26,107,989,2846;995;1652;1734;635,1534,2038;572,770;998;353;1463;1792,1804;1463;366;592;1808;1463;2888;107;592,1190,2281;434;2121;434,2162;454;1463;1706;546;2705;1338;1247;27,1095,1708,1835;1705;1636;1463;2787;2091;994;1655;1463;2540;592;1463;3272;1792,1804;1152;1463;1463;26;404,533;1247;1463;26;26;3552;1399;1463;26,546,1897;137;479;1338;402,549;1231;714;359;935,1419;410,1761;468;801;3701;2689;1707;3453;3087;1534;592;1301;1463;804;363;403;468;433,558,559,560;801;1247;1940,3000,3001;1463;1749;592;656;1463;26,402;26,382,468,482,499;1463;546,3541;454;1463;1784,1785,1786,1787,1827;1463;635,2998;2878;549;1707;3579;26,1331;1707;465,480,592;465,480;592;3584;1784,1785,1786,1787,1827;1463;2406;874;1463,1956;394,1745,1746;1792,1805;394,1745,1746;26,433;121,2040;3131;1792;1707;1247;1247;1247;1463;1139;534,535;440;961;26,1715;27,1095,1708,1835,1838,1839;1267;26;1838,1839;26;27,1095,1835,1836,1837,1838,1839;499;1884;1338;2921,2922;661;880;592;1222;943,944;433,465,467,468;656,1765;2340;3480;434;1182,1463;592,872;546,831,2672;390,506,1703;433;390,506,1703;390,506,1703;433,1696,1697;592;592;390,433,592;390,506,1703;592;390,506,1703,2215;26,592;592;510;592;415;468;2134;943,944;1463;1463;1534;1103;1463;107,2417;1463;783;1463;26,1851;3374;1463;276,277;202;516,517,518,519,520;516,517,518,519,520;479;1707;1707;592;1706;1244,1463;831,1054,1463,1522;402,434,549;363;2905;995,1463;1792,1804;1348;1435;831;410,1419;468;382,433,496,497,498,499;3246,3247;943,944;1792;801;592;854,3494;1463;592;592;499;1399;1792;2985;623;1655;1534;1709;1463;1399;2086;26;2566;1247;2639;1792;592;1247;2263;1463;2223;3123;26,29;29,580,3300;1706,1707,1708,1709;783;2784;592;2847;28,546,635,1534,3498;1386;780;783;801;107,1761;1809;994,1705;26,479;1463;26;1463;2798;107,1775,2409;1463;410;789;1792,1804;669;26;1463;592;783;995;995;995;359,2694;592;1706,1707,1708;592,1711;26;1852;872,955;2121;415;753;592;592;26,592,1677,2766,2767;592;549,1205;434,549;479;801;3285,3763;1763,1764;1534;756;503,1083;1463;2598;410;26,2160;1312;112,829;26,415,454,500,1410,1707;390;1682;1247;635,1921;783;1792;592,652;1558;1247;1749;1808;1792,2709,2710;1463;546;26;1247;383;2613,2614,2615,2616,2617;1324;1355,3560;2178;2689;362;1655;499;29;173;831;401,2529;417,995;592;1463;1463;273,274,275;2415,2623;2987;28,1750;28;1463;3639,3640;592;26;593,594,1709;635;3504;1534;29,580,1534,3300;1792,1804;1762;2158;366,698,751,752;434;1534,3303,3304,3305,3306;1463;26;26;995;1463;2366;1968;652;1463;1534;995,1534;1534;1707;1124;3530;1655;1352;1324;2776;1463;1463;474,1707;490;2381;1707;1009,1010,1011;1969;1463;831;29;943,944;753;943,944;3007;1338;2708;995;802;2301;1163;2191;1809;371;351,1126,1127;592;1534,1733;1534;474,584;1709;573,730,950;503,504;107,2409;1463;103;2190;2788;1707;1463;26;455,592,2674;1763,1764;1996;995;131,359,369,831,1009,2662,2663;592;1399;395;1792;995;359,1720,2589;476,995,1534;804,968,1551,1552,1553;417,1534;1463;1792;592;1792;1548;592;1503,1629;1222;1784,1785,1786,1787,1827;1792;1463;801;1399;844;1472;1655;592;2647;753;1463;26,29,933,1840;1707;3470;6,15,324,325,326,327,329;1265,1655;801;1706;1247;1463;1247;112;1463;3046,3047;956,2005,2083,2167;390,980;1247;1247;1247;1247;1463,1708;1939;1435,3249;637;1973;1116;390,455;1792;1247;1247;635,988,3221;1247;1094;26;995,2640;1707;26,1493;1534;377;515,546,780;394,1745,1746;1534;683,2036;1769;131,1472;723,729;26;1463;26,1368;3213;603;995;3764;592;995,1707;26;1463;1463;1463;971;3140;592;468;1100;592;1707;26,366,501,502;624,1249,1733;995,1707;26,468,482,1067;592,995;693;888;551;551,888;1708;1655;107,1459,1978;592;351,1655;1051;228,229;1463;1707;1792,1804;3415;1247;1706;1792;1463;366;1247;1247;592;410,1419;1707;440;26,546,831,1497;592;592;1338;1247;26;3370,3371,3372,3373;3727;3697,3698;3189;2897;26,29,1672;455;2125;1343,1603;1677;3033,3034;955;3033,3034;1278;546,592,614;402;26,434,592;26;753;402;506;753;724,727;1672;592;614,2124;943,944;546;1463;2694;685,3439;410;592;463;26;591,656;1463;468;1463;434,641;2503;107;2215;424,3124,3125;724,727;1534;479,995;26,995,1707;501;1691;468;592;1691;995;995;592;1022;635;592,1677;786,1499;1463;403;1439;786,1463,1526;1416;995;2496;1861;1463;1463;995;592;26;1534;831;592;1100,2075;1792,1804;592;1463;351;390,1708;390,1708;2694;1707;1463,2130;410;1248;943,944;995;943,944;682,995;592;676;831,961;2809,2810;1763,1764;1300,1753;107,415,592;2690;891;3145;546;1707;1463;1463;1463;1463;124,2569;351;1655;1463;1463;1463;652;630;3376;479;402,434,468,549;390,434,468,592;351;2845;1247;1222;1060;468;1709;1324;351;546,1463,1572;1706,1707,1708;1463;3738;1100,2057;592;390;592;455;1888;831,1054,1463,1522;1247;403;1247;592;402,503,2164;351,1126,1127;656;177,178,179;591;512,592;592;1182;2299;753;1463;354;1792,1804;390,455;390,455;390,455;29,635;501,1716;638;592;382;1463;1733;1534,1730;1463;1083,1356,1357;1463;1399;1655;309,310;417;366,1219;410;2446;1679;445,588;922,1503,1578,1610,1630,1631;1792;26,434,868,870;26,867,868,869;872,2054;1463;3086;351;1399;417;1469,1471,1472;3503;592;897;1463;1463;1205;2830;2086;410,1419,2247,2248;3223;175;1042;1463,1545;1603;410,1761;1463;1534,1733;1463;1463;1463;371,374;705;592;1463;1012,1013;1655,1792;778;2457;1222;2060;1285;1463;1463;1463;831,1054,1463,1522;1165,1166;1463;2916;1463;1792,1804;382;592;335;454,1284;95,96,363;499;635,780,831,1687,1809,1888,1892,1893;363;468;801;1773;800,801;371;1792,1804;736;3566;147,148;147,148,3737;151;1792,1804;3008;1247;1247;1463;1348;1209;700,701,702;1705;1463;572;1463;2217;1463;1463;804,968,1551,1552,1553;656;1713;592;2093,2094,2095;1463;592;1463;3699;2419;26;795;1655;410,1469,1516,1517,1518,1519;1100;1124;1540,1562,1563;1463;1247;3437;1534;2009;837;26;2447;2830;26;2538;718;26;1463;1792;335;656;1244;373;3543;3642;1708;1534;26,3678;417,1730;417;1463,1754;968,1491,2814,2815,2816,2817,2818;417,1534;1572;1463;1463;1463;1144,1469,1568,1569,1570,1571;1463;1854,2724;995;592,2161;417;395;1999;1463;655;995;86;1182;3075,3076;1350;592;592;783;2009;1626;1611;1600;3647;26,1534;26;1709;26,443,808,2035;26;1534;1463;26,1493;26,1577;1438;1463,1493;1792;1463;3709;1655;1124;995;1792;1792;995;1463;1534,3303,3304,3305,3306;253;1792,1804;592;1792;995,1101;1463;454,993;440,769;2177;366;1762;2694;1749;1463;26,402;592;1956,2334;1443;26,2719;1022,2051;1534;1103,3455;2419;753;455;2079;26,29;1463;2731;918;279,1829,1830;1655;1829,1830;1829,1830;1655;377;1405;1386;1655;592;1419;592;403,433,857;26;1789;218,222;1655;410,1761;1247;2694;1655;3129;1655;1502;753;1677;107,2409;592;628;454;1247;1247;753;335,1672;430;1247;1463;943,944;634;1247;1247;1247;753;943,944;3514;753;753;164,165;1463;1463;2002;1463;1463;1655;1324;1792,1804;1222;627;592;1655;943,944;1633;753;506;592;1707;1463;460,3719;1655;1182,1572;955;592;26,28,29,592,1672,1733;468,592;2598;2891;479,1612,2053,2054;335;455,2038,2039;2121;592;592;2608;26,1316,2743,3062,3063,3064,3065;592,2092;480;592;592;391;753;335;1247;410;1534;2011;1463;410;808;924;970,1454,1455;442,506,791,792,793;592;402,434,549;943,944;753;2148;335;1655;978;2058;592;107,1463;1463;3260;974;3260;2631;995,1095,1838,1839;394,1745,1746;546;2717;1463;1655;131,1637;463;26;107;1809;107;468;410,1761;468;1708;515,546;943,944;753;2731;592;3514;3514;592;592;592;468;2105;1792,1804;783;1463;1463;26,27;3235;28;1706,1707,1708;2956,2957,2958;783;1707;1463;2263;943,944;619;1177;3609,3610;3118;1469,3012;2009;546;603;935;1463,1755;26,1873;2731;26,86,1496,1590,1591,1592;1655;2286;1706,1707,1708;1655;1182;1706,1708;1705;359;410;531;1792;1463;3486;1463;393,1463;592;1136,3543;1745;1463;1655;2538;454;454,757;1348,2049;454;26,1534;1438;551,627,1457,1458,1459,1460,1461,1462;1463;3572;1792;401,417,1709;995;1706,1707,1708;107;363;1399;1792,1804;1706;2402;1534;468,592,943;29,1463;1463;1463;26,27,28,29;26,1249,1679,2923;1463;1463;801;265,266,1068,1069;792;2533;2466;1707;29;592;546;592;592;1855;592;134;1463;827;1463;591;2081;1463;107;107;75;592;26,1410,2254;26,592;1009,1010,1011;1182,1463,1534;1182,1463;410;995;1182;26,1715;995;26,1534;366,1672;366,1672;366,1672;474;1784,1785,1786,1787,1827;1784,1785,1786,1787,1827;1792,1804,1975;1247;801;1399;1655;351,1126,1127;2025;656;2694;107;546;403;2694;753;1368,1737;3176;592;592;503,504,614,1190;26,1733,1839;377,3451;26;994;1733;377,423,1706;1708;394,2115;1709;995;1707;926,927,928;1182,1463;1648;1463;1247;28,29,1730;1710;1182,1463;1655;3742;390,468;592;1082;434,549;366,592,1534;592;415;995;2213;434,549,1205;592;1103,3455;26;592;1326;2266;1100;382,592;1534;1792;1792;1809;1229;363;1463;3376;1792,1804;753;995;592;107;2516;26,902;1092,1655;1463;1463;26;26,454,1706,2585;1463;404,506,3551;29;1463;1648;515,546,1463;402,592;1463;359;2215;592;1706;335;1463;1534,3554,3555;1100;1855,3526;1655;1393;2263;1097;2418;592;1463;1463;112,515,546,592,1709;1348,1472,3664;1182;2925;1247;619;451;1399;2538;26,546;2538;354;1648,1649;417;1496,1728,1760;1463;26,442,444;366,668;56;1707;1431;578;1686;1792;592;1324;1399;103;1463;592;1559,1560,1561;3225;434;394,1745,1746;3164;353;351,1126,1127;546;506,592;394,1745,1746;394,1745,1746;366;1222;2579,2580,2581,2582;26;1022;107,2409;1387,1388,1705;1792;546,831,2672;390,506,1703;753;1028;2121;468,592;430,1103,3313;592,1463;592;592;390,506,1703;506,1702,2215;390,506,1703;592;592;1100,1548;1433,1434,1435,1436;515;1419,2267,2560;28,423,995,1706;1463;917;506,592;902;592;753;1103,3455;1707;1809;1463;2120;2131;2131;2131;1463;1577;592;410,1301;1399;1463;1469,1471,1474,1475;1463;1763,1764;479;1007;1655;410,1761;1390;1789;3096;943,944;1792,1804;1463;1288;576,1709;1655;1463;1313;2465;3166;29;1655;1635;1463;1808;1399;1100,2047;1763,1764,1765,3430;410;1463;454,1231,1480,1481;1393;1857;592;590;1124,1706;592;1707;2574;1733;1792;1463;2402;753;592,2806;943,944;592;2295;335;943,944;592;592;1343,2667,2668;1344;1463;1707;2083;546;592,1763,1764;2812;1463;635;2954,2955;1463;1707,1708;1710;647;28;591;474;390,1708;1463;1792,1804;592;455,503,504,505;267;366;910;60,61,62;1247;1247;26,366,956;1992;1182;1222;1399;685,1534,2992;474,1792,2395;2421,2422;1463;3200;1708;1463;682;430;815;1789;2611;1706;335;1463;1463;294;2428;26,417,995,1848,1850;1338;761,1463,2355;1534;363,364,365,1655;3667;1463;1463;1463;1136,3543;26;1965;1708;2849;1100;890;943,944;736,1655;1463;1463;26,417,995,1848,1850;26,417,995,1848,1850;656,1463;1656;1463;107,1463,1563,2703,2910,2911,2912,2913;2052;1416;1463;1463;1463;1463;1463;454,831;1463;402;943,944;592;468;592;109,110;112,1534;1463;1463;693,1706;430,995,1730;401,1706,1707,1708,1709,1730;3419;1247;3264;153,154;1463;351;2550;546,592;1463;75;1463;1792;1792,1804;1463;635;1792;801;366,1099,1100,1101,1103;2086;107;611;592,2138;112,1792;1706;26;1655;1400,2197;3245;1589;448;161;780;298;1463;359;1463;1851;592,2124;592;410;652,1463;403;1798;403;796;2879;1463;26,693,2500;1431;124;386,387,1655;1463;1399;1399;2804;2150;592;592;2855;1463,1763,1764;26,933,1840;1463;635;124;1534;26;29,3649;592,2161;26,1534;1247;1792;1708;779;112,1398;1247;335;2447;2450;1792;251,252;705,831;26;26;1399;3223;1792;831;1399;1463;1709;26;1463;592;26,417;29,635,922,1621,1624;3030;933;592;1172;26,442;434,468;943,944;459;3099;1534;26,402;29,592;1706;26,592;26,402;1534;1706;366;26,402;1488,1490,1491,1492;410;592;410,1761;1655;953;1463,2795,2796,2797;1463;468;1655;1463;1463;1463;454,1284;1792;1792;359,786;1655;3695;1463;359;1103,3455;468;943,944;883;1758;1463;26;0,1,2,3,4,5,7,8,9,10,11,12,13,14,15,16,324,325,326,327,329;753;75;565;1348;592;1679;107;943,944;592;572;26,402;943,944;753;753;753;1706;1792,1804;1463;1710;656;560,1444,1445;1707;371;506,592;1463;382;2014;421,503,504;15,324,325,326,327,328,329;804,968,1551,1552,1553;1707;1463;2086;592;26,1709;3525;2263;995;468;1691;592,3408;29;26;1324;382;1428;1463;1709;287;1655;382,1691;980,994;831;26,417,1712,1848;26,417,1712,1848;592;592;1463;753;1463;1655;1706,1707,1708;1864;1864;1463,2657,3016,3017;572,1160;2342;2202;1463;1463;335;26;943,944;1405,1416,1463,2755,2756;1463;440;656;651,857,1705;943,944;1463;26;995;1247;107;1922;1463;831,1423;1399;1463;1222;640;124;1908;1784,1785,1786,1787,1827;1463;1247;1019;951;2453;1399;1463;138;1655;995;107,2409;1463;468;1182;1792;1247;1463;656;1463;943,944;592;26,454;390;592;26;592,872;592;3668;1808;1855,3526;220,221;1792,1804;882;26;1792,1804;780;753;1771;1463;390,1236,1237;232,233;1301;1792;1655;1706;592;1463;592;515;800,801;546,872;1798;382;614,1190;1977;382;3376;1792,1804;1463;1247;831;1534,3093;1534,3093;1034;867,868,869,870;155,290;1209;740;1792,1804;26,459;1463;1707;359;592;417;390,454,1498,1706;2609;2985;1463;3376;1463;359;592;1463;1633;1655;1708;995,1534;1707;394,479;1247;1231,1463;468;1463;2335;1463;1463;592;455;592;786,1463;26;366;1103,3455;1103;1103,3455;2834;2993;410,1469,1516,1517,1518,1519;831;112;359;1531,1532;1244;1708;107;417,1103;1463;26,404;506,592;359;1655;3706,3707;1534,3303,3304,3305,3306;1463;1100;1247;26;390;1222;1534,1733;26,1534;546;3376;1136,3543;468;786;335;1789;1212;2731,2732,2733;635,1463,1603;371;1708;1463;390,1708;1292,1403;1463;619;107,1775,2409;912;29,1463,2334;2588;351,1126,1127;801;753;1534;205,206;2463;1655;1463;1304;1707;1182;29,1249,3416;430;968,1491,2814,2815,2816,2817,2818;390,1708;1463;592;351;3438;592;2547,2548,2549;363;783;506,592;592;1534;1182,1463;26,548,592;107,790;454,1571,2482;549;546;1792;1376;1463;455;1588;2694;2238,2239;995;1583;943,944;697;1054,1463;1463;1789;1792;1463;557;1534;1463;454;682,1103;359;670;1463;455;592;1709;1343;753;390,1708;2127;1463;1463;546;26,402;1463;1655;1463;26;359;1463;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1950;2447;1022;1463;506;1655;403;1338;1792,1804;995;1463;1463;1655;1707;351,1126,1127;2013;1463;359;592;1463;1534;1792,1804;1792;1463;2094,2095;26,1601;1247;410,1469,1516,1517,1518,1519;1247;1463;1247;1247;943,944;1247;753;1463;351,1126,1127;1808;410,1761;766;1982;1235;2215;1463;384;1792;753;592;1324,1325;831;468;26,1537,1538;1792;1655;1792;26,2149;831,1634;1988,1989;1989;687;928;943,944;753;855;592;1792,1804;296;1054;1054,1563;1463;1706;1440,1441;1232;2646;1463;1792;1497;1463;3718;391;1792;1525,1526;1534,3303,3304,3305,3306;651;1706;592;382;592;592;592;1792,1804;808;1103,3455;351,1126,1127;1419;377;1707;1534;1463;359;26;3751;1463;1463;592;2545;1310;1247;1247;2880;995;1792,1804;1463;897,1100,2012;1463;499,831;592,1097,2374;2073,2384;1463;1733;1623;986,987;1247;592;366;1792;515;112;351;1530;753;1733;1655;1463;1655;560,1444,1445;1463;-2932;3586;1463;1792;403;1655;546;1463;351;935;705;592;627;592;1709;26,27;26;831;1003;1463;592;363,1792;1798;56,57;592;1706;753;366,1672;1463;131;1124;943,944;592;592;1463;2148;1463;1247;995;26;26;1534;1534;1463;26;995;454,757,1544;2576;1247;1463;1655;1463;231;1730;995;230;2155;430,995;371;410,1761;3004;753;1572;1792;417;1247;1463;753;753;26,402;995;943,944;1424;1406;403;1463;2009;2608;2419;363;1655;1463;26;29;1655;656;627;468,592;592;359;780;1472;458;468;1463;415,592;592;592;549,592;572;3773,3774,3775,3776;479;995;1151;1463;1247;1534,3303,3304,3305,3306;371;26;1463;903;2770;1463;1463;656;1083;1463;1792,1804;1463;410;592;1792;2885;26;808;2921,2922;29,1249,3416;2108;402,434,549;468;592;1463;75;26;468;1198,1204;753;548,1699;592;592;390;445;753;592;592;468;390,824;433,468,592;753;1672;935;1155;2148;1103,3455;656;1762,2434;1463;410,1761;363,1792;2694;1655;1247;2065;1829,1830;92;3450;27;2694;783,1935;943,944;1463;762;1792,1804;107;995,1584;1463;1463;1463;410,2150;783;1534;1463;1463;1792;3409;390;1463;1463;656;3230;468,592;431;1463;26;351,1126,1127;75;1463;2312,2313,2314;3705;489;1207;1386;468;1655;1138;592;943,944;1222;2122;753;943,944;753;943,944;1222;592;567;549;943,944;28;107;592;592;26;26;1463;995;592;995;390;1707;454,757;1463;1808;2086;107,2409;363;390,1708;3151;366;619;1463;1655;417;1588;2665;3664;390,1708;26;1247;499,771;2841,2867;468,506;1463;359;103;1399;1534;1534;1381;1534;897;26;1247;26,995,2769;402;468,592;1792,1804;2263;1707;1705;1103,3455;1708;1534;1103,3455;415,572,592;26,1103;383,479,544,1709;1705;1338;26,417,1709,1712,1848,1849,1850;262,263,264;1100;226,227;592;26,1613,2759,3241,3242;935;656;359;26,417,995,1848,1850;475;2120;26,454,995,1326;1435,1448;1463;831;433;1467,1468,1469;1651;635,1541,1542,1543;1789;1749;619;1386,2349;29;1632;806;103;1221;1792,1804;1707;619;592;1828;705;1463;26,995,2874;403;383,572;1326;107,783,2409;1463;1247;1054,1463;1792,1804;620;862;352,2272;298,299;627;3376;1463;1463;1009,1010,1011;112,651,2826;390;780,1124,1244;1742;1707;2694;155;1247;3301;3107;130;995;27;1463;86;1493;402;26;874;592;26,933,1840;26,1841,1842;335;2512;1463;891;1247;240,242;354;140;454,705,1496,1585;1792,1824;1824;479,1029;2694;1247;1247;1792;3183,3184,3185;26;26,2519;1792;410,1469,1516,1517,1518,1519;26;572;635,1496,1622,1623;1463;107;26;460,592,1698;1463;1534;1707;974;592;26,1537;26;592;26,2599;592;382,433,499,506,1065,1066,1067;26,995;390,1708;1054;1534;14,17,18,19,20,21,22,23,24,25,341,342,343,344,345,346,347,348,349,350;1144;527,528;26;403;546,831,2672;107;1655;1750;753;1883;455,592;26;124;1463;1100;1792;1792;1463;1789,1808,1810;1769;786;124,254,255,371,1775;1247;3370,3371,3372,3373;3370,3371,3372,3373;14,17,18,19,20,21,22,23,24,25,341,342,343,344,345,346,347,348,349,350;943,944;3033,3034;592;26;943,944;943,944;592;943,944;943,944;382;1238,2003;546;592;592;1709;635;29;26,402;780;2159;1463;1103,3455;1463;1463;1463;391;1713;434;1792,1804;390;390,393;592;1324;592;382;1014;1391,1392;26,417,1708,1848,1850;1103;1247;2694;2723;1463;468;592;995;2168;3136;1296;107,1774,1775,2409;1463;1463;1463;592;2391;995;943,944;1534,3303,3304,3305,3306;943,944;669;1463;3514;1829,1830;410,1469,1516,1517,1518,1519;943,944;943,944;1463;3593;363;656;935;1792,1804;1655;258,259;351,1126,1127;1463;1792,1804;29,3441,3442;656;753;546,592;468;592;1792,1804;2978;753;26,521;592;1324,2917;532;366;757;2657;1124;2907;1463;377,1221;656;1247;592;1399;1463;26,27;417;1463;1792;1120;1247;943,944;26,1537,1538;1463;1463;2714;1463;2222;2857,2858,2859,2860,2861;1707;1100;2335;26,27;1463;1463;407;1709;391;995;789;236;1763,1764;886;652;3307;1463;390,1708;1792;1655;625;1247;434;1789;112,129,3620,3621,3622,3623,3624;1534;359;1467,1468,1469;1708;1463;1463;1463,1534;635,1687,1760,1889,1890,1891;801;801;750;491;792,1124;3376;307,308,351;107;1792,1804;359,705;351;1655;390,506,1703;1463;705,3376;656;1463;2325;2408;291,292;1463;1136,3543;3543;1463;572;1559,1560,1561;1710;592;1708;1463;1956,2435;1708;2086;1338;1655;1463;1463;26,29,546,1249,3416,3417;1493;592;1463;1463;390,506,1703;540;2711;968,1491,2814,2815,2816,2817,2818;2102,2103;454,995,1231,1271;1463;1749;468;753;1463;2838;351;1534;1247;995,3163;627;499;390;3318;970,1454,1455;943,944;2498,2499;895;592;1377;1247;1247;976;1792;454;753;753;26,1469;26;1763,1764;410,1469,1516,1517,1518,1519;1944;1247;656;415;592;872,955,2928;410;124;3734;786,3134;468;410,1419;1106;685,831,1244,1956,2109;1463;581;468,476;415,572;382;2136;943,944;3081,3082,3083,3084;77,2971,2973,2974,2977;468,592;995;1348;532;721;1399;1749;1655;995,1095,1838,1839;390;3383;1463;1829,1830;1829,1830;434;2134;592;592,1463;1655;3666;625;506,1701;592;995;753;1247;26;1463;1463;532;854;854;1247;753;592;2148;410,1761;1463;1534;1655;1463;107,2409;1751;351,1126,1127;1910,1911;943,944;1463;656;1463;1205;200,201;592;592,2092;2082;1209;1707;1792,2459;655;107;943,944;1463;1792;3376;107;410,1534,1763,3398;26;500,546,1038,1085,1706;1100;124;499;656;635,3469;3286,3287,3288;3286,3287,3288;3286,3287,3288;1655;1255;26;1463;2047;1463;403;1089;26,27;1054,1463;29;943,944;943,944;1962;3235;1829,1830;1247;1247;1247;1463;1308;1463;1463;1708,2153;592;26;2303;1463;1572;440;1463;1463;1655;1338;1655;439;1341,1342,1343;601;1463;351;335,454;1463;1463;1463;1706,1707,1708;1182,1463;656;454;627;26,27;995;1197;351;2124;1463;1534;1247;943,944;2018;1463;1792;506,592;753;26;2396;943,944;2086;410,1761;3376;855;753;1463;780;1791;26;1463;1762;753;107;592;753;1707;1792;1655;3390;26,3292,3293;1708;1709;1463;1463;15,324,325,326,327,328,329;856;1172,1209;130;351;390;592,1730;2419;1584;1463;3527;1707;753;1792;363;3183,3184;592;1808;2419;935;1463;455;1020;390;366;1463;116,117;1463;1247;1608,3626;995,1103;508;592;753;1792;888;3458;656;2389;1656;1792;1463;1655;2124;1708;1776,1777;454;2117;468;2209,3020;3223;1348;29,1733;1463;1463;656;1792,1804;1463;2536;1838,1839;412,413;1534;603;1219;2107;1935;843,1792;1534;592;943,944;592;1463;2215;592;1463;1463;26;1463;1057;1776,1777;801;943,944;1709;783;995;1708;1463;26,454,1482;26;1435,1448;2009;1463;1463;2376;1974;434;1103,3455;468;2131;2131;592;592;3387;468;1463;1326,1733,3044,3045;592;468;3399;1463;943,944;801;410,1761;1022;423;1707;1463;592;1054;1247;783;1463;403;410,1469,1516,1517,1518,1519;1054,1463;149;2086;1463;1463;1463;2268;26;831,1450;468;592;592;1714;995;592;29,546;1463;1586;390,3748;1247;1539;1463;592;1792;351;831;1706;1548;1655;26,455;913,914;1103,3455;1250;1463;1336;1463;3591;1463;2564,2565;1789;1534;1792;995;1534;1103,3455;26,417,1848,1850;1103,3455;549;359;106;1956;26,401,417,995,1848;1705;1534;1534;995;1463;1103;410;112;1100,1463;26,27;1980;351,1126,1127;2251;592;2297;2086;1655;1463;1463;1463;1463;3266;2351;468;382;1424;1324;592;1463;440;619;1574,1575,1576;139;2427;1808;1463;3580;1709;1709;1463;1235;1378,1379;1463;1792;1463;479;1655;1467,1468,1469;862,2272;1792;1463;107;592;2086;1463;592;26,1733,2083,3040;410,1469,1516,1517,1518,1519;592;592;26,2938;1327;753;753;1215,1463;468;3484;1792,1804;1655;831,1450;2303;112;1247;3052;1213,1244;786;134,135;1655;26;2855;1707;1655;417,1103;107;3445;943,944;753;753;512,592;551;1124;515,1708;1463;1648;1463;107;363;1880,1881;1231;695,1352;1707;1463;359;592;2215;390,506,1703,1704;415,572;943,944;753;112;592;753;335;1463;351;1463;3446;107,3236;2842;1707;1709;390,393,487;1463;1244;26,417,1713,1848,1850;1971;506;26,417,1534,1848,1850;1100;1463;1463;592;1182;592;532;1534,3303,3304,3305,3306;1463;417;1829,1830;1167;1406;145;468;753;592;1463;592;3376;404,635;1463;935;1706;1463;705;2416;468;3513;1463;469;592;1655;1463;753;723;1463;782;1463;1495;410,1761;1247;753;619;1463;1792,1804;780;592;753;1463;390,455;619;1124;1792,1804;1655;1792,1800;867,868,871;3619;26,1745;1100;592;1763,1764;155,156;831;2358;2358;592;546;107;780;1706;2905;592;3772;592;2243;1463;592;26,1537,1538;1972;886;410;1103,3455;1221;3538;635,1541,1542,1543;1463;1463;855;635,1541,1542,1543;1792,1804;1662;1247;1463;1124;943,944;2570;635;26,27,28,29;1050,1051;182,183;753;592;335;2683;1463;26,27;1100;1463;831;390,1708;1708;28,383,635;1463;1534,3093;107;1655;3722;1463;26;968,1491,2814,2815,2816,2817,2818;1463;1463;26,27;1463;371;1124;1338;995;371,619;1851;1247;1438;2671;635;827;468,598;3307;351,1126,1127;656;786,833;1463;592;26;415,572,592;1463;359,831;1463;26,359,410;468;2148;995;943,944;506,592;1242;550,551;3428;2181;1463;107;1534;1247;2081;753;592;3662;1463;783;1829,1830;1829,1830;1829,1830;1829,1830;2433;403;1338;1463;546,995,1534;1655;107,1548;783;1052;707;3269;811;1247;943,944;1463;26;753;1655;1430;2548;1247;468;560,1444,1445;1706,1707,1708;1438;416;1417,1418;943,944;371;753;786;1573,2112;107,410,1325,1483,1484;29,455,546,2295;943,944;549;943,944;753;371;1244;114;2030;391;2544;2150;26;2694;107;753;351,1126,1127;753;572;592;1463;26;831;1463;1463;410,2037;636;1463;1463;410,1469,1516,1517,1518,1519;1515;1655;1247;415;1124;592,2899;146;26,27;753;943,944;26,27;983;1829,1830;26,27,28,29;546,592,1534;2362;592;2265;2124;592;1463;625;26,27,28,29;354;1708,2153;753;351,1126,1127;1463;592;1808;1749;1247;1247;1136,3543;75;1655,1792;1749;834;515;1463;780;454;26,454,1566,1567;995;1655;1275;1463;3239,3240;1792;2086;1247;1463;1247;26,27;1058;354;3410;1548,1763,1764;410,1469,1516,1517,1518,1519;1790;1754;1136,3543;1655;1792;592;3224;1247;86,3643,3644,3645;503,2164,2484;592;2694;1463;995;943,944;592,1096;1655;1463;2802;592;1238;1463;1463;112;2079;1463;1733;801;363;1707;26;403;86,3595;2375;874;382,592;1394;995;549;434;2694;2694;1351;1655;1247;943,944;1463;363;943,944;2086;479;546;2161;1463;592;605,606;591;935;1710;1247;1234;1792;592;351;827;1348;546,1705;468;603;1361;572;1792;1463;1463;1463;1655;2799;594,694;1380;1942;592;943,944;107;3591;26;3227;26,1534;677;1463;3542;26,1537,1538;1497;390,506,1703;753;546;390,506,1703;822,823;420;1333;2932;619;600;390,1708;1706;1463;2855;1463;753;2461;1749;2131;2131;1089;1463;1463;3122;592;1463;1247;1419;801;1463;2297;1792,1804;592;2163;26,27;107;1463;1463;26,27;411,592;831,1054,1463,1522;1792,1804;1247;363,1259,1655;2095;468;403;107;26,27;26,455;943,944;592;433,434,849;753;995;592;1463;1463;351,1126,1127;1792,1804;1463;994;26,956,2005,2006;1463;1808,3219,3220;995;1463;410,1469,1516,1517,1518,1519;440;1792;2841,2866,2867;415;1103;1713;1103,3455;240,1581,1582;1708;26,417,1848;1463;546;1247;1463;26,417,995,1848,1850;1707;1463;1231;1663;390,454,757;1792,1804;619;1792;468,592;592;1792,1804;950;656;1792;1706;1463;351,1126,1127;1655;1467,1468,1469;801;1463;1792;592;974,1098;1463;1708;366,1733,2083;476;669;592;1463;1707;1708;3723,3724;1247;1463;359;1386;592;592;1247;546,592;2429;390,1708;1789;1247;1247;500;592;351,1126,1127;26;1209;532;1463;423,592,639;1792;1762;524;1424;592;546,1463;753;753;192,193,194;1153,1154;1924;3206,3207,3208;26,417,1534,1848,1850;1449;1534;1792;366,1707,1708;26,1707;107;1655;351,1126,1127;943,944;895;1792,1804;1302;126;995,2575;1655;1555,1556,1557;3733;3370,3371,3372,3373;26,780;107,1775,2409;1463;1463;402;943,944;943,944;2854;943,944;2784;107;1707;1463;1603;1655;897;635;656;26,417,1712,1848;888,1182;3414;1399;2855;468,592;1349;592;391;1706,1707,1708;402,1222;1463;592;414;1100;943,944;1708;1463;592;1710;897;26;2962;1463;440;1247;1709;1792,1804;1222;26;943,944;468;359;26;410,1761;3376;886,1148;1463;1655;468;26,27;753;1247;1768;3733;1435,1448;1435,1448;390,455;371;26,27;122;1463;2694;26,1493;1792;592;592;1463;1463;1463;1247;2358;1463;592;406,407,408;453;455,983,1191;468;3376;382;1247;592;205,206;2086;1706;1222;888;3445;1463;499;390,1708;884;592;1792;1707;107;943,944;1534;804,968,1551,1552,1553;1415;1247;1655;592,1463;2107,2458;26,479,501;1463;1792,1804;-3710;1026;1136,3543;1463;107;2739,2740,2741;1655;1463;440;1463;611;351;995;831,1402,2717,2718;2862,2863;1749;1584;1338;1338;1338;831,1054,1463,1522;1792;26,3089;695;692,2283;3243;560,1444,1445;1852;1463;2596;3135;592;831;1463;1060;26,1048;26;1710;943,944;107,2409;1534;1789;2075;107;2694;592;831;627;858;1339;572;27,1095,1708,1835;1463;753;1463;753;1655;753;468;155,174;897;753;1247;1829,1830;-737,1829,1830;1829,1830;1829,1830;1829,1830;1338;591;1463;780;78,79,80;1338;1247;1247;1247;351,1126,1127;1792,1804;995;1222;2218;1792,1804;3183,3184;1655;1463;1247;780;1463;1932;1463;546,1690,1742,2055;943,944;75,1593;1463;1463;26;1709;89,3294;1172;359;468,506;1792,1804;410,1469,1516,1517,1518,1519;619;943,944;753;26,27,28,29;1463;1172;455;1463;592;2183;1792,1804;1463;1463;1463;1244;366;974,1315;943,944;592;26,27;26,27,28,29;2694;2265;592;1247;1247;1247;1464;1792,1804;1792,1804;753;1655;1792;1247;1463;1463;1463;410,1469,1516,1517,1518,1519;986,987;576,630,986,987;783,837;3146;1463;1792;3182;1648,3686;704;1100;26,27;780;107;1449;1463;1463;753;592;351;2397;3753;943,944;1758;935;2131;592;26,27,28,29;2047;383;633;131,1209;1248;1655;2121;1792;1463;363;1708;3596;619;402;1009,1010,1011;961,2078,2147;1463;592;1989;1956;1463;468;415,572,592;592;377;440;1655;377;1057;1182;26,27;1792;1792;558;592;591;855;410,1469,1516,1517,1518,1519;1792,1805;592;171,172;1829,1830;3179;2887;29;2921,2922;443,808,2593;935;943,944;1792;943,944;592;592;546,1463;468,592;935;935;1054,1463;455,512;1463;1463;1450,1463,1550;592;2131;391;592;499;592;1707;1248,1874;1808;26,27;1247;417;26,27;1534;26;1463;1222;1655;1463;578;1463;1100;1244;1463;1463;627;3261;705;2687;1463;1708,1713;1463;943,944;943,944;1463;1463;622;368,369,370,1463;2669;995;3605;1103,3455;2800;592;1792;592;1416;1103,3455;546;1463;2069;783;3524;1792,1804;1534;1247;3407;1706;26,417,1712,1848,1850;1851;1103,3455;26,417,1712;592;1709;1792;107,410,2570;753;26,693,1708;1707;26,417,995,1848,1850;1463;335;1708;312,313;656;1792;1463;1142;939;3116;801;674,675;1792,1804;1707;1463;862,2272;26,27,28,29;1366;1852;1463;943,944;943,944;592;1034,2689;1792;1198,1199,1200,1201,1202,1203,1204;753;1463;351,1126,1127;1463;1100;1706;3046,3047;3100;1792;1655;1247;1792,1804;1706,2240;853;26;1463;3122;1463;112;1733;26;390;26;1534;1463;1534;1655;1655;1218;1247;410,1469,1516,1517,1518,1519;1775;1416;1463;390,506,1703;1182,1463;592;2121;943,944;943,944;943,944;1688;619;1792;1071;592;26;1124;26;2664;874;1463;434;772;2121;26,402;592;1463;1463;943,944;1593;1677;1677;1463;1463;1100;1463;943,944;1463;26,107,440;1792,1804;391;1246;935,1993;3103;546;831,1054,1463,1522;2483;592;753;1467,1468,1469;351;390,1463;1324;1463;656,845;1463;656;855;592;2116;670;2694;592;592;26,27,28,29;26;1463;1792,1804;1706;1792;1534;995;1463;786;2086;1792,1804;1463;434;995;2731;1463;27;1463;112;26,2571;1463;-3710;592;786;2576;1231;546;1463;107;26;1463;592;592;373,1655;995;1194,1195;656;592;3611;26;506;1655;592;26,59;995;351,1126,1127;26,2148;3562,3563;2189;1034;107;440;851,995;354;753;1463;1984;831;1463;359;1763,1764;1707;26,1534;1521;592;544;1463;780;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;960,961;1792;565;26,59;1463;848;1706;403,440;1062;592;1247;1075;1707;371;1463;1463;351;592;1463;351,1126,1127;1655;468,1222;351,1126,1127;2694;1463;943,944;943,944;371;1463;1655;1577;886;1707;351;1463;1758;983;1247;1655;1463;705;335;3543;1136,3543;1136,3543;1136,3543;2410;1463;410,1469,1516,1517,1518,1519;403;831,1054,1463,1522;351;2303;1222;3468;351,1126,1127;1438;1708;440,836;-1055,1524;1054;26,27;656;1449;1463;592;753;1247;26,27;1763,1764;1655;26,27;995;831,1054,1463,1522;943,944;935;1790;1792,1804;1655;1705;1361;1651;390,723;351;786,1463;1463;2586;440,455,592;1983;26,434,765;1463;3376;1346,1347;1037;1091,1655;1655;943,944;635,1851,3661;2920;1463;1792,1804;753;753;1792;943,944;335;801;1048;359;656;912;1282;-2980,-2981,-2982,-2983,-2984;3641;261;26,1534,3019;359;615;1463;433,1696,1697;935;627;1463;26;619;592;2131;1463;2694;26,27;454,757;354,1079;335;1792,1804;1655;705,1463;26,27;373,376;1655;417;1707;830;26,27;1463;351,1126,1127;434;1655;157;1463;26;26,592;212;592;943,944;1103,3455;1467,1468,1469;634;415,635,930,1708,2513,2514;26,417,995;410,1469,1516,1517,1518,1519;3601,3602;1463;1463;1463,3128;619;592;1463,1754;26;592;29;1363;317,1071;2063;1463;780;351,1126,1127;592;1103;468;410,1469,1516,1517,1518,1519;86;1942;2943;3186;1463;351,1126,1127;1247;1672;592,1672;390,726;382,506,592;1772;1749;783;1655,1660;1235;995,3379;479;455;26;1707;783;1655;943,944;831;468;1463;1709;1463;1691;592;753;15,-27,324,325,326,327,328,329;351,1126,1127;366,824;1463;916;1061;391;1706;2465;1655;440;1428;656;592;656;1463;1855,3526;592;592;440;1463;371;1182;1360;1247;943,944;592;124,532,3459;786,2336;1749;29;26,27,28,29;1792;410,1419;1792;1428;26,1534;1372,2077;1868,2829;26;1463;1463;1136;1463;479;351;1763,1764;2348;592;1463;831,1054,1463,1522;1447;26,27;1463;1463;1463;2670;366;849;26,27;1338;2528;2528;592;351;2405;499;403;592;943,944;2892;753;1463;1655;403;1829,1830;1829,1830;-737,1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1428;1749;415,572,592;1463;619;468;1655;592;753;1655;1463;1247;371;792;1655;1655;1463;1792;943,944;592;1463;2470;1463;1182;3070;2280;1463;410,1761;1463;974,3067,3068;983;124,131,3722;1450,1463,1550;1247;1463;1463;1247;1247;1247;886;1463;1463;625;753;943,944;26,479;1247;440;2076;1682;1706;26;1463;1247;583;1463;2636;592;112,706;26,27,28,29;542,1046;1463;3523;551;2300;1463;592;1463;1708;1247;935;1100;1655;1103,3455;656;1288;1792,1805;1749;2185;935;2086;2799;205,314;1247;3476,3477;2131;2131;801;1534;1222;2431;1463;1655;801;3586;1435,1448;1422;1825;506,592;592;112,651;1247;1231;1749;1979;1103,3455;924;1138,1283;592;592;1792,1804;1463;656;1463;1463;26;1311;1534;1534;2047;479;753;1463;26,417,995,1848,1850;417;575,576;1749;1463;1435,1448;909;1759;1463;1752;3081,3082,3083;1463;1463;1792,1811;107;801;3042;1792;26,27;1463;1222;403;1792;391;801;2225;1438;1475;107;753;26,27,28,29;2094,2095;3379;592;1038;26,995;592;1706;1655;1655;479;801;1655;1463;1463;3567;476;1749;625;26,369,1191;1707;416;3476,3477;415;463;780;592,995,1463;1103,3455;2987;565;1534,3093;1790;2086;1705;723;592;1222;1875;864;1463;592;482;440;1709;319,320,321;3175;627;1216;2469;1525,1526;506,592;1534;1463;26,27;592;2352;1534;1438;546;1463;1463;354;1655;656;403;324,325,327,2895;1789;943,944;434;3203;943,944;995;1463;2670;2670;935;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;2694;1655;592;454;592;591;2726;1463;1463;943,944;1792,1804;2830;592;592;943,944;1247;1247;1247;780;3068;26,27;26,27,29;112,474;935;1247;1247;1247;1463;26,27,28,29;1966;1298;1463;2072;1247;454;26,27,28,29;1463;284;1463;2836,2837;1463;780;1348;1247;86,1638,1640,1641,1642,1643;1463;1238;410;1792;1463;26,1706;1463;1463;943,944;1583;1425;3376;1055;1247;912;2096;935;109,184;625;1247;1829,1830;1829,1830;2131;801;351,1126,1127;1463;592;371;1655;1749;592;440;1574,1575,1576;354;2047;1044;1655;354;351,1126,1127;260;1933;1463;1792,1804;351;592;3037;1792;1792;1103,3455;359;1348;1321;1100;107;107;1792;780,1648;218,222;2215;592,1463;909;1463;440;1655;26,1720,1850;26,27,28;780;26;26,27,28,29;26,27;382;1749;1829,1830;592;1655;2694;26,27,28,29,1834;1829,1830;351,1126,1127;1463;2694;1655;3476,3477;2576;909;792;1221;3585;1463;780;635,1534;3543;-1494;351,1126,1127;592;269,270;440,482;468;1707;1463;1789;1792;1463;1463;592,907;1463;2267;1829,1830;1829,1830;1829,1830;1829,1830;1463;1655;29;26,27,28,29;2829;619;26,479,1707;1463;592,2220;1247;2393;1069,1255;1705;26,27,28,29;705;351;26,27;625;935;1428;26,27,28,29;307,3741;1463;3745;591;26;1958;780;656;1348;2360;2809,2810,2811;26,27;1247;1655;1534;1463;1655;1463;532;373;592;886;3244;1463;898;1784,1785,1786,1787,1827;1247;1750;417;1027;26;26,3019;808;808;1463;935;935;780;1792,1804;3544;351,1126,1127;468;107,2728;1829,1830;392;1428;912;592;592;402;26,27;1749;1463;1463;1419;26,417,1848,1850;1463;1463;1435,1448;1223,1655;351,1126,1127;619;1463;27;1292;2456;1463;780;440,1100;366;1655;1463;943,944;1708;1749;3238;862;26,1073,1074;1655;2331;26,1709;656;1463;1463;1534,3256;1247;1655;390;1463;1463;2719;1707;1534;592;410,1761;1463;512,625;2572;351,1463;363;1792;625;1463;1463;26;2291,2292;2619;1655;592;455;935;1463;1463;1829,1830;1829,1830;1829,1830;1829,1830;831,1324;1655;1655;1776,1777;482;3476,3477;592;1463;410,1761;1707;1463;655;26,27;26,27;1829,1830;897;1655;403;1655;1706,1707,1708;943,944;26,27,28;780;1655;1463;1655;1716;2694;1930,1931;1463;2920;1463;1655;541;316;26;1829,1830;453;808;3606;935;630;1829,1830;391;995;1463;2694;1247;26,27;1376;627;1100;592;1428;1792;1244;1664;351;1792,1804;1463;753;2200;3222;2715;592;186,187;1707;1705;410,1469,1516,1517,1518,1519;592,2161;1292;831,1054,1463,1522;359;1655;2603;1534,3303,3304,3305,3306,3307;26,27,28,29;1463;1326;3476,3477;410,1761;1348;2393;592;391;1792;1463;2211;1463;107,2409;1235;1009,1010,1011;2015;112;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;1829,1830;144;26,27;26,27;26,27;26;1463;2043;371;656;440;2920;1655,3085;619;592;1463;1175;1792,1805;1792,1805;886;1420;591;1829,1830;3210;1709;75;1463;1463;801;1463;351;26,2719;474;26,808;592;564;86;1348;351,1126,1127;1463;1763,1764;26,644,645;2161;780;2253;1286;26,59;26,59;1829,1830;1463;627;351,1126,1127;26;1107;1463;1463;1247;351;499;1329,1708,1713;1463;1463;1792;3543;909;1463;1655;780;1829,1830;1829,1830;1655;133;2095,2097;499;26,27,28,29;1706,1707,1708;3476,3477;1706;3549;490;2920;1182;1829,1830;1709;1103,3455;3141;403;1749;2694;1655;1182;1463;371;159,160;1100;1463;2734,2735;2573;1707;1348;359;1655;1655;26,27;1463;1463;311;2594,2595;1829,1830;1463;3476,3477;1463;1885,1886;390;3543;1733;1463;560;1829,1830;410,852;354;705;1463;591;780;3436;1463;783;1829,1830;351,1126,1127;26,27,28,29;1463;363;336,337,353,354,3757;1103;26;26;1463;2086;1463;1463;338,339;1463;1829,1830;3476,3477;421,454,757,1709;351,1126,1127;1463;1463;366,591;3476,3477;3476,3477;627;3389;107;749;1428;107;592;27;1534;26,1191,1231,1748;780;1428;1110;3094;1463;1708;3476,3477;2568;351;1384;2864,3074;1463;591;1348;3476,3477;1383;1534;440;3476,3477;1463;26,27,28,29;3476,3477;1709;2402;1792;1348;3476,3477;1655;780;780;26;1984;27;26;3476,3477;592;969;1463;3478;1655;1463;1463;75;415,591;1829,1830;131,1637;889;3476,3477;27;1829,1830;479;897;3309;1463;403;3476,3477;922;792;592;3476,3477;1463;3476,3477;1463;198,199;26,59";

const $scriptletHostnames$ = /* 13081 */ ["j.gs","s.to","3sk.*","al.ly","asd.*","bc.vc","br.de","bs.to","clk.*","di.fm","fc.lc","fr.de","fzm.*","g3g.*","gmx.*","hqq.*","kat.*","lz.de","m4u.*","mt.de","nn.de","nw.de","o2.pl","op.gg","ouo.*","oxy.*","pnd.*","rp5.*","sh.st","sn.at","th.gl","tpb.*","tu.no","tz.de","ur.ly","vev.*","vz.lt","wa.de","wn.de","wp.de","wp.pl","wr.de","x.com","ytc.*","yts.*","za.gl","ze.tt","00m.in","1hd.to","2ddl.*","33sk.*","4br.me","4j.com","538.nl","9tsu.*","a8ix.*","agf.nl","aii.sh","al.com","as.com","av01.*","bab.la","bbf.lt","bcvc.*","bde4.*","btdb.*","btv.bg","c2g.at","cap3.*","cbc.ca","crn.pl","djs.sk","dlhd.*","dna.fr","dnn.de","dodz.*","dood.*","eio.io","epe.es","ettv.*","ew.com","exe.io","eztv.*","fbgo.*","fnp.de","ft.com","geo.de","geo.fr","goo.st","gra.pl","haz.de","hbz.us","hd21.*","hdss.*","hna.de","iir.ai","iiv.pl","imx.to","ioe.vn","jav.re","jav.sb","jav.si","javx.*","kaa.lt","kaa.mx","kat2.*","kio.ac","kkat.*","kmo.to","kwik.*","la7.it","lne.es","lnk.to","lvz.de","m5g.it","met.bz","mexa.*","mmm.dk","mtv.fi","nj.com","nnn.de","nos.nl","now.gg","now.us","noz.de","npo.nl","nrz.de","nto.pl","ntv.cx","och.to","oii.io","oii.la","ok.xxx","oke.io","oko.sh","ovid.*","pahe.*","pe.com","pnn.de","poop.*","qub.ca","ran.de","rgb.vn","rgl.vn","rtl.de","rtv.de","s.to>>","sab.bz","sfr.fr","shz.de","siz.tv","srt.am","svz.de","tek.no","tf1.fr","tfp.is","tii.la","tio.ch","tny.so","top.gg","tpi.li","tv2.no","tvn.pl","tvtv.*","txxx.*","uii.io","upns.*","vido.*","vip.de","vod.pl","voe.sx","vox.de","vsd.fr","waaw.*","waz.de","wco.tv","web.de","xnxx.*","xup.in","xxnx.*","yts2.*","zoro.*","0xxx.ws","10gb.vn","1337x.*","1377x.*","1ink.cc","24pdd.*","5278.cc","5play.*","7mmtv.*","7xm.xyz","8tm.net","a-ha.io","adn.com","adsh.cc","adsrt.*","adsy.pw","adyou.*","adzz.in","ahri8.*","ak4eg.*","akoam.*","akw.cam","akwam.*","an1.com","an1me.*","arbsd.*","babla.*","bbc.com","bgr.com","bgsi.gg","bhg.com","bild.de","biqle.*","bunkr.*","car.com","cbr.com","cbs.com","chip.de","cine.to","clik.pw","cnn.com","crn.com","ctrlv.*","dbna.de","deco.fr","delo.bg","dict.cc","digi.no","dirp.me","dlhd.sx","docer.*","doods.*","doood.*","elixx.*","enit.in","eska.pl","exe.app","exey.io","fakt.pl","faz.net","ffcv.es","filmy.*","fomo.id","fox.com","fpo.xxx","gala.de","gala.fr","gats.io","gdtot.*","giga.de","gk24.pl","gntai.*","gnula.*","goku.sx","gomo.to","gotxx.*","govid.*","gp24.pl","grid.id","gs24.pl","gsurl.*","hdvid.*","hdzog.*","hftg.co","igram.*","inc.com","inra.bg","itv.com","j5z.xyz","javhd.*","jizz.us","jmty.jp","joyn.at","joyn.ch","joyn.de","jpg2.su","jpg6.su","k1nk.co","k511.me","kaas.ro","kfc.com","khsm.io","kijk.nl","kino.de","kinox.*","kinoz.*","koyso.*","ksl.com","ksta.de","lato.sx","laut.de","leak.sx","link.tl","linkz.*","linx.cc","litv.tv","lnbz.la","lnk2.cc","logi.im","lulu.st","m4uhd.*","mail.de","mdn.lol","mega.nz","mexa.sh","mlb.com","mlfbd.*","mlsbd.*","mlwbd.*","moin.de","mopo.de","more.tv","moto.it","movi.pk","mtv.com","myegy.*","n-tv.de","nba.com","nbc.com","netu.ac","news.at","news.bg","news.de","nfl.com","nmac.to","noxx.to","nuvid.*","odum.cl","oe24.at","oggi.it","oload.*","onle.co","onvid.*","opvid.*","oxy.edu","oyohd.*","pelix.*","pes6.es","pfps.gg","pngs.gg","pnj.com","pobre.*","prad.de","qmh.sex","rabo.no","rat.xxx","raw18.*","rmcmv.*","sat1.de","sbot.cf","seehd.*","send.cm","sflix.*","sixx.de","sms24.*","songs.*","spy.com","stape.*","stfly.*","swfr.tv","szbz.de","tj.news","tlin.me","tr.link","ttks.tw","tube8.*","tune.pk","tvhay.*","tvply.*","tvtv.ca","tvtv.us","u.co.uk","ujav.me","uns.bio","upi.com","upn.one","upvid.*","vcp.xxx","veev.to","vidd.se","vidhd.*","vidoo.*","vidop.*","vids.st","vidup.*","vipr.im","viu.com","vix.com","viz.com","vkmp3.*","vods.tv","vox.com","vozz.vn","vpro.nl","vsrc.su","vudeo.*","waaaw.*","waaw1.*","welt.de","wgod.co","wiwo.de","wwd.com","xtits.*","ydr.com","yiv.com","yout.pw","ytmp3.*","zeit.de","zeiz.me","zien.pl","0deh.com","123mkv.*","15min.lt","1flix.to","1mov.lol","20min.ch","2embed.*","2ix2.com","3prn.com","4anime.*","4cash.me","4khd.com","519.best","58n1.com","7mmtv.sx","85po.com","9gag.com","9mod.com","9n8o.com","9xflix.*","a2zapk.*","aalah.me","actvid.*","adbull.*","adeth.cc","adfloz.*","adfoc.us","adsup.lk","aetv.com","afly.pro","agefi.fr","al4a.com","alpin.de","anigo.to","anoboy.*","arcor.de","ariva.de","asd.pics","asiaon.*","atxtv.co","auone.jp","ayo24.id","azsoft.*","babia.to","bbw6.com","bdiptv.*","bdix.app","bif24.pl","bigfm.de","bilan.ch","bing.com","binged.*","bjhub.me","blick.ch","blick.de","bmovie.*","bombuj.*","booru.eu","brato.bg","brevi.eu","bunkr.la","bunkrr.*","bzzhr.co","cam4.com","canna.to","capshd.*","cataz.to","cety.app","cgaa.org","chd4.com","cima4u.*","cineb.gg","cineb.rs","cinen9.*","citi.com","clk.asia","cnbc.com","cnet.com","comix.to","crichd.*","crone.es","cuse.com","cwtv.com","cybar.to","cykf.net","dahh.net","dazn.com","dbna.com","deano.me","dewimg.*","dfiles.*","dlhd.*>>","doods.to","doodss.*","dooood.*","dosya.co","duden.de","dump.xxx","ecac.org","eee1.lat","egolf.jp","eldia.es","emoji.gg","ervik.as","espn.com","exee.app","exeo.app","exyi.net","f75s.com","fastt.gg","fembed.*","files.cx","files.fm","files.im","filma1.*","finya.de","fir3.net","flixhq.*","fmovie.*","focus.de","friv.com","fupa.net","fxmag.pl","fzlink.*","g9r6.com","ganool.*","gaygo.tv","gdflix.*","ggjav.tv","gload.to","glodls.*","gogohd.*","gokutv.*","gol24.pl","golem.de","gtavi.pl","gusto.at","hackr.io","haho.moe","hd44.com","hd44.net","hdbox.ws","hdfull.*","heftig.*","heise.de","hidan.co","hidan.sh","hilaw.vn","hk01.com","hltv.org","howdy.id","hoyme.jp","hpjav.in","hqtv.biz","html.net","huim.com","hulu.com","hydrax.*","hyhd.org","iade.com","ibbs.pro","icelz.to","idnes.cz","imgdew.*","imgsen.*","imgsto.*","imgviu.*","isi7.net","its.porn","j91.asia","janjua.*","jmanga.*","jmmv.dev","jotea.cl","kaido.to","katbay.*","kcra.com","kduk.com","keepv.id","kizi.com","kloo.com","km77.com","kmed.com","kmhd.net","kmnt.com","kpnw.com","ktee.com","ktmx.pro","kukaj.io","kukni.to","kwro.com","l8e8.com","l99j.com","la3c.com","lablue.*","lared.cl","lejdd.fr","levif.be","lin-ks.*","link1s.*","linkos.*","liveon.*","lnk.news","ma-x.org","magesy.*","mail.com","mazpic.*","mcloud.*","mgeko.cc","miro.com","missav.*","mitly.us","mixdrp.*","mixed.de","mkvhub.*","mmsbee.*","moms.com","money.bg","money.pl","movidy.*","movs4u.*","my1ink.*","my4w.com","myad.biz","mycima.*","mzee.com","n.fcd.su","ncaa.com","newdmn.*","nhl66.ir","nick.com","nohat.cc","nola.com","notube.*","ogario.*","orsm.net","oui.sncf","pa1n.xyz","pahe.ink","pasend.*","payt.com","pctnew.*","picks.my","picrok.*","pingit.*","pirate.*","pixlev.*","pluto.tv","plyjam.*","plyvdo.*","pogo.com","pons.com","porn.com","porn0.tv","pornid.*","pornx.to","qa2h.com","quins.us","quoka.de","r2sa.net","racaty.*","radio.at","radio.de","radio.dk","radio.es","radio.fr","radio.it","radio.pl","radio.pt","radio.se","ralli.ee","ranoz.gg","rargb.to","rasoi.me","rdxhd1.*","rintor.*","rootz.so","roshy.tv","saint.to","sanet.lc","sanet.st","sbchip.*","sbflix.*","sbplay.*","sbrulz.*","seeeed.*","senda.pl","seriu.jp","sex3.com","sexvid.*","sflix.fi","shopr.tv","short.pe","shtab.su","shtms.co","shush.se","slant.co","so1.asia","splay.id","sport.de","sport.es","spox.com","sptfy.be","stern.de","stfly.me","strtpe.*","svapo.it","swdw.net","swzz.xyz","sxsw.com","sxyprn.*","t20cup.*","t7meel.*","tasma.ru","tbib.org","tele5.de","thegay.*","thekat.*","thoptv.*","tirexo.*","tmearn.*","tobys.dk","today.it","toggo.de","trakt.tv","trend.at","trrs.pro","tubeon.*","tubidy.*","turbo.fr","tv247.us","tvepg.eu","tvn24.pl","tvnet.lv","txst.com","udvl.com","uiil.ink","upapk.io","uproxy.*","uqload.*","urbia.de","uvnc.com","v.qq.com","vanime.*","vapley.*","vedbam.*","vedbom.*","vembed.*","venge.io","vibe.com","vid4up.*","vidlo.us","vidlox.*","vidsrc.*","vidup.to","viki.com","vipbox.*","viper.to","viprow.*","virpe.cc","vlive.tv","voe.sx>>","voici.fr","voxfm.pl","vozer.io","vozer.vn","vtbe.net","vtmgo.be","vtube.to","vumoo.cc","vxxx.com","wat32.tv","watch.ug","wcofun.*","wcvb.com","webbro.*","wepc.com","wetter.*","wfmz.com","wkyc.com","woman.at","work.ink","wowtv.de","wp.solar","wplink.*","wttw.com","wyze.com","x1337x.*","xcum.com","xh.video","xo7c.com","xvide.me","xxf.mobi","xxr.mobi","xxu.mobi","y2mate.*","yelp.com","yepi.com","yflix.to","youx.xxx","yporn.tv","yt1s.com","yt5s.com","ytapi.cc","ythd.org","z4h4.com","zbporn.*","zdrz.xyz","zee5.com","zooqle.*","zshort.*","0vg9r.com","10.com.au","10short.*","123link.*","123mf9.my","18xxx.xyz","1milf.com","1stream.*","2024tv.ru","26efp.com","2conv.com","2glho.org","2kmovie.*","2ndrun.tv","3dzip.org","3movs.com","49ers.com","4share.vn","4stream.*","4tube.com","51sec.org","5flix.top","5mgz1.com","5movies.*","6jlvu.com","7bit.link","7mm003.cc","7starhd.*","9anime.pe","9hentai.*","9xbuddy.*","9xmovie.*","a-o.ninja","a2zapk.io","aagag.com","aagmaal.*","abcya.com","acortar.*","adcorto.*","adsfly.in","adshort.*","adurly.cc","aduzz.com","afk.guide","agar.live","ah-me.com","aikatu.jp","airtel.in","alphr.com","ampav.com","andyday.*","anidl.org","anikai.to","animekb.*","animesa.*","anitube.*","aniwave.*","anizm.net","apkmb.com","apkmody.*","apl373.me","apl374.me","apl375.me","appdoze.*","appvn.com","aram.zone","arc018.to","arcai.com","art19.com","artru.net","asd.homes","atlaq.com","atomohd.*","awafim.tv","aylink.co","azel.info","azmen.com","azrom.net","bakai.org","bdlink.pw","beeg.fund","befap.com","bflix.*>>","bhplay.me","bibme.org","bigwarp.*","biqle.com","bitfly.io","bitlk.com","blackd.de","blkom.com","blog24.me","blogk.com","bmovies.*","boerse.de","bolly4u.*","boost.ink","brainly.*","btdig.com","buffed.de","busuu.com","c1z39.com","cambabe.*","cambb.xxx","cambro.io","cambro.tv","camcam.cc","camcaps.*","camhub.cc","canela.tv","canoe.com","ccurl.net","cda-hd.cc","cdn1.site","cdn77.org","cdrab.com","cfake.com","chatta.it","chyoa.com","cinema.de","cinetux.*","cl1ca.com","clamor.pl","cloudy.pk","cmovies.*","colts.com","comunio.*","ctrl.blog","curto.win","cutdl.xyz","cybar.xyz","czxxx.org","d000d.com","d0o0d.com","daddyhd.*","daybuy.tw","debgen.fr","dfast.app","dfiles.eu","dflinks.*","dhd24.com","djmaza.my","djstar.in","djx10.org","dlgal.com","do0od.com","do7go.com","domaha.tv","doods.pro","doooood.*","doply.net","dotflix.*","doviz.com","dropmms.*","dropzy.io","drrtyr.mx","drtuber.*","drzna.com","dumpz.net","dvdplay.*","dx-tv.com","dz4soft.*","eater.com","echoes.gr","efukt.com","eg4link.*","egybest.*","egydead.*","eltern.de","embedme.*","embedy.me","embtaku.*","emovies.*","enorme.tv","entano.jp","eodev.com","erogen.su","erome.com","eroxxx.us","erzar.xyz","europix.*","evaki.fun","evo.co.uk","exego.app","eyalo.com","f16px.com","fap16.net","fapnado.*","faps.club","fapxl.com","faselhd.*","fast-dl.*","fc-lc.com","feet9.com","femina.ch","ffjav.com","fifojik.*","file4go.*","fileq.net","filma24.*","filmex.to","finfang.*","flixhd.cc","flixhq.ru","flixhq.to","flixhub.*","flixtor.*","flvto.biz","fmj.co.uk","fmovies.*","fooak.com","forsal.pl","foundit.*","foxhq.com","freep.com","freewp.io","frembed.*","frprn.com","fshost.me","ftopx.com","ftuapps.*","fuqer.com","furher.in","fx-22.com","gahag.net","gayck.com","gayfor.us","gayxx.net","gdirect.*","ggjav.com","gifhq.com","giize.com","globo.com","glodls.to","gm-db.com","gmanga.me","gofile.to","gojo2.com","gomov.bio","gomoviz.*","goplay.ml","goplay.su","gosemut.*","goshow.tv","gototub.*","goved.org","gowyo.com","goyabu.us","gplinks.*","gsdn.live","gsm1x.xyz","guum5.com","gvnvh.net","hanime.tv","happi.com","haqem.com","hax.co.id","hd-xxx.me","hdfilme.*","hdgay.net","hdhub4u.*","hdrez.com","hdss-to.*","heavy.com","hellnaw.*","hentai.tv","hh3dhay.*","hhesse.de","hianime.*","hideout.*","hitomi.la","hmt6u.com","hoca2.com","hoca6.com","hoerzu.de","hojii.net","hokej.net","hothit.me","hotmovs.*","hugo3c.tw","huyamba.*","hxfile.co","i-bits.io","ibooks.to","icdrama.*","iceporn.*","ico3c.com","idpvn.com","ihow.info","ihub.live","ikaza.net","ilinks.in","imeteo.sk","img4fap.*","imgmaze.*","imgrock.*","imgtown.*","imgur.com","imgview.*","imslp.org","ingame.de","intest.tv","inwepo.co","io.google","iobit.com","iprima.cz","iqiyi.com","ireez.com","isohunt.*","janjua.tv","jappy.com","japscan.*","jasmr.net","javboys.*","javcl.com","javct.net","javdoe.sh","javfor.tv","javfun.me","javhat.tv","javhd.*>>","javmix.tv","javpro.cc","javsub.my","javup.org","javwide.*","jkanime.*","jootc.com","kali.wiki","karwan.tv","katfile.*","keepvid.*","ki24.info","kick4ss.*","kickass.*","kicker.de","kinoger.*","kissjav.*","klmanga.*","koora.vip","krx18.com","kuyhaa.me","kzjou.com","l2db.info","l455o.com","lawyex.co","lecker.de","legia.net","lenkino.*","lesoir.be","linkfly.*","liveru.sx","ljcam.net","lkc21.net","lmtos.com","lnk.parts","loader.fo","loader.to","loawa.com","lodynet.*","lookcam.*","lootup.me","los40.com","m.kuku.lu","m1xdrop.*","m4ufree.*","magma.com","magmix.jp","mamadu.pl","mangaku.*","manhwas.*","maniac.de","mapple.tv","marca.com","mavplay.*","mboost.me","mc-at.org","mcrypto.*","mega4up.*","merkur.de","messen.de","mgnet.xyz","mhn.quest","milfnut.*","miniurl.*","mitele.es","mixdrop.*","mkvcage.*","mkvpapa.*","mlbbox.me","mlive.com","mmo69.com","mobile.de","mod18.com","momzr.com","moontv.to","mov2day.*","mp3clan.*","mp3fy.com","mp3spy.cc","mp3y.info","mrgay.com","mrjav.net","msic.site","multi.xxx","mxcity.mx","myaew.com","mynet.com","mz-web.de","nbabox.co","ncdnstm.*","nekopoi.*","netcine.*","neuna.net","news38.de","nhentai.*","niadd.com","nikke.win","nkiri.com","nknews.jp","notion.so","nowgg.lol","noxx.to>>","nozomi.la","npodoc.nl","nxxn.live","nyaa.land","nydus.org","oatuu.org","obsev.com","ocala.com","ocnpj.com","ofiii.com","ofppt.net","ohmymag.*","ok-th.com","okanime.*","okblaz.me","omavs.com","oosex.net","opjav.com","orunk.com","owlzo.com","oxxfile.*","pahe.plus","palabr.as","palimas.*","pasteit.*","pastes.io","pcwelt.de","pelis28.*","pepar.net","pferde.de","phodoi.vn","phois.pro","picrew.me","pixhost.*","pkembed.*","player.pl","plylive.*","pogga.org","popjav.in","poqzn.xyz","porn720.*","porner.tv","pornfay.*","pornhat.*","pornhub.*","pornj.com","pornlib.*","porno18.*","pornuj.cz","powvdeo.*","premio.io","profil.at","psarips.*","pugam.com","pussy.org","pynck.com","q1003.com","qcheng.cc","qcock.com","qlinks.eu","qoshe.com","quizz.biz","radio.net","rarbg.how","readm.org","redd.tube","redisex.*","redtube.*","redwap.me","remaxhd.*","rentry.co","rexporn.*","rexxx.org","rezst.xyz","rezsx.xyz","rfiql.com","riveh.com","rjno1.com","rock.porn","rokni.xyz","rooter.gg","rphost.in","rshrt.com","ruhr24.de","rytmp3.io","s2dfree.*","saint2.cr","samfw.com","satdl.com","sbnmp.bar","sbplay2.*","sbplay3.*","sbsun.com","scat.gold","seazon.fr","seelen.io","seexh.com","series9.*","seulink.*","sexmv.com","sexsq.com","sextb.*>>","sezia.com","sflix.pro","shape.com","shlly.com","shmapp.ca","shorten.*","shrdsk.me","shrib.com","shrink.yt","shrinke.*","shrtfly.*","skardu.pk","skpb.live","skysetx.*","slate.com","slink.bid","smutr.com","son.co.za","songspk.*","spcdn.xyz","sport1.de","sssam.com","ssstik.io","staige.tv","strms.net","strmup.cc","strmup.to","strmup.ws","strtape.*","study.com","sulasok.*","swame.com","swgop.com","syosetu.*","sythe.org","szene1.at","talaba.su","tamilmv.*","taming.io","tatli.biz","tech5s.co","teensex.*","terabox.*","tfly.link","tgo-tv.co","themw.com","thgss.com","thothd.to","thothub.*","tinhte.vn","tnp98.xyz","to.com.pl","today.com","todaypk.*","tojav.net","topflix.*","topjav.tv","torlock.*","tpaste.io","tpayr.xyz","tpz6t.com","trutv.com","tryzt.xyz","tubev.sex","tubexo.tv","tukoz.com","turbo1.co","tvguia.es","tvinfo.de","tvlogy.to","tvporn.cc","txori.com","txxx.asia","ucptt.com","udebut.jp","ufacw.com","uflash.tv","ujszo.com","ulsex.net","unicum.de","upbam.org","upfiles.*","upiapi.in","uplod.net","uporn.icu","upornia.*","uppit.com","uproxy2.*","upxin.net","upzone.cc","uqozy.com","urlcero.*","ustream.*","uxjvp.pro","v1kkm.com","vdtgr.com","vebo1.com","veedi.com","vg247.com","vid2faf.*","vidara.so","vidara.to","vidbm.com","vide0.net","videobb.*","vidfast.*","vidmoly.*","vidplay.*","vidsrc.cc","vidzy.org","vienna.at","vinaurl.*","vinovo.to","vip1s.top","vipurl.in","vivuq.com","vladan.fr","vnuki.net","voodc.com","vplink.in","vtlinks.*","vttpi.com","vvid30c.*","vvvvid.it","w3cub.com","waezg.xyz","waezm.xyz","webmaal.*","webtor.io","wecast.to","weebee.me","wetter.de","wildwap.*","winporn.*","wiour.com","wired.com","woiden.id","world4.eu","wpteq.org","wvt24.top","x-tg.tube","x24.video","xbaaz.com","xbabe.com","xcafe.com","xcity.org","xcoic.com","xcums.com","xecce.com","xexle.com","xhand.com","xhbig.com","xmovies.*","xpaja.net","xtapes.me","xvideos.*","xvipp.com","xxx24.vip","xxxhub.cc","xxxxxx.hu","y2down.cc","yeptube.*","yeshd.net","ygosu.com","yjiur.xyz","ymovies.*","youku.com","younetu.*","youporn.*","yt2mp3s.*","ytmp3s.nu","ytpng.net","ytsaver.*","yu2be.com","zataz.com","zdnet.com","zedge.net","zefoy.com","zhihu.com","zjet7.com","zojav.com","zovo2.top","zrozz.com","0gogle.com","0gomovie.*","10starhd.*","123anime.*","123chill.*","13tv.co.il","141jav.com","18tube.sex","1apple.xyz","1bit.space","1kmovies.*","1link.club","1stream.eu","1tamilmv.*","1todaypk.*","1xanime.in","2best.club","2the.space","2umovies.*","3dzip.info","3fnews.com","3hiidude.*","3kmovies.*","3xyaoi.com","4-liga.com","4kporn.xxx","4porn4.com","4tests.com","4tube.live","5ggyan.com","5xmovies.*","720pflix.*","8boobs.com","8muses.xxx","8xmovies.*","91porn.com","96ar.com>>","9908ww.com","9anime.vip","9animes.ru","9kmovies.*","9monate.de","9xmovies.*","9xupload.*","a1movies.*","acefile.co","acortalo.*","adshnk.com","adslink.pw","aeonax.com","aether.mom","afdah2.com","akmcloud.*","all3do.com","allfeeds.*","alphatv.gr","amboss.com","ameede.com","amindi.org","anchira.to","andani.net","anime4up.*","animedb.in","animeflv.*","animeid.tv","animekai.*","animesup.*","animetak.*","animez.org","anitube.us","aniwatch.*","aniwave.uk","anodee.com","anon-v.com","anroll.net","ansuko.net","antenne.de","anysex.com","apkhex.com","apkmaven.*","apkmody.io","arabseed.*","archive.fo","archive.is","archive.li","archive.md","archive.ph","archive.vn","arcjav.com","areadvd.de","aruble.net","ashrfd.xyz","ashrff.xyz","asiansex.*","asiaon.top","asmroger.*","ate9ni.com","atishmkv.*","atomixhq.*","atomtt.com","av01.media","avjosa.com","avtub.cx>>","awpd24.com","axporn.com","ayuka.link","aznude.com","babeporn.*","baikin.net","bakotv.com","bandle.app","bang14.com","bayimg.com","bblink.com","bbw.com.es","bdokan.com","bdsmx.tube","bdupload.*","beatree.cn","beeg.party","beeimg.com","bembed.net","bestcam.tv","bigten.org","bildirim.*","bloooog.it","bluetv.xyz","bnnvara.nl","boards.net","boombj.com","borwap.xxx","bos21.site","boyfuck.me","brian70.tw","brides.com","brillen.de","brmovies.*","brstej.com","btvplus.bg","byrdie.com","bztube.com","calvyn.com","camflow.tv","camfox.com","camhoes.tv","camseek.tv","canada.com","capital.de","capital.fr","cashkar.in","cavallo.de","cboard.net","cdn256.xyz","ceesty.com","cekip.site","cerdas.com","cgtips.org","chiefs.com","ciberdvd.*","cimanow.cc","cityam.com","citynow.it","ckxsfm.com","cluset.com","codare.fun","code.world","cola16.app","colearn.id","comtasq.ca","connect.de","cookni.net","cpscan.xyz","creatur.io","cricfree.*","cricfy.net","crictime.*","crohasit.*","csrevo.com","cuatro.com","cubshq.com","cuckold.it","cuevana.is","cuevana3.*","cutnet.net","cwseed.com","d0000d.com","ddownr.com","deezer.com","demooh.com","depedlps.*","desiflix.*","desimms.co","desired.de","destyy.com","dev2qa.com","dfbplay.tv","diaobe.net","disqus.com","djamix.net","djxmaza.in","dloady.com","dnevnik.hr","do-xxx.com","dogecoin.*","dojing.net","domahi.net","donk69.com","doodle.com","dopebox.to","dorkly.com","downev.com","dpstream.*","drivebot.*","driveup.in","driving.ca","drphil.com","dshytb.com","dsmusic.in","dtmaga.com","du-link.in","dvm360.com","dz4up1.com","earncash.*","earnload.*","easysky.in","ebc.com.br","ebony8.com","ebookmed.*","ebuxxx.net","edmdls.com","egyup.live","elmundo.es","embed.casa","embedv.net","emsnow.com","emurom.net","epainfo.pl","eplayvid.*","eplsite.uk","erofus.com","erotom.com","eroxia.com","evileaks.*","evojav.pro","ewybory.eu","exeygo.com","exnion.com","express.de","f1livegp.*","f1stream.*","f2movies.*","fabmx1.com","fakaza.com","fake-it.ws","falpus.com","familie.de","fandom.com","fapcat.com","fapdig.com","fapeza.com","fapset.com","faqwiki.us","fastly.net","fautsy.com","fboxtv.com","fbstream.*","festyy.com","ffmovies.*","fhedits.in","fikfak.net","fikiri.net","fikper.com","filedown.*","filemoon.*","fileone.tv","filesq.net","film1k.com","film4e.com","filmi7.net","filmovi.ws","filmweb.pl","filmyfly.*","filmygod.*","filmyhit.*","filmypur.*","filmywap.*","finanzen.*","finclub.in","fitbook.de","flickr.com","flixbaba.*","flixhub.co","flybid.net","fmembed.cc","forgee.xyz","formel1.de","foxnxx.com","freeload.*","freenet.de","freevpn.us","friars.com","frogogo.ru","fsplayer.*","fstore.biz","fuckdy.com","fullreal.*","fulltube.*","fullxh.com","funzen.net","funztv.com","fuxnxx.com","fxporn69.*","fzmovies.*","gadgets.es","game5s.com","gamenv.net","gamepro.de","gatcha.org","gawbne.com","gaydam.net","gcloud.cfd","gdfile.org","gdmax.site","gdplayer.*","gentside.*","gestyy.com","giants.com","gifans.com","giff.cloud","gigaho.com","givee.club","gkbooks.in","gkgsca.com","gleaks.pro","gledaitv.*","gmenhq.com","gnomio.com","go.tlc.com","gocast.pro","gochyu.com","goduke.com","goeags.com","goegoe.net","gofilmes.*","goflix.sbs","gogodl.com","gogoplay.*","gogriz.com","gomovies.*","google.com","gopack.com","gostream.*","goutsa.com","gozags.com","gozips.com","gplinks.co","grasta.net","gtaall.com","gunauc.net","haddoz.net","hamburg.de","hamzag.com","hanauer.de","hanime.xxx","hardsex.cc","harley.top","hartico.tv","haustec.de","haxina.com","hcbdsm.com","hclips.com","hd-tch.com","hdfriday.*","hdporn.net","hdtoday.cc","hdtoday.tv","hdzone.org","health.com","hechos.net","hentaihd.*","hentaisd.*","hextank.io","hhkungfu.*","hianime.to","himovies.*","hitprn.com","hivelr.com","hl-live.de","hoca4u.com","hoca4u.xyz","hostxy.com","hotmasti.*","hotovs.com","house.porn","how2pc.com","howifx.com","hqbang.com","huavod.com","huavod.net","huavod.top","hub2tv.com","hubcdn.vip","hubdrive.*","huoqwk.com","hydracdn.*","icegame.ro","iceporn.tv","idevice.me","idlixvip.*","igay69.com","illink.net","ilmeteo.it","imag-r.com","imgair.net","imgbox.com","imgbqb.sbs","imginn.com","imgmgf.sbs","imgpke.sbs","imguee.sbs","indeed.com","indobo.com","inertz.org","infulo.com","ingles.com","ipamod.com","iplark.com","ironysub.*","isgfrm.com","issuya.com","itdmusic.*","iumkit.net","iusm.co.kr","iwcp.co.uk","jakondo.ru","japgay.com","japscan.ws","jav-fun.cc","jav-xx.com","jav.direct","jav247.top","jav380.com","javbee.vip","javbix.com","javboys.tv","javbull.tv","javdo.cc>>","javembed.*","javfan.one","javfav.com","javfc2.xyz","javgay.com","javhdz.*>>","javhub.net","javhun.com","javlab.net","javmix.app","javmvp.com","javneon.tv","javnew.net","javopen.co","javpan.net","javpas.com","javplay.me","javqis.com","javrip.net","javroi.com","javseen.tv","javsek.net","jnews5.com","jobsbd.xyz","joktop.com","joolinks.*","josemo.com","jpgames.de","jpvhub.com","jrlinks.in","jytechs.in","kaamuu.cfd","kaliscan.*","kamelle.de","kaotic.com","kaplog.com","katlinks.*","kedoam.com","keepvid.pw","kejoam.com","kelaam.com","kendam.com","kenzato.uk","kerapoxy.*","keroseed.*","key-hub.eu","kiaclub.cz","kickass2.*","kickasst.*","kickassz.*","king-pes.*","kinobox.cz","kinoger.re","kinoger.ru","kinoger.to","kjmx.rocks","kkickass.*","klooam.com","klyker.com","kochbar.de","kompas.com","kompiko.pl","kotaku.com","kropic.com","kvador.com","kxbxfm.com","labgame.io","lacrima.jp","larazon.es","leakav.com","leeapk.com","leechall.*","leet365.cc","leolist.cc","lewd.ninja","lglbmm.com","lidovky.cz","likecs.com","line25.com","link1s.com","linkbin.me","linkpoi.me","linkshub.*","linkskat.*","linksly.co","linkspy.cc","linkz.wiki","liquor.com","listatv.pl","live7v.com","livehere.*","livetvon.*","lollty.pro","lookism.me","lootdest.*","lopers.com","love4u.net","loveroms.*","lumens.com","lustich.de","lxmanga.my","m2list.com","macwelt.de","magnetdl.*","mahfda.com","mandai.com","mangago.me","mangaraw.*","mangceh.cc","manwan.xyz","mascac.org","mat6tube.*","mathdf.com","maths.news","maxicast.*","medibok.se","megadb.net","megadede.*","megaflix.*","megafly.in","megalink.*","megaup.net","megaurl.in","megaxh.com","meltol.net","meong.club","merinfo.se","mhdtvmax.*","milfzr.com","mitaku.net","mixdroop.*","mlbb.space","mma-core.*","mmnm.store","mmopeon.ru","mmtv01.xyz","molotov.tv","mongri.net","motchill.*","movibd.com","movie123.*","movie4me.*","moviegan.*","moviehdf.*","moviemad.*","movies07.*","movies2k.*","movies4u.*","movies7.to","moviflex.*","movix.blog","mozkra.com","mp3cut.net","mp3guild.*","mp3juice.*","mreader.co","mrpiracy.*","mtlurb.com","mult34.com","multics.eu","multiup.eu","multiup.io","musichq.cc","my-subs.co","mydaddy.cc","myjest.com","mykhel.com","mylust.com","myplexi.fr","myqqjd.com","myvideo.ge","myviid.com","naasongs.*","nackte.com","naijal.com","nakiny.com","namasce.pl","namemc.com","nbabite.to","nbaup.live","ncdnx3.xyz","negumo.com","neonmag.fr","neoteo.com","neowin.net","netfree.cc","newhome.de","newpelis.*","news18.com","newser.com","nexdrive.*","nflbite.to","ngelag.com","ngomek.com","ngomik.net","nhentai.io","nickles.de","niyaniya.*","nmovies.cc","noanyi.com","nocfsb.com","nohost.one","nosteam.ro","note1s.com","notube.com","novinky.cz","noz-cdn.de","nsfw247.to","nswrom.com","ntucgm.com","nudes7.com","nullpk.com","nuroflix.*","nxbrew.net","nxprime.in","nypost.com","odporn.com","odtmag.com","ofwork.net","ohorse.com","ohueli.net","okleak.com","okmusi.com","okteve.com","onehack.us","oneotv.com","onepace.co","onepunch.*","onezoo.net","onloop.pro","onmovies.*","onvista.de","openload.*","oploverz.*","origami.me","orirom.com","otomoto.pl","owsafe.com","paminy.com","papafoot.*","parade.com","parents.at","pbabes.com","pc-guru.it","pcbeta.com","pcgames.de","pctfenix.*","pcworld.es","pdfaid.com","peetube.cc","people.com","petbook.de","phc.web.id","phim85.com","picmsh.sbs","pictoa.com","pilsner.nu","pingit.com","pirlotv.mx","pitube.net","pixelio.de","pixvid.org","plaion.com","planhub.ca","playboy.de","playfa.com","playgo1.cc","plc247.com","plejada.pl","poapan.xyz","pondit.xyz","poophq.com","popcdn.day","poplinks.*","poranny.pl","porn00.org","porndr.com","pornfd.com","porngo.com","porngq.com","pornhd.com","pornhd8k.*","pornky.com","porntb.com","porntn.com","pornve.com","pornwex.tv","pornx.tube","pornxp.com","pornxp.org","pornxs.com","pouvideo.*","povvideo.*","povvldeo.*","povw1deo.*","povwideo.*","powder.com","powlideo.*","powv1deo.*","powvibeo.*","powvideo.*","powvldeo.*","premid.app","progfu.com","prosongs.*","proxybit.*","proxytpb.*","prydwen.gg","psychic.de","pudelek.pl","puhutv.com","putlog.net","qqxnxx.com","qrixpe.com","qthang.net","quicomo.it","radio.zone","raenonx.cc","rakuten.tv","ranker.com","rawinu.com","rawlazy.si","realgm.com","rebahin.pw","redfea.com","redgay.net","reeell.com","regio7.cat","rencah.com","reshare.pm","rgeyyddl.*","rgmovies.*","riazor.org","rlxoff.com","rmdown.com","roblox.com","rodude.com","romsget.io","ronorp.net","roshy.tv>>","rsrlink.in","rule34.art","rule34.xxx","rule34.xyz","rule34ai.*","rumahit.id","s1p1cd.com","s2dfree.to","s3taku.com","sakpot.com","samash.com","savego.org","sawwiz.com","sbrity.com","sbs.com.au","scribd.com","sctoon.net","scubidu.eu","seeflix.to","serien.cam","seriesly.*","sevenst.us","sexato.com","sexjobs.es","sexkbj.com","sexlist.tv","sexodi.com","sexpin.net","sexpox.com","sexrura.pl","sextor.org","sextvx.com","sfile.mobi","shahid4u.*","shinden.pl","shineads.*","shlink.net","sholah.net","shophq.com","shorttey.*","shortx.net","shortzzy.*","showflix.*","shrink.icu","shrinkme.*","shrt10.com","sibtok.com","sikwap.xyz","silive.com","simpcity.*","skmedix.pl","smoner.com","smsget.net","snbc13.com","snopes.com","snowmtl.ru","soap2day.*","socebd.com","sohot.cyou","sokobj.com","solewe.com","sourds.net","soy502.com","spiegel.de","spielen.de","sportal.de","sportbar.*","sports24.*","srvy.ninja","ssdtop.com","sshkit.com","ssyou.tube","stardima.*","stemplay.*","stiletv.it","stpm.co.uk","strcloud.*","streamsb.*","streamta.*","strefa.biz","suaurl.com","sunhope.it","surfer.com","szene38.de","tapetus.pl","target.com","taxi69.com","tcpvpn.com","tech8s.net","techhx.com","telerium.*","texte.work","th-cam.com","thatav.net","theacc.com","thecut.com","thedaddy.*","theproxy.*","thevidhd.*","thosa.info","thothd.com","thripy.com","tickzoo.tv","tiscali.it","tktube.com","tokuvn.com","tokuzl.net","toorco.com","topito.com","toppng.com","torlock2.*","torrent9.*","tranny.one","trust.zone","trzpro.com","tsubasa.im","tsz.com.np","tubesex.me","tubous.com","tubsexer.*","tubtic.com","tugaflix.*","tulink.org","tumblr.com","tunein.com","turbovid.*","tutelehd.*","tutsnode.*","tutwuri.id","tuxnews.it","tv0800.com","tvline.com","tvnz.co.nz","tvtoday.de","twatis.com","uctnew.com","uindex.org","uiporn.com","unito.life","uol.com.br","up-load.io","upbaam.com","updato.com","updown.cam","updown.fun","updown.icu","upfion.com","upicsz.com","uplinkto.*","uploadev.*","uploady.io","uporno.xxx","uprafa.com","ups2up.fun","upskirt.tv","uptobhai.*","uptomega.*","urlpay.net","usagoals.*","userload.*","usgate.xyz","usnews.com","ustimz.com","ustream.to","utreon.com","uupbom.com","vadbam.com","vadbam.net","vadbom.com","vbnmll.com","vcloud.lol","vdbtm.shop","vecloud.eu","veganab.co","veplay.top","vevioz.com","vgames.fun","vgmlinks.*","vidapi.xyz","vidbam.org","vidbox.dev","vidcloud.*","vidcorn.to","vidembed.*","videyx.cam","videzz.net","vidlii.com","vidnest.io","vidohd.com","vidomo.xyz","vidoza.net","vidply.com","viduro.top","viduyy.com","viewfr.com","vinomo.xyz","vipboxtv.*","vipotv.com","vipstand.*","vivatube.*","vizcloud.*","vortez.net","vrporn.com","vsembed.su","vstream.id","vvide0.com","vvtlinks.*","wapkiz.com","warps.club","watch32.sx","watch4hd.*","watcho.com","watchug.to","watchx.top","wawacity.*","weather.us","web1s.asia","webcafe.bg","weloma.art","weshare.is","weszlo.com","wetter.com","wetter3.de","wikwiki.cv","wintub.com","woiden.com","wooflix.tv","worder.cat","woxikon.de","wpgh53.com","ww9g.com>>","www.cc.com","x-x-x.tube","xanimu.com","xasiat.com","xberuang.*","xhamster.*","xhopen.com","xhspot.com","xhtree.com","xhvid1.com","xiaopan.co","xmorex.com","xmovie.pro","xmovies8.*","xnxx.party","xpicse.com","xprime4u.*","xrares.com","xsober.com","xspiel.com","xsz-av.com","xszav.club","xvideis.cc","xxgasm.com","xxmovz.com","xxxdan.com","xxxfiles.*","xxxmax.net","xxxrip.net","xxxsex.pro","xxxtik.com","xxxtor.com","xxxxsx.com","y-porn.com","y2mate.com","y2tube.pro","ymknow.xyz","yomovies.*","youapk.net","youmath.it","youpit.xyz","youwatch.*","yseries.tv","ytanime.tv","ytboob.com","ytjar.info","ytmp4.live","yts-subs.*","yumacs.com","yuppow.com","yuvutu.com","yy1024.net","z12z0vla.*","zeefiles.*","zilinak.sk","zillow.com","zoechip.cc","zoechip.gg","zpaste.net","zthots.com","0123movie.*","0gomovies.*","0rechner.de","10alert.com","111watcho.*","11xmovies.*","123animes.*","123movies.*","12thman.com","141tube.com","173.249.8.3","17track.net","18comic.vip","1movieshd.*","1moviesz.to","1xanimes.in","2gomovies.*","2rdroid.com","3bmeteo.com","3dyasan.com","3hentai.net","3xfaktor.hu","423down.com","4funbox.com","4gousya.net","4players.de","4shared.com","4spaces.org","4tymode.win","5j386s9.sbs","69games.xxx","7review.com","7starmv.com","80-talet.se","8tracks.com","9animetv.to","9goals.live","9jarock.org","a-hentai.tv","aagmaal.com","abs-cbn.com","abstream.to","ad-doge.com","ad4msan.com","adictox.com","adisann.com","adshrink.it","afilmywap.*","africue.com","afrodity.sk","ahmedmode.*","aiailah.com","aipebel.com","akirabox.to","allkpop.com","almofed.com","almursi.com","altcryp.com","alttyab.net","analdin.com","anavidz.com","andiim3.com","anibatch.me","anichin.top","anigogo.net","animahd.com","anime-i.com","anime3d.xyz","animeblix.*","animebr.org","animecix.tv","animehay.tv","animehub.ac","animepahe.*","animesex.me","anisaga.org","anitube.vip","aniworld.to","anomize.xyz","anonymz.com","anxcinema.*","anyporn.com","anysex.club","aofsoru.com","aosmark.com","apekite.com","apkdink.com","apkhihe.com","apkshrt.com","apksvip.com","aplus.my.id","app.plex.tv","apritos.com","aquipelis.*","arabstd.com","arabxnx.com","arakpop.net","arbweb.info","area51.porn","arenabg.com","arkadmin.fr","artnews.com","asia2tv.com","asianal.xyz","asianclub.*","asiangay.tv","asianload.*","asianplay.*","ask4movie.*","asmr18.fans","asmwall.com","asumesi.com","ausfile.com","auszeit.bio","autobild.de","autokult.pl","automoto.it","autopixx.de","autoroad.cz","autosport.*","avcesar.com","avitter.net","axomtube.in","ayatoon.com","azmath.info","azmovies.to","b2bhint.com","b4ucast.com","babaktv.com","babeswp.com","babyclub.de","badjojo.com","badtaste.it","barfuck.com","batman.city","bbwfest.com","bcmanga.com","bdcraft.net","bdmusic23.*","bdmusic28.*","bdsmporn.cc","beelink.pro","beinmatch.*","bengals.com","berich8.com","berklee.edu","bfclive.com","bg-gledai.*","bi-girl.net","bigconv.com","bigojav.com","bigshare.io","bigwank.com","bikemag.com","bitco.world","bitlinks.pw","bitzite.com","blog4nx.com","blogue.tech","blu-ray.com","blurayufr.*","bokepxv.com","bolighub.dk","bollyflix.*","book18.fans","bootdey.com","botrix.live","bowfile.com","boxporn.net","braflix.win","brbeast.com","brbushare.*","brigitte.de","bristan.com","browser.lol","bsierad.com","btcbitco.in","btvsport.bg","btvsports.*","buondua.com","buzzfeed.at","buzzfeed.de","buzzpit.net","bx-zone.com","bypass.city","bypass.link","cafenau.com","camclips.tv","camel3.live","camsclips.*","camslib.com","camwhores.*","canaltdt.es","carbuzz.com","ch-play.com","chatgbt.one","chatgpt.com","chefkoch.de","chicoer.com","chochox.com","cima-club.*","cinecloud.*","cinefreak.*","civitai.com","civitai.red","claimrbx.gg","clapway.com","clkmein.com","cloubix.com","cloudfam.io","club386.com","cocorip.net","coldfrm.org","collater.al","colnect.com","comicxxx.eu","commands.gg","comnuan.com","comohoy.com","converto.io","coomer1.net","corneey.com","corriere.it","cpmlink.net","cpmlink.pro","crackle.com","crazydl.net","crdroid.net","crvsport.ru","csurams.com","cubuffs.com","cuevana.pro","cupra.forum","cut-fly.com","cutearn.net","cutlink.net","cutpaid.com","cutyion.com","daddyhd.*>>","daddylive.*","daftsex.biz","daftsex.net","daftsex.org","daij1n.info","dailyweb.pl","damitv.live","daozoid.com","dawenet.com","ddlvalley.*","decrypt.day","deltabit.co","devotag.com","dexerto.com","digit77.com","digitask.ru","direct-dl.*","discord.com","disheye.com","diudemy.com","divxtotal.*","dj-figo.com","djqunjab.in","dlpanda.com","dlstreams.*","dma-upd.org","dogdrip.net","donlego.com","dotycat.com","doumura.com","douploads.*","downsub.com","dozarte.com","dramacool.*","dramamate.*","dramanice.*","drawize.com","droplink.co","ds2play.com","dsharer.com","dstat.space","dsvplay.com","duboku.info","dudefilms.*","dz4link.com","e-glossa.it","e2link.link","earnbee.xyz","earnhub.net","easy-coin.*","easybib.com","ebookdz.com","echiman.com","echodnia.eu","ecomento.de","edjerba.com","eductin.com","einthusan.*","elahmad.com","embasic.pro","embedhd.org","embedmoon.*","embedpk.net","embedtv.net","empflix.com","emuenzen.de","enagato.com","eoreuni.com","eporner.com","eroasmr.com","erothots.co","erowall.com","esgeeks.com","eshentai.tv","eskarock.pl","eslfast.com","europixhd.*","everand.com","everia.club","everyeye.it","exalink.fun","exeking.top","ezmanga.net","f51rm.com>>","fapdrop.com","fapguru.com","faptube.com","farescd.com","fastdokan.*","fastream.to","fastssh.com","fbstreams.*","fchopin.net","fembedx.top","feyorra.top","fffmovies.*","figtube.com","file-me.top","file-up.org","file4go.com","file4go.net","filecloud.*","filecrypt.*","filelions.*","filemooon.*","filepress.*","fileq.games","filesamba.*","filmcdn.top","filmisub.cc","films5k.com","filmy-hit.*","filmy4web.*","filmydown.*","filmygod6.*","findjav.com","firefile.cc","fit4art.com","flixrave.me","flixsix.com","flixtor.mov","flixzone.co","fluentu.com","fluvore.com","fmovies0.cc","fmoviesto.*","folkmord.se","foodxor.com","footybite.*","forumdz.com","foumovies.*","foxtube.com","freenem.com","freepik.com","frpgods.com","fseries.org","fsx.monster","ftuapps.dev","fuckfuq.com","futemax.zip","g-porno.com","gal-dem.com","gamcore.com","game-2u.com","game3rb.com","gameblog.in","gameblog.jp","gamehub.cam","gamelab.com","gamer18.net","gamestar.de","gameswelt.*","gametop.com","gamewith.jp","gamezone.de","gamezop.com","garaveli.de","gaytail.com","gayvideo.me","gazzetta.gr","gazzetta.it","gcloud.live","gedichte.ws","genialne.pl","get-to.link","getmega.net","getthit.com","gevestor.de","gezondnu.nl","ggbases.com","girlmms.com","girlshd.xxx","gisarea.com","gitizle.vip","gizmodo.com","globetv.app","go.fakta.id","go.zovo.ink","goalup.live","gobison.com","gocards.com","gocast2.com","godeacs.com","godmods.com","godtube.com","goducks.com","gofilms4u.*","gofrogs.com","gogifox.com","gogoanime.*","goheels.com","gojacks.com","gokerja.net","gold-24.net","golobos.com","gomovies.pk","gomoviesc.*","goodporn.to","gooplay.net","gorating.in","gosexy.mobi","gostyn24.pl","goto.com.np","gotocam.net","gotporn.com","govexec.com","grafikos.cz","gsmware.com","guhoyas.com","gulf-up.com","gupload.xyz","h-flash.com","haaretz.com","hagalil.com","hagerty.com","hardgif.com","hartziv.org","haxmaps.com","haxnode.net","hblinks.pro","hdbraze.com","hdeuropix.*","hdmotori.it","hdonline.co","hdpicsx.com","hdpornt.com","hdtodayz.to","hdtube.porn","helmiau.com","hentai20.io","hentaila.tv","herexxx.com","herzporno.*","hes-goals.*","hexload.com","hhdmovies.*","himovies.sx","hindi.trade","hiphopa.net","history.com","hitokin.net","hmanga.asia","holavid.com","hoofoot.net","hoporno.net","hornpot.net","hornyfap.tv","hotabis.com","hotbabes.tv","hotcars.com","hotfm.audio","hotgirl.biz","hotleak.vip","hotleaks.tv","hotscope.tv","hotscopes.*","hotshag.com","hotstar.com","huaren.live","hubdrive.de","hubison.com","hubstream.*","hubzter.com","hungama.com","hurawatch.*","huskers.com","huurshe.com","hwreload.it","hygiena.com","hypesol.com","icgaels.com","idlixku.com","iegybest.co","iframejav.*","iggtech.com","iimanga.com","iklandb.com","imageweb.ws","imgbvdf.sbs","imgjjtr.sbs","imgnngr.sbs","imgoebn.sbs","imgoutlet.*","imgtaxi.com","imgyhq.shop","impact24.us","in91vip.win","infocorp.io","infokik.com","inkapelis.*","instyle.com","inverse.com","ipa-apps.me","iporntv.net","iptvbin.com","isaimini.ca","isosite.org","ispunlock.*","itpro.co.uk","itudong.com","iv-soft.com","jaguars.com","jaiefra.com","japanfuck.*","japanporn.*","japansex.me","japscan.lol","javbake.com","javball.com","javbobo.com","javboys.com","javcock.com","javdock.com","javdoge.com","javfull.net","javgrab.com","javhoho.com","javideo.net","javlion.xyz","javmenu.com","javmeta.com","javmilf.xyz","javpool.com","javsex.guru","javstor.com","javx357.com","javynow.com","jcutrer.com","jeep-cj.com","jetanimes.*","jetpunk.com","jezebel.com","jkanime.net","jnovels.com","jobsibe.com","jocooks.com","jotapov.com","jpg.fishing","jra.jpn.org","jungyun.net","jxoplay.xyz","karanpc.com","kashtanka.*","kb.arlo.com","khohieu.com","kiaporn.com","kickassgo.*","kiemlua.com","kimoitv.com","kinoking.cc","kissanime.*","kissasia.cc","kissasian.*","kisscos.net","kissmanga.*","kjanime.net","klettern.de","kmansin09.*","kochamjp.pl","kodaika.com","kolyoom.com","komikcast.*","kompoz2.com","kpkuang.org","kppk983.com","ksuowls.com","l23movies.*","l2crypt.com","labstory.in","laposte.net","lapresse.ca","lastampa.it","latimes.com","latitude.to","lbprate.com","leaknud.com","letest25.co","letras2.com","lewdweb.net","lewebde.com","lfpress.com","lgcnews.com","lgwebos.com","libertyvf.*","lifeline.de","liflix.site","ligaset.com","likemag.com","linclik.com","link-to.net","linkmake.in","linkrex.net","links-url.*","linksfire.*","linkshere.*","linksmore.*","lite-link.*","loanpapa.in","lokalo24.de","lookimg.com","lookmovie.*","losmovies.*","losporn.org","lostineu.eu","lovefap.com","lrncook.xyz","lscomic.com","luluvdo.com","luluvid.com","luxmovies.*","m.akkxs.net","m.iqiyi.com","m1xdrop.com","m1xdrop.net","m4maths.com","made-by.org","madoohd.com","madouqu.com","magesy.blog","magesypro.*","mamastar.jp","manga1000.*","manga1001.*","mangahub.io","mangasail.*","mangatv.net","mangayy.org","manhwa18.cc","maths.media","mature4.net","mavanimes.*","mavavid.com","maxstream.*","mcdlpit.com","mchacks.net","mcloud.guru","mcxlive.org","medisite.fr","mega1080p.*","megafile.io","megavideo.*","mein-mmo.de","melodelaa.*","mephimtv.cc","mercari.com","messitv.net","messitv.org","metavise.in","mgoblue.com","mhdsports.*","mhscans.com","miklpro.com","mirrorace.*","mirrored.to","mlbstream.*","mmfenix.com","mmsmaza.com","mobifuq.com","moenime.com","momomesh.tv","momondo.com","momvids.com","moonembed.*","moonmov.pro","motohigh.pl","motphimr.io","moviebaaz.*","movied.link","movieku.ink","movieon21.*","movieplay.*","movieruls.*","movierulz.*","movies123.*","movies4me.*","movies4u3.*","moviesda4.*","moviesden.*","movieshub.*","moviesjoy.*","moviesmod.*","moviesmon.*","moviesub.is","moviesx.org","moviewr.com","moviezwap.*","movizland.*","mp3-now.com","mp3juices.*","mp3yeni.org","mp4moviez.*","mpo-mag.com","mr9soft.com","mrexcel.com","mrunblock.*","mtb-news.de","mtlblog.com","muchfap.com","multiup.org","muthead.com","muztext.com","mycloudz.cc","myflixer.bz","myflixerz.*","mygalls.com","mymp3song.*","mytoolz.net","myunity.dev","myvalley.it","myvidmate.*","myxclip.com","narcity.com","nbabox.co>>","nbastream.*","nbch.com.ar","nbcnews.com","needbux.com","needrom.com","nekopoi.*>>","nelomanga.*","nemenlake.*","netfapx.com","netflix.com","netfuck.net","netplayz.ru","netxwatch.*","netzwelt.de","newscon.org","newsmax.com","nextgov.com","nflbite.com","nflstream.*","nhentai.net","nhlstream.*","nicekkk.com","nichapk.com","nimegami.id","nkreport.jp","notandor.cn","novelism.jp","novohot.com","novojoy.com","nowiny24.pl","nowmovies.*","nrj-play.fr","nsfwr34.com","nudevista.*","nulakers.ca","nunflix.org","nyahentai.*","nysainfo.pl","odiasia.sbs","ofilmywap.*","ogomovies.*","ohentai.org","ohmymag.com","okstate.com","olamovies.*","olarila.com","omuzaani.me","onhockey.tv","onifile.com","onneddy.com","ontools.net","onworks.net","optimum.net","ortograf.pl","osxinfo.net","otakudesu.*","otakuindo.*","outletpic.*","overgal.com","overtake.gg","ovester.com","oxanime.com","p2pplay.pro","packers.com","pagesix.com","paketmu.com","pantube.top","papahd.club","papalah.com","paradisi.de","parents.com","parispi.net","pasokau.com","payskip.org","pcbolsa.com","pcgamer.com","pdfdrive.to","pdfsite.net","pelisplus.*","peppe8o.com","perelki.net","pesktop.com","pewgame.com","pezporn.com","phim1080.in","pianmanga.*","picbqqa.sbs","picnft.shop","picngt.shop","picuenr.sbs","pilot.wp.pl","pinkporno.*","pinterest.*","piratebay.*","pistona.xyz","pitiurl.com","pixjnwe.sbs","pixsera.net","pksmovies.*","pkspeed.net","play.tv3.ee","play.tv3.lt","play.tv3.lv","playrust.io","playtamil.*","playtube.tv","plus.rtl.de","pngitem.com","pngreal.com","pogolinks.*","pokopow.com","polygon.com","pomorska.pl","porcore.com","porn3dx.com","porn77.info","porn78.info","porndaa.com","porndex.com","porndig.com","porndoe.com","porndude.tv","porngem.com","porngun.net","pornhex.com","pornhub.com","pornkai.com","pornken.com","pornkino.cc","pornktube.*","pornmam.com","pornmom.net","porno-365.*","pornoman.pl","pornomoll.*","pornone.com","pornovka.cz","pornpaw.com","pornsai.com","porntin.com","porntry.com","pornult.com","poscitech.*","povvvideo.*","powstream.*","powstreen.*","ppatour.com","primesrc.me","primewire.*","prisjakt.no","promobil.de","pronpic.org","pulpo69.com","pupuweb.com","purplex.app","putlocker.*","pvip.gratis","pxtech.site","qdembed.com","quizack.com","quizlet.com","radamel.icu","raiders.com","rainanime.*","raw1001.net","rawkuma.com","rawkuma.net","rawkuro.net","readfast.in","readmore.de","realbbc.xyz","redgifs.com","redlion.net","redporno.cz","redtub.live","redwap2.com","redwap3.com","reifporn.de","rekogap.xyz","repelis.net","repelisgt.*","repelishd.*","repelisxd.*","repicsx.com","resetoff.pl","rethmic.com","retrotv.org","reuters.com","reverso.net","riedberg.tv","rimondo.com","rl6mans.com","rlshort.com","roadbike.de","rocklink.in","romfast.com","romsite.org","romviet.com","rphangx.net","rpmplay.xyz","rpupdate.cc","rsgamer.app","rubystm.com","rubyvid.com","rugby365.fr","runmods.com","ryxy.online","s0ft4pc.com","saekita.com","safelist.eu","sandrives.*","sankaku.app","sansat.link","sararun.net","sat1gold.de","satcesc.com","savelinks.*","savemedia.*","savetub.com","sbbrisk.com","sbchill.com","scenedl.org","scenexe2.io","schadeck.eu","scripai.com","sdefx.cloud","seclore.com","secuhex.com","see-xxx.com","semawur.com","sembunyi.in","sendvid.com","seoworld.in","serengo.net","serially.it","seriemega.*","seriesflv.*","seselah.com","sexavgo.com","sexdiaryz.*","sexemix.com","sexetag.com","sexmoza.com","sexpuss.org","sexrura.com","sexsaoy.com","sexuhot.com","sexygirl.cc","shaheed4u.*","sharclub.in","sharedisk.*","sharing.wtf","shavetape.*","shortearn.*","shrinkus.tk","shrlink.top","simsdom.com","siteapk.net","sitepdf.com","sixsave.com","smarturl.it","smplace.com","snaptik.app","socks24.org","soft112.com","softrop.com","solobari.it","soninow.com","sosuroda.pl","soundpark.*","souqsky.net","southpark.*","spambox.xyz","spankbang.*","speedporn.*","spinbot.com","sporcle.com","sport365.fr","sportbet.gr","sportcast.*","sportlive.*","sportshub.*","spycock.com","srcimdb.com","ssoap2day.*","ssrmovies.*","staaker.com","stagatv.com","starmusiq.*","steamplay.*","steanplay.*","sterham.net","stickers.gg","stmruby.com","strcloud.in","streamcdn.*","streamed.su","streamers.*","streamhoe.*","streamhub.*","streamix.so","streamm4u.*","streamup.ws","strikeout.*","subdivx.com","subedlc.com","submilf.com","subsvip.com","sukuyou.com","sundberg.ws","sushiscan.*","swatalk.com","t-online.de","tabootube.*","tagblatt.ch","takimag.com","tamilyogi.*","tandess.com","taodung.com","tattle.life","tcheats.com","tdtnews.com","teachoo.com","teamkong.tk","techbook.de","techforu.in","technews.tw","tecnomd.com","telenord.it","telorku.xyz","teltarif.de","tempr.email","terabox.fun","teralink.me","testedich.*","texw.online","thapcam.net","thaript.com","thelanb.com","therams.com","theroot.com","thespun.com","thestar.com","thisvid.com","thotcity.su","thotporn.tv","thotsbay.tv","threads.com","threads.net","tikmate.app","tinys.click","titantv.com","tnaflix.com","todaypktv.*","tonspion.de","toolxox.com","toonanime.*","toonily.com","topgear.com","topmovies.*","topshare.in","topsport.bg","totally.top","toxicwap.us","trahino.net","tranny6.com","trgtkls.org","tribuna.com","trickms.com","trilog3.net","tromcap.com","trxking.xyz","tryvaga.com","ttsfree.com","tubator.com","tube18.sexy","tuberel.com","tubsxxx.com","tukoz.com>>","turkanime.*","turkmmo.com","tutflix.org","tutvlive.ru","tv-media.at","tv.bdix.app","tvableon.me","tvseries.in","tw-calc.net","twitchy.com","twitter.com","ubbulls.com","ucanwatch.*","ufcstream.*","uhdmovies.*","uiiumovie.*","uknip.co.uk","umterps.com","unblockit.*","uozzart.com","updown.link","upfiles.app","uploadbaz.*","uploadhub.*","uploadrar.*","upns.online","uproxy2.biz","uprwssp.org","upstore.net","upstream.to","uptime4.com","uptobox.com","urdubolo.pk","usfdons.com","usgamer.net","ustvgo.live","uyeshare.cc","v2movies.me","v6embed.xyz","vague.style","variety.com","vaughn.live","vectorx.top","vedshar.com","vegamovie.*","ver-pelis.*","verizon.com","veronica.uk","vexfile.com","vexmovies.*","vf-film.net","vgamerz.com","vidbeem.com","vidcloud9.*","videezy.com","vidello.net","videovard.*","videoxxx.cc","videplay.us","videq.cloud","vidfast.pro","vidlink.pro","vidload.net","vidshar.org","vidshare.tv","vidspeed.cc","vidstream.*","vidtube.one","vikatan.com","vikings.com","vip-box.app","vipifsa.com","vipleague.*","vipracing.*","vipshort.in","vipstand.se","viptube.com","virabux.com","visalist.io","visible.com","viva100.com","vixcloud.co","vizcloud2.*","vkprime.com","voirfilms.*","voyeurhit.*","vrcmods.com","vstdrive.in","vulture.com","vvtplayer.*","vw-page.com","w.grapps.me","waploaded.*","watchfree.*","watchporn.*","wavewalt.me","wayfair.com","wcostream.*","weadown.com","weather.com","webcras.com","webfail.com","webtoon.xyz","weights.com","wetsins.com","weviral.org","wgzimmer.ch","why-tech.it","wildwap.com","winshell.de","wintotal.de","wmovies.xyz","woffxxx.com","wonporn.com","wowroms.com","wupfile.com","wvt.free.nf","www.msn.com","x-x-x.video","x.ag2m2.cfd","xemales.com","xflixbd.com","xforum.live","xfreehd.com","xgroovy.com","xhamster.fm","xhamster1.*","xhamster2.*","xhamster3.*","xhamster4.*","xhamster5.*","xhamster7.*","xhamster8.*","xhmoon5.com","xhreal2.com","xhreal3.com","xhtotal.com","xhwide5.com","xmateur.com","xmovies08.*","xnxxcom.xyz","xozilla.xxx","xpicu.store","xpornzo.com","xpshort.com","xsanime.com","xubster.com","xvideos.com","xx.knit.bid","xxxmomz.com","xxxmovies.*","xztgl.com>>","y-2mate.com","y2meta.mobi","yalifin.xyz","yamsoti.com","yesmovies.*","yestech.xyz","yifysub.net","ymovies.vip","yomovies1.*","yoshare.net","youshort.me","youtube.com","yoxplay.xyz","yt2conv.com","ytmp3cc.net","ytsubme.com","yumeost.net","zedporn.com","zemporn.com","zerioncc.pl","zerogpt.com","zetporn.com","ziperto.com","zlpaste.net","zoechip.com","zyromod.com","0123movies.*","0cbcq8mu.com","0l23movies.*","0ochi8hp.com","10-train.com","1024tera.com","103.74.5.104","123-movies.*","1234movies.*","123animes.ru","123moviesc.*","123moviess.*","123unblock.*","1340kbbr.com","16honeys.com","185.53.88.15","18tubehd.com","1fichier.com","1madrasdub.*","1primewire.*","2017tube.com","2cf0xzdu.com","2fb9tsgn.fun","2madrasdub.*","398fitus.com","3gaytube.com","45.86.86.235","456movie.com","4archive.org","4bct9.live>>","4edtcixl.xyz","4fansites.de","4k2h4w04.xyz","4live.online","4movierulz.*","5moviess.com","720pstream.*","7hitmovies.*","8teenxxx.com","a6iqb4m8.xyz","ablefast.com","aboedman.com","absoluporn.*","abysscdn.com","acapellas.eu","adbypass.org","adcrypto.net","addonbiz.com","addtoany.com","adsurfle.com","adultfun.net","aegeanews.gr","afl3ua5u.xyz","afreesms.com","airflix1.com","airliners.de","akinator.com","akirabox.com","alcasthq.com","alexsports.*","aliancapes.*","allcalidad.*","alliptvs.com","allmusic.com","allosurf.net","alotporn.com","alphatron.tv","alrincon.com","alternet.org","amateur8.com","amnaymag.com","amtil.com.au","androidaba.*","anhdep24.com","anime-jl.net","anime3rb.com","animefire.io","animeflv.net","animefreak.*","animelok.xyz","animesanka.*","animeunity.*","animexin.vip","animixplay.*","aninavi.blog","anisubindo.*","anmup.com.np","annabelle.ch","antiadtape.*","antonimos.de","anybunny.com","apetube.asia","apkcombo.com","apkdrill.com","apkmodhub.in","apkprime.org","apkship.shop","apkupload.in","apnablogs.in","app.vaia.com","appsbull.com","appsmodz.com","aranzulla.it","arcaxbydz.id","arkadium.com","arolinks.com","aroratr.club","artforum.com","asiaflix.net","asianporn.li","askim-bg.com","atglinks.com","atgstudy.com","atozmath.com","audiotools.*","audizine.com","autoblog.com","autodime.com","autoembed.cc","autonews.com","autorevue.at","az-online.de","azoranov.com","azores.co.il","b-hentai.com","babesexy.com","babiato.tech","babygaga.com","bagpipe.news","baithak.news","bamgosu.site","bandstand.ph","banned.video","baramjak.com","barchart.com","baritoday.it","batchkun.com","batporno.com","bbyhaber.com","bceagles.com","bclikeqt.com","beemtube.com","beingtek.com","benchmark.pl","bestlist.top","bestwish.lol","biletomat.pl","bilibili.com","biopills.net","biovetro.net","birdurls.com","bitchute.com","bitssurf.com","bittools.net","blog-dnz.com","blogmado.com","blogmura.com","bloground.ro","blwideas.com","bobolike.com","bollydrive.*","bollyshare.*","boltbeat.com","bookfrom.net","bookriot.com","boredbat.com","boundhub.com","boysfood.com","br0wsers.com","braflix.tube","brainzaps.tv","bright-b.com","bsmaurya.com","bubraves.com","buffsports.*","buffstream.*","bugswave.com","bullfrag.com","burakgoc.com","burbuja.info","burnbutt.com","buyjiocoin.*","bysebuho.com","bysekoze.com","bysewihe.com","byswiizen.fr","bz-berlin.de","calbears.com","callfuck.com","camhub.world","camlovers.tv","camporn.tube","camwhores.tv","camwhorez.tv","capoplay.net","cardiagn.com","cariskuy.com","carnewz.site","cashbux.work","casperhd.com","casthill.net","catcrave.com","catholic.com","cbt-tube.net","cctvwiki.com","cdn.vifey.de","celebmix.com","celibook.com","cesoirtv.com","channel4.com","chargers.com","chatango.com","chibchat.com","chopchat.com","choralia.net","chzzkban.xyz","cinedetodo.*","cinemabg.net","cinemaxxl.de","claimbits.io","claimtrx.com","clickapi.net","clicporn.com","clix4btc.com","clockskin.us","closermag.fr","cocogals.com","cocoporn.net","coderblog.in","codesnse.com","coindice.win","coingraph.us","coinsrev.com","collider.com","compsmag.com","compu-pc.com","cool-etv.net","cosmicapp.co","couchtuner.*","coursera.org","cracking.org","crazyblog.in","cricwatch.io","cryptowin.io","cuevana8.com","cut-urls.com","cuts-url.com","cwc.utah.gov","cyberdrop.me","cyberleaks.*","cyclones.com","cyprus.co.il","czechsex.net","da-imnetz.de","daddylive1.*","dafideff.com","dafontvn.com","daftporn.com","dailydot.com","dailysport.*","daizurin.com","daotekno.com","darkibox.com","datacheap.io","datanodes.to","dataporn.pro","datawav.club","dawntube.com","day4news.com","ddlvalley.me","deadline.com","deadspin.com","debridup.com","deckshop.pro","decorisi.com","deepbrid.com","deephot.link","delvein.tech","derwesten.de","descarga.xyz","desi.upn.bio","desihoes.com","desiupload.*","desivideos.*","deviants.com","digimanie.cz","dikgames.com","dir-tech.com","dirproxy.com","dirtyfox.net","dirtyporn.cc","distanta.net","divicast.com","divxtotal1.*","djpunjab2.in","dl-protect.*","dlolcast.pro","dlupload.com","dndsearch.in","dokumen.tips","domahatv.com","doodstream.*","dotabuff.com","doujindesu.*","downloadr.in","drakecomic.*","dreamdth.com","drivefire.co","drivemoe.com","drivers.plus","dropbang.net","dropgalaxy.*","drsnysvet.cz","drublood.com","ds2video.com","dukeofed.org","dumovies.com","duolingo.com","dutchycorp.*","dvd-flix.com","dwlinks.buzz","eastream.net","ecamrips.com","eclypsia.com","edukaroo.com","egram.com.ng","egyanime.com","ehotpics.com","elcultura.pl","electsex.com","elvocero.com","embed4me.com","embedtv.best","emporda.info","endbasic.dev","eng-news.com","engvideo.net","epson.com.cn","eroclips.org","erofound.com","erogarga.com","eropaste.net","eroticmv.com","esportivos.*","estrenosgo.*","estudyme.com","et-invest.de","etonline.com","eurogamer.de","eurogamer.es","eurogamer.it","eurogamer.pt","evernia.site","evfancy.link","ex-foary.com","examword.com","exceljet.net","exe-urls.com","expertvn.com","eymockup.com","ezeviral.com","f1livegp.net","facebook.com","factable.com","fairyhorn.cc","faiviral.com","fansided.com","fansmega.com","fapality.com","fapfappy.com","fartechy.com","fastilinks.*","fat-bike.com","fbsquadx.com","fc2stream.tv","fedscoop.com","feed2all.org","fehmarn24.de","femdomtb.com","ferdroid.net","fileguard.cc","fileguru.net","filemoon.*>>","filerice.com","filescdn.com","filessrc.com","filezipa.com","filmifen.com","filmisongs.*","filmizip.com","filmizletv.*","filmy4wap1.*","filmygod13.*","filmyone.com","filmyzilla.*","financid.com","finevids.xxx","firstonetv.*","fitforfun.de","fivemdev.org","flashbang.sh","flaticon.com","flexy.stream","flexyhit.com","flightsim.to","flixbaba.com","flowsnet.com","flstv.online","flvto.com.co","fm-arena.com","fmoonembed.*","focus4ca.com","footybite.to","forexrw7.com","forogore.com","forplayx.ink","fotopixel.es","freejav.guru","freemovies.*","freemp3.tube","freeshib.biz","freetron.top","freewsad.com","fremdwort.de","freshbbw.com","fruitlab.com","fsileaks.com","fuckmilf.net","fullboys.com","fullcinema.*","fullhd4k.com","fuskator.com","futemais.net","fxpornhd.com","galaxyos.net","game-owl.com","gamebrew.org","gamefast.org","gamekult.com","gamer.com.tw","gamerant.com","gamerxyt.com","games.get.tv","games.wkb.jp","gameslay.net","gameszap.com","gametter.com","gamezizo.com","gamingsym.in","gatagata.net","gay4porn.com","gaystream.pw","gayteam.club","gculopes.com","gelbooru.com","gentside.com","gerbeaud.com","getcopy.link","getitfree.cn","getmodsapk.*","gifcandy.net","gioialive.it","gksansar.com","glo-n.online","globes.co.il","globfone.com","gniewkowo.eu","gnusocial.jp","go2share.net","goanimes.vip","gobadgers.ca","gocast123.me","godzcast.com","gogoanimes.*","gogriffs.com","golancers.ca","gomuraw.blog","gonzoporn.cc","goracers.com","gosexpod.com","gottanut.com","goxavier.com","gplastra.com","grazymag.com","grigtube.com","grosnews.com","gseagles.com","gsmarena.com","gsmhamza.com","guidetnt.com","gurusiana.id","h-game18.xyz","habuteru.com","hachiraw.net","hackshort.me","hackstore.me","halloporno.*","harbigol.com","hbnews24.com","hbrfrance.fr","hdfcfund.com","hdhub4u.fail","hdmoviehub.*","hdmovies23.*","hdmovies4u.*","hdmovies50.*","hdpopcorns.*","hdporn92.com","hdpornos.net","hdvideo9.com","hellmoms.com","helpdice.com","hentai2w.com","hentai4k.com","hentaigo.com","hentaila.com","hentaimoe.me","hentais.tube","hentaitk.net","hentaizm.fun","heqviral.com","hi0ti780.fun","highporn.net","hiperdex.com","hipsonyc.com","hivetoon.com","hmanga.world","hostmath.com","hotmilfs.pro","hqporner.com","hubdrive.com","huffpost.com","hurawatch.cc","hwzone.co.il","hyderone.com","hydrogen.lat","hypnohub.net","ibradome.com","icutlink.com","icyporno.com","idealight.it","idesign.wiki","idntheme.com","iguarras.com","ihdstreams.*","ilovephd.com","ilpescara.it","imagefap.com","imdpu9eq.com","imgadult.com","imgbaron.com","imgblaze.net","imgbnwe.shop","imgbyrev.sbs","imgclick.net","imgdrive.net","imgflare.com","imgfrost.net","imggune.shop","imgjajhe.sbs","imgmffmv.sbs","imgnbii.shop","imgolemn.sbs","imgprime.com","imgqbbds.sbs","imgspark.com","imgthbm.shop","imgtorrnt.in","imgxabm.shop","imgxxbdf.sbs","imintweb.com","indianxxx.us","infodani.net","infofuge.com","informer.com","interssh.com","intro-hd.net","ipacrack.com","ipatriot.com","iptvapps.net","iptvspor.com","iputitas.net","iqksisgw.xyz","isaidub6.net","itainews.com","itz-fast.com","iwanttfc.com","izzylaif.com","jaktsidan.se","jalopnik.com","japanporn.tv","japteenx.com","jav-asia.top","javboys.tv>>","javbraze.com","javguard.xyz","javhahaha.us","javhdz.today","javindo.site","javjavhd.com","javmelon.com","javplaya.com","javplayer.me","javprime.net","javquick.com","javrave.club","javtiful.com","javturbo.xyz","jenpornuj.cz","jeshoots.com","jmzkzesy.xyz","jobfound.org","jobsheel.com","jockantv.com","joymaxtr.net","joziporn.com","jsfiddle.net","jsonline.com","juba-get.com","jujmanga.com","kabeleins.de","kafeteria.pl","kakitengah.*","kamehaus.net","kaoskrew.org","karanapk.com","katmoviehd.*","kattracker.*","kaystls.site","khaddavi.net","khatrimaza.*","khsn1230.com","kickasskat.*","kinisuru.com","kinkyporn.cc","kino-zeit.de","kiss-anime.*","kisstvshow.*","klubsports.*","knowstuff.in","kolcars.shop","kollhong.com","komonews.com","konten.co.id","koramaup.com","kpopjams.com","kr18plus.com","kreisbote.de","kstreaming.*","kubo-san.com","kumapoi.info","kungfutv.net","kunmanga.com","kurazone.net","kusonime.com","ladepeche.fr","landwirt.com","lanjutkeun.*","leaktube.net","learnmany.in","lectormh.com","lecturel.com","leechall.com","leprogres.fr","lesbenhd.com","lesbian8.com","lewdzone.com","liddread.com","lifestyle.bg","lifewire.com","likemanga.io","likuoo.video","linfoweb.com","linkjust.com","linksaya.com","linkshorts.*","linkvoom.com","lionsfan.net","livegore.com","livemint.com","livesport.ws","ln-online.de","lokerwfh.net","longporn.xyz","lookmovie.pn","lookmovie2.*","lootdest.com","lover937.net","lrepacks.net","lucidcam.com","lulustream.*","luluvdoo.com","luluvids.top","luscious.net","lusthero.com","luxuretv.com","m-hentai.net","mac2sell.net","macsite.info","mamahawa.com","manga18.club","mangadna.com","mangafire.to","mangagun.net","mangakio.com","mangakita.id","mangalek.com","mangamanga.*","manganato.gg","manganelo.tv","mangarawjp.*","mangasco.com","mangoporn.co","mangovideo.*","manhuaga.com","manhuascan.*","manhwa68.com","manhwass.com","manhwaus.net","manpeace.org","manyakan.com","manytoon.com","maqal360.com","marmiton.org","masengwa.com","mashtips.com","masslive.com","mat6tube.com","mathaeser.de","maturell.com","mavanimes.co","maxgaming.fi","mazakony.com","mc-hacks.net","mcfucker.com","mcrypto.club","mdbekjwqa.pw","mdtaiwan.com","mealcold.com","medscape.com","medytour.com","meetimgz.com","mega-mkv.com","mega-p2p.net","megafire.net","megatube.xxx","megaupto.com","meilblog.com","metabomb.net","meteolive.it","miaandme.org","micmicidol.*","microify.com","midis.com.ar","mikohub.blog","milftoon.xxx","miraculous.*","mirror.co.uk","missavtv.com","missyusa.com","mitsmits.com","mixloads.com","mjukb26l.fun","mkvcinemas.*","mlbstream.tv","mmsbee47.com","mobitool.net","modcombo.com","moddroid.com","modhoster.de","modsbase.com","modsfire.com","modyster.com","mom4real.com","momo-net.com","momspost.com","momxxx.video","monaco.co.il","mooonten.com","moretvtime.*","moshahda.net","motofakty.pl","movie4u.live","moviedokan.*","movieffm.net","moviefreak.*","moviekids.tv","movielair.cc","movierulzs.*","movierulzz.*","movies123.pk","movies18.net","movies4us.co","moviesapi.to","moviesbaba.*","moviesflix.*","moviesland.*","moviespapa.*","moviesrulz.*","moviesshub.*","moviesxxx.cc","movieweb.com","movstube.net","mp3fiber.com","mp3juices.su","mp4-porn.net","mpg.football","mrscript.net","multporn.net","musictip.net","mutigers.com","myesports.gg","myflixerz.to","myfxbook.com","mylinkat.com","naniplay.com","nanolinks.in","napiszar.com","nar.k-ba.net","natgeotv.com","nbastream.tv","nemumemo.com","nephobox.com","netmovies.to","netoff.co.jp","netuplayer.*","newatlas.com","news.now.com","newsextv.com","newsmondo.it","nextdoor.com","nextorrent.*","neymartv.net","nflscoop.xyz","nflstream.tv","nicetube.one","nicknight.de","nicovideo.jp","nifteam.info","nilesoft.org","niu-pack.com","niyaniya.moe","nkunorse.com","nonktube.com","novelasesp.*","novelbob.com","novelread.co","novoglam.com","novoporn.com","nowmaxtv.com","nowsports.me","nowsportv.nl","nowtv.com.tr","nptsr.live>>","nsfwgify.com","nsfwzone.xyz","nudecams.xxx","nudedxxx.com","nudistic.com","nudogram.com","nudostar.com","nueagles.com","nugglove.com","nusports.com","nwzonline.de","nyaa.iss.ink","nzbstars.com","oaaxpgp3.xyz","octanime.net","of-model.com","oimsmosy.fun","okulsoru.com","oldcamera.pl","olutposti.fi","olympics.com","oncehelp.com","oneupload.to","onlinexxx.cc","onlytech.com","onscreens.me","onyxfeed.com","op-online.de","openload.mov","opomanga.com","optifine.net","orangeink.pk","oricon.co.jp","osuskins.net","otakukan.com","otakuraw.net","ottverse.com","ottxmaza.com","ovagames.com","ovnihoje.com","oyungibi.com","pagalworld.*","pak-mcqs.net","paktech2.com","pandadoc.com","pandamovie.*","panthers.com","papunika.com","parenting.pl","parzibyte.me","paste.bin.sx","pastepvp.org","pastetot.com","patriots.com","pay4fans.com","pc-hobby.com","pcgamesn.com","pdfindir.net","peekvids.com","pelimeli.com","pelis182.net","pelisflix2.*","pelishouse.*","pelispedia.*","pelisplus2.*","pennlive.com","pentruea.com","perisxxx.com","phimmoiaz.cc","photooxy.com","photopea.com","picbaron.com","picjbet.shop","picnwqez.sbs","picyield.com","pietsmiet.de","pig-fuck.com","pilibook.com","pinayflix.me","piratebayz.*","pisatoday.it","pittband.com","pixbnab.shop","pixdfdj.shop","piximfix.com","pixkfkf.shop","pixnbrqw.sbs","pixrqqz.shop","pkw-forum.de","platinmods.*","play.max.com","play.nova.bg","play1002.com","player4u.xyz","playerfs.com","playertv.net","playfront.de","playmogo.com","playstore.pw","playvids.com","plaza.chu.jp","plc4free.com","plusupload.*","pmvhaven.com","poki-gdn.com","politico.com","polygamia.pl","pomofocus.io","ponsel4g.com","pornabcd.com","pornachi.com","porncomics.*","pornditt.com","pornfeel.com","pornfeet.xyz","pornflip.com","porngames.tv","porngrey.com","pornhat.asia","pornhdin.com","pornhits.com","pornhost.com","pornicom.com","pornleaks.in","pornlift.com","pornlore.com","pornluck.com","pornmoms.org","porno-tour.*","pornoaid.com","pornoente.tv","pornohd.blue","pornotom.com","pornozot.com","pornpapa.com","porntape.net","porntrex.com","pornvibe.org","pornwatch.ws","pornyeah.com","pornyfap.com","pornzone.com","poscitechs.*","postazap.com","postimees.ee","powcloud.org","prensa.click","pressian.com","pricemint.in","prime4you.de","produsat.com","programme.tv","promipool.de","proplanta.de","prothots.com","ps2-bios.com","pugliain.net","pupupul.site","pussyspace.*","putlocker9.*","putlockerc.*","putlockers.*","pysznosci.pl","q1-tdsge.com","qashbits.com","qpython.club","quizrent.com","qvzidojm.com","r3owners.net","raidrush.net","rail-log.net","rajtamil.org","ranjeet.best","rapelust.com","rapidzona.tv","rarepike.com","raulmalea.ro","rawmanga.top","rawstory.com","razzball.com","rbs.ta36.com","recipahi.com","recipenp.com","recording.de","reddflix.com","redecanais.*","redretti.com","remilf.xyz>>","reminimod.co","repelisgoo.*","repretel.com","reqlinks.net","resplace.com","retire49.com","richhioon.eu","riotbits.com","ritzysex.com","rockmods.net","rolltide.com","romatoday.it","roms-hub.com","ronaldo7.pro","root-top.com","rosasidan.ws","rosefile.net","rot-blau.com","rotowire.com","royalkom.com","rp-online.de","rtilinks.com","rubias19.com","rue89lyon.fr","ruidrive.com","rushporn.xxx","s2watch.link","salidzini.lv","samfirms.com","samovies.net","satkurier.pl","savefrom.net","savegame.pro","savesubs.com","savevideo.me","scamalot.com","scjhg5oh.fun","seahawks.com","seeklogo.com","seireshd.com","seksrura.net","senimovie.co","senmanga.com","senzuri.tube","servustv.com","sethphat.com","seuseriado.*","sex-pic.info","sexgames.xxx","sexgay18.com","sexroute.net","sexy-games.*","sexyhive.com","sfajacks.com","sgxnifty.org","shanurdu.com","sharedrive.*","sharetext.me","shemale6.com","shemedia.com","sheshaft.com","shorteet.com","shrtslug.biz","sieradmu.com","silkengirl.*","sinonimos.de","siteflix.org","sitekeys.net","skinnyhq.com","skinnyms.com","slawoslaw.pl","slreamplay.*","slutdump.com","slutmesh.net","smailpro.com","smallpdf.com","smcgaels.com","smgplaza.com","snlookup.com","sobatkeren.*","sodomojo.com","solarmovie.*","sonixgvn.net","sortporn.com","sound-park.*","southfreak.*","sp-today.com","sp500-up.com","speedrun.com","spielfilm.de","spinoff.link","sport-97.com","sportico.com","sporting77.*","sportlemon.*","sportlife.es","sportnews.to","sportshub.to","sportskart.*","stardeos.com","stardima.com","stayglam.com","stbturbo.xyz","steelers.com","stevivor.com","stimotion.pl","stre4mplay.*","stream18.net","streamango.*","streambee.to","streameast.*","streampiay.*","streamtape.*","streamwish.*","strikeout.im","stylebook.de","subtaboo.com","sunbtc.space","sunporno.com","superapk.org","superpsx.com","supervideo.*","surfline.com","surrit.store","sushi-scan.*","sussytoons.*","suzihaza.com","suzylu.co.uk","svipvids.com","swiftload.io","synonyms.com","syracuse.com","system32.ink","tabering.net","tabooporn.tv","tacobell.com","tagecoin.com","tajpoint.com","tamilprint.*","tamilyogis.*","tampabay.com","tanfacil.net","tapchipi.com","tapepops.com","tatabrada.tv","team-rcv.xyz","tech24us.com","tech4auto.in","techably.com","techmuzz.com","technons.com","technorj.com","techstage.de","techstwo.com","techtobo.com","techyinfo.in","techzed.info","teczpert.com","teencamx.com","teenhost.net","teensark.com","teensporn.tv","teknorizen.*","telecinco.es","telegraaf.nl","teleriumtv.*","teluguflix.*","teraearn.com","terashare.co","terashare.me","tesbox.my.id","tespedia.com","testious.com","th-world.com","theblank.net","theconomy.me","thedaddy.*>>","thefmovies.*","thegamer.com","thehindu.com","thekickass.*","thelinkbox.*","themezon.net","theonion.com","theproxy.app","thesleak.com","thesukan.net","thevalley.fm","theverge.com","threezly.com","thuglink.com","thurrott.com","tigernet.com","tik-tok.porn","timestamp.fr","tioanime.com","tipranks.com","tnaflix.asia","tnhitsda.net","tntdrama.com","tokuzl.net>>","top10cafe.se","topeuropix.*","topfaucet.us","topkickass.*","topspeed.com","topstreams.*","torture1.net","trahodom.com","trendyol.com","tresdaos.com","truthnews.de","truyenvn.dev","tryboobs.com","ts-mpegs.com","tsmovies.com","tubedupe.com","tubewolf.com","tubxporn.com","tucinehd.com","turbobit.net","turbovid.vip","turkanime.co","turkdown.com","turkrock.com","tusfiles.com","tv3monde.com","tvappapk.com","tvdigital.de","tvpclive.com","tvtropes.org","tweakers.net","twister.porn","tz7z9z0h.com","u-s-news.com","u26bekrb.fun","udoyoshi.com","ugreen.autos","ukchat.co.uk","ukdevilz.com","ukigmoch.com","ultraten.net","umagame.info","unitystr.com","up-4ever.net","upload18.com","uploadbox.io","uploadmx.com","uploads.mobi","upshrink.com","uptomega.net","ur-files.com","usatoday.com","usaxtube.com","userupload.*","usp-forum.de","utahutes.com","utaitebu.com","utakmice.net","utsports.com","uur-tech.net","uwatchfree.*","veganinja.hu","vegas411.com","vibehubs.com","videofilms.*","videojav.com","videos-xxx.*","videovak.com","vidnest.live","vidsaver.net","vidsonic.net","vidsrc-me.su","vidsrc.click","viidshar.com","vijviral.com","vikiporn.com","violablu.net","vipporns.com","viralxns.com","visorsmr.com","vocalley.com","voirseries.*","volokit2.com","warddogs.com","wargamer.com","watchmovie.*","watchmygf.me","watchnow.fun","watchop.live","watchporn.cc","watchporn.to","watchtvchh.*","way2movies.*","web2.0calc.*","webcams.casa","webnovel.com","webxmaza.com","westword.com","whatgame.xyz","whyvpn.my.id","wikifeet.com","wikirise.com","winboard.org","winfuture.de","winlator.com","wishfast.top","withukor.com","wohngeld.org","wolfstream.*","worldaide.fr","worldmak.com","worldsex.com","writedroid.*","wspinanie.pl","www.google.*","x-video.tube","xculitos.com","xemphim1.top","xfantazy.com","xfantazy.org","xhaccess.com","xhadult2.com","xhadult3.com","xhamster10.*","xhamster11.*","xhamster12.*","xhamster13.*","xhamster14.*","xhamster15.*","xhamster16.*","xhamster17.*","xhamster18.*","xhamster19.*","xhamster20.*","xhamster42.*","xhdate.world","xpornium.net","xsexpics.com","xteensex.net","xvideos.name","xvideos2.com","xxporner.com","xxxfiles.com","xxxhdvideo.*","xxxonline.cc","xxxputas.net","xxxshake.com","xxxstream.me","yabiladi.com","yaoiscan.com","yggtorrent.*","yhocdata.com","ynk-blog.com","yogranny.com","you-porn.com","yourlust.com","yts-subs.com","yts-subs.net","ytube2dl.com","yuatools.com","yurudori.com","zealtyro.com","zehnporn.com","zenradio.com","zhlednito.cz","zilla-xr.xyz","zimabdko.com","zone.msn.com","zootube1.com","zplayer.live","zvision.link","zxcprime.icu","01234movies.*","01fmovies.com","10convert.com","10play.com.au","10starhub.com","111.90.150.10","111.90.151.26","111movies.com","123gostream.*","123movies.net","123moviesgo.*","123movieshd.*","123moviesla.*","123moviesme.*","123movieweb.*","123multihub.*","185.53.88.104","185.53.88.204","190.115.18.20","1bitspace.com","1qwebplay.xyz","1xxx-tube.com","247sports.com","2girls1cup.ca","30kaiteki.com","360news4u.net","38.242.194.12","3dhentai.club","4download.net","4drumkits.com","4filmyzilla.*","4horlover.com","4meplayer.com","4movierulz1.*","560pmovie.com","5movierulz2.*","6hiidude.gold","7fractals.icu","7misr4day.com","7movierulz1.*","7moviesrulz.*","7vibelife.com","94.103.83.138","9filmyzilla.*","9ketsuki.info","abczdrowie.pl","abendblatt.de","abseits-ka.de","acusports.com","acutetube.net","adblocktape.*","advantien.com","advertape.net","ainonline.com","aitohuman.org","ajt.xooit.org","akcartoons.in","albania.co.il","alexbacher.fr","alimaniac.com","allitebooks.*","allmomsex.com","alltstube.com","allusione.org","alohatube.xyz","alueviesti.fi","ambonkita.com","angelfire.com","angelgals.com","anihdplay.com","animecast.net","animefever.cc","animeflix.ltd","animefreak.to","animeheaven.*","animenexus.in","animesite.net","animesup.info","animetoast.cc","animeunity.so","animeworld.ac","animeworld.tv","animeyabu.net","animeyabu.org","animeyubi.com","anitube22.vip","aniwatchtv.to","aniworld.to>>","anonyviet.com","anusling.info","aogen-net.com","aparttent.com","appteka.store","arahdrive.com","archive.today","archivebate.*","archpaper.com","areabokep.com","areamobile.de","areascans.net","areatopik.com","arenascan.com","arenavision.*","arhplyrics.in","ariestube.com","ark-unity.com","arldeemix.com","artesacro.org","arti-flora.nl","articletz.com","artribune.com","asianboy.fans","asianhdplay.*","asianlbfm.net","asiansex.life","asiaontop.com","askattest.com","asssex-hd.com","astroages.com","astronews.com","at.wetter.com","audiotag.info","audiotrip.org","austiblox.net","auto-data.net","auto-swiat.pl","autobytel.com","autoextrem.de","autofrage.net","autoscout24.*","autosport.com","autotrader.nl","avnsgames.com","avpgalaxy.net","azcentral.com","aztravels.net","b-bmovies.com","babakfilm.com","babepedia.com","babestube.com","babytorrent.*","baddiehub.com","beasttips.com","beegsexxx.com","besargaji.com","bestgames.com","beverfood.com","biftutech.com","bikeradar.com","bikerszene.de","bilasport.net","bilinovel.com","billboard.com","bimshares.com","bingsport.xyz","bitcosite.com","bitfaucet.net","bitlikutu.com","bitview.cloud","bizdustry.com","blasensex.com","blog.40ch.net","blogesque.net","blograffo.net","blurayufr.cam","bobs-tube.com","bokugents.com","bolly2tolly.*","bollymovies.*","boobgirlz.com","bootyexpo.net","boxylucha.com","boystube.link","bravedown.com","bravoporn.com","brawlhalla.fr","breitbart.com","breznikar.com","brighteon.com","brocoflix.com","brocoflix.xyz","bshifast.live","buffsports.io","buffstreams.*","bustyfats.com","buydekhke.com","bymichiby.com","call4cloud.nl","camarchive.tv","camdigest.com","camgoddess.tv","camvideos.org","camwhorestv.*","camwhoria.com","canalobra.com","canlikolik.my","capo5play.com","capo6play.com","caravaning.de","cardshare.biz","carryflix.icu","carscoops.com","cat-a-cat.net","cat3movie.org","cbsnews.com>>","ccthesims.com","cdiscount.com","celeb.gate.cc","celemusic.com","ceramic.or.kr","ceylonssh.com","cg-method.com","cgcosplay.org","chapteria.com","chataigpt.org","cheatcloud.cc","cheater.ninja","cheatsquad.gg","chevalmag.com","chihouban.com","chikonori.com","chimicamo.org","chloeting.com","cima100fm.com","cinecalidad.*","cinedokan.top","cinema.com.my","cinemabaz.com","cinemitas.org","civitai.green","claim.8bit.ca","claimbits.net","claudelog.com","claydscap.com","clickhole.com","cloudvideo.tv","cloudwish.xyz","cloutgist.com","cmsdetect.com","cmtracker.net","cnnamador.com","cockmeter.com","cocomanga.com","code2care.org","codeastro.com","codesnail.com","codewebit.top","coinbaby8.com","coinfaucet.io","coinlyhub.com","coinsbomb.com","comedyshow.to","comexlive.org","comparili.net","computer76.ru","condorsoft.co","configspc.com","cooksinfo.com","coolcast2.com","coolporno.net","corrector.app","courseclub.me","crackcodes.in","crackevil.com","crackfree.org","crazyporn.xxx","crazyshit.com","crazytoys.xyz","cricket12.com","criollasx.com","criticker.com","crocotube.com","crotpedia.net","crypto4yu.com","cryptonor.xyz","cryptorank.io","cuisineaz.com","cumlouder.com","cureclues.com","cuttlinks.com","cxissuegk.com","cybermania.ws","daddylive.*>>","daddylivehd.*","dailymail.com","dailynews.com","dailypaws.com","dailyrevs.com","dandanzan.top","dankmemer.lol","datavaults.co","dbusports.com","dcleakers.com","ddd-smart.net","decmelfot.xyz","deepfucks.com","deichstube.de","deluxtube.com","demae-can.com","dengarden.com","denofgeek.com","depvailon.com","derusblog.com","descargasok.*","desifakes.com","desijugar.net","desimmshd.com","dfilmizle.com","dickclark.com","dinnerexa.com","dipprofit.com","dirtyship.com","diskizone.com","dl-protect1.*","dlapk4all.com","dldokan.store","dlhe-videa.sk","dlstreams.*>>","doctoraux.com","dongknows.com","donkparty.com","doofree88.com","doomovie-hd.*","dooodster.com","doramasyt.com","dorawatch.net","douploads.net","douxporno.com","downfile.site","downloader.is","downloadhub.*","dr-farfar.com","dragontea.ink","dramafren.com","dramafren.org","dramaviki.com","drivelinks.me","drivenime.com","driveup.space","drop.download","dropnudes.com","dropshipin.id","dubaitime.net","durtypass.com","e-monsite.com","e2link.link>>","eatsmarter.de","ebonybird.com","ebook-hell.to","ebook3000.com","ebooksite.org","edealinfo.com","edukamer.info","egitim.net.tr","elespanol.com","embdproxy.xyz","embed.scdn.to","embedgram.com","embedplayer.*","embedrise.com","embedseek.xyz","embedwish.com","empleo.com.uy","emueagles.com","encurtads.net","encurtalink.*","enjoyfuck.com","ensenchat.com","entenpost.com","entireweb.com","ephoto360.com","epochtimes.de","eporner.video","eramuslim.com","erospots.info","eroticity.net","erreguete.gal","eurogamer.net","exe-links.com","expansion.com","extratipp.com","fadedfeet.com","familyporn.tv","fanfiktion.de","fangraphs.com","fantasiku.com","fapomania.com","faresgame.com","farodevigo.es","fastcars1.com","fclecteur.com","fembed9hd.com","fetish-tv.com","fetishtube.cc","file-upload.*","filegajah.com","filehorse.com","filemooon.top","filmeseries.*","filmibeat.com","filmlinks4u.*","filmy4wap.uno","filmyporno.tv","filmyworlds.*","findheman.com","firescans.xyz","firmwarex.net","firstpost.com","fivemturk.com","flexamens.com","flexxporn.com","flix-wave.lol","flixlatam.com","flyplayer.xyz","fmoviesfree.*","fontyukle.net","footeuses.com","footyload.com","forexforum.co","forlitoday.it","forum.dji.com","fossbytes.com","fosslinux.com","fotoblogia.pl","foxaholic.com","foxsports.com","foxtel.com.au","frauporno.com","free.7hd.club","freedom3d.art","freeflix.info","freegames.com","freeiphone.fr","freeomovie.to","freeporn8.com","freesex-1.com","freeshot.live","freexcafe.com","freexmovs.com","freshscat.com","freyalist.com","fromwatch.com","fsicomics.com","fsl-stream.lu","fsportshd.net","fsportshd.xyz","fuck-beeg.com","fuck-xnxx.com","fuckingfast.*","fucksporn.com","fullassia.com","fullhdxxx.com","funandnews.de","fussball.news","futurezone.de","fzmovies.info","fztvseries.ng","gamearter.com","gamedrive.org","gamefront.com","gamelopte.com","gamereactor.*","games.bnd.com","games.qns.com","gamesite.info","gamesmain.xyz","gamezhero.com","gamovideo.com","garoetpos.com","gatasdatv.com","gayboyshd.com","gaysearch.com","geekering.com","generate.plus","gesundheit.de","getintopc.com","getpaste.link","getpczone.com","gfsvideos.com","ghscanner.com","gigmature.com","gipfelbuch.ch","girlnude.link","girlydrop.com","globalnews.ca","globalrph.com","globalssh.net","globlenews.in","go.linkify.ru","gobobcats.com","gogoanimetv.*","gogoplay1.com","gogoplay2.com","gohuskies.com","gol245.online","goldderby.com","gomaainfo.com","gomoviestv.to","goodriviu.com","govandals.com","grabpussy.com","grantorrent.*","graphicux.com","greatnass.com","greensmut.com","gry-online.pl","gsmturkey.net","guardaserie.*","guessthe.game","gutefrage.net","gutekueche.at","gwusports.com","haaretz.co.il","hailstate.com","hairytwat.org","hancinema.net","haonguyen.top","haoweichi.com","harimanga.com","harzkurier.de","hdgayporn.net","hdmoviefair.*","hdmoviehubs.*","hdmovieplus.*","hdmovies2.org","hdtubesex.net","heatworld.com","heimporno.com","hellabyte.one","hellenism.net","hellporno.com","hentai-ia.com","hentaicop.com","hentaihaven.*","hentaikai.com","hentaimama.tv","hentaipaw.com","hentaiporn.me","hentairead.io","hentaiyes.com","herzporno.net","heutewelt.com","hexupload.net","hiddenleaf.to","hifi-forum.de","hihihaha1.xyz","hihihaha2.xyz","hilites.today","hindimovies.*","hindinest.com","hindishri.com","hindisink.com","hindisite.net","hispasexy.org","hitsports.pro","hlsplayer.top","hobbykafe.com","holaporno.xxx","holymanga.net","hornbunny.com","hornyfanz.com","hosttbuzz.com","hotntubes.com","hotpress.info","howtogeek.com","hqmaxporn.com","hqpornero.com","hqsex-xxx.com","htmlgames.com","hulkshare.com","hurawatchz.to","hydraxcdn.biz","hypebeast.com","hyperdebrid.*","iammagnus.com","iceland.co.uk","ichberlin.com","icy-veins.com","ievaphone.com","iflixmovies.*","ifreefuck.com","igg-games.com","ignboards.com","iiyoutube.com","ikarianews.gr","ikz-online.de","ilpiacenza.it","imagehaha.com","imagenpic.com","imgbbnhi.shop","imgbncvnv.sbs","imgcredit.xyz","imghqqbg.shop","imgkkabm.shop","imgmyqbm.shop","imgouskel.sbs","imgwallet.com","imgwwqbm.shop","imleagues.com","indiafree.net","indiamaja.com","indianyug.com","indiewire.com","ineedskin.com","inextmovies.*","infidrive.net","inhabitat.com","instagram.com","instalker.org","interfans.org","investing.com","iogames.space","ipalibrary.me","iptvpulse.top","italpress.com","itdmusics.com","itdmusicy.com","itmaniatv.com","itopmusic.com","itsguider.com","jadijuara.com","jagoanssh.com","jameeltips.us","japanxxx.asia","jav101.online","javenglish.cc","javguard.club","javhdporn.com","javhdporn.net","javleaked.com","javmobile.net","javporn18.com","javsaga.ninja","javstream.com","javstream.top","javsubbed.xyz","javsunday.com","jaysndees.com","jazzradio.com","jellynote.com","jennylist.xyz","jesseporn.xyz","jiocinema.com","jipinsoft.com","jizzberry.com","jk-market.com","jkdamours.com","jncojeans.com","jobzhub.store","joongdo.co.kr","jpscan-vf.com","jptorrent.org","juegos.as.com","jumboporn.xyz","junkyponk.com","jurukunci.net","justjared.com","justpaste.top","justwatch.com","juventusfc.hu","k12reader.com","kacengeng.com","kakiagune.com","kalileaks.com","kanaeblog.net","kangkimin.com","katdrive.link","katestube.com","katmoviefix.*","kayoanime.com","kckingdom.com","kenta2222.com","kfapfakes.com","kfrfansub.com","kicaunews.com","kickcharm.com","kissasian.*>>","klaustube.com","klikmanga.com","kllproject.lv","klykradio.com","kobieta.wp.pl","kolnovel.site","koreanbj.club","korsrt.eu.org","kotanopan.com","kpopjjang.com","ksusports.com","kumascans.com","kupiiline.com","kuronavi.blog","kurosuen.live","lamorgues.com","laptrinhx.com","latinabbw.xyz","latinlucha.es","laurasia.info","lavoixdux.com","law101.org.za","learn-cpp.org","learnclax.com","lecceprima.it","leccotoday.it","leermanga.net","leinetal24.de","letmejerk.com","letras.mus.br","lewdstars.com","liberation.fr","liiivideo.com","likemanga.ink","lilymanga.net","ling-online.*","link4rev.site","linkfinal.com","linkshortx.in","linkskibe.com","linkspaid.com","linovelib.com","linuxhint.com","lippycorn.com","listeamed.net","litecoin.host","litonmods.com","liveonsat.com","livestreams.*","liveuamap.com","lolcalhost.ru","lolhentai.net","longfiles.com","lookmovie2.to","loot-link.com","lootlemon.com","loptelink.com","lordpremium.*","love4porn.com","lovetofu.cyou","lowellsun.com","lrtrojans.com","lsusports.net","ludigames.com","lulacloud.com","lustesthd.lat","lustholic.com","lusttaboo.com","lustteens.net","lustylist.com","lustyspot.com","luxusmail.org","m.viptube.com","m.youtube.com","maccanismi.it","macrumors.com","macserial.com","magesypro.com","mailnesia.com","mailocal2.xyz","mainbabes.com","mainlinks.xyz","mainporno.com","makeuseof.com","mamochki.info","manga-dbs.com","manga-tube.me","manga18fx.com","mangacrab.com","mangacrab.org","mangadass.com","mangafreak.me","mangahere.onl","mangakoma01.*","mangalist.org","mangarawjp.me","mangaread.org","mangasite.org","mangoporn.net","manhastro.com","manhastro.net","manhuatop.org","manhwatop.com","manofadan.com","map.naver.com","math-aids.com","mathcrave.com","mathebibel.de","mathsspot.com","matomeiru.com","maz-online.de","mconverter.eu","md3b0j6hj.com","mdfx9dc8n.net","mdy48tn97.com","medebooks.xyz","mediafire.com","mediamarkt.be","mediamarkt.de","mediapason.it","medihelp.life","mega-dvdrip.*","megagames.com","megane.com.pl","megawarez.org","megawypas.com","meineorte.com","meinestadt.de","memangbau.com","memedroid.com","menshealth.de","metalflirt.de","meteocity.com","meteopool.org","metrolagu.cam","mettablog.com","meuanime.info","mexicogob.com","mh.baxoi.buzz","mhdsportstv.*","mhdtvsports.*","miohentai.com","miraculous.to","mirrorace.com","missav123.com","missav888.com","mitedrive.com","mixdrop21.net","mixdrop23.net","mixdropjmk.pw","mjakmama24.pl","mmastreams.me","mmorpg.org.pl","mobdi3ips.com","mobdropro.com","modelisme.com","mom-pussy.com","momxxxass.com","momxxxsex.com","moneyhouse.ch","monstream.org","monzatoday.it","moonquill.com","moovitapp.com","moozpussy.com","moregirls.org","morgenpost.de","mosttechs.com","motive213.com","motofan-r.com","motor-talk.de","motorbasar.de","motortests.de","moutogami.com","moviedekho.in","moviefone.com","moviehaxx.pro","moviejones.de","movielinkbd.*","moviepilot.de","movieping.com","movierulzhd.*","moviesdaweb.*","moviesite.app","moviesverse.*","moviexxx.mobi","mp3-gratis.it","mp3fusion.net","mp3juices.icu","mp4mania1.net","mp4upload.com","mrpeepers.net","mtech4you.com","mtg-print.com","mtraffics.com","multicanais.*","musicsite.biz","musikradar.de","myadslink.com","mydomaine.com","myfernweh.com","myflixertv.to","myhindigk.com","myhomebook.de","myicloud.info","myrecipes.com","myshopify.com","mysostech.com","mythvista.com","myvidplay.com","myvidster.com","myviptuto.com","myyouporn.com","naijahits.com","nakenprat.com","napolipiu.com","nastybulb.com","nation.africa","natomanga.com","naturalbd.com","nbcsports.com","ncdexlive.org","needrombd.com","neilpatel.com","nekolink.site","nekopoi.my.id","neoseeker.com","nesiaku.my.id","netcinebs.lat","netfilmes.org","netnaijas.com","nettiauto.com","neuepresse.de","neurotray.com","nevcoins.club","neverdims.com","newstopics.in","newyorker.com","newzjunky.com","nexusgames.to","nexusmods.com","nflstreams.me","nhvnovels.com","nicematin.com","nicomanga.com","nihonkuni.com","nin10news.com","nklinks.click","nlcosplay.com","noblocktape.*","noikiiki.info","noob4cast.com","noor-book.com","nordbayern.de","notevibes.com","nousdecor.com","nouvelobs.com","novamovie.net","novelcrow.com","novelroom.net","novizer.com>>","nsfwalbum.com","nsfwhowto.xyz","nudegista.com","nudistube.com","nuhuskies.com","nukibooks.com","nulledmug.com","nvimfreak.com","nwusports.com","odiadance.com","odiafresh.com","officedepot.*","ogoplayer.xyz","ohmybrush.com","ojogos.com.br","okhatrimaza.*","onemanhua.com","onlinegdb.com","onlyssh.my.id","onlystream.tv","op-marburg.de","openloadmov.*","ostreaming.tv","otakuliah.com","otakuporn.com","otonanswer.jp","ottawasun.com","ovcsports.com","owlsports.com","ozulscans.com","padovaoggi.it","pagalfree.com","pagalmovies.*","pagalworld.us","paidnaija.com","paipancon.com","panuvideo.com","paolo9785.com","parisporn.org","parmatoday.it","pasteboard.co","pasteflash.sx","pastelink.net","patchsite.net","pawastreams.*","pc-builds.com","pc-magazin.de","pclicious.net","peacocktv.com","peladas69.com","peliculas24.*","pelisflix20.*","pelisgratis.*","pelismart.com","pelisplusgo.*","pelisplushd.*","pelisplusxd.*","pelisstar.com","perplexity.ai","pervclips.com","pg-wuming.com","pianokafe.com","pic-upload.de","picbcxvxa.sbs","pichaloca.com","pics-view.com","pienovels.com","piraproxy.app","pirateproxy.*","pixbkghxa.sbs","pixbryexa.sbs","pixnbrqwg.sbs","pixtryab.shop","pkbiosfix.com","pkproject.net","play.aetv.com","player.stv.tv","player4me.vip","playfmovies.*","playpaste.com","plugincim.com","pocketnow.com","poco.rcccn.in","pokemundo.com","polska-ie.com","popcorntime.*","porn4fans.com","pornbaker.com","pornbimbo.com","pornblade.com","pornborne.com","pornchaos.org","pornchimp.com","porncomics.me","porncoven.com","porndollz.com","porndrake.com","pornfelix.com","pornfuzzy.com","pornloupe.com","pornmonde.com","pornoaffe.com","pornobait.com","pornocomics.*","pornoeggs.com","pornohaha.com","pornohans.com","pornohelm.com","pornokeep.com","pornoleon.com","pornomico.com","pornonline.cc","pornonote.pro","pornoplum.com","pornproxy.app","pornproxy.art","pornretro.xyz","pornslash.com","porntopic.com","porntube18.cc","posterify.net","pourcesoir.in","povaddict.com","powforums.com","pravda.com.ua","pregledaj.net","pressplay.cam","pressplay.top","prignitzer.de","primewire.*>>","proappapk.com","proboards.com","produktion.de","promiblogs.de","prostoporno.*","protestia.com","protopage.com","pureleaks.net","pussy-hub.com","pussyspot.net","putlockertv.*","puzzlefry.com","pvpoke-re.com","pygodblog.com","quesignifi.ca","quicasting.it","quickporn.net","rainytube.com","ranourano.xyz","rbscripts.net","read.amazon.*","readingbd.com","realbooru.com","realmadryt.pl","rechtslupe.de","redhdtube.xxx","redsexhub.com","reliabletv.me","repelisgooo.*","restorbio.com","reviewdiv.com","rexdlfile.com","ridvanmau.com","riggosrag.com","ritzyporn.com","rocdacier.com","rockradio.com","rojadirecta.*","roms4ever.com","romsgames.net","romspedia.com","rossoporn.com","rottenlime.pw","roystream.com","rufiiguta.com","rule34.jp.net","rumbunter.com","ruyamanga.com","s.sseluxx.com","sagewater.com","sarapbabe.com","sassytube.com","savefiles.com","scatkings.com","scimagojr.com","scrapywar.com","scrolller.com","sendspace.com","seneporno.com","sensacine.com","seriesite.net","set.seturl.in","sex-babki.com","sexbixbox.com","sexbox.online","sexdicted.com","sexmazahd.com","sexmutant.com","sexphimhd.net","sextube-6.com","sexyscope.net","sexytrunk.com","sfastwish.com","sfirmware.com","shameless.com","share.hntv.tv","share1223.com","sharemods.com","sharkfish.xyz","sharphindi.in","shemaleup.net","short-fly.com","short1ink.com","shortlinkto.*","shortpaid.com","shorttrick.in","shownieuws.nl","shroomers.app","siimanga.cyou","simana.online","simplebits.io","simpmusic.org","sissytube.net","sitefilme.com","sitegames.net","sk8therapy.fr","skymovieshd.*","smartworld.it","smashkarts.io","snapwordz.com","socigames.com","softcobra.com","softfully.com","sohohindi.com","solarmovie.id","solarmovies.*","solotrend.net","songfacts.com","sosovalue.com","spankbang.com","spankbang.mov","speedporn.net","speedtest.net","speedweek.com","spfutures.org","spokesman.com","spontacts.com","sportbar.live","sportlemons.*","sportlemonx.*","sportowy24.pl","sportsbite.cc","sportsembed.*","sportsnest.co","sportsrec.com","sportweb.info","spring.org.uk","ssyoutube.com","stagemilk.com","stalkface.com","starsgtech.in","startpage.com","startseite.to","ster-blog.xyz","stock-rom.com","str8ongay.com","stre4mpay.one","stream-69.com","stream4free.*","streambtw.com","streamcloud.*","streamfree.to","streamhd247.*","streamobs.net","streampoi.com","streamporn.cc","streamsport.*","streamta.site","streamtp1.com","streamvid.net","strefaagro.pl","striptube.net","stylist.co.uk","subtitles.cam","subtorrents.*","suedkurier.de","sufanblog.com","sulleiman.com","sunporno.club","superstream.*","supervideo.tv","supforums.com","sweetgirl.org","swisscows.com","switch520.com","sylverkat.com","sysguides.com","szexkepek.net","szexvideok.hu","t-rocforum.de","tab-maker.com","taboodude.com","taigoforum.de","tamilarasan.*","tamilguns.org","tamilhit.tech","tapenoads.com","tatsublog.com","techacode.com","techclips.net","techdriod.com","techilife.com","technofino.in","techradar.com","techrecur.com","techtrim.tech","techybuff.com","techyrick.com","teenbabe.link","tehnotone.com","teknisitv.com","temp-mail.lol","temp-mail.org","tempumail.com","tennis.stream","ternitoday.it","terrylove.com","testsieger.de","texastech.com","thejournal.ie","thelayoff.com","thememypc.net","thenation.com","thespruce.com","thestreet.com","thetemp.email","thethings.com","thetravel.com","theuser.cloud","theweek.co.uk","thichcode.net","thiepmung.com","thotpacks.xyz","thotslife.com","thoughtco.com","tierfreund.co","tierlists.com","timescall.com","tinyzonetv.cc","tinyzonetv.se","tiz-cycling.*","tmohentai.com","to-travel.net","tok-thots.com","tokopedia.com","tokuzilla.net","topwwnews.com","torgranate.de","torrentz2eu.*","torupload.com","totalcsgo.com","totaldebrid.*","tourporno.com","towerofgod.me","trade2win.com","trailerhg.xyz","trangchu.news","transfaze.com","transflix.net","transtxxx.com","travelbook.de","tremamnon.com","tribeclub.com","tricksplit.io","trigonevo.com","tripsavvy.com","tsubasatr.org","tubehqxxx.com","tubemania.org","tubereader.me","tudigitale.it","tudotecno.com","tukipasti.com","tunabagel.net","tunemovie.fun","turkleech.com","tutcourse.com","tvfutbol.info","twink-hub.com","twstalker.com","txxxporn.tube","uberhumor.com","ubuntudde.com","udemyking.com","udinetoday.it","uhcougars.com","uicflames.com","uniqueten.net","unlockapk.com","unlockxh4.com","unnuetzes.com","unterhalt.net","up4stream.com","upfilesgo.com","uploadgig.com","uptoimage.com","urgayporn.com","utrockets.com","uwbadgers.com","vectorizer.io","vegamoviese.*","veoplanet.com","verhentai.top","vermoegen.org","vibestreams.*","vibraporn.com","vid-guard.com","vidaextra.com","videoplayer.*","vidora.stream","vidspeeds.com","vidstream.pro","viefaucet.com","villanova.com","vintagetube.*","vipergirls.to","vipserije.com","vipstand.pm>>","visionias.net","visnalize.com","vixenless.com","vkrovatku.com","voidtruth.com","voiranime1.fr","voirseries.io","vosfemmes.com","vpntester.org","vpzserver.com","vstplugin.net","vuinsider.com","w3layouts.com","waploaded.com","warezsite.net","watch.plex.tv","watchdirty.to","watchluna.com","watchmovies.*","watchseries.*","watchsite.net","watchtv24.com","wdpglobal.com","weatherwx.com","weirdwolf.net","wendycode.com","westmanga.org","wetpussy.sexy","wg-gesucht.de","whoreshub.com","widewifes.com","wikipekes.com","wikitechy.com","willcycle.com","windowspro.de","wkusports.com","wlz-online.de","wmoviesfree.*","wonderapk.com","wordshake.com","workink.click","world4ufree.*","worldfree4u.*","worldsports.*","worldstar.com","worldtop2.com","wowescape.com","wunderweib.de","wvusports.com","www.amazon.de","www.seznam.cz","www.twitch.tv","www.yahoo.com","x-fetish.tube","x-videos.name","xanimehub.com","xhbranch5.com","xhchannel.com","xhlease.world","xhplanet1.com","xhplanet2.com","xhvictory.com","xhwebsite.com","xmovies08.org","xnxxjapon.com","xoxocomic.com","xrivonet.info","xsportbox.com","xsportshd.com","xstory-fr.com","xxvideoss.org","xxx-image.com","xxxbunker.com","xxxcomics.org","xxxfree.watch","xxxhothub.com","xxxscenes.net","xxxvideo.asia","xxxvideor.com","y2meta-uk.com","yachtrevue.at","yandexcdn.com","yaoiotaku.com","ycongnghe.com","yesmovies.*>>","yesmovies4u.*","yeswegays.com","ymp4.download","yogitimes.com","youjizzz.club","youlife24.com","youngleak.com","youpornfm.com","youtubeai.com","yoyofilmeys.*","yt1s.com.co>>","yumekomik.com","zamundatv.com","zerotopay.com","zigforums.com","zinkmovies.in","zmamobile.com","zoompussy.com","zorroplay.xyz","0dramacool.net","111.90.141.252","111.90.150.149","111.90.159.132","1111fullwise.*","123animehub.cc","123moviefree.*","123movierulz.*","123movies4up.*","123moviesd.com","123movieshub.*","185.193.17.214","188.166.182.72","18girlssex.com","1cloudfile.com","1pack1goal.com","1primewire.com","1shortlink.com","1stkissmanga.*","3gpterbaru.com","3rabsports.com","4everproxy.com","69hoshudaana.*","69teentube.com","90fpsconfig.in","absolugirl.com","absolutube.com","admiregirls.su","adnan-tech.com","adsafelink.com","afilmywapi.biz","agedvideos.com","airsextube.com","akumanimes.com","akutsu-san.com","alexsports.*>>","alimaniacky.cz","allbbwtube.com","allcalidad.app","allcelebs.club","allmovieshub.*","allosoccer.com","allpremium.net","allrecipes.com","alluretube.com","allwpworld.com","almezoryae.com","alphaporno.com","amanguides.com","amateurfun.net","amateurporn.co","amigosporn.top","ancensored.com","anconatoday.it","androgamer.org","androidacy.com","ani-stream.com","anime4mega.net","animeblkom.net","animefire.info","animefire.plus","animeheaven.ru","animeindo.asia","animeshqip.org","animespank.com","animesvision.*","anonymfile.com","anyxvideos.com","aozoraapps.net","app.cekresi.me","appsfree4u.com","arab4media.com","arabincest.com","arabxforum.com","arealgamer.org","ariversegl.com","arlinadzgn.com","armyranger.com","articlebase.pk","artoffocas.com","ashemaletube.*","ashemaletv.com","asianporn.sexy","asianwatch.net","askpaccosi.com","askushowto.com","assesphoto.com","astro-seek.com","atlantic10.com","autocentrum.pl","autopareri.com","av1encodes.com","b3infoarena.in","balkanteka.net","bamahammer.com","bankshiksha.in","bantenexis.com","batmanstream.*","battleboats.io","bbwfuckpic.com","bcanepaltu.com","bcsnoticias.mx","bdsmstreak.com","bdsomadhan.com","bdstarshop.com","beegvideoz.com","belloporno.com","benzinpreis.de","best18porn.com","bestofarea.com","betaseries.com","bgmiesports.in","bharian.com.my","bhugolinfo.com","bidersnotu.com","bildderfrau.de","bingotingo.com","bit-shares.com","bitcotasks.com","bitcrypto.info","bittukitech.in","blackcunts.org","blackteen.link","blocklayer.com","blowjobgif.net","bluedollar.net","boersennews.de","bolly-tube.com","bollywoodx.org","bonstreams.net","boobieblog.com","boobsradar.com","boobsrealm.com","boredgiant.com","boxaoffrir.com","brainknock.net","bravoteens.com","bravotube.asia","brightpets.org","brulosophy.com","btcadspace.com","btcsatoshi.net","btvnovinite.bg","buccaneers.com","buchstaben.com","businessua.com","bustmonkey.com","bustybloom.com","bysefujedu.com","bysejikuar.com","byseqekaho.com","byseraguci.com","bysesukior.com","bysetayico.com","cacfutures.org","cadenadial.com","calculate.plus","calgarysun.com","camgirlbay.net","camgirlfap.com","camsstream.com","canalporno.com","caracol.com.co","cardscanner.co","carrnissan.com","casertanews.it","celebjihad.com","celebwhore.com","cellmapper.net","cesenatoday.it","chachocool.com","chanjaeblog.jp","chart.services","chatgptfree.ai","chaturflix.cam","cheatermad.com","chietitoday.it","cimanow.online","cine-calidad.*","cinelatino.net","cinemalibero.*","cinepiroca.com","claimcrypto.cc","claimlite.club","clasicotas.org","clicknupload.*","clipartmax.com","cloudflare.com","cloudvideotv.*","club-flank.com","codeandkey.com","coinadpro.club","coloradoan.com","comdotgame.com","comicsarmy.com","comixzilla.com","commanders.com","compromath.com","comunio-cl.com","convert2mp3.cx","coolrom.com.au","copyseeker.net","courseboat.com","coverapi.space","coverapi.store","crackshash.com","cracksports.me","crazygames.com","crazyvidup.com","creebhills.com","crichdplays.ru","cricwatch.io>>","croq-kilos.com","crunchyscan.fr","crypt.cybar.to","cryptoforu.org","cryptonetos.ru","cryptotech.fun","cryptstream.de","csgo-ranks.com","cuckoldsex.net","curseforge.com","cwtvembeds.com","cyberscoop.com","czechvideo.org","dagensnytt.com","dailylocal.com","dallasnews.com","dansmovies.com","daotranslate.*","daxfutures.org","dayuploads.com","ddwloclawek.pl","defenseone.com","delcotimes.com","derstandard.at","derstandard.de","desicinema.org","desicinemas.pk","designbump.com","desiremovies.*","desktophut.com","devdrive.cloud","deviantart.com","diampokusy.com","dicariguru.com","dieblaue24.com","digipuzzle.net","direct-cloud.*","dirtytamil.com","disneyplus.com","dobletecno.com","dodgersway.com","dogsexporn.net","doseofporn.com","dotesports.com","dotfreesex.com","dotfreexxx.com","doujinnote.com","dowfutures.org","downloadming.*","drakecomic.com","dreamfancy.org","duniailkom.com","dvdgayporn.com","dvdporngay.com","e123movies.com","easytodoit.com","eatingwell.com","ebooksyard.com","ecacsports.com","echo-online.de","ed-protect.org","eddiekidiw.com","eftacrypto.com","elcorreoweb.es","electomania.es","elitegoltv.org","elitetorrent.*","elmalajeno.com","elnacional.cat","emailnator.com","embedsports.me","embedstream.me","empire-anime.*","emturbovid.com","emugameday.com","enryumanga.com","ensuretips.com","epicstream.com","epornstore.com","ericdraken.com","erinsakura.com","erokomiksi.com","eroprofile.com","esgentside.com","esportivos.fun","este-walks.net","estrenosflix.*","estrenosflux.*","ethiopia.co.il","examscisco.com","exbulletin.com","expertplay.net","exteenporn.com","extratorrent.*","extreme-down.*","eztvtorrent.co","f123movies.com","faaduindia.com","fairyanime.com","fakazagods.com","fakedetail.com","fanatik.com.tr","fantacalcio.it","fap-nation.org","faperplace.com","faselhdwatch.*","fastdour.store","fatxxxtube.com","faucetdump.com","fduknights.com","fetishburg.com","fettspielen.de","fhmemorial.com","fibwatch.store","filemirage.com","fileplanet.com","filesharing.io","filesupload.in","film-adult.com","filme-bune.biz","filmpertutti.*","filmy4waps.org","filmypoints.in","filmyzones.com","filtercams.com","finanztreff.de","finderporn.com","findtranny.com","fine-wings.com","firefaucet.win","fitdynamos.com","fleamerica.com","flostreams.xyz","flycutlink.com","fmoonembed.pro","foodgustoso.it","foodiesjoy.com","foodtechnos.in","football365.fr","fooxybabes.com","forex-trnd.com","freeforums.net","freegayporn.me","freehqtube.com","freeltc.online","freemodsapp.in","freepasses.org","freepdfcomic.*","freepreset.net","freesoccer.net","freesolana.top","freetubetv.net","freiepresse.de","freshplaza.com","freshremix.net","frostytube.com","fu-4u3omzw0.nl","fucktube4k.com","fuckundies.com","fullporner.com","fullvoyeur.com","gadgetbond.com","gamefi-mag.com","gameofporn.com","games.amny.com","games.insp.com","games.metro.us","games.metv.com","games.wtop.com","games2rule.com","games4king.com","gamesgames.com","gamesleech.com","gayforfans.com","gaypornhot.com","gayxxxtube.net","gazettenet.com","gdr-online.com","gdriveplayer.*","gecmisi.com.tr","genovatoday.it","getintopcm.com","getintoway.com","getmaths.co.uk","gettapeads.com","getthispdf.com","gigacourse.com","gisvacancy.com","gknutshell.com","gloryshole.com","goalsport.info","gobearcats.com","gofirmware.com","goislander.com","golightsgo.com","gomoviesfree.*","gomovieshub.io","goodreturns.in","goodstream.one","googlvideo.com","gorecenter.com","gorgeradio.com","goshockers.com","gostanford.com","gostreamon.net","goterriers.com","gotgayporn.com","gotigersgo.com","gourmandix.com","gousfbulls.com","govtportal.org","grannysex.name","grantorrent1.*","grantorrents.*","graphicget.com","grubstreet.com","guitarnick.com","gujjukhabar.in","gurbetseli.net","guruofporn.com","gutfuerdich.co","gyanitheme.com","gyonlineng.com","hairjob.wpx.jp","haloursynow.pl","hanime1-me.top","hannibalfm.net","hardcorehd.xxx","haryanaalert.*","hausgarten.net","hawtcelebs.com","hdhub4one.pics","hdmovies23.com","hdmoviesfair.*","hdmoviesflix.*","hdmoviesmaza.*","hdpornteen.com","healthelia.com","healthmyst.com","hentai-for.net","hentai-hot.com","hentai-one.com","hentaiasmr.moe","hentaiblue.net","hentaibros.com","hentaicity.com","hentaidays.com","hentaihere.com","hentaipins.com","hentairead.com","hentaisenpai.*","hentaiworld.tv","heysigmund.com","hidefninja.com","hilaryhahn.com","hinatasoul.com","hindilinks4u.*","hindimovies.to","hindiporno.pro","hit-erotic.com","hollymoviehd.*","homebooster.de","homeculina.com","hortidaily.com","hotcleaner.com","hotgirlhub.com","hotgirlpix.com","howtocivil.com","hpaudiobooks.*","hyogo.ie-t.net","hypershort.com","i123movies.net","iconmonstr.com","idealfollow.in","idlelivelink.*","ilifehacks.com","ilikecomix.com","imagetwist.com","imgjbxzjv.shop","imgjmgfgm.shop","imgjvmbbm.shop","imgnnnvbrf.sbs","inbbotlist.com","indi-share.com","indiainfo4u.in","indiatimes.com","indopanas.cyou","infocycles.com","infokita17.com","infomaniakos.*","informacion.es","inhumanity.com","insidenova.com","instaporno.net","ios.codevn.net","iqksisgw.xyz>>","isekaitube.com","issstories.xyz","itopmusics.com","itopmusicx.com","iuhoosiers.com","jacksorrell.tv","jalshamoviez.*","janamathaya.lk","japannihon.com","japantaboo.com","javaguides.net","javbangers.com","javggvideo.xyz","javhdvideo.org","javheroine.com","javplayers.com","javsexfree.com","javsubindo.com","javtsunami.com","javxxxporn.com","jeniusplay.com","jewelry.com.my","jizzbunker.com","join2babes.com","joyousplay.xyz","jpopsingles.eu","juegoviejo.com","jugomobile.com","juicy3dsex.com","justababes.com","justembeds.xyz","justthegays.tv","kaboomtube.com","kahanighar.com","kakarotfoot.ru","kannadamasti.*","kashtanka2.com","keepkoding.com","kendralist.com","kgs-invest.com","khabarbyte.com","kickassanime.*","kickasshydra.*","kiddyshort.com","kindergeld.org","kingofdown.com","kiradream.blog","kisahdunia.com","kits4beats.com","klartext-ne.de","kokostream.net","komikmanhwa.me","kompasiana.com","kordramass.com","kurakura21.com","kuruma-news.jp","ladkibahin.com","lampungway.com","laprovincia.es","laradiobbs.net","laser-pics.com","latinatoday.it","lauradaydo.com","layardrama21.*","leaderpost.com","leakedzone.com","leakshaven.com","learnospot.com","lebahmovie.com","ledauphine.com","lesboluvin.com","lesfoodies.com","letmejerk2.com","letmejerk3.com","letmejerk4.com","letmejerk5.com","letmejerk6.com","letmejerk7.com","lewdcorner.com","lifehacker.com","ligainsider.de","limetorrents.*","linemarlin.com","link.vipurl.in","linkconfig.com","livenewsof.com","lizardporn.com","login.asda.com","lokhung888.com","lookmovie186.*","ludwig-van.com","lulustream.com","m.liputan6.com","mactechnews.de","macworld.co.uk","mad4wheels.com","madchensex.com","madmaxworld.tv","mahitimanch.in","mail.yahoo.com","main-spitze.de","maliekrani.com","manga4life.com","mangamovil.net","manganatos.com","mangaraw18.net","mangarawad.fit","mangareader.to","manhuarmtl.com","manhuascan.com","manhwaclub.net","manhwalist.com","manhwaread.com","marketbeat.com","masteranime.tv","mathepower.com","maths101.co.za","matureworld.ws","mcafee-com.com","mega-debrid.eu","megacanais.com","megalinks.info","megamovies.org","megapastes.com","mehr-tanken.de","mejortorrent.*","mercato365.com","meteologix.com","mewingzone.com","milanotoday.it","milanworld.net","milffabrik.com","minecraft.buzz","minorpatch.com","mixmods.com.br","mixrootmod.com","mjsbigblog.com","mkv-pastes.com","mobileporn.cam","mockupcity.com","modapkfile.com","moddedguru.com","modenatoday.it","moderngyan.com","moegirl.org.cn","mommybunch.com","mommysucks.com","momsextube.pro","mortaltech.com","motchill29.com","motherless.com","motogpstream.*","motorgraph.com","motorsport.com","motscroises.fr","movearnpre.com","moviefree2.com","movies2watch.*","moviesapi.club","movieshd.watch","moviesjoy-to.*","moviesjoyhd.to","moviesnation.*","movisubmalay.*","mtsproducoes.*","multiplayer.it","mummumtime.com","musketfire.com","mxpacgroup.com","mycoolmoviez.*","mydesibaba.com","myforecast.com","myglamwish.com","mylifetime.com","mynewsmedia.co","mypornhere.com","myporntape.com","mysexgamer.com","mysexgames.com","myshrinker.com","mytectutor.com","naasongsfree.*","naijauncut.com","nammakalvi.com","naszemiasto.pl","navysports.com","nazarickol.com","nensaysubs.net","neonxcloud.top","neservicee.com","netchimp.co.uk","new.lewd.ninja","newmovierulz.*","newsbreak24.de","newscard24.com","ngontinh24.com","nicheporno.com","nichetechy.com","nikaplayer.com","ninernoise.com","nirjonmela.com","nishankhatri.*","niteshyadav.in","nitro-link.com","nitroflare.com","niuhuskies.com","nodenspace.com","nosteam.com.ro","notunmovie.net","notunmovie.org","novaratoday.it","novel-gate.com","novelaplay.com","novelgames.com","novostrong.com","nowosci.com.pl","nudebabes.sexy","nulledbear.com","nulledteam.com","nullforums.net","nulljungle.com","nurulislam.org","nylondolls.com","ocregister.com","officedepot.fr","oggitreviso.it","okamimiost.com","omegascans.org","onlineatlas.us","onlinekosh.com","onlineporno.cc","onlybabes.site","openstartup.tm","opentunnel.net","oregonlive.com","organismes.org","orgasmlist.com","orgyxxxhub.com","orovillemr.com","osubeavers.com","osuskinner.com","oteknologi.com","ourenseando.es","overhentai.net","palapanews.com","palofw-lab.com","pandamovies.me","pandamovies.pw","pandanote.info","pantieshub.net","panyshort.link","papafoot.click","paradepets.com","paris-tabi.com","paste-drop.com","paylaterin.com","peachytube.com","pelismartv.com","pelismkvhd.com","pelispedia24.*","pelispoptv.com","perfectgirls.*","perfektdamen.*","pervertium.com","perverzija.com","pethelpful.com","petitestef.com","pherotruth.com","phoneswiki.com","picgiraffe.com","picjgfjet.shop","pickleball.com","pictryhab.shop","picturelol.com","pimylifeup.com","pink-sluts.net","pinterpoin.com","pirate4all.com","pirateblue.com","pirateblue.net","pirateblue.org","piratemods.com","pivigames.blog","planetsuzy.org","platinmods.com","play-games.com","playcast.click","player-cdn.com","player.rtl2.de","player.sbnmp.*","playermeow.com","playertv24.com","playhydrax.com","podkontrola.pl","polsatsport.pl","polskatimes.pl","pop-player.com","popno-tour.net","porconocer.com","porn0video.com","pornahegao.xyz","pornasians.pro","pornerbros.com","pornflixhd.com","porngames.club","pornharlot.net","pornhd720p.com","pornincest.net","pornissimo.org","pornktubes.net","pornodavid.com","pornodoido.com","pornofelix.com","pornofisch.com","pornojenny.net","pornoperra.com","pornopics.site","pornoreino.com","pornotommy.com","pornotrack.net","pornozebra.com","pornrabbit.com","pornrewind.com","pornsocket.com","porntrex.video","porntube15.com","porntubegf.com","pornvideoq.com","pornvintage.tv","portaldoaz.org","portalyaoi.com","poscitechs.lol","powerover.site","premierftp.com","prepostseo.com","pressemedie.dk","primagames.com","primemovies.pl","primevid.click","primevideo.com","proapkdown.com","pruefernavi.de","purepeople.com","pussyspace.com","pussyspace.net","pussystate.com","put-locker.com","putingfilm.com","queerdiary.com","querofilmehd.*","questloops.com","quotesopia.com","rabbitsfun.com","radiotimes.com","radiotunes.com","rahim-soft.com","ramblinfan.com","rankersadda.in","rapid-cloud.co","ravenscans.com","rbxscripts.net","realbbwsex.com","realgfporn.com","realmoasis.com","realmomsex.com","realsimple.com","record-bee.com","recordbate.com","redecanaistv.*","redfaucet.site","rednowtube.com","redpornnow.com","redtubemov.com","reggiotoday.it","reisefrage.net","resortcams.com","revealname.com","reviersport.de","reviewrate.net","revivelink.com","richtoscan.com","riminitoday.it","ringelnatz.net","ripplehub.site","rlxtech24h.com","rmacsports.org","roadtrippin.fr","robbreport.com","rokuhentai.com","rollrivers.com","rollstroll.com","romaniasoft.ro","romhustler.org","royaledudes.io","rpmplay.online","rubyvidhub.com","rugbystreams.*","ruinmyweek.com","russland.jetzt","rusteensex.com","ruyashoujo.com","safefileku.com","safemodapk.com","samaysawara.in","sanfoundry.com","saratogian.com","sat.technology","sattaguess.com","saveshared.com","savevideo.tube","sciencebe21.in","scoreland.name","scrap-blog.com","screenflash.io","screenrant.com","scriptsomg.com","scriptsrbx.com","scriptzhub.com","section215.com","seeitworks.com","seekplayer.vip","seirsanduk.com","seksualios.com","selfhacked.com","serienstream.*","series2watch.*","seriesonline.*","seriesperu.com","seriesyonkis.*","serijehaha.com","severeporn.com","sex-empire.org","sex-movies.biz","sexcams-24.com","sexgamescc.com","sexgayplus.com","sextubedot.com","sextubefun.com","sextubeset.com","sexvideos.host","sexyaporno.com","sexybabes.club","sexybabesz.com","sexynakeds.com","sgvtribune.com","shahid.mbc.net","sharedwebs.com","shazysport.pro","sheamateur.com","shegotass.info","sheikhmovies.*","shesfreaky.com","shinobijawi.id","shooshtime.com","shop123.com.tw","short-url.link","shorterall.com","shrinkearn.com","shueisharaw.tv","shupirates.com","sieutamphim.me","siliconera.com","singjupost.com","sitarchive.com","sitemini.io.vn","siusalukis.com","skat-karten.de","slickdeals.net","slideshare.net","smartinhome.pl","smarttrend.xyz","smiechawatv.pl","snhupenmen.com","solidfiles.com","soranews24.com","soundboards.gg","spaziogames.it","speedostream.*","speisekarte.de","spiele.bild.de","spieletipps.de","spiritword.net","spoilerplus.tv","sporteurope.tv","sportsdark.com","sportsonline.*","sportsurge.net","spy-x-family.*","stadelahly.net","stahnivideo.cz","standard.co.uk","stardewids.com","starzunion.com","stbemuiptv.com","steamverde.net","stireazilei.eu","storiesig.info","storyblack.com","stownrusis.com","stream2watch.*","streamdesi.com","streamecho.top","streamlord.com","streamruby.com","stripehype.com","studydhaba.com","subtitleone.cc","subtorrents1.*","super-games.cz","superanimes.in","suvvehicle.com","svetserialu.io","svetserialu.to","swatchseries.*","swordalada.org","tainhanhvn.com","talkceltic.net","talkjarvis.com","tamilnaadi.com","tamilprint29.*","tamilprint30.*","tamilprint31.*","tamilprinthd.*","taradinhos.com","tarnkappe.info","taschenhirn.de","tech-blogs.com","tech-story.net","techhelpbd.com","techiestalk.in","techkeshri.com","techmyntra.net","techperiod.com","techsignin.com","techsslash.com","tecnoaldia.net","tecnobillo.com","tecnoscann.com","tecnoyfoto.com","teenager365.to","teenextrem.com","teenhubxxx.com","teensexass.com","tekkenmods.com","telemagazyn.pl","telesrbija.com","temp.modpro.co","tennisactu.net","testserver.pro","textograto.com","textovisia.com","texturecan.com","theargus.co.uk","theavtimes.com","thefantazy.com","theflixertv.to","thehesgoal.com","themeslide.com","thenetnaija.co","thepiratebay.*","theporngod.com","therichest.com","thesextube.net","thetakeout.com","thethothub.com","thetimes.co.uk","thevideome.com","thewambugu.com","thotchicks.com","titsintops.com","tojimangas.com","tomshardware.*","topcartoons.tv","topsporter.net","topwebgirls.eu","torinotoday.it","tormalayalam.*","torontosun.com","torovalley.net","torrentmac.net","totalsportek.*","tournguide.com","tous-sports.ru","towerofgod.top","toyokeizai.net","tpornstars.com","trafficnews.jp","trancehost.com","trannyline.com","trashbytes.net","traumporno.com","travelhost.com","treehugger.com","trendflatt.com","trentonian.com","trentotoday.it","tribunnews.com","tronxminer.com","truckscout24.*","tuberzporn.com","tubesafari.com","tubexxxone.com","tukangsapu.net","turbocloud.xyz","turkish123.com","tv-films.co.uk","tv.youtube.com","tvspielfilm.de","twincities.com","u123movies.com","ucfknights.com","uciteljica.net","uclabruins.com","ufreegames.com","uiuxsource.com","uktvplay.co.uk","unblocked.name","unblocksite.pw","uncpbraves.com","uncwsports.com","unlvrebels.com","uoflsports.com","uploadbank.com","uploadking.net","uploadmall.com","uploadraja.com","upnewsinfo.com","uptostream.com","urlbluemedia.*","urldecoder.org","usctrojans.com","usdtoreros.com","usersdrive.com","utepminers.com","uyduportal.net","v2movies.click","vavada5com.com","vbox7-mp3.info","vedamdigi.tech","vegamovies4u.*","vegamovvies.to","veo-hentai.com","vestimage.site","video-seed.xyz","video1tube.com","videogamer.com","videolyrics.in","videos1002.com","videoseyred.in","videosgays.net","vidguardto.xyz","vidhidepre.com","vidhidevip.com","vidstreams.net","view.ceros.com","viewmature.com","vikistream.com","viralpedia.pro","visortecno.com","vmorecloud.com","voiceloves.com","voipreview.org","voltupload.com","voyeurblog.net","vulgarmilf.com","vviruslove.com","wantmature.com","warefree01.com","watch-series.*","watchasians.cc","watchomovies.*","watchpornx.com","watchseries1.*","watchseries9.*","wcoanimedub.tv","wcoanimesub.tv","wcoforever.net","webseries.club","weihnachten.me","wenxuecity.com","westmanga.info","wetteronline.*","whatfontis.com","whatismyip.com","whats-new.cyou","whatshowto.com","whodatdish.com","whoisnovel.com","wiacsports.com","wifi4games.com","willyweather.*","windbreaker.me","wizhdsports.fi","wkutickets.com","wmubroncos.com","womennaked.net","wordpredia.com","world4ufree1.*","worldofbin.com","worthcrete.com","wow-mature.com","wowxxxtube.com","wspolczesna.pl","wsucougars.com","www-y2mate.com","www.amazon.com","www.lenovo.com","www.reddit.com","www.tiktok.com","x2download.com","xanimeporn.com","xclusivejams.*","xdld.pages.dev","xerifetech.com","xfrenchies.com","xhofficial.com","xhomealone.com","xhwebsite5.com","xiaomi-miui.gr","xmegadrive.com","xnxxporn.video","xxx-videos.org","xxxbfvideo.net","xxxblowjob.pro","xxxdessert.com","xxxextreme.org","xxxtubedot.com","xxxtubezoo.com","xxxvideohd.net","xxxxselfie.com","xxxymovies.com","xxxyoungtv.com","yabaisub.cloud","yakisurume.com","yelitzonpc.com","yomucomics.com","yottachess.com","youngbelle.net","youporngay.com","youtubetomp3.*","yoututosjeff.*","yuki0918kw.com","yumstories.com","yunakhaber.com","zazzybabes.com","zertalious.xyz","zippyshare.day","zona-leros.com","zonebourse.com","zooredtube.com","10hitmovies.com","123movies-org.*","123moviesfree.*","123moviesfun.is","18-teen-sex.com","18asiantube.com","18porncomic.com","18teen-tube.com","1direct-cloud.*","1vid1shar.space","3xamatorszex.hu","4allprograms.me","5masterzzz.site","6indianporn.com","admediaflex.com","adminreboot.com","adrianoluis.net","adrinolinks.com","advicefunda.com","aeroxplorer.com","aflizmovies.com","agrarwetter.net","ai.hubtoday.app","aitoolsfree.org","alanyapower.com","aliezstream.pro","allclassic.porn","alldeepfake.ink","alldownplay.xyz","allotech-dz.com","allpussynow.com","alltechnerd.com","allucanheat.com","amazon-love.com","amritadrino.com","anallievent.com","androidapks.biz","androidsite.net","androjungle.com","anime-sanka.com","anime7.download","animedao.com.ru","animenew.com.br","animesexbar.com","animesultra.net","animexxxsex.com","antenasports.ru","aoashimanga.com","apfelpatient.de","apkmagic.com.ar","app.blubank.com","arabshentai.com","arcadepunks.com","archivebate.com","archiwumalle.pl","argio-logic.net","asia.5ivttv.vip","asiangaysex.net","asianhdplay.net","askcerebrum.com","astrumscans.xyz","atemporal.cloud","atleticalive.it","atresplayer.com","au-di-tions.com","auto-service.de","autoindustry.ro","automat.systems","automothink.com","avoiderrors.com","awdescargas.com","azcardinals.com","babesaround.com","babesinporn.com","babesxworld.com","badgehungry.com","bangpremier.com","baylorbears.com","bdsmkingdom.xyz","bdsmporntub.com","bdsmwaytube.com","beammeup.com.au","bedavahesap.org","beingmelody.com","bellezashot.com","bengalisite.com","bengalxpress.in","bentasker.co.uk","best-shopme.com","best18teens.com","bestialporn.com","bestjavporn.com","beurettekeh.com","bgmateriali.com","bgmi32bitapk.in","bgsufalcons.com","bibliopanda.com","big12sports.com","bigboobs.com.es","bigtitslust.com","bike-urious.com","bintangplus.com","biologianet.com","blackavelic.com","blackpornhq.com","blacksexmix.com","blogenginee.com","blogpascher.com","blowxxxtube.com","bluebuddies.com","bluedrake42.com","bluemanhoop.com","bluemediafile.*","bluemedialink.*","bluemediaurls.*","bokepsin.in.net","bolly4umovies.*","bollydrive.rest","boobs-mania.com","boobsforfun.com","bookpraiser.com","boosterx.stream","boxingstream.me","boxingvideo.org","boyfriendtv.com","braziliannr.com","bresciatoday.it","brieffreunde.de","brother-usa.com","buffsports.io>>","buffstreamz.com","buickforums.com","bulbagarden.net","bunkr-albums.io","burningseries.*","buzzheavier.com","caminteresse.fr","camwhoreshd.com","camwhorespy.com","camwhorez.video","captionpost.com","carbonite.co.za","casutalaurei.ro","cataniatoday.it","catchthrust.net","cempakajaya.com","cerberusapp.com","chatropolis.com","cheatglobal.com","check-imei.info","cheese-cake.net","cherrynudes.com","chromeready.com","cieonline.co.uk","cinemakottaga.*","cineplus123.org","citibank.com.sg","ciudadgamer.com","claimclicks.com","classicoder.com","classifarms.com","cloud9obits.com","cloudnestra.com","code-source.net","codeitworld.com","codemystery.com","codeproject.com","coloringpage.eu","comicsporno.xxx","comoinstalar.me","compucalitv.com","computerbild.de","consoleroms.com","coromon.wiki.gg","cosplaynsfw.xyz","cpomagazine.com","cracking-dz.com","crackthemes.com","crazyashwin.com","crazydeals.live","creditsgoal.com","crunchyroll.com","crunchytech.net","cryptoearns.com","cta-fansite.com","cubbiescrib.com","cumshotlist.com","cutiecomics.com","cyberlynews.com","cybertechng.com","cyclingnews.com","cycraracing.com","daemonanime.net","daily-times.com","dailyangels.com","dailybreeze.com","dailycaller.com","dailycamera.com","dailyecho.co.uk","dailyknicks.com","dailymail.co.uk","dailymotion.com","dailypost.co.uk","dailystar.co.uk","dark-gaming.com","dawindycity.com","db-creation.net","dbupatriots.com","dbupatriots.org","deathonnews.com","decomaniacos.es","definitions.net","desbloqueador.*","descargas2020.*","desirenovel.com","desixxxtube.org","detikbangka.com","deutschsex.mobi","devopslanka.com","dhankasamaj.com","digiztechno.com","diminimalis.com","direct-cloud.me","dirtybadger.com","discoveryplus.*","diversanews.com","dlouha-videa.cz","dobleaccion.xyz","docs.google.com","dollarindex.org","domainwheel.com","donnaglamour.it","donnerwetter.de","dopomininfo.com","dota2freaks.com","dotadostube.com","downphanmem.com","drake-scans.com","drakerelays.org","drama-online.tv","dramanice.video","dreamcheeky.com","drinksmixer.com","driveplayer.net","droidmirror.com","dtbps3games.com","duplex-full.lol","eaglesnovel.com","easylinkref.com","ebaticalfel.com","editorsadda.com","edmontonsun.com","edumailfree.com","eksporimpor.com","elektrikmen.com","elpasotimes.com","elperiodico.com","embed.acast.com","embed.meomeo.pw","embedcanais.com","embedplayer.xyz","embedsports.top","embedstreams.me","emperorscan.com","empire-stream.*","engstreams.shop","enryucomics.com","erotikclub35.pw","esportsmonk.com","esportsnext.com","exactpay.online","exam-results.in","explorecams.com","explorosity.net","exporntoons.net","exposestrat.com","extratorrents.*","fabioambrosi.it","fapfapgames.com","farmeramania.de","faselhd-watch.*","fastcompany.com","faucetbravo.fun","fcportables.com","fellowsfilm.com","femdomworld.com","femjoybabes.com","feral-heart.com","fidlarmusic.com","file-upload.net","file-upload.org","file.gocmod.com","filecrate.store","filehost9.com>>","filespayout.com","filmesonlinex.*","filmoviplex.com","filmy4wap.co.in","filmyzilla5.com","finalnews24.com","financebolo.com","financemonk.net","financewada.com","financeyogi.net","finanzfrage.net","findnewjobz.com","fingerprint.com","firmenwissen.de","fitnesstipz.com","fiveyardlab.com","fizzlefacts.com","fizzlefakten.de","flashsports.org","flordeloto.site","flyanimes.cloud","flygbussarna.se","flywareagle.com","folgenporno.com","foodandwine.com","footyhunter.lol","forex-yours.com","foxseotools.com","freebitcoin.win","freebnbcoin.com","freecardano.com","freecourse.tech","freecricket.net","freegames44.com","freemockups.org","freeomovie.info","freepornjpg.com","freepornsex.net","freethemesy.com","freevpshere.com","freewebcart.com","french-stream.*","fsportshd.xyz>>","ftsefutures.org","fuckedporno.com","fullxxxporn.net","fztvseries.live","g-streaming.com","gadgetspidy.com","gadzetomania.pl","gamecopyworld.*","gameplayneo.com","gamersglobal.de","games.macon.com","games.word.tips","gamesaktuell.de","gamestorrents.*","gaminginfos.com","gamingvital.com","gartendialog.de","gayboystube.top","gaypornhdfree.*","gaypornlove.net","gaypornwave.com","gayvidsclub.com","gazetaprawna.pl","geiriadur.ac.uk","geissblog.koeln","gendatabase.com","georgiadogs.com","germanvibes.org","gesund-vital.de","getexploits.com","gewinnspiele.tv","gfx-station.com","girlssexxxx.com","givemeaporn.com","givemesport.com","glavmatures.com","globaldjmix.com","go.babylinks.in","gocreighton.com","goexplorers.com","gofetishsex.com","gofile.download","gogoanime.co.in","goislanders.com","gokushiteki.com","golderotica.com","golfchannel.com","gomacsports.com","gomarquette.com","gopsusports.com","goxxxvideos.com","goyoungporn.com","gradehgplus.com","grandmatube.pro","grannyfucko.com","grasshopper.com","greattopten.com","grootnovels.com","gsmfirmware.net","gsmfreezone.com","gsmmessages.com","gut-erklaert.de","hacksnation.com","halohangout.com","handypornos.net","hanimesubth.com","hardcoreluv.com","hardwareluxx.de","hardxxxmoms.com","harshfaucet.com","hd-analporn.com","hd-easyporn.com","hdjavonline.com","hds-streaming.*","healthfatal.com","heavyfetish.com","heidelberg24.de","helicomicro.com","hentai-moon.com","hentai-senpai.*","hentai2read.com","hentaiarena.com","hentaibatch.com","hentaibooty.com","hentaicloud.com","hentaicovid.org","hentaifreak.org","hentaigames.app","hentaihaven.com","hentaihaven.red","hentaihaven.vip","hentaihaven.xxx","hentaiporno.xxx","hentaipulse.com","hentaitube1.lol","heroine-xxx.com","hesgoal-live.io","hiddencamhd.com","hindinews360.in","hokiesports.com","hollaforums.com","hollymoviehd.cc","hollywoodpq.com","hookupnovel.com","hostserverz.com","hot-cartoon.com","hotgameplus.com","hotmediahub.com","hotpornfile.org","hotsexstory.xyz","hotstunners.com","hotxxxpussy.com","hqxxxmovies.com","hscprojects.com","hypicmodapk.org","iban-rechner.de","ibcomputing.com","ibeconomist.com","ideal-teens.com","ikramlar.online","ilbassoadige.it","ilgazzettino.it","illicoporno.com","ilmessaggero.it","ilsole24ore.com","imagelovers.com","imgqnnnebrf.sbs","incgrepacks.com","indiakablog.com","infrafandub.com","inside-handy.de","instabiosai.com","insuredhome.org","interracial.com","investcrust.com","inyatrust.co.in","iptvjournal.com","italianoxxx.com","itsonsitetv.com","iwantmature.com","januflix.expert","japangaysex.com","japansporno.com","japanxxxass.com","jastrzabpost.pl","javcensored.net","javenglish.cc>>","javindosub.site","javmoviexxx.com","javpornfull.com","javraveclub.com","javteentube.com","javtrailers.com","jaysjournal.com","jetztspielen.de","jnvharidwar.org","jobslampung.net","johntryopen.com","jokerscores.com","just-upload.com","kabarportal.com","karaoketexty.cz","kasvekuvvet.net","katmoviehd4.com","kattannonser.se","kawarthanow.com","keezmovies.surf","ketoconnect.net","ketubanjiwa.com","kickass-anime.*","kickassanime.ch","kiddyearner.com","kingsleynyc.com","kisshentaiz.com","kitabmarkaz.xyz","kittycatcam.com","kodewebsite.com","komikdewasa.art","komorkomania.pl","krakenfiles.com","kreiszeitung.de","krktcountry.com","kstorymedia.com","kurierverlag.de","kyoto-kanko.net","la123movies.org","langitmovie.com","laptechinfo.com","latinluchas.com","lavozdigital.es","ldoceonline.com","learnedclub.com","lecrabeinfo.net","legionscans.com","lendrive.web.id","lesbiansex.best","levante-emv.com","libertycity.net","librasol.com.br","liga3-online.de","lightsnovel.com","link.3dmili.com","link.asiaon.top","link.cgtips.org","link.codevn.net","linksheild.site","linkss.rcccn.in","linkvertise.com","linux-talks.com","live.arynews.tv","livescience.com","livesport24.net","livestreames.us","livestreamtv.pk","livexscores.com","livingathome.de","livornotoday.it","lombardiave.com","lookmoviess.com","looptorrent.org","lotusgamehd.xyz","lovelynudez.com","lovingsiren.com","luchaonline.com","lucrebem.com.br","lukesitturn.com","lulustream.live","lustesthd.cloud","lycee-maroc.com","macombdaily.com","macrotrends.net","magdownload.org","maisonbrico.com","mangahentai.xyz","mangahere.today","mangakakalot.gg","mangaonline.fun","mangaraw1001.cc","mangarawjp.asia","mangarussia.com","manhuarmmtl.com","manhwahentai.me","manoramamax.com","mantrazscan.com","marie-claire.es","marimo-info.net","marketmovers.it","maskinbladet.dk","mastakongo.info","mathsstudio.com","mathstutor.life","maxcheaters.com","maxjizztube.com","maxstream.video","maxtubeporn.net","me-encantas.com","medeberiya.site","medeberiya1.com","medeberiyaa.com","medeberiyas.com","medeberiyax.com","mediacast.click","mega4upload.com","mega4upload.net","mejortorrento.*","mejortorrents.*","mejortorrentt.*","memoriadatv.com","mensfitness.com","mensjournal.com","mentalfloss.com","mercerbears.com","mercurynews.com","messinatoday.it","metal-hammer.de","milliyet.com.tr","miniminiplus.pl","minutolivre.com","mirrorpoi.my.id","mixrootmods.com","mmsmasala27.com","mobility.com.ng","mockuphunts.com","modporntube.com","moflix-stream.*","molbiotools.com","mommy-pussy.com","momtubeporn.xxx","motherporno.com","mov18plus.cloud","moviemaniak.com","movierulzfree.*","movierulzlink.*","movies2watch.tv","moviescounter.*","moviesonline.fm","moviessources.*","moviessquad.com","movieuniverse.*","mp3fromyou.tube","mrdeepfakes.com","mscdroidlabs.es","msdos-games.com","msonglyrics.com","msuspartans.com","muchohentai.com","multifaucet.org","musiclutter.xyz","musikexpress.de","myanimelist.net","mybestxtube.com","mydesiboobs.com","myfreeblack.com","mysexybabes.com","mywatchseries.*","myyoungbabe.com","mzansinudes.com","naijanowell.com","naijaray.com.ng","nakedbabes.club","nangiphotos.com","nativesurge.net","nativesurge.top","naughtyza.co.za","nbareplayhd.com","nbcolympics.com","necksdesign.com","needgayporn.com","nekopoicare.*>>","nemzetisport.hu","netflixlife.com","networkhint.com","news-herald.com","news-leader.com","newstechone.com","newyorkjets.com","nflspinzone.com","nicexxxtube.com","nizarstream.com","noindexscan.com","noithatmyphu.vn","nokiahacking.pl","nosteamgames.ro","notebookcheck.*","notesformsc.org","noteshacker.com","notunmovie.link","novelssites.com","nsbtmemoir.site","nsfwmonster.com","nsfwyoutube.com","nswdownload.com","nu6i-bg-net.com","nudeslegion.com","nudismteens.com","nukedpacks.site","nullscripts.net","nursexfilme.com","nyaatorrent.com","oceanofmovies.*","okiemrolnika.pl","olamovies.store","olympustaff.com","omgexploits.com","online-smss.com","onlinekosten.de","open3dmodel.com","openculture.com","openloading.com","order-order.com","orgasmatrix.com","oromedicine.com","otokukensaku.jp","otomi-games.com","ourcoincash.xyz","oyundunyasi.net","ozulscansen.com","pacersports.com","pageflutter.com","pakkotoisto.com","palermotoday.it","panda-novel.com","pandamovies.org","pandasnovel.com","paperzonevn.com","paste4free.site","pawastreams.org","pawastreams.pro","pcgameszone.com","peliculas8k.com","peliculasmx.net","pelisflix20.*>>","pelismarthd.com","pelisxporno.net","pendekarsubs.us","pepperlive.info","perezhilton.com","perfektdamen.co","persianhive.com","perugiatoday.it","pewresearch.org","pflege-info.net","phonerotica.com","phongroblox.com","pianetalecce.it","pics4upload.com","picxnkjkhdf.sbs","pimpandhost.com","pinoyalbums.com","pinoyrecipe.net","piratehaven.xyz","pisshamster.com","pixdfdjkkr.shop","pixkfjtrkf.shop","planetfools.com","platinporno.com","play.hbomax.com","player.msmini.*","plugincrack.com","pocket-lint.com","popcornstream.*","popdaily.com.tw","porhubvideo.com","porn-monkey.com","pornexpanse.com","pornfactors.com","porngameshd.com","pornhegemon.com","pornhoarder.net","porninblack.com","porno-porno.net","porno-rolik.com","pornohammer.com","pornohirsch.net","pornoklinge.com","pornomanoir.com","pornrusskoe.com","portable4pc.com","powergam.online","premiumporn.org","privatemoviez.*","projectfreetv.*","promimedien.com","proxydocker.com","punishworld.com","purelyceleb.com","pussy3dporn.com","pussyhothub.com","qatarstreams.me","quiltfusion.com","quotesshine.com","r1.richtoon.top","rackusreads.com","radionatale.com","radionylive.com","radiorockon.com","railwebcams.net","rajssoid.online","ramdomlives.com","rangerboard.com","ravennatoday.it","rctechsworld.in","readbitcoin.org","readhunters.xyz","readingpage.fun","redpornblog.com","remodelista.com","rennrad-news.de","renoconcrete.ca","rentbyowner.com","reportera.co.kr","restegourmet.de","retroporn.world","risingapple.com","ritacandida.com","robot-forum.com","rojadirectatv.*","rollingstone.de","romaierioggi.it","romfirmware.com","root-nation.com","route-fifty.com","rule34vault.com","runnersworld.de","rushuploads.com","ryansharich.com","saabcentral.com","salernotoday.it","samapkstore.com","sampledrive.org","samuraiscan.org","santhoshrcf.com","satoshi-win.xyz","savealoonie.com","scan-hentai.net","scatnetwork.com","schwaebische.de","sdmoviespoint.*","sekaikomik.live","serienstream.to","seriesmetro.net","seriesonline.sx","seriouseats.com","serverbd247.com","serviceemmc.com","setfucktube.com","sex-torrent.net","sexanimesex.com","sexoverdose.com","sexseeimage.com","sexwebvideo.com","sexxxanimal.com","sexy-parade.com","sexyerotica.net","seznamzpravy.cz","sfmcompile.club","shadagetech.com","shadowrangers.*","sharegdrive.com","sharinghubs.com","shemalegape.net","shomareh-yab.ir","shopkensaku.com","short-jambo.ink","showcamrips.com","showrovblog.com","shrugemojis.com","shugraithou.com","siamfishing.com","sieutamphim.org","singingdalong.*","siriusfiles.com","sitetorrent.com","sivackidrum.net","slapthesign.com","sleazedepot.com","sleazyneasy.com","smartcharts.net","sms-anonyme.net","sms-receive.net","smsonline.cloud","smumustangs.com","soconsports.com","software-on.com","softwaresde.com","solarchaine.com","sommerporno.com","sondriotoday.it","souq-design.com","sourceforge.net","spanishdict.com","spardhanews.com","sport890.com.uy","sports-stream.*","sportsblend.net","sportsonline.si","sportsonline.so","sportsplays.com","sportsseoul.com","sportstiger.com","sportstreamtv.*","starstreams.pro","start-to-run.be","stbemuiptvn.com","sterkinekor.com","stream.bunkr.ru","streamnoads.com","stronakobiet.pl","studybullet.com","subtitlecat.com","sueddeutsche.de","sulasokvids.net","sullacollina.it","sumirekeiba.com","suneelkevat.com","superdeporte.es","superembeds.com","supermarches.ca","supermovies.org","svethardware.cz","swift4claim.com","syracusefan.com","tabooanime.club","tagesspiegel.de","tamilanzone.com","tamilultra.team","tapeantiads.com","tapeblocker.com","techacrobat.com","techadvisor.com","techastuces.com","techedubyte.com","techinferno.com","technichero.com","technorozen.com","techoreview.com","techprakash.com","techsbucket.com","techyhigher.com","techymedies.com","tedenglish.site","teen-hd-sex.com","teenfucksex.com","teenpornjpg.com","teensextube.xxx","teenxxxporn.pro","telegraph.co.uk","telepisodes.org","temporeale.info","tenbaiquest.com","tenies-online.*","tennisonline.me","tennisstreams.*","teracourses.com","texassports.com","textreverse.com","thaiairways.com","the-mystery.org","the2seasons.com","theappstore.org","thebarchive.com","thebigblogs.com","theclashify.com","thedilyblog.com","thegrowthop.com","thejetpress.com","thejoblives.com","themoviesflix.*","theprovince.com","thereporter.com","thestreameast.*","thetoneking.com","theusaposts.com","thewebflash.com","theyarehuge.com","thingiverse.com","thingstomen.com","thisisrussia.io","thueringen24.de","thumpertalk.com","ticketmaster.sg","tickhosting.com","ticonsiglio.com","tieba.baidu.com","tienganhedu.com","tires.costco.ca","today-obits.com","todopolicia.com","toeflgratis.com","tokuzilla.net>>","tokyomotion.com","tokyomotion.net","tophostdeal.com","topnewsshow.com","topperpoint.com","topstarnews.net","torascripts.org","tornadomovies.*","torrentgalaxy.*","torrentgame.org","torrentstatus.*","torresette.news","tradingview.com","transfermarkt.*","trendohunts.com","trevisotoday.it","triesteprima.it","true-gaming.net","trytutorial.com","tubegaytube.com","tubepornnow.com","tudongnghia.com","tuktukcinma.com","turbovidhls.com","turkeymenus.com","tusachmanga.com","tvanouvelles.ca","tvsportslive.fr","twistedporn.com","twitchnosub.com","tyler-brown.com","u6lyxl0w.skin>>","ukathletics.com","ukaudiomart.com","ultramovies.org","undeniable.info","underhentai.net","unipanthers.com","updateroj24.com","uploadbeast.com","uploadcloud.pro","usaudiomart.com","user.guancha.cn","vectogravic.com","veekyforums.com","vegamovies3.org","veneziatoday.it","verpelis.gratis","verywellfit.com","vfxdownload.net","vicenzatoday.it","viciante.com.br","vidcloudpng.com","video.genyt.net","videodidixx.com","videosputas.xxx","vidsrc-embed.ru","vik1ngfile.site","ville-ideale.fr","viralharami.com","viralxvideos.es","voyageforum.com","vtplayer.online","wantedbabes.com","warmteensex.com","watch-my-gf.com","watch.sling.com","watchf1full.com","watchfreexxx.pw","watchhentai.net","watchmovieshd.*","watchporn4k.com","watchpornfree.*","watchseries8.to","watchserieshd.*","watchtvseries.*","watchxxxfree.pw","wealthcatal.com","webmatrices.com","webtoonscan.com","wegotcookies.co","weltfussball.at","wemakesites.net","wheelofgold.com","wholenotism.com","wholevideos.com","wieistmeineip.*","wikijankari.com","wikipooster.com","wikisharing.com","windowslite.net","windsorstar.com","winnipegsun.com","witcherhour.com","womenshealth.de","world-iptv.club","worldgyan18.com","worldofiptv.com","worldsports.*>>","wowpornlist.xyz","wowyoungsex.com","wpgdadatong.com","wristreview.com","writeprofit.org","wvv-fmovies.com","www.youtube.com","xfuckonline.com","xhardhempus.net","xianzhenyuan.cn","xiaomitools.com","xkeezmovies.com","xmoviesforyou.*","xn--31byd1i.net","xnudevideos.com","xnxxhamster.net","xxxindianporn.*","xxxparodyhd.net","xxxpornmilf.com","xxxtubegain.com","xxxtubenote.com","xxxtubepass.com","xxxwebdlxxx.top","yanksgoyard.com","yazilidayim.net","yesmovies123.me","yeutienganh.com","yogablogfit.com","yomoviesnow.com","yorkpress.co.uk","youlikeboys.com","youmedemblik.nl","young-pussy.com","youranshare.com","yourporngod.com","youtubekids.com","yrtourguide.com","ytconverter.app","yuramanga.my.id","zeroradio.co.uk","zonavideosx.com","zone-annuaire.*","zoominar.online","007stockchat.com","123movies-free.*","18-teen-porn.com","18-teen-tube.com","18adultgames.com","18comic-gquu.vip","1movielinkbd.com","1movierulzhd.pro","24pornvideos.com","2kspecialist.net","4fingermusic.com","8-ball-magic.com","9now.nine.com.au","about-drinks.com","activevoyeur.com","activistpost.com","actresstoday.com","adblockstrtape.*","adblockstrtech.*","adult-empire.com","adultporn.com.es","advertafrica.net","agedtubeporn.com","aghasolution.com","ajaxshowtime.com","ajkalerbarta.com","alleveilingen.be","alleveilingen.nl","alliptvlinks.com","allporncomic.com","alphagames4u.com","alphapolis.co.jp","alphasource.site","altselection.com","anakteknik.co.id","analsexstars.com","analxxxvideo.com","androidadult.com","androidfacil.org","androidgreek.com","androidspill.com","anime-odcinki.pl","animesexclip.com","animetwixtor.com","animixstream.com","antennasports.ru","aopathletics.org","apkandroidhub.in","app.simracing.gp","applediagram.com","aquariumgays.com","arezzonotizie.it","articlesmania.me","asianmassage.xyz","asianpornjav.com","assettoworld.com","asyaanimeleri.pw","athlonsports.com","atlantisscan.com","auburntigers.com","audiofanzine.com","audycje.tokfm.pl","autotrader.co.uk","avellinotoday.it","azamericasat.net","azby.fmworld.net","baby-vornamen.de","backfirstwo.site","backyardboss.net","backyardpapa.com","bangyourwife.com","barrier-free.net","base64decode.org","bcuathletics.com","beaddiagrams.com","beritabangka.com","berlin-teltow.de","bestasiansex.pro","bestblackgay.com","bestcash2020.com","bestgamehack.top","bestgrannies.com","besthdmovies.com","bestpornflix.com","bestsextoons.com","beta.plus.rtl.de","biblegateway.com","bigbuttshub2.top","bikeportland.org","birdswatcher.com","bisceglielive.it","bitchesgirls.com","blackandteal.com","blog.livedoor.jp","blowjobfucks.com","bloxinformer.com","bloxyscripts.com","bluemediafiles.*","bluerabbitrx.com","bmw-scooters.com","boardingarea.com","boerse-online.de","bollywoodfilma.*","bondagevalley.cc","booksbybunny.com","boolwowgirls.com","bootstrample.com","bostonherald.com","boysxclusive.com","brandbrief.co.kr","bravoerotica.com","bravoerotica.net","breatheheavy.com","breedingmoms.com","buffalobills.com","buffalowdown.com","businesstrend.jp","butlersports.com","butterpolish.com","bysedikamoum.com","bysesayeveum.com","call2friends.com","caminspector.net","campusfrance.org","camvideoshub.com","camwhoresbay.com","caneswarning.com","cartoonporno.xxx","catmovie.website","ccnworldtech.com","celtadigital.com","cervezaporno.com","championdrive.co","charexempire.com","chattanoogan.com","cheatography.com","chelsea24news.pl","chicagobears.com","chieflyoffer.com","choiceofmods.com","chubbyelders.com","cizzyscripts.com","claimsatoshi.xyz","clever-tanken.de","clickforhire.com","clickndownload.*","clipconverter.cc","cloudgallery.net","cmumavericks.com","coin-profits.xyz","collegehdsex.com","colliersnews.com","coloredmanga.com","comeletspray.com","cometogliere.com","comicspornos.com","comicspornow.com","comicsvalley.com","computerpedia.in","convert2mp3.club","convertinmp4.com","courseleader.net","cr7-soccer.store","cracksports.me>>","criptologico.com","cryptoclicks.net","cryptofactss.com","cryptofaucet.xyz","cryptokinews.com","cryptomonitor.in","cybercityhelp.in","cyberstumble.com","cydiasources.net","dailyboulder.com","dailypudding.com","dailytips247.com","dailyuploads.net","darknessporn.com","darkwanderer.net","dasgelbeblatt.de","dataunlocker.com","dattebayo-br.com","davewigstone.com","dayoftheweek.org","daytonflyers.com","ddl-francais.com","deepfakeporn.net","deepswapnude.com","demonicscans.org","designparty.sx>>","desikamababa.com","detroitlions.com","diariodeibiza.es","dirtytubemix.com","discoveryplus.in","djremixganna.com","doanhnghiepvn.vn","dobrapogoda24.pl","dobreprogramy.pl","donghuaworld.com","dorsetecho.co.uk","downloadapk.info","downloadbatch.me","downloadsite.org","downloadsoft.net","dpscomputing.com","dryscalpgone.com","dualshockers.com","duplichecker.com","dvdgayonline.com","earncrypto.co.in","eartheclipse.com","eastbaytimes.com","easymilftube.net","ebook-hunter.org","ecom.wixapps.net","edufileshare.com","einfachschoen.me","eleceedmanhwa.me","eletronicabr.com","elevationmap.net","eliobenedetto.it","embedseek.online","embedstreams.top","empire-anime.com","emulatorsite.com","english101.co.za","erotichunter.com","eslauthority.com","esportstales.com","everysextube.com","ewrc-results.com","exclusivomen.com","fallbrook247.com","familyporner.com","famousnipple.com","fastdownload.top","fattelodasolo.it","fatwhitebutt.com","faucetcrypto.com","faucetcrypto.net","favefreeporn.com","favoyeurtube.net","femmeactuelle.fr","fernsehserien.de","fessesdenfer.com","fetishshrine.com","filespayouts.com","filmestorrent.tv","filmyhitlink.xyz","filmyhitt.com.in","financacerta.com","fineasiansex.com","finofilipino.org","fitnessholic.net","fitnessscenz.com","flatpanelshd.com","footwearnews.com","footymercato.com","footystreams.net","foreverquote.xyz","forexcracked.com","forextrader.site","forgepattern.net","forum-xiaomi.com","foxsports.com.au","freegetcoins.com","freehardcore.com","freehdvideos.xxx","freelitecoin.vip","freemcserver.net","freemomstube.com","freemoviesu4.com","freeporncave.com","freevstplugins.*","freshersgold.com","fullxcinema1.com","fullxxxmovies.me","fumettologica.it","fussballdaten.de","gadgetxplore.com","game-repack.site","gamemodsbase.com","gamers-haven.org","games.boston.com","games.kansas.com","games.modbee.com","games.puzzles.ca","games.sacbee.com","games.sltrib.com","games.usnews.com","gamesrepacks.com","gamingbeasts.com","gamingdeputy.com","gaminglariat.com","ganstamovies.com","gartenlexikon.de","gaydelicious.com","gazetalubuska.pl","gbmwolverine.com","gdrivelatino.net","gdrivemovies.xyz","gemiadamlari.org","genialetricks.de","gentlewasher.com","getdatgadget.com","getdogecoins.com","getworkation.com","gezegenforum.com","ghettopearls.com","ghostsfreaks.com","gidplayer.online","gigemgazette.com","girlschannel.net","globelempire.com","go.discovery.com","go.shortnest.com","goblackbears.com","godstoryinfo.com","goetbutigers.com","gogetadoslinks.*","gomcpanthers.com","gometrostate.com","goodyoungsex.com","gophersports.com","gopornindian.com","greasygaming.com","greenarrowtv.com","gruene-zitate.de","gruporafa.com.br","gsm-solution.com","gtamaxprofit.com","guncelkaynak.com","gutesexfilme.com","hadakanonude.com","handelsblatt.com","happyinshape.com","hard-tubesex.com","hardfacefuck.com","hausbau-forum.de","hayatarehber.com","hd-tube-porn.com","healthylifez.com","hechosfizzle.com","heilpraxisnet.de","helpdeskgeek.com","hentaicomics.pro","hentaiseason.com","hentaistream.com","hentaivideos.net","hotcopper.com.au","hotdreamsxxx.com","hotpornyoung.com","hotpussyhubs.com","houstonpress.com","hqpornstream.com","huskercorner.com","id.condenast.com","idmextension.xyz","ielts-isa.edu.vn","ignoustudhelp.in","ikindlebooks.com","imagereviser.com","imageshimage.com","imagetotext.info","imperiofilmes.co","infinityfree.com","infomatricula.pt","inprogrammer.com","intellischool.id","interviewgig.com","investopedia.com","investorveda.com","isekaibrasil.com","isekaipalace.com","jalshamoviezhd.*","japaneseasmr.com","japanesefuck.com","japanfuck.com.es","javenspanish.com","javfullmovie.com","justblogbaby.com","justswallows.net","kakarotfoot.ru>>","katiescucina.com","kayifamilytv.com","khatrimazafull.*","kingdomfiles.com","kingstreamz.site","kireicosplay.com","kitchennovel.com","kitraskimisi.com","knowyourmeme.com","kodibeginner.com","kokosovoulje.com","komikstation.com","komputerswiat.pl","kshowsubindo.org","kstatesports.com","ksuathletics.com","kurakura21.space","kuttymovies1.com","lakeshowlife.com","lampungkerja.com","larvelfaucet.com","lascelebrite.com","latesthdmovies.*","latinohentai.com","lavanguardia.com","lawyercontact.us","lectormangaa.com","leechpremium.net","legionjuegos.org","lehighsports.com","lesbiantube.club","letmewatchthis.*","lettersolver.com","levelupalone.com","lg-firmwares.com","libramemoria.com","lifesurance.info","lightxxxtube.com","limetorrents.lol","linux-magazin.de","linuxexplain.com","live.vodafone.de","livenewsflix.com","logofootball.net","lookmovie.studio","loudountimes.com","ltpcalculator.in","luminatedata.com","lumpiastudio.com","lustaufsleben.at","lustesthd.makeup","macrocreator.com","magicseaweed.com","mahobeachcam.com","mammaebambini.it","manga-scantrad.*","mangacanblog.com","mangaforfree.com","mangaindo.web.id","markstyleall.com","masstamilans.com","mastaklomods.com","masterplayer.xyz","matshortener.xyz","mature-tube.sexy","maxisciences.com","meconomynews.com","mee-cccdoz45.com","meetdownload.com","megafilmeshd20.*","megajapansex.com","mejortorrents1.*","merlinshoujo.com","meteoetradar.com","milanreports.com","milfxxxpussy.com","milkporntube.com","mlookalporno.com","mockupgratis.com","mockupplanet.com","moto-station.com","mountaineast.org","movielinkhub.xyz","movierulz2free.*","movierulzwatch.*","movieshdwatch.to","movieshubweb.com","moviesnipipay.me","moviesrulzfree.*","moviestowatch.tv","mrproblogger.com","msmorristown.com","msumavericks.com","multimovies.tech","musiker-board.de","my-ford-focus.de","myair.resmed.com","mycivillinks.com","mydownloadtube.*","myfitnesspal.com","mylegalporno.com","mylivestream.pro","mymotherlode.com","myproplugins.com","myradioonline.pl","nakedbbw-sex.com","naruldonghua.com","nationalpost.com","nativesurge.info","nauathletics.com","naughtyblogs.xyz","neatfreeporn.com","neatpornodot.com","netflixporno.net","netizensbuzz.com","newanimeporn.com","newsinlevels.com","newsobserver.com","newstvonline.com","nghetruyenma.net","nguyenvanbao.com","nhentaihaven.org","niftyfutures.org","nintendolife.com","nl.hardware.info","nocsummer.com.br","nonesnanking.com","nontonhentai.net","notebookchat.com","notiziemusica.it","novablogitalia.*","nude-teen-18.com","nudemomshots.com","null-scripts.net","officecoach24.de","ohionowcast.info","older-mature.net","oldgirlsporn.com","onestringlab.com","onlineporn24.com","onlyfanvideo.com","onlygangbang.com","onlygayvideo.com","onlyindianporn.*","open.spotify.com","openloadmovies.*","optimizepics.com","oranhightech.com","orenoraresne.com","oswegolakers.com","otakuanimess.net","oxfordmail.co.uk","pagalworld.video","pandaatlanta.com","pandafreegames.*","parentcircle.com","parking-map.info","pdfstandards.net","pedroinnecco.com","penis-bilder.com","personefamose.it","phinphanatic.com","physics101.co.za","pigeonburger.xyz","pinsexygirls.com","play.gamezop.com","play.history.com","player.gayfor.us","player.hdgay.net","player.pop.co.uk","player4me.online","playsexgames.xxx","pleasuregirl.net","plumperstube.com","plumpxxxtube.com","pokeca-chart.com","police.community","ponselharian.com","porn-hd-tube.com","pornclassic.tube","pornclipshub.com","pornforrelax.com","porngayclips.com","pornhub-teen.com","pornobengala.com","pornoborshch.com","pornoteensex.com","pornsex-pics.com","pornstargold.com","pornuploaded.net","pornvideotop.com","pornwatchers.com","pornxxxplace.com","pornxxxxtube.net","portnywebcam.com","post-gazette.com","postermockup.com","powerover.site>>","practicequiz.com","prajwaldesai.com","praveeneditz.com","privatenudes.com","programme-tv.net","programsolve.com","prosiebenmaxx.de","purduesports.com","purposegames.com","puzzles.nola.com","pythonjobshq.com","qrcodemonkey.net","rabbitstream.net","radio-deejay.com","realityblurb.com","realjapansex.com","receptyonline.cz","recordonline.com","redbirdrants.com","rendimentibtp.it","repack-games.com","reportbangla.com","reviewmedium.com","ribbelmonster.de","rimworldbase.com","ringsidenews.com","ripplestream4u.*","riwayat-word.com","rocketrevise.com","rollingstone.com","royale-games.com","rule34hentai.net","rv-ecommerce.com","sabishiidesu.com","safehomefarm.com","sainsburys.co.uk","saradahentai.com","sarugbymag.co.za","satoshifaucet.io","savethevideo.com","savingadvice.com","schaken-mods.com","schildempire.com","schoolcheats.net","search.brave.com","seattletimes.com","secretsdujeu.com","semuanyabola.com","sensualgirls.org","serienjunkies.de","serieslandia.com","sesso-escort.com","sexanimetube.com","sexfilmkiste.com","sexflashgame.org","sexhardtubes.com","sexjapantube.com","sexlargetube.com","sexmomvideos.com","sexontheboat.xyz","sexpornasian.com","sextingforum.net","sexybabesart.com","sexyoungtube.com","sharelink-1.site","sheepesports.com","shelovesporn.com","shemalemovies.us","shemalepower.xyz","shemalestube.com","shimauma-log.com","shoot-yalla.live","short.croclix.me","shortenlinks.top","shortylink.store","showbizbites.com","shrinkforearn.in","shrinklinker.com","signupgenius.com","sikkenscolore.it","simpleflying.com","simplyvoyage.com","sitesunblocked.*","skidrowcodex.net","skidrowcrack.com","skintagsgone.com","smallseotools.ai","smart-wohnen.net","smartermuver.com","smashyplayer.top","soccershoes.blog","softdevelopp.com","softwaresite.net","solution-hub.com","soonersports.com","soundpark-club.*","southpark.cc.com","soyoungteens.com","space-faucet.com","spigotunlocked.*","splinternews.com","sportpiacenza.it","sportshub.stream","sportsloverz.xyz","sportstream.live","spotifylists.com","sshconect.com.br","sssinstagram.com","stablerarena.com","stagatvfiles.com","stiflersmoms.com","stileproject.com","stillcurtain.com","stockhideout.com","stopstreamtv.net","storieswatch.com","stream.nflbox.me","stream4free.live","streamblasters.*","streamcenter.xyz","streamextreme.cc","streamingnow.mov","streamingworld.*","streamloverx.com","strefabiznesu.pl","strtapeadblock.*","suamusica.com.br","sukidesuost.info","sunshine-live.de","supremebabes.com","swiftuploads.com","sxmislandcam.com","synoniemboek.com","tamarindoyam.com","tapelovesads.org","taroot-rangi.com","teachmemicro.com","techgeek.digital","techkhulasha.com","technewslive.org","tecnotutoshd.net","teensexvideos.me","telcoinfo.online","telegratuita.com","tempatwisata.pro","text-compare.com","the1security.com","thecozyapron.com","thecustomrom.com","thefappening.pro","thegadgetking.in","thehiddenbay.com","theinventory.com","thejobsmovie.com","thelandryhat.com","thelosmovies.com","thelovenerds.com","thematurexxx.com","thenerdstash.com","thenewsdrill.com","thenewsglobe.net","thenextplanet1.*","theorie-musik.de","thepiratebay.org","thepoorcoder.com","thesportster.com","thesportsupa.com","thesundevils.com","thetrendverse.in","thevikingage.com","thisisfutbol.com","timesnownews.com","timesofindia.com","tires.costco.com","tiroalpaloes.net","titansonline.com","tnstudycorner.in","todays-obits.com","todoandroid.live","tonanmedia.my.id","topvideosgay.com","toramemoblog.com","torrentkitty.one","totallyfuzzy.net","totalsportek.app","toureiffel.paris","towsontigers.com","tptvencore.co.uk","tradersunion.com","travelerdoor.com","trendytalker.com","troyyourlead.com","trucosonline.com","truetrophies.com","truevpnlover.com","tube-teen-18.com","tube.shegods.com","tuotromedico.com","turbogvideos.com","turboplayers.xyz","turtleviplay.xyz","tutorialsaya.com","tweakcentral.net","twobluescans.com","typinggames.zone","uconnhuskies.com","unionpayintl.com","universegunz.net","unrealengine.com","upfiles-urls.com","upgradedhome.com","upstyledaily.com","urlgalleries.net","ustrendynews.com","uvmathletics.com","uwlathletics.com","vancouversun.com","vandaaginside.nl","vegamoviese.blog","veryfreeporn.com","verywellmind.com","vichitrainfo.com","videocdnal24.xyz","videosection.com","vikingf1le.us.to","villettt.kitchen","vinstartheme.com","viralvideotube.*","viralxxxporn.com","vivrebordeaux.fr","vodkapr3mium.com","voiranime.stream","voyeurfrance.net","voyeurxxxsex.com","vpshostplans.com","vrporngalaxy.com","vzrosliedamy.com","watchanime.video","watchfreekav.com","watchfreexxx.net","watchmovierulz.*","watchmovies2.com","wbschemenews.com","wearehunger.site","web.facebook.com","webcamsdolls.com","webcheats.com.br","webdesigndev.com","webdeyazilim.com","webseriessex.com","websitesball.com","werkzeug-news.de","whentostream.com","whitexxxtube.com","wiadomosci.wp.pl","wildpictures.net","willow.arlen.icu","windowsonarm.org","wolfgame-ar.site","womenreality.com","woodmagazine.com","word-grabber.com","workxvacation.jp","worldhistory.org","wrestlinginc.com","wrzesnia.info.pl","wunderground.com","wvuathletics.com","www.amazon.co.jp","www.amazon.co.uk","www.facebook.com","xhamster-art.com","xhamsterporno.mx","xhamsterteen.com","xvideos-full.com","xxxanimefuck.com","xxxlargeporn.com","xxxlesvianas.com","xxxretrofuck.com","xxxteenyporn.com","xxxvideos247.com","yellowbridge.com","yesjavplease.fun","yona-yethu.co.za","youngerporn.mobi","youtubetoany.com","youtubetowav.net","youwatch.monster","youwatchporn.com","ysokuhou.blog.jp","zdravenportal.eu","zecchino-doro.it","ziggogratis.site","ziminvestors.com","ziontutorial.com","zippyshare.cloud","zwergenstadt.com","123moviesonline.*","123strippoker.com","12thmanrising.com","1337x.unblocked.*","1337x.unblockit.*","19-days-manga.com","1movierulzhd.hair","1teentubeporn.com","2japaneseporn.com","acapellas4u.co.uk","acdriftingpro.com","adblockplustape.*","adffdafdsafds.sbs","alaskananooks.com","allcelebspics.com","alternativeto.net","altyazitube22.lat","amateur-twink.com","amateurfapper.com","amsmotoresllc.com","ancient-origins.*","andhrafriends.com","androidonepro.com","androidpolice.com","animalwebcams.net","anime-torrent.com","animecenterbr.com","animeidhentai.com","animelatinohd.com","animeonline.ninja","animepornfilm.com","animesonlinecc.us","animexxxfilms.com","anonymousemail.me","apostoliclive.com","arabshentai.com>>","arcade.lemonde.fr","armypowerinfo.com","asianfucktube.com","asiansexcilps.com","assignmentdon.com","atalantini.online","autoexpress.co.uk","babyjimaditya.com","badassoftcore.com","badgerofhonor.com","bafoeg-aktuell.de","bandyforbundet.no","bargainbriana.com","bcanotesnepal.com","beargoggleson.com","bebasbokep.online","beritasulteng.com","bestanime-xxx.com","besthdgayporn.com","besthugecocks.com","bestpussypics.net","beyondtheflag.com","bgmiupdate.com.in","bigdickwishes.com","bigtitsxxxsex.com","black-matures.com","blackhatworld.com","bladesalvador.com","blizzboygames.net","blog.linksfire.co","blog.textpage.xyz","blogcreativos.com","blogtruyenmoi.com","bollywoodchamp.in","bostoncommons.net","bracontece.com.br","bradleybraves.com","brazzersbabes.com","brindisireport.it","brokensilenze.net","brookethoughi.com","browncrossing.net","brushednickel.biz","calgaryherald.com","camchickscaps.com","cameronaggies.com","candyteenporn.com","carensureplan.com","catatanonline.com","cavalierstream.fr","cdn.gledaitv.live","celebritablog.com","charbelnemnom.com","chat.tchatche.com","cheat.hax4you.net","checkfiletype.com","chicksonright.com","cindyeyefinal.com","cinecalidad5.site","cinema-sketch.com","citethisforme.com","citpekalongan.com","ciudadblogger.com","claplivehdplay.ru","classicreload.com","clickjogos.com.br","cloudhostingz.com","coatingsworld.com","codingshiksha.com","coempregos.com.br","compota-soft.work","computercrack.com","computerfrage.net","computerhilfen.de","comunidadgzone.es","conferenceusa.com","consoletarget.com","cool-style.com.tw","coolmathgames.com","crichd-player.top","cruisingearth.com","cryptednews.space","cryptoblog24.info","cryptowidgets.net","crystalcomics.com","curiosidadtop.com","daemon-hentai.com","dailybulletin.com","dailydemocrat.com","dailyfreebits.com","dailygeekshow.com","dailytech-news.eu","dallascowboys.com","damndelicious.net","darts-scoring.com","dawnofthedawg.com","dealsfinders.blog","dearcreatives.com","deine-tierwelt.de","deinesexfilme.com","dejongeturken.com","denverbroncos.com","descarga-animex.*","design4months.com","designtagebuch.de","desitelugusex.com","developer.arm.com","diamondfansub.com","diaridegirona.cat","diariocordoba.com","diencobacninh.com","dirtyindianporn.*","dl.apkmoddone.com","doctor-groups.com","dorohedoro.online","downloadapps.info","downloadtanku.org","downloadudemy.com","downloadwella.com","dynastyseries.com","dzienniklodzki.pl","e-hausaufgaben.de","earninginwork.com","easyjapanesee.com","easyvidplayer.com","easywithcode.tech","ebonyassclips.com","eczpastpapers.net","editions-actu.org","einfachtitten.com","elamigosgamez.com","elamigosgamez.net","empire-streamz.fr","emulatorgames.net","encurtandourl.com","encurtareidog.top","engel-horoskop.de","enormousbabes.net","entertubeporn.com","epsilonakdemy.com","eromanga-show.com","estrepublicain.fr","eternalmangas.org","etownbluejays.com","euro2024direct.ru","eurotruck2.com.br","extreme-board.com","extremotvplay.com","faceittracker.net","fansonlinehub.com","fantasticporn.net","fastconverter.net","fatgirlskinny.net","fattubevideos.net","femalefirst.co.uk","fgcuathletics.com","fightinghawks.com","file.magiclen.org","financialpost.com","finanzas-vida.com","fineretroporn.com","finexxxvideos.com","finish.addurl.biz","fitnakedgirls.com","fitnessplanss.com","fitnesssguide.com","flight-report.com","floridagators.com","foguinhogames.net","footballstream.tv","footfetishvid.com","footstockings.com","fordownloader.com","formatlibrary.com","forum.blu-ray.com","fplstatistics.com","freeboytwinks.com","freecodezilla.net","freecourseweb.com","freemagazines.top","freeoseocheck.com","freepdf-books.com","freepornrocks.com","freepornstream.cc","freepornvideo.sex","freepornxxxhd.com","freerealvideo.com","freethesaurus.com","freex2line.online","freexxxvideos.pro","french-streams.cc","freshstuff4u.info","friendproject.net","frkn64modding.com","frosinonetoday.it","fuerzasarmadas.eu","fuldaerzeitung.de","fullfreeimage.com","fullxxxmovies.net","futbolsayfasi.net","games-manuals.com","games.puzzler.com","games.thestar.com","gamesofdesire.com","gaminggorilla.com","gay-streaming.com","gaypornhdfree.com","gebrauchtwagen.at","getwallpapers.com","gewinde-normen.de","girlsofdesire.org","girlswallowed.com","globalstreams.xyz","gobigtitsporn.com","goblueraiders.com","godriveplayer.com","gogetapast.com.br","gogueducation.com","goltelevision.com","googleapis.com.de","googleapis.com.do","gothunderbirds.ca","grannyfuckxxx.com","grannyxxxtube.net","graphicgoogle.com","grsprotection.com","gwiazdatalkie.com","hakunamatata5.org","hallo-muenchen.de","happy-otalife.com","hardcoregamer.com","hardwaretimes.com","hbculifestyle.com","hdfilmizlesen.com","hdvintagetube.com","headlinerpost.com","healbot.dpm15.net","healthcheckup.com","hegreartnudes.com","help.cashctrl.com","hentaibrasil.info","hentaienglish.com","hentaitube.online","hideandseek.world","hikarinoakari.com","hollywoodlife.com","hostingunlock.com","hotkitchenbag.com","hotmaturetube.com","hotspringsofbc.ca","houseandgarden.co","houstontexans.com","howtoconcepts.com","hunterscomics.com","iedprivatedqu.com","imgdawgknuttz.com","imperialstudy.com","independent.co.uk","indianporn365.net","indofirmware.site","indojavstream.com","infinityscans.net","infinityscans.org","infinityscans.xyz","inside-digital.de","insidermonkey.com","instantcloud.site","insurancepost.xyz","ironwinter6m.shop","isabihowto.com.ng","isekaisubs.web.id","isminiunuttum.com","jamiesamewalk.com","janammusic.in.net","japaneseholes.com","japanpornclip.com","japanxxxworld.com","jardiner-malin.fr","jokersportshd.org","juegos.elpais.com","k-statesports.com","k-statesports.net","k-statesports.org","kandisvarlden.com","kenshi.fandom.com","kh-pokemon-mc.com","khabardinbhar.net","kickasstorrents.*","kill-the-hero.com","kimcilonlyofc.com","kiuruvesilehti.fi","know-how-tree.com","kontenterabox.com","kontrolkalemi.com","koreanbeauty.club","korogashi-san.org","kreis-anzeiger.de","kurierlubelski.pl","lachainemeteo.com","lacuevadeguns.com","laksa19.github.io","lavozdegalicia.es","lebois-racing.com","lecturisiarome.ro","leechpremium.link","leechyscripts.net","lespartisanes.com","lheritierblog.com","libertestreamvf.*","limontorrents.com","line-stickers.com","link.turkdown.com","linuxsecurity.com","lisatrialidea.com","locatedinfain.com","lonely-mature.com","lovegrowswild.com","lucagrassetti.com","luciferdonghua.in","luckypatchers.com","lycoathletics.com","madhentaitube.com","malaysiastock.biz","maps4study.com.br","marthastewart.com","mature-chicks.com","maturepussies.pro","mdzsmutpcvykb.net","media.cms.nova.cz","megajapantube.com","metaforespress.gr","mfmfinancials.com","miamidolphins.com","miaminewtimes.com","milfpussy-sex.com","minecraftwild.com","mizugigurabia.com","mlbpark.donga.com","mlbstreaming.live","mmorpgplay.com.br","mobilanyheter.net","modelsxxxtube.com","modescanlator.net","mommyporntube.com","momstube-porn.com","moonblinkwifi.com","motorradfrage.net","motorradonline.de","moviediskhd.cloud","movielinkbd4u.com","moviezaddiction.*","mp3cristianos.net","mundovideoshd.com","murtonroofing.com","music.youtube.com","muyinteresante.es","myabandonware.com","myair2.resmed.com","myfunkytravel.com","mynakedwife.video","mzansixporn.co.za","nasdaqfutures.org","national-park.com","negative.tboys.ro","nepalieducate.com","networklovers.com","new-xxxvideos.com","nextchessmove.com","ngin-mobility.com","nieuwsvandedag.nl","nightlifeporn.com","nikkan-gendai.com","nikkeifutures.org","njwildlifecam.com","nobodycancool.com","nonsensediamond.*","nzpocketguide.com","oceanof-games.com","oceanoffgames.com","odekake-spots.com","officedepot.co.cr","officialpanda.com","olemisssports.com","ondemandkorea.com","onepiecepower.com","onlinemschool.com","onlinesextube.com","onlineteenhub.com","ontariofarmer.com","openspeedtest.com","opensubtitles.com","oportaln10.com.br","osmanonline.co.uk","osthessen-news.de","ottawacitizen.com","ottrelease247.com","outdoorchannel.de","overwatchporn.xxx","pahaplayers.click","palmbeachpost.com","pandaznetwork.com","panel.skynode.pro","pantyhosepink.com","paramountplus.com","paraveronline.org","pghk.blogspot.com","phimlongtieng.net","phoenix-manga.com","phonefirmware.com","piazzagallura.org","pistonpowered.com","plantatreenow.com","play.aidungeon.io","playembedapi.site","player.glomex.com","playerflixapi.com","playerjavseen.com","playmyopinion.com","playporngames.com","pleated-jeans.com","pockettactics.com","popcornmovies.org","porn-sexypics.com","pornanimetube.com","porngirlstube.com","pornoenspanish.es","pornoschlange.com","pornxxxvideos.net","practicalkida.com","prague-blog.co.il","premiumporn.org>>","prensaesports.com","prescottenews.com","press-citizen.com","presstelegram.com","primeanimesex.com","primeflix.website","progameguides.com","project-free-tv.*","projectfreetv.one","promisingapps.com","promo-visits.site","protege-liens.com","pubgaimassist.com","publicananker.com","publicdomainq.net","publicdomainr.net","publicflashing.me","punisoku.blogo.jp","pussytorrents.org","qatarstreams.me>>","queenofmature.com","radiolovelive.com","radiosymphony.com","ragnarokmanga.com","randomarchive.com","rateyourmusic.com","rawindianporn.com","readallcomics.com","readcomiconline.*","readfireforce.com","realvoyeursex.com","reporterpb.com.br","reprezentacija.rs","retrosexfilms.com","reviewjournal.com","richieashbeck.com","robloxscripts.com","rojadirectatvhd.*","roms-download.com","roznamasiasat.com","rule34.paheal.net","sahlmarketing.net","samfordsports.com","sanangelolive.com","sanmiguellive.com","sarkarinaukry.com","savemoneyinfo.com","sayphotobooth.com","scandichotels.com","schoolsweek.co.uk","scontianastro.com","searchnsucceed.in","seasons-dlove.net","send-anywhere.com","series9movies.com","sevenjournals.com","sexmadeathome.com","sexyebonyteen.com","sexyfreepussy.com","shahiid-anime.net","share.filesh.site","shentai-anime.com","shinshi-manga.net","shittokuadult.net","shortencash.click","shrink-service.it","sidearmsocial.com","sideplusleaks.com","sim-kichi.monster","simply-hentai.com","simplyrecipes.com","simplywhisked.com","simulatormods.com","skidrow-games.com","skillheadlines.in","skodacommunity.de","slaughtergays.com","smallseotools.com","soccerworldcup.me","softwaresblue.com","south-park-tv.biz","spectrum.ieee.org","speculationis.com","spedostream2.shop","spiritparting.com","sponsorhunter.com","sportanalytic.com","sportingsurge.com","sportlerfrage.net","sportsbuff.stream","sportsgames.today","sportzonline.site","stapadblockuser.*","stellarthread.com","stepsisterfuck.me","storefront.com.ng","stories.los40.com","straatosphere.com","streamadblocker.*","streaming-one.com","streamingunity.to","streamlivetv.site","streamonsport99.*","streamseeds24.com","streamshunters.eu","stringreveals.com","suanoticia.online","super-ethanol.com","susanhavekeep.com","tabele-kalorii.pl","tamaratattles.com","tamilbrahmins.com","tamilsexstory.net","tattoosbeauty.com","tautasdziesmas.lv","techadvisor.co.uk","techautomobile.in","techiepirates.com","techlog.ta-yan.ai","technewsrooms.com","technewsworld.com","techsolveprac.com","teenpornvideo.sex","teenpornvideo.xxx","testlanguages.com","texture-packs.com","thaihotmodels.com","thangdangblog.com","theandroidpro.com","thecelticblog.com","thecubexguide.com","thedailybeast.com","thedigitalfix.com","thefreebieguy.com","thegamearcade.com","thehealthsite.com","theismailiusa.org","thekingavatar.com","theliveupdate.com","theouterhaven.net","theregister.co.uk","thermoprzepisy.pl","thesprucepets.com","theworldobits.com","thousandbabes.com","tichyseinblick.de","tiktokcounter.net","timesnowhindi.com","tippsundtricks.co","titfuckvideos.com","tmail.sys64738.at","tomatespodres.com","toplickevesti.com","topsworldnews.com","torrent-pirat.com","torrentdownload.*","tradingfact4u.com","trannylibrary.com","trannyxxxtube.net","truyen-hentai.com","truyenaudiocv.net","tubepornasian.com","tubepornstock.com","ultimate-catch.eu","ultrateenporn.com","umatechnology.org","undeadwalking.com","unsere-helden.com","uptechnologys.com","urjalansanomat.fi","url.gem-flash.com","utepathletics.com","vanillatweaks.net","venusarchives.com","vide-greniers.org","video.gazzetta.it","videogameszone.de","videos.remilf.com","vietnamanswer.com","viralitytoday.com","virtualnights.com","visualnewshub.com","vitalitygames.com","voiceofdenton.com","voyeurpornsex.com","voyeurspyporn.com","voyeurxxxfree.com","wannafreeporn.com","watchanimesub.net","watchfacebook.com","watchsouthpark.tv","websiteglowgh.com","weknowconquer.com","welcometojapan.jp","wellness4live.com","wirralglobe.co.uk","wirtualnemedia.pl","wohnmobilforum.de","worldfreeware.com","worldgreynews.com","worthitorwoke.com","wpsimplehacks.com","xfreepornsite.com","xhamsterdeutsch.*","xnxx-sexfilme.com","xxxonlinefree.com","xxxpussyclips.com","xxxvideostrue.com","yesdownloader.com","yongfucknaked.com","yummysextubes.com","zeenews.india.com","zeijakunahiko.com","zeroto60times.com","zippysharecue.com","1001tracklists.com","101soundboards.com","10minuteemails.com","123moviesready.org","123moviestoday.net","1337x.unblock2.xyz","247footballnow.com","7daystodiemods.com","adblockeronstape.*","addictinggames.com","adultasianporn.com","advertisertape.com","afasiaarchzine.com","airportwebcams.net","akuebresources.com","allureamateurs.net","alternativa104.net","amateur-mature.net","angrybirdsnest.com","animesonliner4.com","anothergraphic.org","antenasport.online","arcade.buzzrtv.com","arcadeprehacks.com","arkadiumhosted.com","arsiv.mackolik.com","asian-teen-sex.com","asianbabestube.com","asianpornfilms.com","asiansexdiarys.com","asianstubefuck.com","atlantafalcons.com","atlasstudiousa.com","autocadcommand.com","badasshardcore.com","baixedetudo.net.br","ballexclusives.com","barstoolsports.com","basic-tutorials.de","bdsmslavemovie.com","beamng.wesupply.cx","bearchasingart.com","beermoneyforum.com","beginningmanga.com","berliner-kurier.de","beruhmtemedien.com","best-xxxvideos.com","bestialitytaboo.tv","bettingexchange.it","bidouillesikea.com","bigdata-social.com","bigdata.rawlazy.si","bigpiecreative.com","bigsouthsports.com","bigtitsxxxfree.com","birdsandblooms.com","blisseyhusband.net","blogredmachine.com","blogx.almontsf.com","blowjobamateur.net","blowjobpornset.com","bluecoreinside.com","bluemediastorage.*","bombshellbling.com","bonsaiprolink.shop","bosoxinjection.com","businessinsider.de","calculatorsoup.com","camwhorescloud.com","captown.capcom.com","cararegistrasi.com","casos-aislados.com","cdimg.blog.2nt.com","cehennemstream.xyz","cerbahealthcare.it","chiangraitimes.com","chicagobearshq.com","chicagobullshq.com","chicasdesnudas.xxx","chikianimation.org","choiceappstore.xyz","cintateknologi.com","clampschoolholic.*","classicalradio.com","classicxmovies.com","climaaovivo.com.br","clothing-mania.com","codingnepalweb.com","coleccionmovie.com","comicspornoxxx.com","comparepolicyy.com","comparteunclic.com","contractpharma.com","couponscorpion.com","cr7-soccer.store>>","creditcardrush.com","crimsonscrolls.net","crm.urlwebsite.com","cronachesalerno.it","cryptonworld.space","dallasobserver.com","datapendidikan.com","dawgpounddaily.com","dcdirtylaundry.com","denverpioneers.com","depressionhurts.us","descargaspcpro.net","desifuckonline.com","deutschekanale.com","devicediary.online","dianaavoidthey.com","diariodenavarra.es","digicol.dpm.org.cn","dirtyasiantube.com","dirtygangbangs.com","discover-sharm.com","diyphotography.net","diyprojectslab.com","donaldlineelse.com","donghuanosekai.com","doublemindtech.com","downloadcursos.top","downloadgames.info","downloadmusic.info","downloadpirate.com","dragonball-zxk.com","dramathical.stream","dulichkhanhhoa.net","e-mountainbike.com","elconfidencial.com","elearning-cpge.com","embed-player.space","empire-streaming.*","english-dubbed.com","english-topics.com","erikcoldperson.com","evdeingilizcem.com","eveningtimes.co.uk","exactlyhowlong.com","expressbydgoski.pl","extremosports.club","familyhandyman.com","favoyeurtube.net>>","fightingillini.com","financenova.online","financialjuice.com","flacdownloader.com","flashgirlgames.com","flashingjungle.com","foodiesgallery.com","foreversparkly.com","formasyonhaber.net","forum.cstalking.tv","francaisfacile.net","free-gay-clips.com","freeadultcomix.com","freeadultvideos.cc","freebiesmockup.com","freecoursesite.com","freefireupdate.com","freegogpcgames.com","freegrannyvids.com","freemockupzone.com","freemoviesfull.com","freepornasians.com","freepublicporn.com","freereceivesms.com","freeviewmovies.com","freevipservers.net","freevstplugins.net","freewoodworking.ca","freex2line.onlinex","freshwaterdell.com","friscofighters.com","fritidsmarkedet.dk","fuckhairygirls.com","fuckingsession.com","fullvideosporn.com","galinhasamurai.com","gamerevolution.com","games.arkadium.com","games.kentucky.com","games.mashable.com","games.thestate.com","gamingforecast.com","gaypornmasters.com","gazetakrakowska.pl","gazetazachodnia.eu","gdrivelatinohd.net","geniale-tricks.com","geniussolutions.co","girlsgogames.co.uk","go.bucketforms.com","goafricaonline.com","gobankingrates.com","gocurrycracker.com","godrakebulldog.com","gojapaneseporn.com","golf.rapidmice.com","gorro-4go5b3nj.fun","grouppornotube.com","gruenderlexikon.de","gudangfirmwere.com","guessthemovie.name","hamptonpirates.com","hard-tube-porn.com","healthfirstweb.com","healthnewsreel.com","healthy4pepole.com","heatherdisarro.com","hentaipornpics.net","hentaisexfilms.com","heraldscotland.com","hiddencamstube.com","highkeyfinance.com","hindustantimes.com","homeairquality.org","homemoviestube.com","hotanimevideos.com","hotbabeswanted.com","hotxxxjapanese.com","hqamateurtubes.com","huffingtonpost.com","huitranslation.com","humanbenchmark.com","hyundaitucson.info","idedroidsafelink.*","idevicecentral.com","ifreemagazines.com","ikingfile.mooo.com","ilcamminodiluce.it","imagetranslator.io","indecentvideos.com","indesignskills.com","indianbestporn.com","indianpornvideos.*","indiansexbazar.com","infamous-scans.com","infinitehentai.com","infinityblogger.in","infojabarloker.com","informatudo.com.br","informaxonline.com","insidemarketing.it","insidememorial.com","insider-gaming.com","insurancesfact.com","intercelestial.com","investor-verlag.de","iowaconference.com","italianporn.com.es","ithinkilikeyou.net","iusedtobeaboss.com","jacksonguitars.com","jamessoundcost.com","japanesemomsex.com","japanesetube.video","jasminetesttry.com","jemontremabite.com","jeux.meteocity.com","johnalwayssame.com","jojolandsmanga.com","joomlabeginner.com","jujustu-kaisen.com","justfamilyporn.com","justpicsplease.com","justtoysnoboys.com","kawaguchimaeda.com","kdramasmaza.com.pk","kellywhatcould.com","keralatelecom.info","kickasstorrents2.*","kittyfuckstube.com","knowyourphrase.com","kobitacocktail.com","komisanwamanga.com","kr-weathernews.com","krebs-horoskop.com","kstatefootball.net","kstatefootball.org","laopinioncoruna.es","leagueofgraphs.com","leckerschmecker.me","leo-horoscopes.com","letribunaldunet.fr","leviathanmanga.com","levismodding.co.uk","lib.hatenablog.com","link.get2short.com","link.paid4link.com","linkedmoviehub.top","linux-community.de","listenonrepeat.com","literarysomnia.com","littlebigsnake.com","liveandletsfly.com","localemagazine.com","longbeachstate.com","lotus-tours.com.hk","loyolaramblers.com","lukecomparetwo.com","luzernerzeitung.ch","m.timesofindia.com","maggotdrowning.com","magicgameworld.com","makeincomeinfo.com","maketecheasier.com","makotoichikawa.net","mallorcazeitung.es","manager-magazin.de","manchesterworld.uk","mangas-origines.fr","manoramaonline.com","maraudersports.com","mathplayground.com","maturetubehere.com","maturexxxclips.com","mctechsolutions.in","mediascelebres.com","megafilmeshd50.com","megahentaitube.com","megapornfreehd.com","mein-wahres-ich.de","memorialnotice.com","merlininkazani.com","mespornogratis.com","mesquitaonline.com","minddesignclub.org","minhasdelicias.com","mobilelegends.shop","mobiletvshows.site","modele-facture.com","moflix-stream.fans","montereyherald.com","motorcyclenews.com","moviescounnter.com","moviesonlinefree.*","mygardening411.com","myhentaicomics.com","mymusicreviews.com","myneobuxportal.com","mypornstarbook.net","nadidetarifler.com","naijachoice.com.ng","nakedgirlsroom.com","nakedneighbour.com","nauci-engleski.com","nauci-njemacki.com","netaffiliation.com","neueroeffnung.info","nevadawolfpack.com","newjapanesexxx.com","news-geinou100.com","newyorkupstate.com","nicematureporn.com","niestatystyczny.pl","nightdreambabe.com","nontonvidoy.online","noodlemagazine.com","novacodeportal.xyz","nudebeachpussy.com","nudecelebforum.com","nuevos-mu.ucoz.com","nyharborwebcam.com","o2tvseries.website","oceanbreezenyc.org","officegamespot.com","omnicalculator.com","onepunch-manga.com","onetimethrough.com","onlinesudoku.games","onlinetutorium.com","onlinework4all.com","onlygoldmovies.com","onscreensvideo.com","openchat-review.me","pakistaniporn2.com","passeportsante.net","passportaction.com","pc-spiele-wiese.de","pcgamedownload.net","pcgameshardware.de","peachprintable.com","peliculas-dvdrip.*","penisbuyutucum.net","pestleanalysis.com","pinayviralsexx.com","plainasianporn.com","play.starsites.fun","play.watch20.space","player.euroxxx.net","player.vidplus.pro","playeriframe.lol>>","playretrogames.com","pliroforiki-edu.gr","policesecurity.com","policiesreview.com","polskawliczbach.pl","pornhubdeutsch.net","pornmaturetube.com","pornohubonline.com","pornovideos-hd.com","pornvideospass.com","powerthesaurus.org","premiumstream.live","present.rssing.com","printablecrush.com","problogbooster.com","productkeysite.com","projectfreetv2.com","projuktirkotha.com","proverbmeaning.com","psicotestuned.info","pussytubeebony.com","racedepartment.com","radio-en-direct.fr","radioitalylive.com","radionorthpole.com","ratemyteachers.com","realfreelancer.com","realtormontreal.ca","recherche-ebook.fr","redamateurtube.com","redbubbletools.com","redstormsports.com","replica-watch.info","reporterherald.com","rightdark-scan.com","rincondelsazon.com","ripcityproject.com","risefromrubble.com","romaniataramea.com","ryanagoinvolve.com","sabornutritivo.com","samrudhiglobal.com","samurai.rzword.xyz","sandrataxeight.com","sankakucomplex.com","sattakingcharts.in","scarletandgame.com","scarletknights.com","schoener-wohnen.de","sciencechannel.com","scopateitaliane.it","seamanmemories.com","selfstudybrain.com","sethniceletter.com","sexiestpicture.com","sexteenxxxtube.com","sexy-youtubers.com","sexykittenporn.com","sexymilfsearch.com","shadowrangers.live","shemaletoonsex.com","shipseducation.com","shrivardhantech.in","shutupandgo.travel","sidelionreport.com","siirtolayhaber.com","simpledownload.net","siteunblocked.info","slowianietworza.pl","smithsonianmag.com","soccerstream100.to","sociallyindian.com","softwaredetail.com","sosyalbilgiler.net","southernliving.com","southparkstudios.*","spank-and-bang.com","sportstohfa.online","stapewithadblock.*","stream.nflbox.me>>","streamelements.com","streaming-french.*","strtapeadblocker.*","surgicaltechie.com","sweeteroticart.com","syracusecrunch.com","tamilultratv.co.in","tapeadsenjoyer.com","tcpermaculture.com","technicalviral.com","telefullenvivo.com","telexplorer.com.ar","theblissempire.com","thecelticbhoys.com","theendlessmeal.com","thefirearmblog.com","thehentaiworld.com","thelesbianporn.com","thepewterplank.com","thepiratebay10.org","theralphretort.com","thestarphoenix.com","thesuperdownload.*","thiagorossi.com.br","thisisourbliss.com","tiervermittlung.de","tiktokrealtime.com","times-standard.com","tiny-sparklies.com","tips-and-tricks.co","tokyo-ghoul.online","tonpornodujour.com","topbiography.co.in","torrentdosfilmes.*","torrentdownloads.*","totalsportekhd.com","traductionjeux.com","trannysexmpegs.com","transgirlslive.com","traveldesearch.com","travelplanspro.com","trendyol-milla.com","tribeathletics.com","trovapromozioni.it","truckingboards.com","truyenbanquyen.com","truyenhentai18.net","tuhentaionline.com","tulsahurricane.com","turboimagehost.com","tv3play.skaties.lv","tvonlinesports.com","tweaksforgeeks.com","txstatebobcats.com","ucirvinesports.com","ukrainesmodels.com","uncensoredleak.com","universfreebox.com","unlimitedfiles.xyz","urbanmilwaukee.com","urlaubspartner.net","venus-and-mars.com","vermangasporno.com","verywellhealth.com","victor-mochere.com","videos.porndig.com","videosinlevels.com","videosxxxputas.com","vintagepornfun.com","vintagepornnew.com","vintagesexpass.com","waitrosecellar.com","washingtonpost.com","watch.rkplayer.xyz","watch.shout-tv.com","watchadsontape.com","wblaxmibhandar.com","weakstreams.online","weatherzone.com.au","web.livecricket.is","webloadedmovie.com","websitesbridge.com","werra-rundschau.de","wheatbellyblog.com","wildhentaitube.com","windowsmatters.com","winteriscoming.net","wohnungsboerse.net","woman.excite.co.jp","worldstreams.click","wormser-zeitung.de","www.apkmoddone.com","www.cloudflare.com","www.primevideo.com","xbox360torrent.com","xda-developers.com","xn--kckzb2722b.com","xpressarticles.com","xxx-asian-tube.com","xxxanimemovies.com","xxxanimevideos.com","yify-subtitles.org","youngpussyfuck.com","youwatch-serie.com","yt-downloaderz.com","ytmp4converter.com","znanemediablog.com","zxi.mytechroad.com","aachener-zeitung.de","abukabir.fawrye.com","abyssplay.pages.dev","academiadelmotor.es","adblockstreamtape.*","addtobucketlist.com","adultgamesworld.com","agrigentonotizie.it","aliendictionary.com","allafricangirls.net","allindiaroundup.com","allporncartoons.com","almohtarif-tech.net","altadefinizione01.*","amateur-couples.com","amaturehomeporn.com","amazingtrannies.com","androidrepublic.org","angeloyeo.github.io","animefuckmovies.com","animeonlinefree.org","animesonlineshd.com","annoncesescorts.com","anonymous-links.com","anonymousceviri.com","app.link2unlock.com","app.studysmarter.de","aprenderquechua.com","arabianbusiness.com","arizonawildcats.com","arnaqueinternet.com","arrowheadaddict.com","artificialnudes.com","asiananimaltube.org","asianfuckmovies.com","asianporntube69.com","audiobooks4soul.com","audiotruyenfull.com","bailbondsfinder.com","baltimoreravens.com","beautypackaging.com","beisbolinvernal.com","berliner-zeitung.de","bestmaturewomen.com","bethshouldercan.com","bigcockfreetube.com","bigsouthnetwork.com","blackenterprise.com","blog.cloudflare.com","blog.itijobalert.in","blog.potterworld.co","bluemediadownload.*","bordertelegraph.com","brucevotewithin.com","businessinsider.com","calculascendant.com","cambrevenements.com","cancelguider.online","canuckaudiomart.com","celebritynakeds.com","celebsnudeworld.com","certificateland.com","chakrirkhabar247.in","championpeoples.com","chawomenshockey.com","chicagosportshq.com","christiantrendy.com","chubbypornmpegs.com","citationmachine.net","civilenggforall.com","classicpornbest.com","classicpornvids.com","clevelandbrowns.com","collegeteentube.com","columbiacougars.com","comicsxxxgratis.com","commande.rhinov.pro","commsbusiness.co.uk","comofuncionaque.com","compilationtube.xyz","comprovendolibri.it","concealednation.org","consigliatodanoi.it","couponsuniverse.com","crackedsoftware.biz","creativebusybee.com","crossdresserhub.com","crosswordsolver.com","crystal-launcher.pl","custommapposter.com","daddyfuckmovies.com","daddylivestream.com","dailyjobposting.xyz","dailymaverick.co.za","dartmouthsports.com","der-betze-brennt.de","descargaranimes.com","descargatepelis.com","deseneledublate.com","desktopsolution.org","detroitjockcity.com","dev.fingerprint.com","developerinsider.co","diariodemallorca.es","diarioeducacion.com","dichvureviewmap.com","diendancauduong.com","digitalfernsehen.de","digitalseoninja.com","digitalstudiome.com","dignityobituary.com","discordfastfood.com","divinelifestyle.com","divxfilmeonline.net","dktechnicalmate.com","download.megaup.net","dubipc.blogspot.com","dynamicminister.net","dziennikbaltycki.pl","dziennikpolski24.pl","dziennikzachodni.pl","earn.quotesopia.com","edmontonjournal.com","elamigosedition.com","ellibrepensador.com","embed.nana2play.com","en-thunderscans.com","en.financerites.com","erotic-beauties.com","eventiavversinews.*","expresskaszubski.pl","fansubseries.com.br","fatblackmatures.com","faucetcaptcha.co.in","felicetommasino.com","femdomporntubes.com","fifaultimateteam.it","filmeonline2018.net","filmesonlinehd1.org","firstasianpussy.com","footballfancast.com","footballstreams.lol","footballtransfer.ru","fortnitetracker.com","fplstatistics.co.uk","franceprefecture.fr","free-trannyporn.com","freecoursesites.com","freecoursesonline.*","freegamescasual.com","freeindianporn.mobi","freeindianporn2.com","freeplayervideo.com","freescorespiano.com","freesexvideos24.com","freetarotonline.com","freshsexxvideos.com","frustfrei-lernen.de","fuckmonstercock.com","fuckslutsonline.com","futura-sciences.com","gagaltotal666.my.id","gallant-matures.com","gamecocksonline.com","games.bradenton.com","games.dailymail.com","games.fresnobee.com","games.heraldsun.com","games.sunherald.com","gazetawroclawska.pl","generacionretro.net","gesund-vital.online","gfilex.blogspot.com","global.novelpia.com","gloswielkopolski.pl","goarmywestpoint.com","godrakebulldogs.com","godrakebulldogs.net","goodnewsnetwork.org","hailfloridahail.com","hamburgerinsult.com","hardcorelesbian.xyz","hardwarezone.com.sg","hardwoodhoudini.com","hartvannederland.nl","haus-garten-test.de","haveyaseenjapan.com","hawaiiathletics.com","hayamimi-gunpla.com","healthbeautybee.com","helpnetsecurity.com","hentai-mega-mix.com","hentaianimezone.com","hentaisexuality.com","hieunguyenphoto.com","highdefdiscnews.com","hindimatrashabd.com","hindimearticles.net","hindimoviesonline.*","historicaerials.com","hmc-id.blogspot.com","hobby-machinist.com","home-xxx-videos.com","horseshoeheroes.com","hostingdetailer.com","hotbeautyhealth.com","hotorientalporn.com","hqhardcoreporno.com","ianrequireadult.com","ilbolerodiravel.org","ilforumdeibrutti.is","indianpornvideo.org","individualogist.com","ingyenszexvideok.hu","insidertracking.com","insidetheiggles.com","interculturalita.it","inventionsdaily.com","iptvxtreamcodes.com","itsecuritynews.info","iulive.blogspot.com","jacquieetmichel.net","japanesexxxporn.com","javuncensored.watch","jayservicestuff.com","jessicaclearout.com","joguinhosgratis.com","justcastingporn.com","justsexpictures.com","k-statefootball.net","k-statefootball.org","kentstatesports.com","kenzo-flowertag.com","kingjamesgospel.com","kingsofkauffman.com","kissmaturestube.com","klettern-magazin.de","kreuzwortraetsel.de","kstateathletics.com","ladypopularblog.com","lawweekcolorado.com","learnchannel-tv.com","learnmarketinfo.com","legionpeliculas.org","legionprogramas.org","leitesculinaria.com","lemino.docomo.ne.jp","letrasgratis.com.ar","lifeisbeautiful.com","limiteddollqjc.shop","livetv.moviebite.cc","livingstondaily.com","localizaagencia.com","lorimuchbenefit.com","love-stoorey210.net","m.jobinmeghalaya.in","main.24jobalert.com","marketrevolution.eu","masashi-blog418.com","massagefreetube.com","maturepornphoto.com","measuringflower.com","mediatn.cms.nova.cz","meeting.tencent.com","megajapanesesex.com","meicho.marcsimz.com","miamiairportcam.com","miamibeachradio.com","migliori-escort.com","mikaylaarealike.com","mindmotion93y8.shop","minecraft-forum.net","minecraftraffle.com","minhaconexao.com.br","minutemirror.com.pk","mittelbayerische.de","mobilesexgamesx.com","montrealgazette.com","morinaga-office.net","motherandbaby.co.uk","movies-watch.com.pk","myhentaigallery.com","mynaturalfamily.com","myreadingmanga.info","noticiascripto.site","novelmultiverse.com","novelsparadise.site","nude-beach-tube.com","nudeselfiespics.com","nurparatodos.com.ar","obituaryupdates.com","oldgrannylovers.com","onlinefetishporn.cc","onlinepornushka.com","opisanie-kartin.com","orangespotlight.com","outdoor-magazin.com","painting-planet.com","parasportontario.ca","parrocchiapalata.it","paulkitchendark.com","pcgamebenchmark.com","peopleenespanol.com","perfectmomsporn.com","petitegirlsnude.com","pharmaguideline.com","phoenixnewtimes.com","phonereviewinfo.com","pickleballclubs.com","picspornamateur.com","platform.autods.com","play.dictionary.com","play.geforcenow.com","play.mylifetime.com","play.playkrx18.site","player.popfun.co.uk","player.uwatchfree.*","pompanobeachcam.com","popularasianxxx.com","poradyiwskazowki.pl","pornjapanesesex.com","pornocolegialas.org","pornocolombiano.net","pornosubtitula2.com","pornstarsadvice.com","portmiamiwebcam.com","porttampawebcam.com","pranarevitalize.com","protege-torrent.com","psychology-spot.com","publicidadtulua.com","quest.to-travel.net","raccontivietati.com","radiosantaclaus.com","radiotormentamx.com","rawofficethumbs.com","readcomicsonline.ru","realitybrazzers.com","redowlanalytics.com","relampagomovies.com","reneweconomy.com.au","richardsignfish.com","richmondspiders.com","ripplestream4u.shop","roberteachfinal.com","rojadirectaenhd.net","rojadirectatvlive.*","rollingglobe.online","romanticlesbian.com","rundschau-online.de","ryanmoore.marketing","rysafe.blogspot.com","samurai.wordoco.com","santoinferninho.com","savingsomegreen.com","scansatlanticos.com","scholarshiplist.org","schrauben-normen.de","secondhandsongs.com","sempredirebanzai.it","sempreupdate.com.br","serieshdpormega.com","seriezloaded.com.ng","setsuyakutoushi.com","sex-free-movies.com","sexyvintageporn.com","shogaisha-shuro.com","shogaisha-techo.com","sixsistersstuff.com","skidrowreloaded.com","smartkhabrinews.com","soap2day-online.com","soccerfullmatch.com","soccerworldcup.me>>","sociologicamente.it","somulhergostosa.com","sourcingjournal.com","sousou-no-frieren.*","sportitalialive.com","sportzonline.site>>","spotidownloader.com","ssdownloader.online","standardmedia.co.ke","stealthoptional.com","stevenuniverse.best","stormininnorman.com","storynavigation.com","stoutbluedevils.com","stream.offidocs.com","stream.pkayprek.com","streamadblockplus.*","streamcasthub.store","streamshunters.eu>>","streamtapeadblock.*","submissive-wife.net","summarynetworks.com","sussexexpress.co.uk","svetatnazdraveto.bg","sweetadult-tube.com","tainio-mania.online","tamilfreemp3songs.*","tapewithadblock.org","teachersupdates.net","technicalline.store","techtrendmakers.com","tekniikanmaailma.fi","telecharger-igli4.*","thebalancemoney.com","theberserkmanga.com","thecrazytourist.com","theglobeandmail.com","themehospital.co.uk","theoaklandpress.com","thesimsresource.com","thesmokingcuban.com","thewatchseries.live","throwsmallstone.com","timesnowmarathi.com","timmaybealready.com","tiz-cycling-live.io","tophentaicomics.com","toptenknowledge.com","totalfuckmovies.com","totalmaturefuck.com","transexuales.gratis","trendsderzukunft.de","trucs-et-astuces.co","tubepornclassic.com","tubevintageporn.com","turkishseriestv.net","turtleboysports.com","tutorialsduniya.com","tw-hkt.blogspot.com","ukmagazinesfree.com","uktvplay.uktv.co.uk","ultimate-guitar.com","urbandictionary.com","usinger-anzeiger.de","utahstateaggies.com","valleyofthesuns.com","veryfastdownload.pw","vinylcollective.com","vip.stream101.space","virtual-youtuber.jp","virtualdinerbot.com","vitadacelebrita.com","wallpaperaccess.com","watch-movies.com.pk","watchlostonline.net","watchmonkonline.com","watchmoviesrulz.com","watchonlinemovie.pk","webhostingoffer.org","weneverbeenfree.com","weristdeinfreund.de","windows-7-forum.net","winit.heatworld.com","woffordterriers.com","worldaffairinfo.com","worldstarhiphop.com","worldtravelling.com","www2.tmyinsight.net","xhamsterdeutsch.xyz","xn--nbkw38mlu2a.com","xnxx-downloader.net","xnxx-sex-videos.com","xxxhentaimovies.com","xxxpussysextube.com","xxxsexyjapanese.com","yaoimangaonline.com","yellowblissroad.com","yorkshirepost.co.uk","your-daily-girl.com","youramateurporn.com","youramateurtube.com","yourlifeupdated.net","youtubedownloader.*","zeeplayer.pages.dev","25yearslatersite.com","27-sidefire-blog.com","2adultflashgames.com","acienciasgalilei.com","adult-sex-gamess.com","adultdvdparadise.com","akatsuki-no-yona.com","allcelebritywiki.com","allcivilstandard.com","allnewindianporn.com","aman-dn.blogspot.com","amateurebonypics.com","amateuryoungpics.com","analysis-chess.io.vn","androidapkmodpro.com","androidtunado.com.br","angolopsicologia.com","animalextremesex.com","apenasmaisumyaoi.com","aquiyahorajuegos.net","aroundthefoghorn.com","aspdotnet-suresh.com","ayobelajarbareng.com","badassdownloader.com","bailiwickexpress.com","banglachotigolpo.xyz","best-mobilegames.com","bestmp3converter.com","bestshemaleclips.com","bigtitsporn-tube.com","blackwoodacademy.org","bloggingawaydebt.com","bloggingguidance.com","boainformacao.com.br","bogowieslowianscy.pl","bollywoodshaadis.com","boxofficebusiness.in","br.nacaodamusica.com","browardpalmbeach.com","bustyshemaleporn.com","cachevalleydaily.com","canberratimes.com.au","cartoonstvonline.com","cartoonvideos247.com","centralboyssp.com.br","charlestoughrace.com","chasingthedonkey.com","cienagamagdalena.com","climbingtalshill.com","comandotorrenthd.org","consiglietrucchi.com","crackstreamsfree.com","crackstreamshd.click","craigretailers.co.uk","creators.nafezly.com","dailygrindonline.net","dairylandexpress.com","davidsonbuilders.com","decorativemodels.com","defienietlynotme.com","deliciousmagazine.pl","demonyslowianskie.pl","denisegrowthwide.com","descargaseriestv.com","diglink.blogspot.com","divxfilmeonline.tv>>","djsofchhattisgarh.in","docs.fingerprint.com","donna-cerca-uomo.com","downloadfilm.website","durhamopenhouses.com","ear-phone-review.com","earnfromarticles.com","edivaldobrito.com.br","educationbluesky.com","embed.hideiframe.com","encuentratutarea.com","eroticteensphoto.net","escort-in-italia.com","essen-und-trinken.de","eurostreaming.casino","extremereportbot.com","fairforexbrokers.com","famosas-desnudas.org","fastpeoplesearch.com","filmeserialegratis.*","filmpornofrancais.fr","finanznachrichten.de","finding-camellia.com","fle-5r8dchma-moo.com","footballandress.club","foreverconscious.com","forexwikitrading.com","forge.plebmasters.de","forobasketcatala.com","forum.lolesporte.com","forum.thresholdx.net","fotbolltransfers.com","fr.streamon-sport.ru","free-sms-receive.com","freebigboobsporn.com","freecoursesonline.me","freelistenonline.com","freemagazinespdf.com","freemedicalbooks.org","freepatternsarea.com","freereadnovel.online","freeromsdownload.com","freestreams-live.*>>","freethailottery.live","freshshemaleporn.com","fullywatchonline.com","funeral-memorial.com","gaget.hatenablog.com","games.abqjournal.com","games.dallasnews.com","games.denverpost.com","games.kansascity.com","games.sixtyandme.com","games.wordgenius.com","gearingcommander.com","gesundheitsfrage.net","getfreesmsnumber.com","ghajini-4urg44yg.lol","giuseppegravante.com","giveawayoftheday.com","givemenbastreams.com","googledrivelinks.com","gourmetsupremacy.com","greatestshemales.com","griffinathletics.com","hackingwithreact.com","hds-streaming-hd.com","headlinepolitics.com","heartofvicksburg.com","heartrainbowblog.com","heresyoursavings.com","highheelstrample.com","historichorizons.com","hodgepodgehippie.com","hofheimer-zeitung.de","home-made-videos.com","homestratosphere.com","hornyconfessions.com","hostingreviews24.com","hotasianpussysex.com","hotjapaneseshows.com","huffingtonpost.co.uk","hypelifemagazine.com","immobilienscout24.de","india.marathinewz.in","inkworldmagazine.com","intereseducation.com","irresistiblepets.net","italiadascoprire.net","itpassportgokaku.com","jemontremonminou.com","k-stateathletics.com","kachelmannwetter.com","karaoke4download.com","karaokegratis.com.ar","keedabankingnews.com","lacronicabadajoz.com","laopiniondemalaga.es","laopiniondemurcia.es","laopiniondezamora.es","largescaleforums.com","latinatemptation.com","laweducationinfo.com","lazytranslations.com","learn.moderngyan.com","lemonsqueezyhome.com","lempaala.ideapark.fi","lesbianvideotube.com","letemsvetemapplem.eu","letsworkremotely.com","link.djbassking.live","linksdegrupos.com.br","live-tv-channels.org","loan.bgmi32bitapk.in","loan.punjabworks.com","loriwithinfamily.com","luxurydreamhomes.net","main.sportswordz.com","mangcapquangvnpt.com","maturepornjungle.com","maturewomenfucks.com","mauiinvitational.com","maxfinishseveral.com","medicalstudyzone.com","mein-kummerkasten.de","michaelapplysome.com","mkvmoviespoint.autos","money.quotesopia.com","monkeyanimalporn.com","morganhillwebcam.com","motorbikecatalog.com","motorcitybengals.com","motorsport-total.com","movieloversworld.com","moviemakeronline.com","moviesubtitles.click","mujeresdesnudas.club","mustardseedmoney.com","mylivewallpapers.com","mypace.sasapurin.com","myperfectweather.com","mypussydischarge.com","myuploadedpremium.de","naughtymachinima.com","newfreelancespot.com","neworleanssaints.com","newsonthegotoday.com","nibelungen-kurier.de","notebookcheck-ru.com","notebookcheck-tr.com","nudeplayboygirls.com","nuovo.vidplayer.live","nutraingredients.com","nylonstockingsex.net","onechicagocenter.com","online-xxxmovies.com","onlinegrannyporn.com","oraridiapertura24.it","originalteentube.com","pandadevelopment.net","pasadenastarnews.com","pcgamez-download.com","pesprofessionals.com","pipocamoderna.com.br","plagiarismchecker.co","planetaminecraft.com","platform.twitter.com","play.doramasplus.net","player.amperwave.net","player.smashy.stream","playstationhaber.com","popularmechanics.com","porlalibreportal.com","pornhub-sexfilme.net","portnassauwebcam.com","presentation-ppt.com","prismmarketingco.com","pro.iqsmartgames.com","psychologyjunkie.com","pussymaturephoto.com","radiocountrylive.com","ragnarokscanlation.*","ranaaclanhungary.com","rebeccaneverbase.com","recipestutorials.com","redensarten-index.de","remotejobzone.online","reviewingthebrew.com","rhein-main-presse.de","rinconpsicologia.com","robertplacespace.com","rockpapershotgun.com","roemische-zahlen.net","rojadirectaenvivo.pl","roms-telecharger.com","salamanca24horas.com","sandratableother.com","sarkariresult.social","savespendsplurge.com","schoolgirls-asia.org","schwaebische-post.de","securegames.iwin.com","server-tutorials.net","sexypornpictures.org","socialmediagirls.com","socket.pearsoned.com","solomaxlevelnewbie.*","spicyvintageporn.com","sportstohfa.online>>","starkroboticsfrc.com","stream.nbcsports.com","streamingcommunity.*","strtapewithadblock.*","successstoryinfo.com","superfastrelease.xyz","superpackpormega.com","swietaslowianskie.pl","tainguyenmienphi.com","tasteandtellblog.com","teenamateurphoto.com","telephone-soudan.com","teluguonlinemovies.*","telugusexkathalu.com","thefappeningblog.com","thefastlaneforum.com","thegatewaypundit.com","thekitchenmagpie.com","thesarkariresult.net","tienichdienthoai.net","tinyqualityhomes.org","tomb-raider-king.com","totalsportek1000.com","toyoheadquarters.com","travellingdetail.com","trueachievements.com","tutorialforlinux.com","udemy-downloader.com","unblockedgames.world","underground.tboys.ro","utahsweetsavings.com","utepminermaniacs.com","ver-comics-porno.com","ver-mangas-porno.com","videoszoofiliahd.com","vintageporntubes.com","viralviralvideos.com","virgo-horoscopes.com","visualcapitalist.com","wallstreet-online.de","watchallchannels.com","watchcartoononline.*","watchgameofthrones.*","watchhouseonline.net","watchsuitsonline.net","watchtheofficetv.com","wegotthiscovered.com","weihnachts-filme.com","wetasiancreampie.com","whats-on-netflix.com","wife-home-videos.com","wirtualnynowydwor.pl","worldgirlsportal.com","yakyufan-asobiba.com","youfreepornotube.com","youngerasiangirl.net","yourhomemadetube.com","youtube-nocookie.com","yummytummyaarthi.com","1337x.ninjaproxy1.com","3dassetcollection.com","3dprintersforum.co.uk","ableitungsrechner.net","ad-itech.blogspot.com","airportseirosafar.com","airsoftmilsimnews.com","allgemeine-zeitung.de","ar-atech.blogspot.com","arabamob.blogspot.com","arrisalah-jakarta.com","banglachoti-story.com","bestsellerforaday.com","bibliotecadecorte.com","bigbuttshubvideos.com","blackchubbymovies.com","blackmaturevideos.com","blasianluvforever.com","blog.motionisland.com","bournemouthecho.co.uk","branditechture.agency","brandstofprijzen.info","broncathleticfund.com","brutalanimalsfuck.com","bucetaspeludas.com.br","business-standard.com","calculator-online.net","cancer-horoscopes.com","celebritydeeplink.com","charlessheimprove.com","collinsdictionary.com","comentariodetexto.com","conselhosetruques.com","course-downloader.com","daddylivestream.com>>","dailyvideoreports.net","davescomputertips.com","desitab69.sextgem.com","destakenewsgospel.com","deutschpersischtv.com","diarioinformacion.com","diplomaexamcorner.com","dirtyyoungbitches.com","disneyfashionista.com","downloadcursos.gratis","dragontranslation.com","dragontranslation.net","dragontranslation.org","earn.mpscstudyhub.com","easyworldbusiness.com","edwardarriveoften.com","elcriticodelatele.com","electricalstudent.com","embraceinnerchaos.com","envato-downloader.com","eroticmoviesonline.me","errotica-archives.com","evelynthankregion.com","expressilustrowany.pl","filemoon-59t9ep5j.xyz","filemoon-nv2xl8an.xyz","filmpornoitaliano.org","fitting-it-all-in.com","foodsdictionary.co.il","free-famous-toons.com","freebulksmsonline.com","freefatpornmovies.com","freeindiansextube.com","freepikdownloader.com","freshmaturespussy.com","friedrichshainblog.de","froheweihnachten.info","gadgetguideonline.com","games.bostonglobe.com","games.centredaily.com","games.dailymail.co.uk","games.greatergood.com","games.miamiherald.com","games.puzzlebaron.com","games.startribune.com","games.theadvocate.com","games.theolympian.com","games.triviatoday.com","gbadamud.blogspot.com","gemini-horoscopes.com","generalpornmovies.com","gentiluomodigitale.it","gentlemansgazette.com","giantshemalecocks.com","giessener-anzeiger.de","girlfuckgalleries.com","glamourxxx-online.com","gmuender-tagespost.de","googlearth.selva.name","goprincetontigers.com","guardian-series.co.uk","hackedonlinegames.com","hersfelder-zeitung.de","hochheimer-zeitung.de","hoegel-textildruck.de","hollywoodreporter.com","hot-teens-movies.mobi","hotmarathistories.com","howtoblogformoney.net","html5.gamemonetize.co","hungarianhardstyle.hu","iamflorianschulze.com","imasdk.googleapis.com","indiansexstories2.net","indratranslations.com","inmatesearchidaho.com","insideeducation.co.za","jacquieetmicheltv.net","jemontremasextape.com","journaldemontreal.com","journey.to-travel.net","jsugamecocksports.com","juninhoscripts.com.br","kana-mari-shokudo.com","kstatewomenshoops.com","kstatewomenshoops.net","kstatewomenshoops.org","labelandnarrowweb.com","lapaginadealberto.com","learnodo-newtonic.com","lebensmittelpraxis.de","lesbianfantasyxxx.com","lingeriefuckvideo.com","live-sport.duktek.pro","lycomingathletics.com","majalahpendidikan.com","malaysianwireless.com","mangaplus.shueisha.tv","megashare-website.com","meuplayeronlinehd.com","midlandstraveller.com","midwestconference.org","mimaletadepeliculas.*","mmoovvfr.cloudfree.jp","motorsport.uol.com.br","musvozimbabwenews.com","mysflink.blogspot.com","nathanfromsubject.com","nationalgeographic.fr","netsentertainment.net","nobledicion.yoveo.xyz","note.sieuthuthuat.com","notformembersonly.com","oberschwaben-tipps.de","onepiecemangafree.com","onlinetntextbooks.com","onlinewatchmoviespk.*","ovcdigitalnetwork.com","paradiseislandcam.com","pcso-lottoresults.com","peiner-nachrichten.de","pelotalibrevivo.net>>","philippinenmagazin.de","photovoltaikforum.com","pickleballleagues.com","pisces-horoscopes.com","platform.adex.network","portbermudawebcam.com","primapaginamarsala.it","printablecreative.com","prod.hydra.sophos.com","quinnipiacbobcats.com","qul-de.translate.goog","radioitaliacanada.com","radioitalianmusic.com","redbluffdailynews.com","reddit-streams.online","redheaddeepthroat.com","redirect.dafontvn.com","revistaapolice.com.br","salzgitter-zeitung.de","santacruzsentinel.com","santafenewmexican.com","scriptgrowagarden.com","scrubson.blogspot.com","scrumpoker-online.org","sex-amateur-clips.com","sexybabespictures.com","shortgoo.blogspot.com","showdownforrelief.com","sinnerclownceviri.net","skorpion-horoskop.com","smartwebsolutions.org","snapinstadownload.xyz","softwarecrackguru.com","softwaredescargas.com","solomax-levelnewbie.*","solopornoitaliani.xxx","southsideshowdown.com","soziologie-politik.de","space.tribuntekno.com","stablediffusionxl.com","startupjobsportal.com","steamcrackedgames.com","stream.hownetwork.xyz","streaming-community.*","streamingcommunityz.*","studyinghuman6js.shop","supertelevisionhd.com","sweet-maturewomen.com","symboleslowianskie.pl","tapeadvertisement.com","tarjetarojaenvivo.lat","tarjetarojatvonline.*","taurus-horoscopes.com","taurus.topmanhuas.org","tech.trendingword.com","texteditor.nsspot.net","thecakeboutiquect.com","thedigitaltheater.com","thefightingcock.co.uk","thefreedictionary.com","thegnomishgazette.com","theprofoundreport.com","thetruthaboutcars.com","thewebsitesbridge.com","timesheraldonline.com","timesnewsgroup.com.au","tipsandtricksarab.com","toddpartneranimal.com","torrentdofilmeshd.net","towheaddeepthroat.com","travel-the-states.com","travelingformiles.com","tudo-para-android.com","ukiahdailyjournal.com","unsurcoenlasombra.com","utkarshonlinetest.com","vdl.np-downloader.com","virtualstudybrain.com","voyeur-pornvideos.com","walterprettytheir.com","watch.foodnetwork.com","watchcartoonsonline.*","watchfreejavonline.co","watchkobestreams.info","watchonlinemoviespk.*","watchporninpublic.com","watchseriesstream.com","weihnachts-bilder.org","wetterauer-zeitung.de","whisperingauroras.com","whittierdailynews.com","wiesbadener-kurier.de","wirtualnelegionowo.pl","worldwidestandard.net","www.dailymotion.com>>","xn--mlaregvle-02af.nu","yoima.hatenadiary.com","yoima2.hatenablog.com","zone-telechargement.*","123movies-official.net","1plus1plus1equals1.net","45er-de.translate.goog","acervodaputaria.com.br","adelaidepawnbroker.com","aimasummd.blog.fc2.com","algodaodocescan.com.br","allevertakstream.space","androidecuatoriano.xyz","appstore-discounts.com","arbitrarydecisions.com","automobile-catalog.com","batterypoweronline.com","best4hack.blogspot.com","bestialitysextaboo.com","blackamateursnaked.com","brunettedeepthroat.com","bus-location.1507t.xyz","canadianunderwriter.ca","canzoni-per-bambini.it","cartoonporncomics.info","celebritymovieblog.com","clixwarez.blogspot.com","comandotorrentshds.org","conceptoweb-studio.com","cosmonova-broadcast.tv","cotravinh.blogspot.com","cpopchanelofficial.com","currencyconverterx.com","currentrecruitment.com","dads-banging-teens.com","databasegdriveplayer.*","dewfuneralhomenews.com","diananatureforeign.com","digitalbeautybabes.com","downloadfreecourse.com","drakorkita73.kita.rest","drop.carbikenation.com","dtupgames.blogspot.com","ecommercewebsite.store","einewelteinezukunft.de","electriciansforums.net","elektrobike-online.com","elizabeth-mitchell.org","enciclopediaonline.com","eu-proxy.startpage.com","eurointegration.com.ua","exclusiveasianporn.com","exgirlfriendmarket.com","ezaudiobookforsoul.com","fantasticyoungporn.com","filmeserialeonline.org","freelancerartistry.com","freepic-downloader.com","freepik-downloader.com","ftlauderdalewebcam.com","games.besthealthmag.ca","games.heraldonline.com","games.islandpacket.com","games.journal-news.com","games.readersdigest.ca","gewinnspiele-markt.com","gifhorner-rundschau.de","girlfriendsexphoto.com","golink.bloggerishyt.in","hentai-cosplay-xxx.com","hentai-vl.blogspot.com","hiraethtranslation.com","hockeyfantasytools.com","hopsion-consulting.com","hotanimepornvideos.com","housethathankbuilt.com","illustratemagazine.com","imagetwist.netlify.app","incontri-in-italia.com","indianpornvideo.online","insidekstatesports.com","insidekstatesports.net","insidekstatesports.org","irasutoya.blogspot.com","jacquieetmicheltv2.net","jessicaglassauthor.com","jonathansociallike.com","juegos.eleconomista.es","juneauharborwebcam.com","k-statewomenshoops.com","k-statewomenshoops.net","k-statewomenshoops.org","kenkou-maintenance.com","kristiesoundsimply.com","lagacetadesalamanca.es","lecourrier-du-soir.com","livefootballempire.com","livingincebuforums.com","lonestarconference.org","m.bloggingguidance.com","marissasharecareer.com","marketedgeofficial.com","marketplace.nvidia.com","masterpctutoriales.com","megadrive-emulator.com","meteoregioneabruzzo.it","mini.surveyenquete.net","moneywar2.blogspot.com","muleriderathletics.com","nathanmichaelphoto.com","newbookmarkingsite.com","nilopolisonline.com.br","obutecodanet.ig.com.br","oeffnungszeitenbuch.de","onlinetechsamadhan.com","onlinevideoconverter.*","opiniones-empresas.com","oracleerpappsguide.com","originalindianporn.com","osint-info.netlify.app","paginadanoticia.com.br","philadelphiaeagles.com","pianetamountainbike.it","pittsburghpanthers.com","plagiarismdetector.net","play.discoveryplus.com","portstthomaswebcam.com","poweredbycovermore.com","praxis-jugendarbeit.de","principiaathletics.com","puzzles.standard.co.uk","puzzles.sunjournal.com","radioamericalatina.com","redlandsdailyfacts.com","republicain-lorrain.fr","rubyskitchenrecipes.uk","russkoevideoonline.com","salisburyjournal.co.uk","schwarzwaelder-bote.de","scorpio-horoscopes.com","sexyasianteenspics.com","smallpocketlibrary.com","smartfeecalculator.com","sms-receive-online.com","strangernervousql.shop","streamhentaimovies.com","stuttgarter-zeitung.de","supermarioemulator.com","tastefullyeclectic.com","tatacommunications.com","techieway.blogspot.com","teluguhitsandflops.com","thatballsouttahere.com","the-military-guide.com","thecartoonporntube.com","thehouseofportable.com","tipsandtricksjapan.com","tipsandtrickskorea.com","totalsportek1000.com>>","turkishaudiocenter.com","tutoganga.blogspot.com","tvchoicemagazine.co.uk","unity3diy.blogspot.com","universitiesonline.xyz","universityequality.com","watchdocumentaries.com","webcreator-journal.com","welsh-dictionary.ac.uk","xhamster-sexvideos.com","xn--algododoce-j5a.com","youfiles.herokuapp.com","yourdesignmagazine.com","zeeebatch.blogspot.com","aachener-nachrichten.de","adblockeronstreamtape.*","adrianmissionminute.com","ads-ti9ni4.blogspot.com","adultgamescollector.com","alejandrocenturyoil.com","alleneconomicmatter.com","allschoolboysecrets.com","aquarius-horoscopes.com","arcade.dailygazette.com","asianteenagefucking.com","auto-motor-und-sport.de","barranquillaestereo.com","bestbondagevideos.com>>","bestpuzzlesandgames.com","betterbuttchallenge.com","bikyonyu-bijo-zukan.com","brasilsimulatormods.com","buerstaedter-zeitung.de","c--ix-de.translate.goog","careersatcouncil.com.au","cloudapps.herokuapp.com","coolsoft.altervista.org","creditcardgenerator.com","dameungrrr.videoid.baby","destinationsjourney.com","dokuo666.blog98.fc2.com","edgedeliverynetwork.com","elperiodicodearagon.com","encurtador.postazap.com","entertainment-focus.com","escortconrecensione.com","eservice.directauto.com","eskiceviri.blogspot.com","exclusiveindianporn.com","fightforthealliance.com","financeandinsurance.xyz","footballtransfer.com.ua","fourchette-et-bikini.fr","freefiremaxofficial.com","freemovies-download.com","freepornhdonlinegay.com","funeralmemorialnews.com","gamersdiscussionhub.com","games.mercedsunstar.com","games.pressdemocrat.com","games.sanluisobispo.com","games.star-telegram.com","gamingsearchjournal.com","giessener-allgemeine.de","goctruyentranhvui17.com","heatherwholeinvolve.com","historyofroyalwomen.com","homeschoolgiveaways.com","ilgeniodellostreaming.*","india.mplandrecord.info","influencersgonewild.com","insidekstatesports.info","integral-calculator.com","investmentwatchblog.com","iptvdroid1.blogspot.com","jefferycontrolmodel.com","juegosdetiempolibre.org","julieseatsandtreats.com","kennethofficialitem.com","keysbrasil.blogspot.com","keywestharborwebcam.com","kutubistan.blogspot.com","lancewhosedifficult.com","laurelberninteriors.com","legendaryrttextures.com","linklog.tiagorangel.com","lirik3satu.blogspot.com","loldewfwvwvwewefdw.cyou","megaplayer.bokracdn.run","metamani.blog15.fc2.com","miltonfriedmancores.org","ministryofsolutions.com","mobile-tracker-free.com","mobileweb.bankmellat.ir","morganoperationface.com","morrisvillemustangs.com","mountainbike-magazin.de","movielinkbdofficial.com","mrfreemium.blogspot.com","naumburger-tageblatt.de","newlifefuneralhomes.com","news-und-nachrichten.de","northwalespioneer.co.uk","nudeblackgirlfriend.com","nutraceuticalsworld.com","onlinesoccermanager.com","osteusfilmestuga.online","pandajogosgratis.com.br","paradehomeandgarden.com","patriotathleticfund.com","pcoptimizedsettings.com","pepperlivestream.online","phonenumber-lookup.info","player.bestrapeporn.com","player.smashystream.com","player.tormalayalamhd.*","player.xxxbestsites.com","portaldosreceptores.org","portcanaveralwebcam.com","portstmaartenwebcam.com","pramejarab.blogspot.com","predominantlyorange.com","premierfantasytools.com","prepared-housewives.com","privateindianmovies.com","programmingeeksclub.com","puzzles.pressherald.com","receive-sms-online.info","rppk13baru.blogspot.com","searchenginereports.net","seoul-station-druid.com","sexyteengirlfriends.net","sexywomeninlingerie.com","shannonpersonalcost.com","singlehoroskop-loewe.de","snowman-information.com","spacestation-online.com","sqlserveregitimleri.com","streamtapeadblockuser.*","talentstareducation.com","teamupinternational.com","tech.pubghighdamage.com","the-voice-of-germany.de","thechroniclesofhome.com","thehappierhomemaker.com","theinternettaughtme.com","tinycat-voe-fashion.com","tips97tech.blogspot.com","traderepublic.community","tutorialesdecalidad.com","valuable.hatenablog.com","verteleseriesonline.com","watchseries.unblocked.*","wiesbadener-tagblatt.de","windowsaplicaciones.com","xxxjapaneseporntube.com","youtube4kdownloader.com","zonamarela.blogspot.com","zone-telechargement.ing","zoomtventertainment.com","720pxmovies.blogspot.com","abendzeitung-muenchen.de","advertiserandtimes.co.uk","afilmyhouse.blogspot.com","altebwsneno.blogspot.com","anime4mega-descargas.net","aspirapolveremigliori.it","ate60vs7zcjhsjo5qgv8.com","atlantichockeyonline.com","aussenwirtschaftslupe.de","bestialitysexanimals.com","boundlessnecromancer.com","broadbottomvillage.co.uk","businesssoftwarehere.com","canonprintersdrivers.com","cardboardtranslation.com","celebrityleakednudes.com","childrenslibrarylady.com","cimbusinessevents.com.au","cle0desktop.blogspot.com","cloudcomputingtopics.net","culture-informatique.net","democratandchronicle.com","dictionary.cambridge.org","dictionnaire-medical.net","dominican-republic.co.il","downloads.wegomovies.com","downloadtwittervideo.com","dsocker1234.blogspot.com","einrichtungsbeispiele.de","fid-gesundheitswissen.de","freegrannypornmovies.com","freehdinterracialporn.in","ftlauderdalebeachcam.com","futbolenlatelevision.com","galaxytranslations10.com","games.crosswordgiant.com","games.idahostatesman.com","games.thenewstribune.com","games.tri-cityherald.com","gcertificationcourse.com","gelnhaeuser-tageblatt.de","general-anzeiger-bonn.de","greenbaypressgazette.com","hentaianimedownloads.com","hilfen-de.translate.goog","hotmaturegirlfriends.com","inlovingmemoriesnews.com","inmatefindcalifornia.com","insurancebillpayment.net","intelligence-console.com","jacquieetmichelelite.com","jasonresponsemeasure.com","josephseveralconcern.com","juegos.elnuevoherald.com","jumpmanclubbrasil.com.br","lampertheimer-zeitung.de","latribunadeautomocion.es","lauterbacher-anzeiger.de","lespassionsdechinouk.com","liveanimalporn.zooo.club","mariatheserepublican.com","mediapemersatubangsa.com","meine-anzeigenzeitung.de","mentalhealthcoaching.org","minecraft-serverlist.net","moalm-qudwa.blogspot.com","multivideodownloader.com","my-code4you.blogspot.com","noblessetranslations.com","nutraingredients-usa.com","nyangames.altervista.org","oberhessische-zeitung.de","onlinetv.planetfools.com","personality-database.com","phenomenalityuniform.com","philly.arkadiumarena.com","photos-public-domain.com","player.subespanolvip.com","polseksongs.blogspot.com","portevergladeswebcam.com","programasvirtualespc.net","puzzles.centralmaine.com","quelleestladifference.fr","reddit-soccerstreams.com","renierassociatigroup.com","riprendiamocicatania.com","roadrunnersathletics.com","robertordercharacter.com","sandiegouniontribune.com","senaleszdhd.blogspot.com","shoppinglys.blogspot.com","smotret-porno-onlain.com","softdroid4u.blogspot.com","the-crossword-solver.com","thebharatexpressnews.com","thedesigninspiration.com","therelaxedhomeschool.com","thunderousintentions.com","tirumalatirupatiyatra.in","tubeinterracial-porn.com","unityassetcollection.com","upscaler.stockphotos.com","ustreasuryyieldcurve.com","verpeliculasporno.gratis","virginmediatelevision.ie","watchdoctorwhoonline.com","watchtrailerparkboys.com","workproductivityinfo.com","actionviewphotography.com","arabic-robot.blogspot.com","bharatsarkarijobalert.com","blog.receivefreesms.co.uk","braunschweiger-zeitung.de","businessnamegenerator.com","caroloportunidades.com.br","christopheruntilpoint.com","constructionplacement.org","convert-case.softbaba.com","cooldns-de.translate.goog","ctrmarketingsolutions.com","depo-program.blogspot.com","derivative-calculator.net","devere-group-hongkong.com","devoloperxda.blogspot.com","dictionnaire.lerobert.com","everydayhomeandgarden.com","fantasyfootballgeek.co.uk","fitnesshealtharticles.com","footballleagueworld.co.uk","fotografareindigitale.com","freeserverhostingweb.club","freewatchserialonline.com","game-kentang.blogspot.com","games.daytondailynews.com","games.gameshownetwork.com","games.lancasteronline.com","games.ledger-enquirer.com","games.moviestvnetwork.com","games.theportugalnews.com","gloucestershirelive.co.uk","graceaddresscommunity.com","heatherdiscussionwhen.com","housecardsummerbutton.com","kathleenmemberhistory.com","koume-in-huistenbosch.net","krankheiten-simulieren.de","lancashiretelegraph.co.uk","latribunadelpaisvasco.com","mega-hentai2.blogspot.com","nutraingredients-asia.com","oeffentlicher-dienst.info","oneessentialcommunity.com","onepiece-manga-online.net","passionatecarbloggers.com","percentagecalculator.guru","pickleballteamleagues.com","pickleballtournaments.com","printedelectronicsnow.com","programmiedovetrovarli.it","projetomotog.blogspot.com","puzzles.independent.co.uk","realcanadiansuperstore.ca","receitasoncaseiras.online","schooltravelorganiser.com","scripcheck.great-site.net","searchmovie.wp.xdomain.jp","sentinelandenterprise.com","seogroup.bookmarking.info","silverpetticoatreview.com","softwaresolutionshere.com","sofwaremania.blogspot.com","telenovelas-turcas.com.es","thebeginningaftertheend.*","transparentcalifornia.com","truesteamachievements.com","tucsitupdate.blogspot.com","ultimateninjablazingx.com","usahealthandlifestyle.com","vercanalesdominicanos.com","vintage-erotica-forum.com","whatisareverseauction.com","xn--k9ja7fb0161b5jtgfm.jp","youtubemp3donusturucu.net","yusepjaelani.blogspot.com","a-b-f-dd-aa-bb-cctwd3a.fun","a-b-f-dd-aa-bb-ccyh5my.fun","arena.gamesforthebrain.com","audiobookexchangeplace.com","avengerinator.blogspot.com","barefeetonthedashboard.com","basseqwevewcewcewecwcw.xyz","bezpolitickekorektnosti.cz","bibliotecahermetica.com.br","change-ta-vie-coaching.com","collegefootballplayoff.com","cornerstoneconfessions.com","cotannualconference.org.uk","cuatrolatastv.blogspot.com","dinheirocursosdownload.com","downloads.sayrodigital.net","edinburghnews.scotsman.com","elperiodicoextremadura.com","flashplayer.fullstacks.net","former-railroad-worker.com","frankfurter-wochenblatt.de","funnymadworld.blogspot.com","games.bellinghamherald.com","games.everythingzoomer.com","helmstedter-nachrichten.de","html5.gamedistribution.com","investigationdiscovery.com","istanbulescortnetworks.com","jilliandescribecompany.com","johnwardflighttraining.com","mailtool-de.translate.goog","motive213link.blogspot.com","musicbusinessworldwide.com","noticias.gospelmais.com.br","nutraingredients-latam.com","photoshopvideotutorial.com","puzzles.bestforpuzzles.com","recetas.arrozconleche.info","redditsoccerstreams.name>>","ripleyfieldworktracker.com","riverdesdelatribuna.com.ar","sagittarius-horoscopes.com","skillmineopportunities.com","stuttgarter-nachrichten.de","sulocale.sulopachinews.com","thelastgamestandingexp.com","thetelegraphandargus.co.uk","tiendaenlinea.claro.com.ni","todoseriales1.blogspot.com","tokoasrimotedanpayet.my.id","tralhasvarias.blogspot.com","video-to-mp3-converter.com","watchimpracticaljokers.com","whowantstuffs.blogspot.com","windowcleaningforums.co.uk","wolfenbuetteler-zeitung.de","wolfsburger-nachrichten.de","brittneystandardwestern.com","celestialtributesonline.com","charlottepilgrimagetour.com","choose.kaiserpermanente.org","cloud-computing-central.com","cointiply.arkadiumarena.com","constructionmethodology.com","cool--web-de.translate.goog","domainregistrationtips.info","download.kingtecnologia.com","dramakrsubindo.blogspot.com","elperiodicomediterraneo.com","embed.nextgencloudtools.com","evlenmekisteyenbayanlar.net","flash-firmware.blogspot.com","games.myrtlebeachonline.com","ge-map-overlays.appspot.com","happypenguin.altervista.org","iphonechecker.herokuapp.com","littlepandatranslations.com","lurdchinexgist.blogspot.com","newssokuhou666.blog.fc2.com","parametric-architecture.com","pasatiemposparaimprimir.com","practicalpainmanagement.com","puzzles.crosswordsolver.org","redcarpet-fashionawards.com","richardquestionbuilding.com","sztucznainteligencjablog.pl","thewestmorlandgazette.co.uk","timesofindia.indiatimes.com","watchfootballhighlights.com","watchmalcolminthemiddle.com","watchonlyfoolsandhorses.com","your-local-pest-control.com","centrocommercialevulcano.com","conoscereilrischioclinico.it","correction-livre-scolaire.fr","economictimes.indiatimes.com","emperorscan.mundoalterno.org","games.springfieldnewssun.com","gps--cache-de.translate.goog","imagenesderopaparaperros.com","lizs-early-learning-spot.com","locurainformaticadigital.com","michiganrugcleaning.cleaning","mimaletamusical.blogspot.com","net--tools-de.translate.goog","net--tours-de.translate.goog","pekalongan-cits.blogspot.com","publicrecords.netronline.com","skibiditoilet.yourmom.eu.org","springfieldspringfield.co.uk","teachersguidetn.blogspot.com","tekken8combo.kagewebsite.com","theeminenceinshadowmanga.com","uptodatefinishconference.com","watchonlinemovies.vercel.app","www-daftarharga.blogspot.com","youkaiwatch2345.blog.fc2.com","bayaningfilipino.blogspot.com","beautypageants.indiatimes.com","counterstrike-hack.leforum.eu","dev-dark-blog.pantheonsite.io","educationtips213.blogspot.com","fun--seiten-de.translate.goog","hortonanderfarom.blogspot.com","panlasangpinoymeatrecipes.com","pharmaceutical-technology.com","play.virginmediatelevision.ie","pressurewasherpumpdiagram.com","thefreedommatrix.blogspot.com","walkthrough-indo.blogspot.com","web--spiele-de.translate.goog","wojtekczytawh40k.blogspot.com","caq21harderv991gpluralplay.xyz","comousarzararadio.blogspot.com","coolsoftware-de.translate.goog","hipsteralcolico.altervista.org","jennifercertaindevelopment.com","kryptografie-de.translate.goog","mp3songsdownloadf.blogspot.com","noicetranslations.blogspot.com","oxfordlearnersdictionaries.com","pengantartidurkuh.blogspot.com","photo--alben-de.translate.goog","rheinische-anzeigenblaetter.de","thelibrarydigital.blogspot.com","touhoudougamatome.blog.fc2.com","watchcalifornicationonline.com","wwwfotografgotlin.blogspot.com","bigclatterhomesguideservice.com","bitcoinminingforex.blogspot.com","cool--domains-de.translate.goog","ibecamethewifeofthemalelead.com","pickcrackpasswords.blogspot.com","posturecorrectorshop-online.com","safeframe.googlesyndication.com","sozialversicherung-kompetent.de","utilidades.ecuadjsradiocorp.com","akihabarahitorigurasiseikatu.com","deletedspeedstreams.blogspot.com","freesoftpdfdownload.blogspot.com","games.games.newsgames.parade.com","insuranceloan.akbastiloantips.in","situsberita2terbaru.blogspot.com","such--maschine-de.translate.goog","uptodatefinishconferenceroom.com","games.charlottegames.cnhinews.com","loadsamusicsarchives.blogspot.com","pythonmatplotlibtips.blogspot.com","ragnarokscanlation.opchapters.com","tw.xn--h9jepie9n6a5394exeq51z.com","papagiovannipaoloii.altervista.org","softwareengineer-de.translate.goog","rojadirecta-tv-en-vivo.blogspot.com","thenightwithoutthedawn.blogspot.com","tenseishitaraslimedattaken-manga.com","wetter--vorhersage-de.translate.goog","marketing-business-revenus-internet.fr","hardware--entwicklung-de.translate.goog","xn--n8jwbyc5ezgnfpeyd3i0a3ow693bw65a.com","sharpen-free-design-generator.netlify.app","a-b-c-d-e-f9jeats0w5hf22jbbxcrpnq37qq6nbxjwypsy.fun"];

const $scriptletFromRegexes$ = /* 8 */ ["-embed.c","^moon(?:-[a-z0-9]+)?-embed\\.com$","56,57","moonfile","^moonfile-[a-z0-9-]+\\.com$","56,57",".","^[0-9a-z]{5,8}\\.(art|cfd|fun|icu|info|live|pro|sbs|world)$","56,57","-mkay.co","^moo-[a-z0-9]+(-[a-z0-9]+)*-mkay\\.com$","56,57","file-","^file-[a-z0-9]+(-[a-z0-9]+)*-(moon|embed)\\.com$","56,57","-moo.com","^fle-[a-z0-9]+(-[a-z0-9]+)*-moo\\.com$","56,57","filemoon","^filemoon-[a-z0-9]+(?:-[a-z0-9]+)*\\.(?:com|xyz)$","56,57","tamilpri","(\\d{0,1})?tamilprint(\\d{1,2})?\\.[a-z]{3,7}","107,1534,2435"];

const $hasEntities$ = true;
const $hasAncestors$ = true;
const $hasRegexes$ = true;

/******************************************************************************/

const entries = (( ) => {
    const docloc = document.location;
    const origins = [ docloc.origin ];
    if ( docloc.ancestorOrigins ) {
        origins.push(...docloc.ancestorOrigins);
    }
    return origins.map((origin, i) => {
        const beg = origin.indexOf('://');
        if ( beg === -1 ) { return; }
        const hn1 = origin.slice(beg+3)
        const end = hn1.indexOf(':');
        const hn2 = end === -1 ? hn1 : hn1.slice(0, end);
        const hnParts = hn2.split('.');
        if ( hn2.length === 0 ) { return; }
        const hns = [];
        for ( let i = 0; i < hnParts.length; i++ ) {
            hns.push(`${hnParts.slice(i).join('.')}`);
        }
        const ens = [];
        if ( $hasEntities$ ) {
            const n = hnParts.length - 1;
            for ( let i = 0; i < n; i++ ) {
                for ( let j = n; j > i; j-- ) {
                    ens.push(`${hnParts.slice(i,j).join('.')}.*`);
                }
            }
            ens.sort((a, b) => {
                const d = b.length - a.length;
                if ( d !== 0 ) { return d; }
                return a > b ? -1 : 1;
            });
        }
        return { hns, ens, i };
    }).filter(a => a !== undefined);
})();
if ( entries.length === 0 ) { return; }

const collectArglistRefIndices = (out, hn, r) => {
    let l = 0, i = 0, d = 0;
    let candidate = '';
    while ( l < r ) {
        i = l + r >>> 1;
        candidate = $scriptletHostnames$[i];
        d = hn.length - candidate.length;
        if ( d === 0 ) {
            if ( hn === candidate ) {
                out.add(i); break;
            }
            d = hn < candidate ? -1 : 1;
        }
        if ( d < 0 ) {
            r = i;
        } else {
            l = i + 1;
        }
    }
    return i;
};

const indicesFromHostname = (out, hnDetails, suffix = '') => {
    if ( hnDetails.hns.length === 0 ) { return; }
    let r = $scriptletHostnames$.length;
    for ( const hn of hnDetails.hns ) {
        r = collectArglistRefIndices(out, `${hn}${suffix}`, r);
    }
    if ( $hasEntities$ ) {
        let r = $scriptletHostnames$.length;
        for ( const en of hnDetails.ens ) {
            r = collectArglistRefIndices(out, `${en}${suffix}`, r);
        }
    }
};

const todoIndices = new Set();
indicesFromHostname(todoIndices, entries[0]);
if ( $hasAncestors$ ) {
    for ( const entry of entries ) {
        if ( entry.i === 0 ) { continue; }
        indicesFromHostname(todoIndices, entry, '>>');
    }
}
$scriptletHostnames$.length = 0;

// Collect arglist references
const todo = new Set();
if ( todoIndices.size !== 0 ) {
    const arglistRefs = $scriptletArglistRefs$.split(';');
    for ( const i of todoIndices ) {
        for ( const ref of JSON.parse(`[${arglistRefs[i]}]`) ) {
            todo.add(ref);
        }
    }
}
if ( $hasRegexes$ ) {
    const { hns } = entries[0];
    for ( let i = 0, n = $scriptletFromRegexes$.length; i < n; i += 3 ) {
        const needle = $scriptletFromRegexes$[i+0];
        let regex;
        for ( const hn of hns ) {
            if ( hn.includes(needle) === false ) { continue; }
            if ( regex === undefined ) {
                regex = new RegExp($scriptletFromRegexes$[i+1]);
            }
            if ( regex.test(hn) === false ) { continue; }
            for ( const ref of JSON.parse(`[${$scriptletFromRegexes$[i+2]}]`) ) {
                todo.add(ref);
            }
        }
    }
}
if ( todo.size === 0 ) { return; }

// Execute scriplets
{
    const arglists = $scriptletArglists$.split(';');
    const args = $scriptletArgs$;
    for ( const ref of todo ) {
        if ( ref < 0 ) { continue; }
        if ( todo.has(~ref) ) { continue; }
        const arglist = JSON.parse(`[${arglists[ref]}]`);
        const fn = $scriptletFunctions$[arglist[0]];
        try { fn(...arglist.slice(1).map(a => args[a])); }
        catch { }
    }
}

/******************************************************************************/

// End of local scope
})();

void 0;
