import { getStore } from "@netlify/blobs";
import { randomBytes, randomInt, scryptSync, timingSafeEqual } from "node:crypto";

export const config = { path: "/api" };

const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LENGTH = 6;
const MIN_MEMBERS = 3;
const MAX_MEMBERS = 40;
const MAX_FAILS = 5;
const LOCK_MS = 5 * 60 * 1000;

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const rooms = () => getStore({ name: "secret-santa", consistency: "strong" });

/* ---------- validazione ---------- */

const clean = (v) => (typeof v === "string" ? v.replace(/\s+/g, " ").trim() : "");
const hasControlChars = (s) => /[\u0000-\u001f\u007f]/.test(s);
const nameKey = (name) => name.toLocaleLowerCase("it");

function normCode(v) {
  const code = String(v ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (code.length !== CODE_LENGTH || [...code].some((c) => !ALPHABET.includes(c))) {
    throw new ApiError(400, "Il codice stanza non è valido.");
  }
  return code;
}

function validName(v) {
  const name = clean(v);
  if (name.length < 2 || name.length > 30 || hasControlChars(name)) {
    throw new ApiError(400, "Il nome deve avere tra 2 e 30 caratteri.");
  }
  return name;
}

function validPin(v) {
  if (typeof v !== "string" || !/^\d{4,6}$/.test(v)) {
    throw new ApiError(400, "Il PIN deve essere di 4-6 cifre.");
  }
  return v;
}

function optionalText(v, max, label) {
  const text = clean(v);
  if (text.length > max || hasControlChars(text)) {
    throw new ApiError(400, `${label} può avere al massimo ${max} caratteri.`);
  }
  return text;
}

/* ---------- PIN e membri ---------- */

const hashPin = (pin, salt) => scryptSync(pin, salt, 32).toString("hex");

function verifyPin(member, pin) {
  const a = Buffer.from(hashPin(pin, member.salt), "hex");
  const b = Buffer.from(member.pinHash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

function newMember(name, pin, isHost) {
  const salt = randomBytes(16).toString("hex");
  return {
    id: randomBytes(6).toString("hex"),
    name,
    key: nameKey(name),
    salt,
    pinHash: hashPin(pin, salt),
    isHost,
    fails: 0,
    lockUntil: 0,
  };
}

/* Restituisce { member, dirty, error }. dirty = la stanza va salvata. */
function authenticate(room, rawName, rawPin) {
  const name = clean(rawName);
  const pin = typeof rawPin === "string" ? rawPin : "";
  const member = room.members.find((m) => m.key === nameKey(name));
  if (!member) {
    return {
      dirty: false,
      error: new ApiError(401, "Non c'è nessun partecipante con questo nome in questa stanza."),
    };
  }
  const now = Date.now();
  if (member.lockUntil > now) {
    const mins = Math.ceil((member.lockUntil - now) / 60000);
    return {
      dirty: false,
      error: new ApiError(429, `Troppi tentativi. Riprova tra ${mins} ${mins === 1 ? "minuto" : "minuti"}.`),
    };
  }
  if (!/^\d{4,6}$/.test(pin) || !verifyPin(member, pin)) {
    member.fails += 1;
    if (member.fails >= MAX_FAILS) {
      member.fails = 0;
      member.lockUntil = now + LOCK_MS;
      return { dirty: true, error: new ApiError(429, "Troppi tentativi. Riprova tra 5 minuti.") };
    }
    const left = MAX_FAILS - member.fails;
    return {
      dirty: true,
      error: new ApiError(401, `PIN non corretto. Tentativi rimasti: ${left}.`),
    };
  }
  let dirty = false;
  if (member.fails || member.lockUntil) {
    member.fails = 0;
    member.lockUntil = 0;
    dirty = true;
  }
  return { member, dirty };
}

function view(room, me) {
  return {
    code: room.code,
    title: room.title,
    budget: room.budget,
    status: room.status,
    minMembers: MIN_MEMBERS,
    me: { id: me.id, name: me.name, isHost: me.isHost },
    members: room.members.map((m) => ({ id: m.id, name: m.name, isHost: m.isHost })),
  };
}

/* ---------- storage con scrittura condizionale ---------- */

async function mutate(code, fn) {
  const s = rooms();
  for (let attempt = 0; attempt < 8; attempt++) {
    const entry = await s.getWithMetadata(code, { type: "json" });
    if (!entry) throw new ApiError(404, "Stanza non trovata. Controlla il codice.");
    const room = entry.data;
    const out = fn(room);
    if (out.dirty) {
      const w = await s.setJSON(code, room, { onlyIfMatch: entry.etag });
      if (!w.modified) continue; // qualcun altro ha scritto nel frattempo: rileggo e riprovo
    }
    if (out.error) throw out.error;
    return out.result;
  }
  throw new ApiError(409, "Troppe richieste contemporanee. Riprova.");
}

const withAuth = (b, handler) => (room) => {
  const auth = authenticate(room, b.name, b.pin);
  if (auth.error) return { dirty: auth.dirty, error: auth.error };
  const out = handler(room, auth.member);
  return { ...out, dirty: auth.dirty || out.dirty };
};

/* ---------- azioni ---------- */

async function createRoom(b) {
  const name = validName(b.name);
  const pin = validPin(b.pin);
  const title = optionalText(b.title, 40, "Il nome della stanza") || "Secret Santa";
  const budget = optionalText(b.budget, 30, "Il budget");
  const s = rooms();
  for (let i = 0; i < 10; i++) {
    const code = Array.from({ length: CODE_LENGTH }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
    const host = newMember(name, pin, true);
    const room = {
      code,
      title,
      budget,
      status: "open",
      createdAt: Date.now(),
      members: [host],
      assignments: {},
    };
    const w = await s.setJSON(code, room, { onlyIfNew: true });
    if (w.modified) return view(room, host);
  }
  throw new ApiError(500, "Non sono riuscito a creare la stanza. Riprova.");
}

async function roomInfo(b) {
  const code = normCode(b.code);
  const room = await rooms().get(code, { type: "json" });
  if (!room) throw new ApiError(404, "Stanza non trovata. Controlla il codice.");
  return { code, title: room.title, status: room.status, count: room.members.length };
}

function joinRoom(b) {
  const code = normCode(b.code);
  const name = validName(b.name);
  const pin = validPin(b.pin);
  return mutate(code, (room) => {
    if (room.status !== "open") {
      return { error: new ApiError(409, "L'estrazione è già stata fatta: le iscrizioni sono chiuse.") };
    }
    if (room.members.some((m) => m.key === nameKey(name))) {
      return {
        error: new ApiError(409, "Esiste già un partecipante con questo nome. Se sei tu, scegli «Sono già iscritto»."),
      };
    }
    if (room.members.length >= MAX_MEMBERS) {
      return { error: new ApiError(409, "La stanza è piena.") };
    }
    const member = newMember(name, pin, false);
    room.members.push(member);
    return { dirty: true, result: view(room, member) };
  });
}

function roomState(b) {
  return mutate(
    normCode(b.code),
    withAuth(b, (room, me) => ({ result: view(room, me) }))
  );
}

function removeMember(b) {
  return mutate(
    normCode(b.code),
    withAuth(b, (room, me) => {
      if (!me.isHost) return { error: new ApiError(403, "Solo l'host può rimuovere i partecipanti.") };
      if (room.status !== "open") return { error: new ApiError(409, "L'estrazione è già stata fatta.") };
      const target = room.members.find((m) => m.id === b.memberId);
      if (!target) return { error: new ApiError(404, "Partecipante non trovato.") };
      if (target.isHost) return { error: new ApiError(400, "L'host non può rimuovere se stesso.") };
      room.members = room.members.filter((m) => m.id !== target.id);
      return { dirty: true, result: view(room, me) };
    })
  );
}

function shuffle(list) {
  const a = [...list];
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function drawRoom(b) {
  return mutate(
    normCode(b.code),
    withAuth(b, (room, me) => {
      if (!me.isHost) return { error: new ApiError(403, "Solo l'host può avviare l'estrazione.") };
      if (room.status !== "open") return { error: new ApiError(409, "L'estrazione è già stata fatta.") };
      if (room.members.length < MIN_MEMBERS) {
        return { error: new ApiError(409, `Servono almeno ${MIN_MEMBERS} partecipanti.`) };
      }
      // Ciclo unico casuale: nessuno pesca se stesso e ognuno è pescato da una sola persona.
      const order = shuffle(room.members);
      const assignments = {};
      order.forEach((giver, i) => {
        assignments[giver.id] = order[(i + 1) % order.length].id;
      });
      room.assignments = assignments;
      room.status = "drawn";
      room.drawnAt = Date.now();
      return { dirty: true, result: view(room, me) };
    })
  );
}

function revealTarget(b) {
  return mutate(
    normCode(b.code),
    withAuth(b, (room, me) => {
      if (room.status !== "drawn") return { error: new ApiError(409, "L'estrazione non è ancora stata fatta.") };
      const target = room.members.find((m) => m.id === room.assignments[me.id]);
      if (!target) return { error: new ApiError(500, "Abbinamento non trovato.") };
      return { result: { target: target.name } };
    })
  );
}

const actions = {
  create: createRoom,
  info: roomInfo,
  join: joinRoom,
  state: roomState,
  remove: removeMember,
  draw: drawRoom,
  reveal: revealTarget,
};

/* ---------- handler ---------- */

const json = (data, status = 200) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store" } });

export default async (req) => {
  if (req.method !== "POST") return json({ error: "Metodo non consentito." }, 405);
  let body;
  try {
    const text = await req.text();
    if (text.length > 4000) throw new Error("troppo grande");
    body = JSON.parse(text);
    if (!body || typeof body !== "object") throw new Error("formato");
  } catch {
    return json({ error: "Richiesta non valida." }, 400);
  }
  const handler = Object.hasOwn(actions, body.action) ? actions[body.action] : null;
  if (!handler) return json({ error: "Azione sconosciuta." }, 400);
  try {
    return json(await handler(body));
  } catch (e) {
    if (e instanceof ApiError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: "Errore del server. Riprova tra poco." }, 500);
  }
};
