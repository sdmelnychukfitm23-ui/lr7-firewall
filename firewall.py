"""
ЛР №7. Програмний брандмауер (user-space проксі TCP/UDP) з керуванням правилами "на льоту".

Основа - заготовка викладача, доопрацьовано:
  * у журнал додано читабельний час, поле reason (причина), proto, src_ip/dst_ip/порти;
  * журналюються дії адміністратора (додав/видалив/вимкнув правило);
  * валідація правил, виявлення дублікатів, конфліктів і перекриттів (GET /conflicts);
  * /reload тепер реально діє на працюючі проксі (набір правил оновлюється "на місці");
  * потокобезпечні зміни, виправлено однакові id у правилах із config.json.
"""
import argparse, json, os, threading, time, socket, selectors, ipaddress, dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List

LOG_PATH = 'logs/events.jsonl'
LOG_LOCK = threading.Lock()


def jlog(obj):
    """Дописує один рядок JSON у журнал (формат JSON Lines)."""
    ts = time.time()
    rec = {'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'), 'ts': round(ts, 3)}
    rec.update(obj)
    with LOG_LOCK:
        d = os.path.dirname(LOG_PATH)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')


# ----------------------------------------------------------------- ПРАВИЛА
@dataclass(order=True)
class Rule:
    priority: int                       # менше число = вищий пріоритет
    id: int = field(compare=False, default=0)
    action: str = field(compare=False, default='deny')      # 'allow' | 'deny'
    src_ip_cidr: str = field(compare=False, default='0.0.0.0/0')
    dst_ip_cidr: str = field(compare=False, default='0.0.0.0/0')
    src_port: int = field(compare=False, default=0)         # 0 = будь-який
    dst_port: int = field(compare=False, default=0)
    proto: str = field(compare=False, default='TCP')        # 'TCP' | 'UDP'
    enabled: bool = field(compare=False, default=True)
    comment: str = field(compare=False, default='')

    def matches(self, src_ip, dst_ip, src_port, dst_port, proto):
        if not self.enabled:
            return False
        if self.proto.upper() != proto.upper():
            return False
        try:
            if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(self.src_ip_cidr, strict=False):
                return False
            if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(self.dst_ip_cidr, strict=False):
                return False
        except Exception:
            return False
        if self.src_port and self.src_port != src_port:
            return False
        if self.dst_port and self.dst_port != dst_port:
            return False
        return True


ALLOWED_FIELDS = {'action', 'src_ip_cidr', 'dst_ip_cidr', 'src_port', 'dst_port',
                  'proto', 'priority', 'enabled', 'comment'}


def validate_rule(r: Rule):
    """Перевіряє і нормалізує правило. Кидає ValueError з поясненням."""
    r.action = str(r.action).lower()
    if r.action not in ('allow', 'deny'):
        raise ValueError("action має бути 'allow' або 'deny'")
    r.proto = str(r.proto).upper()
    if r.proto not in ('TCP', 'UDP'):
        raise ValueError("proto має бути 'TCP' або 'UDP'")
    for name in ('src_ip_cidr', 'dst_ip_cidr'):
        try:
            ipaddress.ip_network(getattr(r, name), strict=False)
        except ValueError:
            raise ValueError(f'{name}: "{getattr(r, name)}" - некоректна IP-адреса або підмережа (CIDR)')
    for name in ('src_port', 'dst_port'):
        v = int(getattr(r, name))
        if not 0 <= v <= 65535:
            raise ValueError(f'{name} має бути 0..65535 (0 = будь-який)')
        setattr(r, name, v)
    r.priority = int(r.priority)
    r.enabled = bool(r.enabled)


def describe(r: Rule):
    sp = r.src_port or '*'
    dp = r.dst_port or '*'
    return f"#{r.id} {r.action.upper()} {r.proto} {r.src_ip_cidr}:{sp} -> {r.dst_ip_cidr}:{dp} (пріоритет {r.priority})"


def _label(r: Rule):
    return f'#{r.id}' if r.id else 'нове правило'


def _net_rel(a, b):
    na, nb = ipaddress.ip_network(a, strict=False), ipaddress.ip_network(b, strict=False)
    if na == nb:
        return 'equal'
    if na.version != nb.version:
        return 'disjoint'
    return 'overlap' if na.overlaps(nb) else 'disjoint'


def _port_rel(a, b):
    if a == b:
        return 'equal'
    if a == 0 or b == 0:
        return 'overlap'
    return 'disjoint'


def relation(x: Rule, y: Rule):
    """'identical' - однакові умови; 'overlap' - умови частково/повністю перекриваються;
    'disjoint' - жоден пакет не підпадає під обидва правила одночасно."""
    if x.proto.upper() != y.proto.upper():
        return 'disjoint'
    rels = [_net_rel(x.src_ip_cidr, y.src_ip_cidr), _net_rel(x.dst_ip_cidr, y.dst_ip_cidr),
            _port_rel(x.src_port, y.src_port), _port_rel(x.dst_port, y.dst_port)]
    if 'disjoint' in rels:
        return 'disjoint'
    return 'identical' if all(r == 'equal' for r in rels) else 'overlap'


class RuleSet:
    def __init__(self, rules=None):
        self.lock = threading.RLock()
        self.rules: List[Rule] = []
        self.next_id = 1
        self.replace(rules or [])

    def replace(self, rules):
        """Підміна всього набору "на місці" (використовується при /reload)."""
        with self.lock:
            rules = list(rules)
            used = set()
            for r in rules:                      # виправляємо відсутні/повторювані id
                if r.id and r.id not in used:
                    used.add(r.id)
                else:
                    r.id = 0
            nid = max(used, default=0) + 1
            for r in rules:
                if not r.id:
                    r.id = nid
                    nid += 1
            self.rules = sorted(rules)
            self.next_id = nid

    def to_dict(self):
        return [r.__dict__ for r in self.rules]

    # ---- виявлення дублікатів і конфліктів
    def check(self, r: Rule, ignore_id=None):
        errors, warnings = [], []
        for x in self.rules:
            if x.id == ignore_id:
                continue
            rel = relation(r, x)
            if rel == 'disjoint':
                continue
            if rel == 'identical' and x.action == r.action:
                errors.append({'type': 'duplicate_rule', 'existing_id': x.id,
                               'message': f'Дублікат: {describe(x)} вже існує з тією ж дією.'})
                continue
            if not (x.enabled and r.enabled) or x.action == r.action:
                continue                         # вимкнені правила та однакові дії не конфліктують
            if rel == 'identical':
                if x.priority == r.priority:
                    errors.append({'type': 'conflict_same_priority', 'existing_id': x.id,
                                   'message': f'Конфлікт: {describe(x)} має ті самі умови, іншу дію '
                                              f'і той самий пріоритет - результат був би неоднозначним.'})
                else:
                    win = x if x.priority < r.priority else r
                    warnings.append({'type': 'conflict_shadowed', 'existing_id': x.id,
                                     'message': f'Однакові умови, різні дії: переможе {_label(win)} '
                                                f'(менший пріоритет-число = важливіше). Друге правило ніколи не спрацює.'})
            else:  # overlap
                if x.priority == r.priority:
                    errors.append({'type': 'overlap_same_priority', 'existing_id': x.id,
                                   'message': f'Перекриття з {describe(x)}: різні дії та однаковий пріоритет '
                                              f'- порядок спрацювання невизначений.'})
                else:
                    win = x if x.priority < r.priority else r
                    warnings.append({'type': 'overlap_conflict', 'existing_id': x.id,
                                     'message': f'Перекриття з {describe(x)}: різні дії. '
                                                f'У спільній частині переважає {_label(win)}.'})
        return errors, warnings

    def conflicts(self):
        """Аналіз усього існуючого набору правил (GET /conflicts)."""
        out = []
        rs = list(self.rules)
        for i, a in enumerate(rs):
            for b in rs[i + 1:]:
                rel = relation(a, b)
                if rel == 'disjoint':
                    continue
                if rel == 'identical' and a.action == b.action:
                    out.append({'type': 'duplicate_rule', 'rules': [a.id, b.id]})
                elif a.enabled and b.enabled and a.action != b.action:
                    kind = 'conflict_shadowed' if rel == 'identical' else 'overlap_conflict'
                    win = a if a.priority <= b.priority else b
                    out.append({'type': kind, 'rules': [a.id, b.id], 'winner': win.id,
                                'ambiguous': a.priority == b.priority})
        return out

    # ---- операції
    def add(self, r: Rule):
        validate_rule(r)
        with self.lock:
            errors, warnings = self.check(r)
            if errors:
                return None, errors, warnings
            r.id = self.next_id
            self.next_id += 1
            self.rules = sorted(self.rules + [r])
            return r, [], warnings

    def remove(self, rid: int):
        with self.lock:
            n = len(self.rules)
            self.rules = [r for r in self.rules if r.id != rid]
            return len(self.rules) != n

    def update(self, rid: int, **kw):
        with self.lock:
            cur = next((r for r in self.rules if r.id == rid), None)
            if not cur:
                return 404, {'ok': False, 'error': 'not_found'}
            bad = [k for k in kw if k not in ALLOWED_FIELDS]
            if bad:
                return 400, {'ok': False, 'error': 'unknown_fields', 'detail': bad}
            try:
                cand = dataclasses.replace(cur, **kw)
                validate_rule(cand)
            except (ValueError, TypeError) as e:
                return 400, {'ok': False, 'error': 'bad_rule', 'detail': str(e)}
            errors, warnings = self.check(cand, ignore_id=rid) if cand.enabled else ([], [])
            if errors:
                return 409, {'ok': False, 'error': errors[0]['type'], 'issues': errors}
            self.rules = sorted(cand if r.id == rid else r for r in self.rules)
            return 200, {'ok': True, 'rule': cand.__dict__, 'warnings': warnings}

    def decide(self, src_ip, dst_ip, src_port, dst_port, proto):
        """Повертає (дія, id правила, причина). Перше правило за пріоритетом, що підійшло, перемагає."""
        for r in self.rules:
            if r.matches(src_ip, dst_ip, src_port, dst_port, proto):
                why = f'спрацювало правило #{r.id} ({r.action}, пріоритет {r.priority})'
                if r.comment:
                    why += f': {r.comment}'
                return r.action, r.id, why
        return 'allow', 0, 'жодне правило не підійшло (політика за замовчуванням: allow)'


def log_decision(event, proto, src, dst, action, rid, reason, **extra):
    jlog({'event': event, 'proto': proto, 'src': list(src), 'dst': list(dst),
          'src_ip': src[0], 'src_port': src[1], 'dst_ip': dst[0], 'dst_port': dst[1],
          'action': action, 'rule_id': rid, 'reason': reason, **extra})


# ----------------------------------------------------------------- TCP-проксі
def tcp_proxy(listen_host, listen_port, target_host, target_port, ruleset: RuleSet):
    sel = selectors.DefaultSelector()
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((listen_host, listen_port))
    ls.listen(128)
    ls.setblocking(False)
    sel.register(ls, selectors.EVENT_READ)

    def accept(sock):
        try:
            conn, addr = sock.accept()
        except Exception:
            return
        conn.setblocking(False)
        src = (addr[0], addr[1])
        try:
            dst_ip = socket.gethostbyname(target_host)
        except Exception as e:
            jlog({'event': 'tcp.error', 'proto': 'TCP', 'src': list(src), 'err': f'DNS: {e}'})
            conn.close()
            return
        dst = (dst_ip, target_port)
        action, rid, reason = ruleset.decide(src[0], dst_ip, src[1], target_port, 'TCP')
        log_decision('tcp.connect', 'TCP', src, dst, action, rid, reason)
        if action != 'allow':
            conn.close()
            return
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=5)
            upstream.setblocking(False)
        except Exception as e:
            jlog({'event': 'tcp.error', 'proto': 'TCP', 'src': list(src), 'dst': [target_host, target_port], 'err': str(e)})
            conn.close()
            return
        sel.register(conn, selectors.EVENT_READ, data=('c', upstream))
        sel.register(upstream, selectors.EVENT_READ, data=('u', conn))

    def forward(src, dst):
        try:
            data = src.recv(4096)
            if not data:
                raise EOFError
            dst.settimeout(5)
            dst.sendall(data)
            dst.setblocking(False)
        except Exception:
            for s in (src, dst):
                try:
                    sel.unregister(s)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass

    while True:
        for key, _ in sel.select(timeout=1):
            if key.fileobj is ls:
                accept(ls)
            else:
                _, peer = key.data
                forward(key.fileobj, peer)


# ----------------------------------------------------------------- UDP-ретранслятор
def udp_proxy(listen_host, listen_port, target_host, target_port, ruleset: RuleSet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_host, listen_port))
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except OSError:           # на Windows буває ConnectionResetError (10054)
            continue
        src = (addr[0], addr[1])
        try:
            dst_ip = socket.gethostbyname(target_host)
        except Exception as e:
            jlog({'event': 'udp.error', 'proto': 'UDP', 'err': f'DNS: {e}'})
            continue
        dst = (dst_ip, target_port)
        action, rid, reason = ruleset.decide(src[0], dst_ip, src[1], target_port, 'UDP')
        log_decision('udp.packet', 'UDP', src, dst, action, rid, reason, bytes=len(data))
        if action != 'allow':
            continue
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(2)
            up.sendto(data, dst)
            try:
                resp, _ = up.recvfrom(65535)
                sock.sendto(resp, addr)
            except socket.timeout:
                pass
            up.close()
        except Exception as e:
            jlog({'event': 'udp.error', 'proto': 'UDP', 'err': str(e)})


# ----------------------------------------------------------------- Admin API
class Admin(BaseHTTPRequestHandler):
    def _json(self, code, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        ln = int(self.headers.get('Content-Length', '0'))
        try:
            return json.loads(self.rfile.read(ln) or b'{}')
        except ValueError:
            raise ValueError('тіло запиту не є коректним JSON')

    def do_GET(self):
        if self.path.startswith('/rules'):
            self._json(200, rules.ruleset.to_dict())
        elif self.path.startswith('/conflicts'):
            self._json(200, rules.ruleset.conflicts())
        else:
            self._json(404, {'error': 'not_found'})

    def do_POST(self):
        if self.path.startswith('/rules'):
            try:
                b = self._body()
                r = Rule(priority=int(b.get('priority', 100)), action=b.get('action', 'deny'),
                         src_ip_cidr=b.get('src_ip_cidr', '0.0.0.0/0'), dst_ip_cidr=b.get('dst_ip_cidr', '0.0.0.0/0'),
                         src_port=int(b.get('src_port', 0)), dst_port=int(b.get('dst_port', 0)),
                         proto=b.get('proto', 'TCP'), enabled=bool(b.get('enabled', True)),
                         comment=str(b.get('comment', '')))
                new, errors, warnings = rules.ruleset.add(r)
            except (ValueError, TypeError) as e:
                return self._json(400, {'error': 'bad_rule', 'detail': str(e)})
            if errors:
                jlog({'event': 'admin.rule_rejected', 'rule': r.__dict__, 'issues': errors})
                return self._json(409, {'error': errors[0]['type'], 'existing_id': errors[0]['existing_id'],
                                        'issues': errors, 'warnings': warnings})
            jlog({'event': 'admin.rule_add', 'rule_id': new.id, 'rule': new.__dict__, 'warnings': warnings})
            self._json(200, {'id': new.id, 'warnings': warnings})
        elif self.path.startswith('/reload'):
            rules.load()
            jlog({'event': 'admin.reload', 'rules': len(rules.ruleset.rules)})
            self._json(200, {'ok': True, 'rules': len(rules.ruleset.rules)})
        else:
            self._json(404, {'error': 'not_found'})

    def do_PATCH(self):
        if self.path.startswith('/rules/'):
            try:
                rid = int(self.path.split('/')[-1])
                body = self._body()
            except ValueError as e:
                return self._json(400, {'error': 'bad_request', 'detail': str(e)})
            code, res = rules.ruleset.update(rid, **body)
            if code == 200:
                jlog({'event': 'admin.rule_update', 'rule_id': rid, 'changes': body, 'warnings': res.get('warnings', [])})
            self._json(code, res)
        else:
            self._json(404, {'error': 'not_found'})

    def do_DELETE(self):
        if self.path.startswith('/rules/'):
            try:
                rid = int(self.path.split('/')[-1])
            except ValueError:
                return self._json(400, {'error': 'bad_id'})
            ok = rules.ruleset.remove(rid)
            if ok:
                jlog({'event': 'admin.rule_delete', 'rule_id': rid})
            self._json(200 if ok else 404, {'ok': ok})
        else:
            self._json(404, {'error': 'not_found'})


class RuleManager:
    def __init__(self, path):
        self.path = path
        self.ruleset = RuleSet([])
        self.services = []
        self.admin = {'host': '127.0.0.1', 'port': 8081}
        self.load()

    def load(self):
        cfg = json.load(open(self.path, 'r', encoding='utf-8'))
        global LOG_PATH
        LOG_PATH = cfg.get('logging', {}).get('path', LOG_PATH)
        self.admin = cfg.get('admin', self.admin)
        base = []
        for r in cfg.get('rules', []):
            try:
                rule = Rule(priority=int(r.get('priority', 100)), id=int(r.get('id', 0)), action=r.get('action', 'deny'),
                            src_ip_cidr=r.get('src_ip_cidr', '0.0.0.0/0'), dst_ip_cidr=r.get('dst_ip_cidr', '0.0.0.0/0'),
                            src_port=r.get('src_port', 0), dst_port=r.get('dst_port', 0), proto=r.get('proto', 'TCP'),
                            enabled=r.get('enabled', True), comment=r.get('comment', ''))
                validate_rule(rule)
                base.append(rule)
            except (ValueError, TypeError) as e:
                print('Пропущено некоректне правило з конфігурації:', r, '-', e)
        self.ruleset.replace(base)          # оновлюємо НА МІСЦІ - проксі бачать зміни одразу
        self.services = cfg.get('services', self.services)


def main():
    ap = argparse.ArgumentParser(description='Програмний брандмауер (ЛР №7)')
    ap.add_argument('--config', default='config.json')
    args = ap.parse_args()
    global rules
    rules = RuleManager(args.config)

    admin = HTTPServer((rules.admin.get('host', '127.0.0.1'), int(rules.admin.get('port', 8081))), Admin)
    threading.Thread(target=admin.serve_forever, daemon=True).start()

    threads = []
    for s in rules.services:
        fn = tcp_proxy if s.get('proto', 'TCP').upper() == 'TCP' else udp_proxy
        t = threading.Thread(target=fn, args=(s['listen_host'], s['listen_port'], s['target_host'], s['target_port'], rules.ruleset), daemon=True)
        t.start()
        threads.append(t)

    print(f"Admin API http://{rules.admin.get('host')}:{rules.admin.get('port')}")
    for s in rules.services:
        print(f"  {s['proto']}: {s['listen_host']}:{s['listen_port']} -> {s['target_host']}:{s['target_port']}")
    print('Журнал:', LOG_PATH, '| Ctrl+C - зупинити')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\nЗупинено.')


if __name__ == '__main__':
    main()
