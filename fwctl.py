"""Консольне керування брандмауером (обгортка над Admin API).
Приклади:
  python fwctl.py list
  python fwctl.py add --action deny --src 26.147.33.195/32 --proto TCP --priority 10 --comment "блок ноутбука"
  python fwctl.py disable 1
  python fwctl.py enable 1
  python fwctl.py delete 1
  python fwctl.py conflicts
  python fwctl.py reload
"""
import argparse, json, sys, urllib.request, urllib.error

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


def call(api, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(api + path, data=data, method=method, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')
    except urllib.error.URLError as e:
        print('Не вдалося підключитися до Admin API. Чи запущений firewall.py на ЦЬОМУ комп\'ютері?', e)
        sys.exit(1)


def show_rules(items):
    if not items:
        print('(правил немає)')
        return
    hdr = f"{'ID':<3} {'ДІЯ':<5} {'ПРОТО':<5} {'ДЖЕРЕЛО':<20} {'С.ПОРТ':<6} {'ПРИЗНАЧЕННЯ':<20} {'П.ПОРТ':<6} {'ПРІОР':<5} {'УВІМК':<5} КОМЕНТАР"
    print(hdr)
    print('-' * len(hdr))
    for r in items:
        print(f"{r['id']:<3} {r['action']:<5} {r['proto']:<5} {r['src_ip_cidr']:<20} {r['src_port'] or '*':<6} "
              f"{r['dst_ip_cidr']:<20} {r['dst_port'] or '*':<6} {r['priority']:<5} {'так' if r['enabled'] else 'НІ':<5} {r.get('comment','')}")


def show_issues(res):
    for key in ('issues', 'warnings'):
        for i in res.get(key, []):
            print(('ПОМИЛКА   ' if key == 'issues' else 'ПОПЕРЕДЖЕННЯ ') + f"[{i['type']}] {i['message']}")


def main():
    ap = argparse.ArgumentParser(description='Керування брандмауером')
    ap.add_argument('--api', default='http://127.0.0.1:8081')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('list')
    sub.add_parser('conflicts')
    sub.add_parser('reload')
    a = sub.add_parser('add')
    a.add_argument('--action', choices=['allow', 'deny'], required=True)
    a.add_argument('--src', default='0.0.0.0/0', help='IP/CIDR джерела')
    a.add_argument('--dst', default='0.0.0.0/0', help='IP/CIDR призначення')
    a.add_argument('--sport', type=int, default=0)
    a.add_argument('--dport', type=int, default=0)
    a.add_argument('--proto', choices=['TCP', 'UDP'], default='TCP')
    a.add_argument('--priority', type=int, default=100)
    a.add_argument('--comment', default='')
    a.add_argument('--disabled', action='store_true')
    for name in ('delete', 'enable', 'disable'):
        s = sub.add_parser(name)
        s.add_argument('id', type=int)
    args = ap.parse_args()

    if args.cmd == 'list':
        show_rules(call(args.api, 'GET', '/rules')[1])
    elif args.cmd == 'conflicts':
        res = call(args.api, 'GET', '/conflicts')[1]
        print(json.dumps(res, ensure_ascii=False, indent=2) if res else 'Конфліктів і дублікатів не знайдено.')
    elif args.cmd == 'reload':
        print(call(args.api, 'POST', '/reload')[1])
    elif args.cmd == 'add':
        body = {'action': args.action, 'src_ip_cidr': args.src, 'dst_ip_cidr': args.dst, 'src_port': args.sport,
                'dst_port': args.dport, 'proto': args.proto, 'priority': args.priority,
                'enabled': not args.disabled, 'comment': args.comment}
        code, res = call(args.api, 'POST', '/rules', body)
        if code == 200:
            print(f"Правило додано, id = {res['id']}")
        else:
            print(f'Правило НЕ додано (HTTP {code}): {res.get("detail", res.get("error"))}')
        show_issues(res)
    elif args.cmd == 'delete':
        code, res = call(args.api, 'DELETE', f'/rules/{args.id}')
        print('Видалено' if code == 200 else 'Правила з таким id немає')
    else:
        code, res = call(args.api, 'PATCH', f'/rules/{args.id}', {'enabled': args.cmd == 'enable'})
        print(('Увімкнено' if args.cmd == 'enable' else 'Вимкнено') + f' правило {args.id}' if code == 200
              else f'Не вдалося (HTTP {code}): {res.get("detail", res.get("error"))}')
        show_issues(res)


if __name__ == '__main__':
    main()
