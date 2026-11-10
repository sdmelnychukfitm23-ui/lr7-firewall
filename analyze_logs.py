"""Аналіз і пошук у журналі брандмауера (logs/events.jsonl).
Приклади:
  python analyze_logs.py                                  # зведена статистика
  python analyze_logs.py --action deny                    # тільки заблоковані
  python analyze_logs.py --src 26.147.33.195 --proto TCP  # за джерелом і протоколом
  python analyze_logs.py --reason "правило #1"            # за причиною (пошук підрядка)
  python analyze_logs.py --since "2025-12-01 10:00:00" --last 20
  python analyze_logs.py --event admin                    # дії адміністратора
"""
import argparse, collections, json, sys
from datetime import datetime

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


def load(path):
    out = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path', nargs='?', default='logs/events.jsonl')
    ap.add_argument('--action', choices=['allow', 'deny'])
    ap.add_argument('--src', help='IP джерела')
    ap.add_argument('--dst', help='IP призначення')
    ap.add_argument('--dport', type=int)
    ap.add_argument('--proto', choices=['TCP', 'UDP'])
    ap.add_argument('--rule', type=int, help='id правила, що спрацювало')
    ap.add_argument('--event', help='частина назви події, напр. tcp, udp, admin')
    ap.add_argument('--reason', help='підрядок у причині')
    ap.add_argument('--since', help='YYYY-MM-DD HH:MM:SS')
    ap.add_argument('--until', help='YYYY-MM-DD HH:MM:SS')
    ap.add_argument('--last', type=int, help='показати лише N останніх записів')
    ap.add_argument('--top', type=int, default=5)
    args = ap.parse_args()

    try:
        events = load(args.path)
    except FileNotFoundError:
        print('Файл журналу не знайдено:', args.path)
        return

    def ok(e):
        if args.action and e.get('action') != args.action: return False
        if args.src and e.get('src_ip') != args.src: return False
        if args.dst and e.get('dst_ip') != args.dst: return False
        if args.dport and e.get('dst_port') != args.dport: return False
        if args.proto and e.get('proto') != args.proto: return False
        if args.rule is not None and e.get('rule_id') != args.rule: return False
        if args.event and args.event not in e.get('event', ''): return False
        if args.reason and args.reason.lower() not in str(e.get('reason', '')).lower(): return False
        if args.since and e.get('time', '') < args.since: return False
        if args.until and e.get('time', '') > args.until: return False
        return True

    filtered_mode = any([args.action, args.src, args.dst, args.dport, args.proto, args.rule is not None,
                         args.event, args.reason, args.since, args.until, args.last])
    sel = [e for e in events if ok(e)]

    if filtered_mode:
        if args.last:
            sel = sel[-args.last:]
        print(f'Знайдено записів: {len(sel)}\n')
        for e in sel:
            if e.get('event', '').startswith('admin'):
                print(f"{e['time']}  {e['event']:<20} rule_id={e.get('rule_id', '-')} {e.get('changes', '')}")
            else:
                print(f"{e['time']}  {e.get('event', ''):<12} {e.get('proto', ''):<3} "
                      f"{e.get('src_ip', '?')}:{e.get('src_port', '?')} -> {e.get('dst_ip', '?')}:{e.get('dst_port', '?')}  "
                      f"{str(e.get('action', '')).upper():<5} | {e.get('reason', e.get('err', ''))}")
        return

    # ---- зведена статистика
    print(f'Файл: {args.path}   Усього записів: {len(events)}')
    print('Події:', dict(collections.Counter(e.get('event') for e in events)))
    traffic = [e for e in events if e.get('action') in ('allow', 'deny')]
    denies = [e for e in traffic if e['action'] == 'deny']
    print(f'Дозволено: {len(traffic) - len(denies)}   Заблоковано: {len(denies)}')
    print('Блокування за протоколами:', dict(collections.Counter(e.get('proto') for e in denies)))
    print(f'Топ-{args.top} заблокованих джерел:', collections.Counter(e.get('src_ip') for e in denies).most_common(args.top))
    print(f'Топ-{args.top} правил, що блокували:', collections.Counter(e.get('rule_id') for e in denies).most_common(args.top))
    print(f'Топ-{args.top} заблокованих портів призначення:', collections.Counter(e.get('dst_port') for e in denies).most_common(args.top))
    if denies:
        print('Перше блокування:', denies[0]['time'], '| Останнє:', denies[-1]['time'])


if __name__ == '__main__':
    main()
