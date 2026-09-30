"""Challenge/response over the project's shared database, not a network IDS."""
import time
import uuid

POLL_SECONDS = 300
RESPONSE_SECONDS = 60
LAN_RESPONSE_SECONDS = 10
BOARD_SECONDS = 2


class ConnectivityMonitor:
    def __init__(self, manager, clock=None):
        self.manager = manager
        self.db = manager.db
        self.clock = clock or time.time

    def _actor(self, c, admin=False):
        return c.execute(
            'SELECT u.* FROM users u JOIN live_sessions s ON s.user_id=u.id '
            'WHERE s.id=? AND u.id=? AND s.ended_at IS NULL AND u.active=1 '
            'AND u.network_blocked=0' + (' AND u.is_admin=1' if admin else ''),
            (self.manager._session_id, self.manager._user_id)).fetchone()

    def respond(self):
        """Only the current session can answer its own unexpired challenge."""
        now = self.clock()
        with self.db.get_cursor() as c:
            c.execute('BEGIN IMMEDIATE')
            if not self._actor(c):
                return False
            challenge = c.execute(
                'SELECT nonce FROM connectivity_challenges WHERE session_id=? '
                'AND answered_at IS NULL AND resolved_at IS NULL AND deadline>?',
                (self.manager._session_id, now)).fetchone()
            if challenge:
                c.execute('UPDATE connectivity_challenges SET answered_at=? WHERE nonce=?',
                          (now, challenge['nonce']))
            return True

    def poll(self):
        """Admin-only scheduler; persisted cadence deduplicates multiple admins."""
        now = self.clock()
        blocked = []
        with self.db.get_cursor() as c:
            c.execute('BEGIN IMMEDIATE')
            actor = self._actor(c, admin=True)
            if not actor:
                raise PermissionError('Требуется действующий сеанс администратора')
            expired = c.execute(
                'SELECT DISTINCT s.user_id FROM connectivity_challenges q '
                'JOIN live_sessions s ON s.id=q.session_id JOIN users u ON u.id=s.user_id '
                'WHERE q.answered_at IS NULL AND q.resolved_at IS NULL AND q.deadline<=? '
                'AND s.ended_at IS NULL AND u.active=1 AND u.is_admin=0 AND u.network_blocked=0 '
                'AND NOT EXISTS(SELECT 1 FROM lan_presence p WHERE p.session_id=s.id)',
                (now,)).fetchall()
            for row in expired:
                uid = row['user_id']
                c.execute('UPDATE users SET network_blocked=1,updated_at=CURRENT_TIMESTAMP WHERE id=?', (uid,))
                c.execute("UPDATE live_sessions SET ended_at=?,end_reason='network_timeout' "
                          'WHERE user_id=? AND ended_at IS NULL', (now, uid))
                c.execute('DELETE FROM user_sessions WHERE user_id=?', (uid,))
                c.execute("INSERT INTO audit_logs(user_id,action,details) VALUES (?,'NETWORK_BLOCK',?)",
                          (uid, f'Нет ответа за {RESPONSE_SECONDS} с; администратор ID={actor["id"]}'))
                blocked.append(uid)
            c.execute('UPDATE connectivity_challenges SET resolved_at=? WHERE resolved_at IS NULL '
                      'AND (answered_at IS NOT NULL OR deadline<=? OR session_id IN '
                      '(SELECT id FROM live_sessions WHERE ended_at IS NOT NULL))', (now, now))
            state = c.execute('SELECT next_poll FROM connectivity_schedule WHERE id=1').fetchone()
            if state is None or state['next_poll'] <= now:
                sessions = c.execute('SELECT s.id FROM live_sessions s JOIN users u ON u.id=s.user_id '
                                     'WHERE s.ended_at IS NULL AND u.active=1 AND u.is_admin=0 '
                                     'AND u.network_blocked=0 AND NOT EXISTS '
                                     '(SELECT 1 FROM lan_presence p WHERE p.session_id=s.id)').fetchall()
                for session in sessions:
                    c.execute('INSERT INTO connectivity_challenges(session_id,nonce,issued_at,deadline) '
                              'VALUES (?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET '
                              'nonce=excluded.nonce,issued_at=excluded.issued_at,deadline=excluded.deadline,'
                              'answered_at=NULL,resolved_at=NULL',
                              (session['id'], uuid.uuid4().hex, now, now + RESPONSE_SECONDS))
                c.execute('INSERT INTO connectivity_schedule(id,next_poll) VALUES (1,?) '
                          'ON CONFLICT(id) DO UPDATE SET next_poll=excluded.next_poll', (now + POLL_SECONDS,))
        return blocked

    def user_statuses(self):
        """Состояние всех аккаунтов; цвет определяется активностью и свежим сигналом."""
        now = self.clock()
        with self.db.get_cursor() as c:
            if not self._actor(c, admin=True):
                raise PermissionError('Требуется действующий сеанс администратора')
            users = c.execute(
                'SELECT u.id,u.login,u.active,u.network_blocked,'
                '(SELECT MAX(started_at) FROM live_sessions WHERE user_id=u.id) AS last_login,'
                '(SELECT MAX(COALESCE(p.last_heartbeat,s.last_seen_at)) FROM live_sessions s '
                'LEFT JOIN lan_presence p ON p.session_id=s.id WHERE s.user_id=u.id) AS last_seen,'
                'EXISTS(SELECT 1 FROM live_sessions s LEFT JOIN lan_presence p ON p.session_id=s.id '
                'WHERE s.user_id=u.id AND s.ended_at IS NULL AND '
                '((p.session_id IS NOT NULL AND p.last_heartbeat>?) OR '
                '(p.session_id IS NULL AND s.last_seen_at>=?))) AS connected '
                'FROM users u WHERE u.id<>? ORDER BY u.login',
                (now - LAN_RESPONSE_SECONDS, now - RESPONSE_SECONDS, self.manager._user_id)).fetchall()
            result = []
            for row in users:
                item = dict(row)
                if not row['active']:
                    item['status_code'], item['status'] = 'deactivated', 'Пользователь деактивирован'
                elif row['network_blocked']:
                    item['status_code'], item['status'] = 'offline', 'Нет подключения: заблокирован'
                elif row['connected']:
                    item['status_code'], item['status'] = 'online', 'Работает'
                else:
                    item['status_code'], item['status'] = 'offline', 'Нет подключения'
                item.pop('connected')
                presence = c.execute(
                    'SELECT p.address,p.client_name FROM lan_presence p '
                    'JOIN live_sessions s ON s.id=p.session_id WHERE s.user_id=? '
                    'ORDER BY p.last_heartbeat DESC LIMIT 1', (row['id'],)).fetchone()
                item['address'] = presence['address'] if presence else None
                item['client_name'] = presence['client_name'] if presence else None
                item['files'] = [dict(r) for r in c.execute(
                    "SELECT action,details,timestamp FROM audit_logs WHERE user_id=? "
                    "AND action IN ('FILE_OPEN','FILE_SAVE','FILE_CREATE','FILE_DELETE','FILE_RENAME',"
                    "'EXECUTE_FILE','TRANSFER_FILE') ORDER BY id DESC LIMIT 5", (row['id'],)).fetchall()]
                result.append(item)
            return result

    def offline_users(self):
        """Совместимость с прежним окном: только аккаунты без подключения."""
        return [row for row in self.user_statuses() if row['status_code'] != 'online']

    def unblock(self, user_id):
        with self.db.get_cursor() as c:
            c.execute('BEGIN IMMEDIATE')
            actor = self._actor(c, admin=True)
            if not actor:
                raise PermissionError('Требуется действующий сеанс администратора')
            target = c.execute('SELECT login,active,network_blocked FROM users WHERE id=?',
                               (user_id,)).fetchone()
            if target is None or (target['active'] and not target['network_blocked']):
                return False
            if user_id == actor['id']:
                return False
            c.execute('UPDATE users SET active=1,network_blocked=0,updated_at=CURRENT_TIMESTAMP '
                      'WHERE id=?', (user_id,))
            c.execute('DELETE FROM login_attempts WHERE login=?', (target['login'],))
            c.execute('DELETE FROM user_sessions WHERE user_id=?', (user_id,))
            c.execute("UPDATE live_sessions SET ended_at=?,end_reason='reactivated' "
                      'WHERE user_id=? AND ended_at IS NULL', (self.clock(), user_id))
            action = 'REACTIVATE_USER' if not target['active'] else 'NETWORK_UNBLOCK'
            c.execute('INSERT INTO audit_logs(user_id,action,details) VALUES (?,?,?)',
                      (user_id, action, f'Администратор ID={actor["id"]}'))
            return True
