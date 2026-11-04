import copy
import json
import pathlib
import re
import tempfile
import threading
import unittest
from unittest.mock import patch

from bot_actions import BotActions, ActionError

NOW = 1804000000
ACTOR = {'chat_id': '101', 'user_id': '101'}


def buttons(response):
    return [b['callback_data'] for row in response['reply_markup']['inline_keyboard']
            for b in row if 'callback_data' in b]


class FakeRestarts:
    def __init__(self, control):
        self.control = control

    def targets(self, server):
        return {'checkedAt': self.control.now(), 'targets':
                [{'unit': unit, 'label': unit, 'kind': 'service', 'active': True}
                 for unit in server['services']] + copy.deepcopy(self.control.docker_targets)}


class FakeControl:
    def __init__(self, servers, now):
        self.servers, self.now = servers, now
        self.lock = threading.RLock()
        self.plans, self.jobs = {}, {}
        self.busy = []
        self.plan_calls, self.execute_calls = [], []
        self.docker_targets = []
        self.service_restarts = FakeRestarts(self)
        self.fail_execute = False
        self.reject_execute = False
        self.raise_after_job = False
        self.return_wrong_unit = False
        self.summary_overrides = {}
        self.state_path = None
        self.durable_before_execute = False

    def snapshot(self):
        return {'jobs': list(self.jobs.values()), 'busyServers': list(self.busy)}

    def plan(self, data):
        self.plan_calls.append(copy.deepcopy(data))
        server = next(s for s in self.servers if s['id'] == data['server'])
        pid = format(len(self.plan_calls), '032x')
        summary = {'title': 'Restart', 'kind': data['kind'], 'unit': data.get('unit'),
                   'impact': 'Временное прерывание подключений.', 'warnings': [], 'steps': ['Проверить состояние'],
                   'backupRequired': False}
        summary.update(self.summary_overrides)
        plan = {'id': pid, 'server': server['id'], 'host': server['host'], 'createdAt': self.now(),
                'kind': data['kind'], 'unit': data.get('unit'),
                'expiresAt': self.now() + 300, 'used': False, 'revision': 'initial-revision',
                'binding': [server[k] for k in ('host', 'port', 'user', 'key')],
                'request': copy.deepcopy(data), 'summary': summary}
        self.plans[pid] = plan
        return {k: v for k, v in plan.items() if k not in ('request', 'revision', 'binding', 'used')}

    def execute(self, pid, confirmation):
        self.execute_calls.append((pid, confirmation))
        state = json.loads(self.state_path.read_text())
        self.durable_before_execute = (any(s['state'] == 'consumed' for s in state['sessions'].values()) and
                                       any(a['state'] == 'reserved' for a in state['audit'].values()))
        plan = self.plans[pid]
        if self.reject_execute:
            raise ValueError('private-password=hidden-token')
        if self.fail_execute:
            plan['used'] = True  # A used plan without an attributable job is uncertain.
            raise RuntimeError('private-password=hidden-token')
        plan['used'] = True
        jid = format(100 + len(self.execute_calls), '032x')
        job = {'id': jid, 'kind': plan['request']['kind'], 'server': plan['server'], 'host': plan['host'],
               'unit': plan['request'].get('unit'), 'state': 'queued', 'createdAt': self.now()}
        if self.return_wrong_unit:
            job['unit'] = 'different.service'
        self.jobs[jid] = job
        self.busy.append(plan['server'])
        if self.raise_after_job:
            raise RuntimeError('private-password=hidden-token')
        return dict(job)


class BotActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.now = NOW
        self.servers = [dict(id='one', name='Первый VPS', host='192.0.2.1', port=22, user='root', key='one_key', services=['proxy.service', 'panel.service']),
                        dict(id='two', name='VPS 13', host='192.0.2.2', port=22, user='root', key='two_key', services=['proxy.service'])]
        self.control = FakeControl(self.servers, lambda: self.now)
        self.bot = self.build()

    def tearDown(self):
        self.tmp.cleanup()

    def build(self):
        bot = BotActions(self.root, lambda: self.control, lambda: self.servers,
                         clock=lambda: self.now, controller_id='one')
        self.control.state_path = bot.path
        return bot

    def call(self, data=None, text=None, **actor):
        identity = dict(ACTOR, message_id=77)
        identity.update(actor)
        return self.bot.handle(callback_data=data, text=text, **identity)

    def preview(self, server='one', service=True):
        opened = self.call('deck:manage:' + server)
        chosen = next(b for b in buttons(opened) if b.endswith(':service:0' if service else ':reboot'))
        result = self.call(chosen)
        phrase = re.search(r'ПЕРЕЗАПУСТИТЬ [0-9]{6}', result['text']).group()
        return result, phrase

    def complete(self):
        for job in self.control.jobs.values():
            job['state'] = 'succeeded'
        self.control.busy.clear()

    def test_selection_and_plan_never_execute_and_confirmation_is_explicit(self):
        result, phrase = self.preview()
        self.assertEqual(len(self.control.plan_calls), 1)
        self.assertFalse(self.control.execute_calls)
        for value in ['Первый VPS', '192.0.2.1', 'proxy.service', 'временно прервутся', 'план не требует копии', phrase]:
            self.assertIn(value, result['text'])
        self.assertIn('Это сервер управления', result['text'])
        self.assertFalse(any('confirm' in b for b in buttons(result)))
        self.assertNotIn(phrase, self.bot.path.read_text())
        self.assertEqual(self.bot.path.stat().st_mode & 0o777, 0o600)

    def test_confirm_consumes_durably_and_executes_original_plan_exactly_once(self):
        result, phrase = self.preview()
        pid = next(iter(self.control.plans))
        response = self.call(text=phrase)
        self.assertIn('Задача принята', response['text'])
        self.assertTrue(self.control.durable_before_execute)
        self.assertEqual(self.control.execute_calls, [(pid, '192.0.2.1')])
        self.assertEqual(len(self.control.plan_calls), 1)  # No unseen replacement plan.
        self.call(text=phrase)
        self.call(text=phrase)
        self.assertEqual(len(self.control.execute_calls), 1)

    def test_other_chat_or_sender_cannot_select_confirm_or_read_job(self):
        opened = self.call('deck:manage:one')
        action = next(b for b in buttons(opened) if b.endswith(':service:0'))
        self.call(action, chat_id='202', user_id='202')
        self.call(action, chat_id='101', user_id='202')
        self.assertFalse(self.control.plan_calls)
        result = self.call(action)
        phrase = re.search(r'ПЕРЕЗАПУСТИТЬ [0-9]{6}', result['text']).group()
        self.call(text=phrase, chat_id='202', user_id='202')
        self.call(text=phrase, chat_id='101', user_id='202')
        self.assertFalse(self.control.execute_calls)
        done = self.call(text=phrase)
        job_button = next(b for b in buttons(done) if b.startswith('deck:act:job:'))
        denied = self.call(job_button, chat_id='202', user_id='202')
        self.assertNotIn('192.0.2.1', denied['text'])

    def test_callbacks_bind_original_message_but_typed_confirmation_is_a_new_message(self):
        opened = self.call('deck:manage:one', message_id=77)
        action = next(b for b in buttons(opened) if b.endswith(':service:0'))
        for message_id in [78, None, 0, True]:
            self.call(action, message_id=message_id)
        self.assertFalse(self.control.plan_calls)
        result = self.call(action, message_id=77)
        phrase = re.search(r'ПЕРЕЗАПУСТИТЬ [0-9]{6}', result['text']).group()
        cancel = next(b for b in buttons(result) if b.endswith(':cancel'))
        self.call(cancel, message_id=78)
        self.assertIn('Задача принята', self.call(text=phrase, message_id=100)['text'])
        self.assertEqual(len(self.control.execute_calls), 1)

    def test_case_whitespace_wrong_phrase_and_three_attempts_do_not_execute(self):
        _, phrase = self.preview()
        self.assertIsNone(self.call(text=phrase.lower()))
        for text in [phrase + ' ', phrase + '\n', 'ПЕРЕЗАПУСТИТЬ 000000']:
            self.call(text=text)
        self.call(text=phrase)
        self.assertFalse(self.control.execute_calls)

    def test_cancel_expiry_restart_and_repair_invalidate_confirmation(self):
        result, phrase = self.preview()
        self.call(next(b for b in buttons(result) if b.endswith(':cancel')))
        self.call(text=phrase)
        self.assertFalse(self.control.execute_calls)
        _, phrase = self.preview()
        self.now += 121
        self.call(text=phrase)
        self.assertFalse(self.control.execute_calls)
        _, phrase = self.preview()
        self.bot = self.build()
        self.call(text=phrase)
        self.assertFalse(self.control.execute_calls)
        _, phrase = self.preview()
        self.assertTrue(self.bot.invalidate_pending())
        self.call(text=phrase)
        self.assertFalse(self.control.execute_calls)

    def test_registry_identity_and_exact_registered_target_are_bound(self):
        for field, value in [('host', '192.0.2.99'), ('port', 2222), ('user', 'admin'), ('key', 'changed_key')]:
            old = self.servers[0][field]
            _, phrase = self.preview()
            self.servers[0][field] = value
            self.call(text=phrase)
            self.servers[0][field] = old
        _, phrase = self.preview()
        self.servers[0]['services'].remove('proxy.service')
        self.call(text=phrase)
        self.assertFalse(self.control.execute_calls)

    def test_original_plan_revision_or_readiness_changes_require_new_preview(self):
        _, phrase = self.preview()
        next(iter(self.control.plans.values()))['revision'] = 'changed'
        self.assertIn('Исходный план', self.call(text=phrase)['text'])
        self.assertFalse(self.control.execute_calls)
        self.assertEqual(len(self.control.plan_calls), 1)
        self.control.summary_overrides = {'ready': False}
        opened = self.call('deck:manage:one')
        response = self.call(next(b for b in buttons(opened) if b.endswith(':reboot')))
        self.assertIn('запрещает', response['text'])
        self.assertFalse(self.control.execute_calls)

    def test_top_level_target_plan_mutation_and_wrong_executor_target_fail_closed(self):
        _, phrase = self.preview()
        next(iter(self.control.plans.values()))['unit'] = 'different.service'
        self.assertIn('Исходный план', self.call(text=phrase)['text'])
        self.assertFalse(self.control.execute_calls)
        _, phrase = self.preview()
        self.control.return_wrong_unit = True
        result = self.call(text=phrase)
        self.assertIn('Результат отправки не подтверждён', result['text'])
        self.assertEqual(next(iter(self.bot.state['audit'].values()))['state'], 'uncertain')

    def test_any_control_busy_job_blocks_other_host_before_plan_and_before_execute(self):
        self.control.busy = ['two']
        self.assertIn('заблокированы', self.call('deck:manage:one')['text'])
        self.assertFalse(self.control.plan_calls)
        self.control.busy.clear()
        _, phrase = self.preview()
        self.control.jobs['f' * 32] = {'id': 'f' * 32, 'kind': 'update', 'server': 'two', 'state': 'needs_review'}
        self.call(text=phrase)
        self.assertFalse(self.control.execute_calls)

    def test_global_bot_job_lock_survives_restart_and_needs_review(self):
        _, phrase = self.preview(service=False)
        self.call(text=phrase)
        job = next(iter(self.control.jobs.values()))
        job['state'] = 'needs_review'
        self.bot = self.build()
        self.assertIn('ручной проверки', self.call('deck:manage:two')['text'])
        self.assertEqual(len(self.control.execute_calls), 1)
        job['state'] = 'reviewed'
        self.control.busy.clear()
        self.assertIn('Выберите службу', self.call('deck:manage:two')['text'])

    def test_unknown_execute_result_is_durable_and_never_resubmitted(self):
        _, phrase = self.preview()
        self.control.fail_execute = True
        response = self.call(text=phrase)
        self.assertIn('Результат отправки не подтверждён', response['text'])
        self.assertNotIn('hidden-token', response['text'])
        self.call(text=phrase)
        self.bot = self.build()
        self.call(text=phrase)
        self.assertIn('ручной проверки', self.call('deck:manage:two')['text'])
        self.assertEqual(len(self.control.execute_calls), 1)
        self.bot.invalidate_pending()
        self.assertIn('ручной проверки', self.call('deck:manage:two')['text'])

    def test_proven_rejection_before_submission_allows_a_new_preview_without_replay(self):
        _, phrase = self.preview()
        self.control.reject_execute = True
        result = self.call(text=phrase)
        self.assertIn('до отправки команды', result['text'])
        self.assertNotIn('hidden-token', result['text'])
        self.assertFalse(self.control.jobs)
        self.call(text=phrase)
        self.assertEqual(len(self.control.execute_calls), 1)
        self.bot = self.build()
        self.assertIn('Выберите службу', self.call('deck:manage:two')['text'])

    def test_exception_after_job_creation_attaches_existing_job_and_its_review(self):
        _, phrase = self.preview()
        self.control.raise_after_job = True
        result = self.call(text=phrase)
        self.assertIn('сохранил задачу', result['text'])
        self.assertNotIn('hidden-token', result['text'])
        job = next(iter(self.control.jobs.values()))
        audit = next(iter(self.bot.state['audit'].values()))
        self.assertEqual(audit['jobId'], job['id'])
        self.call(text=phrase)
        self.assertEqual(len(self.control.execute_calls), 1)
        job['state'] = 'needs_review'
        self.bot = self.build()
        self.assertIn('ручной проверки', self.call('deck:manage:two')['text'])
        job['state'] = 'reviewed'; self.control.busy.clear()
        self.assertIn('Выберите службу', self.call('deck:manage:two')['text'])

    def test_one_pending_per_actor_replaces_old_target_and_old_phrase_is_invalid(self):
        _, old_phrase = self.preview('one')
        _, new_phrase = self.preview('two')
        self.assertNotEqual(old_phrase, new_phrase)
        self.call(text=old_phrase)
        self.assertFalse(self.control.execute_calls)
        self.call(text=new_phrase)
        job = next(iter(self.control.jobs.values()))
        self.assertEqual(job['server'], 'two')  # USA manual, explicit confirmation is allowed.

    def test_docker_full_id_uses_opaque_callback_and_no_targets_still_offers_reboot(self):
        self.servers[0]['services'] = []
        opened = self.call('deck:manage:one')
        self.assertTrue(any(b.endswith(':reboot') for b in buttons(opened)))
        self.assertFalse(any(':service:' in b for b in buttons(opened)))
        unit = 'docker:' + 'a' * 64
        self.control.docker_targets = [{'kind': 'docker', 'unit': unit, 'label': 'Docker · amnezia-awg', 'active': True}]
        result, phrase = self.preview()
        self.assertIn(unit, result['text'])
        self.assertTrue(all(len(b.encode()) <= 64 for b in buttons(result)))
        self.call(text=phrase)
        job = next(iter(self.control.jobs.values()))
        self.assertEqual(job['unit'], unit)

    def test_pagination_tokens_and_invalid_callbacks_never_accept_arbitrary_unit(self):
        self.servers[0]['services'] = ['proxy-' + str(n) + '.service' for n in range(15)]
        opened = self.call('deck:manage:one')
        next_button = next(b for b in buttons(opened) if b.endswith(':page:1'))
        next_page = self.call(next_button)
        self.assertIn('Страница 2/3', next_page['text'])
        for data in ['deck:manage:missing', 'deck:manage:../one', next_button.replace('page:1', 'service:999'),
                     next_button.replace('page:1', 'shell:reboot'), 'deck:act:' + 'z' * 70]:
            self.call(data)
        self.assertFalse(self.control.plan_calls)
        self.assertFalse(self.control.execute_calls)

    def test_status_reads_cached_job_without_retry_or_raw_error_output(self):
        _, phrase = self.preview()
        self.call(text=phrase)
        job = next(iter(self.control.jobs.values()))
        job.update(state='failed', error='password=hidden-token')
        self.control.busy.clear()
        response = self.call('deck:act:jobs')
        self.assertIn('ошибка', response['text'])
        self.assertNotIn('hidden-token', response['text'])
        self.assertEqual(len(self.control.execute_calls), 1)

    def test_storage_corruption_and_failed_durable_consume_fail_closed(self):
        _, phrase = self.preview()
        with patch.object(self.bot, '_save', side_effect=ActionError('Storage unavailable')):
            self.call(text=phrase)
        self.assertFalse(self.control.execute_calls)
        self.bot.path.write_text('{malformed')
        self.bot = self.build()
        self.assertTrue(self.bot.storage_error)
        self.call('deck:manage:one')
        self.assertFalse(self.control.execute_calls)
        self.assertEqual(self.bot.path.read_text(), '{malformed')

    def test_concurrent_confirmation_messages_execute_only_once(self):
        _, phrase = self.preview()
        replies = []
        workers = [threading.Thread(target=lambda: replies.append(self.call(text=phrase))) for _ in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(3)
        self.assertEqual(len(replies), 4)
        self.assertEqual(len(self.control.execute_calls), 1)

    def test_real_control_plan_and_execute_contract_without_remote_or_worker_calls(self):
        from control import Control
        from reboot import Reboots
        from service_restart import ServiceRestarts

        for service in (True, False):
            with self.subTest(service=service), tempfile.TemporaryDirectory() as folder:
                control = object.__new__(Control)
                control.lock = threading.RLock()
                control.jobs, control.plans, control.busy = {}, {}, set()
                control.servers = lambda: self.servers
                control.path = pathlib.Path(folder) / 'jobs.json'
                control.backups = lambda: []
                control.reboots = Reboots(control)
                control.service_restarts = ServiceRestarts(control)
                info = {'system': 'running', 'aptBusy': [], 'services': {
                    'proxy.service': {'ActiveState': 'active', 'UnitFileState': 'enabled'}},
                    'containers': {}, 'awg': [], 'bootId': 'test-boot',
                    'target': {'name': 'proxy.service', 'unit': 'proxy.service'}}
                remote_calls = []

                def read_only_ssh(server, request, *args):
                    remote_calls.append(request['op'])
                    if request['op'] == 'service-restart-targets':
                        return {'checkedAt': self.now, 'targets': [
                            {'unit': 'proxy.service', 'label': 'proxy.service', 'kind': 'service', 'active': True}]}
                    if request['op'] in ('service-restart-info', 'reboot-info'):
                        return copy.deepcopy(info)
                    raise AssertionError('A worker or mutation must not run in this contract test')

                control.ssh = read_only_ssh
                self.control = control
                self.bot = BotActions(folder, lambda: control, lambda: self.servers, clock=lambda: self.now)
                with patch('control.time.time', return_value=self.now), patch('threading.Thread') as thread:
                    _, phrase = self.preview(service=service)
                    result = self.call(text=phrase, message_id=100)
                    self.assertIn('Задача принята', result['text'])
                    self.assertEqual(len(control.jobs), 1)
                    self.assertEqual(thread.return_value.start.call_count, 1)
                    self.call(text=phrase, message_id=101)
                    self.assertEqual(len(control.jobs), 1)
                saved = json.loads(control.path.read_text())
                self.assertEqual(next(iter(saved.values()))['kind'], 'service-restart' if service else 'reboot')
                self.assertTrue(all(op.endswith(('-info', '-targets')) for op in remote_calls))


if __name__ == '__main__':
    unittest.main()
