import copy
import unittest
from unittest.mock import Mock

from bot_menu import ReadOnlyBotMenu

NOW = 1804000000
ORIGIN = 'https://deck.example'


def sample(**updates):
    result = {'ts': NOW - 10, 'ok': True, 'cpu': 12.5, 'cpuIntervalSeconds': 1.25,
              'memory': {'used': 25, 'total': 100}, 'disk': {'used': 4, 'total': 10},
              'services': [{'unit': 'x-ui.service', 'state': 'active', 'loaded': True}],
              'containers': [], 'awg': [{'interface': 'awg0', 'peers': 4, 'online': 2}],
              'alerts': [], 'failed': [], 'health': 'ok'}
    result.update(updates)
    return result


def callbacks(response):
    return [button['callback_data'] for row in response['reply_markup']['inline_keyboard']
            for button in row if 'callback_data' in button]


class MenuTests(unittest.TestCase):
    def setUp(self):
        self.servers = [{'id': 'one', 'name': 'Первый', 'host': '192.0.2.1', 'port': 22,
                         'key': 'PRIVATE-KEY-NAME', 'services': ['x-ui.service']}]
        self.health = {'servers': {'one': {'latest': sample(), 'stale': False}},
                       'generatedAt': NOW, 'staleAfterSeconds': 150}
        self.security = {'generatedAt': NOW, 'servers': [
            {'id': 'one', 'checkedAt': NOW - 20, 'ok': True,
             'failedPassword10m': 12, 'activeSharedBans': 3}],
            'totals': {'newSharedBans10m': 2}, 'newestEventAt': NOW - 30}
        self.menu = ReadOnlyBotMenu(lambda: self.servers, lambda: self.health,
                                    lambda: self.security, ORIGIN, clock=lambda: NOW)

    def test_commands_return_plain_read_only_responses(self):
        for command in ['/menu', '/status', '/servers', '/services', '/security', '/start',
                        '/menu@ServerDeck_bot', '/security@ServerDeck_bot', '/start@ServerDeck_bot']:
            response = self.menu.handle(text=command)
            self.assertEqual(set(response), {'text', 'reply_markup', 'disable_web_page_preview'})
            self.assertTrue(response['disable_web_page_preview'])
            self.assertNotIn('parse_mode', response)
            self.assertNotIn('PRIVATE-KEY-NAME', response['text'])
            self.assertTrue(callbacks(response))
            self.assertTrue(all(len(value.encode()) <= 64 for value in callbacks(response)))
        for text in ['hello', '/reboot', '/start deck_pairing-code', '/start@ServerDeck_bot deck_pairing-code',
                     '/status one', '/services && reboot', None]:
            self.assertIsNone(self.menu.handle(text=text))

    def test_published_security_and_plain_start_route_to_expected_views(self):
        self.assertEqual(self.menu.handle(text='/security'), self.menu.handle(callback_data='deck:security'))
        self.assertEqual(self.menu.handle(text='/security@ServerDeck_bot'), self.menu.handle(callback_data='deck:security'))
        self.assertEqual(self.menu.handle(text='/start'), self.menu.handle(text='/menu'))
        self.assertEqual(self.menu.handle(text='/start@ServerDeck_bot'), self.menu.handle(text='/menu'))

    def test_management_routes_are_opt_in_and_available_from_server_and_services(self):
        for route in ['deck:status', 'deck:server:one', 'deck:services:one:0']:
            self.assertFalse(any(value.startswith(('deck:manage:', 'deck:act:'))
                                 for value in callbacks(self.menu.handle(callback_data=route))))
        enabled = ReadOnlyBotMenu(lambda: self.servers, lambda: self.health,
                                 lambda: self.security, ORIGIN, clock=lambda: NOW,
                                 actions_enabled=True)
        overview = enabled.handle(text='/menu')
        self.assertIn('deck:act:jobs', callbacks(overview))
        for route in ['deck:server:one', 'deck:services:one:0']:
            response = enabled.handle(callback_data=route)
            self.assertIn('deck:manage:one', callbacks(response))
            self.assertIn('deck:act:jobs', callbacks(response))
            buttons = [button for row in response['reply_markup']['inline_keyboard'] for button in row]
            self.assertTrue(any(button.get('text') == 'Управление сервером' and
                                button.get('callback_data') == 'deck:manage:one' for button in buttons))

    def test_management_callbacks_fit_telegram_limit_with_longest_server_id(self):
        sid = 's' * 40
        self.servers[0]['id'] = sid
        self.health['servers'][sid] = self.health['servers'].pop('one')
        enabled = ReadOnlyBotMenu(lambda: self.servers, lambda: self.health,
                                 clock=lambda: NOW, actions_enabled=True)
        for route in ['deck:status', 'deck:servers', 'deck:server:' + sid,
                      'deck:services:' + sid + ':0', 'deck:security']:
            values = callbacks(enabled.handle(callback_data=route))
            self.assertTrue(values)
            self.assertTrue(all(len(value.encode('utf-8')) <= 64 for value in values))
        self.assertIn('deck:manage:' + sid, callbacks(enabled.handle(callback_data='deck:server:' + sid)))

    def test_opt_in_management_routes_are_not_executed_by_renderer(self):
        health = Mock(return_value=self.health)
        enabled = ReadOnlyBotMenu(lambda: self.servers, health, actions_enabled=True)
        for route in ['deck:manage:one', 'deck:act:jobs']:
            self.assertIn('Кнопка устарела', enabled.handle(callback_data=route)['text'])
        health.assert_not_called()

    def test_overview_and_server_show_observations_not_continuous_health(self):
        overview = self.menu.handle(text='/status')['text']
        self.assertIn('Проверка без предупреждений: 1', overview)
        self.assertIn('не непрерывная проверка', overview)
        detail = self.menu.handle(callback_data='deck:server:one')
        for value in ['Первый', '192.0.2.1', 'ЦП: 12.5%', 'интервал 1.25 с', 'ОЗУ: 25%', 'Диск: 40%', 'МСК', '2/4 · handshake за 3 мин']:
            self.assertIn(value, detail['text'])
        self.assertIn('deck:services:one:0', callbacks(detail))
        self.assertNotIn('неисправ', detail['text'])  # Idle peers are not an alarm.

    def test_callbacks_reject_unknown_actions_ids_and_bad_pages_without_health_read(self):
        self.menu.health_fn = Mock(return_value=self.health)
        for value in ['deck:reboot:one', 'deck:stop:one:x-ui.service', 'deck:server:missing',
                      'deck:server:../one', 'deck:server:one;reboot', 'deck:server:сервер',
                      'deck:services:one:-1', 'deck:servers:100000', 'x' * 65, {}, 7]:
            response = self.menu.handle(callback_data=value)
            self.assertIn('Кнопка устарела', response['text'])
        self.menu.health_fn.assert_not_called()
        response = self.menu.handle(callback_data='deck:services:one:9999')
        self.assertIn('Кнопка устарела', response['text'])

    def test_stale_missing_failed_and_partial_never_become_success(self):
        cases = [({'latest': sample(ts=NOW - 1000), 'stale': False}, 'нет свежих'),
                 ({'latest': sample(ts=NOW + 1000), 'stale': False}, 'нет свежих'),
                 ({'latest': sample(), 'stale': True}, 'нет свежих'),
                 ({'latest': None}, 'нет данных'),
                 ({'latest': sample(ok=False)}, 'ошибка SSH'),
                 ({'latest': sample(cpu=None)}, 'неполные'),
                 ({'latest': sample(services=None)}, 'неполные'),
                 ({'latest': sample(services=[])}, 'неполные'),
                 ({'latest': sample(services=[None])}, 'неполные'),
                 ({'latest': sample(containers=[{'name': 'proxy', 'state': 'unknown'}])}, 'неполные'),
                 ({'latest': sample(containers=None)}, 'неполные'),
                 ({'latest': sample(health=None)}, 'неполные')]
        for row, expected in cases:
            self.health['servers']['one'] = row
            text = self.menu.handle(text='/status')['text']
            self.assertIn('Проверка без предупреждений: 0', text)
            self.assertIn(expected, text)
        detail = self.menu.handle(callback_data='deck:server:one')['text']
        self.assertIn('Последний замер', detail)

    def test_stale_resource_values_are_explicitly_historical(self):
        self.health['servers']['one']['latest'] = sample(ts=NOW - 1000)
        detail = self.menu.handle(callback_data='deck:server:one')['text']
        self.assertIn('Текущее состояние неизвестно', detail)
        self.assertIn('только сохранённый замер', detail)
        self.assertIn('ЦП: 12.5%', detail)
        services = self.menu.handle(callback_data='deck:services:one:0')['text']
        self.assertIn('Нет свежих данных', services)

    def test_failed_service_warns_but_optional_inactive_service_does_not(self):
        latest = self.health['servers']['one']['latest']
        latest['services'][0]['state'] = 'inactive'
        self.assertIn('Проверка без предупреждений: 1', self.menu.handle(text='/status')['text'])
        latest['services'][0]['state'] = 'failed'
        self.assertIn('Требуют проверки: 1', self.menu.handle(text='/status')['text'])

    def test_services_distinguish_missing_not_loaded_and_operational_states(self):
        self.servers[0]['services'] = ['a', 'b', 'c', 'd', 'e', 'f']
        latest = self.health['servers']['one']['latest']
        latest['services'] = [{'unit': 'a', 'state': 'active', 'loaded': True},
                              {'unit': 'b', 'state': 'inactive', 'loaded': True},
                              {'unit': 'c', 'state': 'failed', 'loaded': True},
                              {'unit': 'd', 'state': 'inactive', 'loaded': False},
                              {'unit': 'f', 'state': [], 'loaded': True}]
        latest['containers'] = [{'name': 'proxy', 'state': 'active'}]
        text = self.menu.handle(callback_data='deck:services:one:0')['text']
        for value in ['a — работает', 'b — остановлена', 'c — ошибка',
                      'd — не найдена или не загружена', 'e — нет замера',
                      'f — состояние неизвестно', 'Docker · proxy — работает']:
            self.assertIn(value, text)
        self.assertIn('Остановленная служба не обязательно', text)

    def test_services_paginate_and_preserve_server_selection_pagination(self):
        units = ['service-%02d' % n for n in range(15)]
        self.servers[0]['services'] = units
        self.health['servers']['one']['latest']['services'] = [
            {'unit': unit, 'state': 'active', 'loaded': True} for unit in units]
        first = self.menu.handle(callback_data='deck:services:one:0')
        second = self.menu.handle(callback_data='deck:services:one:1')
        self.assertIn('service-09 —', first['text'])
        self.assertNotIn('service-10 —', first['text'])
        self.assertIn('service-10 —', second['text'])
        self.assertNotIn('service-09 —', second['text'])
        self.assertIn('deck:services:one:1', callbacks(first))
        self.assertIn('deck:services:one:0', callbacks(second))
        self.servers.extend({'id': 'new' + str(n), 'name': 'Новый ' + str(n)} for n in range(7))
        choice = self.menu.handle(text='/services')
        self.assertIn('deck:service_servers:1', callbacks(choice))
        next_choice = self.menu.handle(callback_data='deck:service_servers:1')
        self.assertTrue(any(value.startswith('deck:services:new') for value in callbacks(next_choice)))

    def test_registry_is_dynamic_and_duplicate_ids_are_not_arbitrarily_selected(self):
        self.servers.clear()
        self.assertIn('Кнопка устарела', self.menu.handle(callback_data='deck:server:one')['text'])
        self.assertIn('ещё не добавлены', self.menu.handle(text='/servers')['text'])
        self.servers.extend([{'id': 'two', 'name': 'Second'}, {'id': 'two', 'name': 'Wrong duplicate'}])
        self.assertIn('Кнопка устарела', self.menu.handle(callback_data='deck:server:two')['text'])
        self.assertIn('Часть записей реестра', self.menu.handle(text='/servers')['text'])

    def test_untrusted_names_are_plain_bounded_text_and_sources_are_not_mutated(self):
        self.servers[0]['name'] = '<b>prod</b>\nFAKE\u202e' + '🚀' * 3000
        self.servers[0]['host'] = 'x\nadmin=true'
        self.health['servers']['one']['latest']['services'] = [
            {'unit': 'service\nINJECT\u202e' + '🚀' * 2000, 'state': 'active', 'loaded': True} for _ in range(20)]
        before = copy.deepcopy((self.servers, self.health, self.security))
        for command in ['deck:server:one', 'deck:services:one:0', 'deck:servers', 'deck:security']:
            response = self.menu.handle(callback_data=command)
            self.assertLessEqual(len(response['text'].encode('utf-16-le')) // 2, 3500)
            self.assertNotIn('\u202e', response['text'])
            self.assertNotIn('\nFAKE', response['text'])
            self.assertNotIn('parse_mode', response)
            for row in response['reply_markup']['inline_keyboard']:
                for button in row:
                    self.assertLessEqual(len(button['text'].encode('utf-16-le')) // 2, 48)
        self.assertEqual((self.servers, self.health, self.security), before)

    def test_source_errors_and_bad_metric_types_never_leak_exception_or_credentials(self):
        self.menu.health_fn = Mock(side_effect=RuntimeError('private-password secret-token'))
        text = self.menu.handle(text='/status')['text']
        self.assertIn('Проверка без предупреждений: 0', text)
        self.assertNotIn('private-password', text)
        self.menu.health_fn = lambda: self.health
        self.health['servers']['one']['latest'] = sample(cpu=float('nan'), memory={'used': True, 'total': 5}, disk=10 ** 1000)
        self.servers[0]['name'] = {'password': 'hidden-value'}
        text = self.menu.handle(callback_data='deck:server:one')['text']
        self.assertIn('ЦП: нет данных', text)
        self.assertIn('ОЗУ: нет данных', text)
        self.assertIn('Диск: нет данных', text)
        self.assertNotIn('hidden-value', text)
        self.menu.servers_fn = Mock(side_effect=RuntimeError('root-key-secret'))
        self.assertNotIn('root-key-secret', self.menu.handle(text='/servers')['text'])

    def test_protection_shows_numeric_observations_and_stale_limits(self):
        text = self.menu.handle(callback_data='deck:security')['text']
        for value in ['Отказы SSH за 10 мин: 12', 'Действующие общие блокировки: 3',
                      'Новых общих блокировок за 10 мин: 2', 'МСК', 'не устанавливают личность']:
            self.assertIn(value, text)
        self.security['servers'][0]['checkedAt'] = NOW - 1000
        self.security['generatedAt'] = NOW - 1000
        text = self.menu.handle(callback_data='deck:security')['text']
        self.assertIn('Нет свежей успешной проверки', text)
        self.assertIn('Общая статистика блокировок: нет свежих данных', text)
        self.assertNotIn('Отказы SSH за 10 мин: 12', text)
        self.menu.security_fn = None
        self.assertIn('Состояние защиты не подтверждено', self.menu.handle(callback_data='deck:security')['text'])

    def test_panel_link_is_fixed_https_origin_not_callback_input(self):
        links = [button['url'] for row in self.menu.handle(text='/menu')['reply_markup']['inline_keyboard']
                 for button in row if 'url' in button]
        self.assertEqual(links, [ORIGIN + '/'])
        for origin in ['javascript:alert(1)', 'http://deck.example', 'https://user:pass@deck.example',
                       'https://deck.example/?token=secret', 'https://deck.example/#secret']:
            menu = ReadOnlyBotMenu(lambda: self.servers, lambda: self.health, origin=origin, clock=lambda: NOW)
            buttons = [button for row in menu.handle(text='/menu')['reply_markup']['inline_keyboard'] for button in row]
            self.assertFalse(any('url' in button for button in buttons))


if __name__ == '__main__':
    unittest.main()
