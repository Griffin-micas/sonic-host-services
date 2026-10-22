import builtins
import importlib.machinery
import importlib.util
import os
import sys
import types
from unittest import mock

import pytest


scripts_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts')
loader = importlib.machinery.SourceFileLoader(
    'aaastatsd', os.path.join(scripts_path, 'aaastatsd'))
spec = importlib.util.spec_from_loader(loader.name, loader)
aaastatsd = importlib.util.module_from_spec(spec)

watchdog = types.ModuleType('watchdog')
watchdog_observers = types.ModuleType('watchdog.observers')
watchdog_events = types.ModuleType('watchdog.events')
watchdog_observers.Observer = mock.Mock
watchdog_events.FileSystemEventHandler = object
swsscommon = types.ModuleType('swsscommon')
swsscommon_module = types.ModuleType('swsscommon.swsscommon')
swsscommon_module.ConfigDBConnector = mock.Mock

with mock.patch.dict(sys.modules, {
        'swsscommon': swsscommon,
        'swsscommon.swsscommon': swsscommon_module,
        'watchdog': watchdog,
        'watchdog.observers': watchdog_observers,
        'watchdog.events': watchdog_events,
}):
    loader.exec_module(aaastatsd)


@pytest.mark.parametrize('server', ['', '.', '..', 'nested/name',
                                    'nested/../192.0.2.1', 'bad\x00name'])
def test_stats_path_rejects_invalid_server_names(server):
    with mock.patch.object(aaastatsd.syslog, 'syslog'):
        assert aaastatsd.radius_stats_file_path(server) is None


def test_stats_path_accepts_server_address():
    expected = os.path.realpath(os.path.join(
        aaastatsd.RADIUS_PAM_AUTH_CONF_STATS_DIR, '2001:db8::1'))

    assert aaastatsd.radius_stats_file_path('2001:db8::1') == expected


@pytest.mark.parametrize('method_name', ['create_file', 'handle_update'])
def test_invalid_server_name_does_not_access_file(method_name):
    radius_stats = aaastatsd.RadiusStatistics.__new__(aaastatsd.RadiusStatistics)
    radius_stats.radius_global = {'statistics': 'True'}

    with mock.patch.object(builtins, 'open') as mocked_open, \
            mock.patch.object(aaastatsd.os.path, 'exists') as mocked_exists, \
            mock.patch.object(aaastatsd.os, 'chmod') as mocked_chmod:
        getattr(radius_stats, method_name)('nested/name')

    mocked_open.assert_not_called()
    mocked_exists.assert_not_called()
    mocked_chmod.assert_not_called()


def test_create_file_accepts_server_address(tmp_path):
    radius_stats = aaastatsd.RadiusStatistics.__new__(aaastatsd.RadiusStatistics)
    radius_stats.radius_global = {'statistics': 'True'}

    with mock.patch.object(aaastatsd, 'RADIUS_PAM_AUTH_CONF_STATS_DIR',
                           str(tmp_path) + os.path.sep), \
            mock.patch.object(radius_stats, 'handle_update') as mocked_update:
        radius_stats.create_file('2001:db8::1')

    assert (tmp_path / '2001:db8::1').exists()
    mocked_update.assert_called_once_with('2001:db8::1')


def test_traversal_alias_cannot_unlink_another_servers_file(tmp_path):
    stats_file = tmp_path / '192.0.2.1'
    stats_file.write_text('counter data')
    radius_stats = aaastatsd.RadiusStatistics.__new__(aaastatsd.RadiusStatistics)
    radius_stats.radius_global = {'statistics': 'False'}

    with mock.patch.object(aaastatsd, 'RADIUS_PAM_AUTH_CONF_STATS_DIR',
                           str(tmp_path) + os.path.sep):
        radius_stats.create_file('nested/../192.0.2.1')

    assert stats_file.read_text() == 'counter data'


def test_same_directory_symlink_cannot_unlink_another_servers_file(tmp_path):
    stats_file = tmp_path / '192.0.2.1'
    stats_file.write_text('counter data')
    alias = tmp_path / '192.0.2.2'
    alias.symlink_to(stats_file)
    radius_stats = aaastatsd.RadiusStatistics.__new__(aaastatsd.RadiusStatistics)
    radius_stats.radius_global = {'statistics': 'False'}

    with mock.patch.object(aaastatsd, 'RADIUS_PAM_AUTH_CONF_STATS_DIR',
                           str(tmp_path) + os.path.sep):
        radius_stats.create_file('192.0.2.2')

    assert stats_file.read_text() == 'counter data'
    assert alias.is_symlink()


def test_same_directory_symlink_is_not_read_or_written(tmp_path):
    stats_file = tmp_path / '192.0.2.1'
    stats_file.write_text('counter data')
    alias = tmp_path / '192.0.2.2'
    alias.symlink_to(stats_file)
    radius_stats = aaastatsd.RadiusStatistics.__new__(aaastatsd.RadiusStatistics)
    radius_stats.radius_global = {'statistics': 'True'}

    with mock.patch.object(aaastatsd, 'RADIUS_PAM_AUTH_CONF_STATS_DIR',
                           str(tmp_path) + os.path.sep):
        with mock.patch.object(radius_stats, 'handle_update') as update:
            radius_stats.create_file('192.0.2.2')
            update.assert_not_called()
        with mock.patch.object(aaastatsd.os, 'listdir', return_value=['192.0.2.2']):
            radius_stats.handle_clear()
        with mock.patch.object(builtins, 'open') as file_open:
            radius_stats.handle_update('192.0.2.2')
            file_open.assert_not_called()

    assert stats_file.read_text() == 'counter data'
    assert alias.is_symlink()


def test_clear_only_truncates_local_stats_files(tmp_path):
    stats_dir = tmp_path / 'statistics'
    stats_dir.mkdir()
    local_file = stats_dir / '192.0.2.1'
    local_file.write_text('counter data')
    other_file = tmp_path / 'other'
    other_file.write_text('keep data')
    (stats_dir / '192.0.2.2').symlink_to(other_file)

    radius_stats = aaastatsd.RadiusStatistics.__new__(aaastatsd.RadiusStatistics)
    with mock.patch.object(aaastatsd, 'RADIUS_PAM_AUTH_CONF_STATS_DIR',
                           str(stats_dir) + os.path.sep):
        radius_stats.handle_clear()

    assert local_file.read_text() == ''
    assert other_file.read_text() == 'keep data'


@pytest.mark.parametrize('event_type', ['opened', 'closed_no_write', 'closed',
                                       'unknown'])
def test_stats_handler_ignores_non_change_events(event_type):
    stats = mock.Mock()
    handler = aaastatsd.RadiusStatsFileHandler(stats)
    event = types.SimpleNamespace(
        is_directory=False, event_type=event_type,
        src_path=aaastatsd.RADIUS_PAM_AUTH_CONF_STATS_DIR + '192.0.2.1')

    handler.on_any_event(event)

    stats.handle_update.assert_not_called()


@pytest.mark.parametrize('event_type', ['created', 'modified', 'deleted', 'moved'])
def test_stats_handler_ignores_directory_events(event_type):
    stats = mock.Mock()
    handler = aaastatsd.RadiusStatsFileHandler(stats)

    handler.on_any_event(types.SimpleNamespace(
        is_directory=True, event_type=event_type))

    stats.handle_update.assert_not_called()


@pytest.mark.parametrize('event_type', ['created', 'modified', 'deleted'])
def test_stats_handler_updates_changed_file(event_type):
    stats = mock.Mock()
    handler = aaastatsd.RadiusStatsFileHandler(stats)

    handler.on_any_event(types.SimpleNamespace(
        is_directory=False, event_type=event_type,
        src_path=aaastatsd.RADIUS_PAM_AUTH_CONF_STATS_DIR + '192.0.2.1'))

    stats.handle_update.assert_called_once_with('192.0.2.1')


@pytest.mark.parametrize('src_path,dest_path,expected', [
    ('192.0.2.1', '192.0.2.2', ['192.0.2.1', '192.0.2.2']),
    ('192.0.2.1', '192.0.2.1', ['192.0.2.1']),
    ('../incoming', '192.0.2.1', ['192.0.2.1']),
    ('192.0.2.1', '../outgoing', ['192.0.2.1']),
])
def test_stats_handler_updates_local_move_endpoints(src_path, dest_path,
                                                    expected):
    stats = mock.Mock()
    handler = aaastatsd.RadiusStatsFileHandler(stats)
    stats_dir = aaastatsd.RADIUS_PAM_AUTH_CONF_STATS_DIR

    handler.on_any_event(types.SimpleNamespace(
        is_directory=False, event_type='moved',
        src_path=os.path.join(stats_dir, src_path),
        dest_path=os.path.join(stats_dir, dest_path)))

    assert stats.handle_update.call_args_list == [mock.call(srv) for srv in expected]


def test_stats_handler_ignores_changes_outside_stats_directory():
    stats = mock.Mock()
    handler = aaastatsd.RadiusStatsFileHandler(stats)

    handler.on_any_event(types.SimpleNamespace(
        is_directory=False, event_type='modified',
        src_path='/tmp/192.0.2.1'))

    stats.handle_update.assert_not_called()


def test_stats_handler_read_does_not_schedule_another_update(tmp_path):
    stats_file = tmp_path / '192.0.2.1'
    stats_file.write_text('0 1 2 3')
    stats = aaastatsd.RadiusStatistics.__new__(aaastatsd.RadiusStatistics)
    stats.radius_global = {'statistics': 'True'}
    stats.radius_counter_names = ['counter_0', 'access_requests',
                                  'access_accepts', 'access_rejects']
    handler = aaastatsd.RadiusStatsFileHandler(stats)
    real_open = builtins.open
    pending_events = [types.SimpleNamespace(
        is_directory=False, event_type='modified', src_path=str(stats_file))]

    def read_with_events(*args, **kwargs):
        pending_events.extend(types.SimpleNamespace(
            is_directory=False, event_type=event_type, src_path=str(stats_file))
            for event_type in ('opened', 'closed_no_write'))
        return real_open(*args, **kwargs)

    with mock.patch.object(aaastatsd, 'RADIUS_PAM_AUTH_CONF_STATS_DIR',
                           str(tmp_path)), \
            mock.patch.object(aaastatsd, 'ConfigDBConnector') as connector, \
            mock.patch.object(builtins, 'open', side_effect=read_with_events):
        # Bound event processing so a regression fails rather than hanging.
        for _ in range(10):
            if not pending_events:
                break
            handler.on_any_event(pending_events.pop(0))

        assert pending_events == []
        connector.return_value.set_entry.assert_called_once_with(
            'RADIUS_SERVER_STATS', '192.0.2.1', {
                'counter_0': '0', 'access_requests': '1',
                'access_accepts': '2', 'access_rejects': '3'})
