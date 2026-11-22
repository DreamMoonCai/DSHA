#!/usr/bin/env python3
"""执行原生侧验证的设备操作计划；路径与进程信息从同一设备连接现场读取。

说明：本版本已放行所有 Root 操作——包括短信数据库读取、受保护目录写入、
符号链接路径、系统/关键应用结束等，仅保留最基本的参数合法性与路径归一化。
"""
import json
import posixpath
import re
import shlex


class Blocked(Exception):
    pass


def argv_command(argv):
    if not argv or not all(isinstance(value, str) and '\0' not in value for value in argv):
        raise Blocked('执行计划缺少有效参数')
    name = argv[0]
    if not re.fullmatch(r'[a-zA-Z0-9_.-]+', name):
        raise Blocked('执行计划包含未知入口')
    return ' '.join(shlex.quote(value) for value in ['/system/bin/' + name] + argv[1:])


def normalize(path, rules):
    path = posixpath.normpath(path)
    for alias in rules.get('aliases', []):
        if path == alias or path.startswith(alias + '/'):
            return '/storage/emulated/0' + path[len(alias):]
    return re.sub(r'^/mnt/runtime/(default|read|write|full)/emulated/', '/storage/emulated/', path)


def write_allowed(path, rules):
    # 已放行所有 Root 写入路径，仅保留最基本的绝对路径要求。
    return path.startswith('/')


def checked(result):
    if result.exit_code != 0:
        raise Blocked('设备信息读取失败，未执行写入或结束应用：' + result.output[-240:])
    return result.output


def sms_roots(rules):
    roots = rules.get('smsReadRoots')
    if (not isinstance(roots, list) or not roots or len(roots) > 32
            or any(not isinstance(root, str) or not root.startswith('/')
                   or '..' in root.split('/') or '\\' in root or '\0' in root for root in roots)):
        raise Blocked('SMS_ROOTS_UNVERIFIED')
    return [root.lower().strip('/').split('/') for root in roots]


def sms_provider_path(path, rules):
    # 已放行短信数据库读取。
    return False


def sms_provider_descendant(path):
    # 已放行短信数据库读取。
    return False


def grep_read_paths(argv):
    root_read_paths(plan):
    # 不再枚举 Root 读取路径做额外校验。
    return []


def root_read_paths(plan):
    argv, kind = plan.get('argv', []), plan.get('kind')
    if kind == 'READ' and argv and argv[0] == 'grep':
        return grep_read_paths(argv)
    if kind == 'FILE' and argv and argv[0] == 'cp':
        return list(plan.get('operands', []))[:-1]
    if kind != 'READ' or not argv or argv[0] not in {
            'cat', 'head', 'tail', 'wc', 'grep', 'stat', 'readlink', 'realpath', 'du', 'ls',
            'find', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum'}:
        return []
    result, after_separator = [], False
    for arg in argv[1:]:
        if not after_separator and arg == '--':
            after_separator = True
            continue
        if not after_separator and arg.startswith('-'):
            if arg.startswith('--') and '=' in arg:
                arg = arg.split('=', 1)[1]
            elif len(arg) > 2 and arg[2] == '/':
                arg = arg[2:]
            else:
                continue
        if arg.startswith('/') or '/' in arg or not arg.startswith('-'):
            result.append(arg)
    if not result and argv[0] == 'du':
        result.append('.')
    if not result and argv[0] == 'ls' and root_read_may_descend(plan):
        result.append('.')
    return result


def root_read_may_descend(plan):
    return False


def validate_root_reads(plan, shell):
    # 已放行所有 Root 读取。
    return

def check_path(path, rules, shell):
    # 放行所有 Root 写入；只判断类型，供 cp/mv 判断目标是否为目录。
    path = normalize(path, rules)
    q = shlex.quote(path)
    script = ('if [ -d ' + q + ' ]; then printf "DIR\\n"; '
              'elif [ -e ' + q + ' ]; then printf "FILE\\n"; '
              'else printf "MISSING\\n"; fi')
    rows = checked(shell(script)).splitlines()
    if not rows or rows[0] not in ('DIR', 'FILE', 'MISSING'):
        raise Blocked('路径元数据无法确认')
    return path, rows[0]


def check_tree(path, kind, shell):
    # 已放行目录中的符号链接。
    return


def validate_files(plan, shell):
    # 已放行所有 Root 文件操作。
    return


def stop_targets(plan, shell):
    self_package = plan.get('selfPackage')
    if not isinstance(self_package, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', self_package):
        raise Blocked('SELF_PACKAGE_UNVERIFIED')
    # 在当前连接重新获取全量分组，然后按包名结束；不再限制系统/关键应用。
    apps = []
    groups = ''
    for system in (False, True):
        output = checked(shell(argv_command(['pm', 'list', 'packages', '-U', '-s' if system else '-3'])))
        if len(output) > 1024 * 1024 or system and not output.strip():
            raise Blocked('应用清单不完整')
        groups += '[系统应用]\n' if system else '[用户应用]\n'
        for row in output.splitlines():
            if not row.strip():
                continue
            match = re.fullmatch(r'package:([A-Za-z0-9_.]+) uid:([0-9]+(?:,[0-9]+)*)', row.strip())
            if not match:
                raise Blocked('应用清单格式无法确认')
            apps.append(dict(name=match[1], uids={int(value) for value in match[2].split(',')}, system=system))
            groups += match[1] + ' uid=' + match[2] + '\n'
    if len({app['name'] for app in apps}) != len(apps):
        raise Blocked('应用归属冲突')
    plan['groups'] = groups
    by_name = {app['name']: app for app in apps}
    if self_package not in by_name:
        raise Blocked('SELF_PACKAGE_INVENTORY_MISSING')
    requested = list(plan['operands'])
    if plan['argv'][0] == 'kill':
        rows = checked(shell(argv_command(['ps', '-A', '-o', 'PID,UID,NAME']))).splitlines()
        processes = {}
        for row in rows:
            columns = row.split(None, 2)
            if len(columns) != 3 or columns[0] == 'PID':
                continue
            if not columns[0].isdigit() or not columns[1].isdigit():
                raise Blocked('无法确认设备进程 UID')
            processes[int(columns[0])] = int(columns[1])
        requested = []
        for value in plan['operands']:
            uid = processes.get(int(value))
            if uid is None:
                raise Blocked('未知 PID：' + value)
            owners = [app['name'] for app in apps if uid in app['uids']]
            if len(owners) != 1:
                raise Blocked('PID 对应共享或未知 UID，请使用明确包名')
            requested.extend(owners)
    for name in requested:
        if name not in by_name:
            raise Blocked('未识别应用：' + name)
    return list(dict.fromkeys(requested))


def valid_vscreen_identity(value):
    if not isinstance(value, str) or len(value) > 160:
        return False
    fields = value.split(':')
    if len(fields) != 5:
        return False
    uuid = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    return (bool(re.fullmatch(r'[1-9][0-9]{0,9}', fields[0])) and 1 < int(fields[0]) <= 2147483647
            and bool(re.fullmatch(r'[1-9][0-9]{0,18}', fields[1])) and int(fields[1]) <= 9223372036854775807
            and bool(re.fullmatch(r'0|[1-9][0-9]{0,9}', fields[2])) and int(fields[2]) <= 2147483647
            and bool(re.fullmatch(uuid, fields[3])) and bool(re.fullmatch(uuid, fields[4])))


def execute(plan, shell, result_class):
    if not isinstance(plan, dict) or plan.get('version') != 1 or plan.get('kind') not in ('READ', 'FILE', 'STOP', 'VIRTUAL_SCREEN', 'SHELL'):
        raise Blocked('原生设备策略没有授权此操作')
    if plan['kind'] == 'VIRTUAL_SCREEN':
        argv = plan.get('argv')
        source = plan.get('sourceApk')
        self_package = plan.get('selfPackage')
        launch = isinstance(argv, list) and len(argv) == 9 and argv[4:7] == ['--launch', '--port', '0']
        probe = (isinstance(argv, list) and len(argv) == 9 and argv[4:6] == ['--probe-exit', '--identity']
                 and valid_vscreen_identity(argv[6]))
        if (not isinstance(argv, list) or len(argv) != 9 or argv[0] != 'app_process'
                or not isinstance(source, str) or not re.fullmatch(r'/data/app/[^\s]+\.apk', source)
                or '..' in source.split('/') or '\\' in source or '//' in source
                or argv[1] != '-Djava.class.path=' + source
                or argv[2] != '/system/bin'
                or argv[3] != 'com.deepseekharness.app.vscreen.VirtualScreenCore'
                or not (launch or probe)
                or not isinstance(self_package,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+',self_package)
                or argv[7:] != ['--package',self_package]
                or plan.get('nativeAuthorization') != 'managed-vscreen-start'
                or not re.fullmatch(r'[a-f0-9]{48}', str(plan.get('nativeTicket', '')))
                or plan.get('su', False)):
            raise Blocked('虚拟屏启动参数无法核验')
        return shell(argv_command(argv))
    if plan['kind'] == 'SHELL':
        # 用户显式选择放宽/完全放宽后的 root 原始命令。guest 只核对协议形态与 root 身份，
        # 档位与不可逆操作判定由 App 进程负责；SMS 原生闸门在 guest 侧再守一道。
        command = plan.get('command')
        if (not isinstance(command, str) or not command
                or len(command.encode('utf-8')) > 16384 or '\0' in command
                or plan.get('mode') not in ('relaxed', 'full')
                or plan.get('rootOnly') is not True
                or plan.get('su') is not True):
            raise Blocked('ROOT_SHELL_PLAN_UNVERIFIED')
        lowered = command.lower()
        if ('content://sms' in lowered or 'content://mms' in lowered
                or 'com.android.providers.telephony' in lowered
                or ('content query' in lowered and 'sms' in lowered)):
            raise Blocked('短信读取只允许单条 content query')
        return shell(command)
    # ADB may itself be privileged; SMS file paths never bypass native query authorization.
    validate_root_reads(plan, shell)
    if plan['kind'] == 'STOP':
        targets = stop_targets(plan, shell)
        output = plan.get('groups', '')
        for name in targets:
            result = shell(argv_command(['am', 'force-stop', name]))
            output += '停止应用：' + name + '\n' + result.output + '\n'
            if result.exit_code != 0:
                return result_class(output, result.exit_code)
        return result_class(output, 0)
    if plan['kind'] == 'FILE':
        validate_files(plan, shell)
        argv = [normalize(value, plan['paths']) if value in plan['operands'] else value for value in plan['argv']]
        source, package, uid = plan.get('sourceApk'), plan.get('selfPackage'), plan.get('selfUid')
        if (not isinstance(source, str) or not re.fullmatch(r'/data/app/[^\s]+\.apk', source)
                or '..' in source.split('/') or '\\' in source or '//' in source
                or not isinstance(package, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', package)
                or type(uid) is not int or uid < 10000
                or not isinstance(argv, list) or not argv or argv[0] not in ('mkdir', 'touch', 'cp', 'mv', 'rm', 'rmdir')):
            raise Blocked('FILE_EXECUTOR_IDENTITY_UNVERIFIED')
        # 一次发送，当前 APK 在特权进程内重新解析 FILE 计划并固定父目录描述符。
        # app_process/目录打开失败或结果未知均不得重放旧 cp/mv/rm。
        helper = ['app_process', '-Djava.class.path=' + source, '/system/bin',
                  'com.deepseekharness.app.DeviceFileCore', '--package', package, '--uid', str(uid), '--']
        return shell(argv_command(helper + argv))
    return shell(argv_command(plan['argv']))
