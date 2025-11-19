#!/usr/bin/env python3
# Author: Sotirios Roussis <root@xtonousou.com>
# Revised by: Rik Bon <rikbon@gmail.com>

import re
import os
import sys
import base64
import argparse
import configparser
from getpass import getpass
from typing import Dict, Optional

from Crypto.Hash import SHA512
from Crypto.Cipher import AES, DES3


class MobaXtermCryptoSafe:
    """
    Ref: https://github.com/HyperSine/how-does-MobaXterm-encrypt-password
    """
    def __init__(self, master_password: bytes):
        self.key = SHA512.new(master_password).digest()[0:32]

    def decrypt(self, ciphertext: str) -> bytes:
        iv = AES.new(key=self.key, mode=AES.MODE_ECB).encrypt(b'\x00' * AES.block_size)
        cipher = AES.new(key=self.key, iv=iv, mode=AES.MODE_CFB, segment_size=8)
        return cipher.decrypt(base64.b64decode(ciphertext))


class RemminaCryptoSafe:
    """
    Ref: https://github.com/Rohith050/mremoteng_to_remmina
    """
    def __init__(self, secret: str):
        self.secret = base64.b64decode(secret)

    def encrypt(self, plaintext: str) -> str:
        pad = 8 - len(plaintext) % 8
        plaintext += pad * chr(0)
        return base64.b64encode(DES3.new(self.secret[:24], DES3.MODE_CBC, self.secret[24:]).encrypt(plaintext.encode())).decode()


class ConfigParserMultiOpt(configparser.RawConfigParser):
    """
    Ref: https://stackoverflow.com/questions/13921323/handling-duplicate-keys-with-configparser
    ConfigParser allowing duplicate keys. Values are stored in a list
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._inline_comment_prefixes = ()
        self._comment_prefixes = ('#', ';')

    def _read(self, fp, fpname):
        """Parse a sectioned configuration file.

        Each section in a configuration file contains a header, indicated by
        a name in square brackets (`[]'), plus key/value options, indicated by
        `name' and `value' delimited with a specific substring (`=' or `:' by
        default).

        Values can span multiple lines, as long as they are indented deeper
        than the first line of the value. Depending on the parser's mode, blank
        lines may be treated as parts of multiline values or ignored.

        Configuration files may include comments, prefixed by specific
        characters (`#' and `;' by default). Comments may appear on their own
        in an otherwise empty line or may be entered in lines holding values or
        section names.
        """
        elements_added = set()
        cursect = None                                                # None, or a dictionary
        sectname = None
        optname = None
        lineno = 0
        indent_level = 0
        e = None                                                            # None, or an exception
        for lineno, line in enumerate(fp, start=1):
            comment_start = None
            # strip inline comments
            for prefix in self._inline_comment_prefixes:
                index = line.find(prefix)
                if index == 0 or (index > 0 and line[index-1].isspace()):
                    comment_start = index
                    break
            # strip full line comments
            for prefix in self._comment_prefixes:
                if line.strip().startswith(prefix):
                    comment_start = 0
                    break
            value = line[:comment_start].strip()
            if not value:
                if self._empty_lines_in_values:
                    # add empty line to the value, but only if there was no
                    # comment on the line
                    if (comment_start is None and cursect is not None and optname and cursect[optname] is not None):
                        cursect[optname].append('') # newlines added at join
                else:
                    # empty line marks end of value
                    indent_level = sys.maxsize
                continue
            # continuation line?
            first_nonspace = self.NONSPACECRE.search(line)
            cur_indent_level = first_nonspace.start() if first_nonspace else 0
            if (cursect is not None and optname and cur_indent_level > indent_level):
                cursect[optname].append(value)
            # a section header or option header?
            else:
                indent_level = cur_indent_level
                # is it a section header?
                mo = self.SECTCRE.match(value)
                if mo:
                    sectname = mo.group('header')
                    if sectname in self._sections:
                        if self._strict and sectname in elements_added:
                            raise configparser.DuplicateSectionError(sectname, fpname, lineno)
                        cursect = self._sections[sectname]
                        elements_added.add(sectname)
                    elif sectname == self.default_section:
                        cursect = self._defaults
                    else:
                        cursect = self._dict()
                        self._sections[sectname] = cursect
                        self._proxies[sectname] = configparser.SectionProxy(self, sectname)
                        elements_added.add(sectname)
                    # So sections can't start with a continuation line
                    optname = None
                # no section header in the file?
                elif cursect is None:
                    raise configparser.MissingSectionHeaderError(fpname, lineno, line)
                # an option line?
                else:
                    mo = self._optcre.match(value)
                    if mo:
                        optname, vi, optval = mo.group('option', 'vi', 'value')
                        if not optname:
                            e = self._handle_error(e, fpname, lineno, line)
                        optname = self.optionxform(optname.rstrip())
                        if (self._strict and (sectname, optname) in elements_added):
                            raise configparser.DuplicateOptionError(sectname, optname, fpname, lineno)
                        elements_added.add((sectname, optname))
                        # This check is fine because the OPTCRE cannot
                        # match if it would set optval to None
                        if optval is not None:
                            optval = optval.strip()
                            # Check if this optname already exists
                            if (optname in cursect) and (cursect[optname] is not None):
                                # If it does, convert it to a tuple if it isn't already one
                                if not isinstance(cursect[optname], tuple):
                                    cursect[optname] = tuple(cursect[optname])
                                cursect[optname] = cursect[optname] + tuple([optval])
                            else:
                                cursect[optname] = [optval]
                        else:
                            # valueless option handling
                            cursect[optname] = None
                    else:
                        # a non-fatal parsing error occurred. set up the
                        # exception but keep going. the exception will be
                        # raised at the end of the file and will contain a
                        # list of all bogus lines
                        e = self._handle_error(e, fpname, lineno, line)
        # if any parsing errors occurred, raise an exception
        if e:
            raise e
        self._join_multiline_values()


class SSH:
    def __init__(self, ip: str, port: str, name: str, username: str, password: str, group: str, theme: str):
        self.ip = ip
        self.port = port
        self.name = name
        self.username = username
        self.password = password
        self.group = group
        self.theme = theme
        self.protocol = 'SSH'

    def get_remmina_conf(self) -> configparser.ConfigParser:
        server = f"{self.ip}:{self.port}" if int(self.port) != 22 else self.ip

        config = configparser.ConfigParser()
        config['remmina'] = {
            'ssh_tunnel_loopback': '0',
            'window_maximize': '0',
            'protocol': self.protocol,
            'name': self.name,
            'username': self.username,
            'password': self.password,
            'ssh_proxycommand': '',
            'ssh_passphrase': '',
            'run_line': '',
            'precommand': '',
            'sshlogenabled': '0',
            'ssh_tunnel_enabled': '0',
            'ssh_charset': '',
            'window_height': '480',
            'keyboard_grab': '0',
            'window_width': '640',
            'ssh_auth': '0',
            'ignore-tls-errors': '1',
            'postcommand': '',
            'server': server,
            'disablepasswordstoring': '0',
            'ssh_color_scheme': self.theme,
            'audiblebell': '0',
            'ssh_tunnel_username': '',
            'sshsavesession': '0',
            'ssh_hostkeytypes': '',
            'ssh_tunnel_password': '',
            'profile-lock': '0',
            'sshlogfolder': '',
            'group': self.group,
            'ssh_tunnel_server': '',
            'ssh_ciphers': '',
            'enable-autostart': '0',
            'ssh_kex_algorithms': '',
            'ssh_compression': '0',
            'ssh_tunnel_auth': '0',
            'ssh_tunnel_certfile': '',
            'notes_text': '',
            'exec': '',
            'viewmode': '1',
            'sshlogname': '',
            'ssh_tunnel_passphrase': '',
            'ssh_tunnel_privatekey': '',
            'ssh_stricthostkeycheck': '0',
            'ssh_forward_x11': '0',
        }
        return config

    def __str__(self) -> str:
        return 'ssh'


class RDP:
    def __init__(self, ip: str, port: str, name: str, username: str, password: str, group: str):
        self.protocol = 'RDP'
        self.ip = ip
        self.port = port
        self.name = name
        self.password = password
        self.group = group

        if '\\' in username:
            self.domain, self.username = username.split('\\', 1)
        elif '@' in username:
            self.username, self.domain = username.split('@', 1)
        else:
            self.username = username
            self.domain = ''
        
        if self.domain == '.':
            self.domain = ''

    def get_remmina_conf(self) -> configparser.ConfigParser:
        server = f"{self.ip}:{self.port}" if int(self.port) != 3389 else self.ip

        config = configparser.ConfigParser()
        config['remmina'] = {
            'password': self.password,
            'gateway_username': '',
            'notes_text': '',
            'vc': '',
            'preferipv6': '0',
            'ssh_tunnel_loopback': '0',
            'serialname': '',
            'tls-seclevel': '',
            'freerdp_log_level': 'INFO',
            'printer_overrides': '',
            'name': self.name,
            'console': '0',
            'colordepth': '99',
            'security': '',
            'precommand': '',
            'disable_fastpath': '0',
            'left-handed': '0',
            'postcommand': '',
            'multitransport': '0',
            'group': self.group,
            'server': server,
            'ssh_tunnel_certfile': '',
            'glyph-cache': '0',
            'ssh_tunnel_enabled': '0',
            'disableclipboard': '0',
            'parallelpath': '',
            'audio-output': '',
            'monitorids': '',
            'cert_ignore': '0',
            'serialpermissive': '0',
            'gateway_server': '',
            'protocol': self.protocol,
            'ssh_tunnel_password': '',
            'old-license': '0',
            'resolution_mode': '2',
            'pth': '',
            'loadbalanceinfo': '',
            'disableautoreconnect': '0',
            'clientbuild': '',
            'clientname': '',
            'resolution_width': '0',
            'drive': '',
            'relax-order-checks': '0',
            'username': self.username,
            'base-cred-for-gw': '0',
            'gateway_domain': '',
            'profile-lock': '0',
            'rdp2tcp': '',
            'gateway_password': '',
            'rdp_reconnect_attempts': '',
            'domain': self.domain,
            'serialdriver': '',
            'restricted-admin': '0',
            'smartcardname': '',
            'multimon': '0',
            'serialpath': '',
            'network': 'none',
            'exec': '',
            'enable-autostart': '0',
            'usb': '',
            'shareprinter': '0',
            'ssh_tunnel_passphrase': '',
            'disablepasswordstoring': '0',
            'shareparallel': '0',
            'quality': '9',
            'span': '0',
            'parallelname': '',
            'ssh_tunnel_auth': '0',
            'keymap': '',
            'ssh_tunnel_username': '',
            'execpath': '',
            'shareserial': '0',
            'resolution_height': '0',
            'timeout': '',
            'useproxyenv': '0',
            'sharesmartcard': '0',
            'freerdp_log_filters': '',
            'microphone': '',
            'dvc': '',
            'ssh_tunnel_privatekey': '',
            'gwtransp': 'http',
            'ssh_tunnel_server': '',
            'ignore-tls-errors': '1',
            'disable-smooth-scrolling': '0',
            'gateway_usage': '0',
            'sound': 'off',
            'websockets': '0',
        }
        return config

    def __str__(self) -> str:
        return 'rdp'


class Converter:
    def __init__(self, input_file: str, export_dir: str, theme: str, with_passwords: bool):
        self.input_file = input_file
        self.export_dir = export_dir
        self.theme = theme
        self.with_passwords = with_passwords
        self.config = ConfigParserMultiOpt(empty_lines_in_values=False, strict=False)
        self.mobaxterm_safe: Optional[MobaXtermCryptoSafe] = None
        self.remmina_safe: Optional[RemminaCryptoSafe] = None
        self.moba_proto_map = {0: SSH, 4: RDP}

    def _prepare_fs(self):
        if not os.path.isdir(self.export_dir):
            os.mkdir(self.export_dir)

    @staticmethod
    def get_valid_filename(name: str) -> str:
        s = str(name).strip().replace(' ', '_')
        s = re.sub(r'(?u)[^-\w.]', '', s)
        return s

    def _get_passwords(self) -> Dict[str, str]:
        if not self.with_passwords:
            return {}

        mobaxterm_master_password = getpass('Enter MobaXterm master password: ')
        self.mobaxterm_safe = MobaXtermCryptoSafe(mobaxterm_master_password.encode('cp1251'))
        remmina_secret = getpass('Enter Remmina secret: ')
        self.remmina_safe = RemminaCryptoSafe(remmina_secret)

        passwords = {}
        tmp_passwords = dict(self.config.items('Passwords'))
        for k, v in tmp_passwords.items():
            if isinstance(v, (tuple, list)):
                for credential in v:
                    part_k, part_v = credential.split('=', 1)
                    if part_k not in passwords:
                        passwords[part_k] = part_v
            elif '@' not in k:
                part_k, part_v = v.split('=', 1)
                if part_k not in passwords:
                    passwords[part_k] = part_v
            elif k not in passwords:
                passwords[k] = v
        return passwords

    def convert(self):
        try:
            with open(self.input_file, 'r') as f:
                self.config.read_file(f)
        except FileNotFoundError:
            print(f"Error: Input file not found at '{self.input_file}'")
            sys.exit(1)

        self._prepare_fs()
        passwords = self._get_passwords()

        for section in self.config.sections():
            if not section.lower().startswith('bookmarks'):
                continue

            bookmark = dict(self.config.items(section))
            if len(bookmark) <= 2:  # 'subrep' and 'imgnum'
                continue

            group = bookmark.get('subrep', '').replace('\\', '/')

            for session_name, session_info in bookmark.items():
                if session_name in ('subrep', 'imgnum'):
                    continue

                parts = session_info.split('#')[2].split('%')
                proto_id = int(parts[0])
                
                if proto_id not in self.moba_proto_map:
                    continue

                class_ref = self.moba_proto_map[proto_id]
                ip = parts[1]
                port = parts[2]
                username = parts[3]
                password = '.'

                if self.with_passwords and self.mobaxterm_safe and self.remmina_safe:
                    ciphertext = passwords.get(f'{username}@{ip}')
                    if ciphertext:
                        plain_text = self.mobaxterm_safe.decrypt(ciphertext).decode('ansi')
                        password = self.remmina_safe.encrypt(plain_text)

                session_args = {
                    "ip": ip,
                    "port": port,
                    "name": session_name,
                    "username": username,
                    "password": password,
                    "group": group,
                }
                if class_ref == SSH:
                    session_args["theme"] = self.theme

                session = class_ref(**session_args)

                filename = self.get_valid_filename(
                    f"{group.lower().replace('/', '-')}_{session}_{session_name.lower().replace(' ', '-')}_{ip.replace('.', '-')}.remmina"
                )

                if not filename:
                    print(f"Warning: Cannot export '{session_name}' due to an invalid filename.")
                    continue

                with open(os.path.join(self.export_dir, filename), 'w') as f:
                    session.get_remmina_conf().write(f)

        print(f'Successfully converted and exported Remmina sessions to "{self.export_dir}".')
        print(f'Copy them to "~/.local/share/remmina" to be loaded by Remmina.')


def main():
    parser = argparse.ArgumentParser(description='Convert MobaXterm sessions to Remmina connection files.')
    parser.add_argument('input_file', help='Path to the MobaXterm sessions file (*.mxtsessions)')
    parser.add_argument('--passwords', action='store_true', help='Decrypt and encrypt passwords')
    parser.add_argument('--theme', default='Linux', help='Remmina color theme for SSH sessions')
    parser.add_argument('--export-dir', default='./exported', help='Directory to export Remmina files')
    args = parser.parse_args()

    converter = Converter(
        input_file=args.input_file,
        export_dir=args.export_dir,
        theme=args.theme,
        with_passwords=args.passwords
    )
    converter.convert()


if __name__ == '__main__':
    main()
